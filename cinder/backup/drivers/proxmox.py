# Copyright (C) 2025 Aadarsha Dhakal <aadarsha.dhakal@startsml.com>
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

"""Implementation of a backup service using Proxmox Backup Server (PBS)

**Related Flags**

:backup_proxmox_host: The hostname or IP of the PBS server.
:backup_proxmox_port: The port of the PBS server (default: 8007).
:backup_proxmox_user: Username for PBS authentication (e.g., 'root@pam').
:backup_proxmox_password: Password for PBS authentication.
:backup_proxmox_datastore: The datastore name on PBS server.
:backup_proxmox_namespace: Optional namespace within the datastore.
:backup_proxmox_verify_ssl: Verify SSL certificates (default: True).
:backup_proxmox_fingerprint: Optional SHA256 fingerprint of PBS server cert.
:backup_proxmox_chunk_size: Size of backup chunks in bytes (default: 4MB).
"""

import hashlib
import io
import json
import re
import struct
import time
import zlib
from urllib import parse as urlparse

try:
    import lz4.block
    import lz4.frame
    HAS_LZ4 = True
except ImportError:
    HAS_LZ4 = False

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
import httpx
import h2.connection
import h2.config
import h2.events

from cinder.backup import chunkeddriver
from cinder import exception
from cinder.i18n import _
from cinder import interface

LOG = logging.getLogger(__name__)

proxmoxbackup_service_opts = [
    cfg.StrOpt('backup_proxmox_host',
               help='The hostname or IP address of the Proxmox Backup Server'),
    cfg.PortOpt('backup_proxmox_port',
                default=8007,
                help='The port of the Proxmox Backup Server'),
    cfg.StrOpt('backup_proxmox_user',
               default='root@pam',
               help='Username for Proxmox Backup Server authentication '
                    '(e.g., root@pam)'),
    cfg.StrOpt('backup_proxmox_password',
               secret=True,
               help='Password for Proxmox Backup Server authentication'),
    cfg.StrOpt('backup_proxmox_datastore',
               default='datastore1',
               help='The datastore name on Proxmox Backup Server'),
    cfg.StrOpt('backup_proxmox_namespace',
               default='',
               help='Optional namespace within the datastore'),
    cfg.BoolOpt('backup_proxmox_verify_ssl',
                default=True,
                help='Verify SSL certificates when connecting to PBS'),
    cfg.StrOpt('backup_proxmox_fingerprint',
               default=None,
               help='Optional SHA256 fingerprint of the PBS server '
                    'certificate for additional security'),
    cfg.IntOpt('backup_proxmox_chunk_size',
               default=4 * 1024 * 1024,  # 4MB
               help='The size in bytes of PBS backup chunks'),
    cfg.IntOpt('backup_proxmox_block_size',
               default=64 * 1024,  # 64KB
               help='The size in bytes that changes are tracked '
                    'for incremental backups'),
    cfg.IntOpt('backup_proxmox_retry_attempts',
               default=3,
               help='The number of retries for PBS operations'),
    cfg.IntOpt('backup_proxmox_retry_backoff',
               default=2,
               help='The backoff time in seconds between PBS retries'),
    cfg.BoolOpt('backup_proxmox_enable_progress_timer',
                default=True,
                help='Enable progress notifications to Ceilometer'),
]

CONF = cfg.CONF
CONF.register_opts(proxmoxbackup_service_opts)


class PBSDataBlob:
    """Handler for Proxmox Backup Server data blob encoding/decoding.

    PBS stores data in a specific blob format with magic numbers and CRC checks.
    This class implements the encoding and decoding logic.

    From pbs-datastore/src/file_formats.rs:
    - UNCOMPRESSED_BLOB_MAGIC_1_0: [66, 171, 56, 7, 190, 131, 112, 161]
    - COMPRESSED_BLOB_MAGIC_1_0: [49, 185, 88, 66, 111, 182, 163, 127]
    - ENCRYPTED_BLOB_MAGIC_1_0: [123, 103, 133, 190, 34, 45, 76, 240]
    - ENCR_COMPR_BLOB_MAGIC_1_0: [230, 89, 27, 191, 11, 191, 216, 11]
    """

    # Magic numbers from PBS Rust source (little-endian byte arrays)
    UNCOMPRESSED_BLOB_MAGIC_1_0 = bytes([66, 171, 56, 7, 190, 131, 112, 161])
    COMPRESSED_BLOB_MAGIC_1_0 = bytes([49, 185, 88, 66, 111, 182, 163, 127])
    ENCRYPTED_BLOB_MAGIC_1_0 = bytes([123, 103, 133, 190, 34, 45, 76, 240])
    ENCR_COMPR_BLOB_MAGIC_1_0 = bytes([230, 89, 27, 191, 11, 191, 216, 11])

    def __init__(self, compress=False, encrypt=False):
        """Initialize blob handler.

        :param compress: Whether to compress the data
        :param encrypt: Whether to encrypt the data (not yet implemented)
        """
        self.compress = compress
        self.encrypt = encrypt

    def encode(self, data):
        """Encode data into PBS blob format.

        :param data: Raw bytes to encode
        :returns: Encoded blob bytes
        """
        if self.encrypt:
            raise NotImplementedError("Encryption not yet implemented")

        # Determine magic number based on compression
        if self.compress:
            compressed = zlib.compress(data)
            magic = self.COMPRESSED_BLOB_MAGIC_1_0
            payload = compressed
        else:
            magic = self.UNCOMPRESSED_BLOB_MAGIC_1_0
            payload = data

        # Calculate CRC32 (standard zlib crc32)
        crc = zlib.crc32(payload) & 0xffffffff

        # Build blob: magic(8) + crc(4) + data
        blob = magic + struct.pack('<I', crc) + payload

        return blob

    def decode(self, blob):
        """Decode PBS blob format to raw data.

        :param blob: Blob bytes to decode
        :returns: Decoded raw bytes
        """
        if len(blob) < 12:
            raise ValueError("Blob too small")

        # Parse header
        magic = blob[0:8]
        crc_expected = struct.unpack('<I', blob[8:12])[0]
        payload = blob[12:]

        # Verify CRC
        crc_actual = zlib.crc32(payload) & 0xffffffff
        if crc_actual != crc_expected:
            raise ValueError(f"CRC mismatch: expected {crc_expected}, "
                             f"got {crc_actual}")

        # Decompress if needed based on magic
        if magic == self.COMPRESSED_BLOB_MAGIC_1_0:
            return zlib.decompress(payload)
        elif magic == self.UNCOMPRESSED_BLOB_MAGIC_1_0:
            return payload
        elif magic == self.ENCRYPTED_BLOB_MAGIC_1_0:
            raise NotImplementedError("Encrypted blobs not yet supported")
        elif magic == self.ENCR_COMPR_BLOB_MAGIC_1_0:
            raise NotImplementedError(
                "Encrypted compressed blobs not supported")
        else:
            raise ValueError(f"Unknown blob magic: {magic.hex()}")


class DynamicIndexReader:
    """Reader for PBS Dynamic Index (.didx) files.

    Dynamic Index format (from pbs-datastore/src/dynamic_index.rs):
    - Header: 4096 bytes
      - magic: 8 bytes [28, 145, 78, 165, 25, 186, 179, 205]
      - uuid: 16 bytes
      - ctime: i64 (8 bytes)
      - index_csum: 32 bytes (SHA256 of all entries)
      - reserved: 4032 bytes
    - Entries: 40 bytes each
      - end_le: u64 (8 bytes) - end offset of this chunk
      - digest: 32 bytes - SHA256 digest of the chunk
    """

    HEADER_SIZE = 4096
    ENTRY_SIZE = 40  # 8 bytes offset + 32 bytes digest
    MAGIC = bytes([28, 145, 78, 165, 25, 186, 179, 205])

    def __init__(self, data):
        """Initialize from raw index data.

        :param data: Raw bytes of the .didx file
        """
        if len(data) < self.HEADER_SIZE:
            raise ValueError("Dynamic index too small for header")

        # Parse header
        magic = data[0:8]
        if magic != self.MAGIC:
            raise ValueError(f"Invalid dynamic index magic: {magic.hex()}")

        self.uuid = data[8:24]
        self.ctime = struct.unpack('<q', data[24:32])[0]
        self.index_csum = data[32:64]

        # Parse entries
        self.entries = []
        entry_data = data[self.HEADER_SIZE:]
        num_entries = len(entry_data) // self.ENTRY_SIZE

        for i in range(num_entries):
            offset = i * self.ENTRY_SIZE
            end_offset = struct.unpack('<Q', entry_data[offset:offset + 8])[0]
            digest = entry_data[offset + 8:offset + 40]
            self.entries.append({
                'end_offset': end_offset,
                'digest': digest,
                'digest_hex': digest.hex()
            })

        LOG.debug(f"Parsed dynamic index with {len(self.entries)} chunks")

    def get_chunk_digests(self):
        """Return list of chunk digests in order."""
        return [e['digest'] for e in self.entries]

    def get_chunk_digest_hexes(self):
        """Return list of chunk digest hex strings in order."""
        return [e['digest_hex'] for e in self.entries]

    def get_total_size(self):
        """Return total size of the indexed data."""
        if self.entries:
            return self.entries[-1]['end_offset']
        return 0


class FixedIndexReader:
    """Reader for PBS Fixed Index (.fidx) files.

    Fixed Index format (from pbs-datastore/src/fixed_index.rs):
    - Header: 4096 bytes
      - magic: 8 bytes [47, 127, 65, 237, 145, 253, 15, 205]
      - uuid: 16 bytes
      - ctime: i64 (8 bytes)
      - index_csum: 32 bytes (SHA256 of all digests)
      - size: u64 (8 bytes) - total image size
      - chunk_size: u64 (8 bytes)
      - reserved: 4016 bytes
    - Digests: 32 bytes each (consecutive SHA256 digests)
    """

    HEADER_SIZE = 4096
    DIGEST_SIZE = 32
    MAGIC = bytes([47, 127, 65, 237, 145, 253, 15, 205])

    def __init__(self, data):
        """Initialize from raw index data.

        :param data: Raw bytes of the .fidx file
        """
        if len(data) < self.HEADER_SIZE:
            raise ValueError("Fixed index too small for header")

        # Parse header
        magic = data[0:8]
        if magic != self.MAGIC:
            raise ValueError(f"Invalid fixed index magic: {magic.hex()}")

        self.uuid = data[8:24]
        self.ctime = struct.unpack('<q', data[24:32])[0]
        self.index_csum = data[32:64]
        self.size = struct.unpack('<Q', data[64:72])[0]
        self.chunk_size = struct.unpack('<Q', data[72:80])[0]

        # Parse digests
        self.digests = []
        digest_data = data[self.HEADER_SIZE:]
        num_digests = len(digest_data) // self.DIGEST_SIZE

        for i in range(num_digests):
            offset = i * self.DIGEST_SIZE
            digest = digest_data[offset:offset + 32]
            self.digests.append(digest)

        LOG.debug(f"Parsed fixed index: {len(self.digests)} chunks, "
                  f"chunk_size={self.chunk_size}, total_size={self.size}")

    def get_chunk_digests(self):
        """Return list of chunk digests in order."""
        return self.digests

    def get_chunk_digest_hexes(self):
        """Return list of chunk digest hex strings in order."""
        return [d.hex() for d in self.digests]

    def get_total_size(self):
        """Return total size of the indexed data."""
        return self.size

    def get_chunk_size(self):
        """Return the fixed chunk size."""
        return self.chunk_size


class PBSClient:
    """Client for communicating with Proxmox Backup Server API."""

    def __init__(self, host, port, user, password, verify_ssl=True,
                 fingerprint=None):
        """Initialize PBS client.

        :param host: PBS server hostname or IP
        :param port: PBS server port
        :param user: Username (e.g., 'root@pam')
        :param password: Password
        :param verify_ssl: Whether to verify SSL certificates
        :param fingerprint: Optional SHA256 fingerprint for cert pinning
        """
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.verify_ssl = verify_ssl
        self.fingerprint = fingerprint
        self.base_url = f"https://{host}:{port}"
        self.ticket = None
        self.csrf_token = None
        # HTTP/1.1 session for authentication only
        self.auth_session = httpx.Client(verify=verify_ssl, timeout=60.0)
        # HTTP/2 connection (after upgrade)
        self.h2_conn = None
        self.sock = None
        self.backup_session = None

    def _build_url(self, path):
        """Build full URL for API endpoint."""
        return f"{self.base_url}{path}"

    def authenticate(self):
        """Authenticate and get ticket/CSRF token."""
        auth_url = self._build_url("/api2/json/access/ticket")

        data = {
            'username': self.user,
            'password': self.password,
        }

        try:
            response = self.auth_session.post(auth_url, data=data)
            response.raise_for_status()

            result = response.json()
            if 'data' not in result:
                raise exception.BackupDriverException(
                    _("Authentication failed: no data in response"))

            self.ticket = result['data']['ticket']
            self.csrf_token = result['data']['CSRFPreventionToken']

            LOG.debug("Successfully authenticated to PBS server")

        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to authenticate to PBS: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def _get_headers(self):
        """Get HTTP headers with authentication."""
        if not self.ticket or not self.csrf_token:
            self.authenticate()

        return {
            'CSRFPreventionToken': self.csrf_token,
            'Cookie': f'PBSAuthCookie={self.ticket}',
        }

    def create_backup(self, datastore, backup_type, backup_id, backup_time):
        """Start a backup session and upgrade to HTTP/2 backup protocol.

        :param datastore: Datastore name
        :param backup_type: Backup type (e.g., 'host')
        :param backup_id: Backup ID
        :param backup_time: Backup timestamp (integer epoch)
        """
        # Create raw socket connection
        sock = socket.create_connection((self.host, self.port))

        # Wrap with SSL
        context = ssl.create_default_context()
        if not self.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.sock = context.wrap_socket(sock, server_hostname=self.host)

        # Send HTTP/1.1 upgrade request
        headers = self._get_headers()
        upgrade_request = (
            f"GET /api2/json/backup?"
            f"store={datastore}&"
            f"backup-type={backup_type}&"
            f"backup-id={backup_id}&"
            f"backup-time={int(backup_time)}&"
            f"benchmark=false HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Connection: Upgrade\r\n"
            f"Upgrade: proxmox-backup-protocol-v1\r\n"
            f"Cookie: {headers['Cookie']}\r\n"
            f"CSRFPreventionToken: {headers['CSRFPreventionToken']}\r\n"
            f"\r\n"
        )

        try:
            LOG.debug("Sending HTTP/1.1 upgrade request to PBS")
            self.sock.sendall(upgrade_request.encode())

            # Read upgrade response
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise exception.BackupDriverException(
                        _("Connection closed before upgrade complete"))
                response += chunk

            response_str = response.decode()

            if "101 Switching Protocols" not in response_str:
                raise exception.BackupDriverException(
                    _("Upgrade failed: %s") % response_str)

            LOG.debug("HTTP/2 upgrade successful (101 Switching Protocols)")

            # Initialize H2 connection
            config = h2.config.H2Configuration(client_side=True)
            self.h2_conn = h2.connection.H2Connection(config=config)
            self.h2_conn.initiate_connection()
            self.sock.sendall(self.h2_conn.data_to_send())

            LOG.debug("HTTP/2 connection initialized")

            # Store backup session info
            self.backup_session = {
                'store': datastore,
                'backup-type': backup_type,
                'backup-id': backup_id,
                'backup-time': int(backup_time),
            }

            LOG.info(
                f"Started PBS backup session for {backup_type}/{backup_id}")

        except Exception as e:
            msg = _("Failed to start PBS backup session: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def create_restore(self, datastore, backup_type, backup_id, backup_time):
        """Start a restore session and upgrade to HTTP/2 reader protocol.

        :param datastore: Datastore name
        :param backup_type: Backup type
        :param backup_id: Backup ID
        :param backup_time: Backup timestamp
        """
        # Create raw socket connection
        sock = socket.create_connection((self.host, self.port))

        # Wrap with SSL
        context = ssl.create_default_context()
        if not self.verify_ssl:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        self.sock = context.wrap_socket(sock, server_hostname=self.host)

        # Send HTTP/1.1 upgrade request
        headers = self._get_headers()
        # Note: Reader protocol uses /api2/json/reader
        upgrade_request = (
            f"GET /api2/json/reader?"
            f"store={datastore}&"
            f"backup-type={backup_type}&"
            f"backup-id={backup_id}&"
            f"backup-time={int(backup_time)}&"
            f"debug=true HTTP/1.1\r\n"
            f"Host: {self.host}:{self.port}\r\n"
            f"Connection: Upgrade\r\n"
            f"Upgrade: proxmox-backup-reader-protocol-v1\r\n"
            f"Cookie: {headers['Cookie']}\r\n"
            f"CSRFPreventionToken: {headers['CSRFPreventionToken']}\r\n"
            f"\r\n"
        )

        try:
            LOG.debug("Sending HTTP/1.1 upgrade request (reader) to PBS")
            self.sock.sendall(upgrade_request.encode())

            # Read upgrade response
            response = b""
            while b"\r\n\r\n" not in response:
                chunk = self.sock.recv(4096)
                if not chunk:
                    raise exception.BackupDriverException(
                        _("Connection closed before upgrade complete"))
                response += chunk

            response_str = response.decode()

            if "101 Switching Protocols" not in response_str:
                raise exception.BackupDriverException(
                    _("Upgrade failed: %s") % response_str)

            LOG.debug("HTTP/2 upgrade successful (101 Switching Protocols)")

            # Initialize H2 connection
            config = h2.config.H2Configuration(client_side=True)
            self.h2_conn = h2.connection.H2Connection(config=config)
            self.h2_conn.initiate_connection()
            self.sock.sendall(self.h2_conn.data_to_send())

            LOG.debug("HTTP/2 connection initialized (Restore Session)")

            # Store backup session info
            self.backup_session = {
                'store': datastore,
                'backup-type': backup_type,
                'backup-id': backup_id,
                'backup-time': int(backup_time),
            }

        except Exception as e:
            if self.sock:
                self.sock.close()
                self.sock = None
            msg = _("Failed to start PBS restore session: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def _h2_request(self, method, path, params=None, body=None,
                    content_type='application/octet-stream'):
        """Make an HTTP/2 request over the upgraded connection."""
        if not self.h2_conn:
            raise exception.BackupDriverException(
                _("Not connected - call create_backup first"))

        # Build query string
        query_string = ""
        if params:
            query_parts = [f"{k}={v}" for k, v in params.items()]
            query_string = "?" + "&".join(query_parts)

        # Prepare headers
        headers = [
            (':method', method),
            (':path', path + query_string),
            (':scheme', 'https'),
            (':authority', f'{self.host}:{self.port}'),
        ]

        if body:
            headers.append(('content-length', str(len(body))))
            headers.append(('content-type', content_type))

        # Send request
        stream_id = self.h2_conn.get_next_available_stream_id()
        self.h2_conn.send_headers(
            stream_id, headers, end_stream=(body is None))

        if body:
            # Send body in chunks to respect max frame size
            max_frame_size = self.h2_conn.max_outbound_frame_size
            offset = 0
            while offset < len(body):
                chunk_size = min(max_frame_size, len(body) - offset)
                chunk = body[offset:offset + chunk_size]
                end_stream = (offset + chunk_size >= len(body))
                self.h2_conn.send_data(stream_id, chunk, end_stream=end_stream)
                offset += chunk_size

        self.sock.sendall(self.h2_conn.data_to_send())

        # Receive response
        response_headers = {}
        response_data = b""

        while True:
            data = self.sock.recv(65536)
            if not data:
                break

            events = self.h2_conn.receive_data(data)
            self.sock.sendall(self.h2_conn.data_to_send())

            for event in events:
                if isinstance(event, h2.events.ResponseReceived):
                    response_headers = dict(event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    response_data += event.data
                    self.h2_conn.acknowledge_received_data(
                        event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    # Check status code
                    status = response_headers.get(b':status', b'000').decode()
                    if not status.startswith('2'):
                        error_msg = response_data.decode() if response_data else 'No error message'
                        raise exception.BackupDriverException(
                            _("HTTP %(status)s: %(msg)s") % {
                                'status': status, 'msg': error_msg})
                    return response_headers, response_data

        return response_headers, response_data

    def create_fixed_index(self, archive_name, size):
        """Create a new fixed index.

        :param archive_name: Archive name (e.g. 'volume.fidx')
        :param size: Total size of the archive
        :returns: Writer ID (wid)
        """
        path = "/fixed_index"
        params = {
            'archive-name': archive_name,
            'size': size,
        }

        try:
            headers, data = self._h2_request('POST', path, params=params)
            # Parse response - should be JSON with 'data' field
            result = json.loads(data.decode())
            wid = int(result['data'])
            LOG.debug(f"Created fixed index, wid: {wid}")
            return wid
        except Exception as e:
            msg = _("Failed to create fixed index: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def upload_blob(self, name, data):
        """Upload a named blob (config, manifest, etc).

        :param name: Blob name (e.g. 'cinder-manifest.json.blob')
        :param data: Blob data (raw bytes, will be encoded as PBS blob)
        """
        url = self._build_url("/blob")
        headers = self._get_headers()
        headers['Content-Type'] = 'application/octet-stream'

        # Encode the data as a PBS blob
        blob_handler = PBSDataBlob(compress=False)
        encoded_data = blob_handler.encode(data)

        # PBS expects the file name to end with .blob
        if not name.endswith('.blob'):
            name = name + '.blob'

        params = {
            'file-name': name,
            'encoded-size': len(encoded_data)
        }

        try:
            self.session.post(url, content=encoded_data, params=params,
                              headers=headers).raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            raise exception.BackupDriverException(
                f"Failed to upload blob {name}: {e}")

    def append_index(self, digest_list, offset_list, wid):
        """Append chunks to fixed index.

        :param digest_list: List of chunk digests
        :param offset_list: List of chunk offsets
        :param wid: Writer ID
        """
        path = "/fixed_index"

        # Build JSON body
        body_data = json.dumps({
            'wid': wid,
            'digest-list': digest_list,
            'offset-list': offset_list,
        }).encode()

        try:
            headers, data = self._h2_request(
                'PUT', path, body=body_data, content_type='application/json')
        except Exception as e:
            msg = _("Failed to append to fixed index: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def close_fixed_index(self, chunk_count, csum, size, wid):
        """Close the fixed index.

        :param chunk_count: Number of chunks
        :param csum: Checksum of the index (hex string)
        :param size: Total size of data
        :param wid: Writer ID
        """
        path = "/fixed_close"
        params = {
            'chunk-count': chunk_count,
            'csum': csum,
            'size': size,
            'wid': wid,
        }

        try:
            headers, data = self._h2_request('POST', path, params=params)
        except Exception as e:
            msg = _("Failed to close fixed index: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def upload_manifest(self, archive_name, size, csum):
        """Upload the backup manifest (index.json.blob).

        :param archive_name: Archive filename (e.g., 'volume.fidx')
        :param size: Total size of the archive
        :param csum: Checksum of the archive
        """
        # Create manifest
        manifest = {
            "backup-type": self.backup_session['backup-type'],
            "backup-id": self.backup_session['backup-id'],
            "backup-time": self.backup_session['backup-time'],
            "files": [
                {
                    "filename": archive_name,
                    "size": size,
                    "csum": csum,
                }
            ],
        }

        manifest_json = json.dumps(manifest, indent=2).encode()

        # Wrap manifest in blob format
        chunk_handler = PBSChunk()
        manifest_blob = chunk_handler.encode(manifest_json)

        # Upload as index.json.blob
        path = "/blob"
        params = {
            'file-name': 'index.json.blob',
            'encoded-size': len(manifest_blob),
        }

        try:
            headers, data = self._h2_request(
                'POST', path, params=params, body=manifest_blob)
            LOG.debug("Uploaded manifest (index.json.blob)")
        except Exception as e:
            msg = _("Failed to upload manifest: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def download_index(self, archive_name):
        """Download and parse the fixed index file.

        :param archive_name: Name of the index file (e.g. volume.fidx)
        :returns: List of chunk digests (hex strings)
        """
        # PBS reader protocol uses /download endpoint for file retrieval
        path = "/download"
        params = {'file-name': archive_name}

        try:
            headers, data = self._h2_request('GET', path, params=params)

            # Parse fixed index
            # Format: MAGIC (8 bytes) + ... + Digests (starts at 4096)
            HEADER_SIZE = 4096
            # Magic for fixed index
            MAGIC = bytes([47, 127, 65, 237, 145, 253, 15, 205])

            if len(data) < HEADER_SIZE:
                raise exception.BackupDriverException("Index file too short")

            if data[:8] != MAGIC:
                raise exception.BackupDriverException(
                    "Invalid fixed index magic")

            digests = []
            offset = HEADER_SIZE
            # Each digest is 32 bytes
            while offset + 32 <= len(data):
                digest = data[offset:offset + 32]
                digests.append(digest.hex())
                offset += 32

            return digests

        except Exception as e:
            msg = _("Failed to download index: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def download_blob_direct(self, datastore, backup_type, backup_id, backup_time, name):
        """Download blob/file using REST API.

        :param datastore: Datastore name
        :param backup_type: Backup type (e.g., 'host')
        :param backup_id: Backup ID
        :param backup_time: Backup timestamp (integer epoch)
        :param name: File name to download
        :returns: File content (decoded if it's a blob)
        """
        # Use the download endpoint with backup identification params
        path = f"/api2/json/admin/datastore/{datastore}/download"
        url = self._build_url(path)
        params = {
            'backup-type': backup_type,
            'backup-id': backup_id,
            'backup-time': int(backup_time),
            'file-name': name,
        }
        headers = self._get_headers()

        try:
            response = self.session.get(url, params=params, headers=headers)
            response.raise_for_status()
            content = response.content

            # If this is a .blob file, it needs to be decoded
            if name.endswith('.blob'):
                blob_handler = PBSDataBlob()
                return blob_handler.decode(content)
            return content
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                return None
            msg = _("Failed to download file %s: %s") % (name, str(e))
            raise exception.BackupDriverException(msg)
        except httpx.RequestError as e:
            msg = _("Failed to download file %s: %s") % (name, str(e))
            raise exception.BackupDriverException(msg)

    def download_chunk(self, digest):
        """Download a chunk by its digest.

        :param digest: Hex string digest
        :returns: Blob bytes
        """
        path = '/chunk'
        params = {'digest': digest}

        try:
            headers, data = self._h2_request('GET', path, params=params)
            return data
        except Exception as e:
            msg = _("Failed to download chunk %s: %s") % (digest, str(e))
            raise exception.BackupDriverException(msg)

    def delete_snapshot(self, datastore, backup_type, backup_id, backup_time):
        """Delete a snapshot using the API."""
        path = f"/api2/json/admin/datastore/{datastore}/snapshots/{backup_type}/{backup_id}/{backup_time}"
        url = self._build_url(path)
        headers = self._get_headers()

        try:
            # We use the auth_session, but we need to add tokens in headers if not present
            # httpx Client merges headers, so we can pass them in the call
            response = self.auth_session.delete(url, headers=headers)

            # 200 OK or 404 Not Found (already deleted) are acceptable
            if response.status_code == 404:
                LOG.warning(f"Snapshot {path} not found for deletion")
                return

            response.raise_for_status()
            LOG.info(f"Deleted snapshot {path}")

        except Exception as e:
            msg = _("Failed to delete snapshot: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def download_index(self, name):
        """Download an index file.

        :param name: Index filename
        :returns: Index data
        """
        # This would use HTTP/2 GET /download
        LOG.debug(f"Would download index {name}")
        return b''

    def start_reader_session(self, datastore, backup_type, backup_id,
                             backup_time, namespace=None):
        """Start a reader session for restoring backups.

        This initiates a connection that can be used to download index files
        and chunks from a specific backup snapshot.

        :param datastore: Datastore name
        :param backup_type: Backup type (e.g., 'host')
        :param backup_id: Backup ID
        :param backup_time: Backup timestamp (integer epoch)
        :param namespace: Optional namespace
        :returns: PBSReaderSession instance
        """
        return PBSReaderSession(
            self, datastore, backup_type, backup_id, backup_time, namespace
        )


class PBSReaderSession:
    """Session for reading/restoring data from PBS using the reader protocol.

    The PBS reader protocol is accessed via HTTP/2 after upgrading from
    HTTP/1.1 with the header 'Upgrade: proxmox-backup-reader-protocol-v1'.

    Since httpx doesn't support protocol upgrades in the same way as the Rust
    client, we use the standard REST API endpoints which provide equivalent
    functionality for reading backup data.

    API endpoints used:
    - GET /api2/json/admin/datastore/{store}/download-decoded
      Downloads and decodes files from a backup snapshot
    - GET /api2/json/admin/datastore/{store}/pxar-file-download
      Downloads files from pxar archives (not used here)
    """

    def __init__(self, client, datastore, backup_type, backup_id,
                 backup_time, namespace=None):
        """Initialize reader session.

        :param client: PBSClient instance (authenticated)
        :param datastore: Datastore name
        :param backup_type: Backup type (e.g., 'host')
        :param backup_id: Backup ID
        :param backup_time: Backup timestamp
        :param namespace: Optional namespace
        """
        self.client = client
        self.datastore = datastore
        self.backup_type = backup_type
        self.backup_id = backup_id
        self.backup_time = int(backup_time)
        self.namespace = namespace
        self.blob_handler = PBSDataBlob()
        self._index_cache = {}
        self._chunk_cache = {}

    def _get_backup_params(self):
        """Get common backup identification parameters."""
        params = {
            'backup-type': self.backup_type,
            'backup-id': self.backup_id,
            'backup-time': self.backup_time,
        }
        if self.namespace:
            params['ns'] = self.namespace
        return params

    def download_file(self, filename):
        """Download a file from the backup snapshot.

        :param filename: Name of the file to download (e.g., 'volume.didx')
        :returns: Raw file content
        """
        url = self.client._build_url(
            f"/api2/json/admin/datastore/{self.datastore}/download"
        )
        headers = self.client._get_headers()
        params = self._get_backup_params()
        params['file-name'] = filename

        try:
            response = self.client.session.get(
                url, params=params, headers=headers
            )
            response.raise_for_status()
            return response.content
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                LOG.warning(f"File {filename} not found in backup")
                return None
            msg = _("Failed to download file %s: %s") % (filename, str(e))
            raise exception.BackupDriverException(msg)
        except httpx.RequestError as e:
            msg = _("Failed to download file %s: %s") % (filename, str(e))
            raise exception.BackupDriverException(msg)

    def download_decoded_file(self, filename):
        """Download a file with automatic decoding (blob unwrapping).

        :param filename: Name of the file to download
        :returns: Decoded file content
        """
        url = self.client._build_url(
            f"/api2/json/admin/datastore/{self.datastore}/download-decoded"
        )
        headers = self.client._get_headers()
        params = self._get_backup_params()
        params['file-name'] = filename

        try:
            response = self.client.session.get(
                url, params=params, headers=headers
            )
            response.raise_for_status()
            return response.content
        except httpx.HTTPStatusError as e:
            if e.response.status_code == 404:
                LOG.warning(f"File {filename} not found in backup")
                return None
            msg = _("Failed to download decoded file %s: %s") % (
                filename, str(e))
            raise exception.BackupDriverException(msg)
        except httpx.RequestError as e:
            msg = _("Failed to download decoded file %s: %s") % (
                filename, str(e))
            raise exception.BackupDriverException(msg)

    def download_index(self, index_name):
        """Download and parse an index file.

        :param index_name: Index filename (e.g., 'volume.didx')
        :returns: DynamicIndexReader or FixedIndexReader instance
        """
        if index_name in self._index_cache:
            return self._index_cache[index_name]

        data = self.download_file(index_name)
        if data is None:
            raise exception.BackupDriverException(
                _("Index file %s not found") % index_name
            )

        if index_name.endswith('.didx'):
            index = DynamicIndexReader(data)
        elif index_name.endswith('.fidx'):
            index = FixedIndexReader(data)
        else:
            raise exception.BackupDriverException(
                _("Unknown index type: %s") % index_name
            )

        self._index_cache[index_name] = index
        return index

    def download_chunk(self, digest_hex):
        """Download a single chunk by its digest.

        :param digest_hex: Hex-encoded SHA256 digest of the chunk
        :returns: Decoded chunk data (raw bytes)
        """
        if digest_hex in self._chunk_cache:
            return self._chunk_cache[digest_hex]

        url = self.client._build_url(
            f"/api2/json/admin/datastore/{self.datastore}/chunk"
        )
        headers = self.client._get_headers()
        params = {'digest': digest_hex}

        try:
            response = self.client.session.get(
                url, params=params, headers=headers
            )
            response.raise_for_status()
            blob_data = response.content
        except httpx.HTTPStatusError as e:
            msg = _("Failed to download chunk %s: %s") % (digest_hex, str(e))
            raise exception.BackupDriverException(msg)
        except httpx.RequestError as e:
            msg = _("Failed to download chunk %s: %s") % (digest_hex, str(e))
            raise exception.BackupDriverException(msg)

        # Decode the blob
        decoded = self.blob_handler.decode(blob_data)
        self._chunk_cache[digest_hex] = decoded
        return decoded

    def read_index_data(self, index_name, output_file=None):
        """Read all data from an index file by downloading all chunks.

        :param index_name: Index filename (e.g., 'volume.didx')
        :param output_file: Optional file-like object to write data to
        :returns: Complete data as bytes (if output_file is None)
        """
        index = self.download_index(index_name)
        digests = index.get_chunk_digest_hexes()

        LOG.info(f"Restoring {len(digests)} chunks from {index_name}")

        if output_file is None:
            data = io.BytesIO()
        else:
            data = output_file

        for i, digest_hex in enumerate(digests):
            chunk_data = self.download_chunk(digest_hex)
            data.write(chunk_data)
            if (i + 1) % 100 == 0:
                LOG.debug(f"Restored {i + 1}/{len(digests)} chunks")

        LOG.info(f"Completed restoring {len(digests)} chunks")

        if output_file is None:
            return data.getvalue()
        return None

    def close(self):
        """Close the reader session and clear caches."""
        self._index_cache.clear()
        self._chunk_cache.clear()


class ObjectWriter:
    """Writer for PBS objects (chunks) for fixed index."""

    def __init__(self, client, datastore, name, state=None):
        """Initialize writer.

        :param client: PBSClient instance
        :param datastore: Datastore name
        :param name: Object name
        :param state: Shared state dict for the backup session
        """
        self.client = client
        self.datastore = datastore
        self.name = name
        self.chunk_handler = PBSChunk()
        self.buffer = io.BytesIO()
        self.state = state
        # Get the fixed chunk size from config (default 4MB)
        # Get the fixed chunk size from config (default 4MB)
        self.fixed_chunk_size = CONF.backup_proxmox_chunk_size

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.close()
        return False

    def write(self, data):
        """Write data to the object."""
        self.buffer.write(data)

    def close(self):
        """Finalize and upload the chunk."""
        data = self.buffer.getvalue()
        original_size = len(data)

        # Calculate digest of the RAW data (before encoding)
        # PBS uses the raw data digest to identify chunks
        digest = hashlib.sha256(data).hexdigest()

        # Encode as PBS blob for storage/transport
        blob = self.blob_handler.encode(data)

        # Upload to PBS
        if self.state is not None:
            chunk_size = len(data)
            original_size = chunk_size

            # Check if this is smaller than the fixed chunk size
            if chunk_size < self.fixed_chunk_size:
                # Pad with zeros to make it a full chunk
                # PBS will track the actual data size separately
                padding = b'\x00' * (self.fixed_chunk_size - chunk_size)
                data = data + padding
                chunk_size = self.fixed_chunk_size

                LOG.debug(
                    f"Padded chunk from {original_size} to {chunk_size} bytes")

            # Wrapper chunk in blob format
            chunk_data = self.chunk_handler.encode(data)

            # Calculate digest from the padded chunk data (Revert to original: hash of raw data)
            # For uncompressed chunks, PBS expects the digest of the raw payload
            digest = hashlib.sha256(data).hexdigest()

            wid = self.state['wid']
            self.client.upload_chunk(
                wid, digest, blob, original_size, len(blob))

            # Update stats and checksum for dynamic index
            self.state['chunk_count'] += 1
            self.state['total_size'] += original_size

            # Checksum: SHA256(offset_le || digest_bytes)
            # offset is the END offset of the chunk
            offset_bytes = struct.pack('<Q', self.state['total_size'])
            digest_bytes = bytes.fromhex(digest)
            self.state['csum'].update(digest_bytes)
        else:
            # Fallback for non-indexed uploads (shouldn't happen for chunks)
            pass

        # Update manifest with raw data digest
        if self.manifest is not None:
            self.manifest[self.name] = digest


class ObjectReader:
    """Reader for individual PBS objects (chunks).

    This class handles reading a single backup object from PBS by:
    1. Looking up the object's PBS digest from the Cinder manifest
    2. Downloading and decoding that specific chunk from PBS

    The Cinder chunked driver stores each chunk as a separate object with a
    unique name. During backup, we store a mapping of object_name -> PBS digest
    in a manifest blob. During restore, we look up each object's digest and
    download it individually.
    """

    def __init__(self, client, datastore, name, extra_metadata=None, driver=None):
        """Initialize reader.


        :param client: PBSClient instance
        :param datastore: Datastore name
        :param name: Object name to read
        :param extra_metadata: Metadata containing backup info (volume_id, backup_time)
        :param driver: ProxmoxBackupDriver instance (for manifest lookup)
        """
        self.client = client
        self.datastore = datastore
        self.name = name
        self.extra_metadata = extra_metadata or {}
        self.driver = driver
        self.data = None
        self.blob_handler = PBSDataBlob()

    def __enter__(self):
        # Get backup identification from extra_metadata
        volume_id = self.extra_metadata.get('volume_id')
        backup_time = self.extra_metadata.get('backup_time')

        if not volume_id or not backup_time:
            LOG.error("Missing volume_id or backup_time in extra_metadata, "
                      "cannot restore object %s", self.name)
            return self

        LOG.debug(f"Reading object {self.name} from PBS")

        try:
            # Authenticate client if needed
            self.client.authenticate()

            # Get the PBS digest for this object from the manifest
            digest = None
            if self.driver:
                digest = self.driver.get_object_digest(
                    self.name, self.extra_metadata)

            if not digest:
                LOG.error(f"No PBS digest found for object {self.name}")
                return self

            LOG.debug(f"Object {self.name} has PBS digest {digest}")

            # Download the chunk from PBS
            url = self.client._build_url(
                f"/api2/json/admin/datastore/{self.datastore}/chunk"
            )
            headers = self.client._get_headers()
            params = {'digest': digest}

            response = self.client.session.get(
                url, params=params, headers=headers
            )
            response.raise_for_status()
            blob_data = response.content

            # Decode the blob to get raw data
            self.data = self.blob_handler.decode(blob_data)

            LOG.debug(
                f"Successfully read {len(self.data)} bytes for object {self.name}")

        except httpx.HTTPStatusError as e:
            msg = _("Failed to download object %s: %s") % (self.name, str(e))
            LOG.error(msg)
            raise exception.BackupDriverException(msg)
        except httpx.RequestError as e:
            msg = _("Failed to download object %s: %s") % (self.name, str(e))
            LOG.error(msg)
            raise exception.BackupDriverException(msg)
        except Exception as e:
            LOG.exception(f"Failed to read object {self.name}: {e}")
            raise exception.BackupDriverException(
                _("Failed to restore object %s: %s") % (self.name, str(e))
            )

        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        return False

    def read(self):
        """Read the object data."""
        return self.data if self.data is not None else b''


class PBSChunkReader:
    """Reader for PBS chunks."""

    def __init__(self, client):
        self.chunk_handler = PBSChunk()
        self.client = client

    def read_chunk(self, digest):
        """Download and decode a chunk."""
        blob_data = self.client.download_chunk(digest)
        return self.chunk_handler.decode(blob_data)


@interface.backupdriver
class ProxmoxBackupDriver(chunkeddriver.ChunkedBackupDriver):
    """Backup driver for Proxmox Backup Server.

    This driver implements native PBS protocol communication without
    relying on the proxmox - backup - client command - line tool.
    """

    def __init__(self, context):
        """Initialize the Proxmox Backup driver.

        : param context: The security context
        """
        chunk_size = CONF.backup_proxmox_chunk_size
        sha_block_size = CONF.backup_proxmox_block_size
        backup_default_container = CONF.backup_proxmox_datastore
        enable_progress_timer = CONF.backup_proxmox_enable_progress_timer

        super(ProxmoxBackupDriver, self).__init__(
            context,
            chunk_size,
            sha_block_size,
            backup_default_container,
            enable_progress_timer,
        )

        self._validate_config()
        self._active_clients = {}
        self._backup_state = {}  # State for active backups: backup_id -> dict
        self._current_backup_id = None  # Track current backup being processed
        self._pbs_metadata_cache = {}  # Store metadata files: backup_id -> {filename: data}

    def _validate_config(self):
        """Validate required configuration options."""
        required = [
            'backup_proxmox_host',
            'backup_proxmox_user',
            'backup_proxmox_password',
            'backup_proxmox_datastore',
        ]

        for opt in required:
            if not getattr(CONF, opt):
                msg = _("Configuration option %s is required") % opt
                raise exception.BackupDriverException(msg)

    def _get_client(self):
        """Get or create PBS client instance."""
        return PBSClient(
            host=CONF.backup_proxmox_host,
            port=CONF.backup_proxmox_port,
            user=CONF.backup_proxmox_user,
            password=CONF.backup_proxmox_password,
            verify_ssl=CONF.backup_proxmox_verify_ssl,
            fingerprint=CONF.backup_proxmox_fingerprint,
        )

    def _prepare_backup(self, backup):
        """Prepare the backup."""
        # Track current backup
        self._current_backup_id = backup.id

        # Start PBS session
        client = self._get_client()
        client.authenticate()

        # Use 'vm' type for generic data
        backup_type = 'vm'
        backup_id = f"volume-{backup.volume_id}"
        # Use created_at timestamp for consistency
        if backup.created_at:
            backup_time = int(backup.created_at.timestamp())
        else:
            backup_time = int(time.time())

        client.create_backup(CONF.backup_proxmox_datastore,
                             backup_type, backup_id, backup_time)

        # For fixed index, we need to know the total size upfront
        # Calculate based on volume size, but this is the maximum size
        # The actual size will be determined when we close the index
        volume_size_bytes = backup.size * 1024 * 1024 * 1024  # GB to bytes

        # Round up to nearest chunk size to ensure we have enough space
        chunk_size = CONF.backup_proxmox_chunk_size
        num_chunks = (volume_size_bytes + chunk_size - 1) // chunk_size
        total_size = num_chunks * chunk_size

        # Create the fixed index for volume data
        wid = client.create_fixed_index("volume.fidx", total_size)

        # Store client and state
        self._active_clients[backup.id] = client
        self._backup_state[backup.id] = {
            'wid': wid,
            'chunk_count': 0,
            'total_size': 0,
            'current_offset': 0,
            'digests': [],
            'offsets': [],
            'csum': hashlib.sha256(),
            'expected_total_size': total_size,  # Track what we told PBS
            'backup_time': backup_time,  # Store for service_metadata
            'backup_id': backup_id,  # Store PBS backup_id
        }

        return super(ProxmoxBackupDriver, self)._prepare_backup(backup)

    def _finalize_backup(self, backup, container, object_meta, object_sha256):
        """Finalize the backup."""
        client = self._active_clients.get(backup.id)
        state = self._backup_state.get(backup.id)

        if client and state:
            try:
                # Append all chunks to the index
                if state['digests'] and state['offsets']:
                    client.append_index(
                        state['digests'], state['offsets'], state['wid'])

                # Close the fixed index
                index_csum = state['csum'].hexdigest()
                client.close_fixed_index(
                    state['chunk_count'],
                    index_csum,
                    state['total_size'],
                    state['wid']
                )

                # Upload manifest
                client.upload_manifest(
                    'volume.fidx',
                    state['total_size'],
                    index_csum
                )

                # Complete backup
                client.complete_backup()

                # Save service metadata for restore
                # This is critical - we need the exact backup_time used
                service_metadata = {
                    'backup_id': state['backup_id'],
                    'backup_time': state['backup_time'],
                    'archive_name': 'volume.fidx',
                    'backup_type': 'vm',
                }
                backup.service_metadata = json.dumps(service_metadata)
                backup.save()

                LOG.info("PBS backup completed successfully. "
                         "Saved service_metadata: %s", service_metadata)
            except Exception as e:
                LOG.error(f"Error finishing PBS backup: {e}")
                # Cleanup before re-raising
                if backup.id in self._active_clients:
                    del self._active_clients[backup.id]
                if backup.id in self._backup_state:
                    del self._backup_state[backup.id]
                raise

        # Now call parent's finalize - but mark that PBS is done
        # so get_object_writer knows to handle metadata differently
        if state:
            state['pbs_finalized'] = True

        try:
            super(ProxmoxBackupDriver, self)._finalize_backup(backup, container,
                                                              object_meta, object_sha256)
        finally:
            # Clean up session after parent finalization
            if backup.id in self._active_clients:
                del self._active_clients[backup.id]
            if backup.id in self._backup_state:
                del self._backup_state[backup.id]
            # Note: We keep _backup_metadata[backup.id] for incremental backups
            # It will be used when creating incremental backups that reference this one
            # Clear current backup tracking
            self._current_backup_id = None

    def put_container(self, container):
        """Create the datastore / namespace if needed.

        : param container: Container name(datastore)
        """
        # In PBS, datastores are pre-created via admin interface
        # Namespaces can be created via API if needed
        LOG.debug(f"Using PBS datastore: {container}")

    def get_container_entries(self, container, prefix):
        """Get backup entries in the datastore.

        : param container: Container name(datastore)
        : param prefix: Prefix for filtering backups
        : returns: List of backup names
        """
        # Would query PBS API for backup snapshots
        # For now, return empty list
        LOG.debug(f"Listing backups in {container} with prefix {prefix}")
        return []

    def _generate_object_name_prefix(self, backup):
        """Generate object name prefix for backup.

        : param backup: Backup object
        : returns: Object name prefix
        """
        # Use backup ID as prefix for PBS backup objects
        return f"backup_{backup.id}_"

    def delete_object(self, container, object_name):
        """Delete object from container.

        : param container: Container name(datastore)
        : param object_name: Object name to delete
        """
        # For PBS, objects are managed as part of backup snapshots
        # Individual chunk deletion is handled by PBS garbage collection
        # But we do need to handle the delete_backup call in the driver,
        # which calls delete_snapshot.
        pass

    def get_object_writer(self, container, object_name, extra_metadata=None):
        """Get a writer for uploading an object."""
        # Try to get backup_id from extra_metadata, fall back to current backup
        backup_id = extra_metadata.get('backup_id') if extra_metadata else None
        if not backup_id:
            backup_id = self._current_backup_id

        client = self._active_clients.get(backup_id)
        state = self._backup_state.get(backup_id)

        if not client:
            raise exception.BackupDriverException(
                "No active PBS session for backup")

        # Check if we are writing metadata
        is_metadata = 'backup_metadata' in object_name or 'sha256file' in object_name

        if is_metadata and state and state['index_name'] == 'volume.didx':
            # Switch to metadata index
            # First close the volume index
            client.close_dynamic_index(
                state['wid'],
                state['chunk_count'],
                state['total_size'],
                state['csum'].hexdigest()
            )

            # Create new index for metadata
            wid = client.create_dynamic_index("metadata.didx")

            # Reset state for new index
            state['wid'] = wid
            state['chunk_count'] = 0
            state['total_size'] = 0
            state['csum'] = hashlib.sha256()
            state['index_name'] = 'metadata.didx'

        # Disable compression in PBSDataBlob if Cinder is already compressing
        return ObjectWriter(client, container, object_name,
                            manifest=self._backup_manifests.get(backup_id),
                            compress=False,
                            state=state)

    def get_object_reader(self, container, object_name, extra_metadata=None):
        """Get a reader for downloading an object.

        If extra_metadata is not provided, we try to extract backup info
        from the object_name which follows the pattern:
        volume_{volume_id}/{timestamp}/az_{az}_backup_{backup_id}...
        """
        # If extra_metadata not provided, try to extract from object_name
        if extra_metadata is None:
            extra_metadata = self._extract_backup_info_from_name(object_name)

        client = self._get_client()
        return ObjectReader(client, container, object_name, extra_metadata, driver=self)

    def _extract_backup_info_from_name(self, object_name):
        """Extract backup identification from object name.

        Object names follow the pattern:
        volume_{volume_id}/{timestamp}/az_{az}_backup_{backup_id}...

        :param object_name: The object name to parse
        :returns: dict with volume_id, backup_id, backup_time or empty dict
        """
        try:
            # Parse volume_id from path
            volume_match = re.search(r'volume_([a-f0-9-]+)', object_name)
            backup_match = re.search(r'backup_([a-f0-9-]+)', object_name)

            if not volume_match or not backup_match:
                LOG.warning(
                    f"Could not parse backup info from object name: {object_name}")
                return {}

            volume_id = volume_match.group(1)
            backup_id = backup_match.group(1)

            # Check if we have cached info for this backup
            if backup_id in self._manifests:
                # We already have the manifest, but need backup_time
                pass

            # Try to look up the backup from database to get created_at
            try:
                from cinder import objects
                backup = objects.Backup.get_by_id(self.context, backup_id)
                if backup and backup.created_at:
                    backup_time = int(backup.created_at.timestamp())
                    return {
                        'volume_id': volume_id,
                        'backup_id': backup_id,
                        'backup_time': backup_time,
                        'namespace': CONF.backup_proxmox_namespace,
                    }
            except Exception as e:
                LOG.debug(f"Could not look up backup {backup_id}: {e}")

            # Return partial info - manifest lookup might still work
            return {
                'volume_id': volume_id,
                'backup_id': backup_id,
            }
        except Exception as e:
            LOG.warning(
                f"Error extracting backup info from {object_name}: {e}")
            return {}

    def delete_object(self, container, object_name):
        """Delete object from PBS datastore.

        For PBS, individual objects (chunks) are managed automatically
        by the server via garbage collection. We only need to delete
        complete backup snapshots.
        """
        # PBS manages chunk deletion via garbage collection
        # Individual object deletion is not supported/needed
        LOG.debug(
            f"Delete object {object_name} requested - PBS manages chunks via GC")
        pass

    def _generate_object_name_prefix(self, backup):
        """Generate object name prefix for backup.

        PBS uses a different naming structure (backup-type/backup-id/timestamp)
        but we still need to provide this for compatibility with the parent class.
        """
        az = 'az_%s' % self.az
        backup_name = '%s_backup_%s' % (az, backup.id)
        volume = 'volume_%s' % (backup.volume_id)
        timestamp = timeutils.utcnow().strftime("%Y%m%d%H%M%S")
        prefix = volume + '/' + timestamp + '/' + backup_name
        LOG.debug('generate_object_name_prefix: %s', prefix)
        return prefix

    def get_object_digest(self, object_name, extra_metadata):
        """Get PBS digest for an object from manifest.

        :param object_name: Cinder object name to look up
        :param extra_metadata: Metadata containing backup identification
        :returns: PBS chunk digest (hex string) or None
        """
        backup_id = extra_metadata.get('backup_id')
        if not backup_id:
            return None

        # Check cache
        if backup_id in self._manifests:
            return self._manifests[backup_id].get(object_name)

        # Download manifest
        client = self._get_client()
        client.authenticate()
        datastore = CONF.backup_proxmox_datastore
        backup_type = 'host'
        pbs_backup_id = f"volume-{extra_metadata.get('volume_id')}"
        backup_time = extra_metadata.get('backup_time')

        if not backup_time:
            LOG.warning("No backup_time in metadata, cannot download manifest")
            return None

        try:
            # The manifest is stored as cinder-manifest.json.blob
            data = client.download_blob_direct(datastore, backup_type,
                                               pbs_backup_id, backup_time,
                                               "cinder-manifest.json.blob")
            if data:
                # data is already decoded by download_blob_direct for .blob files
                manifest = json.loads(data.decode('utf-8'))
                self._manifests[backup_id] = manifest
                LOG.debug(f"Loaded manifest with {len(manifest)} entries")
                return manifest.get(object_name)
        except Exception as e:
            LOG.warning(f"Failed to download manifest: {e}")

        return None

    def update_container_name(self, backup, container):
        """Update container name if needed.

        : param backup: Backup object
        : param container: Proposed container name
        : returns: Updated container name or None
        """
        # Use configured datastore
        return CONF.backup_proxmox_datastore

    def get_extra_metadata(self, backup, volume):
        """Get extra metadata for the backup."""
        # Ensure we use the same timestamp as _prepare_backup
        if backup.created_at:
            backup_time = int(backup.created_at.timestamp())
        else:
            backup_time = int(time.time())

        return {
            'volume_id': volume['id'],
            'volume_size': volume['size'],
            'backup_id': backup.id,
            'backup_time': backup_time,
            'datastore': CONF.backup_proxmox_datastore,
            'namespace': CONF.backup_proxmox_namespace,
        }

    def check_for_setup_error(self):
        """Verify PBS connection and configuration."""
        try:
            client = self._get_client()
            client.authenticate()
            LOG.info("Successfully connected to Proxmox Backup Server at %s:%s",
                     CONF.backup_proxmox_host, CONF.backup_proxmox_port)
        except Exception as e:
            msg = _("Failed to connect to Proxmox Backup Server: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def restore(self, backup, volume_id, volume_file, volume_is_new):
        """Restore metadata and volume data from PBS backup."""
        # 1. Connect to PBS
        client = self._get_client()
        client.authenticate()

        # Get backup metadata from service_metadata
        if not backup.service_metadata:
            msg = _("Backup has no service_metadata. Cannot restore - "
                    "backup may have been created with an older driver version.")
            LOG.error(msg)
            raise exception.BackupDriverException(msg)

        try:
            meta = json.loads(backup.service_metadata)
        except (json.JSONDecodeError, TypeError) as e:
            msg = _("Invalid service_metadata format: %s") % str(e)
            LOG.error(msg)
            raise exception.BackupDriverException(msg)

        backup_type = meta.get('backup_type', 'vm')
        backup_id = meta.get('backup_id', f"volume-{backup.volume_id}")
        backup_time = meta.get('backup_time')
        archive_name = meta.get('archive_name', 'volume.fidx')

        if not backup_time:
            msg = _("Missing backup_time in service_metadata")
            LOG.error(msg)
            raise exception.BackupDriverException(msg)

        LOG.info("Starting restore for %s (time: %s)", backup_id, backup_time)

        try:
            # 2. Start restore session
            client.create_restore(CONF.backup_proxmox_datastore,
                                  backup_type, backup_id, backup_time)

            # 3. Download manifest to get actual data size
            manifest = client.download_manifest()
            files = manifest.get('files', [])
            if not files:
                raise exception.BackupDriverException(
                    "No files found in backup manifest")

            # Get the actual size (without padding)
            actual_size = files[0].get('size', 0)
            LOG.info(f"Actual backup data size: {actual_size} bytes")

            # 4. Download Index (using archive_name from service_metadata)
            chunk_digests = client.download_index(archive_name)
            LOG.info(f"Downloaded index with {len(chunk_digests)} chunks")

            # 5. Calculate chunk size and how much to write
            chunk_size = CONF.backup_proxmox_chunk_size
            total_written = 0
            chunk_reader = PBSChunkReader(client)

            # 6. Download and write chunks
            for i, digest in enumerate(chunk_digests):
                chunk_data = chunk_reader.read_chunk(digest)

                # Calculate how much of this chunk to actually write
                remaining = actual_size - total_written
                bytes_to_write = min(len(chunk_data), remaining)

                if bytes_to_write > 0:
                    # Only write the actual data, not the padding
                    volume_file.write(chunk_data[:bytes_to_write])
                    total_written += bytes_to_write

                # Progress logging
                if i > 0 and i % 100 == 0:
                    progress = (total_written / actual_size *
                                100) if actual_size > 0 else 0
                    LOG.debug(f"Restored {i} / {len(chunk_digests)} chunks "
                              f"({progress:.1f}% complete)")

                # Stop if we've written all the data
                if total_written >= actual_size:
                    break

            LOG.info(
                f"Restore completed successfully. Wrote {total_written} bytes")

        except Exception as e:
            LOG.error(f"Restore failed: {e}")
            raise
        finally:
            if client.sock:
                client.sock.close()

    def delete_backup(self, backup):
        """Delete backup from PBS.

        This method is called when a backup is deleted from OpenStack dashboard.
        It removes the backup snapshot from Proxmox Backup Server using the
        exact backup_time that was stored during backup creation.

        :param backup: Backup object to delete
        """
        # Extract PBS backup information from service_metadata
        if not backup.service_metadata:
            LOG.warning("No service_metadata found for backup %s, "
                        "cannot delete from PBS", backup.id)
            return

        try:
            service_metadata = json.loads(backup.service_metadata)
        except (json.JSONDecodeError, TypeError) as e:
            LOG.error("Failed to parse service_metadata for backup %s: %s",
                      backup.id, str(e))
            return

        # Get PBS connection details from metadata
        backup_id = service_metadata.get('backup_id')
        backup_time = service_metadata.get('backup_time')
        backup_type = service_metadata.get('backup_type', 'vm')

        if not backup_id or not backup_time:
            LOG.warning("Missing backup_id or backup_time in service_metadata "
                        "for backup %s", backup.id)
            return

        LOG.info("Deleting backup from PBS: %s (time: %s)",
                 backup_id, backup_time)

        # Create PBS client and authenticate
        client = self._get_client()
        client.authenticate()

        # Delete the snapshot from PBS using the exact backup_time from metadata
        try:
            client.delete_snapshot(
                CONF.backup_proxmox_datastore,
                backup_type,
                backup_id,
                backup_time
            )
            LOG.info("Successfully deleted backup %s from PBS", backup.id)
        except exception.BackupDriverException as e:
            LOG.error("Failed to delete backup %s from PBS: %s",
                      backup.id, str(e))
            raise


def get_backup_driver(context):
    """Return a Proxmox Backup driver instance.

    : param context: Security context
    : returns: ProxmoxBackupDriver instance
    """
    return ProxmoxBackupDriver(context)
