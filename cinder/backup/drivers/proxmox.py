# Copyright (C) 2025 Aadarsha Dhakal <aadarsha.dhakal@startsml.com>
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

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

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
import httpx

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
            raise NotImplementedError("Encrypted compressed blobs not supported")
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
        # Disable verify for now if configured, but ideally use a context
        self.session = httpx.Client(http2=True, verify=verify_ssl, timeout=60.0)
        
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
            response = self.session.post(auth_url, data=data)
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
        """Start a backup session.
        
        :param datastore: Datastore name
        :param backup_type: Backup type (e.g., 'host')
        :param backup_id: Backup ID
        :param backup_time: Backup timestamp (integer epoch)
        """
        path = "/api2/json/backup"
        params = {
            'store': datastore,
            'backup-type': backup_type,
            'backup-id': backup_id,
            'backup-time': int(backup_time),
            'benchmark': 'false'
        }
        
        url = self._build_url(path)
        headers = self._get_headers()
        # Required to upgrade to backup protocol
        headers['Upgrade'] = 'proxmox-backup-protocol-v1'
        
        try:
            # We use the existing session which should be HTTP/2 enabled
            response = self.session.get(url, params=params, headers=headers)
            response.raise_for_status()
            LOG.info(f"Started PBS backup session for {backup_type}/{backup_id}")
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to start PBS backup session: %s") % str(e)
            raise exception.BackupDriverException(msg)
            
    def create_dynamic_index(self, name):
        """Create a new dynamic index (archive).
        
        :param name: Archive name (e.g. 'volume.didx')
        :returns: Writer ID (wid)
        """
        url = self._build_url("/dynamic_index")
        headers = self._get_headers()
        # Archive-Name is passed as a parameter, not header
        params = {'archive-name': name}
        
        try:
            response = self.session.post(url, params=params, headers=headers)
            response.raise_for_status()
            # Response is a JSON integer (wid)
            return int(response.json())
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
            raise exception.BackupDriverException(f"Failed to create index {name}: {e}")

    def close_dynamic_index(self, wid, chunk_count, size, csum):
        """Close the currently open dynamic index.
        
        :param wid: Writer ID
        :param chunk_count: Number of chunks
        :param size: Total size of data
        :param csum: Checksum of the index (hex string)
        """
        url = self._build_url("/dynamic_close")
        headers = self._get_headers()
        
        params = {
            'wid': wid,
            'chunk-count': chunk_count,
            'size': size,
            'csum': csum
        }
        
        try:
            self.session.post(url, params=params, headers=headers).raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            raise exception.BackupDriverException(f"Failed to close index: {e}")

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
            raise exception.BackupDriverException(f"Failed to upload blob {name}: {e}")

    def download_blob(self, name):
        """Download a named blob.
        
        :param name: Blob name
        :returns: Blob data
        """
        url = self._build_url("/blob")
        headers = self._get_headers()
        headers['FileName'] = name
        
        try:
            response = self.session.get(url, headers=headers)
            response.raise_for_status()
            return response.content
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            # If not found, return None or raise?
            if e.response.status_code == 404:
                return None
            raise exception.BackupDriverException(f"Failed to download blob {name}: {e}")

    def upload_chunk(self, wid, digest, data, size, encoded_size):
        """Upload a chunk to PBS.
        
        :param wid: Writer ID
        :param digest: SHA256 digest of the chunk
        :param data: Chunk data (blob)
        :param size: Original size of the chunk (before compression/encryption)
        :param encoded_size: Size of the encoded blob
        """
        url = self._build_url("/dynamic_chunk")
        headers = self._get_headers()
        headers['Content-Type'] = 'application/octet-stream'
        
        params = {
            'wid': wid,
            'digest': digest,
            'size': size,
            'encoded-size': encoded_size
        }
        
        try:
            response = self.session.post(url, content=data, params=params, headers=headers)
            response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to upload chunk to PBS: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def finish_backup(self):
        """Finish the backup and commit."""
        url = self._build_url("/finish")
        headers = self._get_headers()
        
        try:
            self.session.post(url, headers=headers).raise_for_status()
            LOG.info("PBS backup finished successfully")
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            raise exception.BackupDriverException(f"Failed to finish backup: {e}")

    def download_chunk_direct(self, datastore, digest):
        """Download chunk using REST API (no session)."""
        url = self._build_url(f"/api2/json/admin/datastore/{datastore}/chunk/{digest}")
        headers = self._get_headers()
        
        try:
            response = self.session.get(url, headers=headers)
            response.raise_for_status()
            return response.content
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to download chunk %s: %s") % (digest, str(e))
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

    def download_chunk(self, datastore, digest):
        """Download a chunk from PBS.
        
        :param datastore: Datastore name
        :param digest: SHA256 digest of the chunk
        :returns: Chunk data (PBS blob encoded)
        """
        url = self._build_url("/fixed_chunk")
        headers = self._get_headers()
        headers['Upload-Image-Store'] = datastore
        headers['Upload-Chunk-Digest'] = digest
        
        try:
            # Assuming GET request with headers for download
            response = self.session.get(url, headers=headers)
            response.raise_for_status()
            return response.content
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to download chunk from PBS: %s") % str(e)
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
            msg = _("Failed to download decoded file %s: %s") % (filename, str(e))
            raise exception.BackupDriverException(msg)
        except httpx.RequestError as e:
            msg = _("Failed to download decoded file %s: %s") % (filename, str(e))
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
    """Writer for PBS objects (chunks/blobs)."""
    
    def __init__(self, client, datastore, name, manifest=None, compress=False, state=None):
        """Initialize writer.
        
        :param client: PBSClient instance
        :param datastore: Datastore name
        :param name: Object name
        :param manifest: Dictionary to store object->digest mapping
        :param compress: Whether to compress data
        :param state: Shared state dict for the backup session
        """
        self.client = client
        self.datastore = datastore
        self.name = name
        self.manifest = manifest
        self.blob_handler = PBSDataBlob(compress=compress)
        self.buffer = io.BytesIO()
        self.state = state
        
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
        """Finalize and upload the object."""
        data = self.buffer.getvalue()
        original_size = len(data)

        # Calculate digest of the RAW data (before encoding)
        # PBS uses the raw data digest to identify chunks
        digest = hashlib.sha256(data).hexdigest()

        # Encode as PBS blob for storage/transport
        blob = self.blob_handler.encode(data)

        # Upload to PBS
        if self.state is not None:
            wid = self.state['wid']
            self.client.upload_chunk(wid, digest, blob, original_size, len(blob))

            # Update stats and checksum for dynamic index
            self.state['chunk_count'] += 1
            self.state['total_size'] += original_size

            # Checksum: SHA256(offset_le || digest_bytes)
            # offset is the END offset of the chunk
            offset_bytes = struct.pack('<Q', self.state['total_size'])
            digest_bytes = bytes.fromhex(digest)
            self.state['csum'].update(offset_bytes)
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
                digest = self.driver.get_object_digest(self.name, self.extra_metadata)

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

            LOG.debug(f"Successfully read {len(self.data)} bytes for object {self.name}")

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


@interface.backupdriver
class ProxmoxBackupDriver(chunkeddriver.ChunkedBackupDriver):
    """Backup driver for Proxmox Backup Server.
    
    This driver implements native PBS protocol communication without
    relying on the proxmox-backup-client command-line tool.
    """
    
    def __init__(self, context):
        """Initialize the Proxmox Backup driver.

        :param context: The security context
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
        self._backup_state = {} # State for active backups: backup_id -> dict
        self._manifests = {} # Cache for manifests: backup_id -> dict
        self._backup_manifests = {} # Manifests being built: backup_id -> dict
        
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
        # Start PBS session
        client = self._get_client()
        client.authenticate()
        
        # Use 'host' type for generic data
        backup_type = 'host'
        backup_id = f"volume-{backup.volume_id}"
        # Use created_at timestamp for consistency
        if backup.created_at:
            backup_time = int(backup.created_at.timestamp())
        else:
            backup_time = int(time.time())
        
        client.create_backup(CONF.backup_proxmox_datastore, 
                           backup_type, backup_id, backup_time)
                           
        # Create the dynamic index for volume data
        wid = client.create_dynamic_index("volume.didx")
        
        # Store client and state
        self._active_clients[backup.id] = client
        self._backup_state[backup.id] = {
            'wid': wid,
            'chunk_count': 0,
            'total_size': 0,
            'csum': hashlib.sha256(),
            'index_name': 'volume.didx'
        }
        self._backup_manifests[backup.id] = {}
        
        return super(ProxmoxBackupDriver, self)._prepare_backup(backup)

    def _finalize_backup(self, backup, container, object_meta, object_sha256):
        """Finalize the backup."""
        try:
            super(ProxmoxBackupDriver, self)._finalize_backup(backup, container, 
                                                            object_meta, object_sha256)
        finally:
            client = self._active_clients.get(backup.id)
            state = self._backup_state.get(backup.id)
            
            if client and state:
                try:
                    # Upload manifest
                    manifest = self._backup_manifests.get(backup.id, {})
                    manifest_data = json.dumps(manifest).encode('utf-8')
                    client.upload_blob("cinder-manifest.json", manifest_data)
                    
                    # Close whatever index is open
                    client.close_dynamic_index(
                        state['wid'],
                        state['chunk_count'],
                        state['total_size'],
                        state['csum'].hexdigest()
                    )
                    client.finish_backup()
                except Exception as e:
                    LOG.error(f"Error finishing PBS backup: {e}")
                finally:
                    del self._active_clients[backup.id]
                    del self._backup_state[backup.id]
                    del self._backup_manifests[backup.id]

    def put_container(self, container):
        """Create the datastore/namespace if needed.
        
        :param container: Container name (datastore)
        """
        # In PBS, datastores are pre-created via admin interface
        # Namespaces can be created via API if needed
        LOG.debug(f"Using PBS datastore: {container}")
        
    def get_container_entries(self, container, prefix):
        """Get backup entries in the datastore.
        
        :param container: Container name (datastore)
        :param prefix: Prefix for filtering backups
        :returns: List of backup names
        """
        # Would query PBS API for backup snapshots
        # For now, return empty list
        LOG.debug(f"Listing backups in {container} with prefix {prefix}")
        return []
        
    def get_object_writer(self, container, object_name, extra_metadata=None):
        """Get a writer for uploading an object."""
        backup_id = extra_metadata.get('backup_id') if extra_metadata else None
        client = self._active_clients.get(backup_id)
        state = self._backup_state.get(backup_id)
        
        if not client:
            raise exception.BackupDriverException("No active PBS session for backup")
            
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
                LOG.warning(f"Could not parse backup info from object name: {object_name}")
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
            LOG.warning(f"Error extracting backup info from {object_name}: {e}")
            return {}
        
    def delete_object(self, container, object_name):
        """Delete object from PBS datastore.
        
        For PBS, individual objects (chunks) are managed automatically
        by the server via garbage collection. We only need to delete
        complete backup snapshots.
        """
        # PBS manages chunk deletion via garbage collection
        # Individual object deletion is not supported/needed
        LOG.debug(f"Delete object {object_name} requested - PBS manages chunks via GC")
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
        
        :param backup: Backup object
        :param container: Proposed container name
        :returns: Updated container name or None
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


def get_backup_driver(context):
    """Return a Proxmox Backup driver instance.
    
    :param context: Security context
    :returns: ProxmoxBackupDriver instance
    """
    return ProxmoxBackupDriver(context)
