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

import base64
import hashlib
import hmac
import io
import json
import socket
import ssl
import struct
import time
import zlib
from urllib import parse as urlparse

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
import requests
import httpx
import h2.connection
import h2.config
import h2.events

from cinder.backup import chunkeddriver
from cinder import exception
from cinder.i18n import _
from cinder import interface
from cinder.utils import retry

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


class PBSChunk:
    """Handler for Proxmox Backup Server chunk data.

    For fixed index, chunks are stored in blob format with magic bytes and CRC32.
    Reference: https://pbs.proxmox.com/docs/file-formats.html#data-blob-format
    """

    # Data blob magic numbers (unencrypted, uncompressed)
    MAGIC_UNCOMPRESSED = bytes([66, 171, 56, 7, 190, 131, 112, 161])

    def __init__(self):
        """Initialize chunk handler for fixed index."""
        pass

    def encode(self, data):
        """Wrap data in PBS blob format (unencrypted, uncompressed).

        Format: MAGIC (8 bytes) + CRC32 (4 bytes) + Data

        :param data: Raw bytes to store
        :returns: Blob-wrapped chunk data
        """
        crc = zlib.crc32(data)
        blob = self.MAGIC_UNCOMPRESSED + struct.pack('<I', crc) + data
        return blob

    def decode(self, chunk_data):
        """Decode chunk data from blob format.

        :param chunk_data: Blob-wrapped chunk bytes
        :returns: Decoded raw bytes
        """
        # Skip magic (8 bytes) and CRC32 (4 bytes)
        return chunk_data[12:]


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
            if self.sock:
                self.sock.close()
                self.sock = None
            msg = _("Failed to start PBS backup session: %s") % str(e)
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

    def upload_chunk(self, wid, chunk_data, size, encoded_size, digest):
        """Upload a chunk to PBS.

        :param wid: Writer ID
        :param chunk_data: Chunk data (blob)
        :param size: Original size of the chunk
        :param encoded_size: Size of the encoded blob
        :param digest: SHA256 digest of the chunk
        """
        path = "/fixed_chunk"
        params = {
            'wid': wid,
            'digest': digest,
            'size': size,
            'encoded-size': encoded_size,
        }

        try:
            headers, data = self._h2_request(
                'POST', path, params=params, body=chunk_data)
        except Exception as e:
            msg = _("Failed to upload chunk: %s") % str(e)
            raise exception.BackupDriverException(msg)

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

    def complete_backup(self):
        """Mark backup as complete."""
        path = "/finish"

        try:
            headers, data = self._h2_request('POST', path)
            LOG.info("Completed PBS backup session")
        except Exception as e:
            msg = _("Failed to complete PBS backup session: %s") % str(e)
            raise exception.BackupDriverException(msg)
        finally:
            # Close socket connection
            if self.sock:
                self.sock.close()
                self.sock = None
            self.h2_conn = None


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
        from oslo_config import cfg
        self.fixed_chunk_size = cfg.CONF.backup_proxmox_chunk_size

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
        
        if len(data) == 0:
            return
            
        # For fixed index, all chunks except the last MUST be exactly chunk_size
        # If this chunk is less than chunk_size, we need to pad it with zeros
        # to make it a full chunk, UNLESS it's truly the last chunk
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
                
                from oslo_log import log as logging
                LOG = logging.getLogger(__name__)
                LOG.debug(f"Padded chunk from {original_size} to {chunk_size} bytes")
            
            # Wrap chunk in blob format
            chunk_data = self.chunk_handler.encode(data)
            
            # Calculate digest from the padded chunk data
            digest = hashlib.sha256(data).hexdigest()
            
            wid = self.state['wid']

            # Upload chunk (size = padded size, encoded_size = blob size)
            self.client.upload_chunk(
                wid, chunk_data, chunk_size, len(chunk_data), digest)

            # Track for appending to index - use original offset
            self.state['digests'].append(digest)
            self.state['offsets'].append(self.state['current_offset'])

            # Update offset and stats - use PADDED size for offset calculation
            self.state['current_offset'] += chunk_size
            self.state['chunk_count'] += 1
            self.state['total_size'] += chunk_size

            # Update index_csum: SHA256(digest1||digest2||...)
            # Convert hex digest to bytes and update running hash
            digest_bytes = bytes.fromhex(digest)
            self.state['csum'].update(digest_bytes)


class ObjectReader:
    """Reader for PBS objects - not implemented for fixed index restore."""

    def __init__(self, client, datastore, name, extra_metadata=None):
        """Initialize reader.

        :param client: PBSClient instance
        :param datastore: Datastore name
        :param name: Object name
        :param extra_metadata: Metadata
        """
        self.client = client
        self.datastore = datastore
        self.name = name
        self.extra_metadata = extra_metadata or {}
        self.data = None

    def __enter__(self):
        # Restore not yet implemented for fixed index
        LOG.warning(
            "Restore not yet implemented for Proxmox fixed index backups")
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
        }

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
                except Exception as e:
                    LOG.error(f"Error finishing PBS backup: {e}")
                    raise
                finally:
                    del self._active_clients[backup.id]
                    del self._backup_state[backup.id]

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
        LOG.debug(f"Delete object {object_name} from {container}")
        # TODO: Implement snapshot deletion via PBS API if needed
        pass

    def get_object_writer(self, container, object_name, extra_metadata=None):
        """Get a writer for uploading an object."""
        backup_id = extra_metadata.get('backup_id') if extra_metadata else None
        client = self._active_clients.get(backup_id)
        state = self._backup_state.get(backup_id)

        if not client:
            raise exception.BackupDriverException(
                "No active PBS session for backup")

        # For fixed index, chunks are stored as raw data
        return ObjectWriter(client, container, object_name, state=state)

    def get_object_reader(self, container, object_name, extra_metadata=None):
        """Get a reader for downloading an object."""
        client = self._get_client()
        return ObjectReader(client, container, object_name, extra_metadata)

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


def get_backup_driver(context):
    """Return a Proxmox Backup driver instance.

    : param context: Security context
    : returns: ProxmoxBackupDriver instance
    """
    return ProxmoxBackupDriver(context)
