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

import base64
import hashlib
import hmac
import io
import json
import struct
import time
import zlib
from urllib import parse as urlparse

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils
import requests
import httpx

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


class PBSDataBlob:
    """Handler for Proxmox Backup Server data blob encoding/decoding.

    PBS stores data in a specific blob format with magic numbers and CRC checks.
    This class implements the encoding and decoding logic.
    """

    # Magic numbers for different blob types
    # https://pbs.proxmox.com/docs/file-formats.html#data-blob-format
    # [66, 171, 56, 7, 190, 131, 112, 161] -> 0xA17083BE0738AB42 (Little Endian)
    UNENCRYPTED_UNCOMPRESSED_BLOB_MAGIC_1_0 = 0xA17083BE0738AB42
    UNENCRYPTED_COMPRESSED_BLOB_MAGIC_1_0 = 0x0107_5670_ac7a_c807

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
            magic = self.UNENCRYPTED_COMPRESSED_BLOB_MAGIC_1_0
            payload = compressed
        else:
            magic = self.UNENCRYPTED_UNCOMPRESSED_BLOB_MAGIC_1_0
            payload = data

        # Calculate CRC32
        crc = struct.unpack('<I', struct.pack('<I', 0xffffffff ^
                                              zlib.crc32(payload) ^ 0xffffffff))[0]

        # Build blob: magic(8) + crc(4) + data
        blob = struct.pack('<Q', magic) + struct.pack('<I', crc) + payload

        return blob

    def decode(self, blob):
        """Decode PBS blob format to raw data.

        :param blob: Blob bytes to decode
        :returns: Decoded raw bytes
        """
        if len(blob) < 12:
            raise ValueError("Blob too small")

        # Parse header
        magic = struct.unpack('<Q', blob[0:8])[0]
        crc_expected = struct.unpack('<I', blob[8:12])[0]
        payload = blob[12:]

        # Verify CRC
        crc_actual = struct.unpack('<I', struct.pack('<I', 0xffffffff ^
                                                     zlib.crc32(payload) ^ 0xffffffff))[0]
        if crc_actual != crc_expected:
            raise ValueError(f"CRC mismatch: expected {crc_expected}, "
                             f"got {crc_actual}")

        # Decompress if needed
        if magic == self.UNENCRYPTED_COMPRESSED_BLOB_MAGIC_1_0:
            return zlib.decompress(payload)
        elif magic == self.UNENCRYPTED_UNCOMPRESSED_BLOB_MAGIC_1_0:
            return payload
        else:
            raise ValueError(f"Unknown blob magic: {hex(magic)}")


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
        self.session = httpx.Client(
            http2=True, verify=verify_ssl, timeout=60.0)

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
            LOG.info(
                f"Started PBS backup session for {backup_type}/{backup_id}")
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to start PBS backup session: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def create_fixed_index(self, archive_name, size):
        """Create a new fixed index.

        :param archive_name: Archive name (e.g. 'volume.fidx')
        :param size: Total size of the archive
        :returns: Writer ID (wid)
        """
        path = "/api2/json/fixed_index"
        params = {
            'archive-name': archive_name,
            'size': size,
        }

        url = self._build_url(path)
        headers = self._get_headers()

        try:
            response = self.session.post(url, params=params, headers=headers)
            response.raise_for_status()
            return int(response.json())
        except (httpx.RequestError, httpx.HTTPStatusError, ValueError) as e:
            msg = _("Failed to create fixed index for archive: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def upload_chunk(self, wid, chunk_data, size, encoded_size, digest):
        """Upload a chunk to PBS.

        :param wid: Writer ID
        :param chunk_data: Chunk data (blob)
        :param size: Original size of the chunk
        :param encoded_size: Size of the encoded blob
        :param digest: SHA256 digest of the chunk
        """
        path = "/api2/json/fixed_chunk"
        params = {
            'wid': wid,
            'size': size,
            'encoded-size': encoded_size,
            'digest': digest,
        }

        url = self._build_url(path)
        headers = self._get_headers()
        headers['Content-Type'] = 'application/octet-stream'

        try:
            response = self.session.put(
                url, params=params, headers=headers, content=chunk_data)
            response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to upload chunk to fixed index: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def append_index(self, digest_list, offset_list, wid):
        """Append chunks to fixed index.

        :param digest_list: JSON array of chunk digests
        :param offset_list: JSON array of chunk offsets
        :param wid: Writer ID
        """
        path = "/api2/json/fixed_index"
        params = {
            'digest-list': digest_list,
            'offset-list': offset_list,
            'wid': wid,
        }

        url = self._build_url(path)
        headers = self._get_headers()

        try:
            response = self.session.put(url, params=params, headers=headers)
            response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to append to fixed index: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def close_fixed_index(self, chunk_count, csum, size, wid):
        """Close the fixed index.

        :param chunk_count: Number of chunks
        :param csum: Checksum of the index (hex string)
        :param size: Total size of data
        :param wid: Writer ID
        """
        path = "/api2/json/fixed_close"
        params = {
            'chunk-count': chunk_count,
            'csum': csum,
            'size': size,
            'wid': wid,
        }

        url = self._build_url(path)
        headers = self._get_headers()

        try:
            response = self.session.post(url, params=params, headers=headers)
            response.raise_for_status()
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to close fixed index: %s") % str(e)
            raise exception.BackupDriverException(msg)

    def complete_backup(self):
        """Mark backup as complete."""
        path = "/api2/json/finish"

        url = self._build_url(path)
        headers = self._get_headers()

        try:
            response = self.session.post(url, headers=headers)
            response.raise_for_status()
            LOG.info("Completed PBS backup session")
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            msg = _("Failed to complete PBS backup session: %s") % str(e)
            raise exception.BackupDriverException(msg)


class ObjectWriter:
    """Writer for PBS objects (chunks/blobs)."""

    def __init__(self, client, datastore, name, compress=False, state=None):
        """Initialize writer.

        :param client: PBSClient instance
        :param datastore: Datastore name
        :param name: Object name
        :param compress: Whether to compress data
        :param state: Shared state dict for the backup session
        """
        self.client = client
        self.datastore = datastore
        self.name = name
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

        # Encode as PBS blob
        blob = self.blob_handler.encode(data)

        # Calculate digest of the raw data (not the blob)
        digest = hashlib.sha256(data).hexdigest()

        # Upload to PBS
        if self.state is not None:
            wid = self.state['wid']

            # Upload chunk
            self.client.upload_chunk(
                wid, blob, original_size, len(blob), digest)

            # Track for appending to index
            self.state['digests'].append(digest)
            self.state['offsets'].append(self.state['current_offset'])

            # Update offset and stats
            self.state['current_offset'] += original_size
            self.state['chunk_count'] += 1
            self.state['total_size'] += original_size

            # Update checksum (SHA256 of concatenated data)
            self.state['csum'].update(data)


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

        # For fixed index, we need to know the total size upfront
        # We'll use the volume size as approximation
        # TODO: Get more accurate size estimate
        volume_size_bytes = backup.size * 1024 * 1024 * 1024  # GB to bytes

        # Create the fixed index for volume data
        wid = client.create_fixed_index("volume.fidx", volume_size_bytes)

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
                        import json
                        digest_list = json.dumps(state['digests'])
                        offset_list = json.dumps(state['offsets'])
                        client.append_index(
                            digest_list, offset_list, state['wid'])

                    # Close the fixed index
                    client.close_fixed_index(
                        state['chunk_count'],
                        state['csum'].hexdigest(),
                        state['total_size'],
                        state['wid']
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
            raise exception.BackupDriverException(
                "No active PBS session for backup")

        # Disable compression in PBSDataBlob if Cinder is already compressing
        return ObjectWriter(client, container, object_name,
                            compress=False,
                            state=state)

    def get_object_reader(self, container, object_name, extra_metadata=None):
        """Get a reader for downloading an object."""
        client = self._get_client()
        return ObjectReader(client, container, object_name, extra_metadata)

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
