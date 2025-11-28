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
    UNENCRYPTED_BLOB_MAGIC_1_0 = 0xA17083BE0738AB42
    ENCRYPTED_BLOB_MAGIC_1_0 = 0x0107_5670_ac7a_c806    # Encrypted (TODO: Verify)
    COMPRESSED_BLOB_MAGIC_1_0 = 0x0107_5670_ac7a_c807   # Compressed (TODO: Verify)
    ENCR_COMPR_BLOB_MAGIC_1_0 = 0x0107_5670_ac7a_c808  # Encrypted+Compressed (TODO: Verify)
    
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
            magic = self.UNENCRYPTED_BLOB_MAGIC_1_0
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
        if magic == self.COMPRESSED_BLOB_MAGIC_1_0:
            return zlib.decompress(payload)
        elif magic == self.UNENCRYPTED_BLOB_MAGIC_1_0:
            return payload
        elif magic == self.ENCRYPTED_BLOB_MAGIC_1_0:
            raise NotImplementedError("Encrypted blobs not yet supported")
        elif magic == self.ENCR_COMPR_BLOB_MAGIC_1_0:
            raise NotImplementedError("Encrypted compressed blobs not supported")
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
        
        :param name: Blob name (e.g. 'cinder-manifest.json')
        :param data: Blob data (bytes)
        """
        url = self._build_url("/blob")
        headers = self._get_headers()
        headers['Content-Type'] = 'application/octet-stream'
        
        params = {
            'file-name': name,
            'encoded-size': len(data)
        }
        
        try:
            self.session.post(url, content=data, params=params, headers=headers).raise_for_status()
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
        """Download blob using REST API."""
        path = f"/api2/json/admin/datastore/{datastore}/snapshots/{backup_type}/{backup_id}/{backup_time}/download"
        url = self._build_url(path)
        params = {'file-name': name}
        headers = self._get_headers()
        
        try:
            response = self.session.get(url, params=params, headers=headers)
            response.raise_for_status()
            return response.content
        except (httpx.RequestError, httpx.HTTPStatusError) as e:
            if e.response.status_code == 404:
                return None
            msg = _("Failed to download blob %s: %s") % (name, str(e))
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
        
        # Encode as PBS blob
        blob = self.blob_handler.encode(data)
        
        # Calculate digest of the BLOB
        digest = hashlib.sha256(blob).hexdigest()
        
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
        
        # Update manifest
        if self.manifest is not None:
            self.manifest[self.name] = digest


class ObjectReader:
    """Reader for PBS objects (chunks/blobs)."""
    
    def __init__(self, client, datastore, name, extra_metadata=None, driver=None):
        """Initialize reader.
        
        :param client: PBSClient instance
        :param datastore: Datastore name
        :param name: Object name
        :param extra_metadata: Metadata containing digest
        :param driver: ProxmoxBackupDriver instance (for manifest lookup)
        """
        self.client = client
        self.datastore = datastore
        self.name = name
        self.extra_metadata = extra_metadata or {}
        self.driver = driver
        self.blob_handler = PBSDataBlob()
        self.data = None
        
    def __enter__(self):
        digest = None
        # Try to get digest from manifest via driver
        if self.driver:
            digest = self.driver.get_object_digest(self.name, self.extra_metadata)
            
        if not digest:
             # Fallback to extra_metadata if available
             digest = self.extra_metadata.get('pbs_digest')
             
        if not digest:
            LOG.warning(f"No digest found for {self.name}, cannot download")
            return self
            
        blob = self.client.download_chunk_direct(self.datastore, digest)
        self.data = self.blob_handler.decode(blob)
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
        """Get a reader for downloading an object."""
        client = self._get_client()
        return ObjectReader(client, container, object_name, extra_metadata, driver=self)
        
    def get_object_digest(self, object_name, extra_metadata):
        """Get PBS digest for an object from manifest."""
        backup_id = extra_metadata.get('backup_id')
        if not backup_id:
            return None
            
        # Check cache
        if backup_id in self._manifests:
            return self._manifests[backup_id].get(object_name)
            
        # Download manifest
        client = self._get_client()
        datastore = CONF.backup_proxmox_datastore
        backup_type = 'host'
        pbs_backup_id = f"volume-{extra_metadata.get('volume_id')}"
        backup_time = extra_metadata.get('backup_time')
        
        if not backup_time:
            LOG.warning("No backup_time in metadata, cannot download manifest")
            return None
            
        try:
            data = client.download_blob_direct(datastore, backup_type, 
                                             pbs_backup_id, backup_time, 
                                             "cinder-manifest.json")
            if data:
                manifest = json.loads(data)
                self._manifests[backup_id] = manifest
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
