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

"""
Cinder Backup Driver for Proxmox Backup Server (PBS).
"""

import hashlib
import json
import os
import time

from oslo_config import cfg
from oslo_log import log as logging
from oslo_utils import timeutils

from cinder.backup import chunkeddriver
from cinder import exception
from cinder.i18n import _
from cinder import interface
from cinder.backup.drivers.proxmox_client import PBSClient, FixedIndex, PBSBlob

LOG = logging.getLogger(__name__)

proxmoxbackup_service_opts = [
    cfg.StrOpt('backup_proxmox_host',
               help='The hostname or IP address of the Proxmox Backup Server'),
    cfg.PortOpt('backup_proxmox_port',
                default=8007,
                help='The port of the Proxmox Backup Server'),
    cfg.StrOpt('backup_proxmox_user',
               default='root@pam',
               help='Username for Proxmox Backup Server authentication'),
    cfg.StrOpt('backup_proxmox_password',
               secret=True,
               help='Password for Proxmox Backup Server authentication'),
    cfg.StrOpt('backup_proxmox_datastore',
               default='datastore1',
               help='The datastore name on Proxmox Backup Server'),
    cfg.BoolOpt('backup_proxmox_verify_ssl',
                default=True,
                help='Verify SSL certificates'),
    cfg.StrOpt('backup_proxmox_fingerprint',
               default=None,
               help='Optional SHA256 fingerprint of the PBS server certificate'),
    cfg.IntOpt('backup_proxmox_chunk_size',
               default=4 * 1024 * 1024,  # 4MB
               help='The size in bytes of PBS backup chunks (Fixed Chunking)'),
]

CONF = cfg.CONF
CONF.register_opts(proxmoxbackup_service_opts)


@interface.backupdriver
class ProxmoxBackupDriver(chunkeddriver.ChunkedBackupDriver):
    """Provides backup, restore and delete of backup volume within PBS."""

    def __init__(self, context):
        chunk_size_bytes = CONF.backup_proxmox_chunk_size
        sha_block_size_bytes = chunk_size_bytes  # Use same size for tracking
        backup_default_container = CONF.backup_proxmox_datastore
        enable_progress_timer = True
        
        super(ProxmoxBackupDriver, self).__init__(
            context,
            chunk_size_bytes,
            sha_block_size_bytes,
            backup_default_container,
            enable_progress_timer
        )
        
        self.pbs_client = PBSClient(
            host=CONF.backup_proxmox_host,
            port=CONF.backup_proxmox_port,
            user=CONF.backup_proxmox_user,
            password=CONF.backup_proxmox_password,
            datastore=CONF.backup_proxmox_datastore,
            verify_ssl=CONF.backup_proxmox_verify_ssl,
            fingerprint=CONF.backup_proxmox_fingerprint
        )

    def _get_compressor(self, algorithm):
        # PBS handles its own compression/blob format, so Cinder shouldn't compress
        return None

    def put_container(self, container):
        # Datastore usage handled in client init
        pass

    def get_container_entries(self, container, prefix):
        # TODO: Implement if needed for incremental support validation
        return []

    def get_object_writer(self, container, object_name, extra_metadata=None):
        # Not used in this implementation (we use custom loop)
        raise NotImplementedError()

    def get_object_reader(self, container, object_name, extra_metadata=None):
        # Not used in this implementation (we use custom loop)
        raise NotImplementedError()

    def delete_backup(self, backup):
        """Delete backup from PBS."""
        # 1. Prepare Metadata
        try:
            meta = json.loads(backup.service_metadata)
            backup_type = meta['backup_type']
            backup_id = meta['backup_id']
            backup_time = meta['backup_time']
        except (ValueError, TypeError, KeyError):
            # If we can't parse metadata, we can't reliably delete from PBS.
            # But we should clear the Cinder record.
            LOG.warning(f"Could not parse service_metadata for backup {backup.id}. Skipping PBS deletion.")
            return

        # 2. Check/Delete
        try:
            self.pbs_client.delete_snapshot(backup_type, backup_id, backup_time)
        except Exception as e:
            LOG.error(f"Failed to delete backup from PBS: {e}")
            raise

    def delete_object(self, container, object_name):
        """Delete object from container."""
        # Not used in PBS driver as we manage snapshots/chunks differently.
        # But must be implemented as it's abstract.
        pass

    def _generate_object_name_prefix(self, backup):
        """Generates a prefix for the object's name."""
        return backup.id

    def update_container_name(self, backup, container):
        """Allow sub-classes to override container name."""
        return container

    def get_extra_metadata(self, backup, volume):
        """Return extra metadata to use in prepare_backup."""
        return {}

    def check_for_setup_error(self):
        if not CONF.backup_proxmox_host:
            raise exception.InvalidConfigurationValue(option='backup_proxmox_host', value=None)

    def backup(self, backup, volume_file, backup_metadata=True):
        """Backup the volume to PBS."""
        # 1. Prepare Metadata
        backup_type = 'vm' # TODO: Maybe 'host' or 'ct'? Using 'vm' for generic block logic
        backup_id = backup.id
        backup_time = int(time.time())
        
        LOG.info(f"Starting backup {backup_id} to PBS {self.pbs_client.host}")
        
        # 2. Connect & Start Session
        self.pbs_client.connect(backup_type, backup_id, backup_time, mode='backup')
        
        # 3. Create Fixed Index
        archive_name = "volume.fidx"
        volume_size = backup.size * 1024 * 1024 * 1024 # GB to Bytes
        
        # Get wid (Writer ID)
        resp_body = self.pbs_client.create_fixed_index(archive_name, volume_size)
        wid = json.loads(resp_body)['data']
        
        # 4. Read & Upload Chunks
        # We enforce strict 4MB fixed chunks
        chunk_size = self.chunk_size_bytes
        digests = []
        offsets = []
        current_offset = 0
        
        chunk_count = 0
        all_digests = bytearray()
        
        # We read from volume_file
        # Note: In Cinder, volume_file is a file-like object (e.g. /dev/nbd0 or a pipe)
        
        while True:
            data = volume_file.read(chunk_size)
            if not data:
                break
                
            # Pad last chunk if needed to match PBS fixed alignment requirements? 
            # PBS fixed index expects aligned chunks. The last chunk is allowed to be smaller.
            # But strict alignment for middle chunks is required.
            
            # Pad last chunk if needed?
            # PBS fixed index chunking doesn't strictly require padding for the last chunk.

            # Encode data to PBS Blob
            blob = PBSBlob.encode(data)
            
            # Calculate Digest of the BLOB (not raw data)
            hasher = hashlib.sha256()
            hasher.update(blob)
            digest_bytes = hasher.digest()
            digest = hasher.hexdigest()
            
            # Index check sum tracks the digest list (of blobs)
            all_digests.extend(digest_bytes)
            
            # Upload Chunk (passing the blob)
            self.pbs_client.upload_fixed_chunk(wid, blob, digest, len(data))
            
            digests.append(digest)
            offsets.append(current_offset)
            
            current_offset += len(data) # Offset is still based on RAW volume size
            chunk_count += 1
            
            # Append to index periodically
            if len(digests) >= 1000:
                self.pbs_client.append_fixed_index(wid, digests, offsets)
                digests = []
                offsets = []
        
        # Append remaining
        if digests:
            self.pbs_client.append_fixed_index(wid, digests, offsets)
            
        # 5. Close Fixed Index
        index_csum = hashlib.sha256(all_digests).hexdigest()
        
        self.pbs_client.close_fixed_index(wid, chunk_count, volume_size, index_csum)
        
        # 6. Upload Manifest (index.json)
        manifest_data = {
            "backup-type": backup_type,
            "backup-id": backup_id,
            "backup-time": backup_time,
            "files": [
                {
                    "filename": archive_name,
                    "size": volume_size,
                    "csum": index_csum, # Matches index close
                    "crypt-mode": "none"
                }
            ]
        }
        
        self.pbs_client.upload_blob("index.json.blob", json.dumps(manifest_data).encode())
        
        # 7. Finish
        self.pbs_client.finish()
        
        # 8. Save Service Metadata (Cinder DB)
        # We need to save coords to find this backup later
        service_metadata = {
            'backup_type': backup_type,
            'backup_id': backup_id,
            'backup_time': backup_time,
            'offset': 0,
            'length': volume_size
        }
        backup.service_metadata = json.dumps(service_metadata)
        backup.save()
        
        LOG.info("Backup complete.")

    def restore(self, backup, volume_id, volume_file, volume_is_new):
        """Restore volume from PBS."""
        meta = json.loads(backup.service_metadata)
        backup_type = meta['backup_type']
        backup_id = meta['backup_id']
        backup_time = meta['backup_time']
        
        LOG.info(f"Starting restore of {backup_id} from PBS...")
        
        # 1. Connect (Restore Mode)
        self.pbs_client.connect(backup_type, backup_id, backup_time, mode='restore')
        
        # 2. Download Manifest (to get list of files)
        # Try finding the .fidx file
        # Usually it's volume.fidx
        archive_name = "volume.fidx"
        
        # 3. Download Index
        index_data = self.pbs_client.download_file(archive_name)
        # This returns the raw .fidx content (which uses the FixedIndex format)
        
        # 4. Parse Index to get Chunk List
        digests = FixedIndex.parse_digests(index_data)
        
        # 5. Iterate and Download Chunks
        for i, digest in enumerate(digests):
            # Download
            blob = self.pbs_client.download_chunk(digest)
            # Blob Decode happened in client? 
            # - client.download_chunk calls PBSBlob.decode(data)
            # So 'blob' here is actually the raw volume data.
            
            volume_file.write(blob)
            
            if i % 100 == 0:
                LOG.debug(f"Restored chunk {i} / {len(digests)}")
                
        # 6. Finish
        # No explicit finish for restore session in PBS (it's just a reader)
        pass 

