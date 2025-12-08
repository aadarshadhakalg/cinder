#!/usr/bin/env python3
"""Test PBS client for creating a fixed index backup."""

import httpx
import time
import hashlib
import json
import struct
import zlib


class PBSClient:
    """Simple PBS client to test fixed index creation with HTTP/2 upgrade."""

    # Data blob magic numbers (unencrypted, uncompressed)
    MAGIC_UNCOMPRESSED = bytes([66, 171, 56, 7, 190, 131, 112, 161])

    def __init__(self, host, port, user, password):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.base_url = f"https://{host}:{port}"
        self.ticket = None
        self.csrf_token = None
        self.backup_session = None

    def authenticate(self):
        """Authenticate and get ticket/CSRF token."""
        url = f"{self.base_url}/api2/json/access/ticket"
        data = {
            'username': self.user,
            'password': self.password,
        }

        with httpx.Client(verify=False, timeout=60.0) as client:
            response = client.post(url, data=data)
            response.raise_for_status()
            result = response.json()

        self.ticket = result['data']['ticket']
        self.csrf_token = result['data']['CSRFPreventionToken']
        print(f"✓ Authenticated as {self.user}")

    def _get_headers(self):
        """Get HTTP headers with authentication."""
        if not self.ticket:
            self.authenticate()

        return {
            'CSRFPreventionToken': self.csrf_token,
            'Cookie': f'PBSAuthCookie={self.ticket}',
        }

    def start_backup_session(self, datastore, backup_type, backup_id, backup_time):
        """Start a backup session via HTTP/2 upgrade."""
        url = f"{self.base_url}/api2/json/backup"
        params = {
            'store': datastore,
            'backup-type': backup_type,
            'backup-id': backup_id,
            'backup-time': int(backup_time),
            'benchmark': 'false',
        }

        headers = self._get_headers()
        headers['Connection'] = 'upgrade'
        headers['UPGRADE'] = 'proxmox-backup-protocol-v1'

        print(f"Starting backup session: {backup_type}/{backup_id}")

        with httpx.Client(http2=True, verify=False, timeout=60.0) as client:
            response = client.get(url, params=params, headers=headers)
            if response.status_code != 101:
                raise Exception(
                    f"Upgrade failed: {response.status_code} {response.text}")

        # Store backup session info
        self.backup_session = {
            'store': datastore,
            'backup-type': backup_type,
            'backup-id': backup_id,
            'backup-time': int(backup_time),
        }

        print(f"✓ Started backup session: {backup_type}/{backup_id}")

    # Alias for compatibility
    def upgrade_to_h2(self, datastore, backup_type, backup_id, backup_time):
        """Alias for start_backup_session."""
        return self.start_backup_session(datastore, backup_type, backup_id, backup_time)

    def create_fixed_index(self, archive_name, size):
        """Create a fixed index using REST API."""
        path = "/fixed_index"
        params = {
            'archive-name': archive_name,
            'size': size,
        }
        params.update(self.backup_session)

        url = f"{self.base_url}{path}"
        headers = self._get_headers()

        print(f"Creating fixed index: {archive_name} (size: {size} bytes)")

        with httpx.Client(http2=True, verify=False, timeout=60.0) as client:
            response = client.post(url, params=params, headers=headers)
            response.raise_for_status()
            result = response.json()

        wid = int(result['data'])
        print(f"✓ Created fixed index, wid: {wid}")
        return wid

    def _create_blob(self, data):
        """Wrap data in PBS blob format (unencrypted, uncompressed)."""
        # Format: MAGIC (8 bytes) + CRC32 (4 bytes) + Data
        crc = zlib.crc32(data)
        blob = self.MAGIC_UNCOMPRESSED + struct.pack('<I', crc) + data
        return blob

    def upload_chunk(self, wid, chunk_data, size, digest):
        """Upload a chunk using REST API."""
        # Wrap chunk in blob format
        blob_data = self._create_blob(chunk_data)

        path = "/fixed_chunk"
        params = {
            'wid': wid,
            'digest': digest,
            'size': size,              # Original data size
            'encoded-size': len(blob_data),  # Blob size (with headers)
        }
        params.update(self.backup_session)

        url = f"{self.base_url}{path}"
        headers = self._get_headers()
        headers['Content-Type'] = 'application/octet-stream'

        print(
            f"Uploading chunk {digest[:16]}... ({size} bytes, blob: {len(blob_data)} bytes)")

        with httpx.Client(http2=True, verify=False, timeout=60.0) as client:
            response = client.post(
                url, params=params, headers=headers, content=blob_data)
            response.raise_for_status()

        print(f"  ✓ Uploaded chunk")

    def append_index(self, digest_list, offset_list, wid):
        """Append chunks to fixed index using REST API."""
        path = "/fixed_index"

        # Build JSON body
        body_data = {
            'wid': wid,
            'digest-list': digest_list,
            'offset-list': offset_list,
        }
        body_data.update(self.backup_session)

        url = f"{self.base_url}{path}"
        headers = self._get_headers()

        print(f"Appending chunks to index (wid={wid})...")

        with httpx.Client(http2=True, verify=False, timeout=60.0) as client:
            response = client.put(url, json=body_data, headers=headers)
            response.raise_for_status()

        print(f"✓ Appended {len(digest_list)} chunks to index")

    def close_fixed_index(self, chunk_count, csum, size, wid):
        """Close the fixed index using REST API."""
        path = "/fixed_close"
        params = {
            'chunk-count': chunk_count,
            'csum': csum,
            'size': size,
            'wid': wid,
        }
        params.update(self.backup_session)

        url = f"{self.base_url}{path}"
        headers = self._get_headers()

        print(f"Closing fixed index (wid={wid}, chunks={chunk_count})...")

        with httpx.Client(http2=True, verify=False, timeout=60.0) as client:
            response = client.post(url, params=params, headers=headers)
            response.raise_for_status()

        print(f"✓ Closed fixed index (chunks: {chunk_count}, size: {size})")

    def upload_manifest(self, archive_name, size, csum):
        """Upload the backup manifest (index.json)."""
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
        manifest_blob = self._create_blob(manifest_json)

        path = "/blob"
        params = {
            'file-name': 'index.json.blob',
            'encoded-size': len(manifest_blob),
        }
        params.update(self.backup_session)

        url = f"{self.base_url}{path}"
        headers = self._get_headers()
        headers['Content-Type'] = 'application/octet-stream'

        print(f"Uploading manifest (index.json.blob)...")

        with httpx.Client(http2=True, verify=False, timeout=60.0) as client:
            response = client.post(
                url, params=params, headers=headers, content=manifest_blob)
            response.raise_for_status()

        print(f"✓ Uploaded manifest")

    def complete_backup(self):
        """Mark backup as complete using REST API."""
        path = "/finish"
        params = {}
        params.update(self.backup_session)

        url = f"{self.base_url}{path}"
        headers = self._get_headers()

        print(f"Finishing backup session...")

        with httpx.Client(http2=True, verify=False, timeout=60.0) as client:
            response = client.post(url, params=params, headers=headers)
            response.raise_for_status()

        print(f"✓ Completed backup session")


def main():
    """Test PBS fixed index creation."""

    # Configuration - update these values
    PBS_HOST = "192.168.1.4"
    PBS_PORT = 8007
    PBS_USER = "root@pam"
    PBS_PASSWORD = "Kathmandu"  # UPDATE THIS
    DATASTORE = "hell"

    print("=" * 60)
    print("PBS Fixed Index Test")
    print("=" * 60)

    # Create client
    client = PBSClient(PBS_HOST, PBS_PORT, PBS_USER, PBS_PASSWORD)
    client.authenticate()

    # Upgrade to HTTP/2 and start backup session
    backup_type = "host"
    backup_id = "test-volume"
    backup_time = int(time.time())

    print(f"\nStarting backup: {backup_type}/{backup_id}")
    client.upgrade_to_h2(DATASTORE, backup_type, backup_id, backup_time)

    # Create some test data (4MB chunk)
    chunk_size = 4 * 1024 * 1024
    chunk_data = b"TEST" * (chunk_size // 4)

    # Calculate digest
    digest = hashlib.sha256(chunk_data).hexdigest()

    # Create fixed index
    total_size = chunk_size
    wid = client.create_fixed_index("test-volume.fidx", total_size)

    # Upload chunk
    print(f"\nUploading chunks...")
    client.upload_chunk(wid, chunk_data, chunk_size, digest)

    # Append to index
    digest_list = [digest]
    offset_list = [0]
    client.append_index(digest_list, offset_list, wid)

    # Calculate index checksum (SHA256 of digest bytes)
    digest_bytes = bytes.fromhex(digest)
    index_csum = hashlib.sha256(digest_bytes).hexdigest()

    # Close index
    client.close_fixed_index(1, index_csum, total_size, wid)

    # Upload manifest
    client.upload_manifest("test-volume.fidx", total_size, index_csum)

    # Complete backup
    client.complete_backup()

    print("\n" + "=" * 60)
    print("✓ SUCCESS: Fixed index backup completed!")
    print("=" * 60)


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print(f"\n❌ ERROR: {e}")
        import traceback
        traceback.print_exc()
