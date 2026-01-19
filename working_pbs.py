#!/usr/bin/env python3
"""Test PBS client for creating a fixed index backup."""

import httpx
import time
import hashlib
import h2.connection
import h2.config
import ssl
import socket
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
        # HTTP/1.1 session for authentication
        self.auth_session = httpx.Client(verify=False, timeout=60.0)
        # Will store upgraded H2 connection
        self.h2_conn = None
        self.sock = None
        self.backup_session = None

    def authenticate(self):
        """Authenticate and get ticket/CSRF token."""
        url = f"{self.base_url}/api2/json/access/ticket"
        data = {
            'username': self.user,
            'password': self.password,
        }

        response = self.auth_session.post(url, data=data)
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

    def upgrade_to_h2(self, datastore, backup_type, backup_id, backup_time):
        """Upgrade connection to HTTP/2 backup protocol."""
        # Create raw socket connection
        sock = socket.create_connection((self.host, self.port))

        # Wrap with SSL
        context = ssl.create_default_context()
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

        print("Sending HTTP/1.1 upgrade request...")
        print(upgrade_request[:200] + "...")
        self.sock.sendall(upgrade_request.encode())

        # Read upgrade response
        response = b""
        while b"\r\n\r\n" not in response:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise Exception("Connection closed before upgrade complete")
            response += chunk

        response_str = response.decode()
        print(f"\nUpgrade Response:\n{response_str}")

        if "101 Switching Protocols" not in response_str:
            raise Exception(f"Upgrade failed: {response_str}")

        print("✓ HTTP/2 upgrade successful (101 Switching Protocols)")

        # Initialize H2 connection
        config = h2.config.H2Configuration(client_side=True)
        self.h2_conn = h2.connection.H2Connection(config=config)
        self.h2_conn.initiate_connection()
        self.sock.sendall(self.h2_conn.data_to_send())

        print("✓ HTTP/2 connection initialized")

        # Store backup session info
        self.backup_session = {
            'store': datastore,
            'backup-type': backup_type,
            'backup-id': backup_id,
            'backup-time': int(backup_time),
        }

    def _h2_request(self, method, path, params=None, body=None, content_type='application/octet-stream'):
        """Make an HTTP/2 request over the upgraded connection."""
        if not self.h2_conn:
            raise Exception("Not connected - call upgrade_to_h2 first")

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
            # Send body in chunks to respect max frame size (4MB)
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
                        raise Exception(f"HTTP {status}: {error_msg}")
                    return response_headers, response_data

        return response_headers, response_data

    def create_fixed_index(self, archive_name, size):
        """Create a fixed index using HTTP/2."""
        path = "/fixed_index"
        params = {
            'archive-name': archive_name,
            'size': size,
        }

        print(f"Creating fixed index: {archive_name} (size: {size} bytes)")
        print(f"  Path: {path}")
        print(f"  Params: {params}")

        headers, data = self._h2_request('POST', path, params=params)

        print(f"  Response headers: {headers}")
        print(f"  Response data: {data}")

        # Parse response
        result = json.loads(data.decode())
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
        """Upload a chunk using HTTP/2."""
        # Wrap chunk in blob format
        blob_data = self._create_blob(chunk_data)

        path = "/fixed_chunk"
        params = {
            'wid': wid,
            'digest': digest,
            'size': size,              # Original data size
            'encoded-size': len(blob_data),  # Blob size (with headers)
        }
        print(
            f"Uploading chunk {digest[:16]}... ({size} bytes, blob: {len(blob_data)} bytes)")
        headers, data = self._h2_request(
            'POST', path, params=params, body=blob_data)
        print(f"  Response: {headers.get(b':status', b'').decode()}")

    def append_index(self, digest_list, offset_list, wid):
        """Append chunks to fixed index using HTTP/2."""
        path = "/fixed_index"

        # Build JSON body
        body_data = json.dumps({
            'wid': wid,
            'digest-list': digest_list,
            'offset-list': offset_list,
        }).encode()

        print(f"Appending chunks to index (wid={wid})...")
        headers, data = self._h2_request(
            'PUT', path, body=body_data, content_type='application/json')
        print(f"  Response: {headers.get(b':status', b'').decode()}")
        print(f"✓ Appended {len(digest_list)} chunks to index")

    def close_fixed_index(self, chunk_count, csum, size, wid):
        """Close the fixed index using HTTP/2."""
        path = "/fixed_close"
        params = {
            'chunk-count': chunk_count,
            'csum': csum,
            'size': size,
            'wid': wid,
        }

        print(f"Closing fixed index (wid={wid}, chunks={chunk_count})...")
        headers, data = self._h2_request('POST', path, params=params)
        print(f"  Response: {headers.get(b':status', b'').decode()}")
        print(f"  Response data: {data}")
        print(f"✓ Closed fixed index (chunks: {chunk_count}, size: {size})")

    def upload_manifest(self, archive_name, size, csum):
        """Upload the backup manifest (index.json)."""
        import time

        # Create manifest
        manifest = {
            "backup-type": "host",
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

        # Calculate digest of the manifest blob
        manifest_digest = hashlib.sha256(manifest_blob).hexdigest()

        # Upload as index.json.blob
        path = "/blob"
        params = {
            'file-name': 'index.json.blob',
            'encoded-size': len(manifest_blob),
        }

        print(f"Uploading manifest (index.json.blob)...")
        headers, data = self._h2_request(
            'POST', path, params=params, body=manifest_blob)
        print(f"  Response: {headers.get(b':status', b'').decode()}")
        print(f"✓ Uploaded manifest")

    def complete_backup(self):
        """Mark backup as complete using HTTP/2."""
        path = "/finish"
        print(f"Finishing backup session...")
        headers, data = self._h2_request('POST', path)
        print(f"  Response headers: {headers}")
        print(f"  Response data: {data}")
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
