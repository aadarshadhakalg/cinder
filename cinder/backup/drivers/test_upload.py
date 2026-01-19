
import httpx
import struct
import zlib
import hashlib
import time
import os

HOST = "192.168.1.4"
PORT = 8007
USER = "root@pam"
PASS = "Kathmandu"
DATASTORE = "datastore1"

# Copy from proxmox.py
class PBSChunk:
    MAGIC_UNCOMPRESSED = bytes([66, 171, 56, 7, 190, 131, 112, 161])

    def encode(self, data):
        crc = zlib.crc32(data) & 0xffffffff
        blob = self.MAGIC_UNCOMPRESSED + struct.pack('<I', crc) + data
        return blob

def test_upload_flow():
    print(f"Connecting to https://{HOST}:{PORT}")
    
    # Disable SSL warnings
    client = httpx.Client(verify=False, http2=True, timeout=30.0)
    
    try:
        # 1. Authenticate
        resp = client.post(f"https://{HOST}:{PORT}/api2/json/access/ticket", 
                          data={'username': USER, 'password': PASS})
        resp.raise_for_status()
        data = resp.json()['data']
        ticket = data['ticket']
        csrf = data['CSRFPreventionToken']
        
        # Set headers for subsequent requests
        client.headers.update({
            'CSRFPreventionToken': csrf,
            'Cookie': f'PBSAuthCookie={ticket}',
        })
        print("Authenticated successfully.")
        
        # 2. Create a dummy chunk (4MB)
        chunk_size = 4 * 1024 * 1024
        raw_data = os.urandom(chunk_size)
        
        handler = PBSChunk()
        blob_data = handler.encode(raw_data)
        
        # Calculate digests
        digest_blob = hashlib.sha256(blob_data).hexdigest()
        digest_raw = hashlib.sha256(raw_data).hexdigest()
        
        print(f"Blob Digest: {digest_blob}")
        print(f"Raw Digest:  {digest_raw}")
        
        # 3. Create Fixed Index (to get wid)
        archive_name = f"test-{int(time.time())}.fidx"
        resp = client.post(f"https://{HOST}:{PORT}/fixed_index", 
                          json={'archive-name': archive_name, 'size': chunk_size})
        resp.raise_for_status()
        wid = int(resp.json()['data'])
        print(f"Created fixed index, wid: {wid}")
        
        # 4. Try Uploading Chunk - Attempt 1: Using Blob Digest (Expected Correct)
        print("Attempting upload with BLOB digest...")
        try:
            params = {
                'wid': wid,
                'digest': digest_blob,
                'size': chunk_size,
                'encoded-size': len(blob_data)
            }
            resp = client.post(f"https://{HOST}:{PORT}/fixed_chunk", 
                              params=params, 
                              content=blob_data,
                              headers={'Content-Type': 'application/octet-stream'})
            print(f"Upload Status (Blob Digest): {resp.status_code}")
            print(f"Upload Response: {resp.text}")
            resp.raise_for_status() # If this works, my logic in proxmox.py IS correct, and bug is elsewhere (H2 stream?)
            print("SUCCESS: Uploaded with Blob Digest.")
            return
        except Exception as e:
            print(f"FAILED (Blob Digest): {e}")

        # 5. Try Uploading Chunk - Attempt 2: Using Raw Digest (Just in case)
        print("Attempting upload with RAW digest...")
        try:
            params = {
                'wid': wid,
                'digest': digest_raw,
                'size': chunk_size,
                'encoded-size': len(blob_data)
            }
            resp = client.post(f"https://{HOST}:{PORT}/fixed_chunk", 
                              params=params, 
                              content=blob_data,
                              headers={'Content-Type': 'application/octet-stream'})
            print(f"Upload Status (Raw Digest): {resp.status_code}")
            print(f"Upload Response: {resp.text}")
            if resp.status_code == 200:
                print("SUCCESS: Uploaded with Raw Digest.")
        except Exception as e:
            print(f"FAILED (Raw Digest): {e}")
            
    except Exception as e:
        print(f"Fatal Error: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    test_upload_flow()
