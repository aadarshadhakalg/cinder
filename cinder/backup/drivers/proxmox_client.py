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
Client library for Proxmox Backup Server (PBS).
Handles low-level protocol details: HTTP/2 upgrade, Blob wrapping, and Index management.
"""

import json
import socket
import ssl
import struct
import zlib
from urllib import parse as urlparse

import h2.connection
import h2.config
import h2.events
import httpx
from oslo_log import log as logging

from cinder import exception
from cinder.i18n import _

LOG = logging.getLogger(__name__)


class PBSBlob:
    """Handler for PBS Data Blob format.
    
    Ref: https://pbs.proxmox.com/docs/file-formats.html#data-blob-format
    """
    
    # Magic numbers
    MAGIC_UNCOMPRESSED = bytes([66, 171, 56, 7, 190, 131, 112, 161])
    MAGIC_ENCRYPTED = bytes([66, 171, 56, 7, 190, 131, 112, 163]) # TODO: Support encryption
    
    @staticmethod
    def encode(data: bytes) -> bytes:
        """Wrap data in uncompressed blob format."""
        # Blob Format: [Magic: 8] [CRC32: 4] [Data: N]
        crc = zlib.crc32(data)
        # Pack CRC32 as little-endian unsigned int
        return PBSBlob.MAGIC_UNCOMPRESSED + struct.pack('<I', crc) + data

    @staticmethod
    def decode(blob: bytes) -> bytes:
        """Unwrap data from blob format and verify integrity."""
        if len(blob) < 12:
            raise exception.BackupDriverException(_("Blob too short"))
            
        magic = blob[:8]
        stored_crc = struct.unpack('<I', blob[8:12])[0]
        data = blob[12:]
        
        if magic != PBSBlob.MAGIC_UNCOMPRESSED:
            # TODO: Handle compressed/encrypted blobs if we implement that support
            raise exception.BackupDriverException(
                _("Unsupported or invalid blob magic: %s") % magic.hex())
                
        calculated_crc = zlib.crc32(data)
        if calculated_crc != stored_crc:
            raise exception.BackupDriverException(
                _("Blob integrity check failed (CRC32 mismatch)"))
                
        return data


class FixedIndex:
    """Handler for Fixed Index (.fidx) file format."""
    
    # 4096 bytes header
    HEADER_SIZE = 4096
    # Magic: [47, 127, 65, 237, 145, 253, 15, 205]
    MAGIC = bytes([47, 127, 65, 237, 145, 253, 15, 205])
    
    @staticmethod
    def parse_digests(data: bytes) -> list:
        """Parse .fidx file data and return list of chunk digests."""
        if len(data) < FixedIndex.HEADER_SIZE:
             raise exception.BackupDriverException(_("Index file too short"))
             
        magic = data[:8]
        if magic != FixedIndex.MAGIC:
            raise exception.BackupDriverException(_("Invalid fixed index magic"))
            
        # TODO: Parse other header fields if needed (size, ctime, etc.)
        # Header layout:
        # Magic [8], UUID [16], Ctime [8], IndexCsum [32], Size [8], ChunkSize [8], Reserved [...]
        
        current.offset = FixedIndex.HEADER_SIZE
        digests = []
        
        # Digest is 32 bytes (SHA256)
        while current.offset + 32 <= len(data):
            digest = data[current.offset:current.offset + 32]
            # Check for zero-padding (end of index rules?)
            # Actually PBS fixed index is size-defined.
            # But we can just read all available 32-byte blocks.
            digests.append(digest.hex())
            current.offset += 32
            
        return digests


class PBSClient:
    """Client for Proxmox Backup Server API."""
    
    def __init__(self, host, port, user, password, 
                 datastore, verify_ssl=True, fingerprint=None):
        self.host = host
        self.port = port
        self.user = user
        self.password = password
        self.datastore = datastore
        self.verify_ssl = verify_ssl
        self.fingerprint = fingerprint
        
        self.base_url = f"https://{self.host}:{self.port}"
        self.ticket = None
        self.csrf_token = None
        
        # HTTP/1.1 client for auth (short-lived)
        self.auth_client = httpx.Client(
            verify=self.verify_ssl, 
            timeout=30.0,
            http2=False
        )
        
        # HTTP/2 low-level connection state
        self.sock = None
        self.h2_conn = None
        self.backup_session = None

    def _get_ssl_context(self):
        ctx = ssl.create_default_context()
        if not self.verify_ssl:
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        return ctx

    def login(self):
        """Authenticate with PBS to get Ticket and CSRF Token."""
        url = f"{self.base_url}/api2/json/access/ticket"
        data = {'username': self.user, 'password': self.password}
        
        try:
            resp = self.auth_client.post(url, data=data)
            resp.raise_for_status()
            res_json = resp.json()['data']
            self.ticket = res_json['ticket']
            self.csrf_token = res_json['CSRFPreventionToken']
            LOG.info("Successfully authenticated to PBS.")
        except Exception as e:
            msg = _("PBS Authentication failed: %s") % str(e)
            LOG.error(msg)
            raise exception.BackupDriverException(msg)

    def connect(self, backup_type, backup_id, backup_time, mode='backup'):
        """Establish HTTP/2 connection via Upgrade.
        
        :param mode: 'backup' (write) or 'restore' (read)
        """
        if not self.ticket:
            self.login()
            
        # PBS Upgrade Endpoint
        # Backup: GET /api2/json/backup
        # Restore: GET /api2/json/reader
        endpoint = "/api2/json/backup" if mode == 'backup' else "/api2/json/reader"
        protocol = "proxmox-backup-protocol-v1" if mode == 'backup' else "proxmox-backup-reader-protocol-v1"
        
        # Construct Upgrade Request
        # Note: We must use raw socket for manual HTTP/2 upgrade/handshake
        
        ctx = self._get_ssl_context()
        raw_sock = socket.create_connection((self.host, self.port))
        self.sock = ctx.wrap_socket(raw_sock, server_hostname=self.host)

        # Params
        params = [
            f"store={self.datastore}",
            f"backup-type={backup_type}",
            f"backup-id={backup_id}",
            f"backup-time={int(backup_time)}",
            "benchmark=false"
        ]
        if mode == 'restore':
            params.append("debug=true")
            
        path = f"{endpoint}?{'&'.join(params)}"
        
        req_lines = [
            f"GET {path} HTTP/1.1",
            f"Host: {self.host}:{self.port}",
            "Connection: Upgrade",
            f"Upgrade: {protocol}",
            f"Cookie: PBSAuthCookie={self.ticket}",
            f"CSRFPreventionToken: {self.csrf_token}",
            "", ""
        ]
        
        self.sock.sendall("\r\n".join(req_lines).encode())
        
        # Read Upgrade Response
        resp_buffer = b""
        while b"\r\n\r\n" not in resp_buffer:
            chunk = self.sock.recv(4096)
            if not chunk:
                raise exception.BackupDriverException(_("Connection closed during upgrade"))
            resp_buffer += chunk
            
        resp_str = resp_buffer.decode()
        if "101 Switching Protocols" not in resp_str:
            raise exception.BackupDriverException(_("Upgrade failed: %s") % resp_str)
            
        LOG.info(f"PBS Connection Upgraded to {protocol}")
        
        # Initialize HTTP/2
        config = h2.config.H2Configuration(client_side=True)
        self.h2_conn = h2.connection.H2Connection(config=config)
        self.h2_conn.initiate_connection()
        self.sock.sendall(self.h2_conn.data_to_send())
        
        self.backup_session = {
            'type': backup_type,
            'id': backup_id,
            'time': int(backup_time)
        }

    def _h2_request(self, method, path, params=None, body=None, content_type='application/octet-stream'):
        """Send HTTP/2 request and wait for response."""
        if not self.h2_conn:
            raise exception.BackupDriverException(_("No active H2 connection"))

        # Build Headers
        query = ""
        if params:
            query = "?" + urlparse.urlencode(params)
            
        headers = [
            (':method', method),
            (':authority', f"{self.host}:{self.port}"),
            (':scheme', 'https'),
            (':path', path + query),
        ]
        
        if body:
            headers.append(('content-length', str(len(body))))
            headers.append(('content-type', content_type))
            
        stream_id = self.h2_conn.get_next_available_stream_id()
        self.h2_conn.send_headers(stream_id, headers, end_stream=(body is None))
        
        if body:
            # Chunk body to avoid frame size limits (default 16kb usually safe, but let's be explicit)
            # h2 handles frame splitting, but we shouldn't dump 4MB at once to the sending logic without care.
            # h2 library handles it if we just pass bytes, but let's send in reasonable chunks.
            chunk_size = 65535 # Safe max frame size
            for i in range(0, len(body), chunk_size):
                chunk = body[i:i+chunk_size]
                is_last_chunk = (i + chunk_size >= len(body))
                self.h2_conn.send_data(stream_id, chunk, end_stream=is_last_chunk)
                
        self.sock.sendall(self.h2_conn.data_to_send())

        # Receive Loop
        resp_headers = {}
        resp_body = b""
        
        while True:
            # Read from socket
            raw_data = self.sock.recv(65535)
            if not raw_data:
                break
                
            events = self.h2_conn.receive_data(raw_data)
            # If we need to send anything (e.g. flow control, ping acks)
            to_send = self.h2_conn.data_to_send()
            if to_send:
                self.sock.sendall(to_send)
                
            stream_ended = False
            for event in events:
                if hasattr(event, 'stream_id') and event.stream_id != stream_id:
                    continue # Ignore other streams if any (shouldn't be for this sync client)
                    
                if isinstance(event, h2.events.ResponseReceived):
                    resp_headers = dict(event.headers)
                elif isinstance(event, h2.events.DataReceived):
                    resp_body += event.data
                    self.h2_conn.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
                elif isinstance(event, h2.events.StreamEnded):
                    stream_ended = True
            
            if stream_ended:
                break

        # Check Status
        status = resp_headers.get(b':status', b'0').decode()
        if not status.startswith('2'):
            msg = f"PBS Error {status}: {resp_body.decode(errors='ignore')}"
            raise exception.BackupDriverException(msg)
            
        return resp_body

    def create_fixed_index(self, archive_name, size):
        """Register a new fixed .fidx file."""
        return self._h2_request('POST', '/fixed_index', 
            params={'archive-name': archive_name, 'size': size})

    def append_fixed_index(self, wid, digests, offsets):
        """Append chunks to a fixed index."""
        data = json.dumps({
            'wid': int(wid), 
            'digest-list': digests,
            'offset-list': offsets
        }).encode()
        self._h2_request('PUT', '/fixed_index', body=data, content_type='application/json')
        
    def close_fixed_index(self, wid, chunk_count, size, csum):
        """Finalize fixed index."""
        params = {
            'wid': int(wid),
            'chunk-count': chunk_count,
            'size': size,
            'csum': csum
        }
        self._h2_request('POST', '/fixed_close', params=params)

    def upload_fixed_chunk(self, wid, data, digest):
        """Upload a single chunk (if server needs it)."""
        # Note: For fixed index, we might not always upload if deduped.
        # But this method strictly performs the upload action.
        blob = PBSBlob.encode(data)
        params = {
            'wid': int(wid),
            'digest': digest,
            'size': len(data),
            'encoded-size': len(blob)
        }
        self._h2_request('POST', '/fixed_chunk', params=params, body=blob)

    def upload_blob(self, filename, data):
        """Upload a generic blob file (like index.json)."""
        blob = PBSBlob.encode(data)
        params = {
            'file-name': filename,
            'encoded-size': len(blob)
        }
        self._h2_request('POST', '/blob', params=params, body=blob)

    def finish(self):
        """Close backup session."""
        try:
            self._h2_request('POST', '/finish')
        except:
            pass # Ignore errors on finish
        finally:
            if self.sock:
                self.sock.close()

    def download_file(self, filename):
        """Download file content (generic)."""
        # For non-chunk files (index.json, .fidx), /download returns raw content
        return self._h2_request('GET', '/download', params={'file-name': filename})

    def download_chunk(self, digest):
        """Download a chunk by digest."""
        data = self._h2_request('GET', '/chunk', params={'digest': digest})
        # Important: Decode blob to get actual data
        return PBSBlob.decode(data)

    def delete_snapshot(self, backup_type, backup_id, backup_time):
        """Delete a backup snapshot."""
        if not self.ticket:
            self.login()

        url = f"{self.base_url}/api2/json/admin/datastore/{self.datastore}/snapshots"
        
        headers = {
            'CSRFPreventionToken': self.csrf_token,
            'Cookie': f"PBSAuthCookie={self.ticket}"
        }
        
        params = {
            'backup-type': backup_type,
            'backup-id': backup_id,
            'backup-time': int(backup_time)
        }
        
        try:
            resp = self.auth_client.delete(url, headers=headers, params=params)
            resp.raise_for_status()
            LOG.info(f"Successfully deleted snapshot {backup_type}/{backup_id}/{backup_time}")
        except Exception as e:
            msg = _("Failed to delete snapshot: %s") % str(e)
            LOG.error(msg)
            raise exception.BackupDriverException(msg)
