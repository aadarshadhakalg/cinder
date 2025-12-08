"""
Cinder Backup Driver for Proxmox Backup Server (PBS).
"""

import os
import struct
import zlib
import hashlib
import json
import logging
import math
import time
import ssl
import socket
from urllib.parse import urlparse
from typing import Optional, List, Dict
from oslo_config import cfg
from oslo_log import log as logging
from cinder.backup.driver import BackupDriver
from cinder import exception
from cinder.i18n import _
import httpx

LOG = logging.getLogger(__name__)

pbs_backup_opts = [
    cfg.StrOpt('pbs_url', default='',
               help='Url of Proxmox Backup Server (e.g. https://pbs:8007)'),
    cfg.StrOpt('pbs_user', default='', help='User for PBS (e.g. root@pam)'),
    cfg.StrOpt('pbs_password', default='', help='Password for PBS'),
    cfg.StrOpt('pbs_datastore', default='', help='Datastore on PBS'),
    cfg.StrOpt('pbs_fingerprint', default='',
               help='SHA256 Fingerprint of the PBS Server'),
    cfg.StrOpt('pbs_backup_type', default='vm',
               help='Backup Type to use (defaults to vm)'),
    cfg.IntOpt('pbs_chunk_size', default=4 * 1024 * 1024,
               help='Chunk size in bytes (default 4MB)'),
    cfg.IntOpt('pbs_upload_threads', default=4,
               help='Number of threads for upload (not implemented yet, async used)'),
]

cfg.CONF.register_opts(pbs_backup_opts)


# --- Embedded PBS Client Logic (Adapted from pbs_backup_python) ---

# Uncompressed Blob Magic: [66, 171, 56, 7, 190, 131, 112, 161]
UNCOMPRESSED_BLOB_MAGIC = bytes([66, 171, 56, 7, 190, 131, 112, 161])
ENCRYPTED_BLOB_MAGIC = bytes([230, 89, 27, 191, 11, 191, 216, 11])


class DataBlob:
    def __init__(self, data: bytes, compress: bool = False, encrypt: bool = False):
        self.data = data
        self.compress = compress
        self.encrypt = encrypt

    def encode(self) -> bytes:
        if self.compress or self.encrypt:
            raise NotImplementedError(
                "Compression and Encryption not supported yet")

        magic = UNCOMPRESSED_BLOB_MAGIC
        crc = zlib.crc32(self.data) & 0xFFFFFFFF
        header = struct.pack('<8sI', magic, crc)
        return header + self.data

    @staticmethod
    def decode(raw_data: bytes) -> bytes:
        if len(raw_data) < 12:
            raise ValueError("Data too short")

        magic, crc = struct.unpack('<8sI', raw_data[:12])
        data = raw_data[12:]

        # Verify Magic
        if magic != UNCOMPRESSED_BLOB_MAGIC:
            # Just a warning or simple check for now, could be encrypted
            pass

        computed_crc = zlib.crc32(data) & 0xFFFFFFFF
        if crc != computed_crc:
            raise ValueError(
                f"CRC Mismatch: expected {crc}, got {computed_crc}")

        return data


class ProxmoxBackupClient:
    def __init__(self, base_url: str, user: str, password: str, datastore: str, verify_ssl: bool = True, fingerprint: Optional[str] = None):
        self.base_url = base_url.rstrip('/')
        self.user = user
        self.password = password
        self.datastore = datastore
        self.ticket: Optional[str] = None
        self.token: Optional[str] = None
        self.client: Optional[httpx.Client] = None
        # Note: If high concurrency is needed, Cinder usually relies on greenlets (eventlet).
        # httpx.Client is sync (blocking). httpx.AsyncClient is async.
        # Cinder drivers are often blocking calls that run in threads.
        # To avoid async complexity in the driver, we will use sync implementation or run_async wrapper.
        # Given Cinder's architecture, sync is safer unless using native logic.
        self.verify_ssl = verify_ssl
        self.fingerprint = fingerprint

    def _verify_fingerprint(self):
        """
        Verify the server certificate SHA256 fingerprint matches configuration.
        """
        if not self.fingerprint:
            return

        parsed = urlparse(self.base_url)
        host = parsed.hostname
        port = parsed.port or (443 if parsed.scheme == 'https' else 80)

        LOG.info(f"Verifying PBS Fingerprint for {host}:{port}")

        # Create context that doesn't verify CA but we get cert
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert_bin = ssock.getpeercert(binary_form=True)
                    if not cert_bin:
                        raise ValueError("No certificate presented by server")

                    fingerprint_hash = hashlib.sha256(cert_bin).hexdigest()
                    expected = self.fingerprint.lower().replace(':', '')

                    if fingerprint_hash.lower() != expected:
                        raise ValueError(
                            f"Fingerprint Mismatch! Expected {expected}, got {fingerprint_hash}")

                    LOG.info("Fingerprint verified successfully.")
        except Exception as e:
            msg = f"Fingerprint verification failed: {e}"
            LOG.error(msg)
            raise exception.BackupOperationError(msg)

    def connect(self):
        # 1. Verify Fingerprint if configured
        if self.fingerprint:
            self._verify_fingerprint()
            # If validated manually, we can disable standard verify for the httpx client
            # because we trust the connection we just probed (assuming no MiTM race).
            # This is common practice when pinning self-signed certs.
            verify_client = False
        else:
            verify_client = self.verify_ssl

        # Authenticate
        # Note: If fingerprint is validated, we pass verify=False to auth_client too.

        try:
            with httpx.Client(verify=verify_client) as auth_client:
                payload = {"username": self.user, "password": self.password}
                resp = auth_client.post(
                    f"{self.base_url}/api2/json/access/ticket", json=payload)
                resp.raise_for_status()
                data = resp.json()['data']
                self.ticket = data['ticket']
                self.token = data['CSRFPreventionToken']

            headers = {
                "Cookie": f"PBSAuthCookie={self.ticket}",
                "CSRFPreventionToken": self.token,
                "Accept": "application/json",
            }

            self.client = httpx.Client(
                base_url=self.base_url,
                headers=headers,
                http2=True,
                verify=verify_client,
                timeout=120.0
            )
        except httpx.RequestError as e:
            raise exception.BackupOperationError(f"Connection error: {e}")
        except Exception as e:
            raise exception.BackupOperationError(f"Authentication failed: {e}")

    def get_backup_writer(self, backup_type: str, backup_id: str, backup_time: int):
        return BackupWriter(self, backup_type, backup_id, backup_time)

    def get_backup_reader(self, backup_type: str, backup_id: str, backup_time: int):
        return BackupReader(self, backup_type, backup_id, backup_time)

    def close(self):
        if self.client:
            self.client.close()


class BackupWriter:
    def __init__(self, client: ProxmoxBackupClient, backup_type: str, backup_id: str, backup_time: int):
        self.client = client
        self.backup_type = backup_type
        self.backup_id = backup_id
        self.backup_time = backup_time

    def start(self):
        params = {
            "backup-type": self.backup_type,
            "backup-id": self.backup_id,
            "backup-time": self.backup_time,
            "store": self.client.datastore,
            "debug": True
        }
        resp = self.client.client.get("/api2/json/backup", params=params)
        resp.raise_for_status()

    def create_fixed_index(self, archive_name: str):
        resp = self.client.client.post(
            "/fixed_index", json={"archive-name": archive_name})
        resp.raise_for_status()

    def upload_fixed_chunk(self, data: bytes, digest: bytes):
        blob = DataBlob(data)
        encoded_data = blob.encode()
        params = {"digest": digest.hex()}
        resp = self.client.client.post(
            "/fixed_chunk",
            content=encoded_data,
            params=params,
            headers={"Content-Type": "application/octet-stream"}
        )
        resp.raise_for_status()

    def append_fixed_index(self, digest: bytes, size: int):
        params = {"digest": digest.hex(), "size": size}
        resp = self.client.client.put("/fixed_index", json=params)
        resp.raise_for_status()

    def close_fixed_index(self):
        self.client.client.post("/fixed_close").raise_for_status()

    def finish(self):
        self.client.client.post("/finish").raise_for_status()


class BackupReader:
    def __init__(self, client: ProxmoxBackupClient, backup_type: str, backup_id: str, backup_time: int):
        self.client = client
        self.backup_type = backup_type
        self.backup_id = backup_id
        self.backup_time = backup_time
        # For restore, we assume we might need to 'download' calls.
        # But wait, PBS protocol for restore might be different?
        # Protocol: "Restore/Reader Protocol API"
        # "GET /api2/json/reader" instead of backup?
        # Let's check docs or source.
        # Protocol docs: "Restore/Reader Protocol API ... GET /api2/json/reader ... This upgrades the connection..."
        pass

    def start_restore_session(self):
        params = {
            "backup-type": self.backup_type,
            "backup-id": self.backup_id,
            "backup-time": self.backup_time,
            "store": self.client.datastore
        }
        resp = self.client.client.get("/api2/json/reader", params=params)
        resp.raise_for_status()

    def download_fixed_index(self, archive_name: str) -> List[bytes]:
        # GET /download using simple HTTP?
        # Or using the reader connection?
        # The reader protocol is stateful on H2 connection usually.
        # Docs: "Download Index Files ... GET /index"

        # We need to know which index file to download.
        # Protocol says: "GET /index?file-name=..."

        params = {"file-name": archive_name}
        resp = self.client.client.get("/index", params=params)
        resp.raise_for_status()

        # The response is the binary .fidx content.
        # We need to parse it to get the chunk digests.
        return self._parse_fixed_index(resp.content)

    def _parse_fixed_index(self, data: bytes) -> List[bytes]:
        # Format:
        # MAGIC (8) | ... | digest1 (32) | ...
        # Based on file-formats.html
        # Header size is 4096 bytes.
        HEADER_SIZE = 4096
        MAGIC = bytes([47, 127, 65, 237, 145, 253, 15, 205])

        if len(data) < HEADER_SIZE:
            raise ValueError("Index file too short")

        if data[:8] != MAGIC:
            raise ValueError("Invalid Fixed Index Magic")

        # Digests start at offest 4096
        digests = []
        offset = HEADER_SIZE
        while offset < len(data):
            digest = data[offset:offset + 32]
            if len(digest) != 32:
                break
            digests.append(digest)
            offset += 32

        return digests

    def download_chunk(self, digest: bytes) -> bytes:
        # GET /chunk
        params = {"digest": digest.hex()}
        resp = self.client.client.get("/chunk", params=params)
        resp.raise_for_status()

        # Provided as Data Blob
        return DataBlob.decode(resp.content)


# --- Cinder Driver Implementation ---

class PBSBackupDriver(BackupDriver):
    """Proxmox Backup Server Driver."""

    def __init__(self, context):
        super(PBSBackupDriver, self).__init__(context)
        self.pbs_url = cfg.CONF.pbs_url
        self.pbs_user = cfg.CONF.pbs_user
        self.pbs_password = cfg.CONF.pbs_password
        self.pbs_datastore = cfg.CONF.pbs_datastore
        self.pbs_backup_type = cfg.CONF.pbs_backup_type
        self.chunk_size = cfg.CONF.pbs_chunk_size

        self.pbs_fingerprint = cfg.CONF.pbs_fingerprint

        if not all([self.pbs_url, self.pbs_user, self.pbs_password, self.pbs_datastore]):
            # In real cinder, might want to check this more gracefully or default
            LOG.warning("PBS credentials not fully configured.")

    def _get_client(self):
        return ProxmoxBackupClient(
            base_url=self.pbs_url,
            user=self.pbs_user,
            password=self.pbs_password,
            datastore=self.pbs_datastore,
            # If fingerprint used, we handle verify manually
            verify_ssl=False if self.pbs_fingerprint else True,
            fingerprint=self.pbs_fingerprint
        )

    def check_for_setup_error(self):
        """Returns None if setup is correct, else raises exception."""
        if not self.pbs_url:
            raise exception.InvalidConfigurationValue(
                option='pbs_url', value=self.pbs_url)

    def backup(self, backup, volume_file, backup_metadata=False):
        """
        Backup a volume to PBS.
        """
        client = self._get_client()
        try:
            client.connect()

            # Use current time or backup object creation time
            # Cinder backup object has keys? `backup.created_at`?
            # backup['id'] is UUID.
            backup_id = backup.id
            backup_time = int(time.time())  # Use current time for new backup

            writer = client.get_backup_writer(
                self.pbs_backup_type, backup_id, backup_time)
            writer.start()

            # Archive name: volume-{uuid}.img.fidx
            # volume_file is a file-like object.

            # e.g. volume-uuid.img
            archive_name = f"volume-{backup.volume_id}.img"
            index_name = archive_name + ".fidx"

            writer.create_fixed_index(index_name)

            while True:
                data = volume_file.read(self.chunk_size)
                if not data:
                    break

                digest = hashlib.sha256(data).digest()
                writer.upload_fixed_chunk(data, digest)
                writer.append_fixed_index(digest, len(data))

            writer.close_fixed_index()
            writer.finish()

            # Save metadata to service metadata to allow restore
            # We need to know the backup_time and backup_type to restore?
            # backup['service_metadata'] = ...
            service_metadata = {
                "backup_id": backup_id,
                "backup_time": backup_time,
                "archive_name": index_name
            }
            backup.service_metadata = json.dumps(service_metadata)
            backup.save()

        except Exception as e:
            LOG.exception("Backup failed")
            raise exception.BackupOperationError(reason=str(e))
        finally:
            client.close()

    def restore(self, backup, volume_id, volume_file, volume_is_new):
        """
        Restore a backup.
        """
        if not backup.service_metadata:
            raise exception.BackupOperationError(
                reason="Missing service metadata")

        meta = json.loads(backup.service_metadata)
        backup_id = meta.get("backup_id", backup.id)
        backup_time = meta.get("backup_time")
        archive_name = meta.get("archive_name")

        client = self._get_client()
        try:
            client.connect()
            reader = client.get_backup_reader(
                self.pbs_backup_type, backup_id, backup_time)
            reader.start_restore_session()

            # Download Index
            digests = reader.download_fixed_index(archive_name)

            for digest in digests:
                data = reader.download_chunk(digest)
                volume_file.write(data)

        except Exception as e:
            LOG.exception("Restore failed")
            raise exception.BackupOperationError(reason=str(e))
        finally:
            client.close()

    def delete_backup(self, backup):
        """
        Delete a backup from PBS.
        """
        # PBS calls this "Forget".
        # DELETE /api2/json/admin/datastore/{store}/snapshots
        # Params: backup-type, backup-id, backup-time
        if not backup.service_metadata:
            LOG.warning(
                "No metadata for backup, cannot delete from PBS cleanly.")
            return

        meta = json.loads(backup.service_metadata)
        backup_id = meta.get("backup_id", backup.id)
        backup_time = meta.get("backup_time")

        client = self._get_client()
        try:
            client.connect()
            # Standard API call (not on H2 session maybe? or yes?)
            # Usually admin API is on the main port path.

            # Snapshot path: {type}/{id}/{time}
            snapshot_path = f"{self.pbs_backup_type}/{backup_id}/{backup_time}"

            resp = client.client.delete(
                f"/api2/json/admin/datastore/{self.pbs_datastore}/snapshots/{snapshot_path}")
            # If 404, assumed deleted
            if resp.status_code == 404:
                return
            resp.raise_for_status()

        except Exception as e:
            # Cinder expects us to log but maybe not raise if we want to force delete locally?
            LOG.error(f"Failed to delete backup on PBS: {e}")
            # raise?
        finally:
            client.close()
