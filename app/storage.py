"""Encrypted blob storage.

Files never sit on disk in the clear and are never served by the web server
directly; the only way out is through the download endpoint, which calls
authz.require() first.

Envelope encryption:
  * each file version gets its own random 256-bit data key (DEK);
  * the content is sealed with AES-256-GCM under the DEK;
  * the DEK is sealed with AES-256-GCM under the master key (TV_MASTER_KEY)
    and stored in the database, not next to the blob.
Both seals bind the document id and version id as associated data, so a blob
copied or swapped onto another document fails to decrypt instead of being
served under the wrong name.

Blob filenames are random hex generated here, never derived from user input.
"""
import os
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_BLOB_NAME = re.compile(r"^[0-9a-f]{32}$")


class StorageError(Exception):
    pass


def _aad(document_id: str, version_id: str) -> bytes:
    return f"trustvault:{document_id}:{version_id}".encode()


def _path(blob_dir: str, blob_name: str) -> str:
    if not _BLOB_NAME.match(blob_name):
        raise StorageError("invalid blob name")
    return os.path.join(blob_dir, blob_name)


def store(blob_dir: str, master_key: bytes, document_id: str, version_id: str, data: bytes):
    """Encrypt and write. Returns (blob_name, wrapped_key)."""
    os.makedirs(blob_dir, mode=0o700, exist_ok=True)
    aad = _aad(document_id, version_id)
    dek = AESGCM.generate_key(bit_length=256)
    nonce = secrets.token_bytes(12)
    ciphertext = AESGCM(dek).encrypt(nonce, data, aad)
    key_nonce = secrets.token_bytes(12)
    wrapped_key = key_nonce + AESGCM(master_key).encrypt(key_nonce, dek, aad)
    blob_name = secrets.token_hex(16)
    path = _path(blob_dir, blob_name)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(nonce + ciphertext)
    return blob_name, wrapped_key


def load(blob_dir: str, master_key: bytes, document_id: str, version_id: str,
         blob_name: str, wrapped_key: bytes) -> bytes:
    aad = _aad(document_id, version_id)
    try:
        dek = AESGCM(master_key).decrypt(wrapped_key[:12], wrapped_key[12:], aad)
        with open(_path(blob_dir, blob_name), "rb") as f:
            raw = f.read()
        return AESGCM(dek).decrypt(raw[:12], raw[12:], aad)
    except Exception as exc:  # InvalidTag, missing file, etc. Never serve partial data.
        raise StorageError("blob unreadable or tampered") from exc


def destroy(blob_dir: str, blob_name: str) -> None:
    try:
        os.remove(_path(blob_dir, blob_name))
    except FileNotFoundError:
        pass
