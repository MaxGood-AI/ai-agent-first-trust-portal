"""Symmetric encryption for collector credentials at rest.

Uses Fernet (AES-128-CBC + HMAC-SHA-256) with the key material provided via
the ``COLLECTOR_ENCRYPTION_KEY`` environment variable. Multiple keys may be
supplied for rotation via ``COLLECTOR_ENCRYPTION_KEYS`` (comma-separated,
primary key first).

Credentials are serialised as JSON, encrypted, and stored as bytes in the
``collector_config.encrypted_credentials`` column. Credentials are never
logged and never returned through the API.
"""

import json
import logging
import os
from typing import Any

from cryptography.fernet import Fernet, InvalidToken, MultiFernet

logger = logging.getLogger(__name__)


class CollectorEncryptionError(Exception):
    """Raised when credential encryption or decryption fails."""


def _load_keys() -> list[bytes]:
    """Load Fernet keys from environment, primary key first.

    ``COLLECTOR_ENCRYPTION_KEYS`` (comma-separated) takes precedence over
    ``COLLECTOR_ENCRYPTION_KEY`` (single key) to support rotation.
    """
    multi = os.environ.get("COLLECTOR_ENCRYPTION_KEYS")
    if multi:
        return [k.strip().encode() for k in multi.split(",") if k.strip()]
    single = os.environ.get("COLLECTOR_ENCRYPTION_KEY")
    if single:
        return [single.strip().encode()]
    return []


def _get_fernet() -> MultiFernet:
    """Build a MultiFernet from loaded keys."""
    keys = _load_keys()
    if not keys:
        raise CollectorEncryptionError(
            "COLLECTOR_ENCRYPTION_KEY (or COLLECTOR_ENCRYPTION_KEYS) is not set. "
            "Generate one with: python -c 'from cryptography.fernet import Fernet; "
            "print(Fernet.generate_key().decode())'"
        )
    try:
        return MultiFernet([Fernet(k) for k in keys])
    except (ValueError, TypeError) as exc:
        raise CollectorEncryptionError(
            f"Invalid Fernet key material: {exc}"
        ) from exc


def encrypt_credentials(payload: dict[str, Any]) -> bytes:
    """Serialise ``payload`` to JSON, encrypt it, and return ciphertext bytes.

    Never logs the payload or the returned ciphertext content.
    """
    if not isinstance(payload, dict):
        raise CollectorEncryptionError("Credential payload must be a dict")
    fernet = _get_fernet()
    plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    return fernet.encrypt(plaintext)


def decrypt_credentials(ciphertext: bytes | None) -> dict[str, Any]:
    """Decrypt ciphertext and return the original dict. Returns ``{}`` for None input.

    Never logs the decrypted payload.
    """
    if ciphertext is None:
        return {}
    if not isinstance(ciphertext, (bytes, bytearray)):
        raise CollectorEncryptionError("Ciphertext must be bytes")
    fernet = _get_fernet()
    try:
        plaintext = fernet.decrypt(bytes(ciphertext))
    except InvalidToken as exc:
        raise CollectorEncryptionError(
            "Failed to decrypt collector credentials. Check COLLECTOR_ENCRYPTION_KEY."
        ) from exc
    try:
        return json.loads(plaintext.decode())
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectorEncryptionError(
            f"Decrypted credential payload was not valid JSON: {exc}"
        ) from exc


def rotate_ciphertext(ciphertext: bytes) -> bytes:
    """Re-encrypt ciphertext with the current primary key.

    Used during key rotation: load with all keys, re-encrypt with the new
    primary. Callers should update the database row in the same transaction.
    """
    fernet = _get_fernet()
    try:
        return fernet.rotate(ciphertext)
    except InvalidToken as exc:
        raise CollectorEncryptionError(
            "Failed to rotate collector credential ciphertext."
        ) from exc
