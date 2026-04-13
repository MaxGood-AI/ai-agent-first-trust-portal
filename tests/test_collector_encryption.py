"""Tests for collector credential encryption (Fernet + MultiFernet rotation)."""

import os

import pytest
from cryptography.fernet import Fernet

from app.services.collector_encryption import (
    CollectorEncryptionError,
    decrypt_credentials,
    encrypt_credentials,
    rotate_ciphertext,
)


@pytest.fixture
def single_key(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEY", key)
    monkeypatch.delenv("COLLECTOR_ENCRYPTION_KEYS", raising=False)
    return key


@pytest.fixture
def rotated_keys(monkeypatch):
    new_key = Fernet.generate_key().decode()
    old_key = Fernet.generate_key().decode()
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEYS", f"{new_key},{old_key}")
    monkeypatch.delenv("COLLECTOR_ENCRYPTION_KEY", raising=False)
    return new_key, old_key


def test_encrypt_round_trip(single_key):
    payload = {"access_key_id": "AKIATEST", "secret_access_key": "wJalr..."}
    ciphertext = encrypt_credentials(payload)
    assert isinstance(ciphertext, bytes)
    assert b"AKIATEST" not in ciphertext
    assert b"wJalr" not in ciphertext
    recovered = decrypt_credentials(ciphertext)
    assert recovered == payload


def test_encrypt_deterministic_json(single_key):
    """Keys are sorted so two encryptions of the same payload decrypt to the same dict."""
    payload = {"b": 2, "a": 1}
    c1 = encrypt_credentials(payload)
    c2 = encrypt_credentials(payload)
    assert decrypt_credentials(c1) == decrypt_credentials(c2) == payload


def test_decrypt_none_returns_empty(single_key):
    assert decrypt_credentials(None) == {}


def test_encrypt_rejects_non_dict(single_key):
    with pytest.raises(CollectorEncryptionError):
        encrypt_credentials("a string")  # type: ignore[arg-type]


def test_decrypt_rejects_non_bytes(single_key):
    with pytest.raises(CollectorEncryptionError):
        decrypt_credentials("not bytes")  # type: ignore[arg-type]


def test_missing_key_raises(monkeypatch):
    monkeypatch.delenv("COLLECTOR_ENCRYPTION_KEY", raising=False)
    monkeypatch.delenv("COLLECTOR_ENCRYPTION_KEYS", raising=False)
    with pytest.raises(CollectorEncryptionError):
        encrypt_credentials({"x": 1})


def test_invalid_key_raises(monkeypatch):
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEY", "not-a-valid-fernet-key")
    monkeypatch.delenv("COLLECTOR_ENCRYPTION_KEYS", raising=False)
    with pytest.raises(CollectorEncryptionError):
        encrypt_credentials({"x": 1})


def test_multifernet_decrypts_with_old_key(rotated_keys):
    new_key, old_key = rotated_keys
    # Encrypt using only the old key
    old_fernet = Fernet(old_key.encode())
    import json
    payload = {"secret": "value"}
    ciphertext = old_fernet.encrypt(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    # Decrypt via MultiFernet that has the old key as a fallback
    recovered = decrypt_credentials(ciphertext)
    assert recovered == payload


def test_rotate_ciphertext(rotated_keys):
    new_key, old_key = rotated_keys
    # Encrypt with old key only (simulating a pre-rotation ciphertext)
    import json
    old_fernet = Fernet(old_key.encode())
    payload = {"secret": "value"}
    old_ciphertext = old_fernet.encrypt(
        json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()
    )
    # Rotate to the new primary
    new_ciphertext = rotate_ciphertext(old_ciphertext)
    assert new_ciphertext != old_ciphertext
    # New ciphertext decrypts under the new key only
    new_fernet = Fernet(new_key.encode())
    plaintext = new_fernet.decrypt(new_ciphertext)
    assert json.loads(plaintext.decode()) == payload


def test_decrypt_tampered_ciphertext_raises(single_key):
    ciphertext = encrypt_credentials({"x": 1})
    tampered = ciphertext[:-5] + b"AAAAA"
    with pytest.raises(CollectorEncryptionError):
        decrypt_credentials(tampered)
