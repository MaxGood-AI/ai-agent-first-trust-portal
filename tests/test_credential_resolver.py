"""Tests for the CredentialResolver service."""

import uuid
from unittest.mock import MagicMock, patch

import pytest
from cryptography.fernet import Fernet

from app import create_app
from app.config import TestConfig
from app.models import CollectorConfig, db
from app.services.collector_encryption import encrypt_credentials
from app.services.credential_resolver import (
    CredentialResolutionError,
    CredentialResolver,
    ResolvedCredentials,
)


@pytest.fixture
def app_ctx(monkeypatch):
    monkeypatch.setenv("COLLECTOR_ENCRYPTION_KEY", Fernet.generate_key().decode())
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def _make_config(**kwargs):
    defaults = {
        "id": str(uuid.uuid4()),
        "name": "aws",
        "enabled": False,
        "credential_mode": "task_role",
    }
    defaults.update(kwargs)
    return CollectorConfig(**defaults)


def test_rejects_unknown_mode(app_ctx):
    config = _make_config(credential_mode="nonsense")
    db.session.add(config)
    db.session.commit()
    resolver = CredentialResolver()
    with pytest.raises(CredentialResolutionError):
        resolver.resolve(config)


def test_none_mode_returns_empty(app_ctx):
    config = _make_config(credential_mode="none")
    db.session.add(config)
    db.session.commit()
    resolver = CredentialResolver()
    resolved = resolver.resolve(config)
    assert resolved.mode == "none"
    assert resolved.boto_session is None


def test_task_role_uses_default_session(app_ctx):
    config = _make_config(credential_mode="task_role", config={"region": "ca-central-1"})
    db.session.add(config)
    db.session.commit()
    resolver = CredentialResolver()
    resolved = resolver.resolve(config)
    assert resolved.mode == "task_role"
    assert resolved.boto_session is not None
    assert resolved.boto_session.region_name == "ca-central-1"


def test_access_keys_mode_uses_stored_credentials(app_ctx):
    creds = {
        "access_key_id": "AKIATEST",
        "secret_access_key": "SECRETTEST",
        "region": "us-east-1",
    }
    config = _make_config(
        credential_mode="access_keys",
        encrypted_credentials=encrypt_credentials(creds),
    )
    db.session.add(config)
    db.session.commit()

    resolver = CredentialResolver()
    resolved = resolver.resolve(config)
    assert resolved.mode == "access_keys"
    assert resolved.boto_session is not None
    credentials = resolved.boto_session.get_credentials()
    assert credentials.access_key == "AKIATEST"
    assert credentials.secret_key == "SECRETTEST"


def test_access_keys_missing_fields_raises(app_ctx):
    config = _make_config(
        credential_mode="access_keys",
        encrypted_credentials=encrypt_credentials({"access_key_id": "only"}),
    )
    db.session.add(config)
    db.session.commit()
    resolver = CredentialResolver()
    with pytest.raises(CredentialResolutionError):
        resolver.resolve(config)


def test_task_role_assume_missing_role_arn_raises(app_ctx):
    config = _make_config(
        credential_mode="task_role_assume",
        encrypted_credentials=encrypt_credentials({}),
    )
    db.session.add(config)
    db.session.commit()
    resolver = CredentialResolver()
    with pytest.raises(CredentialResolutionError):
        resolver.resolve(config)


def test_task_role_assume_calls_sts(app_ctx):
    from datetime import datetime, timezone

    config = _make_config(
        credential_mode="task_role_assume",
        encrypted_credentials=encrypt_credentials(
            {"role_arn": "arn:aws:iam::123:role/trust-portal-collector-role"}
        ),
        config={"region": "ca-central-1"},
    )
    db.session.add(config)
    db.session.commit()

    expiration = datetime(2030, 1, 1, tzinfo=timezone.utc)
    sts_mock = MagicMock()
    sts_mock.assume_role.return_value = {
        "Credentials": {
            "AccessKeyId": "ASIATEST",
            "SecretAccessKey": "SECRET",
            "SessionToken": "TOKEN",
            "Expiration": expiration,
        }
    }

    base_session = MagicMock()
    base_session.client.return_value = sts_mock

    assumed_session = MagicMock()
    assumed_session.region_name = "ca-central-1"

    with patch("boto3.Session", side_effect=[base_session, assumed_session]) as mock_session:
        resolver = CredentialResolver()
        resolved = resolver.resolve(config)

    sts_mock.assume_role.assert_called_once()
    call_kwargs = sts_mock.assume_role.call_args.kwargs
    assert call_kwargs["RoleArn"] == "arn:aws:iam::123:role/trust-portal-collector-role"
    assert call_kwargs["RoleSessionName"] == "trust-portal-aws"
    assert resolved.mode == "task_role_assume"
    assert resolved.expires_at == expiration
    # Second call should use cached credentials
    resolver.resolve(config)
    assert sts_mock.assume_role.call_count == 1


def test_resolved_credentials_expiry_detection():
    from datetime import datetime, timedelta, timezone

    past = datetime.now(timezone.utc) - timedelta(minutes=5)
    future = datetime.now(timezone.utc) + timedelta(hours=1)

    assert ResolvedCredentials(mode="x", expires_at=past).is_expired is True
    assert ResolvedCredentials(mode="x", expires_at=future).is_expired is False
    assert ResolvedCredentials(mode="x", expires_at=None).is_expired is False


def test_resolver_invalidate(app_ctx):
    config = _make_config(credential_mode="task_role")
    db.session.add(config)
    db.session.commit()
    resolver = CredentialResolver()
    resolver.resolve(config)
    assert config.id in resolver._cache
    resolver.invalidate(config.id)
    assert config.id not in resolver._cache
