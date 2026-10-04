"""Credential resolver for evidence collectors.

Given a CollectorConfig, returns a ready-to-use boto3 Session (for AWS
collectors) or a generic credentials dict (for non-AWS collectors).

Supports three v1 credential modes:

- ``task_role``: use the portal's runtime AWS session
  (``app.services.aws_session.get_session``: the runtime role assumed from
  the base credentials, or the default boto3 chain). Nothing is stored.
- ``task_role_assume``: from the runtime session, call ``sts:AssumeRole``
  on a configured target role ARN (optional external id). The resulting
  credentials refresh automatically.
- ``access_keys``: use stored (Fernet-encrypted) credentials. AWS
  collectors store ``access_key_id`` + ``secret_access_key`` (+ optional
  ``session_token``); non-AWS collectors (e.g. the platform collector) store
  their own keys such as ``bearer_token`` or ``basic_user``/``basic_password``,
  which are returned as ``raw`` without building an AWS session.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.models.collector_config import CollectorConfig
from app.services.collector_encryption import decrypt_credentials

logger = logging.getLogger(__name__)


SUPPORTED_MODES = {"task_role", "task_role_assume", "access_keys", "none"}

# Stored credential keys used by non-AWS collectors in access_keys mode.
GENERIC_CREDENTIAL_KEYS = ("bearer_token", "basic_user", "basic_password")


class CredentialResolutionError(Exception):
    """Raised when credentials cannot be resolved for a collector."""


@dataclass
class ResolvedCredentials:
    """Opaque handle to resolved credentials.

    For AWS collectors, ``boto_session`` is a ready-to-use boto3.Session.
    For non-AWS collectors, ``raw`` holds the decrypted credential dict.
    """

    mode: str
    boto_session: Any = None  # boto3.Session or None
    raw: dict[str, Any] | None = None
    expires_at: datetime | None = None

    @property
    def is_expired(self) -> bool:
        if self.expires_at is None:
            return False
        return datetime.now(timezone.utc) >= self.expires_at - timedelta(minutes=1)


class CredentialResolver:
    """Resolves and caches credentials for collector runs."""

    def __init__(self):
        self._cache: dict[str, ResolvedCredentials] = {}

    def resolve(self, config: CollectorConfig) -> ResolvedCredentials:
        """Return credentials for the given CollectorConfig.

        Results are cached per-config-id for the lifetime of this resolver
        instance, or until expiry for assume-role modes.
        """
        if config.credential_mode not in SUPPORTED_MODES:
            raise CredentialResolutionError(
                f"Unsupported credential_mode: {config.credential_mode}"
            )

        cached = self._cache.get(config.id)
        if cached and not cached.is_expired:
            return cached

        if config.credential_mode == "none":
            resolved = ResolvedCredentials(mode="none")
        elif config.credential_mode == "task_role":
            resolved = self._resolve_task_role(config)
        elif config.credential_mode == "task_role_assume":
            resolved = self._resolve_assume_role(config)
        elif config.credential_mode == "access_keys":
            resolved = self._resolve_access_keys(config)
        else:  # pragma: no cover — guarded above
            raise CredentialResolutionError(
                f"Unsupported credential_mode: {config.credential_mode}"
            )

        self._cache[config.id] = resolved
        return resolved

    def invalidate(self, config_id: str) -> None:
        self._cache.pop(config_id, None)

    # ----- mode handlers -----

    def _resolve_task_role(self, config: CollectorConfig) -> ResolvedCredentials:
        from app.services.aws_session import get_session

        region = (config.config or {}).get("region")
        return ResolvedCredentials(mode="task_role", boto_session=get_session(region))

    def _resolve_assume_role(self, config: CollectorConfig) -> ResolvedCredentials:
        from app.services.aws_session import get_session, session_with_refreshable_role

        creds = decrypt_credentials(config.encrypted_credentials)
        role_arn = creds.get("role_arn")
        if not role_arn:
            raise CredentialResolutionError(
                f"task_role_assume mode requires role_arn; none set for collector {config.name}"
            )
        region = (config.config or {}).get("region")
        session = session_with_refreshable_role(
            get_session(region),
            role_arn,
            external_id=creds.get("external_id"),
            session_name=creds.get("session_name") or f"trust-portal-{config.name}",
            region=region,
        )
        # Fail fast with a clear error rather than on the collector's first call.
        try:
            frozen = session.get_credentials().get_frozen_credentials()
        except Exception as exc:  # boto errors vary; normalize
            raise CredentialResolutionError(
                f"sts:AssumeRole failed for {role_arn}: {exc}"
            ) from exc
        if not frozen.access_key:
            raise CredentialResolutionError(f"sts:AssumeRole returned no credentials for {role_arn}")
        return ResolvedCredentials(mode="task_role_assume", boto_session=session)

    def _resolve_access_keys(self, config: CollectorConfig) -> ResolvedCredentials:
        creds = decrypt_credentials(config.encrypted_credentials)
        access_key = creds.get("access_key_id")
        secret_key = creds.get("secret_access_key")
        if not access_key and not secret_key and any(key in creds for key in GENERIC_CREDENTIAL_KEYS):
            # Non-AWS collector (bearer / basic auth): hand the collector its secrets.
            return ResolvedCredentials(mode="access_keys", raw=creds)
        if not access_key or not secret_key:
            raise CredentialResolutionError(
                f"access_keys mode requires access_key_id and secret_access_key "
                f"(or bearer_token / basic_user and basic_password) for collector {config.name}"
            )
        import boto3

        region = creds.get("region") or (config.config or {}).get("region")
        boto_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=creds.get("session_token"),
            region_name=region,
        )
        return ResolvedCredentials(mode="access_keys", boto_session=boto_session, raw=creds)
