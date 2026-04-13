"""Credential resolver for evidence collectors.

Given a CollectorConfig, returns a ready-to-use boto3 Session (for AWS
collectors) or a generic credentials dict (for non-AWS collectors).

Supports three v1 credential modes:

- ``task_role``: use the default boto3 credential chain (ECS task role,
  EC2 instance role, env vars, shared config). Nothing is stored.
- ``task_role_assume``: use the default chain to call ``sts:AssumeRole``
  on a configured target role ARN. Short-lived credentials are cached
  until expiry.
- ``access_keys``: use stored (Fernet-encrypted) access key + secret
  (+ optional session token).

Cross-account assume-role is explicitly out of v1 scope.
"""

import logging
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from app.models.collector_config import CollectorConfig
from app.services.collector_encryption import decrypt_credentials

logger = logging.getLogger(__name__)


SUPPORTED_MODES = {"task_role", "task_role_assume", "access_keys", "none"}


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
        try:
            import boto3
        except ImportError as exc:
            raise CredentialResolutionError(
                "boto3 is not installed; cannot resolve task_role credentials"
            ) from exc
        region = (config.config or {}).get("region")
        session = boto3.Session(region_name=region) if region else boto3.Session()
        return ResolvedCredentials(mode="task_role", boto_session=session)

    def _resolve_assume_role(self, config: CollectorConfig) -> ResolvedCredentials:
        try:
            import boto3
        except ImportError as exc:
            raise CredentialResolutionError(
                "boto3 is not installed; cannot resolve task_role_assume credentials"
            ) from exc

        creds = decrypt_credentials(config.encrypted_credentials)
        role_arn = creds.get("role_arn")
        if not role_arn:
            raise CredentialResolutionError(
                f"task_role_assume mode requires role_arn; none set for collector {config.name}"
            )
        external_id = creds.get("external_id")
        session_name = creds.get("session_name") or f"trust-portal-{config.name}"
        region = (config.config or {}).get("region")

        base_session = boto3.Session(region_name=region) if region else boto3.Session()
        sts = base_session.client("sts")
        assume_kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": 3600,
        }
        if external_id:
            assume_kwargs["ExternalId"] = external_id

        try:
            response = sts.assume_role(**assume_kwargs)
        except Exception as exc:  # boto errors vary; normalize
            raise CredentialResolutionError(
                f"sts:AssumeRole failed for {role_arn}: {exc}"
            ) from exc

        c = response["Credentials"]
        assumed_session = boto3.Session(
            aws_access_key_id=c["AccessKeyId"],
            aws_secret_access_key=c["SecretAccessKey"],
            aws_session_token=c["SessionToken"],
            region_name=region,
        )
        expires_at = c["Expiration"]
        if expires_at.tzinfo is None:
            expires_at = expires_at.replace(tzinfo=timezone.utc)

        return ResolvedCredentials(
            mode="task_role_assume",
            boto_session=assumed_session,
            expires_at=expires_at,
        )

    def _resolve_access_keys(self, config: CollectorConfig) -> ResolvedCredentials:
        creds = decrypt_credentials(config.encrypted_credentials)
        access_key = creds.get("access_key_id")
        secret_key = creds.get("secret_access_key")
        if not access_key or not secret_key:
            raise CredentialResolutionError(
                f"access_keys mode requires access_key_id and secret_access_key "
                f"for collector {config.name}"
            )
        session_token = creds.get("session_token")
        region = creds.get("region") or (config.config or {}).get("region")

        try:
            import boto3
        except ImportError:
            # Non-AWS collector using generic credentials
            return ResolvedCredentials(mode="access_keys", raw=creds)

        boto_session = boto3.Session(
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
            aws_session_token=session_token,
            region_name=region,
        )
        return ResolvedCredentials(
            mode="access_keys",
            boto_session=boto_session,
            raw=creds,
        )
