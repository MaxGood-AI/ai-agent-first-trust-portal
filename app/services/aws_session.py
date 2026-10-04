"""The single source of AWS credentials for the portal.

Every AWS call the portal makes - reading its secret, shipping logs, running
collectors in ``task_role`` mode, reading CodeCommit git sources - uses a
session from ``get_session()``.

- Base credentials come from the standard boto3 chain (environment variables
  ``AWS_ACCESS_KEY_ID`` / ``AWS_SECRET_ACCESS_KEY``, a shared profile, or an
  instance/task role).
- When ``AWS_RUNTIME_ROLE_ARN`` is set, the base credentials are used only to
  call ``sts:AssumeRole`` on that role (with ``AWS_RUNTIME_ROLE_EXTERNAL_ID``
  when set). The resulting credentials refresh automatically before they
  expire, so long-running processes never hold stale keys.
- Without ``AWS_RUNTIME_ROLE_ARN`` the base credentials are used directly.

Region: ``AWS_REGION`` (or ``AWS_DEFAULT_REGION``), overridable per call.
"""

from __future__ import annotations

import os
import socket
import threading
from datetime import timezone

import boto3
from botocore.credentials import DeferredRefreshableCredentials
from botocore.session import get_session as _botocore_session

ASSUME_ROLE_DURATION_SECONDS = 3600

_lock = threading.Lock()
_runtime_credentials = None
_runtime_key: tuple | None = None


def _setting(name: str) -> str | None:
    value = os.environ.get(name)
    return value.strip() if value and value.strip() else None


def default_region() -> str | None:
    return _setting("AWS_REGION") or _setting("AWS_DEFAULT_REGION")


def runtime_role_arn() -> str | None:
    return _setting("AWS_RUNTIME_ROLE_ARN")


def _session_name() -> str:
    host = socket.gethostname().replace(".", "-")[:40] or "portal"
    return f"trust-portal-{host}"[:64]


def assume_role_refresher(base_session: boto3.Session, role_arn: str, external_id: str | None,
                          session_name: str, region: str | None):
    """Return a zero-argument callable producing refreshable credential metadata."""

    def refresh():
        sts = base_session.client("sts", region_name=region)
        kwargs = {
            "RoleArn": role_arn,
            "RoleSessionName": session_name,
            "DurationSeconds": ASSUME_ROLE_DURATION_SECONDS,
        }
        if external_id:
            kwargs["ExternalId"] = external_id
        creds = sts.assume_role(**kwargs)["Credentials"]
        expiry = creds["Expiration"]
        if expiry.tzinfo is None:
            expiry = expiry.replace(tzinfo=timezone.utc)
        return {
            "access_key": creds["AccessKeyId"],
            "secret_key": creds["SecretAccessKey"],
            "token": creds["SessionToken"],
            "expiry_time": expiry.isoformat(),
        }

    return refresh


def session_with_refreshable_role(base_session: boto3.Session, role_arn: str,
                                  external_id: str | None = None,
                                  session_name: str | None = None,
                                  region: str | None = None) -> boto3.Session:
    """Build a boto3 session whose credentials come from (and refresh through)
    ``sts:AssumeRole`` on ``role_arn`` using ``base_session``."""
    credentials = DeferredRefreshableCredentials(
        refresh_using=assume_role_refresher(
            base_session, role_arn, external_id, session_name or _session_name(), region
        ),
        method="sts-assume-role",
    )
    return _session_from_credentials(credentials, region)


def _session_from_credentials(credentials, region: str | None) -> boto3.Session:
    core = _botocore_session()
    core._credentials = credentials  # noqa: SLF001 - documented botocore pattern
    if region:
        core.set_config_variable("region", region)
    return boto3.Session(botocore_session=core)


def _runtime_role_credentials(region: str | None):
    """Shared refreshable credentials for the runtime role (one per process)."""
    global _runtime_credentials, _runtime_key
    key = (runtime_role_arn(), _setting("AWS_RUNTIME_ROLE_EXTERNAL_ID"), region)
    with _lock:
        if _runtime_credentials is None or _runtime_key != key:
            base = boto3.Session(region_name=region) if region else boto3.Session()
            _runtime_credentials = DeferredRefreshableCredentials(
                refresh_using=assume_role_refresher(base, key[0], key[1], _session_name(), region),
                method="sts-assume-role",
            )
            _runtime_key = key
        return _runtime_credentials


def get_session(region: str | None = None) -> boto3.Session:
    """Return a boto3 session carrying the portal's runtime credentials.

    A new ``boto3.Session`` object is returned on every call (sessions are not
    thread-safe); the underlying refreshable credentials are shared.
    """
    region = region or default_region()
    if runtime_role_arn():
        return _session_from_credentials(_runtime_role_credentials(region), region)
    return boto3.Session(region_name=region) if region else boto3.Session()


def reset_for_tests() -> None:
    global _runtime_credentials, _runtime_key
    with _lock:
        _runtime_credentials = None
        _runtime_key = None
