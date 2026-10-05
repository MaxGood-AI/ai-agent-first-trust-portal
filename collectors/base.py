"""Base interface for evidence collectors.

- Collectors accept a ``CollectorConfig`` and a ``CredentialResolver``: their
  configuration lives in the portal database (admin UI or API) and stored
  credentials are Fernet-encrypted.
- They declare ``required_permissions`` so the ``PermissionProber`` can tell an
  admin up front whether the role/credentials will work.
- ``run()`` produces structured ``CheckResult`` objects that the executor maps
  to ``CollectorRun`` / ``CollectorCheckResult`` / ``Evidence`` database rows.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from types import SimpleNamespace
from typing import Any

from app.models.collector_config import CollectorConfig
from app.services.credential_resolver import CredentialResolver, ResolvedCredentials


@dataclass
class CheckResult:
    """One check's outcome from a collector run.

    ``target_test_name`` lets the executor resolve a TestRecord to link the
    created Evidence row to — exact name match first, then a match ignoring
    case and surrounding spaces.
    """

    check_name: str
    status: str  # "pass" | "fail" | "error" | "skipped"
    target_test_name: str | None = None
    message: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    evidence_description: str | None = None


class BaseCollector(ABC):
    """Abstract base class for v2 evidence collectors.

    Subclasses must declare ``name`` and ``required_permissions`` as class
    attributes and implement ``run()``.
    """

    name: str = ""
    required_permissions: list[str] = []
    credential_modes_supported: list[str] = [
        "task_role",
        "task_role_assume",
        "access_keys",
    ]

    def __init__(
        self,
        config: CollectorConfig,
        resolver: CredentialResolver | None = None,
    ):
        self.config = config
        self.resolver = resolver or CredentialResolver()
        self._resolved: ResolvedCredentials | None = None

    @property
    def resolved(self) -> ResolvedCredentials:
        if self._resolved is None:
            self._resolved = self.resolver.resolve(self.config)
        return self._resolved

    @abstractmethod
    def run(self) -> list[CheckResult]:
        """Execute all checks and return structured results.

        Must not raise; per-check errors should be captured as
        ``CheckResult(status="error", message=...)`` so a single failing probe
        does not abort the entire run.
        """


def read_snapshot(query) -> list[SimpleNamespace]:
    """Run a read-only ORM query, copy each row's columns into a plain object,
    and end the read transaction.

    Collectors use it before slow work (HTTP probes, cloud API calls), so no
    database transaction - and no table lock - stays open while they run.
    """
    from sqlalchemy import inspect as sa_inspect

    from app.models import db

    rows = query.all()
    snapshot = [
        SimpleNamespace(**{attr.key: getattr(row, attr.key) for attr in sa_inspect(type(row)).column_attrs})
        for row in rows
    ]
    db.session.rollback()
    return snapshot
