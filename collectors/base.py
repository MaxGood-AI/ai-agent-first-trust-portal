"""Base interface for v2 evidence collectors.

v2 collectors differ from the legacy ``base_collector.BaseCollector``:

- They accept a ``CollectorConfig`` and a ``CredentialResolver``, so credentials
  flow from the portal DB (encrypted) rather than environment variables.
- They declare ``required_permissions`` so the ``PermissionProber`` can tell an
  admin up front whether the role/credentials will work.
- ``run()`` produces structured ``CheckResult`` objects that the executor maps
  to ``CollectorRun`` / ``CollectorCheckResult`` / ``Evidence`` database rows.

The legacy ``collectors/base_collector.py`` and ``collectors/aws_collector.py``
remain in place for now — they are being replaced by this interface and the
``collectors/aws/`` package, but the cutover happens incrementally so existing
tests continue to pass.
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from app.models.collector_config import CollectorConfig
from app.services.credential_resolver import CredentialResolver, ResolvedCredentials


@dataclass
class CheckResult:
    """One check's outcome from a collector run.

    ``target_test_name`` lets the executor resolve a TestRecord to link the
    created Evidence row to — exact name match first, then relaxed match.
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
