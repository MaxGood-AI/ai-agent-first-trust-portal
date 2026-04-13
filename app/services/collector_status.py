"""Aggregate status helpers for evidence collectors.

Used by:

- The admin dashboard banner ("set up evidence collection") which appears
  when no collector has run successfully yet.
- The first-login setup wizard to show per-collector progress.
- The compliance journey API (phase 5) to count configured collectors.

These helpers are read-only and safe to call from any request handler.
"""

from dataclasses import dataclass

from app.models.collector_config import CollectorConfig


# The five collectors the wizard walks an admin through. The order here
# is the order they appear in the wizard. Each entry is (name, label,
# description).
COLLECTOR_CATALOG: list[tuple[str, str, str]] = [
    (
        "aws",
        "AWS Infrastructure",
        "IAM, S3, RDS, EC2, CloudTrail, KMS, and more — the primary source "
        "for SOC 2 infrastructure evidence.",
    ),
    (
        "git",
        "Git / CodeCommit",
        "Branch protection, PR reviews, commit-message compliance — change "
        "management evidence.",
    ),
    (
        "platform",
        "Platform Services",
        "Health and configuration probes for your own internal services.",
    ),
    (
        "policy",
        "Policies",
        "Policy currency and approval status.",
    ),
    (
        "vendor",
        "Vendors",
        "Vendor security pages and SOC 2 report availability.",
    ),
]


@dataclass
class CollectorSetupStatus:
    name: str
    label: str
    description: str
    configured: bool
    enabled: bool
    has_successful_run: bool
    last_run_status: str | None
    last_run_at: str | None  # ISO-formatted string, or None


@dataclass
class CollectorOverview:
    total: int
    configured: int
    enabled: int
    running_successfully: int
    needs_setup: bool
    statuses: list[CollectorSetupStatus]
    most_recent_success_at: str | None = None
    evidence_last_7_days: int = 0
    any_failing: bool = False

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "configured": self.configured,
            "enabled": self.enabled,
            "running_successfully": self.running_successfully,
            "needs_setup": self.needs_setup,
            "most_recent_success_at": self.most_recent_success_at,
            "evidence_last_7_days": self.evidence_last_7_days,
            "any_failing": self.any_failing,
            "statuses": [
                {
                    "name": s.name,
                    "label": s.label,
                    "description": s.description,
                    "configured": s.configured,
                    "enabled": s.enabled,
                    "has_successful_run": s.has_successful_run,
                    "last_run_status": s.last_run_status,
                    "last_run_at": s.last_run_at,
                }
                for s in self.statuses
            ],
        }


def get_overview() -> CollectorOverview:
    """Compute current collector setup state across the full catalog."""
    from datetime import datetime, timedelta, timezone

    from app.models import Evidence

    configs_by_name = {c.name: c for c in CollectorConfig.query.all()}
    statuses: list[CollectorSetupStatus] = []
    configured = 0
    enabled = 0
    running_successfully = 0
    any_failing = False
    most_recent_success: datetime | None = None

    for name, label, description in COLLECTOR_CATALOG:
        config = configs_by_name.get(name)
        has_run = bool(config and config.last_run_status == "success")
        status = CollectorSetupStatus(
            name=name,
            label=label,
            description=description,
            configured=config is not None,
            enabled=bool(config and config.enabled),
            has_successful_run=has_run,
            last_run_status=config.last_run_status if config else None,
            last_run_at=(
                config.last_run_at.isoformat()
                if config and config.last_run_at
                else None
            ),
        )
        statuses.append(status)
        if status.configured:
            configured += 1
        if status.enabled:
            enabled += 1
        if status.has_successful_run:
            running_successfully += 1
            if config and config.last_run_at:
                last_run_aware = config.last_run_at
                if last_run_aware.tzinfo is None:
                    last_run_aware = last_run_aware.replace(tzinfo=timezone.utc)
                if most_recent_success is None or last_run_aware > most_recent_success:
                    most_recent_success = last_run_aware
        if config and config.last_run_status in ("failure", "partial"):
            any_failing = True

    # Evidence produced by any collector in the last 7 days.
    since = datetime.now(timezone.utc) - timedelta(days=7)
    try:
        evidence_7d = (
            Evidence.query
            .filter(Evidence.collector_name.isnot(None))
            .filter(Evidence.collected_at >= since)
            .count()
        )
    except Exception:  # noqa: BLE001
        # Schemas without collector_name/collected_at should never happen in
        # practice; guard against unit-test fixtures that pre-date those
        # columns.
        evidence_7d = 0

    return CollectorOverview(
        total=len(COLLECTOR_CATALOG),
        configured=configured,
        enabled=enabled,
        running_successfully=running_successfully,
        needs_setup=running_successfully == 0,
        statuses=statuses,
        most_recent_success_at=(
            most_recent_success.isoformat() if most_recent_success else None
        ),
        evidence_last_7_days=evidence_7d,
        any_failing=any_failing,
    )
