"""Path mappings: which repository paths a git source reads, and as what.

A mapping is ``{"pattern": <glob>, "kind": <kind>}``. The first mapping whose
pattern matches a repository path decides the path's kind; unmatched paths
are ignored. Patterns use ``/`` separators and:

- ``*`` matches any characters within one path segment,
- ``?`` matches one character within a segment,
- ``**`` matches any number of whole segments (including none), so
  ``policies/**/*.md`` matches ``policies/a.md`` and ``policies/x/y/a.md``,
  and ``infrastructure/**`` matches every file below ``infrastructure/``.

Kinds
-----
``policy``
    Policy markdown; stored as versioned content and rendered on the public
    policy pages for policies whose ``file_path`` names it.
``governance_document``
    Any other governance file (agent instructions, infrastructure and agent
    configuration docs); stored as versioned content, shown to admins only.
``dataset:<name>``
    An evidence dataset file, imported by the diff-only import engine.
``decision_log``
    A decision-log transcript (``*.jsonl``) or the manifest of a chunked one.

Defaults
--------
A source without ``path_mappings`` uses its role's defaults: for
``governance`` :data:`DEFAULT_GOVERNANCE_MAPPINGS`, for ``evidence``
``evidence_import.DEFAULT_EVIDENCE_MAPPINGS`` (every kind of the evidence
repository layout). An evidence source whose repository leaves pentest
evidence and decision logs to the evidence store has
``evidence_import.AUTHORED_EVIDENCE_MAPPINGS`` (the six authored datasets) as
its ``path_mappings``.

New kinds (for example portal configuration kept in the governance repo)
are added by extending ``CONTENT_KINDS`` or the import dispatch in
``app.services.git_sources.sync``.
"""

from __future__ import annotations

import re
from functools import lru_cache

CONTENT_KINDS = ("policy", "governance_document")

DEFAULT_GOVERNANCE_MAPPINGS = [
    {"pattern": "policies/**/*.md", "kind": "policy"},
    {"pattern": "CLAUDE.md", "kind": "governance_document"},
    {"pattern": "AGENTS.md", "kind": "governance_document"},
    {"pattern": "README.md", "kind": "governance_document"},
    {"pattern": "infrastructure/**", "kind": "governance_document"},
    {"pattern": "agent-config/**", "kind": "governance_document"},
]


def default_mappings(role: str) -> list[dict]:
    if role == "governance":
        return [dict(m) for m in DEFAULT_GOVERNANCE_MAPPINGS]
    if role == "evidence":
        from app.services.evidence_import import DEFAULT_EVIDENCE_MAPPINGS
        return [dict(m) for m in DEFAULT_EVIDENCE_MAPPINGS]
    raise ValueError(f"unknown git source role: {role}")


def effective_mappings(source) -> list[dict]:
    return list(source.path_mappings) if source.path_mappings else default_mappings(source.role)


@lru_cache(maxsize=512)
def _compile(pattern: str) -> re.Pattern:
    parts = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            parts.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile("^" + "".join(parts) + "$")


def matches(path: str, pattern: str) -> bool:
    return bool(_compile(pattern).match(path))


def classify(path: str, mappings: list[dict]) -> str | None:
    """Kind of ``path`` under ``mappings`` (first match wins), or None."""
    for mapping in mappings:
        if matches(path, mapping["pattern"]):
            return mapping["kind"]
    return None


VALID_KIND = re.compile(r"^(policy|governance_document|decision_log|dataset:[a-z-]+)$")


def validate_mappings(mappings) -> list[dict]:
    """Validate an admin-supplied mapping list; returns a normalized copy."""
    if mappings is None:
        return None
    if not isinstance(mappings, list) or not mappings:
        raise ValueError("path_mappings must be a non-empty list of {pattern, kind} objects, or null")
    normalized = []
    for item in mappings:
        if not isinstance(item, dict) or not isinstance(item.get("pattern"), str) \
                or not isinstance(item.get("kind"), str):
            raise ValueError("each path mapping needs string 'pattern' and 'kind'")
        pattern = item["pattern"].strip().lstrip("/")
        if not pattern or ".." in pattern.split("/"):
            raise ValueError(f"invalid pattern: {item['pattern']!r}")
        if not VALID_KIND.match(item["kind"]):
            raise ValueError(f"invalid kind: {item['kind']!r}")
        if item["kind"].startswith("dataset:"):
            from app.services.evidence_import import DATASET_ORDER
            if item["kind"].split(":", 1)[1] not in DATASET_ORDER:
                raise ValueError(f"unknown dataset in kind {item['kind']!r}; "
                                 f"datasets: {', '.join(DATASET_ORDER)}")
        normalized.append({"pattern": pattern, "kind": item["kind"]})
    return normalized
