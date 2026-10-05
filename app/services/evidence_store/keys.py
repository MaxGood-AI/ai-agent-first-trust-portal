"""Evidence-store keys and metadata (``docs/evidence-repo-spec.md`` -> "Keys",
"Writing an object"). Pure functions; no I/O.

Kinds
-----
- ``decision-logs/<YYYY-MM-DD>T<HHMMSS>Z_<session id>.jsonl``
  (:data:`DECISION_LOG_RE`; a real UTC date and time, a session id of 1 to
  100 of ``A-Z a-z 0-9 . _ -``): ``decision_log``, a decision-log transcript;
- the same stem with ``.meta.json``: ``decision_log_sidecar``, read for a
  transcript's agent and exit reason;
- ``pentest-evidence/layer<1-9>/<name>.json`` with a name of 1 to 200
  characters (:data:`PENTEST_RE`): ``pentest_evidence``, pentest findings;
- ``codex-reviews/**``, ``pentest-reports/**``, ``evidence/artifacts/**``:
  ``evidence_document``, a document of kind ``code-review``,
  ``pentest-report`` or ``evidence-artifact``.

Any other key under the prefixes and every key that is not a clean relative
path (empty, over 1,024 bytes, a leading ``/``, an empty, ``.`` or ``..``
segment, a backslash or a control character) is ``unmapped``. Every part of
a mapped key fits the column it is stored in: a key fits
``evidence_store_objects.key`` (3,072, room for an escaped key), a
transcript key a decision-log version's ``source_path`` (500) and a pentest
file's ``source_file`` in any namespace ``pentest_findings.source_file``
(500). A session id the
decision-log tables cannot hold (over 36 characters, or not starting with a
letter or digit) is refused by the decision-log import: the version is
recorded ``rejected``.

Escaped keys
------------
A key holding a control character (PostgreSQL text cannot hold NUL, and no
report should carry raw control characters) is recorded reversibly escaped:
:func:`stored_key` percent-encodes each control character and each ``%``
(``%XX``, upper-case hex of the code point) and the record's
``key_escaped`` flag is set; :func:`raw_key` gives the key back for every S3
call. Such a key is always ``unmapped``. Every other key is recorded as it
is, with the flag unset.

Metadata
--------
Every ``x-amz-meta-*`` value is untrusted. :func:`sanitize_metadata` keeps,
on every object whatever its kind (a bulk copy puts one folder's metadata on
each of its objects, sidecars included), the names of
:data:`METADATA_PATTERNS` whose value is US-ASCII printable, at
most 200 characters and matches the name's pattern (``session-id`` must also
equal the session id in a decision log's key); every other name or value is
dropped and noted (a note never repeats a dropped value).
"""

from __future__ import annotations

import posixpath
import re
import unicodedata
from dataclasses import dataclass
from datetime import datetime

KIND_DECISION_LOG = "decision_log"
KIND_SIDECAR = "decision_log_sidecar"
KIND_PENTEST = "pentest_evidence"
KIND_DOCUMENT = "evidence_document"
KIND_UNMAPPED = "unmapped"
KINDS = (KIND_DECISION_LOG, KIND_SIDECAR, KIND_PENTEST, KIND_DOCUMENT, KIND_UNMAPPED)

DOCUMENT_PREFIXES = {
    "codex-reviews/": "code-review",
    "pentest-reports/": "pentest-report",
    "evidence/artifacts/": "evidence-artifact",
}
MAX_KEY_BYTES = 1024
MAX_METADATA_VALUE = 200
MAX_CONTENT_TYPE = 255
MAX_TITLE = 500

TIMESTAMP_FORMAT = "%Y-%m-%dT%H%M%SZ"
_STEM = r"decision-logs/(?P<timestamp>[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{6}Z)_(?P<session>[A-Za-z0-9._-]{1,100})"
DECISION_LOG_RE = re.compile(rf"^{_STEM}\.jsonl$")
SIDECAR_RE = re.compile(rf"^{_STEM}\.meta\.json$")
PENTEST_RE = re.compile(r"^pentest-evidence/layer[1-9]/(?P<name>[^/]{1,200})\.json$")
_PRINTABLE_RE = re.compile(r"^[\x20-\x7e]*$")
_NAME_RE = re.compile(r"^[a-z0-9-]{1,64}$")

METADATA_PATTERNS = {
    "producer": re.compile(r"[a-z0-9-]{1,40}"),
    "agent": re.compile(r"[A-Za-z0-9_-]{1,50}"),
    "exit-reason": re.compile(r"[A-Za-z0-9_.-]{1,64}"),
    "session-id": re.compile(r"[A-Za-z0-9._-]{1,100}"),
    "redaction": re.compile(r"[A-Za-z0-9._-]{1,40}"),
    "source-repo": re.compile(r"[A-Za-z0-9._-]{1,100}"),
    "source-commit": re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}"),
    "source-blob": re.compile(r"[0-9a-f]{40}|[0-9a-f]{64}"),
}

# Content types the portal serves a document with (from its key's extension);
# anything else is served as application/octet-stream.
SERVE_CONTENT_TYPES = {
    ".jsonl": "application/x-ndjson",
    ".json": "application/json",
    ".md": "text/markdown; charset=utf-8",
    ".txt": "text/plain; charset=utf-8",
    ".log": "text/plain; charset=utf-8",
    ".out": "text/plain; charset=utf-8",
}
TEXT_EXTENSIONS = (".jsonl", ".json", ".md", ".txt", ".log", ".out")


@dataclass(frozen=True)
class Classified:
    """What a key is: its ``kind``, the document kind of an evidence document,
    the session id of a decision log, and why an unmapped key is unmapped."""

    kind: str
    document_kind: str | None = None
    session_id: str | None = None
    detail: str | None = None


_ESCAPED_RE = re.compile(r"%([0-9A-F]{2})")


def _control(ch: str) -> bool:
    return unicodedata.category(ch) == "Cc"


def stored_key(key: str) -> tuple[str, bool]:
    """``(the key as recorded, escaped)``: a key holding a control character
    percent-encoded with its ``%`` (module docstring), every other key as it is."""
    if not any(_control(ch) for ch in key):
        return key, False
    return "".join(f"%{ord(ch):02X}" if ch == "%" or _control(ch) else ch for ch in key), True


def raw_key(key: str, escaped: bool) -> str:
    """The S3 key of a recorded key (:func:`stored_key` reversed)."""
    if not escaped:
        return key
    return _ESCAPED_RE.sub(lambda match: chr(int(match.group(1), 16)), key)


def key_problem(key: str) -> str | None:
    """Why ``key`` is not a clean relative path, or None when it is."""
    if not key:
        return "the key is empty"
    if len(key.encode("utf-8", "surrogatepass")) > MAX_KEY_BYTES:
        return f"the key is longer than {MAX_KEY_BYTES:,} bytes"
    if key.startswith("/"):
        return "the key starts with /"
    if "\\" in key:
        return "the key contains a backslash"
    if any(unicodedata.category(ch) == "Cc" for ch in key):
        return "the key contains a control character"
    if any(segment in ("", ".", "..") for segment in key.split("/")):
        return "the key has an empty, . or .. segment"
    return None


def _decision_log_match(pattern, key: str):
    """The match of a decision-log key whose timestamp is a real date and time, else None."""
    match = pattern.match(key)
    if match is None:
        return None
    try:
        datetime.strptime(match.group("timestamp"), TIMESTAMP_FORMAT)
    except ValueError:
        return None
    return match


def classify(key: str) -> Classified:
    """The kind of ``key`` (module docstring)."""
    problem = key_problem(key)
    if problem:
        return Classified(KIND_UNMAPPED, detail=problem)
    match = _decision_log_match(DECISION_LOG_RE, key)
    if match:
        return Classified(KIND_DECISION_LOG, session_id=match.group("session"))
    if _decision_log_match(SIDECAR_RE, key):
        return Classified(KIND_SIDECAR)
    if PENTEST_RE.match(key):
        return Classified(KIND_PENTEST)
    for prefix, document_kind in DOCUMENT_PREFIXES.items():
        if key.startswith(prefix) and len(key) > len(prefix):
            return Classified(KIND_DOCUMENT, document_kind=document_kind)
    if key.startswith("decision-logs/"):
        return Classified(KIND_UNMAPPED, detail="not a decision-log key "
                                                "(<YYYY-MM-DD>T<HHMMSS>Z_<session id>.jsonl or .meta.json)")
    if key.startswith("pentest-evidence/"):
        return Classified(KIND_UNMAPPED, detail="not a pentest-evidence key (layer<1-9>/<name>.json)")
    return Classified(KIND_UNMAPPED, detail="no evidence-store kind maps this key")


def sidecar_key(transcript_key: str) -> str:
    """``decision-logs/<stem>.meta.json`` of ``decision-logs/<stem>.jsonl``."""
    return transcript_key[: -len(".jsonl")] + ".meta.json"


def _printable(value) -> bool:
    return isinstance(value, str) and len(value) <= MAX_METADATA_VALUE and bool(_PRINTABLE_RE.match(value))


def sanitize_metadata(raw, session_id: str | None = None) -> tuple[dict, list[str]]:
    """``(metadata, notes)``: the valid values of ``raw`` (module docstring) and
    what was dropped, never repeating a dropped value."""
    kept, notes, unknown = {}, [], 0
    for name, value in sorted((raw or {}).items(), key=lambda item: str(item[0])):
        name_text = str(name).lower()
        pattern = METADATA_PATTERNS.get(name_text)
        if pattern is None:
            unknown += 1
            continue
        if not _printable(value) or not pattern.fullmatch(value):
            notes.append(f"metadata {name_text}: invalid value dropped")
            continue
        if name_text == "session-id" and session_id is not None and value != session_id:
            notes.append("metadata session-id differs from the session id in the key; dropped")
            continue
        kept[name_text] = value
    if unknown:
        notes.append(f"{unknown} unknown metadata name(s) dropped")
    return kept, notes


def sanitize_content_type(value) -> str | None:
    """The producer's content type when it is printable ASCII of at most 255 characters."""
    if isinstance(value, str) and value and len(value) <= MAX_CONTENT_TYPE and _PRINTABLE_RE.match(value):
        return value
    return None


def document_title(key: str) -> str:
    """A document's title: its key without the kind's prefix."""
    for prefix in DOCUMENT_PREFIXES:
        if key.startswith(prefix):
            return key[len(prefix):][:MAX_TITLE]
    return key[:MAX_TITLE]


def serve_content_type(key: str) -> str:
    """The content type the portal serves ``key`` with (from its extension, never the producer's)."""
    return SERVE_CONTENT_TYPES.get(posixpath.splitext(key)[1].lower(), "application/octet-stream")


def is_text(key: str) -> bool:
    return key.lower().endswith(TEXT_EXTENSIONS)


def display(key: str, limit: int = 300) -> str:
    """``key`` for a log line or a report: control characters escaped, at most ``limit`` characters."""
    text = "".join(ch if unicodedata.category(ch) != "Cc" else f"\\x{ord(ch):02x}" for ch in key)
    return text if len(text) <= limit else text[: limit - 3] + "..."
