"""Every S3 call of the evidence store, through the runtime role.

The package calls exactly these operations, on clients from
:func:`s3_client`: ``list_object_versions``, ``head_object``,
``get_object``, ``get_bucket_versioning``,
``get_object_lock_configuration``, ``get_bucket_policy`` and
``get_bucket_lifecycle_configuration`` (the deployment grants the runtime
role exactly their IAM actions on the evidence bucket, and nothing that
writes).

- Listings are read a page at a time (:data:`LIST_PAGE_SIZE` versions) and
  grouped by key (:func:`iter_groups`): a key's versions are listed newest
  first, so the last one listed is its first write. Only one page and one
  group are held at a time. :func:`iter_groups_safely` ends at a listing
  error and hands it to its caller to report.
- Bodies are read in chunks of :data:`READ_CHUNK` bytes and never beyond a
  caller's limit plus one chunk (:func:`read_version`, :func:`hash_version`).
- A version's stored checksum is the ``ChecksumSHA256`` S3 stored at upload
  (:func:`stored_checksum`): a full-object SHA-256 (a single ``PutObject``),
  or a SHA-256 COMPOSITE checksum (a multipart upload with SHA-256 part
  checksums: the checksum of the parts' checksums, reported with a
  ``-<parts>`` suffix and ``ChecksumType`` ``COMPOSITE``). An object with no
  SHA-256 checksum (none, or another algorithm's only) is refused, and so is
  a malformed one.
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import re
from dataclasses import dataclass, field

LIST_PAGE_SIZE = 1000
READ_CHUNK = 1024 * 1024
MAX_GROUP_DETAIL = 20
MISSING_CODES = frozenset({"404", "NoSuchKey", "NoSuchVersion"})
DELETE_MARKER_CODES = frozenset({"405", "MethodNotAllowed"})
_CODE_RE = re.compile(r"^[A-Za-z0-9._-]{1,64}$")
DAYS_PER_YEAR = 365


class BodyTooLarge(Exception):
    """A body is larger than the reader's limit (nothing beyond it was kept)."""

    def __init__(self, read: int, limit: int):
        super().__init__(f"the body is larger than {limit} bytes")
        self.read = read
        self.limit = limit


@dataclass(frozen=True)
class ListedVersion:
    key: str
    version_id: str
    size: int
    last_modified: object
    delete_marker: bool = False


@dataclass
class KeyGroup:
    """Every listed version and delete marker of one key, in listing order
    (newest first): ``first`` is the version listed last, the key's first
    write; ``later`` the other versions (at most :data:`MAX_GROUP_DETAIL`
    kept, ``later_count`` counts them all), ``markers`` its delete markers
    (likewise capped, ``marker_count``)."""

    key: str
    first: ListedVersion | None = None
    later: list = field(default_factory=list)
    later_count: int = 0
    markers: list = field(default_factory=list)
    marker_count: int = 0

    def add(self, item: ListedVersion) -> None:
        if item.delete_marker:
            self.marker_count += 1
            if len(self.markers) < MAX_GROUP_DETAIL:
                self.markers.append(item)
            return
        if self.first is not None:
            self.later_count += 1
            if len(self.later) < MAX_GROUP_DETAIL:
                self.later.append(self.first)
        self.first = item


def s3_client():
    """S3 client of the runtime role, with short timeouts and bounded retries."""
    from botocore.config import Config

    from app.services.aws_session import get_session

    return get_session().client("s3", config=Config(
        connect_timeout=5, read_timeout=30, retries={"max_attempts": 3, "mode": "standard"}))


def error_code(exc) -> str:
    """The S3 error code of ``exc`` (or the SQLSTATE of a database error), when it is a plain code."""
    response = getattr(exc, "response", None)
    code = response.get("Error", {}).get("Code", "") if isinstance(response, dict) else ""
    if not code:
        code = getattr(getattr(exc, "orig", exc), "pgcode", None) or ""
    code = str(code)
    return code if _CODE_RE.match(code) else ""


def describe(exc) -> str:
    """``<exception class> <code>``: what a run or a record says about an error, never its message
    (S3 and database messages carry ARNs, account ids, keys and values)."""
    code = error_code(exc)
    return f"{type(exc).__name__} {code}" if code else type(exc).__name__


def is_missing(exc) -> bool:
    """True for the error of a version (or key) that does not exist."""
    return error_code(exc) in MISSING_CODES


def is_delete_marker(exc) -> bool:
    """True for the error of a version id that names a delete marker."""
    return error_code(exc) in DELETE_MARKER_CODES


def _listed(entry: dict, delete_marker: bool) -> ListedVersion:
    return ListedVersion(key=entry["Key"], version_id=str(entry.get("VersionId") or "null"),
                         size=int(entry.get("Size") or 0), last_modified=entry.get("LastModified"),
                         delete_marker=delete_marker)


def iter_groups(client, bucket: str, prefix: str, start_after: str | None = None,
                page_size: int = LIST_PAGE_SIZE):
    """Yield a :class:`KeyGroup` per key under ``prefix``, in key order, after
    the key ``start_after`` (exclusive) when given."""
    request = {"Bucket": bucket, "Prefix": prefix, "MaxKeys": page_size}
    if start_after:
        request["KeyMarker"] = start_after
    group = None
    while True:
        page = client.list_object_versions(**request)
        entries = [(v["Key"], 0, index, _listed(v, False)) for index, v in enumerate(page.get("Versions") or [])]
        entries += [(m["Key"], 1, index, _listed(m, True))
                    for index, m in enumerate(page.get("DeleteMarkers") or [])]
        entries.sort(key=lambda entry: entry[:3])
        for key, _, _, item in entries:
            if group is not None and group.key != key:
                yield group
                group = None
            if group is None:
                group = KeyGroup(key)
            group.add(item)
        if not page.get("IsTruncated"):
            break
        request["KeyMarker"] = page.get("NextKeyMarker")
        if page.get("NextVersionIdMarker"):
            request["VersionIdMarker"] = page["NextVersionIdMarker"]
        else:
            request.pop("VersionIdMarker", None)
    if group is not None:
        yield group


def iter_groups_safely(client, bucket: str, prefix: str, errors: list, start_after: str | None = None):
    """:func:`iter_groups` that ends at a listing error instead of raising it:
    the error is appended to ``errors`` for the caller to report. Errors of
    the caller's own work between groups are not caught."""
    try:
        yield from iter_groups(client, bucket, prefix, start_after=start_after)
    except Exception as exc:  # noqa: BLE001 - reported by the caller, never a crash
        errors.append(exc)


def head_version(client, bucket: str, key: str, version_id: str) -> dict:
    """``HeadObject`` of one version, with its checksum."""
    return client.head_object(Bucket=bucket, Key=key, VersionId=version_id, ChecksumMode="ENABLED")


@dataclass(frozen=True)
class StoredChecksum:
    """The SHA-256 checksum S3 stored with a version: ``sha256`` (hex) for a
    full-object checksum, ``composite`` (the string S3 reports, at most
    :data:`MAX_COMPOSITE_CHECKSUM` characters) for a composite one, else the
    ``problem`` that makes the version non-conforming."""

    sha256: str | None = None
    composite: str | None = None
    problem: str | None = None


MAX_PARTS = 10000
MAX_COMPOSITE_CHECKSUM = 64
_PARTS_RE = re.compile(r"^[1-9][0-9]{0,4}$")
CHECKSUM_TYPES = ("FULL_OBJECT", "COMPOSITE")
MALFORMED_CHECKSUM = "the object's SHA-256 checksum is malformed"


def stored_checksum(head: dict) -> StoredChecksum:
    """The version's stored SHA-256 checksum from its ``HeadObject`` (module docstring).

    A value with a ``-<parts>`` suffix (1 to :data:`MAX_PARTS`) or a
    ``ChecksumType`` of ``COMPOSITE`` is a composite checksum; any other is
    the full object's. Either is the base64 of 32 bytes. A suffix on a
    ``FULL_OBJECT`` checksum, another ``ChecksumType`` or a value that is not
    so formed is malformed."""
    value = head.get("ChecksumSHA256")
    if not value:
        return StoredChecksum(problem="the object has no SHA-256 checksum")
    value = str(value)
    checksum_type = head.get("ChecksumType")
    digest, suffix, parts = value.partition("-")
    if checksum_type and checksum_type not in CHECKSUM_TYPES:
        return StoredChecksum(problem=MALFORMED_CHECKSUM)
    if suffix and (checksum_type == "FULL_OBJECT" or not _PARTS_RE.match(parts) or int(parts) > MAX_PARTS):
        return StoredChecksum(problem=MALFORMED_CHECKSUM)
    try:
        raw = base64.b64decode(digest, validate=True)
    except (binascii.Error, ValueError):
        raw = b""
    if len(raw) != 32:
        return StoredChecksum(problem=MALFORMED_CHECKSUM)
    if suffix or checksum_type == "COMPOSITE":
        return StoredChecksum(composite=value)
    return StoredChecksum(sha256=raw.hex())


def _chunks(response: dict, limit: int):
    body = response["Body"]
    read = 0
    try:
        for chunk in body.iter_chunks(READ_CHUNK):
            read += len(chunk)
            if read > limit:
                raise BodyTooLarge(read, limit)
            yield chunk
    finally:
        body.close()


def read_version(client, bucket: str, key: str, version_id: str, limit: int) -> bytes:
    """The bytes of one version, at most ``limit`` (else :class:`BodyTooLarge`)."""
    response = client.get_object(Bucket=bucket, Key=key, VersionId=version_id, ChecksumMode="ENABLED")
    return b"".join(_chunks(response, limit))


def copy_version(client, bucket: str, key: str, version_id: str, limit: int, sink=None) -> tuple[str, int]:
    """``(sha256 hex, size)`` of one version, streamed into ``sink`` (a writable
    file, or nothing); :class:`BodyTooLarge` beyond ``limit``."""
    response = client.get_object(Bucket=bucket, Key=key, VersionId=version_id, ChecksumMode="ENABLED")
    digest, size = hashlib.sha256(), 0
    for chunk in _chunks(response, limit):
        digest.update(chunk)
        size += len(chunk)
        if sink is not None:
            sink.write(chunk)
    return digest.hexdigest(), size


def hash_version(client, bucket: str, key: str, version_id: str, limit: int) -> tuple[str, int]:
    """``(sha256 hex, size)`` of one version, streamed; :class:`BodyTooLarge` beyond ``limit``."""
    return copy_version(client, bucket, key, version_id, limit)


def first_version(client, bucket: str, key: str) -> ListedVersion | None:
    """The first write of exactly ``key`` (its oldest version), or None when it has none."""
    for group in iter_groups(client, bucket, key):
        if group.key == key:
            return group.first
        if group.key > key:
            break
    return None


def bucket_settings(client, bucket: str) -> dict:
    """``{"versioning", "object_lock", "default_retention"}`` of the bucket:
    the versioning status (``Enabled``, ``Suspended`` or None), whether Object
    Lock is enabled, and the default retention (``{"mode", "days", "years",
    "period_days"}``, a year counting :data:`DAYS_PER_YEAR` days) or None."""
    versioning = client.get_bucket_versioning(Bucket=bucket).get("Status")
    try:
        configuration = client.get_object_lock_configuration(Bucket=bucket).get("ObjectLockConfiguration") or {}
    except Exception as exc:  # noqa: BLE001 - classified below
        if error_code(exc) != "ObjectLockConfigurationNotFoundError":
            raise
        configuration = {}
    retention = (configuration.get("Rule") or {}).get("DefaultRetention")
    default = None
    if retention:
        days, years = retention.get("Days") or None, retention.get("Years") or None
        default = {"mode": retention.get("Mode"), "days": days, "years": years,
                   "period_days": days if days else (years * DAYS_PER_YEAR if years else None)}
    return {"versioning": versioning, "object_lock": configuration.get("ObjectLockEnabled") == "Enabled",
            "default_retention": default}


def bucket_policy(client, bucket: str) -> str | None:
    """The bucket policy (JSON text), or None when the bucket has none."""
    try:
        return client.get_bucket_policy(Bucket=bucket).get("Policy")
    except Exception as exc:  # noqa: BLE001 - classified below
        if error_code(exc) == "NoSuchBucketPolicy":
            return None
        raise


def bucket_lifecycle(client, bucket: str) -> list:
    """The bucket's lifecycle rules (none without a lifecycle configuration)."""
    try:
        return client.get_bucket_lifecycle_configuration(Bucket=bucket).get("Rules") or []
    except Exception as exc:  # noqa: BLE001 - classified below
        if error_code(exc) == "NoSuchLifecycleConfiguration":
            return []
        raise
