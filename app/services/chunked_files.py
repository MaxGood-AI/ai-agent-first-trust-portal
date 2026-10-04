"""Chunked-file convention for evidence repositories.

Git hosting APIs cap the size of a single file they return (CodeCommit's
``GetFile`` returns at most 6 MB), so an evidence repository stores any file
larger than :data:`PART_SIZE` as byte slices next to a manifest:

``X.part-0001``, ``X.part-0002``, ...
    Consecutive byte slices of ``X``, each at most :data:`PART_SIZE` bytes.
``X.manifest.json``
    ``{"format": "chunked-file/v1", "name": "<basename of X>",
    "size": <total bytes>, "sha256": "<hex of X>",
    "parts": [{"name": "<basename>.part-0001", "size": n, "sha256": "<hex>"}, ...]}``

The manifest and its parts live in the same directory. Part names are plain
basenames of the form ``<name>.part-<NNNN>`` (numbered from 0001, in order),
so a manifest can only ever reference its own slices.

Limits: a manifest file is at most :data:`MAX_MANIFEST_BYTES` (1 MiB), lists
at most :data:`MAX_PARTS` (32) parts and describes a file of at most
:data:`MAX_TOTAL_BYTES` (128 MiB). A manifest over any limit is rejected
before any part is read, and :func:`split` refuses data it could not
describe within them.

Writers call :func:`split`; readers call :func:`parse_manifest` and then
:func:`reassemble` with a callable ``read_part(name, max_bytes)`` that
returns at most ``max_bytes`` bytes of a part (its first ``max_bytes`` when
it is longer), resolved relative to the manifest's directory.
:func:`reassemble` asks for each part's declared size plus one byte, so a
part longer than its manifest declares is rejected
(:class:`ChunkedPartTooLargeError`) after at most that many bytes are read.
:func:`read_local` does both for a manifest on the local filesystem.
"""

import hashlib
import json
import os
import re
from dataclasses import dataclass
from typing import Callable

PART_SIZE = 5 * 1024 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_PARTS = 32
MAX_TOTAL_BYTES = 128 * 1024 * 1024
MANIFEST_SUFFIX = ".manifest.json"
FORMAT = "chunked-file/v1"

_SHA256_RE = re.compile(r"^[0-9a-f]{64}$")


class ChunkedFileError(ValueError):
    """A manifest is malformed or a part does not match it."""


class ChunkedPartTooLargeError(ChunkedFileError):
    """A part is longer than the size its manifest declares.

    ``part`` names it, ``declared`` is the manifest's size for it and
    ``read`` the number of bytes read (``declared + 1``).
    """

    def __init__(self, part: str, declared: int, read: int):
        self.part = part
        self.declared = declared
        self.read = read
        super().__init__(f"part {part} is larger than the {declared} bytes its manifest declares")


@dataclass(frozen=True)
class ChunkPart:
    """One byte slice of a chunked file."""

    name: str
    size: int
    sha256: str


@dataclass(frozen=True)
class ChunkManifest:
    """A parsed and validated ``chunked-file/v1`` manifest."""

    name: str
    size: int
    sha256: str
    parts: tuple


def is_manifest(path: str) -> bool:
    """True when ``path`` names a chunked-file manifest."""
    base = os.path.basename(path or "")
    return base.endswith(MANIFEST_SUFFIX) and len(base) > len(MANIFEST_SUFFIX)


def logical_path(manifest_path: str) -> str:
    """Path of the file a manifest describes (the manifest path minus its suffix)."""
    if not is_manifest(manifest_path):
        raise ChunkedFileError(f"not a chunked-file manifest path: {manifest_path!r}")
    return manifest_path[: -len(MANIFEST_SUFFIX)]


def part_name(name: str, index: int) -> str:
    """Name of the ``index``-th part (1-based) of the file ``name``."""
    return f"{name}.part-{index:04d}"


def _check_basename(value, what):
    if not isinstance(value, str) or not value:
        raise ChunkedFileError(f"{what} must be a non-empty string")
    if "/" in value or "\\" in value or "\x00" in value or ".." in value:
        raise ChunkedFileError(f"{what} must be a plain file name: {value!r}")
    return value


def _check_size(value, what):
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ChunkedFileError(f"{what} must be a non-negative integer")
    return value


def _check_sha(value, what):
    if not isinstance(value, str) or not _SHA256_RE.match(value):
        raise ChunkedFileError(f"{what} must be a lowercase hex SHA-256 digest")
    return value


def parse_manifest(data) -> ChunkManifest:
    """Parse and validate manifest bytes (or text).

    Raises :class:`ChunkedFileError` when the manifest is larger than
    :data:`MAX_MANIFEST_BYTES`, is not valid JSON, has the wrong format,
    names a part outside its own directory or out of sequence, lists more
    than :data:`MAX_PARTS` parts, describes more than :data:`MAX_TOTAL_BYTES`,
    or when the part sizes do not add up to the total size.
    """
    length = len(data.encode("utf-8")) if isinstance(data, str) else len(data or b"")
    if length > MAX_MANIFEST_BYTES:
        raise ChunkedFileError(f"manifest is larger than {MAX_MANIFEST_BYTES} bytes")
    try:
        if isinstance(data, (bytes, bytearray)):
            data = bytes(data).decode("utf-8")
        doc = json.loads(data)
    except (UnicodeDecodeError, ValueError, TypeError) as exc:
        raise ChunkedFileError(f"manifest is not valid JSON: {exc}") from None
    if not isinstance(doc, dict):
        raise ChunkedFileError("manifest must be a JSON object")
    if doc.get("format") != FORMAT:
        raise ChunkedFileError(f"unsupported manifest format: {doc.get('format')!r}")

    name = _check_basename(doc.get("name"), "manifest name")
    size = _check_size(doc.get("size"), "manifest size")
    if size > MAX_TOTAL_BYTES:
        raise ChunkedFileError(f"manifest size {size} exceeds the {MAX_TOTAL_BYTES} byte limit")
    sha = _check_sha(doc.get("sha256"), "manifest sha256")
    raw_parts = doc.get("parts")
    if not isinstance(raw_parts, list):
        raise ChunkedFileError("manifest parts must be a list")
    if len(raw_parts) > MAX_PARTS:
        raise ChunkedFileError(f"manifest lists {len(raw_parts)} parts; at most {MAX_PARTS} are allowed")
    if not raw_parts and size:
        raise ChunkedFileError("manifest lists no parts for a non-empty file")

    parts = []
    for index, raw in enumerate(raw_parts, start=1):
        if not isinstance(raw, dict):
            raise ChunkedFileError(f"part {index} must be an object")
        pname = _check_basename(raw.get("name"), f"part {index} name")
        if pname != part_name(name, index):
            raise ChunkedFileError(
                f"part {index} must be named {part_name(name, index)!r}, not {pname!r}")
        psize = _check_size(raw.get("size"), f"part {index} size")
        if psize == 0:
            raise ChunkedFileError(f"part {index} is empty")
        parts.append(ChunkPart(pname, psize, _check_sha(raw.get("sha256"), f"part {index} sha256")))

    if sum(p.size for p in parts) != size:
        raise ChunkedFileError("part sizes do not add up to the manifest size")
    return ChunkManifest(name=name, size=size, sha256=sha, parts=tuple(parts))


def reassemble(manifest: ChunkManifest, read_part: Callable[[str, int], bytes]) -> bytes:
    """Read every part through ``read_part(part_name, max_bytes)`` and return the whole file.

    ``max_bytes`` is the part's declared size plus one. Each part's size and
    SHA-256 is verified, then the whole file's. Raises
    :class:`ChunkedPartTooLargeError` for a part longer than declared and
    :class:`ChunkedFileError` on a missing, truncated or corrupted part.
    """
    chunks = []
    for part in manifest.parts:
        try:
            data = read_part(part.name, part.size + 1)
        except (OSError, LookupError) as exc:
            raise ChunkedFileError(f"part {part.name} could not be read: {type(exc).__name__}") from None
        if not isinstance(data, (bytes, bytearray)):
            raise ChunkedFileError(f"part {part.name} was not returned as bytes")
        if len(data) > part.size:
            raise ChunkedPartTooLargeError(part.name, part.size, len(data))
        if len(data) != part.size:
            raise ChunkedFileError(
                f"part {part.name} is {len(data)} bytes, the manifest says {part.size}")
        if hashlib.sha256(data).hexdigest() != part.sha256:
            raise ChunkedFileError(f"part {part.name} does not match its SHA-256")
        chunks.append(bytes(data))
    whole = b"".join(chunks)
    if len(whole) != manifest.size or hashlib.sha256(whole).hexdigest() != manifest.sha256:
        raise ChunkedFileError(f"reassembled {manifest.name} does not match the manifest SHA-256")
    return whole


def split(name: str, data: bytes, part_size: int = PART_SIZE):
    """Split ``data`` into parts for the file ``name``.

    Returns ``(manifest_bytes, [(part_name, part_bytes), ...])``. The writer
    stores each part and the manifest (as ``name + MANIFEST_SUFFIX``) in the
    directory that would have held ``name``.
    """
    _check_basename(name, "file name")
    if isinstance(part_size, bool) or not isinstance(part_size, int) or part_size <= 0:
        raise ValueError("part_size must be a positive integer")
    data = bytes(data)
    if len(data) > MAX_TOTAL_BYTES:
        raise ValueError(f"{name} is larger than the {MAX_TOTAL_BYTES} byte chunked-file limit")
    if -(-len(data) // part_size) > MAX_PARTS:
        raise ValueError(f"{name} would need more than {MAX_PARTS} parts of {part_size} bytes")
    parts = []
    for index, offset in enumerate(range(0, len(data), part_size), start=1):
        parts.append((part_name(name, index), data[offset:offset + part_size]))
    manifest = {
        "format": FORMAT,
        "name": name,
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
        "parts": [
            {"name": pname, "size": len(chunk), "sha256": hashlib.sha256(chunk).hexdigest()}
            for pname, chunk in parts
        ],
    }
    manifest_bytes = (json.dumps(manifest, indent=2) + "\n").encode("utf-8")
    return manifest_bytes, parts


def read_manifest_file(manifest_path: str) -> bytes:
    """Bytes of a manifest on the local filesystem, reading no more than the
    manifest size limit allows (:func:`parse_manifest` rejects a longer one)."""
    with open(manifest_path, "rb") as fh:
        return fh.read(MAX_MANIFEST_BYTES + 1)


def read_local(manifest_path: str) -> bytes:
    """Reassemble the chunked file described by a manifest on the local filesystem.

    The manifest's ``name`` must match its own file name minus the suffix.
    """
    expected = os.path.basename(logical_path(manifest_path))
    manifest = parse_manifest(read_manifest_file(manifest_path))
    if manifest.name != expected:
        raise ChunkedFileError(f"manifest names {manifest.name!r} but is stored as {expected!r}")
    directory = os.path.dirname(os.path.abspath(manifest_path))

    def read_part(pname, max_bytes):
        with open(os.path.join(directory, pname), "rb") as part_fh:
            return part_fh.read(max_bytes)

    return reassemble(manifest, read_part)
