"""Tests for the chunked-file convention (app.services.chunked_files)."""

import hashlib
import json

import pytest

from app.services import chunked_files
from app.services.chunked_files import ChunkedFileError


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def _manifest(**overrides):
    data = b"abcdefghij"
    doc = {
        "format": "chunked-file/v1",
        "name": "big.jsonl",
        "size": 10,
        "sha256": _sha(data),
        "parts": [
            {"name": "big.jsonl.part-0001", "size": 6, "sha256": _sha(data[:6])},
            {"name": "big.jsonl.part-0002", "size": 4, "sha256": _sha(data[6:])},
        ],
    }
    doc.update(overrides)
    return doc


def test_part_size_is_five_mebibytes():
    assert chunked_files.PART_SIZE == 5_242_880
    assert chunked_files.MANIFEST_SUFFIX == ".manifest.json"


def test_split_parse_reassemble_round_trip():
    data = bytes(range(256)) * 41  # 10,496 bytes
    manifest_bytes, parts = chunked_files.split("t.jsonl", data, part_size=4096)

    assert [name for name, _ in parts] == ["t.jsonl.part-0001", "t.jsonl.part-0002", "t.jsonl.part-0003"]
    assert all(len(chunk) <= 4096 for _, chunk in parts)
    manifest = chunked_files.parse_manifest(manifest_bytes)
    assert manifest.name == "t.jsonl"
    assert manifest.size == len(data)
    assert manifest.sha256 == _sha(data)
    assert len(manifest.parts) == 3

    stored = dict(parts)
    assert chunked_files.reassemble(manifest, lambda name, limit: stored[name]) == data


def test_split_exact_multiple_and_empty():
    _, parts = chunked_files.split("x", b"a" * 8, part_size=4)
    assert [len(chunk) for _, chunk in parts] == [4, 4]

    manifest_bytes, parts = chunked_files.split("empty", b"")
    assert parts == []
    manifest = chunked_files.parse_manifest(manifest_bytes)
    assert manifest.size == 0
    assert chunked_files.reassemble(manifest, lambda name, limit: b"") == b""


def test_split_default_part_size_uses_one_part_for_small_files():
    manifest_bytes, parts = chunked_files.split("small.jsonl", b"hello")
    assert len(parts) == 1
    assert json.loads(manifest_bytes)["parts"][0]["size"] == 5


@pytest.mark.parametrize("part_size", [0, -1, True, 1.5])
def test_split_rejects_bad_part_size(part_size):
    with pytest.raises(ValueError):
        chunked_files.split("x", b"data", part_size=part_size)


@pytest.mark.parametrize("name", ["", "a/b", "..", "../x", "a\\b"])
def test_split_rejects_non_basename(name):
    with pytest.raises(ChunkedFileError):
        chunked_files.split(name, b"data")


def test_is_manifest_and_logical_path():
    assert chunked_files.is_manifest("decision-logs/x.jsonl.manifest.json")
    assert not chunked_files.is_manifest("decision-logs/x.jsonl")
    assert not chunked_files.is_manifest(".manifest.json")
    assert not chunked_files.is_manifest(None)
    assert chunked_files.logical_path("decision-logs/x.jsonl.manifest.json") == "decision-logs/x.jsonl"
    with pytest.raises(ChunkedFileError):
        chunked_files.logical_path("decision-logs/x.jsonl")


def test_parse_manifest_accepts_text():
    manifest = chunked_files.parse_manifest(json.dumps(_manifest()))
    assert [p.name for p in manifest.parts] == ["big.jsonl.part-0001", "big.jsonl.part-0002"]


@pytest.mark.parametrize("data", [b"not json", b"\xff\xfe", b"[]", b'"text"'])
def test_parse_manifest_rejects_non_objects(data):
    with pytest.raises(ChunkedFileError):
        chunked_files.parse_manifest(data)


@pytest.mark.parametrize("overrides", [
    {"format": "chunked-file/v2"},
    {"name": "../escape.jsonl"},
    {"name": "dir/file.jsonl"},
    {"name": ""},
    {"size": -1},
    {"size": True},
    {"size": "10"},
    {"sha256": "ABC"},
    {"sha256": "0" * 63},
    {"parts": "nope"},
    {"parts": []},
    {"parts": ["not-an-object"]},
    {"size": 11},
])
def test_parse_manifest_rejects_invalid_fields(overrides):
    with pytest.raises(ChunkedFileError):
        chunked_files.parse_manifest(json.dumps(_manifest(**overrides)))


@pytest.mark.parametrize("part_override", [
    {"name": "../big.jsonl.part-0001"},
    {"name": "other.jsonl.part-0001"},
    {"name": "big.jsonl.part-0002"},
    {"size": 0},
    {"sha256": "xyz"},
])
def test_parse_manifest_rejects_invalid_parts(part_override):
    doc = _manifest()
    doc["parts"][0] = dict(doc["parts"][0], **part_override)
    with pytest.raises(ChunkedFileError):
        chunked_files.parse_manifest(json.dumps(doc))


def _parts():
    return {"big.jsonl.part-0001": b"abcdef", "big.jsonl.part-0002": b"ghij"}


def test_reassemble_detects_corrupted_part():
    manifest = chunked_files.parse_manifest(json.dumps(_manifest()))
    parts = _parts()
    parts["big.jsonl.part-0002"] = b"ghiX"
    with pytest.raises(ChunkedFileError, match="SHA-256"):
        chunked_files.reassemble(manifest, lambda name, limit: parts[name])


def test_reassemble_detects_truncated_part():
    manifest = chunked_files.parse_manifest(json.dumps(_manifest()))
    parts = _parts()
    parts["big.jsonl.part-0001"] = b"abc"
    with pytest.raises(ChunkedFileError, match="bytes"):
        chunked_files.reassemble(manifest, lambda name, limit: parts[name])


def test_reassemble_detects_missing_part():
    manifest = chunked_files.parse_manifest(json.dumps(_manifest()))
    parts = _parts()
    del parts["big.jsonl.part-0002"]
    with pytest.raises(ChunkedFileError, match="could not be read"):
        chunked_files.reassemble(manifest, lambda name, limit: parts[name])

    def missing_file(name, limit):
        raise FileNotFoundError(name)

    with pytest.raises(ChunkedFileError, match="could not be read"):
        chunked_files.reassemble(manifest, missing_file)


def test_reassemble_rejects_non_bytes_part():
    manifest = chunked_files.parse_manifest(json.dumps(_manifest()))
    with pytest.raises(ChunkedFileError, match="bytes"):
        chunked_files.reassemble(manifest, lambda name, limit: "abcdef")


def test_reassemble_detects_whole_file_mismatch():
    manifest = chunked_files.parse_manifest(json.dumps(_manifest(sha256=_sha(b"something else"))))
    with pytest.raises(ChunkedFileError, match="does not match the manifest"):
        chunked_files.reassemble(manifest, lambda name, limit: _parts()[name])


def test_read_local(tmp_path):
    data = b"line\n" * 1000
    manifest_bytes, parts = chunked_files.split("s.jsonl", data, part_size=1024)
    for name, chunk in parts:
        (tmp_path / name).write_bytes(chunk)
    manifest_path = tmp_path / "s.jsonl.manifest.json"
    manifest_path.write_bytes(manifest_bytes)

    assert chunked_files.read_local(str(manifest_path)) == data


def test_read_local_rejects_mismatched_name(tmp_path):
    manifest_bytes, parts = chunked_files.split("other.jsonl", b"data")
    for name, chunk in parts:
        (tmp_path / name).write_bytes(chunk)
    manifest_path = tmp_path / "s.jsonl.manifest.json"
    manifest_path.write_bytes(manifest_bytes)

    with pytest.raises(ChunkedFileError, match="stored as"):
        chunked_files.read_local(str(manifest_path))


# --- size caps ---------------------------------------------------------------


def test_limits():
    assert chunked_files.MAX_MANIFEST_BYTES == 1024 * 1024
    assert chunked_files.MAX_PARTS == 32
    assert chunked_files.MAX_TOTAL_BYTES == 128 * 1024 * 1024


def test_parse_manifest_rejects_an_oversized_manifest():
    padded = json.dumps(_manifest(padding="x" * chunked_files.MAX_MANIFEST_BYTES))
    for data in (padded, padded.encode()):
        with pytest.raises(ChunkedFileError, match="larger than 1048576 bytes"):
            chunked_files.parse_manifest(data)


def test_parse_manifest_rejects_a_total_size_over_the_limit():
    limit = chunked_files.MAX_TOTAL_BYTES
    parts = [{"name": chunked_files.part_name("big.jsonl", 1), "size": limit + 1, "sha256": "0" * 64}]
    with pytest.raises(ChunkedFileError, match="exceeds the 134217728 byte limit"):
        chunked_files.parse_manifest(json.dumps(_manifest(size=limit + 1, parts=parts)))


def test_parse_manifest_rejects_too_many_parts():
    parts = [{"name": chunked_files.part_name("big.jsonl", i), "size": 1, "sha256": "0" * 64}
             for i in range(1, 34)]
    with pytest.raises(ChunkedFileError, match="lists 33 parts; at most 32"):
        chunked_files.parse_manifest(json.dumps(_manifest(size=33, parts=parts)))
    parsed = chunked_files.parse_manifest(json.dumps(_manifest(size=32, parts=parts[:32])))
    assert len(parsed.parts) == 32


def test_split_refuses_data_readers_would_reject():
    with pytest.raises(ValueError, match="more than 32 parts"):
        chunked_files.split("big.jsonl", b"x" * 33, part_size=1)
    assert len(chunked_files.split("big.jsonl", b"x" * 32, part_size=1)[1]) == 32


def test_split_refuses_data_over_the_total_limit(monkeypatch):
    monkeypatch.setattr(chunked_files, "MAX_TOTAL_BYTES", 10)
    with pytest.raises(ValueError, match="larger than the 10 byte"):
        chunked_files.split("big.jsonl", b"x" * 11)


def test_read_local_reads_no_more_than_the_manifest_limit(tmp_path):
    manifest_path = tmp_path / "s.jsonl.manifest.json"
    manifest_path.write_bytes(b" " * (chunked_files.MAX_MANIFEST_BYTES + 100))
    assert len(chunked_files.read_manifest_file(str(manifest_path))) == chunked_files.MAX_MANIFEST_BYTES + 1
    with pytest.raises(ChunkedFileError, match="larger than"):
        chunked_files.read_local(str(manifest_path))
