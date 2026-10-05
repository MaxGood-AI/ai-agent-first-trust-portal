"""Evidence store without a database server: key rules, metadata
sanitization, checksums and listings, and the routes' access rules,
OpenAPI documentation and admin pages (SQLite)."""

import base64
import hashlib
import io
import json
import uuid
from datetime import datetime, timezone

import pytest

from app import create_app
from app.config import TestConfig
from app.models import Control, db
from app.models.evidence_store import EvidenceDocument, EvidenceDocumentLink, EvidenceStoreObject
from app.services import team_service
from app.services.evidence_store import keys, service, store
from app.services.evidence_store import verify as store_verify
from tests.conftest import login


# --------------------------------------------------------------------------
# Keys and metadata
# --------------------------------------------------------------------------

@pytest.mark.parametrize("key,kind,extra", [
    ("decision-logs/2026-10-01T000000Z_sess-1.jsonl", "decision_log", {"session_id": "sess-1"}),
    ("decision-logs/2026-10-01T000000Z_sess-1.meta.json", "decision_log_sidecar", {}),
    ("pentest-evidence/layer3/scan.json", "pentest_evidence", {}),
    ("codex-reviews/2026/10/review.md", "evidence_document", {"document_kind": "code-review"}),
    ("pentest-reports/q3.pdf", "evidence_document", {"document_kind": "pentest-report"}),
    ("evidence/artifacts/a/b.txt", "evidence_document", {"document_kind": "evidence-artifact"}),
    ("decision-logs/sub/2026_s.jsonl", "unmapped", {}),
    ("decision-logs/2026.jsonl", "unmapped", {}),
    ("decision-logs/2026_bad id.jsonl", "unmapped", {}),
    ("decision-logs/x.jsonl.manifest.json", "unmapped", {}),
    ("pentest-evidence/scan.json", "unmapped", {}),
    ("pentest-evidence/layerX/scan.json", "unmapped", {}),
    ("codex-reviews/", "unmapped", {}),
])
def test_classify(key, kind, extra):
    classified = keys.classify(key)
    assert classified.kind == kind
    for name, value in extra.items():
        assert getattr(classified, name) == value


@pytest.mark.parametrize("key,problem", [
    ("", "empty"), ("/decision-logs/a_b.jsonl", "starts with /"), ("codex-reviews/a\\b", "backslash"),
    ("codex-reviews/a\x07b", "control character"), ("codex-reviews/./a", ". or .."),
    ("codex-reviews/../a", ". or .."), ("codex-reviews//a", ". or .."), ("codex-reviews/" + "é" * 600, "1,024"),
])
def test_unclean_keys_are_unmapped(key, problem):
    classified = keys.classify(key)
    assert classified.kind == "unmapped" and problem in classified.detail


def test_keys_helpers():
    assert keys.stored_key("a") == ("a", False) and keys.stored_key("a\x00b") == ("a%00b", True)
    assert keys.display("a\x01b") == "a\\x01b" and len(keys.display("x" * 500)) == 300
    assert keys.sidecar_key("decision-logs/t_s.jsonl") == "decision-logs/t_s.meta.json"
    assert keys.document_title("pentest-reports/2026/q3.pdf") == "2026/q3.pdf"
    assert keys.serve_content_type("codex-reviews/r.MD") == "text/markdown; charset=utf-8"
    assert keys.serve_content_type("evidence/artifacts/x.html") == "application/octet-stream"
    assert keys.is_text("a/b.log") and not keys.is_text("a/b.pdf")
    assert keys.sanitize_content_type("text/plain") == "text/plain"
    assert keys.sanitize_content_type("text/\x00plain") is None and keys.sanitize_content_type("x" * 300) is None


def test_metadata_is_sanitized_and_never_echoed():
    raw = {"producer": "session-end", "Agent": "claude-code", "exit-reason": "prompt_input_exit",
           "session-id": "other", "redaction": "rules.v1", "source-commit": "a" * 40, "source-blob": "B" * 40,
           "x-evil": "<script>", "agent ": "x"}
    kept, notes = keys.sanitize_metadata(raw, session_id="sess")
    assert kept == {"producer": "session-end", "agent": "claude-code", "exit-reason": "prompt_input_exit",
                    "redaction": "rules.v1", "source-commit": "a" * 40}
    assert "metadata source-blob: invalid value dropped" in notes
    assert any("session-id differs" in note for note in notes)
    assert "2 unknown metadata name(s) dropped" in notes
    assert not any("<script>" in note or "BBBB" in note for note in notes)
    kept, notes = keys.sanitize_metadata({"producer": "p" * 41, "agent": "é", "exit-reason": 5})
    assert kept == {} and len(notes) == 3


_B64 = base64.b64encode(b"x" * 32).decode()


@pytest.mark.parametrize("head,expected", [
    ({}, (None, None, "no SHA-256")),
    ({"ChecksumCRC32": "AAAAAA=="}, (None, None, "no SHA-256")),  # another algorithm only
    ({"ChecksumSHA256": _B64 + "-3"}, (None, _B64 + "-3", None)),
    ({"ChecksumSHA256": _B64 + "-3", "ChecksumType": "COMPOSITE"}, (None, _B64 + "-3", None)),
    ({"ChecksumSHA256": _B64 + "-10000", "ChecksumType": "COMPOSITE"}, (None, _B64 + "-10000", None)),
    ({"ChecksumSHA256": _B64, "ChecksumType": "COMPOSITE"}, (None, _B64, None)),
    ({"ChecksumSHA256": _B64 + "-3", "ChecksumType": "FULL_OBJECT"}, (None, None, "malformed")),
    ({"ChecksumSHA256": _B64 + "-0"}, (None, None, "malformed")),
    ({"ChecksumSHA256": _B64 + "-10001"}, (None, None, "malformed")),
    ({"ChecksumSHA256": _B64 + "-02"}, (None, None, "malformed")),
    ({"ChecksumSHA256": _B64 + "-"}, (None, None, "malformed")),
    ({"ChecksumSHA256": _B64 + "-2-2"}, (None, None, "malformed")),
    ({"ChecksumSHA256": "not base64!-2"}, (None, None, "malformed")),
    ({"ChecksumSHA256": _B64, "ChecksumType": "MD5"}, (None, None, "malformed")),
    ({"ChecksumSHA256": "not base64!"}, (None, None, "malformed")),
    ({"ChecksumSHA256": base64.b64encode(b"x" * 31).decode()}, (None, None, "malformed")),
    ({"ChecksumSHA256": base64.b64encode(b"x" * 31).decode() + "-2"}, (None, None, "malformed")),
    ({"ChecksumSHA256": _B64, "ChecksumType": "FULL_OBJECT"}, ((b"x" * 32).hex(), None, None)),
    ({"ChecksumSHA256": _B64}, ((b"x" * 32).hex(), None, None)),
])
def test_stored_checksum(head, expected):
    checksum = store.stored_checksum(head)
    assert (checksum.sha256, checksum.composite) == expected[:2]
    assert (checksum.problem is None) if expected[2] is None else expected[2] in checksum.problem
    assert checksum.composite is None or len(checksum.composite) <= store.MAX_COMPOSITE_CHECKSUM


def test_composite_checksum_of_the_fake_store_is_the_checksum_of_part_checksums():
    from tests.store_fakes import composite_sha256

    body = b"abcdefgh"
    digests = hashlib.sha256(b"abcd").digest() + hashlib.sha256(b"efgh").digest()
    assert composite_sha256(body) == base64.b64encode(hashlib.sha256(digests).digest()).decode() + "-2"
    assert store.stored_checksum({"ChecksumSHA256": composite_sha256(body), "ChecksumType": "COMPOSITE"}).composite


def test_bulk_copy_metadata_is_kept_on_every_kind_of_object():
    bulk = {"producer": "backfill", "source-repo": "Evidence_Repo-1.x", "source-commit": "a" * 40,
            "redaction": "rules-2026.1"}
    for session_id in ("sess-1", None):  # a transcript or sidecar of a session, or any other object
        kept, notes = keys.sanitize_metadata(bulk, session_id)
        assert kept == bulk and notes == []
    kept, notes = keys.sanitize_metadata(dict(bulk, **{"source-blob": "b" * 64}))
    assert kept["source-blob"] == "b" * 64 and notes == []
    for bad in ("", "r" * 101, "repo/name", "repo name", "répo"):
        kept, notes = keys.sanitize_metadata({"source-repo": bad})
        assert kept == {} and notes == ["metadata source-repo: invalid value dropped"]
    kept, _ = keys.sanitize_metadata({"source-repo": "r" * 100})
    assert kept == {"source-repo": "r" * 100}


class _Pages:
    """A listing served page by page, as list_object_versions does."""

    def __init__(self, pages):
        self.pages = pages
        self.requests = []

    def list_object_versions(self, **kwargs):
        self.requests.append(kwargs)
        return self.pages[len(self.requests) - 1]


def _v(key, version, marker=False):
    return {"Key": key, "VersionId": version, "Size": 1, "LastModified": datetime.now(timezone.utc)}


def test_groups_span_pages_and_keep_the_first_write():
    pages = _Pages([
        {"Versions": [_v("a", "a1"), _v("b", "b3"), _v("b", "b2")], "IsTruncated": True,
         "NextKeyMarker": "b", "NextVersionIdMarker": "b2"},
        {"Versions": [_v("b", "b1"), _v("c", "c1")], "DeleteMarkers": [_v("b", "m1")], "IsTruncated": False},
    ])
    groups = list(store.iter_groups(pages, "bucket", "p/", start_after="0", page_size=3))
    assert [g.key for g in groups] == ["a", "b", "c"]
    b = groups[1]
    assert b.first.version_id == "b1" and [v.version_id for v in b.later] == ["b3", "b2"] and b.later_count == 2
    assert b.marker_count == 1 and b.markers[0].delete_marker
    assert pages.requests[0]["KeyMarker"] == "0" and pages.requests[1]["VersionIdMarker"] == "b2"


def test_anomalies_are_counted_beyond_the_listed_detail():
    from app.services.evidence_store import sync

    group = store.KeyGroup("k")
    for index in range(25):
        group.add(store.ListedVersion("k", f"v{index}", 1, None))
    for index in range(22):
        group.add(store.ListedVersion("k", f"m{index}", 0, None, delete_marker=True))
    tally = sync.Tally()
    sync.note_anomalies(group, tally)
    assert group.first.version_id == "v24" and group.later_count == 24 and group.marker_count == 22
    assert tally.counts["anomalies"] == 46 and len(tally.anomalies) == 42
    assert tally.status() == "partial"


def test_bodies_are_bounded():
    class Body:
        def __init__(self, data):
            self.data, self.closed = data, False

        def iter_chunks(self, size):
            for start in range(0, len(self.data), 4):
                yield self.data[start:start + 4]

        def close(self):
            self.closed = True

    body = Body(b"0123456789")

    class Client:
        def get_object(self, **kwargs):
            return {"Body": body}

    with pytest.raises(store.BodyTooLarge):
        store.read_version(Client(), "b", "k", "v", 5)
    assert body.closed
    assert store.read_version(Client(), "b", "k", "v", 10) == b"0123456789"
    assert store.hash_version(Client(), "b", "k", "v", 10) == (hashlib.sha256(b"0123456789").hexdigest(), 10)


def test_cursor_round_trip():
    position = {"phase": "listing", "prefix": 2, "after_key": "codex-reviews/x"}
    assert store_verify.decode_cursor(store_verify.encode_cursor(position)) == position
    assert store_verify.decode_cursor(None) == {"phase": "records", "after_id": None}
    for bad in ("!!", store_verify.encode_cursor({"phase": "listing", "prefix": 9}),
                store_verify.encode_cursor({"phase": "other"}),
                store_verify.encode_cursor({"phase": "records", "after_id": 5})):
        with pytest.raises(ValueError):
            store_verify.decode_cursor(bad)


# --------------------------------------------------------------------------
# Routes (SQLite)
# --------------------------------------------------------------------------

@pytest.fixture
def app(monkeypatch):
    monkeypatch.delenv("EVIDENCE_STORE_BUCKET", raising=False)
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


@pytest.fixture
def members(app):
    return {
        "admin": team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True),
        "agent": team_service.create_member("Agent", "agent@example.com", "agent"),
        "client": team_service.create_member("Client", "client@example.com", "client", company="Auditor"),
    }


@pytest.fixture
def document(app):
    row = EvidenceStoreObject(id=str(uuid.uuid4()), bucket="b", key="codex-reviews/secret-review.md",
                              version_id="v1", kind="evidence_document", status="ingested", sha256="a" * 64,
                              size=10, lock_mode="GOVERNANCE", object_metadata={"producer": "code-review"})
    doc = EvidenceDocument(id=str(uuid.uuid4()), store_object_id=row.id, kind="code-review",
                           title="secret-review.md", key=row.key, sha256="a" * 64, size=10)
    db.session.add_all([row, doc])
    db.session.commit()
    return doc


ROUTES = [
    ("get", "/api/evidence-store"), ("post", "/api/evidence-store/sync"), ("get", "/api/evidence-store/runs/x"),
    ("get", "/api/evidence-store/objects"), ("get", "/api/evidence-store/verify"),
    ("get", "/api/evidence-documents"), ("get", "/api/evidence-documents/x"),
    ("get", "/api/evidence-documents/x/content"), ("post", "/api/evidence-documents/x/links"),
    ("delete", "/api/evidence-documents/x/links/y"),
]
ADMIN_ONLY = {"/api/evidence-store", "/api/evidence-store/sync", "/api/evidence-store/runs/x",
              "/api/evidence-store/verify", "/api/evidence-documents/x/links", "/api/evidence-documents/x/links/y"}


@pytest.mark.parametrize("method,path", ROUTES)
def test_routes_refuse_anonymous_and_client_keys(app, members, method, path):
    client = app.test_client()
    assert getattr(client, method)(path).status_code == 401
    response = getattr(client, method)(path, headers={"X-API-Key": members["client"].issued_api_key})
    assert response.status_code == 403
    agent = getattr(client, method)(path, headers={"X-API-Key": members["agent"].issued_api_key})
    assert (agent.status_code == 403) == (path in ADMIN_ONLY)


def test_no_evidence_store_route_is_open_to_clients():
    from app.auth import CLIENT_ALLOWED_ENDPOINTS

    assert not any(endpoint.startswith(("evidence_store_api.", "admin_store."))
                   for endpoint in CLIENT_ALLOWED_ENDPOINTS)


def test_documents_are_listed_for_team_members_only_and_never_public(app, members, document):
    client = app.test_client()
    headers = {"X-API-Key": members["agent"].issued_api_key}
    listed = client.get("/api/evidence-documents?kind=code-review", headers=headers).get_json()
    assert listed["total"] == 1 and listed["items"][0]["title"] == "secret-review.md"
    assert listed["items"][0]["version_id"] == "v1" and listed["items"][0]["metadata"] == {"producer": "code-review"}
    assert client.get("/api/evidence-documents?kind=bogus", headers=headers).status_code == 400
    assert client.get("/api/evidence-documents?page=x", headers=headers).status_code == 400
    assert client.get("/api/evidence-documents/nope", headers=headers).status_code == 404
    detail = client.get(f"/api/evidence-documents/{document.id}", headers=headers).get_json()
    assert detail["links"] == [] and detail["sha256"] == "a" * 64
    objects = client.get("/api/evidence-store/objects?kind=evidence_document&status=ingested", headers=headers)
    assert objects.get_json()["items"][0]["key"] == "codex-reviews/secret-review.md"
    assert client.get("/api/evidence-store/objects?status=bogus", headers=headers).status_code == 400
    assert client.get("/api/evidence-store/objects?kind=bogus", headers=headers).status_code == 400
    public = app.test_client()
    for path in ("/", "/controls", "/policies", "/status", "/systems", "/vendors", "/ai-transparency", "/legal"):
        response = public.get(path)
        assert b"secret-review" not in response.data, path


def test_content_and_routes_when_the_store_is_not_configured(app, members, document):
    client = app.test_client()
    agent = {"X-API-Key": members["agent"].issued_api_key}
    admin = {"X-API-Key": members["admin"].issued_api_key}
    assert client.get(f"/api/evidence-documents/{document.id}/content", headers=agent).status_code == 503
    assert client.post("/api/evidence-store/sync", headers=admin).status_code == 400
    assert client.get("/api/evidence-store/verify", headers=admin).status_code == 400
    assert client.get("/api/decision-log/verify?against_store=true", headers=admin).status_code == 400
    status = client.get("/api/evidence-store", headers=admin).get_json()
    assert status["configured"] is False and status["documents"] == 1
    assert client.get("/api/evidence-store/runs/nope", headers=admin).status_code == 404
    from app.services.evidence_store import _periodic_sync

    _periodic_sync(app)  # no bucket: nothing queued
    assert client.get("/api/evidence-store", headers=admin).get_json()["last_run"] is None


def test_oversized_documents_are_not_served(app, members, document, monkeypatch):
    monkeypatch.setenv("EVIDENCE_STORE_BUCKET", "b")
    document.size = service.SERVE_LIMIT + 1
    db.session.commit()
    response = app.test_client().get(f"/api/evidence-documents/{document.id}/content",
                                     headers={"X-API-Key": members["agent"].issued_api_key})
    assert response.status_code == 413
    assert service.download_name(document) == "secret-review.md"
    document.key = "evidence/artifacts/..\"weird name\".txt"
    assert service.download_name(document) == "weird_name_.txt"


def test_links_validate_their_target(app, members, document):
    client = app.test_client()
    headers = {"X-API-Key": members["admin"].issued_api_key}
    url = f"/api/evidence-documents/{document.id}/links"
    assert client.post(url, data="x", headers=headers).status_code == 400
    assert client.post(url, json={}, headers=headers).status_code == 400
    assert client.post(url, json={"control_id": 5}, headers=headers).status_code == 400
    assert client.post(url, json={"test_id": "missing"}, headers=headers).status_code == 400
    assert client.post("/api/evidence-documents/nope/links", json={"control_id": "c"}, headers=headers).status_code == 404
    assert client.delete("/api/evidence-documents/nope/links/x", headers=headers).status_code == 404


def test_flasgger_documents_every_evidence_store_route(app):
    for rule in app.url_map.iter_rules():
        if rule.endpoint.startswith("evidence_store_api."):
            doc = app.view_functions[rule.endpoint].__doc__ or ""
            assert "---" in doc and "responses:" in doc, rule.rule
    paths = app.test_client().get("/apispec_1.json").get_json()["paths"]
    assert {"/evidence-store", "/evidence-store/sync", "/evidence-store/runs/{run_id}", "/evidence-store/objects",
            "/evidence-store/verify", "/evidence-documents", "/evidence-documents/{document_id}",
            "/evidence-documents/{document_id}/content", "/evidence-documents/{document_id}/links",
            "/evidence-documents/{document_id}/links/{link_id}"} <= set(paths)


def test_admin_pages(app, members, document, monkeypatch):
    client = app.test_client()
    login(client, members["agent"])
    assert client.get("/admin/evidence-store", headers={"Accept": "text/html"}).status_code == 302
    login(client, members["admin"])
    page = client.get("/admin/evidence-store?kind=evidence_document&status=bogus&page=x")
    assert page.status_code == 200 and b"secret-review.md" in page.data and b"EVIDENCE_STORE_BUCKET" in page.data
    dashboard = client.get("/admin/")
    assert b"/admin/evidence-store" in dashboard.data
    assert client.post("/admin/evidence-store/sync").status_code == 302  # not configured: flashed

    db.session.add(Control(id="c1", name="MFA", category="security", control_id_short="AC-1"))
    db.session.commit()
    detail_url = f"/admin/evidence-store/documents/{document.id}"
    assert client.get(detail_url).status_code == 200
    assert client.post(f"{detail_url}/links", data={"target": "control:c1"}).status_code == 302
    link = EvidenceDocumentLink.query.one()
    assert link.control_id == "c1" and link.created_by == members["admin"].id
    assert client.post(f"{detail_url}/links", data={"target": "control:c1"}).status_code == 302  # duplicate: flashed
    assert b"AC-1" in client.get(detail_url).data
    assert client.post(f"{detail_url}/links/{link.id}/delete").status_code == 302
    assert EvidenceDocumentLink.query.count() == 0
    assert client.post(f"{detail_url}/links/{link.id}/delete").status_code == 302
    assert client.get("/admin/evidence-store/documents/nope").status_code == 404

    monkeypatch.setenv("EVIDENCE_STORE_BUCKET", "b")
    content = b"# Review\n<b>bold</b>\n"
    db.session.execute(db.text("UPDATE evidence_documents SET sha256 = :s"), {"s": hashlib.sha256(content).hexdigest()})
    db.session.commit()
    def serving(body):
        def copy_version(client, bucket, key, version, limit, sink):
            sink.write(body)
            return hashlib.sha256(body).hexdigest(), len(body)
        return copy_version

    monkeypatch.setattr(store, "copy_version", serving(content))
    monkeypatch.setattr(store, "s3_client", lambda: object())
    view = client.get(f"{detail_url}/view")
    assert view.status_code == 200 and b"&lt;b&gt;bold&lt;/b&gt;" in view.data
    monkeypatch.setattr(store, "copy_version", serving(b"tampered"))
    assert client.get(f"{detail_url}/view").status_code == 302
    queued = client.post("/admin/evidence-store/sync")
    assert queued.status_code == 302
    assert client.post("/admin/evidence-store/sync").status_code == 302  # already queued: flashed


def test_hourly_sync_is_a_periodic_task_not_a_cron_target(app):
    from app.services import evidence_store, scheduler

    evidence_store.register()
    try:
        task = {t.name: t for t in scheduler.periodic_tasks()}["evidence_store_sync"]
        assert task.interval == 3600
    finally:
        scheduler.unregister_periodic("evidence_store_sync")
    assert scheduler.enqueue_scheduled("evidence_store_sync", "bucket") is None
    assert scheduler.enqueue_missed_fire("evidence_store_sync", "bucket", "0 * * * *",
                                         datetime.now(timezone.utc)) is None
    assert "evidence_store_sync" not in {spec[0] for spec in scheduler.desired_schedules().values()}


def test_the_leader_queues_a_store_sync_at_leadership_and_then_every_hour(app, monkeypatch):
    from app.services import evidence_store, scheduler

    queued = []
    monkeypatch.setattr(evidence_store, "_periodic_sync", lambda app_: queued.append(app_))
    evidence_store.register()
    try:
        leader = scheduler.SchedulerService(app)
        assert "evidence_store_sync" in leader.run_periodic(now=10.0)  # when it gains leadership
        assert "evidence_store_sync" not in leader.run_periodic(now=10.0 + 3599)
        assert "evidence_store_sync" in leader.run_periodic(now=10.0 + 3600)  # an hour later
        assert "evidence_store_sync" in leader.run_periodic(now=10.0 + 7200)
    finally:
        scheduler.unregister_periodic("evidence_store_sync")
    assert queued == [app, app, app]


def test_status_cli_without_a_bucket(app, monkeypatch, tmp_path):
    from cli import evidence_store_cmd

    db_file = tmp_path / "portal.db"
    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", f"sqlite:///{db_file}")
    from app import runtime_config

    runtime_config._reset_for_tests()
    other = create_app()
    with other.app_context():
        db.create_all()
    out = io.StringIO()
    args = type("Args", (), {"action": "status", "json": False})()
    assert evidence_store_cmd.run(args, out=out) == 0
    assert "not configured" in out.getvalue() and "last sync: none" in out.getvalue()
    out = io.StringIO()
    args.json = True
    assert evidence_store_cmd.run(args, out=out) == 0
    assert json.loads(out.getvalue())["configured"] is False


# --------------------------------------------------------------------------
# Strict keys, limited parsing, the bucket policy and lifecycle, capped lists
# --------------------------------------------------------------------------

@pytest.mark.parametrize("key,kind", [
    ("decision-logs/2026-10-01T235959Z_" + "s" * 100 + ".jsonl", "decision_log"),
    ("decision-logs/2026-10-01T235959Z_a.b_c-d.meta.json", "decision_log_sidecar"),
    ("decision-logs/2026-02-30T000000Z_s.jsonl", "unmapped"),
    ("decision-logs/2026-10-01T246000Z_s.jsonl", "unmapped"),
    ("decision-logs/2026-10-01_s.jsonl", "unmapped"),
    ("decision-logs/2026-10-01T000000Z_s.meta.json.bak", "unmapped"),
    ("decision-logs/2026-10-01T000000Z_bad id.meta.json", "unmapped"),
    ("pentest-evidence/layer9/" + "n" * 200 + ".json", "pentest_evidence"),
    ("pentest-evidence/layer1/.json", "unmapped"),
    ("pentest-evidence/layer1/a/b.json", "unmapped"),
])
def test_strict_store_keys(key, kind):
    assert keys.classify(key).kind == kind


def test_store_json_is_depth_and_size_limited():
    from app.services.evidence_store import sync

    assert sync.parse_json(b'{"a": [1, 2]}', max_values=10) == {"a": [1, 2]}
    for bad in (b"[" * 70 + b"]" * 70, b"[1, 2, 3, 4, 5]", b"\xff", b"{not json"):
        with pytest.raises(sync.ContentRejected):
            sync.parse_json(bad, max_values=3)


def test_transcript_lines_are_depth_limited():
    from app.services.transcript_ingest import TranscriptError, parse_transcript

    with pytest.raises(TranscriptError, match="nested"):
        parse_transcript(b'{"type": "user", "message": ' + b"[" * 200 + b"]" * 200 + b"}\n")


def test_policy_check():
    from tests.store_fakes import bucket_policy

    issues, principals = store_verify.check_policy(json.dumps(bucket_policy("b")), "b")
    assert (issues, principals) == ([], [])
    issues, principals = store_verify.check_policy(json.dumps(bucket_policy("b", erasure_principal="arn:x")), "b")
    assert (issues, principals) == ([], ["arn:x"])
    other_bucket = json.dumps(bucket_policy("other"))
    assert any("s3:DeleteObject" in issue for issue in store_verify.check_policy(other_bucket, "b")[0])
    wildcard = {"Statement": [
        {"Effect": "Deny", "Principal": {"AWS": ["*"]}, "Action": ["s3:Delete*", "s3:PutObjectRetention",
                                                                  "s3:BypassGovernanceRetention"],
         "Resource": "arn:aws:s3:::b/*"},
        {"Effect": "Deny", "Principal": "*", "Action": "s3:*", "Resource": "arn:aws:s3:::b/*",
         "Condition": {"Null": {"s3:if-none-match": "true"}}}]}
    assert store_verify.check_policy(json.dumps(wildcard), "b") == ([], [])
    narrowed = json.loads(json.dumps(wildcard))
    narrowed["Statement"][0]["Resource"] = "arn:aws:s3:::b/decision-logs/*"
    narrowed["Statement"][0]["Principal"] = {"AWS": "arn:aws:iam::1:root"}
    assert len(store_verify.check_policy(json.dumps(narrowed), "b")[0]) == 4
    for broken in ("not json", "[]", json.dumps({"Statement": "x"})):
        assert store_verify.check_policy(broken, "b")[0]


def test_lifecycle_check():
    assert store_verify.check_lifecycle([]) == []
    assert store_verify.check_lifecycle([{"ID": "a", "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]) == []
    for rule in ({"Expiration": {"Days": 1}}, {"Transitions": [{"Days": 1}]},
                 {"NoncurrentVersionTransitions": [{"NoncurrentDays": 1}]},
                 {"NoncurrentVersionExpiration": {"NoncurrentDays": 1}}):
        assert store_verify.check_lifecycle([dict(rule, ID="r")])


def test_capped_findings_keep_exact_counts():
    found = store_verify.Capped(cap=2)
    for index in range(5):
        found.add({"i": index})
    assert found.count == 5 and len(found.items) == 2 and found.report(1) == [{"i": 0}]
