"""Red-team round 2, git sources and decision logs (SQLite): who may extend a
transcript and how (back-dating, metadata, insertion order), the 32 MiB
transcript cap, no provider call inside a transaction, disabled governance
sources, last-synced-commit resets and compare-and-set, history truncation,
URL columns in imports and unstorable transcript values."""

import json
import uuid

import pytest
from sqlalchemy import update

from app.models import DecisionLogEntry, DecisionLogSession, DecisionLogTranscript, Evidence, Policy, Vendor, db
from app.models.git_source import GitSource
from app.services import chunked_files, evidence_import, governance_docs, team_service
from app.services import evidence_import_decision_logs as dl
from app.services.evidence_import import import_dataset_file, import_decision_log, import_directory
from app.services.git_sources import service, sync
from app.services.git_sources.providers import GitSourceError

from tests.test_git_sync import (  # noqa: F401 - fixtures and helpers
    FakeProvider,
    admin,
    app,
    base,
    blob,
    counts,
    fake,
    fake_source,
    files_of,
    run_sync,
    write,
)


def rec(role, text, ts, msg_id, model=None, **extra):
    message = {"role": role, "id": msg_id, "content": [{"type": "text", "text": text}]}
    if model:
        message["model"] = model
    record = {"type": role, "message": message}
    if ts:
        record["timestamp"] = ts
    record.update(extra)
    return json.dumps(record)


GENUINE = [
    rec("user", "please deploy", "2026-03-16T12:00:00Z", "u1"),
    rec("assistant", "Please verify, then reply done.", "2026-03-16T12:05:00Z", "a1"),
    rec("user", "it is broken, do not ship", "2026-03-16T12:30:00Z", "u2"),
]


def member(name):
    return team_service.create_member(name, f"{name.lower().replace(' ', '.')}@example.com", "agent")


def upload(client, who, session_id, lines, query=""):
    body = "\n".join(lines) if isinstance(lines, list) else lines
    return client.post(f"/api/decision-log/upload?session_id={session_id}{query}", data=body,
                       headers={"X-API-Key": who.issued_api_key})


def stored_texts(session_id):
    db.session.expire_all()
    return [e.content_text for e in DecisionLogEntry.query.filter_by(session_id=session_id)
            .order_by(DecisionLogEntry.id)]


# --------------------------------------------------------------------------
# N3: who may extend a transcript, back-dating, order, metadata
# --------------------------------------------------------------------------

def test_backdated_done_from_another_member_is_refused(app):
    a, b = member("Agent A"), member("Agent B")
    client = app.test_client()
    assert upload(client, a, "sess-a", GENUINE).status_code == 200
    forged = GENUINE + [rec("user", "done.", "2026-03-16T12:06:00Z", "u-forged")]
    resp = upload(client, b, "sess-a", forged)
    assert resp.status_code == 403
    assert resp.get_json()["status"] == "rejected"
    assert stored_texts("sess-a") == ["please deploy", "Please verify, then reply done.",
                                      "it is broken, do not ship"]
    shown = client.get("/api/decision-log/session/sess-a", headers={"X-API-Key": a.issued_api_key}).get_json()
    assert not any(e["is_verification"] for e in shown["entries"])
    listing = client.get("/api/decision-log/sessions", headers={"X-API-Key": a.issued_api_key}).get_json()
    assert listing["items"][0]["verifications"] == 0


def test_appended_entries_must_not_be_backdated(app, admin):
    a = member("Agent A")
    client = app.test_client()
    upload(client, a, "sess-b", GENUINE)
    backdated = GENUINE + [rec("user", "done.", "2026-03-16T12:06:00Z", "u3")]
    for who in (a, admin):
        resp = upload(client, who, "sess-b", backdated)
        assert resp.status_code == 409, who.name
        assert "must not be back-dated" in resp.get_json()["error"]
        assert "entry 4 is timestamped 2026-03-16T12:06:00+00:00" in resp.get_json()["error"]
    assert DecisionLogTranscript.query.filter_by(session_id="sess-b", status="rejected").count() == 1
    assert len(stored_texts("sess-b")) == 3

    # Equal timestamps and entries without a timestamp are allowed.
    later = GENUINE + [rec("user", "no timestamp", None, "u3"),
                       rec("user", "done.", "2026-03-16T12:30:00Z", "u4")]
    resp = upload(client, a, "sess-b", later)
    assert resp.status_code == 200 and resp.get_json()["status"] == "replaced"
    assert stored_texts("sess-b")[-2:] == ["no timestamp", "done."]


def test_submitter_admin_and_system_may_extend_until_the_repository_holds_it(app, admin):
    a, b = member("Agent A"), member("Agent B")
    client = app.test_client()
    upload(client, a, "sess-c", GENUINE[:1])
    assert upload(client, b, "sess-c", GENUINE[:2]).status_code == 403
    assert upload(client, admin, "sess-c", GENUINE[:2]).get_json()["status"] == "replaced"
    assert import_decision_log("\n".join(GENUINE), session_id="sess-c").status == "replaced"  # system
    db.session.commit()
    more = GENUINE + [rec("user", "fixed now", "2026-03-16T12:40:00Z", "u3")]
    # Once the repository has imported it, only the repository extends it (round 6).
    assert upload(client, a, "sess-c", more).status_code == 409
    assert upload(client, admin, "sess-c", more).status_code == 409
    assert db.session.get(DecisionLogSession, "sess-c").submitted_by == a.id

    # A session a git sync created is extended only by the repository.
    assert import_decision_log(GENUINE[0], session_id="sess-d").status == "created"
    db.session.commit()
    assert upload(client, a, "sess-d", GENUINE[:2]).status_code == 403
    assert upload(client, admin, "sess-d", GENUINE[:2]).status_code == 409
    assert db.session.get(DecisionLogSession, "sess-d").submitted_by is None

    # A shorter or identical upload by another member changes nothing and is not an error.
    assert upload(client, b, "sess-c", GENUINE[:1]).get_json()["status"] == "kept_existing"
    with pytest.raises(ValueError, match="must name its submitter"):
        import_decision_log(GENUINE[0], session_id="sess-e", authority=dl.AUTHORITY_MEMBER)
    with pytest.raises(ValueError, match="authority must be one of"):
        import_decision_log(GENUINE[0], session_id="sess-e", authority="anyone")


def test_entries_are_read_in_transcript_order_not_by_timestamp(app):
    a = member("Agent A")
    client = app.test_client()
    lines = [rec("user", "first", "2026-03-16T12:30:00Z", "u1"),
             rec("assistant", "second", "2026-03-16T12:00:00Z", "a1"),
             rec("user", "third", None, "u2")]
    upload(client, a, "sess-o", lines)
    shown = client.get("/api/decision-log/session/sess-o", headers={"X-API-Key": a.issued_api_key}).get_json()
    assert [e["content_text"] for e in shown["entries"]] == ["first", "second", "third"]
    session = db.session.get(DecisionLogSession, "sess-o")
    assert [e.content_text for e in session.interactions] == ["first", "second", "third"]


def test_session_metadata_is_fixed_except_by_an_admin(app, admin):
    a = member("Agent A")
    client = app.test_client()
    first = rec("user", "hi", "2026-03-16T12:00:00Z", "u1", model="genuine-model", cwd="/genuine",
                gitBranch="main")
    assert upload(client, a, "meta", [first], "&exit_reason=clean").status_code == 200
    forged = rec("user", "hi", "2026-03-16T12:00:00Z", "u1", model="forged-model", cwd="/attacker",
                 gitBranch="evil")
    tail = rec("user", "x", "2026-03-16T12:01:00Z", "u2")
    resp = upload(client, a, "meta", [forged, tail], "&exit_reason=forged")
    assert resp.get_json()["status"] == "replaced"
    db.session.expire_all()
    session = db.session.get(DecisionLogSession, "meta")
    assert (session.model, session.cwd, session.git_branch, session.exit_reason) == \
        ("genuine-model", "/genuine", "main", "clean")
    assert session.submitted_by == a.id and session.agent_type == "claude_code"
    assert session.ended_at.isoformat() == "2026-03-16T12:01:00"

    tail2 = rec("user", "y", "2026-03-16T12:02:00Z", "u3")
    assert upload(client, admin, "meta", [forged, tail, tail2], "&exit_reason=admin-set").status_code == 200
    db.session.expire_all()
    session = db.session.get(DecisionLogSession, "meta")
    assert (session.model, session.cwd, session.git_branch, session.exit_reason) == \
        ("forged-model", "/attacker", "evil", "admin-set")
    assert session.submitted_by == a.id

    # A later version fills a field that is still unset.
    upload(client, a, "meta-2", [rec("user", "hi", "2026-03-16T12:00:00Z", "u1")])
    upload(client, a, "meta-2", [rec("user", "hi", "2026-03-16T12:00:00Z", "u1"),
                                 rec("user", "x", "2026-03-16T12:01:00Z", "u2", cwd="/later")],
           "&exit_reason=late")
    db.session.expire_all()
    session = db.session.get(DecisionLogSession, "meta-2")
    assert (session.cwd, session.exit_reason) == ("/later", "late")


@pytest.mark.parametrize("name, record", [
    ("long-role", {"type": "user", "message": {"role": "r" * 50, "content": "x"}}),
    ("dict-role", {"type": "user", "message": {"role": {"a": 1}, "content": "x"}}),
    ("dict-cwd", {"type": "user", "cwd": {"a": 1}, "message": {"role": "user", "content": "x"}}),
    ("long-cwd", {"type": "user", "cwd": "c" * 501, "message": {"role": "user", "content": "x"}}),
    ("list-branch", {"type": "user", "gitBranch": ["main"], "message": {"role": "user", "content": "x"}}),
    ("long-branch", {"type": "user", "gitBranch": "b" * 201, "message": {"role": "user", "content": "x"}}),
    ("long-msgid", {"type": "user", "message": {"role": "user", "id": "i" * 300, "content": "x"}}),
    ("int-msgid", {"type": "user", "message": {"role": "user", "id": 12345, "content": "x"}}),
    ("dict-model", {"type": "assistant", "message": {"role": "assistant", "model": {"m": 1}, "content": "x"}}),
    ("long-model", {"type": "assistant", "message": {"role": "assistant", "model": "m" * 101, "content": "x"}}),
])
def test_upload_rejects_unstorable_field_values_with_400(app, name, record):
    a = member("Agent A")
    resp = upload(app.test_client(), a, f"w-{name}", json.dumps(record))
    assert resp.status_code == 400, resp.get_data(as_text=True)
    assert "line 1:" in resp.get_json()["error"]
    assert db.session.get(DecisionLogSession, f"w-{name}") is None


def test_upload_stores_odd_but_storable_values(app):
    a = member("Agent A")
    client = app.test_client()
    cases = {
        "ts-overflow": ({"type": "user", "timestamp": "0001-01-01T00:00:00+14:00",
                         "message": {"role": "user", "content": "x"}}, "x"),
        "nul": ({"type": "user", "message": {"role": "user", "content": "a\u0000b"}}, "a�b"),
    }
    for name, (record, expected) in cases.items():
        resp = upload(client, a, f"odd-{name}", json.dumps(record))
        assert resp.status_code == 200, (name, resp.get_data(as_text=True))
        (entry,) = DecisionLogEntry.query.filter_by(session_id=f"odd-{name}").all()
        assert entry.content_text == expected and entry.timestamp is None
    lone_surrogate = '{"type":"user","message":{"role":"user","content":"a\\ud800b"}}'
    assert upload(client, a, "odd-surrogate", lone_surrogate).status_code == 200
    assert DecisionLogEntry.query.filter_by(session_id="odd-surrogate").one().content_text == "a�b"


# --------------------------------------------------------------------------
# N5: 32 MiB transcript cap
# --------------------------------------------------------------------------

BIG = "\n".join(rec("user", "y" * 100, "2026-03-16T12:00:00Z", f"u{i}") for i in range(30))


@pytest.fixture
def small_cap(monkeypatch):
    monkeypatch.setattr(dl, "MAX_TRANSCRIPT_BYTES", 2000, raising=False)
    assert len(BIG.encode()) > 2000
    return 2000


def test_transcript_cap_is_enforced_on_upload_and_import(app, small_cap):
    a = member("Agent A")
    app.config["MAX_CONTENT_LENGTH"] = 64 * 1024 * 1024
    resp = upload(app.test_client(), a, "sess-big", BIG)
    assert resp.status_code == 413
    assert "exceeds the 2000 byte limit" in resp.get_json()["error"]
    assert DecisionLogSession.query.count() == 0
    with pytest.raises(dl.TranscriptTooLargeError, match="limited to 2000 bytes"):
        import_decision_log(BIG, session_id="sess-big")
    assert import_decision_log(GENUINE[0], session_id="sess-small").status == "created"


def evidence_source(**extra):
    return service.create_source(base(name="ev", role="evidence", repository="/unused", **extra))


LOG_BIG = "decision-logs/2026-01-01T000000Z_sess-big.jsonl"
LOG_OK = "decision-logs/2026-01-01T000000Z_sess-ok.jsonl"


def test_oversized_decision_log_is_flagged_once_until_its_blob_changes(app, fake, small_cap):
    source = evidence_source()
    fake.commit("c1", {LOG_BIG: BIG, LOG_OK: GENUINE[0]})
    run = run_sync(source)
    assert run.status == "partial"
    assert run.counts == counts(created=1, flagged=1)
    assert run.details["flagged"] == [{"path": LOG_BIG, "size": len(BIG), "limit": 2000,
                                       "reason": "decision-log transcript exceeds the decision-log size limit"}]
    record = files_of(source)[LOG_BIG]
    assert (record.status, record.size, record.blob_id) == ("too_large", len(BIG), blob(BIG.encode()))
    assert db.session.get(DecisionLogSession, "sess-big") is None

    # Not read again while its blob is unchanged: neither by a diff nor by a tree comparison.
    fake.calls.clear()
    fake.commit("c2", {LOG_BIG: BIG, LOG_OK: "\n".join(GENUINE[:2])})
    assert run_sync(source).counts == counts(updated=1)
    fake.diff_error = GitSourceError("no diff")
    fake.commit("c3", {LOG_BIG: BIG, LOG_OK: "\n".join(GENUINE)})
    assert run_sync(source).counts == counts(updated=1)
    assert not [call for call in fake.calls if call[1] == LOG_BIG]

    fake.commit("c4", {LOG_BIG: "\n".join(GENUINE), LOG_OK: "\n".join(GENUINE)})
    assert run_sync(source).counts == counts(created=1)
    assert files_of(source)[LOG_BIG].status == "ok"
    assert len(stored_texts("sess-big")) == 3


def test_oversized_chunked_transcript_is_flagged_from_its_manifest(app, fake, small_cap):
    source = evidence_source()
    manifest, parts = chunked_files.split("2026-01-01T000000Z_sess-big.jsonl", BIG.encode(), part_size=1000)
    files = {LOG_BIG + chunked_files.MANIFEST_SUFFIX: manifest}
    files.update({f"decision-logs/{name}": data for name, data in parts})
    fake.commit("c1", files)
    run = run_sync(source)
    assert run.counts == counts(flagged=1)
    assert not [call for call in fake.calls if ".part-" in str(call[1])]
    record = files_of(source)[LOG_BIG + chunked_files.MANIFEST_SUFFIX]
    assert (record.status, record.size) == ("too_large", len(BIG))


def test_directory_import_reports_an_oversized_transcript(app, tmp_path, small_cap):
    write(tmp_path, LOG_BIG, BIG)
    write(tmp_path, LOG_OK, GENUINE[0])
    result = import_directory(str(tmp_path), include_decision_logs=True)
    assert result["decision_logs"]["failed"] == 1 and result["decision_logs"]["created"] == 1
    assert any(line.startswith(f"{LOG_BIG}: not imported (TranscriptTooLargeError:") for line in result["errors"])
    assert db.session.get(DecisionLogSession, "sess-big") is None


# --------------------------------------------------------------------------
# M14: no provider call while the sync's session has a transaction open
# --------------------------------------------------------------------------

class TransactionCheckingProvider(FakeProvider):
    """Records every provider call made while the database session has a transaction open."""

    def __init__(self):
        super().__init__()
        self.inside = []

    def _check(self, name):
        if db.session().in_transaction():
            self.inside.append(name)

    def resolve_head(self):
        self._check("resolve_head")
        return super().resolve_head()

    def list_tree(self, commit_id):
        self._check("list_tree")
        return super().list_tree(commit_id)

    def diff(self, from_commit, to_commit):
        self._check("diff")
        return super().diff(from_commit, to_commit)

    def read_blob(self, entry_or_blob_id, *, path=None, commit_id=None, max_bytes=None):
        self._check(f"read_blob {path}")
        return super().read_blob(entry_or_blob_id, path=path, commit_id=commit_id, max_bytes=max_bytes)

    def read_file(self, path, commit_id, *, max_bytes=None):
        self._check(f"read_file {path}")
        return super().read_file(path, commit_id, max_bytes=max_bytes)

    def commits_between(self, from_commit, to_commit, limit):
        self._check("commits_between")
        return super().commits_between(from_commit, to_commit, limit)

    def commit_changed_paths(self, commit):
        self._check("commit_changed_paths")
        return super().commit_changed_paths(commit)


def test_sync_makes_no_provider_call_inside_a_transaction(app, monkeypatch):
    provider = TransactionCheckingProvider()
    monkeypatch.setattr(sync, "build_provider_for", lambda source: provider)
    source = evidence_source(options={"record_commits": True})
    chunked = "decision-logs/2026-01-02T000000Z_sess-chunked.jsonl"
    manifest, parts = chunked_files.split(chunked.rsplit("/", 1)[1], "\n".join(GENUINE).encode(), part_size=100)
    files = {"controls.json": json.dumps([{"id": "c1", "name": "MFA", "tsc_category": "security"}]),
             "systems.json": "[]", LOG_OK: GENUINE[0],
             LOG_OK.replace(".jsonl", ".meta.json"): json.dumps({"reason": "clear"}),
             chunked + chunked_files.MANIFEST_SUFFIX: manifest}
    files.update({f"decision-logs/{name}": data for name, data in parts})
    provider.commit("c1", files)
    provider.failing.add("systems.json")
    first = run_sync(source)
    assert first.status == "partial" and first.counts["created"] == 3 and first.counts["errors"] == 1

    provider.failing.clear()
    files.pop("controls.json")
    files[LOG_OK] = "\n".join(GENUINE[:2])
    provider.commit("c2", files)
    second = run_sync(source)  # diff + retry of systems.json (read_file and list_tree) + deletion
    assert second.status == "success", second.details
    assert second.details["strategy"] == "diff"
    assert files_of(source)["systems.json"].status == "ok"
    assert first.details["commits_recorded"] == 1 and second.details["commits_recorded"] == 1
    assert provider.inside == []


# --------------------------------------------------------------------------
# M15: disabled governance sources, last synced commit resets and compare-and-set
# --------------------------------------------------------------------------

def make_policy(file_path):
    policy = Policy(id=str(uuid.uuid4()), title="Access", category="security", status="approved",
                    file_path=file_path)
    db.session.add(policy)
    db.session.commit()
    return policy


def test_a_disabled_sources_policy_is_not_served_nor_replaced_by_another_file(app, tmp_path):
    gov, other = tmp_path / "gov", tmp_path / "other"
    write(gov, "policies/access.md", "# Access\n\nSOURCE TEXT\n")
    write(other, "drafts/access.md", "# Access\n\nOTHER SOURCE DRAFT\n")
    source = service.create_source(base(name="gov", repository=str(gov)))
    second = service.create_source(base(name="other", repository=str(other),
                                        path_mappings=[{"pattern": "drafts/*.md", "kind": "policy"}]))
    run_sync(source)
    run_sync(second)
    policy = make_policy("policies/access.md")
    client = app.test_client()
    assert "SOURCE TEXT" in client.get(f"/policies/{policy.id}").get_data(as_text=True)

    service.update_source(db.session.get(GitSource, source.id), {"enabled": False})
    html = client.get(f"/policies/{policy.id}").get_data(as_text=True)
    assert "OTHER SOURCE DRAFT" not in html and "SOURCE TEXT" not in html
    assert "not available for online viewing" in html
    assert governance_docs.policy_file_state("policies/access.md") == ("unavailable", None)

    service.update_source(db.session.get(GitSource, source.id), {"enabled": True})
    assert "SOURCE TEXT" in client.get(f"/policies/{policy.id}").get_data(as_text=True)


def test_a_file_name_match_stays_owned_by_its_disabled_source(app, tmp_path):
    gov, other = tmp_path / "gov", tmp_path / "other"
    write(gov, "policies/access.md", "# Access\n\nSOURCE TEXT\n")
    source = service.create_source(base(name="gov", repository=str(gov)))
    run_sync(source)
    policy = make_policy("old-layout/access.md")  # resolved by its file name
    client = app.test_client()
    assert "SOURCE TEXT" in client.get(f"/policies/{policy.id}").get_data(as_text=True)

    service.update_source(db.session.get(GitSource, source.id), {"enabled": False})
    assert governance_docs.policy_file_state("old-layout/access.md") == ("unavailable", None)
    write(other, "drafts/access.md", "# Access\n\nOTHER SOURCE DRAFT\n")
    run_sync(service.create_source(base(name="other", repository=str(other),
                                        path_mappings=[{"pattern": "drafts/*.md", "kind": "policy"}])))
    html = client.get(f"/policies/{policy.id}").get_data(as_text=True)
    assert "OTHER SOURCE DRAFT" not in html and "not available for online viewing" in html


def test_changing_what_a_source_reads_resets_its_last_synced_commit(app, admin):
    commit = "a" * 40

    def synced(data):
        source = service.create_source(data, member_id=admin.id)
        return service.set_last_synced_commit(source, commit)

    def after(source, change):
        return service.update_source(db.session.get(GitSource, source.id), change,
                                     member_id=admin.id).last_synced_commit

    local = synced(base(name="loc"))
    assert after(local, {"schedule_cron": "0 * * * *", "enabled": False}) == commit
    assert after(local, {"branch": "main", "repository": "/srv/gov"}) == commit  # same values
    assert after(local, {"branch": "release"}) is None
    service.set_last_synced_commit(db.session.get(GitSource, local.id), commit)
    assert after(local, {"repository": "/srv/other"}) is None

    github = synced(base(name="gh", provider="github", repository="octo/repo", credential_mode="none"))
    assert after(github, {"options": {"history_limit": 7}}) == commit
    assert after(github, {"options": {"api_url": "https://ghe.example"}}) is None
    codecommit = synced(base(name="cc", provider="codecommit", repository="repo", region="ca-central-1"))
    assert after(codecommit, {"region": "us-east-1"}) is None


def test_admin_form_reports_the_reset_of_the_last_synced_commit(app, admin):
    from tests.conftest import login

    source = service.set_last_synced_commit(service.create_source(base(name="gov")), "a" * 40)
    client = app.test_client()
    login(client, admin)
    form = {"repository": "/srv/gov", "branch": "main", "enabled": "on"}
    client.post(f"/admin/git-sources/{source.id}", data=form)
    assert db.session.get(GitSource, source.id).last_synced_commit == "a" * 40
    resp = client.post(f"/admin/git-sources/{source.id}", data=dict(form, branch="release"),
                       follow_redirects=True)
    assert "its last synced commit was cleared" in resp.get_data(as_text=True)
    assert db.session.get(GitSource, source.id).last_synced_commit is None


def test_cli_update_reports_the_reset_of_the_last_synced_commit(app, monkeypatch):
    import io

    from cli import git_source_cmd
    from cli.__main__ import build_parser

    source = service.set_last_synced_commit(service.create_source(base(name="gov")), "a" * 40)
    monkeypatch.setattr("app.create_app", lambda *args, **kwargs: app)
    out = io.StringIO()
    args = build_parser().parse_args(["git-source", "update", "--name", "gov", "--branch", "release"])
    assert git_source_cmd.run(args, out=out) == 0
    assert "its last synced commit was cleared" in out.getvalue()
    assert db.session.get(GitSource, source.id).last_synced_commit is None


def test_a_finishing_sync_keeps_a_commit_an_admin_set_during_the_run(app, fake, fake_source, monkeypatch):
    fake.commit("c1", {"policies/a.md": "# A\n"})
    first = run_sync(fake_source)
    fake.commit("c2", {"policies/a.md": "# A2\n"})
    cutover = "c" * 40
    real = sync.process_candidate

    def admin_sets_commit(source, fetched, candidate, head, tally, member_id):
        real(source, fetched, candidate, head, tally, member_id)
        db.session.execute(update(GitSource).where(GitSource.id == source.id).values(last_synced_commit=cutover))

    monkeypatch.setattr(sync, "process_candidate", admin_sets_commit)
    run = run_sync(fake_source)
    assert run.status == "success" and run.from_commit == first.to_commit
    source = db.session.get(GitSource, fake_source.id)
    assert source.last_synced_commit == cutover
    assert source.last_sync_status == "success"


# --------------------------------------------------------------------------
# Lows: history truncation, URL columns, session lock order
# --------------------------------------------------------------------------

def test_history_truncation_is_flagged(app, fake, fake_source):
    for index in range(3):
        fake.commit(f"c{index}", {"policies/a.md": f"# A{index}\n"})
    service.update_source(db.session.get(GitSource, fake_source.id), {"options": {"history_limit": 2}})
    run = run_sync(fake_source)
    assert run.details["history_truncated"] is True and run.details["commits_recorded"] == 2
    service.update_source(db.session.get(GitSource, fake_source.id), {"options": {"history_limit": 10}})
    fake.commit("c3", {"policies/a.md": "# A3\n"})
    run = run_sync(fake_source)
    assert run.details["history_truncated"] is False and run.details["commits_recorded"] == 2
    assert run_sync(fake_source).details["history_truncated"] is False  # unchanged head: no history read


VENDORS = [
    {"id": "v1", "name": "Good", "website_url": "https://good.example", "tos_url": ""},
    {"id": "v2", "name": "Script", "website_url": "javascript:alert(1)"},
    {"id": "v3", "name": "Data", "privacy_policy_url": "data:text/html,<script>x</script>"},
    {"id": "v4", "name": "Relative", "security_page_url": "/relative"},
]


def test_imported_url_columns_must_be_http_urls(app, tmp_path):
    result = import_dataset_file("vendors", "vendors.json", VENDORS)
    db.session.commit()
    assert (result.created, result.skipped) == (1, 3)
    assert {v.id for v in Vendor.query.all()} == {"v1"}
    assert "vendors.json: item 1 (id=v2): website_url must be an http(s) URL" in result.errors
    assert any("privacy_policy_url must be an http(s) URL" in line for line in result.errors)
    assert any("security_page_url must be an http(s) URL" in line for line in result.errors)

    write(tmp_path, "controls.json", json.dumps([{"id": "c1", "name": "MFA", "tsc_category": "security"}]))
    write(tmp_path, "tests.json", json.dumps([{"id": "t1", "control_id": "c1", "name": "MFA test"}]))
    write(tmp_path, "evidence/evidence-index.json", json.dumps([
        {"test_name": "MFA test", "evidence_type": "link", "url": "javascript:alert(1)",
         "collected_at": "2026-03-27T00:00:00+00:00"},
        {"test_name": "MFA test", "evidence_type": "link", "url": "https://example.com/ok",
         "collected_at": "2026-03-28T00:00:00+00:00"}]))
    summary = import_directory(str(tmp_path), datasets=["controls", "tests", "evidence"])
    assert summary["datasets"]["evidence"]["created"] == 1 and summary["datasets"]["evidence"]["skipped"] == 1
    assert any("url must be an http(s) URL" in line for line in summary["errors"])
    assert [e.url for e in Evidence.query.all()] == ["https://example.com/ok"]


def test_git_sync_takes_the_session_lock_before_writing_a_decision_log(app, fake, monkeypatch):
    source = evidence_source()
    fake.commit("c1", {LOG_OK: GENUINE[0]})
    order = []
    real_record = sync._file_record
    monkeypatch.setattr(evidence_import, "lock_session", lambda sid: order.append(f"lock {sid}"),
                        raising=False)

    def recording(src, candidate):
        order.append(f"record {candidate.path}")
        return real_record(src, candidate)

    monkeypatch.setattr(sync, "_file_record", recording)
    assert run_sync(source).counts == counts(created=1)
    assert order[:2] == ["lock sess-ok", f"record {LOG_OK}"]
