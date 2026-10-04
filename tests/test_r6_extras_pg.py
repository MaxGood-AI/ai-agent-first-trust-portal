"""Round 6 additions from the production-configured review instance.

1. Keys never reach stdout or stderr; CLI logs never reach stdout.
2. Repository versions are not rejected as back-dated (synthetic transcripts
   with the out-of-order shapes real agent exports have; no real content).
3. The local provider walks only the mapped roots and skips vendor trees.
4. db-check-role prints an OK line; the dashboard always shows the witness.
5. The one-time pentest rebuild is recorded in the sync run.
"""

import json
import os
import secrets
import subprocess
import sys

import pytest

from app.models import TeamMember, db

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _production_cli(db_url, *args, tmp_path):
    env = {key: value for key, value in os.environ.items()
           if not key.startswith(("AWS_", "DATABASE_", "PORTAL_", "AUDIT_", "BOOTSTRAP", "SECRET_KEY"))}
    env.update(PORTAL_ENV="production", SECRET_KEY=secrets.token_urlsafe(48), DATABASE_URL=db_url,
               LOG_LEVEL="DEBUG", HOME=str(tmp_path))
    return subprocess.run([sys.executable, "-m", "cli", *args], cwd=ROOT, env=env, capture_output=True,
                          text=True, timeout=120)


# --------------------------------------------------------------------------
# 1. Keys and logs
# --------------------------------------------------------------------------

def test_key_issuing_commands_never_print_or_log_a_key(migrated_pg_url, tmp_path):
    key_file = tmp_path / "admin.key"
    created = _production_cli(migrated_pg_url, "create-admin", "--name", "Ops", "--email", "ops@example.com",
                              "--key-file", str(key_file), tmp_path=tmp_path)
    assert created.returncode == 0, created.stderr[-2000:]
    key = key_file.read_text().strip()
    assert len(key) >= 32 and oct(key_file.stat().st_mode & 0o777) == "0o600"
    rekey_file = tmp_path / "rekey.key"
    rekeyed = _production_cli(migrated_pg_url, "regenerate-key", "--member", "ops@example.com",
                              "--key-file", str(rekey_file), tmp_path=tmp_path)
    assert rekeyed.returncode == 0, rekeyed.stderr[-2000:]
    new_key = rekey_file.read_text().strip()
    for result in (created, rekeyed):
        for stream in (result.stdout, result.stderr):
            assert key not in stream and new_key not in stream
        # stdout is exactly the command's one line; every log line (JSON in production) is on stderr
        assert len(result.stdout.splitlines()) == 1 and not result.stdout.lstrip().startswith("{")
        assert str(key_file if result is created else rekey_file) in result.stdout


def test_key_file_is_never_overwritten_nor_written_inside_a_git_tree(cli_env, tmp_path):
    from cli import admin_cmd
    from cli.__main__ import build_parser
    import io

    existing = tmp_path / "exists.key"
    existing.write_text("keep me")
    repo = tmp_path / "repo"
    (repo / ".git").mkdir(parents=True)
    (repo / "sub").mkdir()
    for path, message in ((existing, "already exists"), (repo / "sub" / "k.key", "inside a git working tree"),
                          (tmp_path / "missing-dir" / "k.key", "is not a directory")):
        out = io.StringIO()
        code = admin_cmd.run(build_parser().parse_args(
            ["create-admin", "--name", "X", "--email", "x@example.com", "--key-file", str(path)]), out=out)
        assert code == 2 and message in out.getvalue()
    assert existing.read_text() == "keep me"
    assert TeamMember.query.filter_by(email="x@example.com").count() == 0  # nothing issued


@pytest.fixture
def cli_env(pg_app, migrated_pg_url, monkeypatch):
    from app import runtime_config

    monkeypatch.setenv("PORTAL_ENV", "test")
    monkeypatch.setenv("DATABASE_URL", migrated_pg_url)
    runtime_config._reset_for_tests()
    yield
    runtime_config._reset_for_tests()


def test_cli_logs_never_go_to_stdout(capsys):
    import logging

    from app.logging_config import configure_logging, route_logs_to_stderr

    route_logs_to_stderr()
    configure_logging(force=True)
    logging.getLogger("cli.test").warning("a log line")
    captured = capsys.readouterr()
    assert "a log line" not in captured.out and "a log line" in captured.err


# --------------------------------------------------------------------------
# 2. Repository versions are not "back-dated"
# --------------------------------------------------------------------------

def _line(role, text_value, ts, msg_id, **extra):
    record = {"type": role, "timestamp": ts,
              "message": {"role": role, "id": msg_id, "content": [{"type": "text", "text": text_value}]}}
    record.update(extra)
    return json.dumps(record)


# The shapes real exports have (content replaced): a side-chain (sub-agent) record and a resumed
# session's record written after later ones but carrying earlier timestamps.
FIRST = [_line("user", "task", "2026-03-16T12:00:00Z", "u1"),
         _line("assistant", "working", "2026-03-16T12:20:00Z", "a1")]
LATER = [_line("assistant", "sub-agent result", "2026-03-16T12:10:00Z", "s1", isSidechain=True),
         _line("user", "resumed", "2026-03-16T12:05:00Z", "u2"),
         _line("user", "done.", "2026-03-16T12:30:00Z", "u3")]


def test_repository_version_with_out_of_order_timestamps_imports(pg_app):
    from app.services.evidence_import import import_decision_log

    path = "decision-logs/2026-03-16T120000Z_ooo.jsonl"
    assert import_decision_log("\n".join(FIRST).encode(), session_id="ooo", source_path=path).status == "created"
    db.session.commit()
    result = import_decision_log("\n".join(FIRST + LATER).encode(), session_id="ooo", source_path=path)
    db.session.commit()
    assert (result.status, result.reason) == ("replaced", None)


def test_member_appends_are_still_held_to_the_back_dating_rule(pg_app):
    from app.services import team_service

    member = team_service.create_member("Member", "m@example.com", "agent")
    client = pg_app.test_client()
    headers = {"X-API-Key": member.issued_api_key}
    assert client.post("/api/decision-log/upload?session_id=api-only", data="\n".join(FIRST).encode(),
                       headers=headers).status_code in (200, 201)
    response = client.post("/api/decision-log/upload?session_id=api-only",
                           data="\n".join(FIRST + LATER).encode(), headers=headers)
    assert response.status_code == 409 and "back-dated" in response.get_json()["error"]


# --------------------------------------------------------------------------
# 3. Local provider: only the mapped roots
# --------------------------------------------------------------------------

def test_local_provider_walks_only_mapped_roots(tmp_path, monkeypatch):
    from app.services.git_sources.providers import LocalDirectoryProvider

    (tmp_path / "decision-logs").mkdir()
    (tmp_path / "decision-logs" / "a.jsonl").write_text("{}")
    (tmp_path / "controls.json").write_text("[]")
    (tmp_path / "pentest-evidence" / "layer1").mkdir(parents=True)
    (tmp_path / "pentest-evidence" / "layer1" / "scan.json").write_text("{}")
    (tmp_path / "pentest-evidence" / "node_modules").mkdir()
    (tmp_path / "pentest-evidence" / "node_modules" / "x.json").write_text("{}")
    for name in ("unrelated", "node_modules", ".git"):
        (tmp_path / name / "deep").mkdir(parents=True)
        for n in range(50):
            (tmp_path / name / "deep" / f"f{n}.txt").write_text(str(n))
    hashed = []
    real_hash = LocalDirectoryProvider._hash

    def counting(self, rel, target, stat):
        hashed.append(rel)
        return real_hash(self, rel, target, stat)

    monkeypatch.setattr(LocalDirectoryProvider, "_hash", counting)
    patterns = ["decision-logs/*.jsonl", "controls.json", "pentest-evidence/**/*.json"]
    provider = LocalDirectoryProvider(tmp_path, include=patterns)
    head = provider.resolve_head()
    assert sorted(hashed) == ["controls.json", "decision-logs/a.jsonl", "pentest-evidence/layer1/scan.json"]
    (tmp_path / "unrelated" / "deep" / "f1.txt").write_text("changed")
    assert provider.resolve_head() == head  # unmapped changes do not move the head
    assert LocalDirectoryProvider.walk_plan(["*.json", "**/x.md"]) == [("", True)]
    assert LocalDirectoryProvider.walk_plan(["*.json"]) == [("", False)]


# --------------------------------------------------------------------------
# 4. UX
# --------------------------------------------------------------------------

def test_db_check_role_unsafe_line_on_stdout_logs_only_on_stderr(migrated_pg_url, tmp_path):
    result = _production_cli(migrated_pg_url, "db-check-role", tmp_path=tmp_path)
    # The owner is not a safe serving role; the line says so explicitly.
    assert result.returncode == 1 and result.stdout.startswith("UNSAFE: role ")
    assert len(result.stdout.splitlines()) == 1 and "Unsafe serving role" not in result.stdout
    assert "Unsafe serving role" in result.stderr and result.stderr.lstrip().startswith("{")  # JSON logs


def test_db_check_role_prints_ok_for_the_app_role(migrated_pg_url, tmp_path):
    import uuid

    from sqlalchemy.engine import make_url

    from cli.db_cmd import provision_app_role

    url = make_url(migrated_pg_url).set(username=f"tpa_{uuid.uuid4().hex[:8]}", password="p" + uuid.uuid4().hex)
    rendered = url.render_as_string(hide_password=False)
    assert provision_app_role(migrated_pg_url, rendered) is True
    result = _production_cli(rendered, "db-check-role", tmp_path=tmp_path)
    assert result.returncode == 0, result.stderr[-2000:]
    assert result.stdout.strip() == f"OK: role {url.username} is safe to serve requests"


def test_dashboard_always_shows_the_witness_state(pg_app, monkeypatch):
    from app.services import team_service
    from tests.conftest import login

    monkeypatch.setenv("AUDIT_WITNESS_BUCKET", "witness")
    admin = team_service.create_member("Admin", "a@example.com", "human", is_compliance_admin=True)
    client = pg_app.test_client()
    login(client, admin)
    page = client.get("/admin/").get_data(as_text=True)
    assert 'id="witness-state"' in page and "<strong>unarmed</strong>" in page


# --------------------------------------------------------------------------
# 5. Pentest rebuild
# --------------------------------------------------------------------------

def test_pentest_rebuild_is_counted_and_reported(pg_app):
    from app.services.evidence_import import import_dataset_file
    from app.services.git_sources.sync import SyncTally
    from tests.test_evidence_import import L1_PATH, SCAN_L1

    assert import_dataset_file("pentest-findings", L1_PATH, SCAN_L1).created == 3   # restored, no namespace
    db.session.commit()
    counts = import_dataset_file("pentest-findings", L1_PATH, SCAN_L1, namespace="source-1")
    db.session.commit()
    assert (counts.retired, counts.deleted, counts.created) == (3, 3, 3)
    tally = SyncTally()
    tally.rebuild["retired"] += counts.retired
    tally.rebuild["created"] += counts.created
    assert tally.details()["pentest_rebuild"]["note"] == (
        "pentest rebuild: 3 retired (old ID scheme, stored without a git-source namespace), 3 created")
    again = import_dataset_file("pentest-findings", L1_PATH, SCAN_L1, namespace="source-1")
    assert again.retired == 0 and "pentest_rebuild" not in SyncTally().details()
