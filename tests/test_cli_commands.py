"""CLI commands: ``python -m cli`` dispatch, ``git-source``, the admin commands
(create-admin, audit-verify, audit-anchor, run-jobs), ``scaffold`` and the
database lifecycle commands (db-wait, db-migrate).

Commands that open the portal database call ``create_app()`` without a config
class, so they are configured from the environment (``PORTAL_ENV=test``,
``DATABASE_URL`` = a migrated PostgreSQL database); the ``pg_app`` fixture
reads back what they wrote.
"""

import argparse
import base64
import hashlib
import hmac
import io
import json
import logging
import os
import re
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from cryptography.fernet import Fernet
from sqlalchemy import create_engine, text
from sqlalchemy.engine import URL, make_url

from app import create_app, runtime_config
from app.config import TestConfig
from app.models import CollectorConfig, CollectorRun, Policy, TeamMember, db
from app.models.git_source import GitSource, GitSourceFile, GitSyncRun
from app.models.team_member import hash_api_key
from app.services import scheduler
from app.services.collector_encryption import decrypt_credentials
from app.services.evidence_import import import_directory
from app.services.git_sources import service
from cli import __main__ as cli_main
from cli import admin_cmd, db_cmd, git_source_cmd, scaffold_cmd

ENV_TO_CLEAR = (
    "PORTAL_SECRET_ID", "SECRET_KEY", "DATABASE_URL", "DATABASE_HOST", "DATABASE_PORT", "DATABASE_NAME",
    "DATABASE_USER", "DATABASE_PASSWORD", "DATABASE_SSLMODE", "DATABASE_OWNER_URL", "DATABASE_OWNER_USER",
    "DATABASE_OWNER_PASSWORD", "COLLECTOR_ENCRYPTION_KEYS", "COLLECTOR_ENCRYPTION_KEY", "GITHUB_TOKEN",
    "CLOUDWATCH_LOG_GROUP", "AWS_RUNTIME_ROLE_ARN", "BOOTSTRAP_TOKEN",
)
HEX64 = "c" * 64


@pytest.fixture(autouse=True)
def _restore_logging(monkeypatch):
    """CLI commands configure process-wide logging; undo it after each test."""
    from app import logging_config

    root = logging.getLogger()
    handlers, level = root.handlers[:], root.level
    noisy = {name: logging.getLogger(name).level for name in logging_config._NO_SHIP_PREFIXES}
    monkeypatch.setattr(logging_config, "_configured_pid", logging_config._configured_pid)
    yield
    root.handlers[:] = handlers
    root.setLevel(level)
    for name, noisy_level in noisy.items():
        logging.getLogger(name).setLevel(noisy_level)


@pytest.fixture
def clean_env(monkeypatch):
    for name in ENV_TO_CLEAR:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("PORTAL_ENV", "test")
    runtime_config._reset_for_tests()
    yield monkeypatch
    runtime_config._reset_for_tests()


@pytest.fixture
def cli_db(clean_env, migrated_pg_url):
    """Environment for commands that open the (migrated) portal database."""
    clean_env.setenv("DATABASE_URL", migrated_pg_url)
    return migrated_pg_url


def invoke(module, argv):
    """Parse ``argv`` with the real parser and run ``module``; returns (code, output)."""
    args = cli_main.build_parser().parse_args(argv)
    out = io.StringIO()
    code = module.run(args, out=out)
    return code, out.getvalue()


def refreshed(model, **filters):
    db.session.expire_all()
    return model.query.filter_by(**filters).one()


@pytest.fixture
def gov_dir(tmp_path):
    root = tmp_path / "governance"
    (root / "policies").mkdir(parents=True)
    (root / "policies" / "access.md").write_text("# Access\n\nReviewed quarterly.\n")
    (root / "CLAUDE.md").write_text("# Agents\n")
    return root


# --------------------------------------------------------------------------
# python -m cli dispatch
# --------------------------------------------------------------------------

def test_main_without_command_prints_help(capsys):
    assert cli_main.main([]) == 1


def test_main_dispatches_init_export_and_import(tmp_path):
    with patch("cli.init.run") as init_run:
        assert cli_main.main(["init", "--data-dir", str(tmp_path), "--dry-run", "-v"]) == 0
    init_run.assert_called_once_with(str(tmp_path), dry_run=True, verbose=True)

    with patch("cli.export.export_all") as export_all, patch("cli.export.git_commit_and_push") as push:
        assert cli_main.main(["export", "--output-dir", str(tmp_path)]) == 0
        export_all.assert_called_once_with(str(tmp_path), include_audit_log=False)
        push.assert_not_called()
        assert cli_main.main(["export", "--output-dir", str(tmp_path), "--git-commit",
                              "--include-audit-log"]) == 0
        push.assert_called_once_with(str(tmp_path), push=False)
        assert export_all.call_args.kwargs == {"include_audit_log": True}
        assert cli_main.main(["export", "--output-dir", str(tmp_path), "--git-push"]) == 0
        assert push.call_args.kwargs == {"push": True}

    with patch("cli.import_cmd.run", return_value=7) as import_run:
        assert cli_main.main(["import", "--data-dir", str(tmp_path), "--json"]) == 7
    assert import_run.call_args.args[0].data_dir == str(tmp_path)


def test_main_dispatches_database_backed_commands(cli_db, pg_app, gov_dir, tmp_path):
    assert cli_main.main(["create-admin", "--name", "Ops", "--email", "ops@example.com",
                          "--key-file", str(tmp_path / "ops.key")]) == 0
    assert cli_main.main(["git-source", "add", "--name", "gov", "--role", "governance", "--provider", "local",
                          "--repository", str(gov_dir)]) == 0
    assert cli_main.main(["git-source", "list"]) == 0
    assert cli_main.main(["run-jobs"]) == 0
    assert cli_main.main(["db-wait", "--timeout", "5"]) == 0
    assert cli_main.main(["scaffold", "--governance-dir", str(tmp_path / "g"),
                          "--evidence-dir", str(tmp_path / "e"), "--company", "Example Ltd"]) == 0
    assert refreshed(TeamMember, email="ops@example.com").is_compliance_admin is True
    assert refreshed(GitSource, name="gov").repository == str(gov_dir)
    assert (tmp_path / "g" / "CLAUDE.md").is_file()


# --------------------------------------------------------------------------
# git-source
# --------------------------------------------------------------------------

def add_args(name, repository, *extra, role="governance", provider="local"):
    return ["git-source", "add", "--name", name, "--role", role, "--provider", provider,
            "--repository", str(repository), *extra]


def test_git_source_add_list_and_update(cli_db, pg_app, gov_dir, tmp_path):
    mappings_file = tmp_path / "mappings.json"
    mappings_file.write_text(json.dumps([{"pattern": "docs/*.md", "kind": "policy"}]))

    code, out = invoke(git_source_cmd, add_args("gov", gov_dir, "--branch", "trunk", "--schedule",
                                                "*/15 * * * *", "--history-limit", "20",
                                                "--no-record-commits"))
    assert code == 0
    source = refreshed(GitSource, name="gov")
    assert out == f"Created git source gov ({source.id}).\n"
    assert source.branch == "trunk"
    assert source.schedule_cron == "*/15 * * * *"
    assert source.options == {"record_commits": False, "history_limit": 20}
    assert source.enabled is True

    code, _ = invoke(git_source_cmd, add_args("ev", tmp_path, "--disabled", "--mappings-file",
                                              str(mappings_file), role="evidence"))
    assert code == 0
    evidence = refreshed(GitSource, name="ev")
    assert evidence.enabled is False
    assert evidence.path_mappings == [{"pattern": "docs/*.md", "kind": "policy"}]

    code, out = invoke(git_source_cmd, ["git-source", "list"])
    assert code == 0
    lines = out.splitlines()
    assert len(lines) == 2
    assert lines[0].startswith("ev ") and "evidence" in lines[0] and "last=- status=-" in lines[0]
    assert lines[1].startswith("gov ") and f"{gov_dir} @trunk" in lines[1]

    code, out = invoke(git_source_cmd, ["git-source", "list", "--json"])
    listed = json.loads(out)
    assert [s["name"] for s in listed] == ["ev", "gov"]
    assert "encrypted_credentials" not in listed[0]

    code, out = invoke(git_source_cmd, ["git-source", "update", "--name", "gov", "--branch", "main",
                                        "--schedule", "", "--disabled"])
    assert (code, out) == (0, "Updated git source gov.\n")
    source = refreshed(GitSource, name="gov")
    assert source.branch == "main" and source.schedule_cron is None and source.enabled is False
    assert source.name == "gov" and source.role == "governance"

    code, _ = invoke(git_source_cmd, ["git-source", "update", "--name", "gov", "--enabled"])
    assert code == 0 and refreshed(GitSource, name="gov").enabled is True


def test_git_source_update_keeps_unmentioned_options(cli_db, pg_app, gov_dir):
    """``update`` changes only the options it is given: ``--record-commits``
    alone must not reset a configured ``--history-limit``."""
    invoke(git_source_cmd, add_args("gov", gov_dir, "--history-limit", "20"))
    code, _ = invoke(git_source_cmd, ["git-source", "update", "--name", "gov", "--no-record-commits"])
    assert code == 0
    assert service.effective_options(refreshed(GitSource, name="gov")) == {
        "record_commits": False, "history_limit": 20}


def test_git_source_errors_return_2(cli_db, pg_app, gov_dir):
    assert invoke(git_source_cmd, add_args("gov", gov_dir))[0] == 0
    code, out = invoke(git_source_cmd, add_args("gov", gov_dir))
    assert code == 2 and out == "error: a git source named 'gov' already exists\n"
    code, out = invoke(git_source_cmd, add_args("bad name", gov_dir))
    assert code == 2 and out.startswith("error: name must be")
    code, out = invoke(git_source_cmd, ["git-source", "update", "--name", "gov", "--schedule", "sometimes"])
    assert code == 2 and out == "error: invalid cron expression: sometimes\n"
    for action in (["update", "--name", "nope", "--branch", "x"], ["set-commit", "--name", "nope", "--commit",
                   "a" * 40], ["sync", "--name", "nope"]):
        code, out = invoke(git_source_cmd, ["git-source", *action])
        assert code == 2 and out == "error: no git source named 'nope'\n"
    code, out = invoke(git_source_cmd, ["git-source", "set-commit", "--name", "gov", "--commit", "abc"])
    assert code == 2 and "full commit SHA" in out
    assert refreshed(GitSource, name="gov").schedule_cron is None


def test_git_source_credentials_options(cli_db, pg_app, clean_env):
    clean_env.setenv("COLLECTOR_ENCRYPTION_KEYS", Fernet.generate_key().decode())
    clean_env.setenv("GH_TOKEN_FOR_TEST", "ghp_from_cli_env")
    code, out = invoke(git_source_cmd, add_args("gh", "octo/repo", "--credential-mode", "stored_token",
                                                "--token-env", "GH_TOKEN_FOR_TEST", provider="github"))
    assert code == 0 and "ghp_from_cli_env" not in out
    assert decrypt_credentials(refreshed(GitSource, name="gh").encrypted_credentials) == {
        "token": "ghp_from_cli_env"}

    role_arn = "arn:aws:iam::123456789012:role/reader"
    code, _ = invoke(git_source_cmd, add_args("cc", "governance", "--credential-mode", "assume_role",
                                              "--role-arn", role_arn, "--external-id", "ext-9",
                                              "--region", "ca-central-1", provider="codecommit"))
    assert code == 0
    codecommit = refreshed(GitSource, name="cc")
    assert codecommit.region == "ca-central-1"
    assert decrypt_credentials(codecommit.encrypted_credentials) == {"role_arn": role_arn, "external_id": "ext-9"}

    clean_env.setenv("EMPTY_TOKEN_FOR_TEST", "")
    with pytest.raises(SystemExit, match="EMPTY_TOKEN_FOR_TEST is empty"):
        invoke(git_source_cmd, add_args("gh2", "octo/repo", "--credential-mode", "stored_token",
                                        "--token-env", "EMPTY_TOKEN_FOR_TEST", provider="github"))


def test_git_source_set_commit(cli_db, pg_app, gov_dir):
    invoke(git_source_cmd, add_args("gov", gov_dir))
    commit = "ab" * 20
    code, out = invoke(git_source_cmd, ["git-source", "set-commit", "--name", "gov", "--commit", commit.upper()])
    assert (code, out) == (0, f"gov: last synced commit set to {commit}.\n")
    assert refreshed(GitSource, name="gov").last_synced_commit == commit


def test_git_source_sync_runs_in_process(cli_db, pg_app, gov_dir):
    invoke(git_source_cmd, add_args("gov", gov_dir))
    code, out = invoke(git_source_cmd, ["git-source", "sync", "--name", "gov"])
    assert code == 0
    run = json.loads(out)
    assert run["status"] == "success"
    assert run["trigger_type"] == "manual"
    assert run["counts"]["created"] == 2
    source = refreshed(GitSource, name="gov")
    assert source.last_synced_commit == run["to_commit"]
    assert {f.path for f in GitSourceFile.query.filter_by(source_id=source.id)} == {"policies/access.md",
                                                                                    "CLAUDE.md"}

    code, out = invoke(git_source_cmd, ["git-source", "sync", "--name", "gov"])
    assert code == 0 and json.loads(out)["status"] == "unchanged"

    code, out = invoke(git_source_cmd, ["git-source", "sync", "--name", "gov", "--full"])
    full = json.loads(out)
    assert code == 0 and full["status"] == "success"
    assert full["details"]["strategy"] == "full" and full["counts"]["unchanged"] == 2

    code, out = invoke(git_source_cmd, ["git-source", "sync", "--name", "gov", "--no-wait"])
    queued = refreshed(GitSyncRun, source_id=source.id, status="queued")
    assert (code, out) == (0, f"Queued sync run {queued.id}.\n")
    code, out = invoke(git_source_cmd, ["git-source", "sync", "--name", "gov"])
    assert (code, out) == (1, f"A sync is already queued (run {queued.id}).\n")


def test_git_source_sync_failure_returns_1(cli_db, pg_app, tmp_path):
    invoke(git_source_cmd, add_args("gone", tmp_path / "missing"))
    code, out = invoke(git_source_cmd, ["git-source", "sync", "--name", "gone"])
    assert code == 1
    run = json.loads(out)
    assert run["status"] == "failure" and "not a directory" in run["error_message"]


def test_git_source_unknown_action_raises(cli_db, pg_app, gov_dir):
    invoke(git_source_cmd, add_args("gov", gov_dir))
    with pytest.raises(ValueError, match="unknown action"):
        git_source_cmd.run(SimpleNamespace(action="explode", name="gov"), out=io.StringIO())


# --------------------------------------------------------------------------
# create-admin, audit-verify, audit-anchor, run-jobs
# --------------------------------------------------------------------------

def test_create_admin_writes_the_key_only_to_its_file(cli_db, pg_app, tmp_path):
    key_file = tmp_path / "ops.key"
    code, out = invoke(admin_cmd, ["create-admin", "--name", "Ops Admin", "--email", "ops@example.com",
                                   "--key-file", str(key_file)])
    assert code == 0
    member = refreshed(TeamMember, email="ops@example.com")
    key = key_file.read_text().strip()
    assert out == (f"Created compliance admin Ops Admin ({member.id}); its API key (stored only as a hash) "
                   f"is in {key_file} (mode 0600).\n")
    assert key not in out and oct(key_file.stat().st_mode & 0o777) == "0o600"
    assert member.api_key_hash == hash_api_key(key) and member.api_key_hash not in out
    assert member.is_compliance_admin is True and member.role == "human"
    headers = {"X-API-Key": key}
    assert pg_app.test_client().get("/api/git-sources", headers=headers).status_code == 200


def test_audit_anchor_then_verify(cli_db, pg_app, tmp_path):
    """An anchored chain verifies as intact but ``unverified`` (exit 4) without the
    witness bucket; the full archive -> anchor -> verify sequence against S3 is in
    tests/test_audit_archive_pg.py."""
    from app.services.audit_chain import insert_anchor

    code, out = invoke(admin_cmd, ["audit-anchor", "--manifest", "archives/x/y.manifest.json"])
    assert code == 2 and out.startswith("error: audit-anchor needs --bucket")
    anchor_id = insert_anchor(db.session, archive_id="archive-1", archive_sha256="B" * 64,
                              archived_chain_head=HEX64, archived_entries=42,
                              manifest_key="archives/x/archive-1.manifest.json", manifest_sha256="d" * 64,
                              note="cutover")
    db.session.commit()
    invoke(admin_cmd, ["create-admin", "--name", "Ops", "--email", "ops@example.com",
                       "--key-file", str(tmp_path / "ops.key")])

    code, out = invoke(admin_cmd, ["audit-verify"])
    assert code == 4
    first, anchor_line, checked = out.splitlines()[:3]
    assert first.startswith("status=unverified verified=") and "true_breaks=0" in first
    anchor = json.loads(anchor_line.split("=", 1)[1])
    assert anchor["id"] == anchor_id and anchor["archived_entries"] == 42
    assert anchor["archive_sha256"] == "b" * 64
    assert anchor["archive_manifest_key"] == "archives/x/archive-1.manifest.json"
    assert checked == "anchor_verification=unverified"

    code, out = invoke(admin_cmd, ["audit-verify", "--json"])
    result = json.loads(out)
    assert code == 4 and result["status"] == "unverified" and result["complete"] is True

    code, out = invoke(admin_cmd, ["audit-verify", "--json", "--max-rows", "1"])
    assert code == 4 and json.loads(out)["verified"] == 1 and json.loads(out)["complete"] is False


def test_audit_verify_empty_and_broken_chain(cli_db, pg_app, tmp_path):
    code, out = invoke(admin_cmd, ["audit-verify"])
    assert code == 0 and out.startswith("status=empty")

    invoke(admin_cmd, ["create-admin", "--name", "One", "--email", "one@example.com",
                       "--key-file", str(tmp_path / "one.key")])
    invoke(admin_cmd, ["create-admin", "--name", "Two", "--email", "two@example.com",
                       "--key-file", str(tmp_path / "two.key")])
    ids = [row[0] for row in db.session.execute(text("SELECT id FROM audit_log ORDER BY id"))]
    assert len(ids) >= 2
    db.session.execute(text("ALTER TABLE audit_log DISABLE TRIGGER audit_log_append_only"))
    db.session.execute(text("UPDATE audit_log SET changed_by = 'forged' WHERE id = :i"), {"i": ids[0]})
    db.session.execute(text("ALTER TABLE audit_log ENABLE TRIGGER audit_log_append_only"))
    db.session.commit()

    code, out = invoke(admin_cmd, ["audit-verify"])
    assert code == 1
    assert out.startswith("status=broken")
    first_break = json.loads(out.splitlines()[1].split("=", 1)[1])
    assert first_break["id"] == ids[0]


def test_run_jobs_executes_queued_runs_and_reaps_stuck_ones(cli_db, pg_app, gov_dir):
    config = CollectorConfig(id=str(uuid.uuid4()), name="policy", enabled=True, credential_mode="none")
    db.session.add(config)
    db.session.commit()
    collector_run, _ = scheduler.enqueue_collector_run(config, "manual")
    source = service.create_source({"name": "gov", "role": "governance", "provider": "local",
                                    "repository": str(gov_dir)})
    sync_run, _ = scheduler.enqueue_git_sync(source, "manual")
    stuck_source = service.create_source({"name": "stuck", "role": "governance", "provider": "local",
                                          "repository": str(gov_dir)})
    stuck = GitSyncRun(id=str(uuid.uuid4()), source_id=stuck_source.id, status="running",
                       started_at=datetime.now(timezone.utc) - timedelta(hours=1))
    db.session.add(stuck)
    db.session.commit()
    collector_run_id, sync_run_id, stuck_id = collector_run.id, sync_run.id, stuck.id

    executed = []

    def fake_execute(run):
        executed.append(run.id)
        run.status = "success"
        run.finished_at = datetime.now(timezone.utc)
        db.session.commit()

    with patch("app.services.collector_executor.execute_run", side_effect=fake_execute):
        code, out = invoke(admin_cmd, ["run-jobs"])
    assert code == 0
    assert out == "Executed 2 queued run(s); reaped 1 interrupted run(s).\n"
    assert executed == [collector_run_id]
    db.session.expire_all()
    assert db.session.get(CollectorRun, collector_run_id).status == "success"
    assert db.session.get(GitSyncRun, sync_run_id).status == "success"
    reaped = db.session.get(GitSyncRun, stuck_id)
    assert reaped.status == "failure" and "Interrupted" in reaped.error_message


def test_admin_unknown_command_raises(cli_db, pg_app):
    with pytest.raises(ValueError, match="Unknown command"):
        admin_cmd.run(argparse.Namespace(command="nope"), out=io.StringIO())


# --------------------------------------------------------------------------
# scaffold
# --------------------------------------------------------------------------

TEMPLATES = sorted(name for name in os.listdir(scaffold_cmd.POLICY_TEMPLATES) if name.endswith(".md"))


def test_scaffold_creates_both_repositories(tmp_path):
    governance, evidence = tmp_path / "gov", tmp_path / "ev"
    code, out = invoke(scaffold_cmd, ["scaffold", "--governance-dir", str(governance), "--evidence-dir",
                                      str(evidence), "--company", "Example Holdings Ltd"])
    assert code == 0
    written = int(re.match(r"Wrote (\d+) file\(s\)\.", out).group(1))
    assert "git-source add" in out
    assert TEMPLATES

    templates = Path(scaffold_cmd.POLICY_TEMPLATES)
    for name in TEMPLATES:
        assert (governance / "policies" / name).read_text() == (templates / name).read_text(encoding="utf-8")
    year = str(datetime.now(timezone.utc).year)
    for doc in ("CLAUDE.md", "AGENTS.md"):
        text_ = (governance / doc).read_text()
        assert "{{ LEGAL_ENTITY }}" not in text_ and "{{ YEAR }}" not in text_
        assert f"Copyright {year} Example Holdings Ltd - All rights reserved." in text_
    assert "Example Holdings Ltd" in (governance / "README.md").read_text()
    assert (governance / "infrastructure" / "README.md").is_file()
    assert (governance / "agent-config" / "README.md").is_file()

    assert json.loads((evidence / ".evidence-repo.json").read_text()) == scaffold_cmd.EVIDENCE_REPO_FORMAT
    for name in ("controls.json", "systems.json", "tests.json", "vendors.json", "risk-register.json"):
        assert json.loads((evidence / name).read_text()) == []
    assert (evidence / "evidence" / "artifacts" / "decisions" / ".gitkeep").is_file()
    # The machine-produced kinds go to the evidence store: the repository has no place for them.
    for absent in ("evidence/evidence-index.json", "pentest-evidence", "decision-logs"):
        assert not (evidence / absent).exists()
    created = sorted(str(path.relative_to(evidence)) for path in evidence.rglob("*") if path.is_file())
    assert created == [".evidence-repo.json", "README.md", "controls.json", "evidence/artifacts/decisions/.gitkeep",
                       "policy-index.json", "risk-register.json", "systems.json", "tests.json", "vendors.json"]
    readme = (evidence / "README.md").read_text()
    assert "Example Holdings Ltd" in readme and "evidence store" in readme

    index = json.loads((evidence / "policy-index.json").read_text())
    assert [entry["file_path"] for entry in index] == [f"policies/{name}" for name in TEMPLATES]
    for entry, name in zip(index, TEMPLATES):
        assert entry["id"] == str(uuid.uuid5(scaffold_cmd.POLICY_NAMESPACE, name))
        assert entry["status"] == "draft" and entry["version"] == "1.0"
        assert entry["soc2_control_ids"] == []
        assert entry["title"] and entry["category"]
        assert (governance / entry["file_path"]).is_file()
    # governance: policies + CLAUDE/AGENTS/README + 2 section READMEs; evidence: format marker,
    # 5 datasets, policy index, the decisions .gitkeep marker, README
    assert written == len(TEMPLATES) + 5 + (1 + 5 + 1 + 1 + 1)


def test_scaffold_does_not_overwrite_without_force(tmp_path):
    governance, evidence = str(tmp_path / "gov"), str(tmp_path / "ev")
    scaffold_cmd.scaffold(governance, evidence, "Example Ltd")
    policy = tmp_path / "gov" / "policies" / TEMPLATES[0]
    policy.write_text("# Customised\n")
    (tmp_path / "ev" / "controls.json").write_text('[{"id": "c1"}]')

    assert scaffold_cmd.scaffold(governance, evidence, "Other Name") == []
    assert policy.read_text() == "# Customised\n"
    assert "Example Ltd" in (tmp_path / "gov" / "README.md").read_text()

    rewritten = scaffold_cmd.scaffold(governance, evidence, "Other Name", force=True)
    assert str(policy) in rewritten
    assert policy.read_text() != "# Customised\n"
    assert json.loads((tmp_path / "ev" / "controls.json").read_text()) == []
    assert "Other Name" in (tmp_path / "gov" / "README.md").read_text()
    assert not any(path.endswith(".gitkeep") for path in rewritten)  # markers are only created once


def test_policy_title_and_category_parsing():
    assert scaffold_cmd._policy_title_and_category(
        "# Vendor Policy\n\n**Category:** Processing Integrity\n", "v.md") == ("Vendor Policy", "processing_integrity")
    assert scaffold_cmd._policy_title_and_category("no heading", "x.md") == ("x.md", "security")


@pytest.fixture
def sqlite_app():
    app = create_app(TestConfig)
    with app.app_context():
        db.create_all()
        yield app
        db.session.remove()
        db.drop_all()


def test_scaffolded_repositories_import_sync_and_render(sqlite_app, tmp_path):
    governance, evidence = tmp_path / "gov", tmp_path / "ev"
    scaffold_cmd.scaffold(str(governance), str(evidence), "Example Ltd")

    result = import_directory(str(evidence))
    assert result["errors"] == []
    assert result["failed_files"] == 0
    assert result["datasets"]["policies"]["created"] == len(TEMPLATES)
    assert Policy.query.count() == len(TEMPLATES)

    source = service.create_source({"name": "governance", "role": "governance", "provider": "local",
                                    "repository": str(governance)})
    run, _ = scheduler.enqueue_git_sync(source, "manual")
    scheduler.execute_claimed("git_sync", run.id)
    db.session.expire_all()
    run = db.session.get(GitSyncRun, run.id)
    assert run.status == "success", run.details
    assert run.counts["created"] == len(TEMPLATES) + 5
    assert run.counts["errors"] == 0

    client = sqlite_app.test_client()
    for policy in Policy.query.all():
        assert client.get(f"/policies/{policy.id}").status_code == 404  # drafts are not public
        policy.status = "approved"
    db.session.commit()
    for policy in Policy.query.all():
        html = client.get(f"/policies/{policy.id}").get_data(as_text=True)
        assert "not available for online viewing" not in html, policy.file_path
        assert f"<code>{policy.file_path}</code>" in html
        assert "<strong>This is a template.</strong>" in html


# --------------------------------------------------------------------------
# db-wait, db-migrate, SCRAM verifiers
# --------------------------------------------------------------------------

VERIFIER = re.compile(r"^SCRAM-SHA-256\$(\d+):([A-Za-z0-9+/=]+)\$([A-Za-z0-9+/=]+):([A-Za-z0-9+/=]+)$")


def test_scram_verifier_format_and_determinism():
    salt = bytes(range(16))
    first = db_cmd.scram_sha256_verifier("s3cret-pass", salt=salt)
    assert first == db_cmd.scram_sha256_verifier("s3cret-pass", salt=salt)
    match = VERIFIER.match(first)
    assert match and match.group(1) == "4096"
    assert base64.b64decode(match.group(2)) == salt
    assert len(base64.b64decode(match.group(3))) == 32 and len(base64.b64decode(match.group(4))) == 32

    salted = hashlib.pbkdf2_hmac("sha256", b"s3cret-pass", salt, 4096)
    client_key = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    assert base64.b64decode(match.group(3)) == hashlib.sha256(client_key).digest()
    assert base64.b64decode(match.group(4)) == hmac.new(salted, b"Server Key", hashlib.sha256).digest()

    assert db_cmd.scram_sha256_verifier("other", salt=salt) != first
    assert db_cmd.scram_sha256_verifier("s3cret-pass", salt=b"x" * 16) != first
    assert db_cmd.scram_sha256_verifier("p", salt=salt, iterations=10).startswith("SCRAM-SHA-256$10:")
    random_a, random_b = db_cmd.scram_sha256_verifier("p"), db_cmd.scram_sha256_verifier("p")
    assert random_a != random_b
    assert len(base64.b64decode(VERIFIER.match(random_a).group(2))) == 16


def test_wait_for_database_success(pg_url):
    slept = []
    assert db_cmd.wait_for_database(timeout=5, url=pg_url, sleep=slept.append) is True
    assert slept == []


class FakeClock:
    def __init__(self):
        self.now = 1000.0
        self.sleeps = []

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.sleeps.append(seconds)
        self.now += seconds


def test_wait_for_database_times_out(monkeypatch):
    clock = FakeClock()
    monkeypatch.setattr(db_cmd, "time", clock)
    unreachable = "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=1"
    assert db_cmd.wait_for_database(timeout=5, url=unreachable, sleep=clock.sleep) is False
    assert clock.sleeps == [2, 2, 2]


def test_run_db_wait_uses_the_environment(clean_env, pg_url, monkeypatch):
    clean_env.setenv("DATABASE_URL", pg_url)
    assert db_cmd.run(argparse.Namespace(command="db-wait", timeout=1)) == 0
    clean_env.setenv("DATABASE_URL", "postgresql://nobody:nothing@127.0.0.1:1/none?connect_timeout=1")
    assert db_cmd.run(argparse.Namespace(command="db-wait", timeout=0)) == 1


def test_run_db_migrate_single_role(clean_env, pg_url):
    clean_env.setenv("DATABASE_URL", pg_url)
    assert db_cmd.run(argparse.Namespace(command="db-migrate")) == 0
    engine = create_engine(pg_url)
    try:
        with engine.connect() as conn:
            assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar()
            assert conn.execute(text("SELECT to_regclass('git_sources')")).scalar() == "git_sources"
    finally:
        engine.dispose()


def _drop_role(url, role):
    """Roles created by the test database's owner are dropped by the pg_url fixture."""
    return None


def test_run_db_migrate_provisions_the_app_role(clean_env, pg_url):
    """With an owner URL the migration runs as the owner, then the app role is
    created with a SCRAM verifier that PostgreSQL accepts for its password."""
    role = f"tp_app_{uuid.uuid4().hex[:8]}"
    password = "App-Pass-" + uuid.uuid4().hex[:8]
    app_url = make_url(pg_url).set(username=role, password=password).render_as_string(hide_password=False)
    clean_env.setenv("DATABASE_OWNER_URL", pg_url)
    clean_env.setenv("DATABASE_URL", app_url)
    try:
        assert db_cmd.run(argparse.Namespace(command="db-migrate")) == 0
        engine = create_engine(app_url)
        try:
            with engine.connect() as conn:
                assert conn.execute(text("SELECT current_user")).scalar() == role
                assert conn.execute(text("SELECT count(*) FROM git_sources")).scalar() == 0
                with pytest.raises(Exception, match="permission denied"):
                    conn.execute(text("DELETE FROM audit_log"))
        finally:
            engine.dispose()
        wrong = make_url(app_url).set(password="wrong-password").render_as_string(hide_password=False)
        engine = create_engine(wrong)
        try:
            with pytest.raises(Exception, match="password authentication failed"):
                engine.connect()
        finally:
            engine.dispose()
    finally:
        _drop_role(pg_url, role)


def _url_as(url, username, password):
    parts = make_url(url)
    return URL.create(parts.drivername, username=username, password=password, host=parts.host,
                      port=parts.port, database=parts.database).render_as_string(hide_password=False)


def test_provision_app_role_guards(pg_url):
    assert db_cmd.provision_app_role(pg_url, pg_url) is False
    same_user = _url_as(pg_url, make_url(pg_url).username, "different-password")
    assert db_cmd.provision_app_role(pg_url, same_user) is False
    assert db_cmd.provision_app_role(pg_url, _url_as(pg_url, None, None)) is False
    role = f"tp_nopass_{uuid.uuid4().hex[:8]}"
    try:
        with pytest.raises(RuntimeError, match="needs a password"):
            db_cmd.provision_app_role(pg_url, _url_as(pg_url, role, None))
    finally:
        _drop_role(pg_url, role)
