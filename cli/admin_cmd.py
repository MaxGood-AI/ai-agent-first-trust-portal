"""Administrative commands for operators with shell access.

``python -m cli create-admin --name NAME --email EMAIL --key-file PATH``
    Create a compliance admin; its API key is written ONLY to ``PATH``.
``python -m cli regenerate-key --member ID_OR_EMAIL --key-file PATH``
    Issue a new API key for an existing member, written ONLY to ``PATH``;
    the previous key stops working. Used to re-key members after migration 017.

A key file is created with mode 0600 and never overwritten; a path inside a
git working tree is refused. Nothing a command prints (stdout) or logs
(stderr, for every command) contains a key.
``python -m cli audit-verify [--max-rows N] [--json] [WITNESS]``
    WITNESS is ``--witness-s3 [--bucket B] [--rehash-archive]`` or
    ``--witness-file PATH``.
    Recompute every audit-log hash and report the chain status; with a
    witness, also check every published chain head against the database.
    ``--witness-s3`` also checks the anchor against its archive manifest
    (``--rehash-archive`` streams the archive and recomputes its SHA-256).
    ``--decision-logs`` also checks every session's stored decision-log
    entries against the digest its audited transcript version recorded
    (``app.services.decision_log_verify``).
    Exit status: 0 valid or empty, 3 intact with forks, 4 unverified (intact,
    but the anchor was not checked: no ``--witness-s3``), 1 broken, 2 usage or
    the witness bucket cannot be listed.
``python -m cli audit-archive-manifest --dump PATH --name NAME [--archive-key KEY] [--bucket B]``
    Archive the audit chain of the database ``DATABASE_*`` points at (every
    writer stopped): hash the dump while streaming it, upload it to
    ``archives/<chain id>/<NAME>`` (or pin an object already under
    ``archives/`` with ``--archive-key``), publish the chain's final head and
    write ``archives/<chain id>/<NAME>.manifest.json``. Uses the operator's
    own AWS credentials (the runtime role cannot write ``archives/``). Exit
    2 when ``AUDIT_WITNESS_DISABLED`` is set or no bucket is known.
``python -m cli audit-anchor --manifest KEY [--bucket B] [--note TEXT]``
    Start an empty audit log from an archive manifest (first row = ANCHOR):
    the manifest must verify (archive present with its size, final head
    published) before anything is inserted. Runs as the database owner
    (``DATABASE_OWNER_*`` in the environment; the anchor function is not
    executable by the application role), reads the manifest with the
    operator's AWS credentials, arms the witness, then publishes the new
    chain head.
``python -m cli audit-verify-archive --dump FILE --scratch-url URL [--manifest KEY] [--bucket B] [--keep] [--json]``
    Auditor/operator check of what an archive dump CONTAINS
    (``app.services.audit_archive_dump``): hashes the whole pg_dump
    custom-format file, streams only its ``audit_log`` data into a scratch
    schema of the database at ``--scratch-url`` (dropped afterwards unless
    ``--keep``), verifies that chain, checks it against every head the
    witness published for its chain id, and against the manifest's SHA-256,
    size, chain id, final row and row count. Needs no portal configuration.
    Exit 0 verified, 1 a finding, 4 not checked against the witness or a
    manifest (``--bucket`` / ``--manifest`` missing), 2 usage or unreadable
    dump.
``python -m cli audit-witness-arm [--note TEXT]``
    Arm the audit witness (owner role, ``DATABASE_OWNER_*``; audited): chain
    heads are published only once it is armed. Publishes the head right away
    when ``AUDIT_WITNESS_BUCKET`` is set.
``python -m cli audit-publish-head``
    Publish the current chain head to ``AUDIT_WITNESS_BUCKET`` now (exit 2
    when the witness is disabled, unconfigured or not armed).
``python -m cli run-jobs``
    Execute every queued collector run and git-source sync now, in this
    process (useful where no gunicorn worker runs the scheduler).
"""

from __future__ import annotations

import functools
import json
import sys


def add_parsers(subparsers) -> None:
    admin = subparsers.add_parser("create-admin", help="Create a compliance admin and print its API key once")
    admin.add_argument("--name", required=True)
    admin.add_argument("--email", required=True)
    admin.add_argument("--key-file", required=True,
                       help="New file (mode 0600, outside any git working tree) that receives the API key")

    rekey = subparsers.add_parser("regenerate-key", help="Issue a new API key for a member (written to a file)")
    rekey.add_argument("--member", required=True, help="Member id or email")
    rekey.add_argument("--key-file", required=True,
                       help="New file (mode 0600, outside any git working tree) that receives the API key")

    verify = subparsers.add_parser("audit-verify", help="Verify the audit-log hash chain")
    verify.add_argument("--max-rows", type=int, default=None)
    verify.add_argument("--json", action="store_true", help="Print the full JSON result")
    witness = verify.add_mutually_exclusive_group()
    witness.add_argument("--witness-s3", action="store_true",
                         help="Also check every chain head published to the witness bucket")
    witness.add_argument("--witness-file", help="Also check heads from a JSON/JSON-lines file or directory")
    verify.add_argument("--bucket", help="Witness bucket (default AUDIT_WITNESS_BUCKET)")
    verify.add_argument("--rehash-archive", action="store_true",
                        help="With --witness-s3: stream the anchor's archive and recompute its SHA-256")
    verify.add_argument("--decision-logs", action="store_true",
                        help="Also check stored decision-log entries against their audited digests")
    verify.add_argument("--against-repo", action="store_true",
                        help="With --decision-logs: check every repository-import version against the evidence "
                             "repository at its recorded commit")
    verify.add_argument("--source", help="The evidence git source (name or id) when there is more than one")
    verify.add_argument("--after-session", help="Resume the decision-log checks after this session id")
    verify.add_argument("--max-sessions", type=int, help="Check at most this many sessions")

    archive = subparsers.add_parser("audit-archive-manifest",
                                    help="Upload the final dump and write the archive manifest (operator)")
    archive.add_argument("--dump", required=True, help="Local dump file of the database being archived")
    archive.add_argument("--name", required=True, help="Archive name (1-36 of A-Z a-z 0-9 . _ -)")
    archive.add_argument("--archive-key", help="An object already under archives/ holding the dump")
    archive.add_argument("--bucket", help="Witness bucket (default AUDIT_WITNESS_BUCKET)")

    anchor = subparsers.add_parser("audit-anchor", help="Anchor an empty audit log to an archive manifest")
    anchor.add_argument("--manifest", required=True,
                        help="Manifest key: archives/<chain id>/<name>.manifest.json")
    anchor.add_argument("--bucket", help="Witness bucket (default AUDIT_WITNESS_BUCKET)")
    anchor.add_argument("--note", default=None)

    dump = subparsers.add_parser("audit-verify-archive",
                                 help="Verify an archive dump's audit chain against the witness and its manifest")
    dump.add_argument("--dump", required=True, help="pg_dump --format=custom file (uncompressed or gzip)")
    dump.add_argument("--scratch-url", required=True,
                      help="PostgreSQL database where a scratch schema may be created (needs ~audit_log's size)")
    dump.add_argument("--manifest", help="Archive manifest key (archives/<chain id>/<name>.manifest.json)")
    dump.add_argument("--bucket", help="Witness bucket (default AUDIT_WITNESS_BUCKET)")
    dump.add_argument("--keep", action="store_true", help="Keep the scratch schema")
    dump.add_argument("--json", action="store_true", help="Print the full JSON result")

    arm = subparsers.add_parser("audit-witness-arm", help="Arm the audit witness (owner role; audited)")
    arm.add_argument("--note", default=None, help="Why the witness is armed (at most 500 characters)")
    subparsers.add_parser("audit-publish-head", help="Publish the audit chain head to the witness bucket now")
    subparsers.add_parser("run-jobs", help="Execute queued collector runs and git syncs now")


def _anchor_as_owner(args, out) -> int:
    """Anchor from a manifest with the owner role's own connection (EXECUTE is owner-only)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.runtime_config import env, migration_database_url
    from app.services import audit_archive
    from app.services.audit_witness import publish_head

    bucket = args.bucket or env("AUDIT_WITNESS_BUCKET")
    if not bucket:
        out.write("error: audit-anchor needs --bucket or AUDIT_WITNESS_BUCKET (the manifest's bucket)\n")
        return 2
    client = audit_archive.operator_s3_client()
    engine = create_engine(migration_database_url())
    try:
        with Session(engine) as session:
            try:
                anchored = audit_archive.anchor_from_manifest(session, bucket=bucket, client=client,
                                                              manifest_key=args.manifest, note=args.note)
            except audit_archive.ArchiveError as exc:
                session.rollback()
                out.write(f"error: {exc}\n")
                return 1
            session.commit()
            out.write(f"Anchored audit log at row {anchored['anchor_id']} to {args.manifest} "
                      f"(archived chain {anchored['manifest']['chain_id']}, "
                      f"final row {anchored['manifest']['final_row_id']}).\n")
            out.write("Armed the audit witness.\n")
            published = publish_head(session, bucket=bucket, client=client)
            if published:
                out.write(f"Published chain head to {published['key']}.\n")
    finally:
        engine.dispose()
    return 0


def _arm_as_owner(args, out) -> int:
    """Arm the witness with the owner role's own connection (EXECUTE is owner-only)."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import Session

    from app.runtime_config import migration_database_url
    from app.services.audit_witness import arm, publish_head, witness_state

    engine = create_engine(migration_database_url())
    try:
        with Session(engine) as session:
            arming_id = arm(session, note=args.note)
            session.commit()
            out.write(f"Armed the audit witness (arming {arming_id}).\n")
            state = witness_state(session)
            if state != "enabled":
                out.write(f"Nothing published: the witness is {state}.\n")
                return 0
            published = publish_head(session)
            out.write(f"Published chain head to {published['key']}.\n" if published
                      else "Nothing to publish (empty chain).\n")
    finally:
        engine.dispose()
    return 0


def _archive_manifest(args, out) -> int:
    from app.models import db
    from app.runtime_config import env, witness_disabled
    from app.services import audit_archive

    if witness_disabled():
        out.write("error: AUDIT_WITNESS_DISABLED is set: no manifest is written\n")
        return 2
    bucket = args.bucket or env("AUDIT_WITNESS_BUCKET")
    if not bucket:
        out.write("error: audit-archive-manifest needs --bucket or AUDIT_WITNESS_BUCKET\n")
        return 2
    try:
        written = audit_archive.create_archive_manifest(
            db.session, bucket=bucket, client=audit_archive.operator_s3_client(), dump_path=args.dump,
            name=args.name, archive_key=args.archive_key)
    except audit_archive.WitnessDisabledError as exc:
        out.write(f"error: {exc}\n")
        return 2
    except audit_archive.ArchiveError as exc:
        out.write(f"error: {exc}\n")
        return 1
    manifest = written["manifest"]
    out.write(f"Archive: s3://{bucket}/{manifest['archive_key']} ({manifest['archive_size']} bytes, "
              f"sha256 {manifest['archive_sha256']}).\n")
    out.write(f"Final head: row {manifest['final_row_id']} {manifest['final_row_hash']} "
              f"(chain {manifest['chain_id']}, {manifest['entries']} entries, "
              f"status {manifest['verify']['status']}).\n")
    out.write(f"Manifest: {written['manifest_key']} (sha256 {written['manifest_sha256']}).\n")
    out.write(f"Anchor the new database with: python -m cli audit-anchor --manifest {written['manifest_key']}\n")
    return 0


class KeyFileError(ValueError):
    pass


def check_key_file(path: str) -> str:
    """The absolute path a key may be written to, or KeyFileError: the file must not
    exist, its directory must, and no directory from it upwards may hold ``.git``."""
    import os

    target = os.path.abspath(os.path.expanduser(path))
    if os.path.lexists(target):
        raise KeyFileError(f"{target} already exists; a key file is never overwritten")
    directory = os.path.dirname(target)
    if not os.path.isdir(directory):
        raise KeyFileError(f"{directory} is not a directory")
    probe = os.path.realpath(directory)
    while True:
        if os.path.exists(os.path.join(probe, ".git")):
            raise KeyFileError(f"{target} is inside a git working tree ({probe}); write keys elsewhere")
        parent = os.path.dirname(probe)
        if parent == probe:
            return target
        probe = parent


def write_key_file(path: str, key: str) -> None:
    import os

    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(key + "\n")


def _verify_archive(args, out) -> int:
    """No app, no portal database: an auditor may run it anywhere."""
    from app.runtime_config import env
    from app.services import audit_archive_dump
    from app.services.audit_witness import s3_client

    bucket = args.bucket or env("AUDIT_WITNESS_BUCKET")
    if args.manifest and not bucket:
        out.write("error: --manifest needs --bucket or AUDIT_WITNESS_BUCKET\n")
        return 2

    def progress(done, last_id):
        sys.stderr.write(f"\rverified {done} rows (id {last_id})")

    try:
        result = audit_archive_dump.verify_archive_dump(
            args.dump, args.scratch_url, bucket=bucket, client=s3_client() if bucket else None,
            manifest_key=args.manifest, keep=args.keep, progress=progress)
    except (audit_archive_dump.DumpError, OSError) as exc:
        out.write(f"error: {exc}\n")
        return 2
    sys.stderr.write("\n")
    if args.json:
        out.write(json.dumps(result, indent=2, default=str) + "\n")
    else:
        dump, verify = result["dump"], result["verify"]
        out.write(f"{'verified' if result['ok'] else 'NOT VERIFIED'}: dump sha256={dump['sha256']} "
                  f"size={dump['size']} rows={dump['rows']} chain={result['chain_id']} "
                  f"final_row={json.dumps(result['final_row'])}\n")
        out.write(f"chain: status={verify['status']} verified={verify.get('verified')} "
                  f"forks={verify.get('forks')} true_breaks={verify.get('true_breaks')} "
                  f"content_mismatches={verify.get('content_mismatches')}\n")
        witness = verify.get("witness")
        if witness is not None:
            out.write(f"witness: heads_checked={witness.get('checked')} mismatches={verify.get('witness_mismatches')} "
                      f"invalid_objects={verify.get('invalid_witness_objects')}\n")
        for issue in result["issues"] + result["unchecked"]:
            out.write(f"  - {issue}\n")
    if result["issues"]:
        return 1
    return 4 if result["unchecked"] else 0


def run(args, out=sys.stdout) -> int:
    from app.logging_config import route_logs_to_stderr

    route_logs_to_stderr()  # also when run() is called without python -m cli
    if args.command == "audit-verify-archive":
        return _verify_archive(args, out)

    from app import create_app
    from app.models import db

    app = create_app()
    with app.app_context():
        if args.command == "create-admin":
            from app.services import team_service

            try:
                key_file = check_key_file(args.key_file)
            except KeyFileError as exc:
                out.write(f"error: {exc}\n")
                return 2
            member = team_service.create_member(args.name, args.email, "human", is_compliance_admin=True)
            write_key_file(key_file, member.issued_api_key)
            out.write(f"Created compliance admin {member.name} ({member.id}); its API key (stored only as a "
                      f"hash) is in {key_file} (mode 0600).\n")
            return 0

        if args.command == "regenerate-key":
            from app.services import team_service

            try:
                key_file = check_key_file(args.key_file)
            except KeyFileError as exc:
                out.write(f"error: {exc}\n")
                return 2
            member = team_service.find_member(args.member)
            if member is None:
                out.write(f"error: no single member matches {args.member!r}\n")
                return 2
            member = team_service.regenerate_key(member.id)
            write_key_file(key_file, member.issued_api_key)
            out.write(f"New API key for {member.name} ({member.id}) is in {key_file} (mode 0600); the previous "
                      "key no longer works.\n")
            return 0

        if args.command == "audit-verify":
            from app.services import audit_witness
            from app.services.audit_chain import verify_chain

            heads, anchor_verifier = None, None
            if args.rehash_archive and not args.witness_s3:
                out.write("error: --rehash-archive needs --witness-s3\n")
                return 2
            try:
                if args.witness_file:
                    heads = audit_witness.load_heads_file(args.witness_file)
                elif args.witness_s3:
                    from app.services.audit_archive import verify_anchor

                    bucket = args.bucket or audit_witness.witness_bucket()
                    if not bucket:
                        out.write("error: --witness-s3 needs --bucket or AUDIT_WITNESS_BUCKET\n")
                        return 2
                    client = audit_witness.s3_client()
                    heads = audit_witness.load_heads_s3(bucket, client=client)  # every chain, every version
                    anchor_verifier = functools.partial(verify_anchor, bucket=bucket, client=client,
                                                        rehash=args.rehash_archive, heads=heads)
            except (audit_witness.WitnessError, OSError) as exc:
                out.write(f"error: {exc}\n")
                return 2
            except Exception as exc:  # noqa: BLE001 - listing the bucket failed (credentials, network)
                out.write(f"error: cannot list the witness bucket: {exc}\n")
                return 2

            def progress(done, last_id):
                sys.stderr.write(f"\rverified {done} rows (id {last_id})")

            result = verify_chain(db.session, max_rows=args.max_rows, progress=progress, witness_heads=heads,
                                  anchor_verifier=anchor_verifier)
            sys.stderr.write("\n")
            if args.against_repo and not args.decision_logs:
                out.write("error: --against-repo needs --decision-logs\n")
                return 2
            if args.decision_logs:
                from app.services.decision_log_verify import verify_decision_logs

                checked = verify_decision_logs(db.session, after_session=args.after_session,
                                               max_sessions=args.max_sessions)
                result["decision_logs"] = checked
                if checked["mismatch_count"]:
                    result["status"] = "broken"
                    result["first_break"] = result.get("first_break") or {
                        "id": None, "issue": "Decision-log entries: " + checked["mismatches"][0]["issue"]}
                if args.against_repo:
                    from app.services import decision_log_repo_verify as repo_verify
                    from app.services.git_sources.service import build_provider_for

                    try:
                        evidence = repo_verify.evidence_source(args.source)
                        provider = build_provider_for(evidence)
                    except Exception as exc:  # noqa: BLE001 - no source, several sources, bad credentials
                        out.write(f"error: {exc}\n")
                        return 2
                    repo = repo_verify.verify_against_repo(db.session, provider, source=evidence,
                                                           after_session=args.after_session,
                                                           max_sessions=args.max_sessions)
                    checked["against_repo"] = repo
                    if repo["status"] == "broken":
                        result["status"] = "broken"
                        first = (repo["mismatches"] or repo["missing"] or repo["unreadable"]
                                 or repo["missing_commit"])[0]
                        result["first_break"] = result.get("first_break") or {
                            "id": None, "issue": f"Decision log {first['session_id']} against the repository: "
                                                 f"{first['issue']}"}
                    elif repo["status"] == "unverified" and result["status"] in ("valid", "intact_with_forks"):
                        result["status"] = "unverified"
            if args.json:
                out.write(json.dumps(result, indent=2, default=str) + "\n")
            else:
                out.write(f"status={result['status']} verified={result.get('verified')} "
                          f"content_mismatches={result.get('content_mismatches')} "
                          f"forks={result.get('forks')} true_breaks={result.get('true_breaks')} "
                          f"chain_head={result.get('chain_head')}\n")
                if heads is not None:
                    witness = result.get("witness") or {}
                    out.write(f"witness: published={witness.get('published')} checked={witness.get('checked')} "
                              f"mismatches={result.get('witness_mismatches')} "
                              f"invalid_objects={result.get('invalid_witness_objects')} "
                              f"continued_chains={witness.get('continued_chains_count')} "
                              f"unverified_continuations={witness.get('unverified_continuations_count')} "
                              f"latest_published_id={witness.get('latest_published_id')}\n")
                    for finding in witness.get("mismatches", [])[:10]:
                        out.write(f"witness mismatch: {json.dumps(finding, default=str)}\n")
                    for finding in witness.get("invalid_heads", [])[:10]:
                        out.write(f"invalid witness object: {json.dumps(finding, default=str)}\n")
                if result.get("anchor"):
                    out.write(f"anchor={json.dumps(result['anchor'], default=str)}\n")
                    checked = result["anchor_verification"]
                    detail = checked["issues"] or checked["reasons"]
                    out.write(f"anchor_verification={checked['status']}"
                              + (f" rehashed={checked.get('rehashed')}" if checked.get("rehashed") else "")
                              + "".join(f"\n  - {line}" for line in detail) + "\n")
                    if checked.get("archived_chain"):
                        out.write(f"archived_chain={json.dumps(checked['archived_chain'], default=str)}\n")
                if result.get("decision_logs"):
                    checked = result["decision_logs"]
                    out.write(f"decision_logs: checked={checked['sessions_checked']} "
                              f"unrecorded={checked['unrecorded']} mismatches={checked['mismatch_count']}\n")
                    for finding in checked["mismatches"][:10]:
                        out.write(f"decision-log mismatch: {json.dumps(finding, default=str)}\n")
                    repo = checked.get("against_repo")
                    if repo:
                        out.write(f"against_repo: status={repo['status']} versions={repo['versions_checked']} "
                                  f"mismatches={repo['mismatches_count']} missing={repo['missing_count']} "
                                  f"unreadable={repo['unreadable_count']} "
                                  f"missing_commit={repo['missing_commit_count']} "
                                  f"unverifiable={repo['unverifiable_count']} (no_commit={repo['no_commit_count']} "
                                  f"local_history={repo['local_history_count']}) "
                                  f"not_in_repository={repo['not_in_repository_count']}\n")
                        for name in ("mismatches", "missing", "unreadable", "missing_commit"):
                            for finding in repo[name][:10]:
                                out.write(f"against-repo {name}: {json.dumps(finding, default=str)}\n")
                    if checked.get("next_after_session"):
                        out.write(f"next_after_session={checked['next_after_session']}\n")
                if result.get("first_break"):
                    out.write(f"first_break={json.dumps(result['first_break'])}\n")
            return {"valid": 0, "empty": 0, "intact_with_forks": 3, "unverified": 4}.get(result["status"], 1)

        if args.command == "audit-archive-manifest":
            return _archive_manifest(args, out)

        if args.command == "audit-anchor":
            return _anchor_as_owner(args, out)

        if args.command == "audit-witness-arm":
            return _arm_as_owner(args, out)

        if args.command == "audit-publish-head":
            from app.services.audit_witness import publish_head, witness_state

            state = witness_state(db.session)
            if state != "enabled":
                reason = {"disabled": "AUDIT_WITNESS_DISABLED is set",
                          "unconfigured": "AUDIT_WITNESS_BUCKET is not set",
                          "unarmed": "the witness is not armed (python -m cli audit-witness-arm)"}[state]
                out.write(f"error: {reason}\n")
                return 2
            published = publish_head(db.session)
            out.write(f"Published chain head to {published['key']}.\n" if published
                      else "Nothing to publish (empty chain).\n")
            return 0

        if args.command == "run-jobs":
            from app.services.scheduler import dispatch_once, reap_once

            reaped = reap_once()
            executed = dispatch_once()
            out.write(f"Executed {executed} queued run(s); reaped {reaped} interrupted run(s).\n")
            return 0

    raise ValueError(f"Unknown command {args.command}")
