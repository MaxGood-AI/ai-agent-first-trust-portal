"""``python -m cli evidence-store`` - the evidence store from a shell.

  evidence-store status [--json]
      The bucket (EVIDENCE_STORE_BUCKET), its retention floor, recorded
      versions by status and kind, documents and the latest sync.
  evidence-store sync [--wait]
      Queue a sync of the bucket; with --wait run it in this process and print
      the run (exit 0 success or unchanged, 1 partial, failure or a sync
      already active, 2 not configured).
  evidence-store record-erasure --key K --version-id V --reason TEXT --admin ID_OR_EMAIL [--bucket B]
      Mark a recorded version as erased after a documented erasure (a
      data-subject erasure request or a leaked-secret purge). The reason is
      required; ``HeadObject`` of the exact version must report it absent
      (it is refused while the version still exists); the change is audited
      and attributed to --admin, an active compliance admin. Verification
      then lists the version as erased instead of failing it.
  evidence-store acknowledge (--key K --version-id V | --file PATH) --reason TEXT --admin ID_OR_EMAIL [--bucket B]
      Settle a version an import cannot settle, marking it acknowledged
      (with the status it leaves): a ``non_conforming`` version (an upload
      without a SHA-256 checksum, or whose body does not match it); a refusal (``rejected`` or ``too_large``) that no longer re-derives
      from its body (it is re-derived first; a refusal that still holds is
      refused);
      an ``error`` version that failed at least 3 syncs (which every sync
      otherwise reads again). Same rules for the reason and --admin; audited.
      Verification then lists it apart from the failures (informational)
      and still checks that it exists with the recorded size, ETag and
      SHA-256 (a non-conforming one: SHA-256 with ``--full``). ``--file`` names a file
      of JSON lines ``{"key": K, "version_id": V}`` (at most 100,000 lines of
      at most 8 KiB): each line is acknowledged on its own, by the same rules
      and with its own audited change; a line that cannot be parsed (any
      parse error, nesting too deep included) or looked up is refused with
      its line number and the rest go on; a summary is printed.
  evidence-store set-retention-floor --days N --reason TEXT --admin ID_OR_EMAIL [--bucket B]
      Set the bucket's retention floor - the lowest default Object Lock
      retention verification accepts, which the bucket's first sync sets
      from its default - to N days: a new floor row, dated by the database
      (audited, attributed to --admin; refused before the bucket's first
      sync). The only way to lower it; verification lists every lowering.

``--bucket`` (default: the configured bucket) names the bucket a record was
recorded in, so the records of a former bucket can be handled. A key that
held a control character is matched by its key or by its recorded
(percent-encoded) form.

Trust boundary: these commands run in an operator shell with the portal's
database credentials. ``--admin`` names the active compliance admin the
audited change is attributed to; the shell does not authenticate that
admin, so whoever runs the command is trusted as much as the database
credentials it holds (they could write the same rows directly), and the
audit log records the change, its reason and the named admin.

Exit status of record-erasure, acknowledge and set-retention-floor: 0
recorded (every line, for --file), 2 refused (any line, for --file).

Verification is ``python -m cli audit-verify --evidence-store [--full]``.
"""

from __future__ import annotations

import json
import sys

MAX_FILE_LINES = 100_000
MAX_LINE_BYTES = 8 * 1024
ADMIN_HELP = ("Id or email of the active compliance admin the audited change is attributed to (asserted by the "
              "operator running this shell, which holds the portal's database credentials)")


def add_parser(subparsers) -> None:
    parser = subparsers.add_parser("evidence-store", help="Sync and inspect the evidence store")
    actions = parser.add_subparsers(dest="action", required=True)

    status = actions.add_parser("status", help="Show the evidence store's status")
    status.add_argument("--json", action="store_true")

    sync = actions.add_parser("sync", help="Queue a sync of the evidence store")
    sync.add_argument("--wait", action="store_true", help="Run the sync in this process and print the run")

    erasure = actions.add_parser("record-erasure", help="Record the documented erasure of a version (audited)")
    erasure.add_argument("--key", required=True)
    erasure.add_argument("--version-id", required=True)
    acknowledge = actions.add_parser("acknowledge", help="Acknowledge versions an import cannot settle: non-conforming "
                                                         "uploads, refusals that no longer re-derive, persistent "
                                                         "errors (audited)")
    acknowledge.add_argument("--key")
    acknowledge.add_argument("--version-id")
    acknowledge.add_argument("--file", help='JSON lines {"key": K, "version_id": V}, each acknowledged on its own')
    floor = actions.add_parser("set-retention-floor", help="Set the bucket's retention floor (audited)")
    floor.add_argument("--days", required=True, type=int, help="The floor in days (at least 1)")
    for action, reason in ((erasure, "Why the version was erased (required)"),
                           (acknowledge, "Why the versions are acknowledged (required)"),
                           (floor, "Why the floor is set to this value (required)")):
        action.add_argument("--reason", required=True, help=reason)
        action.add_argument("--admin", required=True, help=ADMIN_HELP)
        action.add_argument("--bucket", help="The bucket the records belong to (default: EVIDENCE_STORE_BUCKET)")


def run(args, out=sys.stdout) -> int:
    from app import create_app
    from app.logging_config import route_logs_to_stderr

    route_logs_to_stderr()
    app = create_app()
    with app.app_context():
        if args.action == "status":
            return _status(args, out)
        if args.action == "sync":
            return _sync(args, out)
        if args.action in ("record-erasure", "acknowledge", "set-retention-floor"):
            return _administer(args, out)
    raise ValueError(f"unknown action {args.action}")


def _status(args, out) -> int:
    from app.services.evidence_store import service

    status = service.status()
    if args.json:
        out.write(json.dumps(status, indent=2, default=str) + "\n")
        return 0
    out.write(f"bucket: {status['bucket'] or 'not configured (EVIDENCE_STORE_BUCKET is not set)'}\n")
    out.write(f"retention floor: {status['retention_floor_days']} days\n" if status["retention_floor_days"]
              else "retention floor: none (the first sync sets it)\n")
    out.write(f"recorded versions: {status['objects']} "
              + " ".join(f"{name}={count}" for name, count in sorted(status["objects_by_status"].items())) + "\n")
    out.write(f"evidence documents: {status['documents']}\n")
    last = status["last_run"]
    out.write(f"last sync: {last['status']} queued {last['queued_at']} (run {last['id']})\n" if last
              else "last sync: none\n")
    return 0


def _sync(args, out) -> int:
    from app.models import db
    from app.models.evidence_store import EvidenceStoreSyncRun
    from app.services.evidence_store import NOT_CONFIGURED, StoreNotConfigured, service
    from app.services.scheduler import ActiveRunConflict, execute_claimed

    try:
        run_row, created = service.enqueue_sync("manual")
    except StoreNotConfigured:
        out.write(f"error: {NOT_CONFIGURED}\n")
        return 2
    except ActiveRunConflict as exc:
        out.write(f"error: {exc}\n")
        return 1
    if not created:
        out.write(f"A sync is already {run_row.status} (run {run_row.id}).\n")
        return 1
    if not args.wait:
        out.write(f"Queued sync run {run_row.id}.\n")
        return 0
    outcome = execute_claimed("evidence_store_sync", run_row.id)
    db.session.expire_all()
    final = db.session.get(EvidenceStoreSyncRun, run_row.id)
    out.write(json.dumps(service.serialize_run(final), indent=2) + "\n")
    return 0 if outcome == "executed" and final.status in ("success", "unchanged") else 1


def _administer(args, out) -> int:
    """``record-erasure``, ``acknowledge`` or ``set-retention-floor`` (audited, attributed to --admin)."""
    from flask import g

    from app.services import team_service
    from app.services.evidence_store import NOT_CONFIGURED, store_bucket

    admin = team_service.find_member(args.admin)
    if admin is None or not admin.is_active or not admin.is_compliance_admin:
        out.write(f"error: {args.admin!r} is not an active compliance admin\n")
        return 2
    bucket = args.bucket or store_bucket()
    g.current_team_member = admin
    if args.action == "set-retention-floor":
        if bucket is None:
            out.write(f"error: {NOT_CONFIGURED}; name the bucket with --bucket\n")
            return 2
        return _set_floor(args, bucket, admin, out)
    if args.action == "acknowledge" and args.file:
        if args.key or args.version_id:
            out.write("error: --file replaces --key and --version-id\n")
            return 2
        return _acknowledge_file(args, bucket, admin, out)
    if not args.key or not args.version_id:
        out.write("error: name the version with --key and --version-id (or --file)\n")
        return 2
    error = _mark(args.action, args.key, args.version_id, bucket, args.reason, admin)
    if error:
        out.write(f"error: {error}\n")
        return 2
    out.write(f"Recorded the {'erasure' if args.action == 'record-erasure' else 'acknowledgement'} of {args.key} "
              f"version {args.version_id}.\n")
    return 0


def _mark(action: str, key, version_id, bucket: str | None, reason: str, admin) -> str | None:
    """Erase or acknowledge one recorded version in its own transaction; why it was refused, or None."""
    from app.models import db
    from app.services.evidence_store import service

    if not isinstance(key, str) or not isinstance(version_id, str) or not key or not version_id:
        return "a version is named by a key and a version id (strings)"
    row = service.find_object(key, version_id, bucket)
    if row is None:
        return "no single recorded version has that key and version id" + (f" in bucket {bucket}" if bucket else "")
    try:
        if action == "record-erasure":
            service.record_erasure(row, reason, admin.id)
        else:
            service.acknowledge(row, reason, admin.id)
        db.session.commit()
    except service.EvidenceStoreError as exc:
        db.session.rollback()
        return str(exc)
    return None


def _acknowledge_file(args, bucket: str | None, admin, out) -> int:
    """Acknowledge every version a JSON-lines file names, each on its own (summary printed)."""
    acknowledged, refused = 0, []
    try:
        with open(args.file, "rb") as handle:
            for number, raw in enumerate(handle, start=1):
                if number > MAX_FILE_LINES:
                    refused.append((number, f"the file has more than {MAX_FILE_LINES:,} lines; the rest is not read"))
                    break
                if not raw.strip():
                    continue
                if len(raw) > MAX_LINE_BYTES:
                    refused.append((number, f"the line is longer than {MAX_LINE_BYTES:,} bytes"))
                    continue
                try:
                    entry = json.loads(raw)
                except (ValueError, RecursionError, TypeError):
                    refused.append((number, "not a JSON object"))
                    continue
                if not isinstance(entry, dict):
                    refused.append((number, "not a JSON object"))
                    continue
                try:
                    error = _mark("acknowledge", entry.get("key"), entry.get("version_id"), bucket, args.reason,
                                  admin)
                except Exception as exc:  # noqa: BLE001 - one line never stops the others
                    from app.models import db

                    db.session.rollback()
                    error = f"the version cannot be looked up ({type(exc).__name__})"
                if error:
                    refused.append((number, error))
                else:
                    acknowledged += 1
    except OSError as exc:
        out.write(f"error: cannot read {args.file}: {exc.strerror or type(exc).__name__}\n")
        return 2
    for number, error in refused[:100]:
        out.write(f"line {number}: refused: {error}\n")
    out.write(f"Acknowledged {acknowledged} version(s); refused {len(refused)}.\n")
    return 2 if refused else 0


def _set_floor(args, bucket: str, admin, out) -> int:
    from app.models import db
    from app.services.evidence_store import service

    try:
        floor = service.set_retention_floor(bucket, args.days, args.reason, admin.id)
        db.session.commit()
    except service.EvidenceStoreError as exc:
        db.session.rollback()
        out.write(f"error: {exc}\n")
        return 2
    out.write(f"Set the retention floor of {bucket} to {floor.days} days.\n")
    return 0
