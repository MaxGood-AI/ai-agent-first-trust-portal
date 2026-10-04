"""``python -m cli git-source`` — manage git sources from a shell.

  git-source list [--json]
  git-source add --name N --role governance|evidence --provider codecommit|github|local
                 --repository R [--branch B] [--region AWS_REGION] [--credential-mode M]
                 [--role-arn ARN] [--external-id ID] [--token-env VAR]
                 [--schedule "CRON"] [--disabled] [--mappings-file FILE.json]
                 [--record-commits | --no-record-commits] [--history-limit N]
  git-source update --name N [any add option]
  git-source set-commit --name N --commit SHA      (cutover: next sync diffs from SHA)
  git-source sync --name N [--full] [--no-wait]    (queue a sync; run it here unless --no-wait)

Field names match the API (``POST /api/git-sources``).
"""

from __future__ import annotations

import json
import os
import sys


def add_parser(subparsers) -> None:
    parser = subparsers.add_parser("git-source", help="Manage git sources (governance/evidence repos)")
    actions = parser.add_subparsers(dest="action", required=True)

    listing = actions.add_parser("list", help="List git sources")
    listing.add_argument("--json", action="store_true")

    for name in ("add", "update"):
        sub = actions.add_parser(name, help=f"{name.capitalize()} a git source")
        sub.add_argument("--name", required=True)
        required = name == "add"
        sub.add_argument("--role", choices=("governance", "evidence"), required=required)
        sub.add_argument("--provider", choices=("codecommit", "github", "local"), required=required)
        sub.add_argument("--repository", required=required)
        sub.add_argument("--branch")
        sub.add_argument("--region")
        sub.add_argument("--credential-mode")
        sub.add_argument("--role-arn", help="assume_role: role to assume from the runtime role")
        sub.add_argument("--external-id")
        sub.add_argument("--token-env", help="stored_token: name of the env var holding the token")
        sub.add_argument("--schedule", help="5-field crontab (UTC, 0 = Sunday); '' clears it")
        sub.add_argument("--disabled", action="store_true", default=None)
        sub.add_argument("--enabled", action="store_true", default=None)
        sub.add_argument("--mappings-file", help="JSON file with a [{pattern, kind}] list")
        sub.add_argument("--record-commits", dest="record_commits", action="store_true", default=None)
        sub.add_argument("--no-record-commits", dest="record_commits", action="store_false")
        sub.add_argument("--history-limit", type=int)

    commit = actions.add_parser("set-commit", help="Set the last synced commit (cutover)")
    commit.add_argument("--name", required=True)
    commit.add_argument("--commit", required=True)

    sync = actions.add_parser("sync", help="Queue a sync and run it in this process")
    sync.add_argument("--name", required=True)
    sync.add_argument("--no-wait", action="store_true", help="Only queue; the scheduler leader runs it")
    sync.add_argument("--full", action="store_true",
                      help="Re-import every mapped file at head (still diff-only per record); "
                           "resyncs a source whose last synced commit is no longer in the repository")


def _payload(args) -> dict:
    data = {"name": args.name}
    for field in ("role", "provider", "repository", "branch", "region"):
        value = getattr(args, field, None)
        if value is not None:
            data[field] = value
    if args.credential_mode:
        data["credential_mode"] = args.credential_mode
    if args.role_arn:
        data["credentials"] = {"role_arn": args.role_arn}
        if args.external_id:
            data["credentials"]["external_id"] = args.external_id
    elif args.token_env:
        token = os.environ.get(args.token_env)
        if not token:
            raise SystemExit(f"environment variable {args.token_env} is empty")
        data["credentials"] = {"token": token}
    if args.schedule is not None:
        data["schedule_cron"] = args.schedule or None
    if args.disabled:
        data["enabled"] = False
    elif args.enabled:
        data["enabled"] = True
    if args.mappings_file:
        with open(args.mappings_file, encoding="utf-8") as handle:
            data["path_mappings"] = json.load(handle)
    options = {}
    if args.record_commits is not None:
        options["record_commits"] = args.record_commits
    if args.history_limit is not None:
        options["history_limit"] = args.history_limit
    if options:
        data["options"] = options
    return data


def run(args, out=sys.stdout) -> int:
    from app import create_app
    from app.services.git_sources import service

    app = create_app()
    with app.app_context():
        if args.action == "list":
            from app.models.git_source import GitSource

            sources = [service.serialize_source(s) for s in GitSource.query.order_by(GitSource.name).all()]
            if args.json:
                out.write(json.dumps(sources, indent=2) + "\n")
            else:
                for s in sources:
                    out.write(f"{s['name']:<20} {s['role']:<10} {s['provider']:<10} {s['repository']} "
                              f"@{s['branch']} last={(s['last_synced_commit'] or '-')[:12]} "
                              f"status={s['last_sync_status'] or '-'}\n")
            return 0

        if args.action == "add":
            try:
                source = service.create_source(_payload(args))
            except service.GitSourceConfigError as exc:
                out.write(f"error: {exc}\n")
                return 2
            out.write(f"Created git source {source.name} ({source.id}).\n")
            return 0

        source = service.find_source(args.name)
        if source is None:
            out.write(f"error: no git source named {args.name!r}\n")
            return 2

        if args.action == "update":
            payload = _payload(args)
            payload.pop("name")
            synced_commit = source.last_synced_commit
            try:
                service.update_source(source, payload)
            except service.GitSourceConfigError as exc:
                out.write(f"error: {exc}\n")
                return 2
            out.write(f"Updated git source {source.name}.\n")
            if synced_commit and source.last_synced_commit is None:
                out.write("The source now reads a different repository, branch, role or set of mapped "
                          "paths; its last synced commit was cleared, so the next sync compares the "
                          "whole branch.\n")
            return 0

        if args.action == "set-commit":
            try:
                service.set_last_synced_commit(source, args.commit)
            except service.GitSourceConfigError as exc:
                out.write(f"error: {exc}\n")
                return 2
            out.write(f"{source.name}: last synced commit set to {source.last_synced_commit}.\n")
            return 0

        if args.action == "sync":
            from app.services.scheduler import ActiveRunConflict, enqueue_git_sync, execute_claimed

            if not source.enabled:
                out.write(f"error: git source {source.name!r} is disabled\n")
                return 2
            try:
                run_row, created = enqueue_git_sync(source, "manual", full=args.full)
            except ActiveRunConflict as exc:
                out.write(f"error: {exc}\n")
                return 1
            if not created:
                out.write(f"A sync is already {run_row.status} (run {run_row.id}).\n")
                return 1
            if args.no_wait:
                out.write(f"Queued sync run {run_row.id}.\n")
                return 0
            outcome = execute_claimed("git_sync", run_row.id)
            from app.models import db
            from app.models.git_source import GitSyncRun

            db.session.expire_all()
            final = db.session.get(GitSyncRun, run_row.id)
            out.write(json.dumps(service.serialize_run(final), indent=2) + "\n")
            return 0 if outcome == "executed" and final.status in ("success", "unchanged") else 1

    raise ValueError(f"unknown action {args.action}")
