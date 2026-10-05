"""Trust portal command line: ``python -m cli <command> [options]``.

Commands:
  import         Load a local evidence-repo checkout (diff-only)
  init           Load the compliance datasets of a checkout (diff-only; no decision logs)
  export         Export compliance data to JSON files
  create-admin   Create a compliance admin and print its API key once
  regenerate-key Issue a new API key for a member (printed once)
  audit-verify   Recompute and verify the audit-log hash chain
  audit-archive-manifest  Archive the chain: upload the dump, publish its final head, write the manifest
  audit-anchor   Start an empty audit log from an archive manifest (owner role)
  audit-verify-archive  Verify an archive dump's audit chain against the witness and its manifest
  audit-witness-arm  Arm the audit witness (owner role; heads are published only once armed)
  audit-publish-head  Publish the audit chain head to the witness bucket
  run-jobs       Execute queued collector runs, git-source syncs and evidence-store syncs now
  git-source     Manage git sources (list, add, set-commit, sync)
  evidence-store Sync and inspect the evidence store; record a documented erasure
  scaffold       Create governance and evidence repository skeletons for a new organisation
  db-wait        Wait for the database (container entrypoint)
  db-migrate     Migrate to head and provision the app role (container entrypoint)
  db-check-role  Check that the application role is safe to serve with
"""

import argparse
import sys


def build_parser():
    parser = argparse.ArgumentParser(prog="cli", description="Trust portal CLI tools")
    subparsers = parser.add_subparsers(dest="command")

    from cli import import_cmd
    import_cmd.add_parser(subparsers)

    init_parser = subparsers.add_parser("init", help="Load compliance datasets from a directory (diff-only)")
    init_parser.add_argument("--data-dir", required=True, help="Path to the evidence-repo checkout")
    init_parser.add_argument("--dry-run", action="store_true", help="Report changes without writing")
    init_parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")

    export_parser = subparsers.add_parser("export", help="Export compliance data to JSON files")
    export_parser.add_argument("--output-dir", required=True, help="Directory to write JSON files")
    export_parser.add_argument("--git-commit", action="store_true", help="Auto-commit changes to git after export")
    export_parser.add_argument("--git-push", action="store_true", help="Push after commit (implies --git-commit)")
    export_parser.add_argument("--include-audit-log", action="store_true", help="Include audit_log.json in the export")

    from cli import admin_cmd, db_cmd, evidence_store_cmd, git_source_cmd, scaffold_cmd
    admin_cmd.add_parsers(subparsers)
    git_source_cmd.add_parser(subparsers)
    evidence_store_cmd.add_parser(subparsers)
    scaffold_cmd.add_parser(subparsers)
    db_cmd.add_parsers(subparsers)
    return parser


def main(argv=None):
    from app.logging_config import route_logs_to_stderr

    route_logs_to_stderr()  # stdout carries only command output (never a log line next to a key)
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == "import":
        from cli import import_cmd
        return import_cmd.run(args)
    if args.command == "init":
        from cli.init import run
        run(args.data_dir, dry_run=args.dry_run, verbose=args.verbose)
        return 0
    if args.command == "export":
        from cli.export import export_all, git_commit_and_push
        export_all(args.output_dir, include_audit_log=args.include_audit_log)
        if args.git_push or args.git_commit:
            git_commit_and_push(args.output_dir, push=args.git_push)
        return 0
    if args.command in ("create-admin", "regenerate-key", "audit-verify", "audit-verify-archive",
                        "audit-archive-manifest",
                        "audit-witness-arm", "audit-anchor", "audit-publish-head", "run-jobs"):
        from cli import admin_cmd
        return admin_cmd.run(args)
    if args.command == "git-source":
        from cli import git_source_cmd
        return git_source_cmd.run(args)
    if args.command == "evidence-store":
        from cli import evidence_store_cmd
        return evidence_store_cmd.run(args)
    if args.command == "scaffold":
        from cli import scaffold_cmd
        return scaffold_cmd.run(args)
    if args.command in ("db-wait", "db-migrate", "db-check-role"):
        from cli import db_cmd
        return db_cmd.run(args)
    parser.print_help()
    return 1


if __name__ == "__main__":
    sys.exit(main())
