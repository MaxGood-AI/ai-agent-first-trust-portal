"""Entry point for `python -m cli init --data-dir /path` and `python -m cli export --output-dir /path`."""

import argparse
import sys


def main():
    parser = argparse.ArgumentParser(
        prog="cli",
        description="Trust portal CLI tools",
    )
    subparsers = parser.add_subparsers(dest="command")

    init_parser = subparsers.add_parser("init", help="Load compliance data from a directory")
    init_parser.add_argument(
        "--data-dir",
        required=True,
        help="Path to the data directory containing JSON files",
    )
    init_parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be loaded without writing to the database",
    )
    init_parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable verbose output",
    )

    export_parser = subparsers.add_parser("export", help="Export compliance data to JSON files")
    export_parser.add_argument(
        "--output-dir",
        required=True,
        help="Directory to write JSON files",
    )
    export_parser.add_argument(
        "--git-commit",
        action="store_true",
        help="Auto-commit changes to git after export",
    )
    export_parser.add_argument(
        "--git-push",
        action="store_true",
        help="Push after commit (implies --git-commit)",
    )
    export_parser.add_argument(
        "--include-audit-log",
        action="store_true",
        help="Include audit_log.json in the export",
    )

    args = parser.parse_args()

    if args.command == "init":
        from cli.init import run
        run(args.data_dir, dry_run=args.dry_run, verbose=args.verbose)
    elif args.command == "export":
        from cli.export import export_all, git_commit_and_push
        result = export_all(
            args.output_dir,
            include_audit_log=args.include_audit_log,
        )
        if args.git_push or args.git_commit:
            git_commit_and_push(args.output_dir, push=args.git_push)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
