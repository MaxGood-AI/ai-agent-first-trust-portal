"""Entry point for `python -m cli init --data-dir /path`."""

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

    args = parser.parse_args()

    if args.command == "init":
        from cli.init import run
        run(args.data_dir, dry_run=args.dry_run, verbose=args.verbose)
    else:
        parser.print_help()
        sys.exit(1)


if __name__ == "__main__":
    main()
