"""`python -m cli import` — diff-only import of an evidence-repository checkout.

Usage:
    python -m cli import --data-dir DIR [--dry-run] [--decision-logs]
                         [--dataset NAME ...] [--json]

Imports the authored datasets of DIR (controls, systems, tests, policies,
vendors, risk-register) in dependency order, writing only real differences,
and prints created / updated / unchanged / deleted / skipped counts.
--dataset (repeatable) names exactly the datasets imported, among them
``evidence`` and ``pentest-findings``, whose default source is the evidence
store; --decision-logs also imports DIR's decision-logs/. --dry-run compares
with the database and reports the counts without writing. --json prints the
summary as JSON on stdout; progress lines go to stderr.

Decision logs follow the upload rules: a transcript that does not extend
the stored one is rejected (kept for review, reported as an error).

Exit status: 0 on success, 1 when the data directory does not exist, any
file could not be imported, or a transcript was rejected.
"""

import argparse
import json
import os
import sys

from app.services.evidence_import import DATASET_ORDER, DEFAULT_DATASETS


def _add_arguments(parser):
    parser.add_argument("--data-dir", required=True,
                        help="Evidence repository checkout to import")
    parser.add_argument("--dry-run", action="store_true",
                        help="Report what would change without writing")
    parser.add_argument("--decision-logs", action="store_true",
                        help="Also import decision-logs/ (their default source is the evidence store)")
    parser.add_argument("--dataset", action="append", dest="datasets", choices=DATASET_ORDER,
                        metavar="NAME",
                        help="Import exactly the datasets named (repeatable; default: "
                             + ", ".join(DEFAULT_DATASETS) + "): " + ", ".join(DATASET_ORDER))
    parser.add_argument("--json", action="store_true",
                        help="Print the summary as JSON")
    return parser


def add_parser(subparsers):
    """Register the ``import`` subcommand on an argparse subparsers object."""
    parser = subparsers.add_parser(
        "import",
        help="Import an evidence repository checkout, writing only differences",
        description=("Import the authored datasets of an evidence repository checkout (and, when "
                     "named, its evidence index, pentest evidence and decision logs), writing only "
                     "real differences."),
    )
    _add_arguments(parser)
    parser.set_defaults(func=run)
    return parser


def _format_counts(counts):
    return (f"created={counts['created']} updated={counts['updated']} "
            f"unchanged={counts['unchanged']} deleted={counts['deleted']} "
            f"skipped={counts['skipped']}")


def format_summary(result):
    """Human-readable summary of an import_directory result."""
    lines = ["DRY RUN — nothing was written" if result.get("dry_run") else "Import complete"]
    for name, counts in result["datasets"].items():
        lines.append(f"  {name}: {_format_counts(counts)}")
    logs = result["decision_logs"]
    lines.append("  decision-logs: " + " ".join(f"{key}={value}" for key, value in logs.items()))
    lines.append(f"Totals: {_format_counts(result['totals'])}")
    if result["errors"]:
        lines.append("Errors:")
        lines.extend(f"  {message}" for message in result["errors"])
        if result["errors_omitted"]:
            lines.append(f"  ... and {result['errors_omitted']} more")
    return "\n".join(lines)


def run(args):
    """Run the import described by parsed ``args``; returns the exit status."""
    data_dir = os.path.abspath(args.data_dir)
    if not os.path.isdir(data_dir):
        print(f"error: data directory does not exist: {data_dir}", file=sys.stderr)
        return 1

    from app import create_app
    from app.services.evidence_import import import_directory

    def progress(message):
        print(message, file=sys.stderr)

    app = create_app()
    with app.app_context():
        result = import_directory(
            data_dir,
            dry_run=args.dry_run,
            include_decision_logs=args.decision_logs,
            datasets=args.datasets,
            log=progress,
        )
    result["dry_run"] = bool(args.dry_run)
    if args.json:
        print(json.dumps(result, indent=2, sort_keys=True))
    else:
        print(format_summary(result))
    return 1 if result["failed_files"] else 0


def main(argv=None):
    parser = _add_arguments(argparse.ArgumentParser(prog="python -m cli.import_cmd"))
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
