"""Orchestrator for the `init` command — loads compliance data into the database.

Imports the authored datasets of an evidence-repository checkout
(``evidence_import.DEFAULT_DATASETS``) with the diff-only engine in
``app.services.evidence_import``: only real differences are written, so
rerunning it on unchanged data writes nothing. ``python -m cli import`` also
imports, when named, the evidence index, pentest evidence and decision logs.

Usage:
    python -m cli.init --data-dir /path/to/data
    python -m cli init --data-dir /path/to/data
"""

import argparse
import logging
import os
import sys

logger = logging.getLogger(__name__)


def run(data_dir, dry_run=False, verbose=False):
    """Import the datasets in data_dir into the database; returns the engine's result dict."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(levelname)s  %(message)s",
    )

    data_dir = os.path.abspath(data_dir)
    if not os.path.isdir(data_dir):
        logger.error("Data directory does not exist: %s", data_dir)
        sys.exit(1)

    logger.info("Loading compliance data from: %s", data_dir)
    if dry_run:
        logger.info("DRY RUN — no database writes will be made")

    from app import create_app
    from app.services.evidence_import import import_directory

    app = create_app()
    with app.app_context():
        result = import_directory(data_dir, dry_run=dry_run, log=logger.info)

    totals = result["totals"]
    logger.info("--- Init complete ---")
    logger.info(
        "Created: %d  Updated: %d  Unchanged: %d  Deleted: %d  Skipped: %d",
        totals["created"],
        totals["updated"],
        totals["unchanged"],
        totals["deleted"],
        totals["skipped"],
    )
    for message in result["errors"]:
        logger.warning("  %s", message)
    if result["errors_omitted"]:
        logger.warning("  ... and %d more", result["errors_omitted"])
    return result


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load compliance data into the database")
    parser.add_argument("--data-dir", required=True, help="Path to the data directory")
    parser.add_argument("--dry-run", action="store_true", help="Report counts without writing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    run(args.data_dir, dry_run=args.dry_run, verbose=args.verbose)
