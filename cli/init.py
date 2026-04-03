"""Orchestrator for the `init` command — loads compliance data into the database.

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
    """Load all compliance data from data_dir into the database."""
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
    from app.models import db

    app = create_app()
    with app.app_context():
        from cli.loaders import LOADER_REGISTRY

        totals = {"inserted": 0, "updated": 0, "skipped": 0}

        for loader_class in LOADER_REGISTRY:
            loader = loader_class()
            result = loader.load(data_dir, dry_run=dry_run)
            totals["inserted"] += result["inserted"]
            totals["updated"] += result["updated"]
            totals["skipped"] += result["skipped"]

        logger.info("--- Init complete ---")
        logger.info(
            "Inserted: %d  Updated: %d  Skipped: %d",
            totals["inserted"],
            totals["updated"],
            totals["skipped"],
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Load compliance data into the database")
    parser.add_argument("--data-dir", required=True, help="Path to the data directory")
    parser.add_argument("--dry-run", action="store_true", help="Print without writing")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    args = parser.parse_args()
    run(args.data_dir, dry_run=args.dry_run, verbose=args.verbose)
