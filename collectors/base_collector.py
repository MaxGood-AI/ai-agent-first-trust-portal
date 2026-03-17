"""Base class for automated evidence collectors.

Each collector gathers evidence from a specific source (AWS, GitHub, etc.)
and returns structured results that can be stored in the database.
"""

import logging
from abc import ABC, abstractmethod
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class BaseCollector(ABC):
    """Base class for evidence collectors.

    Subclasses implement collect() to gather evidence from their source.
    Each run produces a list of evidence items that map to specific test records.
    """

    def __init__(self, name):
        self.name = name
        self.collected_at = None

    def run(self):
        """Execute the collector and return evidence items."""
        self.collected_at = datetime.now(timezone.utc)
        logger.info("Running collector: %s", self.name)
        try:
            results = self.collect()
            logger.info("Collector %s found %d evidence items", self.name, len(results))
            return results
        except Exception:
            logger.exception("Collector %s failed", self.name)
            raise

    @abstractmethod
    def collect(self):
        """Gather evidence from the source.

        Returns a list of dicts with keys:
            - test_name: str — the test this evidence applies to
            - evidence_type: str — "link", "file", "screenshot", "automated"
            - description: str — what the evidence shows
            - url: str | None — URL for link-type evidence
            - file_path: str | None — local file path for file-type evidence
        """
