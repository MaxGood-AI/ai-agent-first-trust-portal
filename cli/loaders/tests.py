"""Loader for tests.json → TestRecord model."""

import logging

from app.models import Control, TestRecord
from cli.loaders.base import BaseLoader

logger = logging.getLogger(__name__)


class TestsLoader(BaseLoader):
    model_class = TestRecord
    file_name = "tests.json"

    field_map = {}

    value_maps = {
        "status": {
            "success": "passed",
            "failure": "failed",
            "not_run": "pending",
            "excluded": "not_applicable",
        },
        "evidence_status": {
            "missing": "missing",
            "up_to_date": "submitted",
            "outdated": "outdated",
            "not_required": "submitted",
            "due": "due_soon",
        },
    }

    def _validate(self, item, record):
        """Ensure the referenced control exists."""
        from app.models import db

        control_id = record.get("control_id")
        if control_id and db.session.get(Control, control_id) is None:
            logger.warning(
                "  Skipping test '%s': control_id '%s' not found",
                item.get("name", "?"),
                control_id,
            )
            return False
        return True
