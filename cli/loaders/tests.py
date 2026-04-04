"""Loader for tests.json → TestRecord model."""

import logging

from app.models import Control, TestRecord
from cli.loaders.base import BaseLoader

logger = logging.getLogger(__name__)


class TestsLoader(BaseLoader):
    model_class = TestRecord
    file_name = "tests.json"

    field_map = {}

    # JSON `system` is a nested object {"id": "...", "name": "...", "short_name": "..."}.
    # We extract system["id"] → system_id before _build_record runs.
    nested_fk_extractions = {
        "system": "system_id",  # extract system.id → system_id
    }

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

    def _build_record(self, item):
        """Extract nested objects before standard build."""
        item = dict(item)

        # Extract system.id → system_id
        for nested_key, fk_column in self.nested_fk_extractions.items():
            nested_obj = item.get(nested_key)
            if isinstance(nested_obj, dict) and "id" in nested_obj:
                item[fk_column] = nested_obj["id"]

        # Extract owner.id/owner.name
        owner = item.get("owner")
        if isinstance(owner, dict):
            item["owner_id"] = owner.get("id")
            item["owner_name"] = owner.get("name")

        return super()._build_record(item)

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
