"""Loader for tests.json → TestRecord model."""

from app.models import Control, System, TestRecord
from cli.loaders.base import BaseLoader, SkipRecord


class TestsLoader(BaseLoader):
    dataset = "tests"
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
        item = self._with_owner(item)

        # Extract system.id → system_id
        for nested_key, fk_column in self.nested_fk_extractions.items():
            nested_obj = item.get(nested_key)
            if isinstance(nested_obj, dict) and "id" in nested_obj:
                item[fk_column] = nested_obj["id"]

        return super()._build_record(item)

    def resolve_references(self, item, record, ctx):
        """The control must exist; an unknown system is dropped with a warning."""
        control_id = record.get("control_id")
        if not control_id:
            raise SkipRecord("control_id is missing")
        if control_id not in ctx.ids(Control):
            raise SkipRecord(f"control_id {control_id!r} not found")

        system_id = record.get("system_id")
        if system_id and system_id not in ctx.ids(System):
            record["system_id"] = None
            return [f"system_id {system_id!r} not found; stored without a system"]
        return None
