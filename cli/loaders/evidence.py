"""Loader for evidence/evidence-index.json → Evidence model."""

import uuid
from datetime import datetime

from app.models import Control, Evidence, TestRecord
from cli.loaders.base import BaseLoader, SkipRecord

EVIDENCE_UUID_NAMESPACE = uuid.UUID("a1b2c3d4-e5f6-7890-abcd-ef1234567890")


class EvidenceLoader(BaseLoader):
    dataset = "evidence"
    model_class = Evidence
    file_name = "evidence/evidence-index.json"
    field_map = {}
    value_maps = {}

    def _resolve_test_record_id(self, test_name, control_name=None):
        """Resolve a test_name (or control_name) to a test_record_id.

        Strategy:
        1. Exact match on TestRecord.name using test_name
        2. Match on Control.name using test_name, then use its first test
        3. If control_name provided and differs from test_name:
           exact match on Control.name using control_name, then first test
        4. None if no match found
        """
        test = TestRecord.query.filter_by(name=test_name).first()
        if test:
            return test.id

        control = Control.query.filter_by(name=test_name).first()
        if control:
            test = TestRecord.query.filter_by(control_id=control.id).first()
            if test:
                return test.id

        if control_name and control_name != test_name:
            control = Control.query.filter_by(name=control_name).first()
            if control:
                test = TestRecord.query.filter_by(control_id=control.id).first()
                if test:
                    return test.id

        return None

    def _build_record(self, item):
        """Custom build: deterministic ID; test_record_id is resolved later."""
        columns = self._get_model_columns()

        test_name = item.get("test_name", "")
        file_path = item.get("file_path", "")
        collected_at = item.get("collected_at", "")

        # Deterministic ID for idempotency
        det_id = str(uuid.uuid5(
            EVIDENCE_UUID_NAMESPACE,
            f"{test_name}|{file_path}|{collected_at}",
        ))

        record = {"id": det_id}
        other_data = {}

        for json_key, value in item.items():
            col_name = self._apply_field_map(json_key)

            if col_name in ("test_name", "control_name"):
                # Always goes to other_data for reference
                other_data[json_key] = value
                continue

            if col_name in columns and col_name not in ("id", "test_record_id", "other_data"):
                mapped_value, original = self._apply_value_map(col_name, value)

                # Parse datetime columns
                col = self.model_class.__table__.columns.get(col_name)
                if col is not None and hasattr(col.type, "python_type"):
                    try:
                        if col.type.python_type is datetime:
                            mapped_value = self._parse_date(mapped_value)
                    except NotImplementedError:
                        pass

                record[col_name] = mapped_value
                if original is not None:
                    other_data[f"_original_{col_name}"] = original
            else:
                other_data[json_key] = value

        record["other_data"] = other_data if other_data else {}
        return record

    def resolve_references(self, item, record, ctx):
        """Resolve test_name/control_name to test_record_id (cached per import)."""
        test_name = item.get("test_name", "")
        control_name = item.get("control_name")
        if not isinstance(test_name, str) or not (control_name is None or isinstance(control_name, str)):
            raise SkipRecord("test_name and control_name must be strings")
        cache = ctx.cache.setdefault("evidence_test_record_ids", {})
        key = (test_name, control_name)
        if key not in cache:
            cache[key] = self._resolve_test_record_id(test_name, control_name)
        test_record_id = cache[key]
        if test_record_id is None:
            detail = f" or control_name={control_name!r}" if control_name else ""
            raise SkipRecord(f"no test matches test_name={test_name!r}{detail}")
        record["test_record_id"] = test_record_id
        return None
