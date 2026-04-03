"""Base loader with runtime column introspection and other_data preservation."""

import json
import logging
import os
from datetime import datetime, timezone

from sqlalchemy import inspect as sa_inspect

logger = logging.getLogger(__name__)


class BaseLoader:
    """Abstract base for data file loaders.

    Subclasses set:
        model_class  — SQLAlchemy model (or None for stub loaders)
        file_name    — relative path within the data directory
        field_map    — dict mapping JSON keys to model column names
        value_maps   — dict of {column: {json_val: model_val}} for enum translation
    """

    model_class = None
    file_name = None
    field_map = {}
    value_maps = {}

    def _get_model_columns(self):
        """Return the set of column attribute names on the model."""
        mapper = sa_inspect(self.model_class)
        return {attr.key for attr in mapper.column_attrs}

    def _table_exists(self, db):
        """Check whether the model's table exists in the database."""
        if self.model_class is None:
            return False
        inspector = sa_inspect(db.engine)
        return inspector.has_table(self.model_class.__tablename__)

    def _read_json(self, data_dir):
        """Read and parse the JSON data file. Returns list or None."""
        path = os.path.join(data_dir, self.file_name)
        if not os.path.exists(path):
            logger.warning("File not found, skipping: %s", self.file_name)
            return None
        with open(path, "r") as f:
            data = json.load(f)
        if not isinstance(data, list):
            logger.warning("Expected JSON array in %s, got %s", self.file_name, type(data).__name__)
            return None
        return data

    def _apply_field_map(self, key):
        """Translate a JSON key to a model column name via field_map."""
        return self.field_map.get(key, key)

    def _apply_value_map(self, column_name, value):
        """Translate a value via value_maps; return (mapped_value, original_or_None)."""
        if column_name in self.value_maps and value in self.value_maps[column_name]:
            return self.value_maps[column_name][value], value
        return value, None

    def _parse_date(self, value):
        """Parse a date or datetime string into a datetime object."""
        if value is None:
            return None
        if isinstance(value, datetime):
            return value
        value = str(value).strip()
        if not value:
            return None
        # Try ISO 8601 with timezone
        try:
            return datetime.fromisoformat(value)
        except ValueError:
            pass
        # Try date-only
        try:
            return datetime.strptime(value, "%Y-%m-%d").replace(tzinfo=timezone.utc)
        except ValueError:
            logger.warning("Could not parse date: %s", value)
            return None

    def _build_record(self, item):
        """Split a JSON item into model columns and other_data.

        Returns (column_dict, other_data_dict). Column introspection ensures
        only existing columns are populated; everything else goes to other_data.
        """
        columns = self._get_model_columns()
        record = {}
        other_data = {}

        # Columns that are targeted by field_map entries — if a JSON key's
        # natural name clashes with one of these, the field_map source wins
        # and the clashing key goes to other_data.
        mapped_to_columns = set(self.field_map.values())

        for json_key, value in item.items():
            col_name = self._apply_field_map(json_key)

            # Resolve clash: JSON key "category" would naturally map to column
            # "category", but field_map says "tsc_category" → "category". The
            # field_map source wins; the clashing key goes to other_data.
            if json_key not in self.field_map and json_key in mapped_to_columns:
                other_data[json_key] = value
                continue

            if col_name in columns and col_name != "other_data":
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

                # Preserve original value if mapping changed it
                if original is not None:
                    other_data[f"_original_{col_name}"] = original
            else:
                # Field doesn't map to a column — store in other_data
                other_data[json_key] = value

        record["other_data"] = other_data if other_data else {}
        return record

    def _upsert(self, db, record_dict):
        """Merge (insert or update) a record into the database.

        Returns 'inserted' or 'updated'.
        """
        pk = record_dict.get("id")
        existing = None
        if pk is not None:
            existing = db.session.get(self.model_class, pk)

        instance = self.model_class(**record_dict)
        db.session.merge(instance)

        return "updated" if existing else "inserted"

    def load(self, data_dir, dry_run=False):
        """Load data from the JSON file into the database.

        Returns dict with inserted/updated/skipped counts.
        """
        from app.models import db

        result = {"inserted": 0, "updated": 0, "skipped": 0}

        if not self._table_exists(db):
            logger.warning(
                "SKIP %s: no '%s' table found in the database",
                self.file_name,
                self.model_class.__tablename__ if self.model_class else "(no model)",
            )
            return result

        data = self._read_json(data_dir)
        if data is None:
            return result

        logger.info("Loading %s (%d records)...", self.file_name, len(data))

        for item in data:
            record = self._build_record(item)
            if record is None:
                result["skipped"] += 1
                continue

            if not self._validate(item, record):
                result["skipped"] += 1
                continue

            if dry_run:
                logger.debug("  [dry-run] would load: %s", record.get("id", record.get("name", "?")))
                result["inserted"] += 1
                continue

            action = self._upsert(db, record)
            result[action] += 1

        if not dry_run:
            db.session.commit()

        logger.info(
            "  %s: inserted=%d updated=%d skipped=%d",
            self.file_name,
            result["inserted"],
            result["updated"],
            result["skipped"],
        )
        return result

    def _validate(self, item, record):
        """Override in subclasses to add validation. Return False to skip."""
        return True
