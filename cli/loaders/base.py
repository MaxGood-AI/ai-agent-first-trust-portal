"""Record builders for the evidence-repository datasets.

A loader knows how one dataset file of an evidence repository maps onto its
model: which JSON keys map to which columns (``field_map``), which values are
translated (``value_maps``), which nested objects are flattened, and which
references must resolve. It turns each JSON item into a *record*: a dict of
column values in which every key the model has no column for is preserved in
``other_data``.

Loaders never write. The diff-only import engine
(:mod:`app.services.evidence_import`) compares each record with the stored
row and writes only real differences; :meth:`BaseLoader.load` runs that
engine for this loader's file(s) in a local directory.
"""

import logging
from collections import namedtuple
from datetime import datetime, timezone

from sqlalchemy import inspect as sa_inspect

logger = logging.getLogger(__name__)

# A many-to-many link a dataset carries as a list of ids in an item.
#   relationship  — relationship attribute on the model (e.g. "controls")
#   key           — JSON key holding the list of target ids (kept in other_data)
#   target        — model the ids refer to
LinkSpec = namedtuple("LinkSpec", ["relationship", "key", "target"])


class SkipRecord(Exception):
    """Raised while building a record that cannot be imported; the message says why."""


class BaseLoader:
    """Base for dataset loaders.

    Subclasses set:
        dataset      — engine dataset name (see ``app.services.evidence_import.DATASET_ORDER``)
        model_class  — SQLAlchemy model the records are stored in
        file_name    — path of the dataset file within the evidence repository
        field_map    — dict mapping JSON keys to model column names
        value_maps   — dict of {column: {json_val: model_val}} for enum translation
        link         — optional :data:`LinkSpec` for a many-to-many list of ids
    """

    dataset = None
    model_class = None
    file_name = None
    field_map = {}
    value_maps = {}
    link = None

    def _get_model_columns(self):
        """Return the set of column attribute names on the model."""
        mapper = sa_inspect(self.model_class)
        return {attr.key for attr in mapper.column_attrs}

    def _apply_field_map(self, key):
        """Translate a JSON key to a model column name via field_map."""
        return self.field_map.get(key, key)

    def _apply_value_map(self, column_name, value):
        """Translate a value via value_maps; return (mapped_value, original_or_None)."""
        try:
            mapping = self.value_maps.get(column_name)
            if mapping is not None and value in mapping:
                return mapping[value], value
        except TypeError:  # unhashable value (list/dict) is never a mapped enum
            pass
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
        # ISO 8601, including the basic-format time of scanner output (2026-04-16T193413Z)
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

    @staticmethod
    def _with_owner(item):
        """Copy ``item`` with ``owner.id``/``owner.name`` flattened to owner_id/owner_name."""
        item = dict(item)
        owner = item.get("owner")
        if isinstance(owner, dict):
            item["owner_id"] = owner.get("id")
            item["owner_name"] = owner.get("name")
        return item

    def _build_record(self, item):
        """Split a JSON item into model columns and other_data.

        Returns the record dict. Column introspection ensures only existing
        columns are populated; everything else goes to other_data.
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

    def resolve_references(self, item, record, ctx):
        """Check (and fill in) references that need the database.

        Raise :class:`SkipRecord` to skip the item. May return an iterable of
        warning messages for problems that do not prevent the import.
        ``ctx`` is the engine's ``ImportContext`` (cached id sets and lookups).
        """
        return None

    def load(self, data_dir, dry_run=False):
        """Import this loader's file(s) from ``data_dir`` with the diff-only engine.

        Commits after each file (unless ``dry_run``) and returns the counts
        dict (created / updated / unchanged / deleted / skipped / errors).
        """
        from app.services.evidence_import import import_loader_from_directory

        return import_loader_from_directory(self, data_dir, dry_run=dry_run).as_dict()
