"""Loader for controls.json → Control model."""

from app.models import Control
from cli.loaders.base import BaseLoader


class ControlsLoader(BaseLoader):
    dataset = "controls"
    model_class = Control
    file_name = "controls.json"

    # The JSON `tsc_category` maps to the model's `category` column (TSC values).
    # The JSON `category` (rich org category) maps to `source_category`.
    field_map = {
        "tsc_category": "category",
        "category": "source_category",
    }

    def _build_record(self, item):
        """Extract owner.id/owner.name from nested object before standard build."""
        return super()._build_record(self._with_owner(item))
