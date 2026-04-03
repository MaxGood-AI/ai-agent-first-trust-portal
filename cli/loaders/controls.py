"""Loader for controls.json → Control model."""

from app.models import Control
from cli.loaders.base import BaseLoader


class ControlsLoader(BaseLoader):
    model_class = Control
    file_name = "controls.json"

    # The JSON `tsc_category` maps to the model's `category` column (TSC values).
    # The JSON `category` (rich category like "Cloud Infrastructure") goes to other_data.
    field_map = {
        "tsc_category": "category",
    }
