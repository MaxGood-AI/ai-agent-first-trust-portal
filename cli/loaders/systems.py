"""Loader for systems.json → System model."""

from app.models import System
from cli.loaders.base import BaseLoader


class SystemsLoader(BaseLoader):
    model_class = System
    file_name = "systems.json"

    # JSON `type` maps to model `system_type` (avoids Python keyword conflict)
    field_map = {
        "type": "system_type",
    }
