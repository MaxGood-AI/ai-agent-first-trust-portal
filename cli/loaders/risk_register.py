"""Loader for risk-register.json → RiskRegister model."""

from app.models import RiskRegister
from cli.loaders.base import BaseLoader


class RiskRegisterLoader(BaseLoader):
    model_class = RiskRegister
    file_name = "risk-register.json"
    field_map = {}
    value_maps = {}

    def _build_record(self, item):
        """Extract owner.id/owner.name from nested object before standard build."""
        item = dict(item)
        owner = item.get("owner")
        if isinstance(owner, dict):
            item["owner_id"] = owner.get("id")
            item["owner_name"] = owner.get("name")
        return super()._build_record(item)
