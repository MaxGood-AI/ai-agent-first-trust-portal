"""Loader for risk-register.json → RiskRegister model."""

from app.models import RiskRegister
from cli.loaders.base import BaseLoader


class RiskRegisterLoader(BaseLoader):
    dataset = "risk-register"
    model_class = RiskRegister
    file_name = "risk-register.json"
    field_map = {}
    value_maps = {}

    def _build_record(self, item):
        """Extract owner.id/owner.name from nested object before standard build."""
        return super()._build_record(self._with_owner(item))
