"""Loader for policy-index.json → Policy model with soc2_control_ids M2M."""

from app.models import Control, Policy
from cli.loaders.base import BaseLoader, LinkSpec


class PoliciesLoader(BaseLoader):
    dataset = "policies"
    model_class = Policy
    file_name = "policy-index.json"
    field_map = {}
    value_maps = {}

    # soc2_control_ids stays in other_data and drives the policy_controls links.
    # A non-empty list is authoritative for the policy's links; an empty or
    # missing list leaves the stored links as they are.
    link = LinkSpec(relationship="controls", key="soc2_control_ids", target=Control)

    def _build_record(self, item):
        """Extract owner.id/owner.name from nested object before standard build."""
        return super()._build_record(self._with_owner(item))
