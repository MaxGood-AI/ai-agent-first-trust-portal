"""Loader for policy-index.json → Policy model with soc2_control_ids M2M."""

import logging

from app.models import Control, Policy
from cli.loaders.base import BaseLoader

logger = logging.getLogger(__name__)


class PoliciesLoader(BaseLoader):
    model_class = Policy
    file_name = "policy-index.json"
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

    def load(self, data_dir, dry_run=False):
        """Load policies, then sync soc2_control_ids M2M from other_data."""
        from app.models import db

        result = super().load(data_dir, dry_run=dry_run)

        if dry_run or result["inserted"] + result["updated"] == 0:
            return result

        # Sync M2M: soc2_control_ids stored in other_data by BaseLoader
        policies = Policy.query.all()
        for policy in policies:
            control_ids = (policy.other_data or {}).get("soc2_control_ids", [])
            if not control_ids:
                continue

            controls = []
            for cid in control_ids:
                control = db.session.get(Control, cid)
                if control:
                    controls.append(control)
                else:
                    logger.debug(
                        "  Policy '%s': control_id '%s' not found, skipping M2M link",
                        policy.title, cid,
                    )
            policy.controls = controls

        db.session.commit()
        return result
