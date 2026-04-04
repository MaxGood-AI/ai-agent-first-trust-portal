"""Loader for vendors.json → Vendor model with system_ids M2M."""

import logging

from app.models import System, Vendor
from cli.loaders.base import BaseLoader

logger = logging.getLogger(__name__)


class VendorsLoader(BaseLoader):
    model_class = Vendor
    file_name = "vendors.json"
    field_map = {}
    value_maps = {}

    def load(self, data_dir, dry_run=False):
        """Load vendors, then sync system_ids M2M from other_data."""
        from app.models import db

        result = super().load(data_dir, dry_run=dry_run)

        if dry_run or result["inserted"] + result["updated"] == 0:
            return result

        # Sync M2M: system_ids stored in other_data by BaseLoader
        vendors = Vendor.query.all()
        for vendor in vendors:
            system_ids = (vendor.other_data or {}).get("system_ids", [])
            if not system_ids:
                continue

            systems = []
            for sid in system_ids:
                system = db.session.get(System, sid)
                if system:
                    systems.append(system)
                else:
                    logger.debug(
                        "  Vendor '%s': system_id '%s' not found, skipping M2M link",
                        vendor.name, sid,
                    )
            vendor.systems = systems

        db.session.commit()
        return result
