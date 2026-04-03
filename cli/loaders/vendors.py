"""Stub loader for vendors.json — skips until Vendor model exists."""

from cli.loaders.base import BaseLoader


class VendorsLoader(BaseLoader):
    model_class = None
    file_name = "vendors.json"

    def load(self, data_dir, dry_run=False):
        import logging
        import os
        logger = logging.getLogger(__name__)
        path = os.path.join(data_dir, self.file_name)
        if os.path.exists(path):
            logger.warning("SKIP %s: no 'vendors' table found in the database", self.file_name)
        return {"inserted": 0, "updated": 0, "skipped": 0}
