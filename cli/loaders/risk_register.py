"""Stub loader for risk-register.json — skips until RiskRegister model exists."""

from cli.loaders.base import BaseLoader


class RiskRegisterLoader(BaseLoader):
    model_class = None
    file_name = "risk-register.json"

    def load(self, data_dir, dry_run=False):
        import logging
        import os
        logger = logging.getLogger(__name__)
        path = os.path.join(data_dir, self.file_name)
        if os.path.exists(path):
            logger.warning(
                "SKIP %s: no 'risk_register' table found in the database",
                self.file_name,
            )
        return {"inserted": 0, "updated": 0, "skipped": 0}
