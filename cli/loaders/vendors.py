"""Loader for vendors.json → Vendor model with system_ids M2M."""

from app.models import System, Vendor
from cli.loaders.base import BaseLoader, LinkSpec


class VendorsLoader(BaseLoader):
    dataset = "vendors"
    model_class = Vendor
    file_name = "vendors.json"
    field_map = {}
    value_maps = {}

    # system_ids stays in other_data and drives the vendor_systems links.
    # A non-empty list is authoritative for the vendor's links; an empty or
    # missing list leaves the stored links as they are.
    link = LinkSpec(relationship="systems", key="system_ids", target=System)
