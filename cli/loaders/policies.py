"""Loader for policy-index.json → Policy model."""

from app.models import Policy
from cli.loaders.base import BaseLoader


class PoliciesLoader(BaseLoader):
    model_class = Policy
    file_name = "policy-index.json"
    field_map = {}
    value_maps = {}
