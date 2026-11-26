"""Loader for policy-index.json → Policy model with soc2_control_ids M2M."""

import re

from app.models import Control, Policy
from cli.loaders.base import BaseLoader, LinkSpec, SkipRecord

# Mirrors the `slug` property of cli/schemas/policies.schema.json.
SLUG_PATTERN = re.compile(r"^[a-z0-9]+(-[a-z0-9]+)*$")
UUID_PATTERN = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
SLUG_MAX_LENGTH = 100


def slug_problem(value):
    """Why ``value`` is not a valid policy slug, or None when it is valid."""
    if not isinstance(value, str) or not SLUG_PATTERN.match(value) or len(value) > SLUG_MAX_LENGTH:
        return (f"slug {value!r} must be lowercase letters and digits in hyphen-separated groups, "
                f"at most {SLUG_MAX_LENGTH} characters")
    if UUID_PATTERN.match(value):
        return f"slug {value!r} must not be shaped like a uuid"
    return None


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

    def resolve_references(self, item, record, ctx):
        """A slug must be valid and belong to one policy in the import run."""
        slug = (record.get("other_data") or {}).get("slug")
        if slug is None:
            return None
        problem = slug_problem(slug)
        if problem:
            raise SkipRecord(problem)
        owners = ctx.cache.setdefault("policy_slugs", {})
        owner = owners.setdefault(slug, record.get("id"))
        if owner != record.get("id"):
            raise SkipRecord(f"slug {slug!r} is already used by policy {owner}")
        return None
