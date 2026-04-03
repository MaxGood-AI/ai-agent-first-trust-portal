"""Loader registry — controls load order (respects FK constraints)."""

from cli.loaders.controls import ControlsLoader
from cli.loaders.systems import SystemsLoader
from cli.loaders.tests import TestsLoader
from cli.loaders.policies import PoliciesLoader
from cli.loaders.vendors import VendorsLoader
from cli.loaders.evidence import EvidenceLoader
from cli.loaders.risk_register import RiskRegisterLoader

# Ordered: parents before children, FK targets before FK sources.
LOADER_REGISTRY = [
    ControlsLoader,
    SystemsLoader,       # stub — skips until System model exists
    TestsLoader,
    PoliciesLoader,
    VendorsLoader,       # stub — skips until Vendor model exists
    EvidenceLoader,
    RiskRegisterLoader,  # stub — skips until RiskRegister model exists
]
