"""Loader registry — controls load order (respects FK constraints)."""

from cli.loaders.controls import ControlsLoader
from cli.loaders.systems import SystemsLoader
from cli.loaders.tests import TestsLoader
from cli.loaders.policies import PoliciesLoader
from cli.loaders.vendors import VendorsLoader
from cli.loaders.evidence import EvidenceLoader
from cli.loaders.risk_register import RiskRegisterLoader
from cli.loaders.pentest_findings import PentestFindingsLoader

# Ordered: parents before children, FK targets before FK sources.
LOADER_REGISTRY = [
    ControlsLoader,
    SystemsLoader,
    TestsLoader,
    PoliciesLoader,
    VendorsLoader,
    EvidenceLoader,
    RiskRegisterLoader,
    PentestFindingsLoader,
]
