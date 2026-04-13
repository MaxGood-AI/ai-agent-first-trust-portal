"""v2 collector registry.

Maps collector names (as stored in ``collector_config.name``) to their
``BaseCollector`` subclass.
"""

from collectors.aws import AWSCollector
from collectors.base import BaseCollector
from collectors.git import GitCollector
from collectors.platform_collector import PlatformCollector
from collectors.policy_check_collector import PolicyCollector
from collectors.vendor_check_collector import VendorCollector

COLLECTOR_CLASSES: dict[str, type[BaseCollector]] = {
    "aws": AWSCollector,
    "git": GitCollector,
    "platform": PlatformCollector,
    "policy": PolicyCollector,
    "vendor": VendorCollector,
}


def get_collector_class(name: str) -> type[BaseCollector] | None:
    return COLLECTOR_CLASSES.get(name)


def known_collector_names() -> list[str]:
    return sorted(COLLECTOR_CLASSES.keys())
