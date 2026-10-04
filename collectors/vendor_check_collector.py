"""Vendor v2 collector — checks vendor inventory completeness and link health.

Reads vendors directly from the portal database. No AWS/IAM permissions
required. Optionally probes each vendor's ``security_page_url`` to verify
it's reachable, but only when the config flag ``probe_urls`` is set. Probes go
through ``app.services.safe_http.safe_get``: a URL that is not http(s), or
whose host (or any redirect hop) resolves to a private, loopback, link-local,
multicast, reserved or cloud metadata address, is refused and reported as
unreachable without being requested.
"""

import logging
from typing import Any

from app.models import Vendor
from collectors.base import BaseCollector, CheckResult, read_snapshot

logger = logging.getLogger(__name__)


VENDOR_REQUIRED_PERMISSIONS: list[str] = []


class VendorCollector(BaseCollector):
    """Verifies the portal's vendor inventory is complete enough for SOC 2
    vendor-management evidence."""

    name = "vendor"
    required_permissions = VENDOR_REQUIRED_PERMISSIONS
    credential_modes_supported = ["none", "task_role"]

    def run(self) -> list[CheckResult]:
        config_dict = self.config.config or {}
        probe_urls = bool(config_dict.get("probe_urls", False))
        http_timeout = int(config_dict.get("http_timeout_seconds", 5))

        try:
            vendors = read_snapshot(Vendor.query.order_by(Vendor.name))
        except Exception as exc:  # noqa: BLE001
            logger.exception("Failed to query vendors")
            return [
                CheckResult(
                    check_name="vendor_query",
                    status="error",
                    message=str(exc),
                )
            ]

        if not vendors:
            return [
                CheckResult(
                    check_name="vendor_inventory",
                    status="fail",
                    target_test_name="Vendor Management",
                    message="No vendors in portal inventory",
                    evidence_description="Portal vendor inventory is empty",
                )
            ]

        results: list[CheckResult] = []
        active = [v for v in vendors if (v.status or "").lower() == "active"]

        # Overall inventory check
        results.append(
            CheckResult(
                check_name="vendor_inventory",
                status="pass",
                target_test_name="Vendor Management",
                message=(
                    f"Portal has {len(vendors)} vendors "
                    f"({len(active)} active)"
                ),
                detail={
                    "total": len(vendors),
                    "active": len(active),
                },
                evidence_description=(
                    f"Portal vendor inventory: {len(vendors)} vendors "
                    f"({len(active)} active)"
                ),
            )
        )

        # Per-vendor completeness checks
        for vendor in active:
            has_security_page = bool(vendor.security_page_url)
            has_privacy_policy = bool(vendor.privacy_policy_url)
            has_purpose = bool(vendor.purpose)
            all_complete = has_security_page and has_privacy_policy and has_purpose

            results.append(
                CheckResult(
                    check_name=f"vendor_record_completeness:{vendor.id}",
                    status="pass" if all_complete else "fail",
                    target_test_name="Vendor Management",
                    message=(
                        f"Vendor {vendor.name}: "
                        f"security_page={has_security_page}, "
                        f"privacy_policy={has_privacy_policy}, "
                        f"purpose={has_purpose}"
                    ),
                    detail={
                        "vendor_id": vendor.id,
                        "has_security_page_url": has_security_page,
                        "has_privacy_policy_url": has_privacy_policy,
                        "has_purpose": has_purpose,
                    },
                    evidence_description=(
                        f"Vendor {vendor.name} record completeness: "
                        f"{'complete' if all_complete else 'incomplete'}"
                    ),
                )
            )

        # Optional HTTP probing
        if probe_urls:
            for vendor in active:
                if not vendor.security_page_url:
                    continue
                result = _probe_url(vendor.security_page_url, timeout=http_timeout)
                results.append(
                    CheckResult(
                        check_name=f"vendor_security_page_reachable:{vendor.id}",
                        status="pass" if result["reachable"] else "fail",
                        target_test_name="Vendor Management",
                        message=(
                            f"Vendor {vendor.name} security page: "
                            f"{result['status_code'] or result['error']}"
                        ),
                        detail={
                            "vendor_id": vendor.id,
                            "url": vendor.security_page_url,
                            **result,
                        },
                        evidence_description=(
                            f"Vendor {vendor.name} security page "
                            f"({vendor.security_page_url}) "
                            f"{'reachable' if result['reachable'] else 'unreachable'}"
                        ),
                    )
                )

        return results


def _probe_url(url: str, timeout: int = 5) -> dict[str, Any]:
    """Attempt a checked HTTP GET against ``url`` (redirects followed and
    re-checked by ``safe_get``) and return a structured result.

    Lives at module level so it's easily mockable in tests.
    """
    from app.services.safe_http import release, safe_get

    try:
        resp = safe_get(url, timeout=timeout, stream=True)
        status_code = resp.status_code
        release(resp)
        return {
            "reachable": status_code < 400,
            "status_code": status_code,
            "error": None,
        }
    except Exception as exc:  # noqa: BLE001
        return {
            "reachable": False,
            "status_code": None,
            "error": str(exc),
        }
