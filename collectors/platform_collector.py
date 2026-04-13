"""Platform v2 collector — probes internal service health endpoints.

Configuration accepts a ``services`` list describing which endpoints to
probe:

    {
      "services": [
        {
          "name": "maxgoodai-prod",
          "url": "https://api.example.com",
          "health_path": "/api/health",
          "auth": "none"    // or "bearer" / "basic"
        }
      ],
      "http_timeout_seconds": 10
    }

If a service requires bearer or basic auth, the credential is decrypted
from ``encrypted_credentials`` under keys ``bearer_token`` or
``basic_user``/``basic_password``. Credentials are shared across services
in v1; per-service credentials can be added later if needed.
"""

import logging
from typing import Any

from app.services.collector_encryption import decrypt_credentials
from collectors.base import BaseCollector, CheckResult

logger = logging.getLogger(__name__)


PLATFORM_REQUIRED_PERMISSIONS: list[str] = []


class PlatformCollector(BaseCollector):
    """HTTP health probes against configured internal services."""

    name = "platform"
    required_permissions = PLATFORM_REQUIRED_PERMISSIONS
    credential_modes_supported = ["none", "access_keys"]

    def run(self) -> list[CheckResult]:
        config_dict = self.config.config or {}
        services = config_dict.get("services") or []
        timeout = int(config_dict.get("http_timeout_seconds", 10))

        if not services:
            return [
                CheckResult(
                    check_name="platform_inventory",
                    status="fail",
                    target_test_name="Platform availability",
                    message="No services configured",
                    evidence_description=(
                        "No services defined in platform collector config"
                    ),
                )
            ]

        auth_creds: dict[str, Any] = {}
        if self.config.credential_mode == "access_keys":
            try:
                auth_creds = decrypt_credentials(self.config.encrypted_credentials)
            except Exception as exc:  # noqa: BLE001
                logger.exception("Failed to decrypt platform credentials")
                return [
                    CheckResult(
                        check_name="platform_credentials",
                        status="error",
                        message=f"Credential decryption failed: {exc}",
                    )
                ]

        try:
            import requests
        except ImportError:
            return [
                CheckResult(
                    check_name="platform_http",
                    status="error",
                    message="requests library is not installed",
                )
            ]

        results: list[CheckResult] = []
        for service in services:
            name = service.get("name") or service.get("url") or "unknown"
            url_base = (service.get("url") or "").rstrip("/")
            health_path = service.get("health_path") or "/"
            if not health_path.startswith("/"):
                health_path = "/" + health_path
            full_url = url_base + health_path
            auth_type = (service.get("auth") or "none").lower()

            if not url_base:
                results.append(
                    CheckResult(
                        check_name=f"platform_health:{name}",
                        status="error",
                        target_test_name="Platform availability",
                        message=f"Service {name} has no url configured",
                    )
                )
                continue

            headers: dict[str, str] = {}
            auth_tuple = None
            if auth_type == "bearer":
                token = auth_creds.get("bearer_token")
                if token:
                    headers["Authorization"] = f"Bearer {token}"
            elif auth_type == "basic":
                user = auth_creds.get("basic_user")
                pw = auth_creds.get("basic_password")
                if user and pw:
                    auth_tuple = (user, pw)

            try:
                resp = requests.get(
                    full_url,
                    headers=headers,
                    auth=auth_tuple,
                    timeout=timeout,
                    allow_redirects=True,
                )
                passed = 200 <= resp.status_code < 400
                results.append(
                    CheckResult(
                        check_name=f"platform_health:{name}",
                        status="pass" if passed else "fail",
                        target_test_name="Platform availability",
                        message=(
                            f"Service {name} ({full_url}): "
                            f"HTTP {resp.status_code}"
                        ),
                        detail={
                            "service": name,
                            "url": full_url,
                            "status_code": resp.status_code,
                            "elapsed_ms": int(resp.elapsed.total_seconds() * 1000),
                        },
                        evidence_description=(
                            f"Platform health probe {name}: HTTP {resp.status_code}"
                        ),
                    )
                )
            except Exception as exc:  # noqa: BLE001
                results.append(
                    CheckResult(
                        check_name=f"platform_health:{name}",
                        status="fail",
                        target_test_name="Platform availability",
                        message=(
                            f"Service {name} ({full_url}): probe failed: {exc}"
                        ),
                        detail={
                            "service": name,
                            "url": full_url,
                            "error": str(exc),
                        },
                        evidence_description=(
                            f"Platform health probe {name}: unreachable ({exc})"
                        ),
                    )
                )

        return results
