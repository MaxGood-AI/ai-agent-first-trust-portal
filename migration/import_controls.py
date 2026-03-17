"""Import controls and tests from TrustCloud into the local database.

Usage:
    python3 -m migration.import_controls

Requires TRUSTCLOUD_API_KEY in the environment or .env file.
Uses the TrustCloud API via the trust-cloud skill's CLI script.
"""

import json
import subprocess
import sys
import uuid

TRUSTCLOUD_CLI = "python3 /Users/mishkinberteig/.claude/skills/trust-cloud/scripts/trustcloud_api.py"

# Mapping of TrustCloud control names to TSC categories.
# This is a starting heuristic — controls should be reviewed and re-categorized manually.
CATEGORY_KEYWORDS = {
    "security": [
        "mfa", "multi-factor", "password", "access", "firewall", "encryption",
        "incident", "sso", "single sign", "penetration", "security", "host hardening",
        "patch", "tls", "ssh", "tcp", "port", "administrative",
    ],
    "availability": [
        "backup", "restore", "disaster", "bcdr", "business continuity", "uptime",
    ],
    "confidentiality": [
        "confidential", "data in transit", "encryption documentation",
    ],
    "privacy": [
        "privacy", "gdpr", "personal", "data subject",
    ],
    "processing_integrity": [
        "change management", "release", "deployment", "sdlc", "code review",
        "infrastructure-as-code", "separation of environments",
    ],
}


def classify_control(control_name):
    """Classify a control into a TSC category based on name keywords."""
    name_lower = control_name.lower()
    for category, keywords in CATEGORY_KEYWORDS.items():
        if any(kw in name_lower for kw in keywords):
            return category
    return "security"  # Default fallback


def fetch_trustcloud_controls():
    """Fetch all controls from TrustCloud."""
    result = subprocess.run(
        f"{TRUSTCLOUD_CLI} controls".split(),
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error fetching controls: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def fetch_trustcloud_tests():
    """Fetch all tests from TrustCloud."""
    result = subprocess.run(
        f"{TRUSTCLOUD_CLI} tests".split(),
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error fetching tests: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def main():
    print("Fetching controls from TrustCloud...")
    controls_data = fetch_trustcloud_controls()
    print(f"Found {len(controls_data)} controls")

    print("Fetching tests from TrustCloud...")
    tests_data = fetch_trustcloud_tests()
    print(f"Found {len(tests_data)} tests")

    # Build import structure
    controls = []
    for tc_control in controls_data:
        control = {
            "id": str(uuid.uuid4()),
            "trustcloud_id": tc_control.get("id"),
            "name": tc_control.get("name", "Unknown"),
            "description": tc_control.get("description", ""),
            "category": classify_control(tc_control.get("name", "")),
            "state": tc_control.get("state", "adopted"),
        }
        controls.append(control)

    tests = []
    for tc_test in tests_data:
        test = {
            "id": str(uuid.uuid4()),
            "trustcloud_id": tc_test.get("id"),
            "name": tc_test.get("name", "Unknown"),
            "question": tc_test.get("question", ""),
            "recommendation": tc_test.get("recommendation", ""),
            "evidence_status": tc_test.get("evidenceStatus", "missing"),
        }
        tests.append(test)

    # Output for review before import
    output = {"controls": controls, "tests": tests}
    output_path = "migration/trustcloud_export.json"
    with open(output_path, "w") as f:
        json.dump(output, f, indent=2)
    print(f"Export written to {output_path}")
    print("Review the export, then run import_to_db.py to load into PostgreSQL.")


if __name__ == "__main__":
    main()
