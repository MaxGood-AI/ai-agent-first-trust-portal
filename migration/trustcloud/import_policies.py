"""Import policies from TrustCloud into the local system.

Usage:
    python3 -m migration.import_policies

Fetches policy data from TrustCloud and creates corresponding
markdown files in policies/ and database records.
"""

import json
import os
import subprocess
import sys

TRUSTCLOUD_CLI = os.environ.get("TRUSTCLOUD_CLI", "trustcloud-api")

CATEGORY_MAP = {
    "security": "security",
    "privacy": "privacy",
    "availability": "availability",
    "confidentiality": "confidentiality",
    "processing integrity": "processing-integrity",
}


def fetch_policies():
    """Fetch all policies from TrustCloud."""
    result = subprocess.run(
        f"{TRUSTCLOUD_CLI} policies".split(),
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error fetching policies: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def main():
    print("Fetching policies from TrustCloud...")
    policies = fetch_policies()
    print(f"Found {len(policies)} policies")

    for policy in policies:
        title = policy.get("name", "Untitled Policy")
        slug = title.lower().replace(" ", "-").replace("/", "-")
        # Default to security if category unclear
        category_dir = "security"

        policy_path = f"policies/{category_dir}/{slug}.md"
        os.makedirs(os.path.dirname(policy_path), exist_ok=True)

        with open(policy_path, "w") as f:
            f.write(f"# {title}\n\n")
            f.write(f"**Status:** {policy.get('status', 'draft')}\n\n")
            f.write(f"**TrustCloud ID:** {policy.get('id', 'N/A')}\n\n")
            f.write("## Purpose\n\n")
            f.write("TODO: Migrate policy content from TrustCloud.\n\n")
            f.write("## Scope\n\n")
            f.write("TODO: Define scope.\n\n")
            f.write("## Policy\n\n")
            f.write("TODO: Migrate policy details.\n")

        print(f"Created: {policy_path}")

    print("Policy migration complete. Review and update content manually.")


if __name__ == "__main__":
    main()
