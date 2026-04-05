"""Import evidence history from TrustCloud.

Usage:
    python3 -m migration.import_evidence

Fetches evidence submission history for all tests and exports
to a JSON file for review before database import.
"""

import json
import os
import subprocess
import sys

TRUSTCLOUD_CLI = os.environ.get("TRUSTCLOUD_CLI", "trustcloud-api")


def fetch_tests():
    """Fetch all tests to get their IDs."""
    result = subprocess.run(
        f"{TRUSTCLOUD_CLI} tests".split(),
        capture_output=True, text=True
    )
    if result.returncode != 0:
        print(f"Error fetching tests: {result.stderr}", file=sys.stderr)
        sys.exit(1)
    return json.loads(result.stdout)


def fetch_evidence_history(test_id):
    """Fetch evidence history for a specific test."""
    result = subprocess.run(
        f"{TRUSTCLOUD_CLI} evidence-history --id {test_id}".split(),
        capture_output=True, text=True
    )
    if result.returncode != 0:
        return []
    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError:
        return []


def main():
    print("Fetching tests from TrustCloud...")
    tests = fetch_tests()
    print(f"Found {len(tests)} tests")

    all_evidence = []
    for i, test in enumerate(tests):
        test_id = test.get("id")
        if not test_id:
            continue
        print(f"  [{i + 1}/{len(tests)}] Fetching evidence for: {test.get('name', 'Unknown')}")
        history = fetch_evidence_history(test_id)
        if history:
            all_evidence.append({
                "test_id": test_id,
                "test_name": test.get("name"),
                "evidence_history": history,
            })

    output_path = "migration/trustcloud_evidence_export.json"
    with open(output_path, "w") as f:
        json.dump(all_evidence, f, indent=2)

    total_items = sum(len(e["evidence_history"]) for e in all_evidence)
    print(f"\nExported {total_items} evidence items across {len(all_evidence)} tests")
    print(f"Written to {output_path}")


if __name__ == "__main__":
    main()
