"""Optional TrustCloud migration helpers.

These scripts import data from TrustCloud's API into the local system.
They are not required for normal operation — the primary data import
path is `python -m cli.init --data-dir /path/to/data`.

Requires TRUSTCLOUD_CLI environment variable pointing to a TrustCloud
API client script, and TRUSTCLOUD_API_KEY for authentication.
"""
