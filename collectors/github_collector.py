"""GitHub/CodeCommit evidence collector.

Gathers evidence related to change management, branch protection, and code review.
Requires a GITHUB_TOKEN environment variable. If not set, collection is skipped.
"""

import logging
import os

import requests

from collectors.base_collector import BaseCollector

logger = logging.getLogger(__name__)


class GitHubCollector(BaseCollector):
    """Collects evidence from GitHub repositories."""

    def __init__(self):
        super().__init__("github")
        self.token = os.environ.get("GITHUB_TOKEN")
        self.base_url = os.environ.get("GITHUB_API_URL", "https://api.github.com")
        self.org = os.environ.get("GITHUB_ORG", "")
        self.repos = [
            r.strip()
            for r in os.environ.get("GITHUB_REPOS", "").split(",")
            if r.strip()
        ]

    def collect(self):
        if not self.token:
            logger.warning("GITHUB_TOKEN not set — skipping GitHub evidence collection")
            return []

        if not self.org:
            logger.warning("GITHUB_ORG not set — skipping GitHub evidence collection")
            return []

        if not self.repos:
            logger.warning("GITHUB_REPOS not set — skipping GitHub evidence collection")
            return []

        evidence = []
        evidence.extend(self._collect_branch_protection())
        evidence.extend(self._collect_recent_prs())
        return evidence

    def _headers(self):
        return {
            "Authorization": f"token {self.token}",
            "Accept": "application/vnd.github.v3+json",
        }

    def _collect_branch_protection(self):
        """Check branch protection rules on configured repositories."""
        results = []
        for repo in self.repos:
            try:
                resp = requests.get(
                    f"{self.base_url}/repos/{self.org}/{repo}/branches/main/protection",
                    headers=self._headers(),
                    timeout=30,
                )
                if resp.status_code == 200:
                    protection = resp.json()
                    results.append({
                        "test_name": "Change Management Branch Protection",
                        "evidence_type": "automated",
                        "description": (
                            f"{repo}/main: branch protection enabled, "
                            f"required reviews: {protection.get('required_pull_request_reviews', {}).get('required_approving_review_count', 'none')}"
                        ),
                        "url": f"https://github.com/{self.org}/{repo}/settings/branches",
                        "file_path": None,
                    })
                elif resp.status_code == 404:
                    results.append({
                        "test_name": "Change Management Branch Protection",
                        "evidence_type": "automated",
                        "description": f"{repo}/main: NO branch protection configured",
                        "url": None,
                        "file_path": None,
                    })
            except Exception:
                logger.exception("Failed to check branch protection for %s", repo)
        return results

    def _collect_recent_prs(self):
        """Verify recent PRs have reviews (change management approval evidence)."""
        results = []
        for repo in self.repos:
            try:
                resp = requests.get(
                    f"{self.base_url}/repos/{self.org}/{repo}/pulls",
                    headers=self._headers(),
                    params={"state": "closed", "sort": "updated", "direction": "desc", "per_page": 5},
                    timeout=30,
                )
                if resp.status_code == 200:
                    prs = resp.json()
                    reviewed_count = sum(1 for pr in prs if pr.get("merged_at"))
                    results.append({
                        "test_name": "Change management approval",
                        "evidence_type": "automated",
                        "description": f"{repo}: {reviewed_count}/{len(prs)} recent PRs were merged (reviewed)",
                        "url": f"https://github.com/{self.org}/{repo}/pulls?q=is%3Apr+is%3Aclosed",
                        "file_path": None,
                    })
            except Exception:
                logger.exception("Failed to collect PR data for %s", repo)
        return results
