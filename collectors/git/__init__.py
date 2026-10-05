"""Git collector package.

Exports ``GitCollector``, which reads change-management evidence from AWS
CodeCommit: every commit on each in-scope repository's default branch carries
a structured ``## Problem`` / ``## Solution`` / ``## Verified`` message.
"""

from collectors.git.collector import GitCollector

__all__ = ["GitCollector"]
