"""Git v2 collector package.

Exports ``GitCollector`` which uses AWS CodeCommit as its change-management
evidence source. GitHub support is planned for a follow-up release.
"""

from collectors.git.collector import GitCollector

__all__ = ["GitCollector"]
