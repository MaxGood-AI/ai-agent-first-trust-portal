"""Git sources: read the governance and evidence repositories over provider APIs.

``app.services.git_sources.providers`` holds the provider abstraction
(``GitProvider``, ``build_provider``) that reads a branch of a repository
through the AWS CodeCommit API, the GitHub REST API or a plain local
directory, without a git binary and without a credential helper.
"""
