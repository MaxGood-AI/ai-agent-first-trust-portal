"""Git sources: repositories the portal pulls governance documents and
evidence from.

- ``GitSource``: one configured repository. ``role`` is ``governance``
  (policies, agent instructions, infrastructure docs; stored as versioned
  documents) or ``evidence`` (the evidence repo; imported into the compliance
  tables by the diff-only import engine). ``provider`` is ``codecommit``,
  ``github`` or ``local``.
- ``GitSourceFile``: every mapped path the source has seen, with the blob it
  was last synced at. Makes syncs resumable and diff-only.
- ``GitFileVersion``: stored content of governance files, one row per
  distinct blob, keyed by the commit that introduced it.
- ``GitCommit``: change records - commits that touched mapped paths.
- ``GitSyncRun``: one row per sync, with its commit range and counts.
"""

from datetime import datetime, timezone

from app.models import db


def _now():
    return datetime.now(timezone.utc)


ROLES = ("governance", "evidence")
PROVIDERS = ("codecommit", "github", "local")
CREDENTIAL_MODES = {
    "codecommit": ("runtime_role", "assume_role"),
    "github": ("portal_secret", "stored_token", "none"),
    "local": ("none",),
}


class GitSource(db.Model):
    __tablename__ = "git_sources"

    id = db.Column(db.String(36), primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    role = db.Column(db.String(16), nullable=False, comment="governance | evidence")
    provider = db.Column(db.String(16), nullable=False, comment="codecommit | github | local")
    repository = db.Column(db.String(500), nullable=False,
                           comment="CodeCommit repository name, GitHub owner/name, or local directory path")
    branch = db.Column(db.String(255), nullable=False, default="main")
    region = db.Column(db.String(32), comment="AWS region (CodeCommit); defaults to AWS_REGION")
    credential_mode = db.Column(db.String(32), nullable=False, default="runtime_role")
    encrypted_credentials = db.Column(db.LargeBinary,
                                      comment="Fernet JSON: {role_arn, external_id} or {token}")
    path_mappings = db.Column(db.JSON, comment="[{pattern, kind}]; NULL = the role's defaults")
    options = db.Column(db.JSON, comment="{record_commits, history_limit, api_url}")
    schedule_cron = db.Column(db.String(64))
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_synced_commit = db.Column(db.String(64))
    last_synced_at = db.Column(db.DateTime(timezone=True))
    last_sync_status = db.Column(db.String(16))
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)
    created_by_id = db.Column(db.String(36), db.ForeignKey("team_members.id"))
    updated_by_id = db.Column(db.String(36), db.ForeignKey("team_members.id"))

    files = db.relationship("GitSourceFile", backref="source", lazy="dynamic",
                            cascade="all, delete-orphan")
    runs = db.relationship("GitSyncRun", backref="source", lazy="dynamic",
                           cascade="all, delete-orphan")

    def __repr__(self):
        return f"<GitSource {self.name} {self.role}/{self.provider}>"


class GitSourceFile(db.Model):
    __tablename__ = "git_source_files"

    id = db.Column(db.String(36), primary_key=True)
    source_id = db.Column(db.String(36), db.ForeignKey("git_sources.id"), nullable=False)
    path = db.Column(db.String(1024), nullable=False)
    kind = db.Column(db.String(64), nullable=False,
                     comment="policy | governance_document | dataset:<name> | decision_log")
    blob_id = db.Column(db.String(64), comment="Provider blob id the file was last processed at")
    size = db.Column(db.BigInteger)
    status = db.Column(db.String(16), nullable=False, default="ok",
                       comment="ok | incomplete | too_large | error | deleted")
    status_detail = db.Column(db.Text)
    last_commit_id = db.Column(db.String(64))
    current_version_id = db.Column(db.String(36), comment="GitFileVersion holding the current content")
    updated_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now, onupdate=_now)

    versions = db.relationship("GitFileVersion", backref="file", lazy="dynamic",
                               cascade="all, delete-orphan",
                               order_by="GitFileVersion.created_at.desc()")

    __table_args__ = (db.UniqueConstraint("source_id", "path", name="uq_git_source_files_path"),)


class GitFileVersion(db.Model):
    __tablename__ = "git_file_versions"

    id = db.Column(db.String(36), primary_key=True)
    file_id = db.Column(db.String(36), db.ForeignKey("git_source_files.id"), nullable=False)
    commit_id = db.Column(db.String(64), nullable=False, comment="Commit at which this content was synced")
    blob_id = db.Column(db.String(64), nullable=False)
    sha256 = db.Column(db.String(64), nullable=False)
    size = db.Column(db.BigInteger, nullable=False)
    content = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)

    __table_args__ = (db.UniqueConstraint("file_id", "blob_id", name="uq_git_file_versions_blob"),)


class GitCommit(db.Model):
    __tablename__ = "git_commits"

    id = db.Column(db.String(36), primary_key=True)
    source_id = db.Column(db.String(36), db.ForeignKey("git_sources.id"), nullable=False)
    commit_id = db.Column(db.String(64), nullable=False)
    parent_ids = db.Column(db.JSON)
    author_name = db.Column(db.String(255))
    author_email = db.Column(db.String(255))
    authored_at = db.Column(db.DateTime(timezone=True))
    committer_name = db.Column(db.String(255))
    committer_email = db.Column(db.String(255))
    committed_at = db.Column(db.DateTime(timezone=True))
    message = db.Column(db.Text)
    paths = db.Column(db.JSON, comment="Mapped paths this commit changed")
    recorded_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)

    __table_args__ = (db.UniqueConstraint("source_id", "commit_id", name="uq_git_commits_commit"),)


class GitSyncRun(db.Model):
    __tablename__ = "git_sync_runs"

    id = db.Column(db.String(36), primary_key=True)
    source_id = db.Column(db.String(36), db.ForeignKey("git_sources.id"), nullable=False)
    trigger_type = db.Column(db.String(16), nullable=False, default="manual",
                             comment="scheduled | manual | api")
    triggered_by_team_member_id = db.Column(db.String(36), db.ForeignKey("team_members.id"))
    status = db.Column(db.String(16), nullable=False, default="queued",
                       comment="queued | running | success | partial | failure | unchanged")
    from_commit = db.Column(db.String(64))
    to_commit = db.Column(db.String(64))
    queued_at = db.Column(db.DateTime(timezone=True), nullable=False, default=_now)
    started_at = db.Column(db.DateTime(timezone=True))
    finished_at = db.Column(db.DateTime(timezone=True))
    files_changed = db.Column(db.Integer, nullable=False, default=0)
    counts = db.Column(db.JSON, comment="{created, updated, unchanged, deleted, skipped, flagged}")
    details = db.Column(db.JSON, comment="Per-kind counts and flagged files")
    error_message = db.Column(db.Text)
    heartbeat_at = db.Column(db.DateTime(timezone=True),
                             comment="Refreshed by the executing process while it holds the run's lock")
    executor_token = db.Column(db.String(36), comment="Executor allowed to record this run's result")

    __table_args__ = (
        db.Index(
            "uq_git_sync_runs_one_active",
            "source_id",
            unique=True,
            postgresql_where=db.text("status IN ('queued', 'running')"),
            sqlite_where=db.text("status IN ('queued', 'running')"),
        ),
    )
