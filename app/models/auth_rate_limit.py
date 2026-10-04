"""Rate-limit counters: one row per (bucket, client, fixed window), shared by every process."""

from app.models import db


class AuthRateLimitWindow(db.Model):
    __tablename__ = "auth_rate_limit"

    id = db.Column(db.BigInteger().with_variant(db.Integer, "sqlite"), primary_key=True, autoincrement=True)
    bucket = db.Column(db.String(32), nullable=False, comment="login | client_login | setup")
    client_key = db.Column(db.String(128), nullable=False, comment="Client IP address")
    window_start = db.Column(db.DateTime(timezone=True), nullable=False,
                             comment="Start of the fixed rate-limit window")
    attempts = db.Column(db.Integer, nullable=False, default=0, server_default="0")

    __table_args__ = (
        db.UniqueConstraint("bucket", "client_key", "window_start", name="uq_auth_rate_limit_window"),
        db.Index("ix_auth_rate_limit_window_start", "window_start"),
    )
