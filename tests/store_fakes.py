"""Test helpers for the evidence store: a moto bucket with Object Lock and a
client wrapper that reports SHA-256 checksums the way S3 does.

moto stores no ``ChecksumSHA256`` for a ``PutObject`` and returns none from
``HeadObject`` / ``GetObject``. :class:`ChecksummingS3` records, per version,
the checksum a producer sent (the body's own SHA-256 by default, none, a
composite one, or any other value) and adds it to ``head_object`` and
``get_object`` responses, as S3 does with ``ChecksumMode=ENABLED`` (a
composite checksum with ``ChecksumType`` ``COMPOSITE``). It also
counts the calls per operation and key, so tests can show what was (not) read.

moto enforces a bucket policy on the requests it serves, and tests write and
delete versions the way a producer or an administrator would. The wrapper
therefore keeps each bucket's policy itself (``put_bucket_policy``,
``get_bucket_policy``, ``delete_bucket_policy``), which the portal reads
exactly as it reads S3's.
"""

from __future__ import annotations

import base64
import collections
import hashlib
import json

BUCKET = "evidence-store-test"


def b64_sha256(body: bytes) -> str:
    return base64.b64encode(hashlib.sha256(body).digest()).decode("ascii")


def composite_sha256(body: bytes, parts: int = 2) -> str:
    """The SHA-256 COMPOSITE checksum S3 stores for ``body`` uploaded in ``parts``
    parts with SHA-256 part checksums: the base64 SHA-256 of the parts' raw
    SHA-256 digests, then ``-<parts>``."""
    size = max(1, -(-len(body) // parts))
    digests = b"".join(hashlib.sha256(body[i * size:(i + 1) * size]).digest() for i in range(parts))
    return b64_sha256(digests) + f"-{parts}"


class ChecksummingS3:
    def __init__(self, client, bucket: str = BUCKET):
        self.client = client
        self.bucket = bucket
        self.checksums: dict[tuple[str, str], str | None] = {}
        self.calls = collections.Counter()
        self.head_overrides: dict[tuple[str, str], dict] = {}
        self.policies: dict[str, str] = {}
        self.lock_overrides: dict[str, dict] = {}

    def set_default_retention(self, bucket: str, retention: dict) -> None:
        """Report ``retention`` as the bucket's default retention (moto refuses to change
        the Object Lock configuration of a bucket holding objects; S3 does not)."""
        self.lock_overrides[bucket] = {"ObjectLockConfiguration": {
            "ObjectLockEnabled": "Enabled", "Rule": {"DefaultRetention": retention}}}

    def get_object_lock_configuration(self, Bucket):  # noqa: N803 - boto3 parameter names
        if Bucket in self.lock_overrides:
            return self.lock_overrides[Bucket]
        return self.client.get_object_lock_configuration(Bucket=Bucket)

    # -- the bucket policy (kept here: module docstring) --
    def put_bucket_policy(self, Bucket, Policy):  # noqa: N803 - boto3 parameter names
        self.policies[Bucket] = Policy

    def delete_bucket_policy(self, Bucket):  # noqa: N803
        self.policies.pop(Bucket, None)

    def get_bucket_policy(self, Bucket):  # noqa: N803
        from botocore.exceptions import ClientError

        if Bucket not in self.policies:
            raise ClientError({"Error": {"Code": "NoSuchBucketPolicy", "Message": "none"}}, "GetBucketPolicy")
        return {"Policy": self.policies[Bucket]}

    # -- producer side --
    def put(self, key: str, body: bytes, *, checksum="auto", metadata=None, content_type=None) -> str:
        """Store ``body`` at ``key``; returns the version id. ``checksum``:
        ``"auto"`` the body's SHA-256, None no checksum, ``"composite"`` the
        composite checksum of a two-part upload (:func:`composite_sha256`), or a
        value to report (reported as ``COMPOSITE`` when it holds a ``-``)."""
        kwargs = {"Bucket": self.bucket, "Key": key, "Body": body,
                  "ContentMD5": base64.b64encode(hashlib.md5(body).digest()).decode("ascii")}  # noqa: S324
        if metadata:
            kwargs["Metadata"] = metadata
        if content_type:
            kwargs["ContentType"] = content_type
        version_id = self.client.put_object(**kwargs)["VersionId"]
        if checksum == "auto":
            checksum = b64_sha256(body)
        elif checksum == "composite":
            checksum = composite_sha256(body)
        self.checksums[(key, version_id)] = checksum
        return version_id

    # -- the portal's side --
    def _add_checksum(self, response: dict, key: str, version_id: str | None) -> dict:
        version_id = version_id or response.get("VersionId")
        checksum = self.checksums.get((key, version_id))
        if checksum:
            response["ChecksumSHA256"] = checksum
            response["ChecksumType"] = "COMPOSITE" if "-" in checksum else "FULL_OBJECT"
        response.update(self.head_overrides.get((key, version_id), {}))
        return response

    def head_object(self, **kwargs):
        self.calls[("head_object", kwargs["Key"])] += 1
        response = self.client.head_object(**kwargs)
        return self._add_checksum(response, kwargs["Key"], kwargs.get("VersionId"))

    def get_object(self, **kwargs):
        self.calls[("get_object", kwargs["Key"])] += 1
        response = self.client.get_object(**kwargs)
        return self._add_checksum(response, kwargs["Key"], kwargs.get("VersionId"))

    def list_object_versions(self, **kwargs):
        self.calls[("list_object_versions", kwargs.get("Prefix"))] += 1
        return self.client.list_object_versions(**kwargs)

    def __getattr__(self, name):
        return getattr(self.client, name)

    def reads(self, key: str) -> int:
        return self.calls[("get_object", key)]


PROTECTED_ACTIONS = ["s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
                     "s3:BypassGovernanceRetention"]


WRITER_ROLE = "arn:aws:iam::111122223333:role/evidence-writer"
STORE_PREFIXES = ("decision-logs/", "pentest-evidence/", "codex-reviews/", "pentest-reports/", "evidence/artifacts/")


def bucket_policy(bucket: str = BUCKET, *, erasure_principal: str | None = None, actions=None,
                  if_none_match: bool = True, delete_condition=None, writer_role: str | None = WRITER_ROLE) -> dict:
    """The evidence bucket's policy as the stack writes it (deploy/aws/trust-portal.yaml): with
    ``writer_role``, only that role writes the store prefixes."""
    arn = f"arn:aws:s3:::{bucket}"
    statements = [
        {"Sid": "DenyInsecureTransport", "Effect": "Deny", "Principal": "*", "Action": "s3:*",
         "Resource": [arn, f"{arn}/*"], "Condition": {"Bool": {"aws:SecureTransport": "false"}}},
    ]
    if writer_role:
        statements.append({"Sid": "OnlyTheWriterRoleWritesEvidence", "Effect": "Deny", "Principal": "*",
                           "Action": "s3:PutObject", "Resource": [f"{arn}/{prefix}*" for prefix in STORE_PREFIXES],
                           "Condition": {"ArnNotEquals": {"aws:PrincipalArn": writer_role}}})
    if if_none_match:
        statements.append({"Sid": "DenyWriteWithoutIfNoneMatch", "Effect": "Deny", "Principal": "*",
                           "Action": "s3:PutObject", "Resource": f"{arn}/*",
                           "Condition": {"Null": {"s3:if-none-match": "true"},
                                         "Bool": {"s3:ObjectCreationOperation": "true"}}})
    deny = {"Sid": "DenyDeletesAndRetentionChanges", "Effect": "Deny", "Principal": "*",
            "Action": list(PROTECTED_ACTIONS if actions is None else actions), "Resource": f"{arn}/*"}
    if erasure_principal:
        deny["Condition"] = {"ArnNotEquals": {"aws:PrincipalArn": erasure_principal}}
    elif delete_condition:
        deny["Condition"] = delete_condition
    statements.append(deny)
    return {"Version": "2012-10-17", "Statement": statements}


def make_bucket(client, bucket: str = BUCKET, *, retention: bool = True, policy: bool = True) -> None:
    """A bucket with versioning and Object Lock (default GOVERNANCE retention of 7 years) and the
    stack's bucket policy (``client`` is a :class:`ChecksummingS3`, which keeps the policy)."""
    client.create_bucket(Bucket=bucket, ObjectLockEnabledForBucket=True)
    if retention:
        client.put_object_lock_configuration(Bucket=bucket, ObjectLockConfiguration={
            "ObjectLockEnabled": "Enabled",
            "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Years": 7}}})
    if policy:
        client.put_bucket_policy(Bucket=bucket, Policy=json.dumps(bucket_policy(bucket)))
