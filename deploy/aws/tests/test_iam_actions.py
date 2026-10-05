"""The IAM grants match what the code calls, and every action name is real.

The AWS operations are derived from the source with `ast`: clients created with
`<x>.client("<service>")` (assigned or chained), their method calls, their
paginators, and the CodeCommit git-source provider's `self._call("<op>")`. In
the evidence store package every call of an S3 client method name (from
botocore's S3 model) counts, whatever the receiver is called.
OPERATION_ACTIONS maps each operation to the IAM action that authorizes it,
taken from the Service Authorization Reference; where the API name and the
action name differ (for example S3 GetBucketEncryption, authorized by
s3:GetEncryptionConfiguration) the table records the action. An operation the
table does not know fails the test, so a new call is mapped deliberately.
"""
import ast
import json
import re
import unittest
from pathlib import Path

AWS_DIR = Path(__file__).resolve().parent.parent
REPO = AWS_DIR.parent.parent
TEMPLATE = (AWS_DIR / "trust-portal.yaml").read_text()
ALL_TEMPLATES = TEMPLATE + (AWS_DIR / "trust-portal-pipeline.yaml").read_text()
POLICY = json.loads((REPO / "iam" / "trust-portal-collector-policy.json").read_text())

# Code the collector policy serves: the collectors and the permission check.
COLLECTOR_SOURCES = sorted((REPO / "collectors").rglob("*.py")) + [REPO / "app" / "services" / "permission_prober.py"]
PROVIDER_SOURCE = REPO / "app" / "services" / "git_sources" / "providers.py"
# Witness and archive code; its S3 clients are passed in as `client`.
WITNESS_SOURCES = [REPO / "app" / "services" / "audit_witness.py", REPO / "app" / "services" / "audit_archive.py"]
OPERATOR_POLICY = json.loads((REPO / "iam" / "trust-portal-archive-operator-policy.json").read_text())
# Evidence store code: every module of the package reads the bucket through the runtime role.
EVIDENCE_STORE_DIR = REPO / "app" / "services" / "evidence_store"
# The operations the evidence store calls; the runtime role holds exactly their actions on the bucket.
EVIDENCE_STORE_OPERATIONS = {("s3", "list_object_versions"), ("s3", "head_object"), ("s3", "get_object"),
                             ("s3", "get_bucket_versioning"), ("s3", "get_object_lock_configuration"),
                             ("s3", "get_bucket_policy"), ("s3", "get_bucket_lifecycle_configuration")}

OPERATION_ACTIONS = {
    ("sts", "get_caller_identity"): "sts:GetCallerIdentity",
    ("iam", "list_users"): "iam:ListUsers",
    ("iam", "list_access_keys"): "iam:ListAccessKeys",
    ("iam", "list_mfa_devices"): "iam:ListMFADevices",
    ("iam", "list_virtual_mfa_devices"): "iam:ListVirtualMFADevices",
    ("iam", "get_account_password_policy"): "iam:GetAccountPasswordPolicy",
    ("rds", "describe_db_instances"): "rds:DescribeDBInstances",
    ("s3", "list_buckets"): "s3:ListAllMyBuckets",
    ("s3", "get_bucket_encryption"): "s3:GetEncryptionConfiguration",
    ("s3", "get_bucket_replication"): "s3:GetReplicationConfiguration",
    ("s3", "get_bucket_versioning"): "s3:GetBucketVersioning",
    ("s3", "get_public_access_block"): "s3:GetBucketPublicAccessBlock",
    ("cloudtrail", "describe_trails"): "cloudtrail:DescribeTrails",
    ("cloudtrail", "get_trail_status"): "cloudtrail:GetTrailStatus",
    ("codecommit", "list_repositories"): "codecommit:ListRepositories",
    ("codecommit", "get_repository"): "codecommit:GetRepository",
    ("codecommit", "get_branch"): "codecommit:GetBranch",
    ("codecommit", "get_commit"): "codecommit:GetCommit",
    ("codecommit", "get_differences"): "codecommit:GetDifferences",
    ("codecommit", "get_file"): "codecommit:GetFile",
    ("codecommit", "get_blob"): "codecommit:GetBlob",
    # Witness and archive calls (app/services/audit_witness.py, audit_archive.py).
    ("s3", "put_object"): "s3:PutObject",
    ("s3", "get_object"): ("s3:GetObject", "s3:GetObjectVersion"),  # reads pinned versions
    ("s3", "list_object_versions"): "s3:ListBucketVersions",
    ("s3", "create_multipart_upload"): "s3:PutObject",
    ("s3", "upload_part"): "s3:PutObject",
    ("s3", "complete_multipart_upload"): "s3:PutObject",
    ("s3", "abort_multipart_upload"): "s3:AbortMultipartUpload",
    # Evidence store reads (app/services/evidence_store/). HeadObject returns a version's
    # Object Lock mode and retain-until date only to a caller holding s3:GetObjectRetention.
    ("s3", "head_object"): ("s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"),
    ("s3", "get_object_lock_configuration"): "s3:GetBucketObjectLockConfiguration",
    # The portal checks the bucket policy's denials and that no lifecycle rule expires or
    # transitions an object; GetBucketLifecycleConfiguration is authorized by s3:GetLifecycleConfiguration.
    ("s3", "get_bucket_policy"): "s3:GetBucketPolicy",
    ("s3", "get_bucket_lifecycle_configuration"): "s3:GetLifecycleConfiguration",
}

# API names that are not IAM actions; the real action is in OPERATION_ACTIONS.
NOT_IAM_ACTIONS = {"s3:GetBucketEncryption", "s3:GetBucketReplication", "s3:ListBuckets",
                   "s3:GetPublicAccessBlock", "s3:GetBucketLifecycleConfiguration"}


def _client_service(node):
    if (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "client"
            and node.args and isinstance(node.args[0], ast.Constant) and isinstance(node.args[0].value, str)):
        return node.args[0].value
    return None


def called_operations(paths):
    """Return {(service, operation)} called on boto3 clients in the given files."""
    operations = set()
    for path in paths:
        tree = ast.parse(path.read_text(), str(path))
        bound = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign) and _client_service(node.value):
                for target in node.targets:
                    bound[ast.unparse(target)] = _client_service(node.value)
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            receiver = node.func.value
            service = _client_service(receiver) or bound.get(ast.unparse(receiver))
            if service is None:
                continue
            operation = node.func.attr
            if operation == "get_paginator" and node.args and isinstance(node.args[0], ast.Constant):
                operation = node.args[0].value
            operations.add((service, operation))
    return operations


def provider_operations():
    """Return the CodeCommit operations CodeCommitProvider sends through self._call."""
    tree = ast.parse(PROVIDER_SOURCE.read_text(), str(PROVIDER_SOURCE))
    provider = next(n for n in ast.walk(tree) if isinstance(n, ast.ClassDef) and n.name == "CodeCommitProvider")
    return {("codecommit", n.args[0].value) for n in ast.walk(provider)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == "_call"
            and n.args and isinstance(n.args[0], ast.Constant)}


def to_actions(operations):
    unknown = sorted(op for op in operations if op not in OPERATION_ACTIONS)
    if unknown:
        raise AssertionError("map these operations in OPERATION_ACTIONS: %s" % unknown)
    actions = set()
    for op in operations:
        mapped = OPERATION_ACTIONS[op]
        actions.update([mapped] if isinstance(mapped, str) else mapped)
    return actions


def policy_actions(policy):
    return {action for statement in policy["Statement"] for action in statement["Action"]}


def template_statement_actions(sid):
    lines = TEMPLATE.split("\n")
    start = next(i for i, line in enumerate(lines) if line.strip() == "- Sid: %s" % sid)
    action_line = next(line for line in lines[start:start + 4] if "Action:" in line)
    return set(re.findall(r"'([^']+)'", action_line)) or {action_line.split("Action:")[1].strip()}


class CollectorPolicyMatchesCodeTests(unittest.TestCase):
    def test_collector_policy_grants_exactly_what_the_collectors_call(self):
        called = to_actions(called_operations(COLLECTOR_SOURCES))
        self.assertEqual(policy_actions(POLICY), called)

    def test_git_source_statement_grants_exactly_what_the_provider_calls(self):
        called = to_actions(provider_operations())
        self.assertEqual(template_statement_actions("GitSourceRead"), called)

    def test_scan_finds_the_calls_it_is_meant_to_find(self):
        operations = called_operations(COLLECTOR_SOURCES)
        self.assertIn(("s3", "get_bucket_encryption"), operations)
        self.assertIn(("codecommit", "get_commit"), operations)
        self.assertIn(("codecommit", "get_file"), provider_operations())


def witness_operations():
    """Return the S3 operations the witness and archive code call on its clients."""
    operations = set()
    for path in WITNESS_SOURCES:
        tree = ast.parse(path.read_text(), str(path))
        for node in ast.walk(tree):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            if not ast.unparse(node.func.value).endswith("client"):
                continue
            operation = node.func.attr
            if operation == "get_paginator" and node.args and isinstance(node.args[0], ast.Constant):
                operation = node.args[0].value
            operations.add(("s3", operation))
    return operations


def runtime_s3_allow_statements():
    """Return {Sid: statement text} of the runtime role's block-YAML Allow statements naming S3 actions."""
    from test_template import resource_block, statement_block
    runtime = resource_block("RuntimeRole")
    statements = {}
    for sid in re.findall(r"^\s+- Sid: (\w+)$", runtime, re.MULTILINE):
        statement = statement_block(runtime, sid)
        if "Effect: Allow" in statement and "s3:" in statement:
            statements[sid] = statement
    return statements


def runtime_s3_allows(bucket=None):
    """The S3 actions the runtime role's Allow statements grant, on one bucket (logical id) or on any."""
    actions = set()
    for statement in runtime_s3_allow_statements().values():
        if bucket is None or "%s.Arn" % bucket in statement:
            actions |= set(re.findall(r"'(s3:[A-Z]\w+)'", statement))
            actions |= set(re.findall(r"Action: (s3:[A-Z]\w+)\s*$", statement, re.MULTILINE))
    return actions


# boto3 adds these managed-transfer methods to every S3 client.
S3_TRANSFER_METHODS = {"upload_file", "upload_fileobj", "download_file", "download_fileobj"}


def s3_method_names():
    """Every S3 client method name: botocore's S3 operations, snake_cased, and the transfer methods."""
    import botocore.session
    from botocore import xform_name
    model = botocore.session.get_session().get_service_model("s3")
    # CreateSession serves S3 Express directory buckets only; the name is common in other code.
    return {xform_name(name) for name in model.operation_names} - {"create_session"} | S3_TRANSFER_METHODS


def s3_operations_in(sources):
    """Return {("s3", operation)} for every call of an S3 client method name in the given source texts.

    The receiver's name does not matter, so a client passed in, stored on `self` or
    wrapped is still seen; `get_paginator("<op>")` counts as that operation.
    """
    names = s3_method_names()
    operations = set()
    for source in sources:
        for node in ast.walk(ast.parse(source)):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)):
                continue
            operation = node.func.attr
            if operation == "get_paginator" and node.args and isinstance(node.args[0], ast.Constant):
                operation = node.args[0].value
            if operation in names:
                operations.add(("s3", operation))
    return operations


def uses_an_aws_client(source):
    """Whether code creates a client (`.client(`, `get_session(`) or calls a method on one (`*client`, `*s3`)."""
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            if node.func.attr in ("client", "get_session"):
                return True
            if ast.unparse(node.func.value).lower().endswith(("client", "s3")):
                return True
    return False


def evidence_store_sources():
    return sorted(EVIDENCE_STORE_DIR.rglob("*.py")) if EVIDENCE_STORE_DIR.is_dir() else []


def evidence_store_operations():
    """S3 operations by method name, plus the calls on any other service's client the package creates."""
    paths = evidence_store_sources()
    other_services = {op for op in called_operations(paths) if op[0] != "s3"}
    return s3_operations_in([path.read_text() for path in paths]) | other_services


class WitnessGrantsMatchCodeTests(unittest.TestCase):
    def test_operator_policy_grants_exactly_what_the_witness_and_archive_code_calls(self):
        self.assertEqual(policy_actions(OPERATOR_POLICY), to_actions(witness_operations()))

    def test_runtime_role_holds_only_the_serving_subset(self):
        serving = to_actions({("s3", "put_object"), ("s3", "get_object"), ("s3", "list_object_versions")})
        self.assertLessEqual(serving, to_actions(witness_operations()))
        self.assertEqual(runtime_s3_allows("ArchiveBucket"), serving)

    def test_every_runtime_s3_grant_names_exactly_one_bucket(self):
        statements = runtime_s3_allow_statements()
        self.assertTrue(statements)
        for sid, statement in statements.items():
            buckets = [b for b in ("ArchiveBucket", "EvidenceBucket") if "%s.Arn" % b in statement]
            self.assertEqual(len(buckets), 1, sid)
        self.assertEqual(runtime_s3_allows(), runtime_s3_allows("ArchiveBucket") | runtime_s3_allows("EvidenceBucket"))

    def test_scan_sees_the_multipart_upload(self):
        operations = witness_operations()
        for op in ("create_multipart_upload", "upload_part", "complete_multipart_upload", "abort_multipart_upload"):
            self.assertIn(("s3", op), operations)


class EvidenceStoreGrantsMatchCodeTests(unittest.TestCase):
    """The runtime role reads the evidence store with exactly what app/services/evidence_store/ calls."""

    def test_runtime_role_grants_exactly_the_evidence_store_reads(self):
        self.assertEqual(runtime_s3_allows("EvidenceBucket"), to_actions(EVIDENCE_STORE_OPERATIONS))
        self.assertEqual(runtime_s3_allows("EvidenceBucket"),
                         {"s3:ListBucketVersions", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
                          "s3:GetBucketPolicy", "s3:GetLifecycleConfiguration",
                          "s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"})

    def test_evidence_store_code_calls_only_the_granted_operations(self):
        called = evidence_store_operations()
        self.assertEqual(called - EVIDENCE_STORE_OPERATIONS, set(),
                         "a new evidence store call: map it, grant it and add it to EVIDENCE_STORE_OPERATIONS")
        self.assertLessEqual(to_actions(called), runtime_s3_allows("EvidenceBucket"))

    def test_scan_sees_the_listing_once_the_package_uses_a_client(self):
        sources = [path.read_text() for path in evidence_store_sources()]
        if any(uses_an_aws_client(source) for source in sources):
            self.assertIn(("s3", "list_object_versions"), evidence_store_operations())

    def test_client_use_is_detected(self):
        self.assertTrue(uses_an_aws_client("s3 = aws_session.get_session().client('s3')"))
        self.assertTrue(uses_an_aws_client("def f(client):\n    return client.anything(Bucket=b)"))
        self.assertTrue(uses_an_aws_client("def f(self):\n    return self._s3.anything(Bucket=b)"))
        self.assertFalse(uses_an_aws_client('"""Calls list_object_versions on a client."""\nPREFIXES = ("a/",)'))

    def test_scan_finds_s3_calls_whatever_the_client_is_called(self):
        source = "\n".join([
            "def sync(store, session):",
            "    page = store._s3.list_object_versions(Bucket=b, Prefix=p)",
            "    head = self.client.head_object(Bucket=b, Key=k, VersionId=v, ChecksumMode='ENABLED')",
            "    pages = s3.get_paginator('list_object_versions').paginate(Bucket=b)",
            "    lock = session.client('s3').get_object_lock_configuration(Bucket=b)",
            "    record = dict(metadata).copy()",
            "    values.update(other)",
            "    s3.download_file(b, k, path)",
        ])
        self.assertEqual(s3_operations_in([source]),
                         {("s3", "list_object_versions"), ("s3", "head_object"),
                          ("s3", "get_object_lock_configuration"), ("s3", "download_file")})
        with self.assertRaises(AssertionError):
            to_actions(s3_operations_in([source]))  # download_file is not mapped: a new call fails the test


class ActionNameTests(unittest.TestCase):
    def all_template_actions(self):
        found = set(re.findall(r"'([a-z0-9-]+:[A-Za-z*]+)'", ALL_TEMPLATES))
        found |= set(re.findall(r'"([a-z0-9-]+:[A-Za-z*]+)"', ALL_TEMPLATES))
        found |= set(re.findall(r"Action: ([a-z0-9-]+:[A-Za-z*]+)\s*$", ALL_TEMPLATES, re.MULTILINE))
        return {a for a in found if not a.startswith(("aws:", "arn:", "sts:ExternalId", "kms:ViaService"))}

    def test_no_api_name_is_used_as_an_action(self):
        for action in policy_actions(POLICY) | self.all_template_actions():
            self.assertNotIn(action, NOT_IAM_ACTIONS, action)

    def test_runtime_role_holds_no_unused_service_reads(self):
        for prefix in ("ec2:", "elasticloadbalancing:", "ecs:", "elasticache:", "acm:", "kms:List", "kms:Get"):
            for action in policy_actions(POLICY):
                self.assertFalse(action.startswith(prefix), action)
        self.assertNotIn("ecs:DescribeTaskDefinition", ALL_TEMPLATES)


if __name__ == "__main__":
    unittest.main()
