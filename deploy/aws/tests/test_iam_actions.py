"""The IAM grants match what the code calls, and every action name is real.

The AWS operations are derived from the source with `ast`: clients created with
`<x>.client("<service>")` (assigned or chained), their method calls, their
paginators, and the CodeCommit git-source provider's `self._call("<op>")`.
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
    ("codecommit", "list_approval_rule_templates"): "codecommit:ListApprovalRuleTemplates",
    ("codecommit", "list_associated_approval_rule_templates_for_repository"):
        "codecommit:ListAssociatedApprovalRuleTemplatesForRepository",
    ("codecommit", "list_pull_requests"): "codecommit:ListPullRequests",
    ("codecommit", "get_pull_request"): "codecommit:GetPullRequest",
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
}

# API names that are not IAM actions; the real action is in OPERATION_ACTIONS.
NOT_IAM_ACTIONS = {"s3:GetBucketEncryption", "s3:GetBucketReplication", "s3:ListBuckets",
                   "s3:GetPublicAccessBlock"}


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
        self.assertIn(("codecommit", "list_pull_requests"), operations)
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


def runtime_s3_allows():
    from test_template import resource_block, statement_block
    runtime = resource_block("RuntimeRole")
    actions = set()
    for sid in re.findall(r"^\s+- Sid: (\w+)$", runtime, re.MULTILINE):
        statement = statement_block(runtime, sid)
        if "Effect: Allow" in statement:
            actions |= set(re.findall(r"'(s3:[A-Z]\w+)'", statement))
            actions |= set(re.findall(r"Action: (s3:[A-Z]\w+)\s*$", statement, re.MULTILINE))
    return actions


class WitnessGrantsMatchCodeTests(unittest.TestCase):
    def test_operator_policy_grants_exactly_what_the_witness_and_archive_code_calls(self):
        self.assertEqual(policy_actions(OPERATOR_POLICY), to_actions(witness_operations()))

    def test_runtime_role_holds_only_the_serving_subset(self):
        serving = to_actions({("s3", "put_object"), ("s3", "get_object"), ("s3", "list_object_versions")})
        self.assertLessEqual(serving, to_actions(witness_operations()))
        self.assertEqual(runtime_s3_allows(), serving)

    def test_scan_sees_the_multipart_upload(self):
        operations = witness_operations()
        for op in ("create_multipart_upload", "upload_part", "complete_multipart_upload", "abort_multipart_upload"):
            self.assertIn(("s3", op), operations)


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
