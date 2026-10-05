"""The evidence store bucket, its bucket policy and its IAM (docs/evidence-repo-spec.md, "Evidence store").

The core template is read with cfn-lint's CloudFormation YAML decoder, so intrinsic
functions appear as {"Fn::Sub": ...}, {"Ref": ...} and {"Fn::If": [...]}. The bucket
policy is also evaluated against sample requests, each on one object key and from one
principal, with the IAM condition semantics it relies on (a negated operator matches an
absent key; Bool and the Null pairing do not).
evidence-bucket-check.sh, which proves the rules against real S3, is run here against
a fake `aws` command that applies the same rules, and against fakes that break each one;
its --writer-profile checks run against a fake writer role that holds only the writer
policy, and against fakes that grant it one more request each.
"""
import ast
import datetime
import fnmatch
import importlib.util
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

import cfnlint
from cfnlint.decode import cfn_yaml

AWS_DIR = Path(__file__).resolve().parent.parent
REPO = AWS_DIR.parent.parent
TEMPLATE = cfn_yaml.loads((AWS_DIR / "trust-portal.yaml").read_text())
PIPELINE = cfn_yaml.loads((AWS_DIR / "trust-portal-pipeline.yaml").read_text())
RESOURCES = TEMPLATE["Resources"]
DEPLOY_SH = (AWS_DIR / "deploy.sh").read_text()
CHECK_SCRIPT = AWS_DIR / "evidence-bucket-check.sh"
WRITER_POLICY_FILE = REPO / "iam" / "trust-portal-evidence-writer-policy.json"
ASSUME_POLICY_FILE = REPO / "iam" / "trust-portal-evidence-writer-assume-policy.json"
S3_ACTIONS = json.loads((Path(cfnlint.__file__).parent / "data" / "AdditionalSpecs" / "Policies.json")
                        .read_text())["s3"]["Actions"]

STORE_PREFIXES = ["decision-logs/", "codex-reviews/", "pentest-evidence/", "pentest-reports/", "evidence/artifacts/"]
BUCKET_ARN = {"Fn::GetAtt": ["EvidenceBucket", "Arn"]}
OBJECTS = {"Fn::Sub": "${EvidenceBucket.Arn}/*"}
STORE_OBJECTS = [{"Fn::Sub": "${EvidenceBucket.Arn}/%s*" % prefix} for prefix in STORE_PREFIXES]
WRITER_ROLE = {"Fn::GetAtt": ["EvidenceWriterRole", "Arn"]}
NO_VALUE = {"Ref": "AWS::NoValue"}
BUCKET_READS = {"s3:ListBucketVersions", "s3:GetBucketVersioning", "s3:GetBucketObjectLockConfiguration",
                "s3:GetBucketPolicy", "s3:GetLifecycleConfiguration"}
READS = BUCKET_READS | {"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"}
LOCK_AND_DELETE = {"s3:DeleteObject", "s3:DeleteObjectVersion", "s3:PutObjectRetention", "s3:PutObjectLegalHold",
                   "s3:BypassGovernanceRetention"}
REPLICATION = ("s3:ReplicateObject", "s3:ReplicateDelete")
ERASER = "arn:aws:iam::111122223333:role/evidence-erasure"
ADMIN = "arn:aws:iam::111122223333:role/administrator"
# The writer role's ARN, which is also the aws:PrincipalArn of every session of the role.
WRITER_ROLE_ARN = "arn:aws:iam::111122223333:role/ex-user-trust-portal-evidence-writer-prod"
STORE_KEY = "decision-logs/2026-10-04T120000Z_session-1.jsonl"


def properties(logical_id):
    return RESOURCES[logical_id]["Properties"]


def as_list(value):
    return list(value) if isinstance(value, list) else [value]


def policy_statements(document):
    """Every statement of a policy document, with each Fn::If branch that is a statement."""
    found = []
    for entry in document["Statement"]:
        if "Fn::If" in entry:
            found += [branch for branch in entry["Fn::If"][1:] if branch != NO_VALUE]
        else:
            found.append(entry)
    return found


def by_sid(document):
    return {statement["Sid"]: statement for statement in policy_statements(document)}


def runtime_statements():
    return by_sid(properties("RuntimeRole")["Policies"][0]["PolicyDocument"])


def evidence_policy():
    return by_sid(properties("EvidenceBucketPolicy")["PolicyDocument"])


def policy_documents(node):
    """Yield every policy document in a decoded template."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key in ("PolicyDocument", "AssumeRolePolicyDocument", "RepositoryPolicyText") \
                    and isinstance(value, dict) and "Statement" in value:
                yield value
            else:
                yield from policy_documents(value)
    elif isinstance(node, list):
        for value in node:
            yield from policy_documents(value)


def condition_matches(condition, request, erasure):
    """Whether one statement's Condition matches a request, with IAM's absent-key rules."""
    if "Fn::If" in condition:
        name, when_set, when_unset = condition["Fn::If"]
        assert name == "HasErasurePrincipal", name
        condition = when_set if erasure else when_unset
    if condition == NO_VALUE:
        return True
    for operator, tests in condition.items():
        for key, expected in tests.items():
            if expected == {"Ref": "EvidenceErasurePrincipalArn"}:
                expected = erasure
            elif expected == WRITER_ROLE:
                expected = WRITER_ROLE_ARN
            present, value = key in request, request.get(key)
            if operator == "Null":
                matched = (not present) == (expected == "true")
            elif operator == "Bool":
                matched = present and str(value).lower() == expected
            elif operator in ("StringNotEquals", "ArnNotEquals"):
                matched = (not present) or value != expected  # a negated operator matches an absent key
            elif operator == "ArnEquals":
                matched = present and value == expected
            else:
                raise AssertionError("no evaluator for condition operator %s" % operator)
            if not matched:
                return False
    return True


def bucket_statements(erasure="", erasure_key=""):
    """The evidence bucket policy's statements as deployed with EvidenceErasurePrincipalArn
    `erasure` and EvidenceErasureObjectKey `erasure_key` (a statement-level Fn::If resolved)."""
    found = []
    for entry in properties("EvidenceBucketPolicy")["PolicyDocument"]["Statement"]:
        if "Fn::If" in entry:
            name, when_set, when_unset = entry["Fn::If"]
            assert name == "HasErasurePrincipal", name
            entry = when_set if erasure else when_unset
        if entry != NO_VALUE:
            found.append(entry)
    return found


def object_resources(value, erasure_key):
    """A Resource or NotResource value as a list, its HasErasureKey Fn::If resolved."""
    if isinstance(value, dict) and "Fn::If" in value:
        name, when_set, when_unset = value["Fn::If"]
        assert name == "HasErasureKey", name
        value = when_set if erasure_key else when_unset
    return as_list(value)


def names_object(resource, key, erasure_key):
    """Whether one resource ARN names the object `key` (the bucket ARN itself names no object)."""
    if resource == BUCKET_ARN:
        return False
    pattern = resource["Fn::Sub"].replace("${EvidenceErasureObjectKey}", erasure_key)
    return fnmatch.fnmatchcase("${EvidenceBucket.Arn}/" + key, pattern)


def covers_object(statement, key, erasure_key=""):
    """Whether a statement applies to the object `key`: one its Resource names, or, for a
    NotResource, every object it does not name."""
    if "NotResource" in statement:
        return not any(names_object(resource, key, erasure_key)
                       for resource in object_resources(statement["NotResource"], erasure_key))
    return any(names_object(resource, key, erasure_key) for resource in object_resources(statement["Resource"], erasure_key))


def denied(action, request=None, principal=WRITER_ROLE_ARN, erasure="", secure=True, key=STORE_KEY, erasure_key=""):
    """Whether the evidence bucket policy denies an action on an object to a principal (None: anonymous)."""
    request = dict(request or {}, **{"aws:SecureTransport": str(secure).lower()})
    if principal is not None:
        request["aws:PrincipalArn"] = principal
    for statement in bucket_statements(erasure, erasure_key):
        if any(fnmatch.fnmatchcase(action, pattern) for pattern in as_list(statement["Action"])) \
                and covers_object(statement, key, erasure_key) \
                and condition_matches(statement.get("Condition", NO_VALUE), request, erasure):
            return True
    return False


PRODUCER_PUT = {"s3:if-none-match": "*", "s3:ObjectCreationOperation": "true"}


class EvidenceParameterTests(unittest.TestCase):
    def test_retention_years_default_to_seven(self):
        years = TEMPLATE["Parameters"]["EvidenceRetentionYears"]
        self.assertEqual((years["Type"], years["Default"], years["MinValue"]), ("Number", 7, 1))
        self.assertGreaterEqual(years["MaxValue"], 7)

    def test_erasure_principal_is_empty_or_one_iam_role_or_user(self):
        parameter = TEMPLATE["Parameters"]["EvidenceErasurePrincipalArn"]
        self.assertEqual((parameter["Type"], parameter["Default"]), ("String", ""))
        pattern = re.compile(parameter["AllowedPattern"])
        for value in ("", ERASER, "arn:aws:iam::111122223333:role/ops/erasure", "arn:aws:iam::111122223333:user/alice",
                      "arn:aws-us-gov:iam::111122223333:role/erasure"):
            self.assertTrue(pattern.fullmatch(value), value)
        for value in ("*", "arn:aws:iam::111122223333:root", "arn:aws:iam::111122223333:group/admins",
                      "arn:aws:sts::111122223333:assumed-role/erasure/session", "arn:aws:iam::*:role/erasure",
                      ERASER + ",arn:aws:iam::111122223333:role/other"):
            self.assertIsNone(pattern.fullmatch(value), value)
        self.assertEqual(TEMPLATE["Conditions"]["HasErasurePrincipal"],
                         {"Fn::Not": [{"Fn::Equals": [{"Ref": "EvidenceErasurePrincipalArn"}, ""]}]})

    def test_erasure_object_key_is_empty_or_one_literal_key(self):
        parameter = TEMPLATE["Parameters"]["EvidenceErasureObjectKey"]
        self.assertEqual((parameter["Type"], parameter["Default"]), ("String", ""))
        pattern = re.compile(parameter["AllowedPattern"])
        for value in ("", STORE_KEY, "pentest-evidence/layer1/scan 1.json", "evidence/artifacts/a+b=c.pdf"):
            self.assertTrue(pattern.fullmatch(value), value)
        for value in ("*", "decision-logs/*", "decision-logs/?.jsonl", "${aws:username}", "decision-logs/$x"):
            self.assertIsNone(pattern.fullmatch(value), value)  # a wildcard or a policy variable names more keys
        self.assertEqual(TEMPLATE["Conditions"]["HasErasureKey"],
                         {"Fn::Not": [{"Fn::Equals": [{"Ref": "EvidenceErasureObjectKey"}, ""]}]})


class EvidenceBucketTests(unittest.TestCase):
    def setUp(self):
        self.bucket = properties("EvidenceBucket")

    def test_bucket_is_retained_and_named_for_the_environment(self):
        resource = RESOURCES["EvidenceBucket"]
        self.assertEqual((resource["DeletionPolicy"], resource["UpdateReplacePolicy"]), ("Retain", "Retain"))
        name = self.bucket["BucketName"]["Fn::Sub"]
        self.assertEqual(name, "${OrgPrefix}-${AppName}-evstore-${EnvironmentName}-${AWS::AccountId}-${AWS::Region}")
        from test_template import NamingTests
        self.assertLessEqual(len(NamingTests().render(name)), 63)

    def test_object_lock_governance_for_the_retention_parameter_and_versioning(self):
        self.assertIs(self.bucket["ObjectLockEnabled"], True)
        self.assertEqual(self.bucket["ObjectLockConfiguration"],
                         {"ObjectLockEnabled": "Enabled",
                          "Rule": {"DefaultRetention": {"Mode": "GOVERNANCE", "Years": {"Ref": "EvidenceRetentionYears"}}}})
        self.assertEqual(self.bucket["VersioningConfiguration"], {"Status": "Enabled"})

    def test_sse_s3_with_sse_c_blocked(self):
        self.assertEqual(self.bucket["BucketEncryption"]["ServerSideEncryptionConfiguration"],
                         [{"ServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": True,
                           "BlockedEncryptionTypes": {"EncryptionType": ["SSE-C"]}}])

    def test_private_and_owner_enforced(self):
        self.assertEqual(self.bucket["PublicAccessBlockConfiguration"],
                         {"BlockPublicAcls": True, "BlockPublicPolicy": True, "IgnorePublicAcls": True,
                          "RestrictPublicBuckets": True})
        self.assertEqual(self.bucket["OwnershipControls"], {"Rules": [{"ObjectOwnership": "BucketOwnerEnforced"}]})

    def test_lifecycle_only_aborts_incomplete_uploads(self):
        rules = self.bucket["LifecycleConfiguration"]["Rules"]
        self.assertEqual(len(rules), 1)
        self.assertEqual(rules[0]["AbortIncompleteMultipartUpload"], {"DaysAfterInitiation": 1})
        self.assertEqual(set(rules[0]) - {"Id", "Status", "AbortIncompleteMultipartUpload"}, set())


class EvidenceBucketPolicyTests(unittest.TestCase):
    def test_every_statement_is_a_named_deny_to_everyone(self):
        policy = properties("EvidenceBucketPolicy")
        self.assertEqual(policy["Bucket"], {"Ref": "EvidenceBucket"})
        statements = policy_statements(policy["PolicyDocument"])
        self.assertEqual(len(statements), len(evidence_policy()))
        for statement in statements:
            self.assertEqual((statement["Effect"], statement["Principal"]), ("Deny", "*"), statement["Sid"])
            if statement["Sid"] == "ConfineErasureToOneKey":
                self.assertNotIn("Resource", statement)
                self.assertEqual(statement["NotResource"], {"Fn::If": [
                    "HasErasureKey", {"Fn::Sub": "${EvidenceBucket.Arn}/${EvidenceErasureObjectKey}"}, BUCKET_ARN]})
                continue
            self.assertIn(statement["Resource"], (OBJECTS, [BUCKET_ARN, OBJECTS], STORE_OBJECTS), statement["Sid"])

    def test_statements_match_the_contract(self):
        policy = evidence_policy()
        self.assertEqual(policy["DenyInsecureTransport"]["Action"], "s3:*")
        self.assertEqual(policy["DenyInsecureTransport"]["Condition"], {"Bool": {"aws:SecureTransport": "false"}})
        self.assertEqual(policy["DenyWriteWithoutIfNoneMatch"]["Condition"],
                         {"Null": {"s3:if-none-match": "true"}, "Bool": {"s3:ObjectCreationOperation": "true"}})
        self.assertEqual(policy["DenyNonSseS3Writes"]["Condition"],
                         {"Null": {"s3:x-amz-server-side-encryption": "false"},
                          "StringNotEquals": {"s3:x-amz-server-side-encryption": "AES256"}})
        self.assertEqual(policy["DenySseCWrites"]["Condition"],
                         {"Null": {"s3:x-amz-server-side-encryption-customer-algorithm": "false"}})
        self.assertEqual(policy["DenyNonStandardStorageClass"]["Condition"],
                         {"Null": {"s3:x-amz-storage-class": "false"},
                          "StringNotEquals": {"s3:x-amz-storage-class": "STANDARD"}})
        for sid in ("DenyWriteWithoutIfNoneMatch", "DenyNonSseS3Writes", "DenySseCWrites", "DenyNonStandardStorageClass"):
            self.assertEqual(policy[sid]["Action"], "s3:PutObject", sid)
        lock = policy["DenyDeletesAndRetentionChanges"]
        self.assertEqual(set(lock["Action"]), LOCK_AND_DELETE)
        self.assertEqual(lock["Condition"], {"Fn::If": ["HasErasurePrincipal",
                                                        {"ArnNotEquals": {"aws:PrincipalArn":
                                                                          {"Ref": "EvidenceErasurePrincipalArn"}}},
                                                        NO_VALUE]})
        self.assertEqual(policy["DenyReplicationWrites"], {
            "Sid": "DenyReplicationWrites", "Effect": "Deny", "Principal": "*",
            "Action": ["s3:ReplicateObject", "s3:ReplicateDelete"], "Resource": OBJECTS})
        confine = policy["ConfineErasureToOneKey"]
        self.assertEqual(set(confine["Action"]), LOCK_AND_DELETE)
        self.assertEqual(confine["Condition"], {"ArnEquals": {"aws:PrincipalArn": {"Ref": "EvidenceErasurePrincipalArn"}}})
        conditional = [entry["Fn::If"] for entry in properties("EvidenceBucketPolicy")["PolicyDocument"]["Statement"]
                       if "Fn::If" in entry]
        self.assertEqual(conditional, [["HasErasurePrincipal", confine, NO_VALUE]])  # present exactly while it is set

    def test_replication_writes_are_denied_to_every_principal_on_every_key(self):
        """A replication role writes replicas and delete markers with s3:ReplicateObject and
        s3:ReplicateDelete, not s3:PutObject or s3:DeleteObject: the bucket refuses both to
        everyone, the writer role and the named erasure principal included."""
        for action in REPLICATION:
            self.assertIn(action.split(":")[1].lower(), S3_ACTIONS)
            for key in [prefix + "object.json" for prefix in STORE_PREFIXES] + ["bucket-check/object.txt"]:
                for erasure in ("", ERASER):
                    for principal in (WRITER_ROLE_ARN, ADMIN, ERASER, None):
                        self.assertTrue(denied(action, principal=principal, erasure=erasure, key=key),
                                        (action, key, principal, erasure))

    def test_a_producer_put_is_allowed_and_every_other_write_is_denied(self):
        self.assertFalse(denied("s3:PutObject", PRODUCER_PUT))
        self.assertFalse(denied("s3:PutObject", dict(PRODUCER_PUT, **{"s3:x-amz-server-side-encryption": "AES256",
                                                                      "s3:x-amz-storage-class": "STANDARD"})))
        self.assertTrue(denied("s3:PutObject", {"s3:ObjectCreationOperation": "true"}))
        self.assertTrue(denied("s3:PutObject", PRODUCER_PUT, secure=False))
        self.assertTrue(denied("s3:PutObject", dict(PRODUCER_PUT, **{"s3:x-amz-server-side-encryption": "aws:kms"})))
        self.assertTrue(denied("s3:PutObject", dict(PRODUCER_PUT, **{
            "s3:x-amz-server-side-encryption-customer-algorithm": "AES256"})))
        for storage_class in ("STANDARD_IA", "GLACIER", "DEEP_ARCHIVE", "INTELLIGENT_TIERING", "REDUCED_REDUNDANCY"):
            self.assertTrue(denied("s3:PutObject", dict(PRODUCER_PUT, **{"s3:x-amz-storage-class": storage_class})))

    def test_only_the_writer_role_creates_objects_under_the_store_prefixes(self):
        self.assertEqual(evidence_policy()["OnlyTheWriterRoleWritesEvidence"], {
            "Sid": "OnlyTheWriterRoleWritesEvidence", "Effect": "Deny", "Principal": "*", "Action": "s3:PutObject",
            "Resource": STORE_OBJECTS, "Condition": {"ArnNotEquals": {"aws:PrincipalArn": WRITER_ROLE}}})
        writes = policy_statements(properties("EvidenceWriterPolicy")["PolicyDocument"])[0]["Resource"]
        self.assertEqual(writes, STORE_OBJECTS)  # the role's grant and the bucket's exemption name the same keys

    def test_a_store_put_by_any_principal_but_the_writer_role_is_denied(self):
        others = (ADMIN, ERASER, None, "arn:aws:iam::111122223333:user/alice",
                  WRITER_ROLE_ARN.replace("111122223333", "444455556666"),
                  WRITER_ROLE_ARN.replace(":role/", ":role/other/"), WRITER_ROLE_ARN + "-copy")
        part = {"s3:ObjectCreationOperation": "false"}  # UploadPart and CreateMultipartUpload are PutObject too
        for prefix in STORE_PREFIXES:
            key = prefix + "bucket-check/object.txt"
            for erasure in ("", ERASER):
                for request in (PRODUCER_PUT, part):
                    self.assertFalse(denied("s3:PutObject", request, erasure=erasure, key=key), (prefix, request))
                    for principal in others:
                        self.assertTrue(denied("s3:PutObject", request, principal=principal, erasure=erasure, key=key),
                                        (prefix, principal, request))
        for key in ("bucket-check/20261004T120000Z/object.txt", "decision-logs", "evidence/other.txt"):
            self.assertFalse(denied("s3:PutObject", PRODUCER_PUT, principal=ADMIN, key=key), key)

    def test_the_bucket_policy_creates_no_dependency_cycle(self):
        def depends_on(logical_id):
            return {other for other in RESOURCES if other != logical_id and references(RESOURCES[logical_id], other)}

        seen, path = set(), []

        def visit(logical_id):
            self.assertNotIn(logical_id, path, path)
            if logical_id not in seen:
                path.append(logical_id)
                for other in depends_on(logical_id):
                    visit(other)
                path.pop()
                seen.add(logical_id)

        visit("EvidenceBucketPolicy")
        self.assertTrue({"EvidenceBucket", "EvidenceWriterRole", "EvidenceWriterPolicy"} <= seen, seen)

    def test_multipart_parts_need_no_if_none_match_but_completion_does(self):
        self.assertFalse(denied("s3:PutObject", {"s3:ObjectCreationOperation": "false"}))
        self.assertTrue(denied("s3:PutObject", {"s3:ObjectCreationOperation": "true"}))

    def test_deletes_and_lock_changes_are_denied_to_everyone_while_no_erasure_principal_is_set(self):
        for action in sorted(LOCK_AND_DELETE):
            for principal in (ADMIN, ERASER):
                self.assertTrue(denied(action, principal=principal), (action, principal))

    def test_the_erasure_exemption_covers_only_the_named_key(self):
        """The erasure principal is exempt on the object EvidenceErasureObjectKey names, every version
        of it (a version's ARN is its key's), and denied on every other object; nobody else is exempt."""
        others = ("decision-logs/2026-10-04T120000Z_session-2.jsonl", STORE_KEY + ".meta.json", STORE_KEY + "x",
                  "pentest-evidence/layer1/scan.json", "bucket-check/object.txt")
        for action in sorted(LOCK_AND_DELETE):
            self.assertFalse(denied(action, principal=ERASER, erasure=ERASER, erasure_key=STORE_KEY), action)
            for key in others:
                self.assertTrue(denied(action, principal=ERASER, erasure=ERASER, erasure_key=STORE_KEY, key=key),
                                (action, key))
            for principal in (ADMIN, WRITER_ROLE_ARN, None):
                self.assertTrue(denied(action, principal=principal, erasure=ERASER, erasure_key=STORE_KEY),
                                (action, principal))
            self.assertTrue(denied(action, principal=ERASER, erasure=ERASER, erasure_key=STORE_KEY, secure=False), action)
        self.assertTrue(denied("s3:PutObject", {"s3:ObjectCreationOperation": "true"}, principal=ERASER, erasure=ERASER,
                               erasure_key=STORE_KEY))

    def test_an_erasure_principal_without_a_key_is_exempt_nowhere(self):
        for action in sorted(LOCK_AND_DELETE):
            for key in (STORE_KEY, "pentest-evidence/layer1/scan.json", "bucket-check/object.txt"):
                self.assertTrue(denied(action, principal=ERASER, erasure=ERASER, key=key), (action, key))

    def test_a_key_without_an_erasure_principal_exempts_nobody(self):
        self.assertEqual(bucket_statements("", STORE_KEY), bucket_statements())
        self.assertNotIn("ConfineErasureToOneKey", {entry["Sid"] for entry in bucket_statements("", STORE_KEY)})
        for action in sorted(LOCK_AND_DELETE):
            for principal in (ADMIN, ERASER, WRITER_ROLE_ARN):
                self.assertTrue(denied(action, principal=principal, erasure_key=STORE_KEY), (action, principal))
        self.assertEqual(rendered_bucket_policy(erasure_key=STORE_KEY), rendered_bucket_policy())


class EvidenceWriterPolicyTests(unittest.TestCase):
    def setUp(self):
        self.policy = properties("EvidenceWriterPolicy")

    def test_named_and_described_like_the_other_managed_policies(self):
        self.assertEqual(RESOURCES["EvidenceWriterPolicy"]["Type"], "AWS::IAM::ManagedPolicy")
        self.assertEqual(self.policy["ManagedPolicyName"],
                         {"Fn::Sub": "${OrgPrefix}-${AppName}-evidence-writer-${EnvironmentName}"})
        self.assertIn("deploy/aws/trust-portal.yaml", self.policy["Description"]["Fn::Sub"])
        self.assertIn("${AWS::StackName}", self.policy["Description"]["Fn::Sub"])

    def test_grants_only_put_object_on_the_store_prefixes(self):
        statements = policy_statements(self.policy["PolicyDocument"])
        self.assertEqual(len(statements), 1)
        statement = statements[0]
        self.assertEqual((statement["Sid"], statement["Effect"], statement["Action"]),
                         ("WriteEvidence", "Allow", "s3:PutObject"))
        self.assertNotIn("Condition", statement)
        self.assertEqual(statement["Resource"],
                         [{"Fn::Sub": "${EvidenceBucket.Arn}/%s*" % prefix} for prefix in STORE_PREFIXES])

    def test_producers_write_exactly_the_prefixes_the_portal_imports(self):
        declared = []
        for path in sorted((REPO / "app" / "services" / "evidence_store").glob("*.py")):
            for node in ast.parse(path.read_text()).body:
                if isinstance(node, ast.Assign) and [ast.unparse(t) for t in node.targets] == ["PREFIXES"]:
                    declared.append((path.name, set(ast.literal_eval(node.value))))
        for name, prefixes in declared:
            self.assertEqual(prefixes, set(STORE_PREFIXES), name)

    def test_the_policy_file_mirrors_the_managed_policy(self):
        document = json.loads(WRITER_POLICY_FILE.read_text())
        mirrored = []
        for statement in policy_statements(self.policy["PolicyDocument"]):
            mirrored.append({"Sid": statement["Sid"], "Effect": statement["Effect"],
                             "Action": as_list(statement["Action"]),
                             "Resource": [r["Fn::Sub"].replace("${EvidenceBucket.Arn}", "arn:aws:s3:::EVIDENCE_BUCKET")
                                          for r in as_list(statement["Resource"])]})
        self.assertEqual(document, {"Version": "2012-10-17", "Statement": mirrored})


def references(node, logical_id):
    """Whether a decoded template node refers to a resource (Ref, Fn::GetAtt or ${...} in Fn::Sub)."""
    text = json.dumps(node)
    return any(marker in text for marker in ('{"Ref": "%s"}' % logical_id, '["%s", ' % logical_id,
                                             "${%s}" % logical_id, "${%s." % logical_id))


PRODUCER_USER = "arn:aws:iam::111122223333:user/alice"
PRODUCER_ROLE = "arn:aws:iam::111122223333:role/ci/evidence-producer"
ACCOUNT_ROOT = "arn:aws:iam::111122223333:root"


def trusted(principal_arn, writer_arns):
    """Whether the writer role's trust policy lets a signed AssumeRole request from a principal of
    the stack's account (its aws:PrincipalArn, always in the request context) assume the role,
    with EvidenceWriterPrincipalArns set to `writer_arns` (CloudFormation's list: [""] when empty)."""
    has_writers = "".join(writer_arns) != ""
    for statement in properties("EvidenceWriterRole")["AssumeRolePolicyDocument"]["Statement"]:
        assert statement["Principal"] == {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}}
        name, when_set, when_unset = statement["Condition"]["Fn::If"]
        assert name == "HasWriterPrincipals", name
        condition = when_set if has_writers else when_unset
        matched = True
        for operator, tests in condition.items():
            for key, expected in tests.items():
                assert key == "aws:PrincipalArn", key
                if operator == "StringEquals":
                    assert expected == {"Ref": "EvidenceWriterPrincipalArns"}, expected
                    matched = matched and principal_arn in writer_arns
                elif operator == "Null":
                    matched = matched and (expected == "false")  # the key is present in every signed request
                else:
                    raise AssertionError("no evaluator for condition operator %s" % operator)
        if statement["Effect"] == "Allow" and statement["Action"] == "sts:AssumeRole" and matched:
            return True
    return False


class EvidenceWriterRoleTests(unittest.TestCase):
    """Producers upload as the writer role, which holds the writer policy and nothing else."""

    def setUp(self):
        self.role = properties("EvidenceWriterRole")

    def test_named_and_described_like_the_other_roles_within_the_name_limit(self):
        self.assertEqual(RESOURCES["EvidenceWriterRole"]["Type"], "AWS::IAM::Role")
        name = self.role["RoleName"]["Fn::Sub"]
        self.assertEqual(name, "${OrgPrefix}-user-${AppName}-evidence-writer-${EnvironmentName}")
        from test_template import NamingTests
        self.assertLessEqual(len(NamingTests().render(name)), 64)
        self.assertEqual(self.role["Path"], "/")
        self.assertIn("deploy/aws/trust-portal.yaml", self.role["Description"]["Fn::Sub"])
        self.assertIn("${AWS::StackName}", self.role["Description"]["Fn::Sub"])
        self.assertEqual(self.role["MaxSessionDuration"], 3600)

    def test_holds_only_the_writer_policy(self):
        self.assertEqual(self.role["ManagedPolicyArns"], [{"Ref": "EvidenceWriterPolicy"}])
        self.assertEqual(set(self.role), {"RoleName", "Path", "Description", "MaxSessionDuration", "ManagedPolicyArns",
                                          "AssumeRolePolicyDocument"})
        users = {logical_id for logical_id, resource in RESOURCES.items()
                 if logical_id != "EvidenceWriterRole" and references(resource, "EvidenceWriterRole")}
        # The assume policy's Resource and the bucket policy's exemption; nothing attaches a policy to the role.
        self.assertEqual(users, {"EvidenceWriterAssumePolicy", "EvidenceBucketPolicy"})

    def test_trusts_only_the_named_producer_principals_of_the_stacks_account(self):
        self.assertEqual(self.role["AssumeRolePolicyDocument"], {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "TrustNamedProducers", "Effect": "Allow",
                           "Principal": {"AWS": {"Fn::Sub": "arn:${AWS::Partition}:iam::${AWS::AccountId}:root"}},
                           "Action": "sts:AssumeRole",
                           "Condition": {"Fn::If": ["HasWriterPrincipals",
                                                    {"StringEquals": {"aws:PrincipalArn":
                                                                      {"Ref": "EvidenceWriterPrincipalArns"}}},
                                                    {"Null": {"aws:PrincipalArn": "true"}}]}}]})

    def test_the_trust_policy_never_trusts_the_account_without_the_principal_restriction(self):
        for statement in self.role["AssumeRolePolicyDocument"]["Statement"]:
            if statement["Effect"] != "Allow":
                continue
            condition = statement.get("Condition")
            self.assertIsNotNone(condition, statement["Sid"])
            self.assertIn("Fn::If", condition, statement["Sid"])
            name, when_set, when_unset = condition["Fn::If"]
            self.assertEqual(name, "HasWriterPrincipals")
            for branch in (when_set, when_unset):  # neither branch may drop the condition
                self.assertNotEqual(branch, NO_VALUE)
                self.assertTrue(branch, statement["Sid"])

    def test_the_writer_principals_parameter_is_wired(self):
        parameter = TEMPLATE["Parameters"]["EvidenceWriterPrincipalArns"]
        self.assertEqual((parameter["Type"], parameter["Default"]), ("CommaDelimitedList", ""))
        pattern = re.compile(parameter["AllowedPattern"])  # CloudFormation applies it to each element
        for value in ("", PRODUCER_USER, PRODUCER_ROLE, "arn:aws-us-gov:iam::111122223333:role/producer"):
            self.assertTrue(pattern.fullmatch(value), value)
        for value in ("*", "arn:aws:iam::111122223333:root", "arn:aws:iam::111122223333:user/*",
                      "arn:aws:iam::111122223333:group/producers", "arn:aws:iam::*:role/producer",
                      "arn:aws:sts::111122223333:assumed-role/producer/session"):
            self.assertIsNone(pattern.fullmatch(value), value)
        self.assertEqual(TEMPLATE["Conditions"]["HasWriterPrincipals"],
                         {"Fn::Not": [{"Fn::Equals": [{"Fn::Join": ["", {"Ref": "EvidenceWriterPrincipalArns"}]}, ""]}]})
        self.assertIn("EvidenceWriterPrincipalArns", json.dumps(self.role["AssumeRolePolicyDocument"]))

    def test_an_empty_list_trusts_nobody(self):
        for principal in (ADMIN, ERASER, PRODUCER_USER, PRODUCER_ROLE, ACCOUNT_ROOT, ""):
            self.assertFalse(trusted(principal, [""]), principal)

    def test_a_list_trusts_exactly_its_principals(self):
        writers = [PRODUCER_USER, PRODUCER_ROLE]
        for principal in writers:
            self.assertTrue(trusted(principal, writers), principal)
        for principal in (ADMIN, ERASER, ACCOUNT_ROOT, PRODUCER_USER + "-copy", PRODUCER_USER.upper(),
                          PRODUCER_ROLE.replace(":role/", ":role/other/"),
                          PRODUCER_ROLE.replace("111122223333", "444455556666")):
            self.assertFalse(trusted(principal, writers), principal)


class EvidenceWriterAssumePolicyTests(unittest.TestCase):
    """The managed policy that lets a producer identity assume the writer role, and nothing else."""

    def setUp(self):
        self.policy = properties("EvidenceWriterAssumePolicy")

    def test_named_and_described_like_the_other_managed_policies(self):
        self.assertEqual(RESOURCES["EvidenceWriterAssumePolicy"]["Type"], "AWS::IAM::ManagedPolicy")
        name = self.policy["ManagedPolicyName"]["Fn::Sub"]
        self.assertEqual(name, "${OrgPrefix}-${AppName}-evidence-writer-assume-${EnvironmentName}")
        from test_template import NamingTests
        self.assertLessEqual(len(NamingTests().render(name)), 128)
        self.assertIn("deploy/aws/trust-portal.yaml", self.policy["Description"]["Fn::Sub"])
        self.assertIn("${AWS::StackName}", self.policy["Description"]["Fn::Sub"])

    def test_grants_exactly_assume_role_on_the_writer_role_and_is_attached_to_nothing(self):
        self.assertEqual(self.policy["PolicyDocument"], {
            "Version": "2012-10-17",
            "Statement": [{"Sid": "AssumeEvidenceWriterRole", "Effect": "Allow", "Action": "sts:AssumeRole",
                           "Resource": {"Fn::GetAtt": ["EvidenceWriterRole", "Arn"]}}]})
        self.assertEqual(set(self.policy) & {"Roles", "Users", "Groups"}, set())

    def test_the_policy_file_mirrors_the_managed_policy(self):
        document = json.loads(ASSUME_POLICY_FILE.read_text())
        role_arn = {"Fn::GetAtt": ["EvidenceWriterRole", "Arn"]}
        mirrored = [{"Sid": statement["Sid"], "Effect": statement["Effect"], "Action": as_list(statement["Action"]),
                     "Resource": ["arn:aws:iam::ACCOUNT_ID:role/EVIDENCE_WRITER_ROLE" if resource == role_arn
                                  else resource for resource in as_list(statement["Resource"])]}
                    for statement in policy_statements(self.policy["PolicyDocument"])]
        self.assertEqual(document, {"Version": "2012-10-17", "Statement": mirrored})


class RuntimeRoleEvidenceTests(unittest.TestCase):
    def test_reads_versions_retention_and_bucket_configuration(self):
        statements = runtime_statements()
        bucket = statements["ReadEvidenceStore"]
        self.assertEqual((bucket["Effect"], bucket["Resource"]), ("Allow", BUCKET_ARN))
        self.assertEqual(set(bucket["Action"]), BUCKET_READS)
        objects = statements["ReadEvidenceVersions"]
        self.assertEqual((objects["Effect"], objects["Resource"]), ("Allow", OBJECTS))
        self.assertEqual(set(objects["Action"]), {"s3:GetObject", "s3:GetObjectVersion", "s3:GetObjectRetention"})

    def test_no_allow_on_the_evidence_bucket_beyond_the_reads(self):
        for sid, statement in runtime_statements().items():
            text = json.dumps(statement)
            if statement["Effect"] == "Allow" and "EvidenceBucket" in text:
                self.assertLessEqual(set(as_list(statement["Action"])), READS, sid)

    def test_every_write_delete_retention_acl_and_tagging_action_is_denied(self):
        deny = runtime_statements()["NoEvidenceWrites"]
        self.assertEqual((deny["Effect"], deny["Resource"]), ("Deny", [BUCKET_ARN, OBJECTS]))
        patterns = [pattern.lower() for pattern in deny["Action"]]
        mutating = sorted(name for name, spec in S3_ACTIONS.items()
                          if {"bucket", "object"} & set(spec.get("Resources", []))
                          and not name.startswith(("get", "list", "describe")))
        self.assertIn("putobjectretention", mutating)
        for name in mutating:
            self.assertTrue(any(fnmatch.fnmatchcase("s3:" + name, p) for p in patterns), name)
        for read in READS:
            self.assertFalse(any(fnmatch.fnmatchcase(read.lower(), p) for p in patterns), read)


class EvidenceOutputTests(unittest.TestCase):
    def test_outputs_name_the_bucket_the_writer_role_and_its_policies(self):
        outputs = TEMPLATE["Outputs"]
        expected = {"EvidenceBucketName": {"Ref": "EvidenceBucket"},
                    "EvidenceWriterPolicyArn": {"Ref": "EvidenceWriterPolicy"},
                    "EvidenceWriterRoleArn": {"Fn::GetAtt": ["EvidenceWriterRole", "Arn"]},
                    "EvidenceWriterAssumePolicyArn": {"Ref": "EvidenceWriterAssumePolicy"}}
        for name, value in expected.items():
            self.assertEqual(outputs[name], {"Value": value}, name)  # no export: the pipeline imports none


class SidTests(unittest.TestCase):
    def test_every_policy_statement_has_a_unique_sid(self):
        for template in (TEMPLATE, PIPELINE):
            for document in policy_documents(template):
                sids = [statement.get("Sid") for statement in policy_statements(document)]
                self.assertTrue(all(sids), sids)
                self.assertEqual(len(sids), len(set(sids)), sids)


class DeployEnvironmentTests(unittest.TestCase):
    def test_every_deploy_gives_the_container_the_evidence_bucket(self):
        self.assertIn("\nEVIDENCE_BUCKET=$(output EvidenceBucketName)\n", DEPLOY_SH)  # top level: every run
        self.assertIn('--arg evidence "$EVIDENCE_BUCKET"', DEPLOY_SH)
        environment = DEPLOY_SH[DEPLOY_SH.index("environment: (("):DEPLOY_SH.index("}}' > \"$WORK/containers.json\"")]
        self.assertIn("EVIDENCE_STORE_BUCKET: $evidence,", environment)
        self.assertNotIn("EVIDENCE_STORE_BUCKET", environment[:environment.index(" end)")])

    def test_the_runtime_secret_never_holds_the_evidence_bucket(self):
        for function in ("SecretInitFunction", "PortalSecretValues"):
            text = json.dumps(properties(function))
            self.assertIn('\\"AUDIT_WITNESS_BUCKET\\",\\"EVIDENCE_STORE_BUCKET\\"]', text, function)

    def test_set_secret_key_refuses_the_bucket_names_before_any_aws_call(self):
        with tempfile.TemporaryDirectory() as directory:
            fake = FakeAws(Path(directory))
            value = Path(directory) / "value"
            value.write_text("bucket\n")
            for key in ("EVIDENCE_STORE_BUCKET", "AUDIT_WITNESS_BUCKET"):
                result = fake.run(["bash", str(AWS_DIR / "set-secret-key.sh"), "--stack", "core", "--key", key,
                                   "--value-file", str(value), "--region", "us-east-1"])
                self.assertEqual(result.returncode, 2, key)
                self.assertIn("never goes in the runtime secret", result.stderr)
                self.assertEqual(fake.calls(), [], key)


FAKE_AWS = r'''
import base64, datetime, hashlib, json, os, sys

import jmespath

YEARS = 7
BUCKET = os.environ["FAKE_S3_BUCKET"]
FLAW = os.environ.get("FAKE_S3_FLAW", "")
STATE = os.environ["FAKE_S3_STATE"]
POLICY = os.environ.get("FAKE_S3_POLICY", "")
LOCK_HEADERS = ("--object-lock-mode", "--object-lock-retain-until-date", "--object-lock-legal-hold-status")
try:
    with open(STATE) as handle:
        state = json.load(handle)
except FileNotFoundError:
    state = {"calls": [], "versions": {}, "markers": {}, "uploads": {}}
args = sys.argv[1:]
service, command, flags, i = args[0], args[1], {}, 2
while i < len(args):
    if i + 1 < len(args) and not args[i + 1].startswith("--"):
        flags[args[i]] = args[i + 1]
        i += 2
    else:
        flags[args[i]] = True
        i += 1
key = flags.get("--key", "")
state["calls"].append([command, key])
PROFILE = flags.get("--profile")
state.setdefault("profiles", []).append(PROFILE)
WRITER_ROLE = os.environ["FAKE_WRITER_ROLE"]
STORE =("decision-logs/", "codex-reviews/", "pentest-evidence/", "pentest-reports/", "evidence/artifacts/")
now = datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)


def text(value):
    """The AWS CLI's text output of a scalar or a flat list."""
    if isinstance(value, list):
        return "\t".join(text(item) for item in value)
    return "None" if value is None else str(value)


def finish(response=None, error=None, operation=None):
    """Save the state, then answer like the AWS CLI: --query applied, text or JSON output."""
    with open(STATE, "w") as handle:
        json.dump(state, handle)
    if error:
        operation = operation or "".join(part.title() for part in command.split("-"))
        sys.stderr.write("\nAn error occurred (%s) when calling the %s operation: fake\n" % (error, operation))
        sys.exit(254)
    if response is not None:
        result = jmespath.search(flags["--query"], response) if "--query" in flags else response
        print(text(result) if flags.get("--output") == "text" else json.dumps(result, indent=4))
    sys.exit(0)


def sha256_of(path):
    with open(path, "rb") as handle:
        return base64.b64encode(hashlib.sha256(handle.read()).digest()).decode()


def default_retain_until():
    if FLAW == "day-years":  # a year read as 365 days
        return now + datetime.timedelta(days=365 * YEARS)
    try:
        until = now.replace(year=now.year + YEARS)
    except ValueError:  # 29 February
        until = now.replace(year=now.year + YEARS, day=28)
    return until - datetime.timedelta(days=40 if FLAW == "short-retention" else 0)


def store(sha, retain_until=None):
    version = "v%d" % len(state["calls"])
    state["versions"].setdefault(key, []).append({"id": version, "sha": sha, "created": now.isoformat(),
                                                  "retain": (retain_until or default_retain_until()).isoformat()})
    return version


if service == "cloudformation" and command == "describe-stacks":
    outputs = [{"OutputKey": "EvidenceBucketName", "OutputValue": BUCKET}]
    if FLAW != "no-writer-role":
        outputs.append({"OutputKey": "EvidenceWriterRoleArn", "OutputValue": WRITER_ROLE})
    finish({"Stacks": [{"Outputs": outputs,
                        "Parameters": [{"ParameterKey": "EvidenceRetentionYears", "ParameterValue": str(YEARS)},
                                       {"ParameterKey": "EvidenceErasurePrincipalArn",
                                        "ParameterValue": os.environ.get("FAKE_S3_ERASER", "")}]}]})
# A --profile is the producer's writer profile, which assumes the writer role: its one grant
# is PutObject under the store prefixes. A "writer-<command>" flaw grants it that command too.
if PROFILE is not None and PROFILE != os.environ.get("FAKE_WRITER_PROFILE"):
    finish(error="ProfileNotFound")
if PROFILE is not None and FLAW == "writer-assume-denied":
    finish(error="AccessDenied", operation="AssumeRole")
if service == "sts" and command == "get-caller-identity":
    arn = "arn:aws:iam::111122223333:user/operator"
    if PROFILE is not None:
        arn = ("arn:aws:iam::111122223333:user/alice" if FLAW == "writer-identity" else
               "arn:aws:sts::111122223333:assumed-role/%s/alice" % WRITER_ROLE.rsplit("/", 1)[1])
    finish({"UserId": "AIDAFAKE", "Account": "111122223333", "Arn": arn})
if service != "s3api" or flags.get("--bucket") != BUCKET or not flags.get("--region"):
    finish(error="NoSuchBucket")
if PROFILE is not None:
    if FLAW != "writer-" + command and not (
            command == "put-object" and (key.startswith(STORE) or FLAW == "writer-anywhere")):
        finish(error="AccessDenied")
    if command != "put-object":
        finish({})  # a flaw granted the writer this request, and the bucket lets it through
# OnlyTheWriterRoleWritesEvidence: under the store prefixes, every s3:PutObject request but the writer
# role's is refused; the "operator-store-write" flaw is a bucket policy without that statement.
if PROFILE is None and key.startswith(STORE) and FLAW != "operator-store-write" and command in (
        "put-object", "create-multipart-upload", "upload-part", "complete-multipart-upload", "copy-object"):
    finish(error="AccessDenied")
versions = state["versions"].get(key, [])
conditional = flags.get("--if-none-match") == "*"
if command == "put-object":
    sha = sha256_of(flags["--body"])
    if flags.get("--checksum-sha256") != sha:
        finish(error="BadDigest")
    until = None
    if ("--object-lock-mode" in flags) != ("--object-lock-retain-until-date" in flags):
        finish(error="InvalidRequest")
    if "--object-lock-retain-until-date" in flags:
        until = datetime.datetime.strptime(flags["--object-lock-retain-until-date"], "%Y-%m-%dT%H:%M:%SZ")
        until = until.replace(tzinfo=datetime.timezone.utc)
        if flags["--object-lock-mode"] not in ("GOVERNANCE", "COMPLIANCE") or until <= now:
            finish(error="InvalidArgument")
    if flags.get("--object-lock-legal-hold-status", "ON") != "ON":
        finish(error="InvalidArgument")
    if not conditional and FLAW != "unconditional-put":
        finish(error="AccessDenied")
    if "--sse-customer-algorithm" in flags or flags.get("--server-side-encryption", "AES256") != "AES256":
        finish(error="AccessDenied")
    if flags.get("--storage-class", "STANDARD") != "STANDARD" and FLAW != "storage-class":
        finish(error="AccessDenied")
    if any(name in flags for name in LOCK_HEADERS) and FLAW != "object-lock-headers":
        finish(error="AccessDenied")  # retention and legal-hold headers need the denied lock actions
    if versions and conditional:
        finish(error="PreconditionFailed")
    finish({"VersionId": store(sha, until), "ChecksumSHA256": sha, "ETag": '"etag"'})
if command == "create-multipart-upload":
    if flags.get("--checksum-algorithm") != "SHA256":
        finish(error="InvalidRequest")
    upload_id = "upload-%d" % len(state["calls"])
    state["uploads"][upload_id] = {"key": key, "parts": {}}
    finish({"Bucket": BUCKET, "Key": key, "UploadId": upload_id})
upload = state["uploads"].get(flags.get("--upload-id"))
if command in ("upload-part", "complete-multipart-upload", "abort-multipart-upload") and (
        not upload or upload["key"] != key):
    finish(error="NoSuchUpload")
if command == "upload-part":
    sha = sha256_of(flags["--body"])
    if flags.get("--checksum-sha256") != sha:
        finish(error="BadDigest")
    etag = '"etag-%s"' % flags["--part-number"]
    upload["parts"][flags["--part-number"]] = {"ETag": etag, "ChecksumSHA256": sha}
    finish({"ETag": etag, "ChecksumSHA256": sha})
if command == "complete-multipart-upload":
    with open(flags["--multipart-upload"][len("file://"):]) as handle:
        parts = json.load(handle)["Parts"]
    listed = [dict(part, PartNumber=int(number)) for number, part in sorted(upload["parts"].items())]
    if not listed or parts != listed:
        finish(error="InvalidPart")
    if not conditional and FLAW != "unconditional-complete":
        finish(error="AccessDenied")
    if versions and conditional:
        finish(error="PreconditionFailed")
    del state["uploads"][flags["--upload-id"]]
    finish({"Bucket": BUCKET, "Key": key, "VersionId": store(listed[0]["ChecksumSHA256"])})
if command == "abort-multipart-upload":
    del state["uploads"][flags["--upload-id"]]
    finish()
if command == "copy-object":
    source_key, _, source_version = flags.get("--copy-source", "").partition("/")[2].partition("?versionId=")
    source = [v for v in state["versions"].get(source_key, []) if v["id"] == source_version]
    if not flags.get("--copy-source", "").startswith(BUCKET + "/") or not source:
        finish(error="NoSuchVersion")
    if not conditional and FLAW != "copy":
        finish(error="AccessDenied")
    finish({"VersionId": store(source[0]["sha"]), "CopyObjectResult": {"ETag": '"etag"'}})
if command == "delete-object":
    if "--version-id" not in flags and FLAW == "delete":
        state["markers"][key] = state["markers"].get(key, 0) + 1
        finish({"DeleteMarker": True})
    finish(error="AccessDenied")
if command == "put-object-retention":
    retention = json.loads(flags["--retention"])
    datetime.datetime.strptime(retention["RetainUntilDate"], "%Y-%m-%dT%H:%M:%SZ")
    finish(error="AccessDenied" if retention["Mode"] == "GOVERNANCE" else "MalformedXML")
if command == "put-object-legal-hold":
    finish(error="AccessDenied" if json.loads(flags["--legal-hold"]) == {"Status": "ON"} else "MalformedXML")
if command == "head-object":
    match = [v for v in versions if v["id"] == flags.get("--version-id")]
    if not match or flags.get("--checksum-mode") != "ENABLED":
        finish(error="404")
    finish({"LastModified": match[0]["created"], "ChecksumSHA256": match[0]["sha"], "ServerSideEncryption": "AES256",
            "ObjectLockMode": "GOVERNANCE", "ObjectLockRetainUntilDate": match[0]["retain"]})
if command == "list-object-versions":
    prefix = flags["--prefix"]
    response = {"Name": BUCKET, "Prefix": prefix}
    listed = [{"Key": k, "VersionId": v["id"], "LastModified": v["created"]}
              for k, vs in sorted(state["versions"].items()) if k.startswith(prefix) for v in vs]
    markers = [{"Key": k, "VersionId": "m%d" % n} for k, count in sorted(state["markers"].items())
               if k.startswith(prefix) for n in range(count)]
    if listed:
        response["Versions"] = listed
    if markers:
        response["DeleteMarkers"] = markers
    finish(response)
if command == "get-bucket-policy":
    if not POLICY or not os.path.exists(POLICY):
        finish(error="NoSuchBucketPolicy")
    with open(POLICY) as handle:
        finish({"Policy": handle.read()})
retention = {"lock-days": {"Mode": "GOVERNANCE", "Days": 30}, "lock-mode": {"Mode": "COMPLIANCE", "Years": YEARS},
             "lock-years": {"Mode": "GOVERNANCE", "Years": 1}}.get(FLAW, {"Mode": "GOVERNANCE", "Years": YEARS})
rules = [{"ID": "AbortIncompleteUploadsAfter1Day", "Filter": {"Prefix": ""}, "Status": "Enabled",
          "AbortIncompleteMultipartUpload": {"DaysAfterInitiation": 1}}]
if FLAW == "expiring-lifecycle":
    rules.append({"ID": "Tidy", "Filter": {"Prefix": ""}, "Status": "Enabled",
                  "NoncurrentVersionExpiration": {"NoncurrentDays": 30}})
fixed = {
    "get-bucket-versioning": {"Status": "Enabled"},
    "get-object-lock-configuration": {"ObjectLockConfiguration": {"ObjectLockEnabled": "Enabled",
                                                                  "Rule": {"DefaultRetention": retention}}},
    "get-bucket-encryption": {"ServerSideEncryptionConfiguration": {"Rules": [
        {"ApplyServerSideEncryptionByDefault": {"SSEAlgorithm": "AES256"}, "BucketKeyEnabled": True}]}},
    "get-public-access-block": {"PublicAccessBlockConfiguration": {
        "BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": True, "RestrictPublicBuckets": True}},
    "get-bucket-lifecycle-configuration": {"Rules": rules},
}
finish(fixed[command]) if command in fixed else finish(error="UnknownOperation")
'''
SECRET = "FAKE-SECRET-ACCESS-KEY-NEVER-PRINTED"
FAKE_BUCKET = "example-evstore-bucket"
WRITER_PROFILE = "evidence-writer"
WRITER_SESSION = "arn:aws:sts::111122223333:assumed-role/ex-user-trust-portal-evidence-writer-prod"
NO_VALUE_MARK = object()


def rendered_bucket_policy(erasure="", erasure_key=""):
    """The evidence bucket policy as S3 holds it for the fake bucket, intrinsic functions resolved."""
    arn = "arn:aws:s3:::" + FAKE_BUCKET

    def render(node):
        if isinstance(node, list):
            return [item for item in map(render, node) if item is not NO_VALUE_MARK]
        if not isinstance(node, dict):
            return node
        if node == NO_VALUE:
            return NO_VALUE_MARK
        if node == BUCKET_ARN:
            return arn
        if node == {"Ref": "EvidenceErasurePrincipalArn"}:
            return erasure
        if node == WRITER_ROLE:
            return WRITER_ROLE_ARN
        if "Fn::Sub" in node:
            return node["Fn::Sub"].replace("${EvidenceBucket.Arn}", arn).replace("${EvidenceErasureObjectKey}", erasure_key)
        if "Fn::If" in node:
            name, when_set, when_unset = node["Fn::If"]
            assert name in ("HasErasurePrincipal", "HasErasureKey"), name
            return render(when_set if {"HasErasurePrincipal": erasure, "HasErasureKey": erasure_key}[name] else when_unset)
        rendered = {name: render(value) for name, value in node.items()}
        return {name: value for name, value in rendered.items() if value is not NO_VALUE_MARK}

    document = render(properties("EvidenceBucketPolicy")["PolicyDocument"])
    assert "${" not in json.dumps(document) and "Fn::" not in json.dumps(document)
    return document


def statement(document, sid):
    return next(entry for entry in document["Statement"] if entry["Sid"] == sid)


class FakeAws:
    """An `aws` command on PATH that keeps a small S3 state in a JSON file.

    It answers like the AWS CLI (JMESPath --query, text or JSON output) and applies the
    bucket's rules; `flaw` breaks one of them, `policy` is the bucket policy it holds
    (none: get-bucket-policy answers NoSuchBucketPolicy) and `eraser` is the stack's
    EvidenceErasurePrincipalArn. A request with `--profile WRITER_PROFILE` acts as the
    stack's evidence writer role.
    """

    def __init__(self, directory, flaw="", policy=None, eraser=""):
        self.bin = directory / "bin"
        self.bin.mkdir()
        self.state_file = directory / "state.json"
        policy_file = directory / "policy.json"
        if policy is not None:
            policy_file.write_text(json.dumps(policy))
        aws = self.bin / "aws"
        aws.write_text("#!%s\n%s" % (sys.executable, FAKE_AWS))
        aws.chmod(0o755)
        self.env = {"PATH": "%s:%s" % (self.bin, os.environ["PATH"]), "HOME": str(directory),
                    "FAKE_S3_STATE": str(self.state_file), "FAKE_S3_FLAW": flaw, "FAKE_S3_BUCKET": FAKE_BUCKET,
                    "FAKE_S3_POLICY": str(policy_file), "FAKE_S3_ERASER": eraser,
                    "FAKE_WRITER_PROFILE": WRITER_PROFILE, "FAKE_WRITER_ROLE": WRITER_ROLE_ARN,
                    "AWS_ACCESS_KEY_ID": "AKIAFAKEFAKEFAKE", "AWS_SECRET_ACCESS_KEY": SECRET}

    def run(self, command):
        return subprocess.run(command, env=self.env, capture_output=True, text=True, timeout=120)

    def state(self):
        return json.loads(self.state_file.read_text()) if self.state_file.exists() else {"calls": []}

    def calls(self):
        return self.state()["calls"]


def policy_for(flaw):
    """The bucket policy the fake holds for a flaw: the template's, or one broken by the flaw."""
    if flaw == "no-policy":
        return None
    document = rendered_bucket_policy(ERASER if flaw == "erasure-exemption" else "")
    if flaw == "weak-policy":
        statement(document, "DenyDeletesAndRetentionChanges")["Action"].remove("s3:BypassGovernanceRetention")
    if flaw == "unconditional-policy":
        statement(document, "DenyWriteWithoutIfNoneMatch")["Condition"]["Null"]["s3:if-none-match"] = "false"
    if flaw == "operator-store-write":
        document["Statement"].remove(statement(document, "OnlyTheWriterRoleWritesEvidence"))
    if flaw == "other-writer-role":
        statement(document, "OnlyTheWriterRoleWritesEvidence")["Condition"]["ArnNotEquals"]["aws:PrincipalArn"] = ADMIN
    if flaw == "fewer-writer-prefixes":
        statement(document, "OnlyTheWriterRoleWritesEvidence")["Resource"].pop()
    if flaw == "replicable-policy":
        statement(document, "DenyReplicationWrites")["Action"].remove("s3:ReplicateDelete")
    if flaw == "allow-policy":
        document["Statement"].append({"Sid": "AllowReaders", "Effect": "Allow",
                                      "Principal": {"AWS": "arn:aws:iam::444455556666:root"},
                                      "Action": "s3:GetObject", "Resource": "arn:aws:s3:::%s/*" % FAKE_BUCKET})
    return document


class CheckScriptCase(unittest.TestCase):
    """Runs evidence-bucket-check.sh against a fake S3 and counts its checks."""

    def run_check(self, flaw="", eraser="", writer=False):
        with tempfile.TemporaryDirectory() as directory:
            policy = rendered_bucket_policy(eraser) if eraser else policy_for(flaw)
            fake = FakeAws(Path(directory), flaw, policy, eraser)
            command = ["bash", str(CHECK_SCRIPT), "--stack", "core", "--region", "us-east-1"]
            result = fake.run(command + (["--writer-profile", WRITER_PROFILE] if writer else []))
            return result, fake.state()

    @staticmethod
    def writer_checks():
        """The writer profile's checks: the indented record and refused lines of its block."""
        script = CHECK_SCRIPT.read_text()
        start = script.index('    echo "Writer profile')
        return re.findall(r"^    (?:record|refused) \"", script[start:script.index("\nfi\n", start)], re.MULTILINE)

    def assert_every_check_passes(self, result, writer=False):
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        lines = result.stdout.splitlines()
        self.assertEqual([line for line in lines if line.startswith("FAIL")], [])
        checks = re.findall(r"^(?:check|record|expect) \"", CHECK_SCRIPT.read_text(), re.MULTILINE)
        self.assertGreaterEqual(len(checks), 30)
        expected = len(checks) + (len(self.writer_checks()) if writer else 0)
        self.assertEqual(len([line for line in lines if line.startswith("PASS")]), expected)


class EvidenceBucketCheckScriptTests(CheckScriptCase):
    """The live check, run against a fake S3 that applies the bucket's rules (and fakes that break one)."""

    def test_a_compliant_bucket_passes_every_check(self):
        result, _ = self.run_check()
        self.assert_every_check_passes(result)
        self.assertIn("PASS  the bucket policy holds the store's denials (DenyDeletesAndRetentionChanges ", result.stdout)
        self.assertIn(" OnlyTheWriterRoleWritesEvidence)\n", result.stdout)
        self.assertRegex(result.stdout, r"\nPASS  the operator's put to decision-logs/bucket-check/\d{8}T\d{6}Z/"
                                        r"operator\.txt \(a store prefix\) is refused \(denied\)\n")
        self.assertIn("PASS  Object Lock defaults to GOVERNANCE for exactly 7 years (Enabled GOVERNANCE 7 None)",
                      result.stdout)

    def test_a_bucket_whose_policy_exempts_the_named_erasure_principal_passes(self):
        result, _ = self.run_check(eraser=ERASER)
        self.assert_every_check_passes(result)

    def test_a_retention_of_365_day_years_passes(self):
        result, _ = self.run_check("day-years")
        self.assert_every_check_passes(result)

    def test_it_writes_only_under_the_bucket_check_prefix_and_aborts_its_upload(self):
        _, state = self.run_check()
        written = [key for command, key in state["calls"]
                   if command in ("put-object", "copy-object", "create-multipart-upload", "upload-part",
                                  "complete-multipart-upload")]
        self.assertGreaterEqual(len(written), 13)
        store = [key for key in written if key.startswith(tuple(STORE_PREFIXES))]
        self.assertEqual(len(store), 1, store)  # the operator's put, which the bucket refuses
        self.assertRegex(store[0], r"^decision-logs/bucket-check/\d{8}T\d{6}Z/operator\.txt$")
        for key in written:
            self.assertRegex(key, r"^(decision-logs/)?bucket-check/\d{8}T\d{6}Z/[a-z-]+\.txt$")
        self.assertEqual([command for command, _ in state["calls"]].count("abort-multipart-upload"), 1)
        self.assertEqual(state["uploads"], {})
        self.assertEqual(sorted(key.split("/")[0] + "/" + key.rsplit("/", 1)[1] for key in state["versions"]),
                         ["bucket-check/explicit.txt", "bucket-check/object.txt"])

    def test_the_store_key_it_tries_is_one_the_portal_records_as_unmapped(self):
        _, state = self.run_check()
        key = next(key for command, key in state["calls"] if key.startswith("decision-logs/"))
        spec = importlib.util.spec_from_file_location("_portal_evidence_store_keys",
                                                      REPO / "app" / "services" / "evidence_store" / "keys.py")
        module = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = module  # dataclasses resolves the module's annotations through sys.modules
        try:
            spec.loader.exec_module(module)
            self.assertEqual(module.classify(key).kind, "unmapped", key)
        finally:
            del sys.modules[spec.name]

    def test_an_operator_write_under_a_store_prefix_fails_and_names_the_stored_key(self):
        result, state = self.run_check("operator-store-write")
        self.assertEqual(result.returncode, 1)
        stored = [key for key in state["versions"] if key.startswith("decision-logs/")]
        self.assertEqual(len(stored), 1, state["versions"])
        failed = [line for line in result.stdout.splitlines() if line.startswith("FAIL")]
        self.assertEqual(failed, ["FAIL  the operator's put to %s (a store prefix) is refused: expected denied, got ok"
                                  % stored[0],
                                  "FAIL  the bucket policy holds the store's denials: expected DenyDeletesAndRetention"
                                  "Changes DenyInsecureTransport DenyNonSseS3Writes DenyNonStandardStorageClass "
                                  "DenyReplicationWrites DenySseCWrites DenyWriteWithoutIfNoneMatch "
                                  "OnlyTheWriterRoleWritesEvidence, got DenyDeletesAndRetentionChanges "
                                  "DenyInsecureTransport DenyNonSseS3Writes DenyNonStandardStorageClass "
                                  "DenyReplicationWrites DenySseCWrites DenyWriteWithoutIfNoneMatch"])
        self.assertIn("\n      %s is stored: Object Lock keeps it, and the portal records it as unmapped\n" % stored[0],
                      result.stdout)

    def test_each_broken_rule_fails_the_check(self):
        for flaw, failure in (("unconditional-put", "a put without If-None-Match is refused"),
                              ("delete", "a delete (a delete marker) is refused"),
                              ("delete", "the key holds one version and no delete marker"),
                              ("storage-class", "a STANDARD_IA put is refused"),
                              ("object-lock-headers", "a put with an Object Lock retention of its own is refused"),
                              ("object-lock-headers", "a put with a legal hold is refused"),
                              ("unconditional-complete", "completing a multipart upload without If-None-Match is refused"),
                              ("copy", "a copy into the bucket (CopyObject without If-None-Match) is refused"),
                              ("short-retention", "the version is retained for 7 years from its creation"),
                              ("lock-days", "Object Lock defaults to GOVERNANCE for exactly 7 years"),
                              ("lock-mode", "Object Lock defaults to GOVERNANCE for exactly 7 years"),
                              ("lock-years", "Object Lock defaults to GOVERNANCE for exactly 7 years"),
                              ("no-policy", "the bucket policy exists"),
                              ("no-policy", "the bucket policy holds the store's denials"),
                              ("weak-policy", "the bucket policy holds the store's denials"),
                              ("unconditional-policy", "the bucket policy holds the store's denials"),
                              ("erasure-exemption", "the bucket policy holds the store's denials"),
                              ("other-writer-role", "the bucket policy holds the store's denials"),
                              ("fewer-writer-prefixes", "the bucket policy holds the store's denials"),
                              ("replicable-policy", "the bucket policy holds the store's denials"),
                              ("allow-policy", "the bucket policy allows nothing"),
                              ("expiring-lifecycle", "the one lifecycle rule aborts incomplete uploads after 1 day "
                                                     "and expires nothing")):
            with self.subTest(flaw=flaw, failure=failure):
                result, _ = self.run_check(flaw)
                self.assertEqual(result.returncode, 1, flaw)
                self.assertIn("FAIL  " + failure + ":", result.stdout, flaw)

    def test_the_rendered_policy_is_the_template_policy(self):
        document = rendered_bucket_policy()
        self.assertEqual({entry["Sid"] for entry in document["Statement"]}, set(evidence_policy()) - {"ConfineErasureToOneKey"})
        self.assertEqual({entry["Sid"] for entry in rendered_bucket_policy(ERASER)["Statement"]}, set(evidence_policy()))
        arn = "arn:aws:s3:::" + FAKE_BUCKET
        self.assertEqual(statement(rendered_bucket_policy(ERASER), "ConfineErasureToOneKey")["NotResource"], arn)
        self.assertEqual(statement(rendered_bucket_policy(ERASER, STORE_KEY), "ConfineErasureToOneKey")["NotResource"],
                         arn + "/" + STORE_KEY)
        self.assertNotIn("Condition", statement(document, "DenyDeletesAndRetentionChanges"))
        exempt = statement(rendered_bucket_policy(ERASER), "DenyDeletesAndRetentionChanges")
        self.assertEqual(exempt["Condition"], {"ArnNotEquals": {"aws:PrincipalArn": ERASER}})
        self.assertNotIn("Condition", statement(rendered_bucket_policy(ERASER), "DenyReplicationWrites"))
        writer = statement(document, "OnlyTheWriterRoleWritesEvidence")
        self.assertEqual(writer["Condition"], {"ArnNotEquals": {"aws:PrincipalArn": WRITER_ROLE_ARN}})
        self.assertEqual(writer["Resource"], ["arn:aws:s3:::%s/%s*" % (FAKE_BUCKET, p) for p in STORE_PREFIXES])

    def test_days_counts_calendar_days(self):
        script = CHECK_SCRIPT.read_text()
        function = script[script.index("\ndays() {"):script.index("\n}\n", script.index("\ndays() {")) + 3]
        epoch = datetime.date(1970, 1, 1)
        for day in ("1970-01-01", "2000-02-29", "2024-02-28", "2024-03-01", "2033-10-04T12:00:00+00:00", "2100-12-31"):
            result = subprocess.run(["bash", "-c", function + 'days "$1"', "days", day],
                                    capture_output=True, text=True, timeout=30)
            self.assertEqual(result.stdout.strip(), str((datetime.date.fromisoformat(day[:10]) - epoch).days), day)

    def test_it_never_prints_or_reads_credentials(self):
        for writer in (False, True):
            result, _ = self.run_check(writer=writer)
            self.assertNotIn(SECRET, result.stdout + result.stderr)
            self.assertNotIn("AKIAFAKEFAKEFAKE", result.stdout + result.stderr)
        code = "\n".join(line for line in CHECK_SCRIPT.read_text().split("\n") if not line.lstrip().startswith("#"))
        for word in ("secretsmanager", "AWS_SECRET_ACCESS_KEY", "AWS_ACCESS_KEY_ID", "aws configure", "assume-role",
                     "get-session-token", "export-credentials", "credential_process"):
            self.assertNotIn(word, code)
        sts = [line.strip() for line in code.split("\n") if "aws sts" in line]
        self.assertEqual(len(sts), 1, sts)
        self.assertIn('aws sts get-caller-identity --profile "$WRITER" --query Arn --output text', sts[0])

    def test_usage_errors_make_no_aws_call(self):
        for arguments in (["--region", "us-east-1"],
                          ["--stack", "core", "--region", "us-east-1", "--writer-profile"],
                          ["--stack", "core", "--region", "us-east-1", "--writer-profile", ""]):
            with tempfile.TemporaryDirectory() as directory:
                fake = FakeAws(Path(directory))
                result = fake.run(["bash", str(CHECK_SCRIPT)] + arguments)
                self.assertEqual(result.returncode, 2, arguments)
                self.assertEqual(fake.calls(), [], arguments)


class EvidenceWriterProfileCheckTests(CheckScriptCase):
    """evidence-bucket-check.sh --writer-profile: the producer's profile acts as the writer role,
    which is refused each request a producer never makes."""

    def test_a_profile_acting_as_the_writer_role_passes_every_check(self):
        result, state = self.run_check(writer=True)
        self.assert_every_check_passes(result, writer=True)
        self.assertEqual(len(self.writer_checks()), 11)
        self.assertIn("PASS  the writer profile acts as the evidence writer role (%s)" % WRITER_SESSION, result.stdout)
        for refusal in ("GetObject", "ListBucket", "ListBucketVersions", "DeleteObject", "DeleteObjectVersion",
                        "PutObject", "PutObjectRetention", "PutObjectLegalHold", "PutObjectAcl", "PutObjectTagging"):
            self.assertRegex(result.stdout, r"\nPASS  the writer role cannot [^\n]* \(%s\) \(denied\)\n" % refusal)
        as_writer = [call for call, profile in zip(state["calls"], state["profiles"]) if profile == WRITER_PROFILE]
        self.assertEqual(len(as_writer), 11)
        self.assertEqual(as_writer[0], ["get-caller-identity", ""])
        for command, key in as_writer[1:]:
            if command.startswith("list-"):
                self.assertEqual(key, "", command)
            else:
                self.assertRegex(key, r"^bucket-check/\d{8}T\d{6}Z/(object|writer)\.txt$", command)
        self.assertEqual(set(state["profiles"]), {None, WRITER_PROFILE})
        self.assertEqual(sorted(key.rsplit("/", 1)[1] for key in state["versions"]), ["explicit.txt", "object.txt"])

    def test_without_a_writer_profile_no_request_names_a_profile(self):
        result, state = self.run_check()
        self.assertNotIn("writer", result.stdout)
        self.assertEqual(set(state["profiles"]), {None})
        self.assertNotIn("get-caller-identity", [command for command, _ in state["calls"]])

    def test_each_writer_flaw_fails_its_check(self):
        for flaw, failure in (("writer-identity", "the writer profile acts as the evidence writer role"),
                              ("writer-assume-denied", "the writer profile acts as the evidence writer role"),
                              ("writer-assume-denied", "the writer role cannot read the stored version (GetObject)"),
                              ("writer-assume-denied", "the writer role cannot put outside the store prefixes"),
                              ("writer-get-object", "the writer role cannot read the stored version (GetObject)"),
                              ("writer-list-objects-v2", "the writer role cannot list the bucket (ListBucket)"),
                              ("writer-list-object-versions",
                               "the writer role cannot list object versions (ListBucketVersions)"),
                              ("writer-delete-object", "the writer role cannot delete the object (DeleteObject)"),
                              ("writer-delete-object",
                               "the writer role cannot delete the version (DeleteObjectVersion)"),
                              ("writer-anywhere", "the writer role cannot put outside the store prefixes (PutObject)"),
                              ("writer-put-object-retention",
                               "the writer role cannot change the version's retention (PutObjectRetention)"),
                              ("writer-put-object-legal-hold",
                               "the writer role cannot place a legal hold on the version (PutObjectLegalHold)"),
                              ("writer-put-object-acl", "the writer role cannot set the version's ACL (PutObjectAcl)"),
                              ("writer-put-object-tagging",
                               "the writer role cannot tag the version (PutObjectTagging)")):
            with self.subTest(flaw=flaw, failure=failure):
                result, _ = self.run_check(flaw, writer=True)
                self.assertEqual(result.returncode, 1, flaw)
                self.assertIn("FAIL  " + failure, result.stdout, flaw)
                failed = [line for line in result.stdout.splitlines() if line.startswith("FAIL")]
                expected = {"writer-assume-denied": len(self.writer_checks()), "writer-delete-object": 2}
                self.assertEqual(len(failed), expected.get(flaw, 1), result.stdout)

    def test_a_stack_without_the_writer_role_output_stops_before_any_s3_request(self):
        for writer in (False, True):  # the bucket policy's check needs the role's ARN too
            result, state = self.run_check("no-writer-role", writer=writer)
            self.assertEqual(result.returncode, 1, writer)
            self.assertIn("stack core has no EvidenceWriterRoleArn output", result.stderr)
            self.assertEqual({command for command, _ in state["calls"]}, {"describe-stacks"})


if __name__ == "__main__":
    unittest.main()
