"""Consistency tests for the two CloudFormation templates in deploy/aws/.

trust-portal.yaml is the core stack; trust-portal-pipeline.yaml is the optional
CI/CD stack that imports the core stack's exports. Standard library only.
These tests keep the core template's inline Lambda code equal to
deploy/aws/lambdas/*.py and its collector statements equal to
iam/trust-portal-collector-policy.json, keep every import matched by an export
and the deploy role scoped to the core stack's resources, keep both templates
small enough for `aws cloudformation deploy` without an S3 bucket, and keep the
deployment files free of account-specific values.
"""
import json
import re
import unittest
from pathlib import Path

AWS_DIR = Path(__file__).resolve().parent.parent
REPO = AWS_DIR.parent.parent
TEMPLATE_PATH = AWS_DIR / "trust-portal.yaml"
PIPELINE_PATH = AWS_DIR / "trust-portal-pipeline.yaml"
TEMPLATE = TEMPLATE_PATH.read_text()
PIPELINE = PIPELINE_PATH.read_text()
LINES = TEMPLATE.split("\n")
PIPELINE_LINES = PIPELINE.split("\n")
DEPLOY_SH = (AWS_DIR / "deploy.sh").read_text()

# `aws cloudformation deploy` sends a template inline only up to this size.
INLINE_TEMPLATE_LIMIT = 51200

# Statements the template scopes with parameters instead of copying verbatim.
SCOPED_SIDS = {"TrustPortalCollectorCodeCommitRepositories"}
STACK_UUID = "!Select [2, !Split ['/', !Ref 'AWS::StackId']]"


def inline_code(source_name):
    marker = "# Source of truth: deploy/aws/lambdas/%s" % source_name
    start = next(i for i, line in enumerate(LINES) if marker in line)
    assert LINES[start + 1].strip() == "ZipFile: |", LINES[start + 1]
    indent = len(LINES[start + 1]) - len(LINES[start + 1].lstrip()) + 2
    block = []
    for line in LINES[start + 2:]:
        if line.strip() and len(line) - len(line.lstrip()) < indent:
            break
        block.append(line[indent:] if line.strip() else "")
    while block and not block[-1]:
        block.pop()
    return "\n".join(block) + "\n"


def collector_block():
    begin = next(i for i, line in enumerate(LINES) if "# BEGIN iam/trust-portal-collector-policy.json" in line)
    end = next(i for i, line in enumerate(LINES) if "# END iam/trust-portal-collector-policy.json" in line)
    return [json.loads(line.strip()[2:]) for line in LINES[begin + 1:end]]


def template_statement_actions(sid):
    start = next(i for i, line in enumerate(LINES) if line.strip() == "- Sid: %s" % sid)
    action_line = next(line for line in LINES[start:start + 4] if "Action:" in line)
    return re.findall(r"'([^']+)'", action_line)


def output_keys(lines=LINES):
    start = lines.index("Outputs:")
    return {m.group(1) for line in lines[start + 1:] for m in [re.match(r"^  (\w+):", line)] if m}


def resource_block(logical_id, lines=LINES):
    """Return the template text of one resource (its header line to the next resource)."""
    start = lines.index("  %s:" % logical_id)
    end = next(i for i in range(start + 1, len(lines))
               if re.match(r"^  [A-Za-z]", lines[i]) or lines[i] in ("Outputs:",))
    return "\n".join(lines[start:end])


def statement_block(block, sid):
    lines = block.split("\n")
    start = next(i for i, line in enumerate(lines) if line.strip().endswith("Sid: %s" % sid))
    indent = len(lines[start]) - len(lines[start].lstrip())
    end = next((i for i in range(start + 1, len(lines))
                if lines[i].strip() and len(lines[i]) - len(lines[i].lstrip()) <= indent), len(lines))
    return "\n".join(lines[start:end])


def secret_specs():
    """The secret-init function's SECRET_SPECS, with ${...} references kept as text."""
    match = re.search(r"SECRET_SPECS: !Sub '(.+)'\n", TEMPLATE)
    return json.loads(match.group(1))


def core_import(name):
    return "{'Fn::ImportValue': !Sub '${CoreStackName}-%s'}" % name


# How the scripts read a stack output: deploy.sh's `$(output Name)` helper, or a
# jq/JMESPath filter on OutputKey. Output names are PascalCase, so AWS CLI flags
# such as `--output text)` never match.
OUTPUT_READS = (
    re.compile(r"\$\(output ([A-Z]\w*)\)"),
    re.compile(r'OutputKey ?== ?"([A-Z]\w*)"'),
    re.compile(r"OutputKey=='([A-Z]\w*)'"),
)


def outputs_read(text):
    return {name for pattern in OUTPUT_READS for name in pattern.findall(text)}


class InlineCodeTests(unittest.TestCase):
    def test_snapshot_function_code_matches_source(self):
        source = (AWS_DIR / "lambdas" / "db_snapshot.py").read_text()
        self.assertEqual(inline_code("db_snapshot.py"), source)

    def test_secret_init_function_code_matches_source(self):
        source = (AWS_DIR / "lambdas" / "secret_init.py").read_text()
        self.assertEqual(inline_code("secret_init.py"), source)


class CollectorPolicyTests(unittest.TestCase):
    def setUp(self):
        policy = json.loads((REPO / "iam" / "trust-portal-collector-policy.json").read_text())
        self.file_statements = {s["Sid"]: s for s in policy["Statement"]}
        self.block = {s["Sid"]: s for s in collector_block()}

    def test_every_collector_statement_is_granted_verbatim(self):
        for sid, statement in self.file_statements.items():
            if sid in SCOPED_SIDS:
                continue
            self.assertEqual(self.block.get(sid), statement, sid)

    def test_template_adds_no_unlisted_collector_statement(self):
        extra = set(self.block) - set(self.file_statements)
        self.assertEqual(extra, set())

    def test_scoped_codecommit_statement_grants_the_same_actions(self):
        for sid in SCOPED_SIDS & set(self.file_statements):
            self.assertEqual(sorted(template_statement_actions(sid)),
                             sorted(self.file_statements[sid]["Action"]))


class TemplateShapeTests(unittest.TestCase):
    def test_both_templates_fit_the_inline_deploy_limit(self):
        for text in (TEMPLATE, PIPELINE):
            self.assertLessEqual(len(text.encode()), INLINE_TEMPLATE_LIMIT)

    def test_every_bucket_policy_of_a_retained_bucket_is_retained(self):
        """Deleting the stack, or replacing the policy, never strips a retained bucket of its denials."""
        retain = {"    DeletionPolicy: Retain", "    UpdateReplacePolicy: Retain"}
        checked = []
        for text, lines in ((TEMPLATE, LINES), (PIPELINE, PIPELINE_LINES)):
            for logical_id in re.findall(r"^  (\w+):\n    Type: AWS::S3::BucketPolicy$", text, re.MULTILINE):
                policy = resource_block(logical_id, lines).split("\n")
                bucket = next(re.fullmatch(r" {6}Bucket: !Ref (\w+)", line) for line in policy
                              if line.startswith("      Bucket: ")).group(1)
                if "    DeletionPolicy: Retain" in resource_block(bucket, lines).split("\n"):
                    self.assertLessEqual(retain, set(policy), logical_id)
                    checked.append(logical_id)
        self.assertEqual(sorted(checked), ["ArchiveBucketPolicy", "EvidenceBucketPolicy"])

    def test_outputs_read_by_scripts_exist_on_the_core_stack(self):
        keys = output_keys()
        for script in ("deploy.sh", "bootstrap-admin.sh", "set-secret-key.sh", "archive-bucket-check.sh",
                       "evidence-bucket-check.sh"):
            used = outputs_read((AWS_DIR / script).read_text())
            self.assertTrue(used, script)
            self.assertEqual(used - keys, set(), script)

    def test_output_scan_ignores_cli_flags_and_catches_missing_outputs(self):
        sample = "\n".join([
            "VERSION=$(aws lightsail get-x --query 'a.b' --output text)",
            "STATE=$(aws lightsail get-y --output json)",
            "SERVICE=$(output ContainerServiceName)",
            "GONE=$(output NoSuchOutput)",
            "URL=$(jq -r '.[] | select(.OutputKey == \"PublicUrl\") | .OutputValue' f)",
            "ARN=$(aws cloudformation describe-stacks --query \"Stacks[0].Outputs[?OutputKey=='PortalSecretArn']\" --output text)",
        ])
        used = outputs_read(sample)
        self.assertEqual(used, {"ContainerServiceName", "NoSuchOutput", "PublicUrl", "PortalSecretArn"})
        self.assertEqual(used - output_keys(), {"NoSuchOutput"})

    def test_buildspecs_named_by_the_pipeline_exist(self):
        paths = re.findall(r"BuildSpec: (\S+)\}", PIPELINE)
        self.assertEqual(len(paths), 2)
        for path in paths:
            self.assertTrue((REPO / path).is_file(), path)

    def test_no_account_ids_in_deployment_files(self):
        for path in AWS_DIR.parent.rglob("*"):
            if path.is_file() and "tests" not in path.parts and path.suffix in {".yaml", ".yml", ".sh", ".py", ".md", ".json"}:
                self.assertIsNone(re.search(r"\b\d{12}\b", path.read_text()), path)

    def test_app_user_must_differ_from_the_owner(self):
        self.assertIn("Assert: !Not [!Equals [!Ref DatabaseAppUsername, !Ref DatabaseMasterUsername]]", TEMPLATE)


class StackSplitTests(unittest.TestCase):
    """The pipeline stack reads the core stack only through its exports."""

    def test_every_import_has_a_core_export(self):
        imported = set(re.findall(r"\$\{CoreStackName\}-(\w+)'", PIPELINE))
        exported = set(re.findall(r"Export: \{Name: !Sub '\$\{AWS::StackName\}-(\w+)'\}", TEMPLATE))
        self.assertTrue(imported)
        self.assertEqual(imported - exported, set())

    def test_core_stack_holds_no_ci_cd_resources(self):
        for resource_type in ("AWS::CodePipeline::Pipeline", "AWS::CodeBuild::Project",
                              "AWS::CodeConnections::Connection", "AWS::Events::Rule"):
            self.assertNotIn(resource_type, TEMPLATE)
            self.assertIn(resource_type, PIPELINE)

    def test_pipeline_deploys_to_the_core_stack(self):
        project = resource_block("DeployProject", PIPELINE_LINES)
        self.assertIn("- {Name: STACK_NAME, Value: !Ref CoreStackName}", project)
        self.assertIn("- {Name: WITNESS_ARMED, Value: !Ref WitnessArmed}", project)
        self.assertIn("    Default: 'false'", PIPELINE[PIPELINE.index("  WitnessArmed:"):])


class OwnerCredentialTests(unittest.TestCase):
    """D-A: owner credentials live in their own secret and never reach the runtime role."""

    def test_runtime_role_reads_only_the_runtime_secret(self):
        runtime = resource_block("RuntimeRole")
        self.assertIn("Resource: !Ref PortalSecret", statement_block(runtime, "PortalSecretRead"))
        self.assertNotIn("OwnerSecret", runtime)

    def test_owner_secret_is_read_by_the_deploy_role_and_filled_by_secret_init_only(self):
        core = [name for name in ("SecretInitRole", "RuntimeRole", "SnapshotRole")
                if "OwnerSecret" in resource_block(name)]
        pipeline = [name for name in ("DeployRole", "BuildRole", "PipelineRole")
                    if "OwnerSecret" in resource_block(name, PIPELINE_LINES)]
        self.assertEqual(core, ["SecretInitRole"])
        self.assertEqual(pipeline, ["DeployRole"])

    def test_database_master_password_comes_from_the_owner_secret(self):
        self.assertIn("{{resolve:secretsmanager:${OwnerSecret}:SecretString:DATABASE_OWNER_PASSWORD}}",
                      resource_block("Database"))

    def test_runtime_secret_is_stripped_of_owner_keys_and_the_bucket_names(self):
        runtime, owner = secret_specs()
        self.assertEqual(runtime["SecretId"], "${PortalSecret}")
        self.assertEqual(runtime["Remove"], ["DATABASE_OWNER_USER", "DATABASE_OWNER_PASSWORD",
                                             "DATABASE_OWNER_URL", "AUDIT_WITNESS_BUCKET", "EVIDENCE_STORE_BUCKET"])
        self.assertNotIn("DATABASE_OWNER_PASSWORD", runtime["Generate"])
        self.assertNotIn("AUDIT_WITNESS_BUCKET", runtime["Fixed"])
        self.assertNotIn("EVIDENCE_STORE_BUCKET", runtime["Fixed"])
        self.assertEqual(owner["SecretId"], "${OwnerSecret}")
        self.assertEqual(owner["Generate"], {"DATABASE_OWNER_PASSWORD": "password"})
        self.assertEqual(runtime["Regenerable"], ["SECRET_KEY", "DATABASE_PASSWORD", "BOOTSTRAP_TOKEN"])

    def test_no_stateful_secret_uses_generate_secret_string(self):
        self.assertNotIn("GenerateSecretString", TEMPLATE)

    def test_deploy_passes_owner_credentials_from_the_owner_secret(self):
        self.assertIn('--secret-id "$OWNER_SECRET"', DEPLOY_SH)
        self.assertIn("DATABASE_OWNER_USER: $owner[0].DATABASE_OWNER_USER", DEPLOY_SH)
        self.assertIn("DATABASE_OWNER_PASSWORD: $owner[0].DATABASE_OWNER_PASSWORD", DEPLOY_SH)


class WitnessTests(unittest.TestCase):
    """D-B, N7 and the shakedown mode."""

    def test_runtime_role_writes_only_chain_heads_and_never_archives(self):
        runtime = resource_block("RuntimeRole")
        publish = statement_block(runtime, "PublishChainHeads")
        self.assertIn("Action: s3:PutObject", publish)
        self.assertIn("Resource: !Sub '${ArchiveBucket.Arn}/chain-heads/*'", publish)
        deny = statement_block(runtime, "NoArchiveWrites")
        self.assertIn("Effect: Deny", deny)
        self.assertIn("Action: ['s3:PutObject', 's3:AbortMultipartUpload']", deny)
        self.assertIn("Resource: !Sub '${ArchiveBucket.Arn}/archives/*'", deny)
        allows = [statement_block(runtime, sid) for sid in re.findall(r"^\s+- Sid: (\w+)$", runtime, re.MULTILINE)]
        writers = [s for s in allows if "Effect: Allow" in s and "s3:PutObject" in s]
        self.assertEqual(writers, [publish])

    def test_runtime_role_reads_manifests_and_heads_for_the_anchor_check(self):
        runtime = resource_block("RuntimeRole")
        listing = statement_block(runtime, "ListWitnessVersions")
        self.assertIn("Action: s3:ListBucketVersions", listing)
        self.assertIn("Condition: {StringLike: {'s3:prefix': ['archives/*', 'chain-heads/*']}}", listing)
        reading = statement_block(runtime, "ReadManifestsAndHeads")
        self.assertIn("Action: ['s3:GetObject', 's3:GetObjectVersion']", reading)
        self.assertIn("Resource: [!Sub '${ArchiveBucket.Arn}/archives/*.manifest.json', "
                      "!Sub '${ArchiveBucket.Arn}/chain-heads/*']", reading)

    def test_archives_are_write_once_without_blocking_multipart_parts(self):
        statement = statement_block(resource_block("ArchiveBucketPolicy"), "DenyArchiveWriteWithoutIfNoneMatch")
        self.assertIn("Effect: Deny", statement)
        self.assertIn("Action: s3:PutObject", statement)
        self.assertIn("Resource: !Sub '${ArchiveBucket.Arn}/archives/*'", statement)
        self.assertIn("'Null': {'s3:if-none-match': 'true'}", statement)
        self.assertIn("Bool: {'s3:ObjectCreationOperation': 'true'}", statement)
        self.assertIn("AbortIncompleteMultipartUpload: {DaysAfterInitiation: 7}", resource_block("ArchiveBucket"))

    def test_operator_policy_writes_archives_and_heads_and_reads_both(self):
        policy = json.loads((REPO / "iam" / "trust-portal-archive-operator-policy.json").read_text())
        by_sid = {s["Sid"]: s for s in policy["Statement"]}
        self.assertEqual(by_sid["WriteArchives"]["Action"], ["s3:PutObject", "s3:AbortMultipartUpload"])
        self.assertTrue(by_sid["WriteArchives"]["Resource"].endswith("/archives/*"))
        self.assertEqual(by_sid["PublishFinalHead"]["Action"], ["s3:PutObject"])
        self.assertTrue(by_sid["PublishFinalHead"]["Resource"].endswith("/chain-heads/*"))
        self.assertEqual(by_sid["ListWitnessVersions"]["Condition"],
                         {"StringLike": {"s3:prefix": ["archives/*", "chain-heads/*"]}})
        managed = resource_block("ArchiveOperatorPolicy")
        for sid in by_sid:
            self.assertIn("Sid: " + sid, managed)
        self.assertIn("ArchiveOperatorPolicyArn: {Value: !Ref ArchiveOperatorPolicy}", TEMPLATE)

    def test_bucket_policy_denies_head_writes_without_if_none_match(self):
        statement = statement_block(resource_block("ArchiveBucketPolicy"), "DenyHeadWriteWithoutIfNoneMatch")
        self.assertIn("Effect: Deny", statement)
        self.assertIn("Principal: '*'", statement)
        self.assertIn("Action: s3:PutObject", statement)
        self.assertIn("Resource: !Sub '${ArchiveBucket.Arn}/chain-heads/*'", statement)
        self.assertIn("Condition: {'Null': {'s3:if-none-match': 'true'}}", statement)

    def test_archive_bucket_policy_denies_deletes_and_retention_changes(self):
        policy = resource_block("ArchiveBucketPolicy")
        self.assertIn("Effect: Deny", statement_block(policy, "DenyDeletes"))
        self.assertIn("'s3:DeleteObject', 's3:DeleteObjectVersion'", statement_block(policy, "DenyDeletes"))
        self.assertIn("'s3:PutObjectRetention', 's3:PutBucketObjectLockConfiguration'",
                      statement_block(policy, "DenyRetentionChanges"))

    def test_archive_bucket_policy_denies_replication_writes_to_everyone(self):
        """Replicas and replicated delete markers (s3:ReplicateObject, s3:ReplicateDelete) never land in the bucket."""
        self.assertEqual(statement_block(resource_block("ArchiveBucketPolicy"), "DenyReplicationWrites").split("\n"), [
            "          - Sid: DenyReplicationWrites",
            "            Effect: Deny",
            "            Principal: '*'",
            "            Action: ['s3:ReplicateObject', 's3:ReplicateDelete']",
            "            Resource: !Sub '${ArchiveBucket.Arn}/*'"])

    def test_every_deploy_states_its_witness_mode(self):
        self.assertIn('WITNESS=""\n', DEPLOY_SH)
        self.assertIn('--witness) [ -z "$WITNESS" ] || usage; WITNESS=1; shift ;;', DEPLOY_SH)
        self.assertIn('--no-witness) [ -z "$WITNESS" ] || usage; WITNESS=0; shift ;;', DEPLOY_SH)
        self.assertIn('&& [ -n "$WITNESS" ] || usage', DEPLOY_SH)

    def test_no_witness_sets_the_kill_switch_and_omits_the_bucket(self):
        self.assertRegex(DEPLOY_SH, r'if \[ "\$WITNESS" -eq 1 \]; then\n\s+WITNESS_BUCKET=\$\(output ArchiveBucketName\)')
        self.assertIn('(if $witness == "" then {AUDIT_WITNESS_DISABLED: "true"} '
                      'else {AUDIT_WITNESS_BUCKET: $witness} end)', DEPLOY_SH)

    def test_deploy_fails_unless_health_reports_an_intended_witness_state(self):
        check = DEPLOY_SH[DEPLOY_SH.index("ACTUAL_WITNESS="):]
        self.assertLess(DEPLOY_SH.index('[ "$code" = "200" ]'), DEPLOY_SH.index("ACTUAL_WITNESS="))
        self.assertIn("jq -r '.witness // \"missing\"'", check)
        self.assertIn("        enabled) log ", check)
        self.assertIn("        unarmed) log ", check)
        self.assertRegex(check, r'\*\) fail "the portal reports witness')
        self.assertIn('[ "$ACTUAL_WITNESS" = "disabled" ] \\\n        || fail', check)

    def test_pipeline_passes_an_explicit_flag_and_defaults_to_no_witness(self):
        buildspec = (AWS_DIR / "buildspec-deploy.yml").read_text()
        self.assertIn('if [ "${WITNESS_ARMED:-false}" = "true" ]; then WITNESS_FLAG="--witness"; '
                      'else WITNESS_FLAG="--no-witness"; fi', buildspec)
        self.assertIn('"$WITNESS_FLAG"', buildspec)
        self.assertNotIn("PublishWitness", PIPELINE)

    def test_operators_cannot_put_a_bucket_name_in_the_secret(self):
        self.assertIn("DATABASE_OWNER_*|AUDIT_WITNESS_BUCKET|EVIDENCE_STORE_BUCKET)", (AWS_DIR / "set-secret-key.sh").read_text())

    def test_verifier_policy_reads_heads_and_archives_only(self):
        policy = json.loads((REPO / "iam" / "trust-portal-witness-verifier-policy.json").read_text())
        actions = {a for s in policy["Statement"] for a in s["Action"]}
        self.assertEqual(actions, {"s3:ListBucketVersions", "s3:GetObject", "s3:GetObjectVersion"})
        listing = next(s for s in policy["Statement"] if "s3:ListBucketVersions" in s["Action"])
        self.assertEqual(listing["Condition"], {"StringLike": {"s3:prefix": ["archives/*", "chain-heads/*"]}})
        reading = next(s for s in policy["Statement"] if "s3:GetObjectVersion" in s["Action"])
        self.assertEqual([r.rsplit("/", 2)[-2] for r in reading["Resource"]], ["archives", "chain-heads"])
        managed = resource_block("WitnessVerifierPolicy")
        self.assertIn("Action: s3:ListBucketVersions", managed)
        self.assertIn("Condition: {StringLike: {'s3:prefix': ['archives/*', 'chain-heads/*']}}", managed)
        self.assertIn("Action: ['s3:GetObject', 's3:GetObjectVersion']", managed)
        self.assertNotIn("s3:PutObject", managed)


class SecretInitTrustTests(unittest.TestCase):
    """M6: the secret-init function acts only on its own environment, for this stack."""

    def test_spec_comes_from_the_function_environment(self):
        function = resource_block("SecretInitFunction")
        self.assertIn("STACK_ID: !Ref 'AWS::StackId'", function)
        self.assertIn("SECRET_SPECS: !Sub '", function)
        custom = resource_block("PortalSecretValues")
        self.assertNotIn("Secrets:", custom)
        env_spec = re.search(r"SECRET_SPECS: !Sub ('.+')\n", function).group(1)
        self.assertIn("      Spec: !Sub " + env_spec + "\n", custom)

    def test_only_this_stacks_cloudformation_may_invoke_it(self):
        permission = resource_block("SecretInitPermission")
        self.assertIn("Principal: cloudformation.amazonaws.com", permission)
        self.assertIn("SourceArn: !Ref 'AWS::StackId'", permission)
        self.assertIn("SourceAccount: !Ref 'AWS::AccountId'", permission)
        self.assertIn("FunctionName: !Ref SecretInitFunction", permission)


class HeadEncryptionTests(unittest.TestCase):
    """H3: heads are written only with SSE-S3, so every auditor can read them."""

    def test_runtime_role_cannot_write_heads_with_kms_or_customer_keys(self):
        runtime = resource_block("RuntimeRole")
        sse = statement_block(runtime, "HeadsOnlySseS3")
        self.assertIn("Effect: Deny", sse)
        self.assertIn("Resource: !Sub '${ArchiveBucket.Arn}/chain-heads/*'", sse)
        # Deny only a present header that is not AES256; a request without one
        # (UploadPart, CompleteMultipartUpload) takes the bucket's SSE-S3 default.
        self.assertIn("'Null': {'s3:x-amz-server-side-encryption': 'false'}", sse)
        self.assertIn("StringNotEquals: {'s3:x-amz-server-side-encryption': AES256}", sse)
        self.assertNotIn("IfExists", TEMPLATE)
        ssec = statement_block(runtime, "NoSseCHeads")
        self.assertIn("Effect: Deny", ssec)
        self.assertIn("Condition: {'Null': {'s3:x-amz-server-side-encryption-customer-algorithm': 'false'}}", ssec)
        self.assertIn("SSEAlgorithm: AES256", resource_block("ArchiveBucket"))

    def test_bucket_policy_keeps_every_witness_and_archive_write_on_sse_s3(self):
        policy = resource_block("ArchiveBucketPolicy")
        both = "Resource: [!Sub '${ArchiveBucket.Arn}/chain-heads/*', !Sub '${ArchiveBucket.Arn}/archives/*']"
        sse = statement_block(policy, "DenyNonSseS3Writes")
        self.assertIn(both, sse)
        # Deny only a present header that is not AES256; a request without one
        # (UploadPart, CompleteMultipartUpload) takes the bucket's SSE-S3 default.
        self.assertIn("'Null': {'s3:x-amz-server-side-encryption': 'false'}", sse)
        self.assertIn("StringNotEquals: {'s3:x-amz-server-side-encryption': AES256}", sse)
        self.assertNotIn("IfExists", TEMPLATE)
        ssec = statement_block(policy, "DenySseCWrites")
        self.assertIn(both, ssec)
        self.assertIn("Condition: {'Null': {'s3:x-amz-server-side-encryption-customer-algorithm': 'false'}}", ssec)


class ArchiveBucketCheckScriptTests(unittest.TestCase):
    """The live check the unit tests cannot replace (the S3 mock ignores bucket policies)."""

    def setUp(self):
        self.text = (AWS_DIR / "archive-bucket-check.sh").read_text()

    def test_it_writes_only_under_the_deploy_test_prefix(self):
        self.assertIn('PREFIX="archives/deploy-test/$(date -u +%Y%m%dT%H%M%SZ)"', self.text)
        code = [line for line in self.text.split("\n") if not line.lstrip().startswith("#")]
        self.assertFalse([line for line in code if "chain-heads" in line and "echo" not in line])

    def test_it_proves_write_once_sse_and_multipart(self):
        for expected, name in (("ok", "single-part write"), ("412", "the same key again"),
                               ("denied", "without If-None-Match"), ("denied", "SSE-KMS"),
                               ("ok", "multipart upload"), ("412", "second multipart upload")):
            self.assertRegex(self.text, r'check "[^"]*%s[^"]*" %s ' % (re.escape(name), expected))
        self.assertIn("--multipart-upload \"file://$WORK/upload.json\" --if-none-match '*'", self.text)
        self.assertIn('exit "$FAILED"', self.text)


class SuppressionTests(unittest.TestCase):
    def test_no_template_suppresses_a_cfn_lint_check(self):
        for text in (TEMPLATE, PIPELINE):
            self.assertNotIn("ignore_checks", text)


class HealthBudgetTests(unittest.TestCase):
    def test_health_window_covers_database_wait_and_migration_lock_retries(self):
        interval = int(re.search(r"intervalSeconds: (\d+)", DEPLOY_SH).group(1))
        threshold = int(re.search(r"unhealthyThreshold: (\d+)", DEPLOY_SH).group(1))
        database_wait, lock_retries = 120, 5 * 5 + 4 * 3
        self.assertGreaterEqual(interval * threshold, database_wait + lock_retries + 60)


class NamingTests(unittest.TestCase):
    CORE_NAMES = re.compile(
        r"^\s+(?:Name|RoleName|PolicyName|BucketName|FunctionName|LogGroupName|ServiceName|CertificateName|"
        r"RepositoryName|RelationalDatabaseName|UserName|ConnectionName|ManagedPolicyName): !Sub (.+)$", re.MULTILINE)
    PIPELINE_NAMES = re.compile(r"(?:Name|RoleName|BucketName|LogGroupName|ConnectionName): !Sub\n\s+- (\S+)\n")
    LONGEST = {"OrgPrefix": "a" * 8, "AppName": "b" * 12, "EnvironmentName": "c" * 5,
               "O": "a" * 8, "A": "b" * 12, "E": "c" * 5,
               "AWS::AccountId": "1" * 12, "AWS::Region": "ap-southeast-2",
               "AWS::Partition": "aws", "AWS::StackName": "s"}

    def render(self, name):
        return re.sub(r"\$\{([^}]+)\}", lambda m: self.LONGEST[m.group(1)], name)

    def test_every_resource_name_carries_the_environment(self):
        core = self.CORE_NAMES.findall(TEMPLATE)
        pipeline = [n for n in self.PIPELINE_NAMES.findall(PIPELINE) if not n.startswith("arn:")]
        self.assertGreater(len(core), 15)
        self.assertGreater(len(pipeline), 9)
        for name in core:
            self.assertIn("${EnvironmentName}", name)
        for name in pipeline:
            self.assertIn("${E}", name)

    def test_bucket_names_carry_account_and_region(self):
        buckets = re.findall(r"BucketName: !Sub (.+)", TEMPLATE)
        buckets += re.findall(r"BucketName: !Sub\n\s+- (\S+)", PIPELINE)
        self.assertEqual(len(buckets), 3)
        for bucket in buckets:
            self.assertTrue(bucket.endswith("-${AWS::AccountId}-${AWS::Region}"), bucket)
            self.assertLessEqual(len(self.render(bucket)), 63, bucket)

    def test_lightsail_names_are_unique_across_resource_types(self):
        # Lightsail resource names share one namespace per region: a certificate named like the
        # container service makes whichever is created second fail with "already exists".
        names = re.findall(r"^\s+(?:ServiceName|CertificateName|RelationalDatabaseName): !Sub (.+)$",
                           TEMPLATE, re.MULTILINE)
        self.assertEqual(len(names), 3)
        self.assertEqual(len(set(names)), 3, names)

    def test_longest_names_fit_their_service_limits(self):
        roles = re.findall(r"RoleName: !Sub (.+)", TEMPLATE) + re.findall(r"RoleName: !Sub\n\s+- (\S+)", PIPELINE)
        for role in roles:
            self.assertLessEqual(len(self.render(role)), 64, role)
        connections = re.findall(r"ConnectionName: !Sub\n\s+- (\S+)", PIPELINE)
        self.assertEqual(len(connections), 1)
        self.assertLessEqual(len(self.render(connections[0])), 32)
        for function in re.findall(r"FunctionName: !Sub (.+)", TEMPLATE):
            self.assertLessEqual(len(self.render(function)), 64, function)


class LightsailScopeTests(unittest.TestCase):
    """N10: Lightsail writes are limited to the core stack's resources and tagged snapshots."""

    def test_snapshot_function_creates_and_deletes_only_this_stacks_snapshots(self):
        role = resource_block("SnapshotRole")
        create = statement_block(role, "CreateTaggedSnapshot")
        self.assertIn("StringEquals: {'aws:RequestTag/trust-portal-stack': %s}" % STACK_UUID, create)
        self.assertIn("ForAllValues:StringEquals: {'aws:TagKeys': [trust-portal-stack]}", create)
        delete = statement_block(role, "DeleteOwnSnapshots")
        self.assertIn("StringEquals: {'aws:ResourceTag/trust-portal-stack': %s}" % STACK_UUID, delete)

    def test_snapshot_function_tags_with_the_same_key_and_value(self):
        function = resource_block("SnapshotFunction")
        self.assertIn("SNAPSHOT_TAG_KEY: trust-portal-stack", function)
        self.assertIn("SNAPSHOT_TAG_VALUE: " + STACK_UUID, function)
        self.assertIn("SnapshotTagValue: {Value: %s, Export:" % STACK_UUID, TEMPLATE)
        self.assertIn('[{key: "trust-portal-stack", value: $value}]', DEPLOY_SH)
        self.assertIn('--tags "$SNAPSHOT_TAGS"', DEPLOY_SH)

    def test_tagged_snapshot_creates_may_tag_on_create(self):
        # Lightsail authorizes the --tags of a create as lightsail:TagResource; without it the
        # tag-conditioned create is denied.
        for role, sid in ((resource_block("SnapshotRole"), "CreateTaggedSnapshot"),
                          (resource_block("DeployRole", PIPELINE_LINES), "SnapshotBeforeDeploy")):
            self.assertIn("Action: [lightsail:CreateRelationalDatabaseSnapshot, lightsail:TagResource]",
                          statement_block(role, sid))

    def test_deploy_role_is_scoped_to_the_core_stack(self):
        role = resource_block("DeployRole", PIPELINE_LINES)
        self.assertIn("Resource: !Sub 'arn:${AWS::Partition}:cloudformation:${AWS::Region}:${AWS::AccountId}:"
                      "stack/${CoreStackName}/*'", statement_block(role, "ReadCoreStackOutputs"))
        secrets = statement_block(role, "ReadDeploySecrets")
        self.assertIn(core_import("CredentialsSecretArn"), secrets)
        self.assertIn(core_import("OwnerSecretArn"), secrets)
        snapshot = statement_block(role, "SnapshotBeforeDeploy")
        self.assertIn("StringEquals: {'aws:RequestTag/trust-portal-stack': %s}" % core_import("SnapshotTagValue"),
                      snapshot)
        self.assertIn("ForAllValues:StringEquals: {'aws:TagKeys': [trust-portal-stack]}", snapshot)
        self.assertIn("Resource: " + core_import("ContainerServiceArn"), statement_block(role, "CreateDeployment"))

    def test_every_lightsail_grant_on_star_is_conditioned(self):
        for role, lines in (("SnapshotRole", LINES), ("DeployRole", PIPELINE_LINES)):
            block = resource_block(role, lines)
            for sid in re.findall(r"Sid: (\w+)", block):
                statement = statement_block(block, sid)
                if "lightsail:" in statement and "Resource: '*'" in statement:
                    self.assertIn("Condition", statement, "%s.%s" % (role, sid))

    def test_deploy_role_cannot_list_container_services(self):
        self.assertNotIn("lightsail:GetContainerServices'", resource_block("DeployRole", PIPELINE_LINES))


class AssumableRoleTests(unittest.TestCase):
    def test_runtime_role_assumes_only_the_listed_roles_and_only_when_listed(self):
        runtime = resource_block("RuntimeRole")
        self.assertIn("- HasAssumableRoles\n                - {Sid: AssumeCollectorRoles, Effect: Allow, "
                      "Action: 'sts:AssumeRole', Resource: !Ref CollectorAssumableRoleArns}", runtime)
        self.assertEqual(runtime.count("sts:AssumeRole"), 2)  # the trust policy and this statement
        self.assertIn("HasAssumableRoles: !Not [!Equals [!Join ['', !Ref CollectorAssumableRoleArns], '']]", TEMPLATE)


class BootstrapAdminScriptTests(unittest.TestCase):
    """Static guarantees of bootstrap-admin.sh (POST /api/setup, contract v6)."""

    def setUp(self):
        self.text = (AWS_DIR / "bootstrap-admin.sh").read_text()
        self.lines = [line for line in self.text.split("\n") if not line.lstrip().startswith("#")]

    def test_token_travels_only_as_bearer_header_on_curl_stdin(self):
        curl_lines = [line for line in self.lines if "curl " in line]
        self.assertEqual(len(curl_lines), 1)
        self.assertIn("printf 'header = \"Authorization: Bearer %s\"\\n' \"$TOKEN\" | curl --config -", curl_lines[0])
        for line in self.lines:
            if "$TOKEN" in line and "printf" not in line and "[[" not in line and "[ -n" not in line:
                self.fail("token used outside the stdin header: " + line.strip())

    def test_body_carries_only_name_and_email(self):
        self.assertIn("'{name: $name, email: $email}'", self.text)
        self.assertNotRegex(self.text, r"\{[^}]*token:")

    def test_secret_never_written_to_disk(self):
        secret_line = next(line for line in self.lines if "get-secret-value" in line)
        continuation = self.lines[self.lines.index(secret_line) + 1]
        self.assertIn("| jq -r '.BOOTSTRAP_TOKEN // empty')", continuation)

    def test_every_documented_status_is_handled(self):
        for status in ("201", "400", "401", "404", "429", "000"):
            self.assertRegex(self.text, r"\n    %s\)\n" % status, status)

    def test_api_key_is_written_to_files_only(self):
        for line in self.lines:
            if "API_KEY" in line and ("echo" in line or "printf" in line):
                self.assertRegex(line, r'> "\$KEY_FILE(\.header)?"$', line.strip())

    def test_refuses_to_overwrite_or_write_inside_a_repository(self):
        self.assertIn('[ -e "$KEY_FILE" ]', self.text)
        self.assertIn("rev-parse --is-inside-work-tree", self.text)


if __name__ == "__main__":
    unittest.main()
