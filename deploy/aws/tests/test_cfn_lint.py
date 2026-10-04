"""cfn-lint guard for the two templates in deploy/aws/ and the iam/ policies.

cfn-lint is pinned in requirements-dev.txt; its bundled Service Authorization
data (cfnlint/data/AdditionalSpecs/Policies.json) is the pinned list of valid
IAM actions. The build stage runs the same version and fails on any warning.
"""
import json
import re
import tempfile
import unittest
from pathlib import Path

import cfnlint
from cfnlint.api import lint_file
from cfnlint.version import __version__ as installed_version

AWS_DIR = Path(__file__).resolve().parent.parent
REPO = AWS_DIR.parent.parent
TEMPLATE_PATH = AWS_DIR / "trust-portal.yaml"
PIPELINE_PATH = AWS_DIR / "trust-portal-pipeline.yaml"
TEMPLATE = TEMPLATE_PATH.read_text()
TEMPLATES = TEMPLATE + PIPELINE_PATH.read_text()
ACTION_DATA = json.loads((Path(cfnlint.__file__).parent / "data" / "AdditionalSpecs" / "Policies.json").read_text())
KNOWN_ACTIONS = {service.lower(): {action.lower() for action in spec.get("Actions", {})}
                 for service, spec in ACTION_DATA.items()}


def findings(path):
    return [match for match in lint_file(Path(path)) if match.rule.id[:1] in ("E", "W")]


# The value of an Action or NotAction key: a flow list, a quoted string, or a
# bare word (block YAML, flow mappings, and the JSON collector lines). Condition
# keys such as s3:ObjectCreationOperation never sit there.
ACTION_VALUE = re.compile(r"""(?:"(?:Not)?Action"|\b(?:Not)?Action):\s*(\[[^\]]*\]|'[^']*'|"[^"]*"|[^\s,}]+)""")


def template_actions(text=None):
    actions = set()
    for value in ACTION_VALUE.findall(TEMPLATES if text is None else text):
        actions |= set(re.findall(r"[a-z0-9-]+:[A-Za-z0-9*]+", value))
    return actions


def policy_file_actions():
    actions = set()
    for path in sorted((REPO / "iam").glob("*.json")):
        for statement in json.loads(path.read_text())["Statement"]:
            value = statement["Action"]
            actions.update([value] if isinstance(value, str) else value)
    return actions


class CfnLintTests(unittest.TestCase):
    def test_core_template_has_no_warnings_or_errors(self):
        self.assertEqual([str(match) for match in findings(TEMPLATE_PATH)], [])

    def test_pipeline_template_has_no_warnings_or_errors(self):
        self.assertEqual([str(match) for match in findings(PIPELINE_PATH)], [])

    def test_an_invalid_action_fails_the_lint(self):
        broken = TEMPLATE.replace("s3:GetEncryptionConfiguration", "s3:GetBucketEncryption", 1)
        self.assertNotEqual(broken, TEMPLATE)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "broken.yaml"
            path.write_text(broken)
            rule_ids = {match.rule.id for match in findings(path)}
        self.assertIn("W3037", rule_ids)

    def test_build_stage_runs_the_pinned_version_and_fails_on_warnings(self):
        pinned = re.search(r"^cfn-lint==(\S+)$", (REPO / "requirements-dev.txt").read_text(), re.MULTILINE)
        self.assertIsNotNone(pinned)
        buildspec = (AWS_DIR / "buildspec-build.yml").read_text()
        self.assertIn('"cfn-lint==%s"' % pinned.group(1), buildspec)
        self.assertIn("cfn-lint --non-zero-exit-code warning deploy/aws/trust-portal.yaml "
                      "deploy/aws/trust-portal-pipeline.yaml", buildspec)
        self.assertEqual(installed_version, pinned.group(1))


class ActionReferenceTests(unittest.TestCase):
    def assert_known(self, actions):
        self.assertTrue(actions)
        for action in sorted(actions):
            service, _, name = action.partition(":")
            self.assertIn(service.lower(), KNOWN_ACTIONS, action)
            if "*" not in name:
                self.assertIn(name.lower(), KNOWN_ACTIONS[service.lower()], action)

    def test_every_iam_policy_file_action_exists(self):
        self.assert_known(policy_file_actions())

    def test_every_template_action_exists(self):
        self.assert_known(template_actions())

    def test_condition_keys_are_not_read_as_actions(self):
        sample = "\n".join([
            "            Action: s3:PutObject",
            "            Condition:",
            "              'Null': {'s3:if-none-match': 'true'}",
            "              Bool: {'s3:ObjectCreationOperation': 'true'}",
            "                Condition: {StringEquals: {'aws:SourceAccount': !Ref 'AWS::AccountId'}}",
            "              - {Sid: A, Effect: Allow, Action: 'sts:AssumeRole', Resource: '*'}",
            '              - {"Sid": "B", "Action": ["iam:ListUsers", "iam:ListMFADevices"], "Resource": "*"}',
            "                NotAction: ['kms:Decrypt']",
            "              ActionTypeId: {Category: Build, Owner: AWS}",
        ])
        self.assertEqual(template_actions(sample),
                         {"s3:PutObject", "sts:AssumeRole", "iam:ListUsers", "iam:ListMFADevices", "kms:Decrypt"})

    def test_the_reference_rejects_api_names(self):
        self.assertNotIn("getbucketencryption", KNOWN_ACTIONS["s3"])
        self.assertIn("getencryptionconfiguration", KNOWN_ACTIONS["s3"])


if __name__ == "__main__":
    unittest.main()
