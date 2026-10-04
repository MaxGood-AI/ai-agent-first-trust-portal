"""Unit tests for the secrets custom resource (deploy/aws/lambdas/secret_init.py).

cfnresponse and Secrets Manager are fakes; no AWS call is made.
"""
import base64
import io
import json
import os
import sys
import types
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas"))

FAKE_CFNRESPONSE = types.ModuleType("cfnresponse")
FAKE_CFNRESPONSE.SUCCESS = "SUCCESS"
FAKE_CFNRESPONSE.FAILED = "FAILED"
FAKE_CFNRESPONSE.send = mock.MagicMock()
sys.modules.setdefault("cfnresponse", FAKE_CFNRESPONSE)

import secret_init  # noqa: E402

RUNTIME = "arn:aws:secretsmanager:us-east-1:111122223333:secret:acme-trust-portal-prod-AbCdEf"
OWNER = "arn:aws:secretsmanager:us-east-1:111122223333:secret:acme-trust-portal-db-owner-prod-GhIjKl"
RUNTIME_GENERATE = {"SECRET_KEY": "session-key", "DATABASE_PASSWORD": "password",
                    "BOOTSTRAP_TOKEN": "token", "COLLECTOR_ENCRYPTION_KEYS": "fernet"}
OWNER_KEYS = ["DATABASE_OWNER_PASSWORD", "DATABASE_OWNER_URL", "DATABASE_OWNER_USER"]
SPECS = [
    {"SecretId": RUNTIME, "Generate": RUNTIME_GENERATE,
     "Regenerable": ["SECRET_KEY", "DATABASE_PASSWORD", "BOOTSTRAP_TOKEN"],
     "Fixed": {"CLOUDWATCH_LOG_GROUP": "/lightsail/acme-trust-portal-prod"}, "Remove": OWNER_KEYS},
    {"SecretId": OWNER, "Generate": {"DATABASE_OWNER_PASSWORD": "password"},
     "Fixed": {"DATABASE_OWNER_USER": "dbmasteruser"}},
]


class FakeSecrets:
    def __init__(self, values):
        self.values = dict(values)
        self.puts = []

    def get_secret_value(self, SecretId):
        return {"SecretString": self.values[SecretId]}

    def put_secret_value(self, SecretId, SecretString):
        self.puts.append(SecretId)
        self.values[SecretId] = SecretString

    def stored(self, secret_id):
        return json.loads(self.values[secret_id])


def complete(client, spec, creating=False):
    return secret_init.complete(client, spec["SecretId"], spec.get("Generate", {}), spec.get("Fixed", {}),
                                spec.get("Remove", []), spec.get("Regenerable", []), creating)


class CompleteTests(unittest.TestCase):
    def test_new_secret_gets_every_generated_and_fixed_key(self):
        client = FakeSecrets({RUNTIME: "{}"})
        added, removed = complete(client, SPECS[0], creating=True)
        stored = client.stored(RUNTIME)
        self.assertEqual(added, sorted(RUNTIME_GENERATE))
        self.assertEqual(removed, [])
        self.assertEqual(stored["CLOUDWATCH_LOG_GROUP"], "/lightsail/acme-trust-portal-prod")
        self.assertGreaterEqual(len(stored["SECRET_KEY"]), 64)
        # The portal refuses to start in production with a bootstrap token under 32 characters.
        self.assertGreaterEqual(len(stored["BOOTSTRAP_TOKEN"]), 32)

    def test_existing_keys_are_never_regenerated(self):
        existing = {key: "kept-" + key for key in RUNTIME_GENERATE}
        existing["GITHUB_TOKEN"] = "operator-set"
        client = FakeSecrets({RUNTIME: json.dumps(existing)})
        added, _ = complete(client, SPECS[0])
        stored = client.stored(RUNTIME)
        self.assertEqual(added, [])
        for key in RUNTIME_GENERATE:
            self.assertEqual(stored[key], "kept-" + key)
        self.assertEqual(stored["GITHUB_TOKEN"], "operator-set")

    def test_runtime_secret_loses_owner_credentials(self):
        client = FakeSecrets({RUNTIME: json.dumps({"DATABASE_OWNER_USER": "dbmasteruser",
                                                   "DATABASE_OWNER_PASSWORD": "leaked"})})
        _, removed = complete(client, SPECS[0], creating=True)
        stored = client.stored(RUNTIME)
        self.assertEqual(removed, ["DATABASE_OWNER_PASSWORD", "DATABASE_OWNER_USER"])
        for key in OWNER_KEYS:
            self.assertNotIn(key, stored)

    def test_owner_secret_holds_user_and_a_lightsail_safe_password(self):
        client = FakeSecrets({OWNER: "{}"})
        complete(client, SPECS[1], creating=True)
        stored = client.stored(OWNER)
        self.assertEqual(stored["DATABASE_OWNER_USER"], "dbmasteruser")
        password = stored["DATABASE_OWNER_PASSWORD"]
        self.assertTrue(8 <= len(password) <= 63)
        for char in '/"@ ':
            self.assertNotIn(char, password)

    def test_collector_key_is_a_valid_fernet_key(self):
        client = FakeSecrets({RUNTIME: "{}"})
        complete(client, SPECS[0], creating=True)
        key = client.stored(RUNTIME)["COLLECTOR_ENCRYPTION_KEYS"]
        self.assertEqual(len(base64.urlsafe_b64decode(key)), 32)

    def test_complete_secret_is_not_rewritten(self):
        full = {"DATABASE_OWNER_USER": "dbmasteruser", "DATABASE_OWNER_PASSWORD": "x" * 32}
        client = FakeSecrets({OWNER: json.dumps(full)})
        self.assertEqual(complete(client, SPECS[1]), ([], []))
        self.assertEqual(client.puts, [])

    def test_non_json_secret_is_refused_and_left_untouched(self):
        for value in ("not json", "[1, 2]", '"a string"'):
            client = FakeSecrets({RUNTIME: value})
            with self.assertRaisesRegex(secret_init.SecretSpecError, "does not hold a JSON object"):
                complete(client, SPECS[0])
            self.assertEqual(client.puts, [])
            self.assertEqual(client.values[RUNTIME], value)


class BlankKeyTests(unittest.TestCase):
    def full_runtime(self, **overrides):
        values = {key: "kept-" + key for key in RUNTIME_GENERATE}
        values.update(overrides)
        return json.dumps(values)

    def test_blank_regenerable_key_is_regenerated(self):
        client = FakeSecrets({RUNTIME: self.full_runtime(BOOTSTRAP_TOKEN="")})
        added, _ = complete(client, SPECS[0])
        stored = client.stored(RUNTIME)
        self.assertEqual(added, ["BOOTSTRAP_TOKEN"])
        self.assertGreaterEqual(len(stored["BOOTSTRAP_TOKEN"]), 32)
        self.assertEqual(stored["DATABASE_PASSWORD"], "kept-DATABASE_PASSWORD")

    def test_blank_owner_password_fails_and_changes_nothing(self):
        value = json.dumps({"DATABASE_OWNER_USER": "dbmasteruser", "DATABASE_OWNER_PASSWORD": ""})
        client = FakeSecrets({OWNER: value})
        with self.assertRaisesRegex(secret_init.SecretSpecError, "DATABASE_OWNER_PASSWORD absent or blank"):
            complete(client, SPECS[1])
        self.assertEqual(client.puts, [])
        self.assertEqual(client.values[OWNER], value)

    def test_blank_collector_key_fails_even_at_creation(self):
        client = FakeSecrets({RUNTIME: self.full_runtime(COLLECTOR_ENCRYPTION_KEYS="")})
        with self.assertRaisesRegex(secret_init.SecretSpecError, "COLLECTOR_ENCRYPTION_KEYS"):
            complete(client, SPECS[0], creating=True)
        self.assertEqual(client.puts, [])

    def test_deleted_non_regenerable_key_fails_after_creation(self):
        values = {key: "kept-" + key for key in RUNTIME_GENERATE if key != "COLLECTOR_ENCRYPTION_KEYS"}
        client = FakeSecrets({RUNTIME: json.dumps(values)})
        with self.assertRaisesRegex(secret_init.SecretSpecError, "COLLECTOR_ENCRYPTION_KEYS"):
            complete(client, SPECS[0])
        self.assertEqual(client.puts, [])


STACK = "arn:aws:cloudformation:us-east-1:111122223333:stack/acme-trust-portal-prod/0f0e0d0c-1111-2222-3333-444455556666"


class HandlerTests(unittest.TestCase):
    def setUp(self):
        FAKE_CFNRESPONSE.send.reset_mock()

    def invoke(self, request_type, client, stack=STACK, properties=None):
        fake_boto3 = mock.MagicMock()
        fake_boto3.client.return_value = client
        event = {"RequestType": request_type, "StackId": stack, "ResourceProperties": properties or {}}
        buffer = io.StringIO()
        environment = {"SECRET_SPECS": json.dumps(SPECS), "STACK_ID": STACK}
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}), \
                mock.patch.dict(os.environ, environment), redirect_stdout(buffer):
            secret_init.handler(event, None)
        return fake_boto3, buffer.getvalue()

    def test_event_properties_never_choose_the_secrets(self):
        attacker = "arn:aws:secretsmanager:us-east-1:111122223333:secret:someone-else-XyZ"
        client = FakeSecrets({RUNTIME: "{}", OWNER: "{}", attacker: "{}"})
        self.invoke("Create", client, properties={"Secrets": [
            {"SecretId": attacker, "Generate": {"STOLEN": "token"}, "Remove": ["EVERYTHING"]}]})
        self.assertEqual(client.values[attacker], "{}")
        self.assertIn("SECRET_KEY", client.stored(RUNTIME))

    def test_request_from_another_stack_touches_nothing_and_sends_nothing(self):
        client = FakeSecrets({RUNTIME: "{}", OWNER: "{}"})
        fake_boto3, output = self.invoke("Create", client, stack=STACK.replace("prod", "other"))
        fake_boto3.client.assert_not_called()
        FAKE_CFNRESPONSE.send.assert_not_called()
        self.assertIn("secret_init_ignored", output)
        self.assertEqual(client.puts, [])

    def test_create_fills_both_secrets_without_returning_values(self):
        client = FakeSecrets({RUNTIME: "{}", OWNER: "{}"})
        _, output = self.invoke("Create", client)
        args, kwargs = FAKE_CFNRESPONSE.send.call_args
        self.assertEqual(args[2:5], ("SUCCESS", {}, RUNTIME))
        for secret_id in (RUNTIME, OWNER):
            for key, value in client.stored(secret_id).items():
                if key.endswith(("PASSWORD", "TOKEN", "KEY", "KEYS")):
                    self.assertNotIn(value, output)

    def test_delete_touches_nothing(self):
        fake_boto3, _ = self.invoke("Delete", FakeSecrets({}))
        fake_boto3.client.assert_not_called()
        self.assertEqual(FAKE_CFNRESPONSE.send.call_args[0][2], "SUCCESS")

    def test_non_json_secret_fails_the_resource_with_a_clear_reason(self):
        client = FakeSecrets({RUNTIME: "not json", OWNER: "{}"})
        self.invoke("Update", client)
        args, kwargs = FAKE_CFNRESPONSE.send.call_args
        self.assertEqual(args[2], "FAILED")
        self.assertIn("does not hold a JSON object", kwargs["reason"])
        self.assertEqual(client.values[RUNTIME], "not json")

    def test_blank_owner_password_fails_the_update_by_name(self):
        full_runtime = json.dumps({key: "kept-" + key for key in RUNTIME_GENERATE})
        owner = json.dumps({"DATABASE_OWNER_USER": "dbmasteruser", "DATABASE_OWNER_PASSWORD": ""})
        client = FakeSecrets({RUNTIME: full_runtime, OWNER: owner})
        self.invoke("Update", client)
        args, kwargs = FAKE_CFNRESPONSE.send.call_args
        self.assertEqual(args[2], "FAILED")
        self.assertIn("DATABASE_OWNER_PASSWORD", kwargs["reason"])
        self.assertEqual(client.values[OWNER], owner)

    def test_other_failures_report_the_error_type_only(self):
        client = mock.MagicMock()
        client.get_secret_value.side_effect = PermissionError("AccessDenied for value=hunter2")
        _, output = self.invoke("Update", client)
        args, kwargs = FAKE_CFNRESPONSE.send.call_args
        self.assertEqual(args[2], "FAILED")
        self.assertNotIn("hunter2", kwargs["reason"])
        self.assertNotIn("hunter2", output)


if __name__ == "__main__":
    unittest.main()
