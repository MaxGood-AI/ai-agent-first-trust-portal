"""Unit tests for the database snapshot Lambda (deploy/aws/lambdas/db_snapshot.py).

The Lightsail client is a fake; no AWS call is made.
"""
import datetime
import io
import json
import os
import sys
import unittest
from contextlib import redirect_stdout
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "lambdas"))

import db_snapshot  # noqa: E402

UTC = datetime.timezone.utc
NOW = datetime.datetime(2026, 9, 28, 6, 15, 0, tzinfo=UTC)
DB = "acme-trust-portal-db-prod"
PREFIX = "acme-trust-portal-db-prod-"
TAG_KEY, TAG_VALUE = "trust-portal-stack", "0f0e0d0c-1111-2222-3333-444455556666"
TAG_ENV = {"SNAPSHOT_TAG_KEY": TAG_KEY, "SNAPSHOT_TAG_VALUE": TAG_VALUE}
# MIN_SNAPSHOTS 1 keeps the pruning cases small; MinimumKeptTests covers the default.
ENV = dict(TAG_ENV, DATABASE_NAME=DB, SNAPSHOT_PREFIX=PREFIX, RETENTION_DAYS="35", MIN_SNAPSHOTS="1")


def snap(name, days_old, database=DB, state="available", tags=((TAG_KEY, TAG_VALUE),)):
    return {"name": name, "fromRelationalDatabaseName": database, "state": state,
            "createdAt": NOW - datetime.timedelta(days=days_old),
            "tags": [{"key": key, "value": value} for key, value in tags]}


RECENT = snap(PREFIX + "20260927-061500", 1)


class FakeLightsail:
    def __init__(self, pages, fail_create=False, fail_delete=()):
        self.pages = pages
        self.fail_create = fail_create
        self.fail_delete = set(fail_delete)
        self.created = []
        self.deleted = []
        self.page_tokens = []

    def create_relational_database_snapshot(self, relationalDatabaseName, relationalDatabaseSnapshotName, tags=None):
        if self.fail_create:
            raise RuntimeError("OperationFailureException")
        self.created.append((relationalDatabaseName, relationalDatabaseSnapshotName))
        self.created_tags = tags
        return {"operations": [{"id": "op-1"}]}

    def get_relational_database_snapshots(self, pageToken=None):
        self.page_tokens.append(pageToken)
        index = int(pageToken) if pageToken else 0
        page = {"relationalDatabaseSnapshots": self.pages[index]}
        if index + 1 < len(self.pages):
            page["nextPageToken"] = str(index + 1)
        return page

    def delete_relational_database_snapshot(self, relationalDatabaseSnapshotName):
        if relationalDatabaseSnapshotName in self.fail_delete:
            raise RuntimeError("NotFoundException")
        self.deleted.append(relationalDatabaseSnapshotName)


def run_quietly(client, env=ENV, dry_run=False):
    buffer = io.StringIO()
    with redirect_stdout(buffer):
        result = db_snapshot.run(client, env, NOW, dry_run)
    return result, [json.loads(line) for line in buffer.getvalue().splitlines()]


class ConfigTests(unittest.TestCase):
    def test_defaults_retention_to_35_days(self):
        env = dict(TAG_ENV, DATABASE_NAME=DB, SNAPSHOT_PREFIX=PREFIX)
        self.assertEqual(db_snapshot.load_config(env), (DB, PREFIX, 35, 7, (TAG_KEY, TAG_VALUE)))

    def test_requires_the_stack_tag(self):
        for missing in ("SNAPSHOT_TAG_KEY", "SNAPSHOT_TAG_VALUE"):
            env = dict(ENV)
            del env[missing]
            with self.assertRaises(ValueError):
                db_snapshot.load_config(env)

    def test_rejects_zero_minimum(self):
        with self.assertRaises(ValueError):
            db_snapshot.load_config(dict(ENV, MIN_SNAPSHOTS="0"))

    def test_requires_database_name(self):
        with self.assertRaises(ValueError):
            db_snapshot.load_config(dict(TAG_ENV, SNAPSHOT_PREFIX=PREFIX))

    def test_rejects_prefix_that_does_not_end_in_hyphen(self):
        with self.assertRaises(ValueError):
            db_snapshot.load_config(dict(TAG_ENV, DATABASE_NAME=DB, SNAPSHOT_PREFIX="acme-snap"))

    def test_rejects_prefix_too_short_to_be_specific(self):
        with self.assertRaises(ValueError):
            db_snapshot.load_config(dict(TAG_ENV, DATABASE_NAME=DB, SNAPSHOT_PREFIX="a-"))

    def test_rejects_zero_retention(self):
        with self.assertRaises(ValueError):
            db_snapshot.load_config(dict(ENV, RETENTION_DAYS="0"))


class RunTests(unittest.TestCase):
    def test_creates_snapshot_named_with_prefix_and_utc_timestamp(self):
        client = FakeLightsail([[]])
        result, _ = run_quietly(client)
        self.assertEqual(client.created, [(DB, PREFIX + "20260928-061500")])
        self.assertEqual(result["snapshot"], PREFIX + "20260928-061500")

    def test_new_snapshot_carries_the_stack_tag(self):
        client = FakeLightsail([[]])
        run_quietly(client)
        self.assertEqual(client.created_tags, [{"key": TAG_KEY, "value": TAG_VALUE}])

    def test_prunes_only_snapshots_carrying_this_stacks_tag(self):
        untagged = snap(PREFIX + "20260601-061500", 119, tags=())
        other_stack = snap(PREFIX + "20260602-061500", 118, tags=((TAG_KEY, "another-stack"),))
        ours = snap(PREFIX + "20260603-061500", 117)
        client = FakeLightsail([[untagged, other_stack, ours, RECENT]])
        run_quietly(client)
        self.assertEqual(client.deleted, [PREFIX + "20260603-061500"])

    def test_deletes_only_expired_snapshots_with_the_exact_name_shape(self):
        client = FakeLightsail([[
            snap(PREFIX + "20260801-061500", 58),
            snap(PREFIX + "20260823-061500", 36),
            snap(PREFIX + "20260824-061500", 35 - 0.01),
            snap(PREFIX + "20260920-061500", 8),
            snap(PREFIX + "before-cutover", 90),
            snap("manual-" + PREFIX + "20260101-000000", 90),
            snap(PREFIX + "20260101-000000", 90, database="other-db"),
        ]])
        result, _ = run_quietly(client)
        self.assertEqual(client.deleted, [PREFIX + "20260801-061500", PREFIX + "20260823-061500"])
        self.assertEqual(result["deleted"], client.deleted)
        self.assertEqual(result["failed"], [])

    def test_follows_every_page_of_snapshots(self):
        client = FakeLightsail([
            [snap(PREFIX + "20260701-061500", 89)],
            [snap(PREFIX + "20260702-061500", 88)],
            [snap(PREFIX + "20260703-061500", 87), RECENT],
        ])
        run_quietly(client)
        self.assertEqual(client.page_tokens, [None, "1", "2"])
        self.assertEqual(len(client.deleted), 3)

    def test_skips_snapshot_without_creation_time(self):
        entry = snap(PREFIX + "20260701-061500", 89)
        del entry["createdAt"]
        client = FakeLightsail([[entry, RECENT]])
        run_quietly(client)
        self.assertEqual(client.deleted, [])

    def test_failed_creation_prunes_nothing(self):
        client = FakeLightsail([[snap(PREFIX + "20260701-061500", 89)]], fail_create=True)
        with self.assertRaises(RuntimeError):
            run_quietly(client)
        self.assertEqual(client.deleted, [])
        self.assertEqual(client.page_tokens, [])

    def test_failed_deletion_continues_then_raises(self):
        first, second = PREFIX + "20260701-061500", PREFIX + "20260702-061500"
        client = FakeLightsail([[snap(first, 89), snap(second, 88), RECENT]], fail_delete=[first])
        buffer = io.StringIO()
        with redirect_stdout(buffer), self.assertRaises(RuntimeError):
            db_snapshot.run(client, ENV, NOW)
        self.assertEqual(client.deleted, [second])
        events = [json.loads(line)["event"] for line in buffer.getvalue().splitlines()]
        self.assertIn("snapshot_delete_failed", events)
        self.assertEqual(events[-1], "snapshot_run_complete")

    def test_dry_run_changes_nothing_and_reports_the_plan(self):
        old = PREFIX + "20260701-061500"
        client = FakeLightsail([[snap(old, 89), RECENT]])
        result, logs = run_quietly(client, dry_run=True)
        self.assertEqual(client.created, [])
        self.assertEqual(client.deleted, [])
        self.assertEqual(result["deleted"], [old])
        self.assertTrue(result["dry_run"])
        self.assertEqual(logs[-1]["event"], "snapshot_run_complete")

    def test_logs_one_json_object_per_line(self):
        client = FakeLightsail([[snap(PREFIX + "20260701-061500", 89), RECENT]])
        _, logs = run_quietly(client)
        self.assertEqual([entry["event"] for entry in logs],
                         ["snapshot_created", "snapshot_deleted", "snapshot_run_complete"])
        self.assertEqual(logs[-1]["database"], DB)


class MinimumKeptTests(unittest.TestCase):
    def test_default_minimum_keeps_seven_newest_whatever_their_age(self):
        old = [snap(PREFIX + "202601%02d-061500" % day, 200 - day) for day in range(1, 11)]
        env = dict(TAG_ENV, DATABASE_NAME=DB, SNAPSHOT_PREFIX=PREFIX)
        client = FakeLightsail([old])
        result, _ = run_quietly(client, env=env)
        self.assertEqual(result["min_snapshots"], 7)
        self.assertEqual(client.deleted, [PREFIX + "20260101-061500", PREFIX + "20260102-061500",
                                          PREFIX + "20260103-061500"])

    def test_never_prunes_below_the_minimum_even_when_all_are_expired(self):
        old = [snap(PREFIX + "2026010%d-061500" % day, 200 - day) for day in range(1, 4)]
        client = FakeLightsail([old])
        run_quietly(client, env=dict(ENV, MIN_SNAPSHOTS="3"))
        self.assertEqual(client.deleted, [])

    def test_prunes_only_available_snapshots(self):
        creating = snap(PREFIX + "20260601-061500", 119, state="creating")
        failed = snap(PREFIX + "20260602-061500", 118, state="error")
        available = snap(PREFIX + "20260603-061500", 117)
        client = FakeLightsail([[creating, failed, available, RECENT]])
        run_quietly(client)
        self.assertEqual(client.deleted, [PREFIX + "20260603-061500"])

    def test_snapshots_in_other_states_do_not_count_towards_the_minimum(self):
        pending = snap(PREFIX + "20260926-061500", 2, state="creating")
        old = snap(PREFIX + "20260601-061500", 119)
        client = FakeLightsail([[pending, old]])
        run_quietly(client)
        self.assertEqual(client.deleted, [])


class HandlerTests(unittest.TestCase):
    def test_handler_builds_lightsail_client_and_reads_environment(self):
        fake_boto3 = mock.MagicMock()
        fake_boto3.client.return_value = FakeLightsail([[]])
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}), \
                mock.patch.dict(os.environ, ENV, clear=True), \
                redirect_stdout(io.StringIO()):
            result = db_snapshot.lambda_handler({}, None)
        fake_boto3.client.assert_called_once_with("lightsail")
        self.assertFalse(result["dry_run"])
        self.assertTrue(result["snapshot"].startswith(PREFIX))
        json.dumps(result)

    def test_handler_accepts_string_dry_run(self):
        fake_boto3 = mock.MagicMock()
        client = FakeLightsail([[]])
        fake_boto3.client.return_value = client
        with mock.patch.dict(sys.modules, {"boto3": fake_boto3}), \
                mock.patch.dict(os.environ, ENV, clear=True), \
                redirect_stdout(io.StringIO()):
            result = db_snapshot.lambda_handler({"dry_run": "True"}, None)
        self.assertTrue(result["dry_run"])
        self.assertEqual(client.created, [])


if __name__ == "__main__":
    unittest.main()
