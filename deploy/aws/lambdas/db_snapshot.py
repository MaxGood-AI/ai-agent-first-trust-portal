"""Daily snapshot <SNAPSHOT_PREFIX><YYYYMMDD-HHMMSS> (UTC) of DATABASE_NAME,
tagged SNAPSHOT_TAG_KEY=SNAPSHOT_TAG_VALUE. Then deletes that database's tagged,
"available" snapshots of that name shape older than RETENTION_DAYS, keeping the
newest MIN_SNAPSHOTS; nothing else is touched. {"dry_run": true} changes nothing.
"""
import datetime
import json
import os
import re

STAMP = "%Y%m%d-%H%M%S"


def log(event, **fields):
    print(json.dumps(dict(fields, event=event), default=str, sort_keys=True))


def load_config(env):
    database = env.get("DATABASE_NAME", "").strip()
    prefix = env.get("SNAPSHOT_PREFIX", "").strip()
    retention = int(env.get("RETENTION_DAYS", "35"))
    minimum = int(env.get("MIN_SNAPSHOTS", "7"))
    tag = (env.get("SNAPSHOT_TAG_KEY", "").strip(), env.get("SNAPSHOT_TAG_VALUE", "").strip())
    if not database:
        raise ValueError("DATABASE_NAME is required")
    if not all(tag):
        raise ValueError("SNAPSHOT_TAG_KEY and SNAPSHOT_TAG_VALUE are required")
    if not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,200}-", prefix):
        raise ValueError("SNAPSHOT_PREFIX must be lowercase letters, digits "
                         "and hyphens, ending in a hyphen")
    if retention < 1:
        raise ValueError("RETENTION_DAYS must be at least 1")
    if minimum < 1:
        raise ValueError("MIN_SNAPSHOTS must be at least 1")
    return database, prefix, retention, minimum, tag


def list_snapshots(client):
    token = None
    while True:
        kwargs = {"pageToken": token} if token else {}
        page = client.get_relational_database_snapshots(**kwargs)
        yield from page.get("relationalDatabaseSnapshots", [])
        token = page.get("nextPageToken")
        if not token:
            return


def tagged(snapshot, tag):
    return any(t.get("key") == tag[0] and t.get("value") == tag[1] for t in snapshot.get("tags") or [])


def expired(snapshots, database, prefix, cutoff, minimum, tag):
    pattern = re.compile(re.escape(prefix) + r"\d{8}-\d{6}")
    ours = [s for s in snapshots
            if s.get("fromRelationalDatabaseName") == database
            and pattern.fullmatch(s.get("name", ""))
            and tagged(s, tag)
            and s.get("state") == "available"
            and s.get("createdAt") is not None]
    ours.sort(key=lambda s: s["createdAt"], reverse=True)
    return sorted(s["name"] for s in ours[minimum:] if s["createdAt"] < cutoff)


def run(client, env, now, dry_run=False):
    database, prefix, retention, minimum, tag = load_config(env)
    name = prefix + now.strftime(STAMP)
    cutoff = now - datetime.timedelta(days=retention)
    result = {"database": database, "snapshot": name, "dry_run": dry_run,
              "retention_days": retention, "min_snapshots": minimum,
              "deleted": [], "failed": []}
    if not dry_run:
        try:
            client.create_relational_database_snapshot(
                relationalDatabaseName=database,
                relationalDatabaseSnapshotName=name,
                tags=[{"key": tag[0], "value": tag[1]}])
        except Exception as exc:
            log("snapshot_create_failed", database=database, snapshot=name,
                error=type(exc).__name__, detail=str(exc)[:300])
            raise
        log("snapshot_created", database=database, snapshot=name)
    for old in expired(list_snapshots(client), database, prefix, cutoff, minimum, tag):
        if dry_run:
            result["deleted"].append(old)
            continue
        try:
            client.delete_relational_database_snapshot(
                relationalDatabaseSnapshotName=old)
        except Exception as exc:
            result["failed"].append(old)
            log("snapshot_delete_failed", database=database, snapshot=old,
                error=type(exc).__name__, detail=str(exc)[:300])
            continue
        result["deleted"].append(old)
        log("snapshot_deleted", database=database, snapshot=old)
    log("snapshot_run_complete", **result)
    if result["failed"]:
        raise RuntimeError("failed to delete %d snapshot(s)" % len(result["failed"]))
    return result


def lambda_handler(event, context):
    import boto3
    dry_run = str((event or {}).get("dry_run", "")).lower() in ("true", "1")
    now = datetime.datetime.now(datetime.timezone.utc)
    return run(boto3.client("lightsail"), os.environ, now, dry_run)
