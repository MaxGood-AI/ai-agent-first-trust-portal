"""Custom resource that fills the portal's secrets (see deploy/README.md).

The secrets and what to do with them come only from SECRET_SPECS (set by the
template), never from the event; a request for any stack but STACK_ID is
ignored. Adds each missing Generate key, sets Fixed keys, deletes Remove keys,
and never changes a key that holds a value. A key absent or blank after
creation is regenerated only if listed in Regenerable; otherwise, or when a
secret is not a JSON object, the resource fails and nothing is written.
"""
import base64
import json
import os
import secrets

import cfnresponse

GENERATORS = {
    "password": lambda: secrets.token_urlsafe(24),
    "token": lambda: secrets.token_urlsafe(32),
    "session-key": lambda: secrets.token_urlsafe(48),
    "fernet": lambda: base64.urlsafe_b64encode(os.urandom(32)).decode(),
}


class SecretSpecError(Exception):
    pass


def complete(client, secret_id, generate, fixed, remove, regenerable=(), creating=False):
    raw = client.get_secret_value(SecretId=secret_id)["SecretString"]
    try:
        current = json.loads(raw)
    except ValueError:
        current = None
    if not isinstance(current, dict):
        raise SecretSpecError("secret %s does not hold a JSON object; restore its JSON value "
                              "(no key is regenerated), then update the stack again" % secret_id)
    needed = sorted(k for k in generate if not current.get(k))
    blocked = [k for k in needed if k not in regenerable and (k in current or not creating)]
    if blocked:
        raise SecretSpecError("secret %s: %s absent or blank and not regenerable; restore the "
                              "value(s), then update the stack again" % (secret_id, ", ".join(blocked)))
    for key in needed:
        current[key] = GENERATORS[generate[key]]()
    removed = sorted(k for k in remove if k in current)
    for key in removed:
        del current[key]
    changed = bool(needed or removed)
    for key, value in fixed.items():
        if current.get(key) != value:
            current[key] = value
            changed = True
    if changed:
        client.put_secret_value(SecretId=secret_id, SecretString=json.dumps(current))
    return needed, removed


def handler(event, context):
    if event.get("StackId") != os.environ.get("STACK_ID"):
        print(json.dumps({"event": "secret_init_ignored", "reason": "request is not from this stack"}))
        return
    specs = json.loads(os.environ["SECRET_SPECS"])
    status, reason = cfnresponse.SUCCESS, None
    try:
        if event["RequestType"] in ("Create", "Update"):
            import boto3
            client = boto3.client("secretsmanager")
            for spec in specs:
                added, removed = complete(client, spec["SecretId"], spec.get("Generate", {}),
                                          spec.get("Fixed", {}), spec.get("Remove", []),
                                          spec.get("Regenerable", []), event["RequestType"] == "Create")
                print(json.dumps({"event": "secret_completed", "secret": spec["SecretId"],
                                  "keys_added": added, "keys_removed": removed}))
    except SecretSpecError as exc:
        status, reason = cfnresponse.FAILED, str(exc)
    except Exception as exc:
        status, reason = cfnresponse.FAILED, "secret init failed: %s" % type(exc).__name__
    if status == cfnresponse.FAILED:
        print(json.dumps({"event": "secret_init_failed", "reason": reason}))
    physical_id = specs[0]["SecretId"] if specs else event.get("PhysicalResourceId", "portal-secrets")
    cfnresponse.send(event, context, status, {}, physical_id, reason=reason)
