#!/bin/sh
# Container entrypoint: load configuration, wait for the database, migrate,
# provision the application role (when owner credentials are present in this
# process's environment), then drop the owner credentials and exec the
# command (gunicorn by default). The serving process never sees
# DATABASE_OWNER_*; it refuses to start in production when its own database
# role could alter the audit trail. Any failure exits non-zero, so a broken
# release never reports healthy.
set -e

python -m cli db-wait --timeout 120
python -m cli db-migrate

unset DATABASE_OWNER_URL DATABASE_OWNER_USER DATABASE_OWNER_PASSWORD

exec "$@"
