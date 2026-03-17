#!/bin/bash
set -e

echo "Waiting for PostgreSQL..."
until python3 -c "
import os, psycopg2
conn = psycopg2.connect(os.environ.get(
    'DATABASE_URL',
    'postgresql://mgcompliance:password@db:5432/mgcompliance'
))
conn.close()
" 2>/dev/null; do
    sleep 1
done
echo "PostgreSQL is ready."

echo "Running database migrations..."
alembic upgrade head
echo "Migrations complete."

exec "$@"
