"""Portal font settings on PostgreSQL: migration 022 and the audit trigger."""

import ast
from pathlib import Path

from alembic import command
from sqlalchemy import create_engine, inspect, text

from app.models import db
from app.services import team_service
from cli import db_cmd
from tests.test_migrations_pg import _alembic_config

HEADING = 'Georgia, "Times New Roman", serif'
TEXT = "Geneva, Verdana, sans-serif"


def test_migration_022_adds_nullable_columns_and_keeps_the_row(pg_url):
    cfg = _alembic_config(pg_url)
    command.upgrade(cfg, "021")
    engine = create_engine(pg_url)
    with engine.begin() as conn:
        conn.execute(text("INSERT INTO portal_settings (id, company_brand_name) VALUES (1, 'Kept')"))
    command.upgrade(cfg, "head")
    with engine.connect() as conn:
        columns = {c["name"]: c for c in inspect(conn).get_columns("portal_settings")}
        for name in ("heading_font", "text_font"):
            assert columns[name]["nullable"] is True
        row = conn.execute(text(
            "SELECT company_brand_name, heading_font, text_font FROM portal_settings")).one()
        assert tuple(row) == ("Kept", None, None)
        assert conn.execute(text("SELECT version_num FROM alembic_version")).scalar() == "022"
    engine.dispose()


def test_migration_022_names_its_locks():
    tree = ast.parse((Path(db_cmd.ROOT) / "migrations" / "env.py").read_text())
    assigned = {node.targets[0].id: node.value for node in tree.body
                if isinstance(node, ast.Assign) and isinstance(node.targets[0], ast.Name)}
    locks = assigned["REVISION_LOCKS"]
    by_revision = {ast.literal_eval(k): v for k, v in zip(locks.keys, locks.values)}
    assert ast.literal_eval(by_revision["022"]) == (("portal_settings",), False)


def test_font_settings_changes_are_audited(pg_app):
    admin = team_service.create_member("Admin", "admin@example.com", "human", is_compliance_admin=True)
    admin_id = admin.id
    client = pg_app.test_client()
    resp = client.put("/api/settings", headers={"X-API-Key": admin.issued_api_key},
                      json={"heading_font": HEADING, "text_font": TEXT})
    assert resp.status_code == 200
    db.session.remove()
    row = db.session.execute(text(
        "SELECT action, new_values, changed_by FROM audit_log "
        "WHERE table_name = 'portal_settings' ORDER BY id DESC LIMIT 1")).one()
    assert row.new_values["heading_font"] == HEADING
    assert row.new_values["text_font"] == TEXT
    assert row.changed_by == admin_id
