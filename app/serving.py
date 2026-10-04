"""Serving-role guard: the web process must not hold rights to alter the audit trail.

Before gunicorn serves requests, ``enforce_serving_role`` checks the database
role the app connects as, and every role it can use (``SET ROLE`` or
inherited membership), with ``cli.db_cmd.serving_role_problems``. In
production the portal refuses to start when any of them is a superuser or
has CREATEROLE, BYPASSRLS or REPLICATION; may run programs or write files as
the database server; owns the database or any portal object; may create
objects (TEMPORARY or CREATE on the database, CREATE on a schema) or
triggers; may write ``audit_log`` or ``audit_witness_arming`` (including
MAINTAIN); or may set ``session_replication_role`` - i.e. single-role mode
or a misconfigured application role. Development and test log a warning
instead.
"""

import logging

from app.runtime_config import ConfigurationError, is_production

logger = logging.getLogger(__name__)


def enforce_serving_role(flask_app) -> list[str]:
    from cli.db_cmd import serving_role_problems

    problems = serving_role_problems(flask_app.config["SQLALCHEMY_DATABASE_URI"])
    if problems:
        message = ("The database role this process connects as can alter the audit trail: "
                   + "; ".join(problems)
                   + ". Configure DATABASE_OWNER_* for migrations and a separate application role.")
        if is_production():
            raise ConfigurationError(message)
        logger.warning("%s (allowed outside production)", message)
    return problems
