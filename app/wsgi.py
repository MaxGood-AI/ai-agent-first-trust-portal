"""WSGI entry point for gunicorn: ``gunicorn -c gunicorn.conf.py app.wsgi:app``.

The database role is checked before serving (``app.serving``): production
refuses to start in single-role mode.
"""

from app import create_app
from app.serving import enforce_serving_role

app = create_app(serving=True)
enforce_serving_role(app)
