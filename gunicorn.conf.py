"""gunicorn configuration for the trust portal (production and development).

- gthread workers: ``WEB_CONCURRENCY`` processes (default 2) x 4 threads.
- 120 s request timeout (25 MB transcript uploads over slow links), 30 s
  graceful shutdown for rolling deploys.
- Access and error logs go to stdout/stderr; the app's logging setup ships
  them to CloudWatch when ``CLOUDWATCH_LOG_GROUP`` is set.
- ``X-Forwarded-*`` headers are interpreted by the application (ProxyFix,
  ``TRUSTED_PROXY_HOPS``); gunicorn trusts them only when proxies are
  configured, so the two layers agree.
- Every worker starts the background scheduler in standby; exactly one
  process per database becomes the leader (PostgreSQL advisory lock).
"""

import os

bind = "0.0.0.0:5100"
workers = int(os.environ.get("WEB_CONCURRENCY", "2"))
worker_class = "gthread"
threads = 4
timeout = 120
graceful_timeout = 30
keepalive = 5
worker_tmp_dir = "/dev/shm" if os.path.isdir("/dev/shm") else None
accesslog = "-"
errorlog = "-"
access_log_format = '%({x-forwarded-for}i)s %(h)s "%(r)s" %(s)s %(b)s %(M)sms "%(a)s"'
limit_request_line = 8190


def _proxy_hops() -> int:
    default = "1" if os.environ.get("PORTAL_ENV", "production") == "production" else "0"
    try:
        return int(os.environ.get("TRUSTED_PROXY_HOPS", default) or default)
    except ValueError:
        return 0


forwarded_allow_ips = "*" if _proxy_hops() > 0 else "127.0.0.1"


def post_worker_init(worker):
    from app.logging_config import configure_logging
    from app.services import scheduler

    configure_logging()
    scheduler.start_background(worker.wsgi)


def worker_exit(server, worker):
    from app.logging_config import shutdown_logging
    from app.services import scheduler

    scheduler.stop_background()
    shutdown_logging()
