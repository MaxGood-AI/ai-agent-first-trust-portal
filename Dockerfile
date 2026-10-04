# syntax=docker/dockerfile:1
#
# Stages:
#   base        runtime dependencies and the unprivileged "portal" user
#   test        base + test dependencies + the full source tree; runs the unit suite
#   production  base + application code only (default target); runs as uid 10001
#
#   docker build --target test -t trust-portal:test .
#   docker build --build-arg PORTAL_VERSION=$(git rev-parse --short HEAD) -t trust-portal .

# Base images come from ECR Public (no Docker Hub rate limits in CI).
FROM public.ecr.aws/docker/library/python:3.12-slim AS base

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN groupadd --system --gid 10001 portal \
    && useradd --system --uid 10001 --gid portal --home-dir /app --no-create-home \
       --shell /usr/sbin/nologin portal

WORKDIR /app
COPY requirements.txt .
RUN pip install -r requirements.txt


FROM base AS test
COPY requirements-dev.txt .
RUN pip install -r requirements-dev.txt
COPY . .
ENV PORTAL_ENV=test
CMD ["pytest", "-q", "-p", "no:cacheprovider", "--cov=app", "--cov=cli", "--cov=collectors", "--cov-report=term"]


FROM base AS production
ARG PORTAL_VERSION=dev
ENV PORTAL_ENV=production \
    PORTAL_VERSION=${PORTAL_VERSION}

COPY alembic.ini gunicorn.conf.py entrypoint.sh ./
COPY app ./app
COPY cli ./cli
COPY collectors ./collectors
COPY migrations ./migrations
COPY policy-templates ./policy-templates
COPY templates ./templates
RUN chmod 0755 entrypoint.sh

USER 10001:10001
EXPOSE 5100

HEALTHCHECK --interval=30s --timeout=5s --start-period=60s --retries=3 \
    CMD ["python", "-c", "import sys, urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5100/api/health', timeout=4).status == 200 else 1)"]

ENTRYPOINT ["./entrypoint.sh"]
CMD ["gunicorn", "-c", "gunicorn.conf.py", "app.wsgi:app"]
