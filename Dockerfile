# syntax=docker/dockerfile:1.7

# ------------------------------------------------------------------
# Stage 1 — builder. Installs Poetry, resolves and installs the
# project into an isolated virtualenv. Kept separate so build-time
# toolchain (gcc, git, dev headers) never reaches the runtime image.
# ------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS builder

ENV PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POETRY_VERSION=1.8.3 \
    POETRY_HOME=/opt/poetry \
    POETRY_VIRTUALENVS_CREATE=true \
    POETRY_VIRTUALENVS_IN_PROJECT=true \
    POETRY_NO_INTERACTION=1

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential \
        git \
        curl \
    && rm -rf /var/lib/apt/lists/* \
    && curl -sSL https://install.python-poetry.org | python3 - \
    && ln -s /opt/poetry/bin/poetry /usr/local/bin/poetry

WORKDIR /app

# Copy dep manifests first so layer cache survives application changes.
COPY pyproject.toml poetry.lock README.md ./

RUN poetry install --no-interaction --no-root --only main

# Now bring in the source and install the project itself.
COPY src ./src
RUN poetry install --no-interaction --only-root

# ------------------------------------------------------------------
# Stage 2 — runtime. Minimal image, non-root user, HEALTHCHECK.
# The builder's apt toolchain is intentionally NOT copied forward.
# ------------------------------------------------------------------
FROM python:3.11-slim-bookworm AS runtime

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/app/.venv/bin:${PATH}" \
    APPROVED_DIRECTORY=/projects \
    DATABASE_URL=sqlite:////app/data/bot.db

# Install only runtime OS deps. ``ca-certificates`` is required for
# outbound HTTPS to the Telegram + Anthropic APIs. ``tini`` gives us
# a proper PID 1 that reaps zombies and forwards signals.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        tini \
    && rm -rf /var/lib/apt/lists/* \
    # Non-root user. UID:GID 10001 keeps us well outside the
    # Debian system range and stable across rebuilds.
    && groupadd --system --gid 10001 bot \
    && useradd --system --uid 10001 --gid bot --home-dir /app --shell /usr/sbin/nologin bot

WORKDIR /app

COPY --from=builder --chown=bot:bot /app/.venv /app/.venv
COPY --from=builder --chown=bot:bot /app/src /app/src
COPY --from=builder --chown=bot:bot /app/pyproject.toml /app/README.md /app/

# Per-container mutable state. Volumes mount here in practice.
RUN mkdir -p /app/data /projects \
    && chown -R bot:bot /app/data /projects

USER bot

# HEALTHCHECK: if we've bound the API server on port 8080 (the
# default when ``ENABLE_API_SERVER=true``), probe it. When the API
# server is disabled, set ``HEALTHCHECK_URL=`` empty at container
# runtime to suppress. Uses Python rather than ``curl`` to avoid
# pulling another apt package.
HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 \
    CMD python - <<'PY' || exit 1
import os, sys, urllib.request
url = os.environ.get("HEALTHCHECK_URL", "http://127.0.0.1:8080/health")
if not url:
    sys.exit(0)
try:
    with urllib.request.urlopen(url, timeout=4) as resp:
        sys.exit(0 if 200 <= resp.status < 500 else 1)
except Exception:
    sys.exit(1)
PY

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["claude-telegram-bot"]
