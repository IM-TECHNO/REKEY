# syntax=docker/dockerfile:1
FROM python:3.12-slim AS build
ENV UV_LINK_MODE=copy UV_COMPILE_BYTECODE=1 PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN pip install uv==0.11.6
WORKDIR /app
# Dependencies first (cached until the lock file changes), exactly as locked.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
RUN uv sync --frozen --no-dev --no-editable

FROM python:3.12-slim
ENV PATH="/app/.venv/bin:$PATH" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
RUN useradd --system --uid 10001 --no-create-home --shell /usr/sbin/nologin rekey
WORKDIR /app
COPY --from=build /app/.venv /app/.venv
COPY alembic.ini ./
COPY migrations ./migrations
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod 0555 /usr/local/bin/docker-entrypoint.sh
USER 10001
EXPOSE 8000
HEALTHCHECK --interval=15s --timeout=3s --start-period=20s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/health', timeout=2).status == 200 else 1)"
ENTRYPOINT ["docker-entrypoint.sh"]
