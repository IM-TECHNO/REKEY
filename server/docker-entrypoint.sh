#!/bin/sh
set -eu

# Keys live in this process's memory while unsealed: never write a core dump.
ulimit -c 0 2>/dev/null || true

# Apply database migrations first (set REKEY_AUTO_MIGRATE=0 to run them as a separate job).
if [ "${REKEY_AUTO_MIGRATE:-1}" = "1" ]; then
  alembic upgrade head
fi

# One worker on purpose: the unsealed key and the rate limiter live in process memory.
# Forwarded headers are interpreted by Rekey itself (REKEY_TRUSTED_PROXY_HOPS), not by uvicorn.
exec uvicorn rekey.main:create_app --factory \
  --host 0.0.0.0 --port 8000 --workers 1 \
  --no-proxy-headers --no-server-header
