#!/bin/bash
set -e

echo "Running database migrations..."
/app/.venv/bin/python scripts/run_migrations.py

echo "Starting security server..."
exec /app/.venv/bin/uvicorn server.main:app \
  --host 0.0.0.0 \
  --port "${PORT:-8001}" \
  --workers 2
