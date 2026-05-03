#!/bin/bash
set -e

cd /home/site/wwwroot

# Install dependencies
pip install uv --quiet
uv sync --no-dev

# Run migrations
python scripts/run_migrations.py

# Start server — Azure injects PORT env var
PORT=${PORT:-8001}
uvicorn server.main:app --host 0.0.0.0 --port $PORT --workers 2
