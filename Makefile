.PHONY: help install server migrate health lint format clean

# ── default ───────────────────────────────────────────────────────────────────

help:
	@echo "Usage: make <target>"
	@echo ""
	@echo "  install    Install all dependencies via uv sync"
	@echo "  server     Start the FastAPI HTTP server (port 8001)"
	@echo ""
	@echo "  migrate    Run DB migrations"
	@echo ""
	@echo "  health     Check Postgres + Redis connectivity"
	@echo "  lint       Run ruff linter"
	@echo "  format     Run ruff formatter"
	@echo "  clean      Remove __pycache__ and .pyc files"

# ── dependencies ──────────────────────────────────────────────────────────────

install:
	uv sync --all-extras

# ── server ────────────────────────────────────────────────────────────────────

server:
	uv run uvicorn server.main:app --host 0.0.0.0 --port 8001 --reload

# ── database ──────────────────────────────────────────────────────────────────

migrate:
	uv run python scripts/run_migrations.py

# ── ops ───────────────────────────────────────────────────────────────────────

# Checks Postgres and Redis connectivity. Exits 0 if both reachable, 1 otherwise.
health:
	uv run python scripts/health_check.py

# ── quality ───────────────────────────────────────────────────────────────────

lint:
	uv run ruff check .

format:
	uv run ruff format .

# ── housekeeping ──────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
