.PHONY: help install server setup migrate seed-sigs seed-signal-registry \
        seed-scores health lint format test test-unit test-integration clean

# ── default ───────────────────────────────────────────────────────────────────

help:
	@echo "Usage: make <target> [ARGS='...']"
	@echo ""
	@echo "  install               Install all dependencies via uv sync"
	@echo "  server                Start the FastAPI HTTP server (port 8001)"
	@echo ""
	@echo "  setup                 Full seed sequence: migrate + seed-sigs + seed-signal-registry + seed-scores"
	@echo "  migrate               Run DB migrations"
	@echo "  seed-sigs             Seed injection_signatures for the dev tenant"
	@echo "  seed-signal-registry  Seed the signal registry"
	@echo "  seed-scores           Backfill security_findings + session_risk_scores"
	@echo ""
	@echo "  health                Check Postgres + Redis connectivity"
	@echo "  lint                  Run ruff linter"
	@echo "  format                Run ruff formatter"
	@echo "  test                  Run all tests"
	@echo "  test-unit             Run unit tests only"
	@echo "  test-integration      Run integration tests only"
	@echo "  clean                 Remove __pycache__ and .pyc files"

# ── dependencies ──────────────────────────────────────────────────────────────

install:
	uv sync --all-extras

# ── server ────────────────────────────────────────────────────────────────────

server:
	uv run uvicorn server.main:app --host 0.0.0.0 --port 8001 --reload

# ── database / seed ───────────────────────────────────────────────────────────

setup: migrate seed-sigs seed-signal-registry seed-scores

migrate:
	uv run python scripts/run_migrations.py

# Seeds injection_signatures for the dapplepot_dev tenant (fixed sig_ids).
seed-sigs:
	uv run python scripts/seed_signatures.py

seed-signal-registry:
	uv run python scripts/seed_signal_registry.py

# Backfills security_findings + session_risk_scores for the 5 seeded dev
# sessions. Runs the post-session scorer directly against ClickHouse —
# no live Kafka events required. Must run after seed-sigs + pipeline seed-dev.
seed-scores:
	uv run python scripts/seed_dev_scores.py

# ── ops ───────────────────────────────────────────────────────────────────────

# Checks Postgres and Redis connectivity. Exits 0 if both reachable, 1 otherwise.
health:
	uv run python scripts/health_check.py

# ── quality ───────────────────────────────────────────────────────────────────

lint:
	uv run ruff check .

format:
	uv run ruff format .

# ── tests ─────────────────────────────────────────────────────────────────────

test:
	uv run pytest tests/

test-unit:
	uv run pytest tests/unit/

test-integration:
	uv run pytest tests/integration/

# ── housekeeping ──────────────────────────────────────────────────────────────

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -name "*.pyc" -delete
