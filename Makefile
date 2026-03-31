.PHONY: run migrate seed-sigs health test test-unit test-integration

run:
	uv run python -m consumers.security_eval.consumer

migrate:
	uv run python scripts/run_migrations.py

seed-sigs:
	uv run python scripts/seed_signatures.py

# Reports dp-security-eval consumer lag on obs.events.v1.
# Exits 1 if any partition lag exceeds --max-lag (default 10,000).
health:
	uv run python scripts/health_check.py

test:
	uv run pytest tests/

test-unit:
	uv run pytest tests/unit/

test-integration:
	uv run pytest tests/integration/
