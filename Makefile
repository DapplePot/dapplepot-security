.PHONY: run setup migrate seed-sigs seed-scores health test test-unit test-integration

run:
	uv run python -m consumers.security_eval.consumer

# Step 3 of platform startup: run after `make seed-dev` in dapplepot_pipeline.
setup: migrate seed-sigs seed-scores

migrate:
	uv run python scripts/run_migrations.py

# Seeds injection_signatures for the dapplepot_dev tenant (fixed sig_ids).
seed-sigs:
	uv run python scripts/seed_signatures.py

# Backfills security_findings + session_risk_scores for the 5 seeded dev
# sessions. Runs the post-session scorer directly against ClickHouse —
# no live Kafka events required. Must run after seed-sigs + pipeline seed-dev.
seed-scores:
	uv run python scripts/seed_scores.py

# Reports dp-security-eval consumer lag on obs.events.v1.
# Exits 1 if any partition lag exceeds --max-lag (default 10,000).
# Usage: make health -- --max-lag 5000
health:
	uv run python scripts/health_check.py $(ARGS)

test:
	uv run pytest tests/

test-unit:
	uv run pytest tests/unit/

test-integration:
	uv run pytest tests/integration/
