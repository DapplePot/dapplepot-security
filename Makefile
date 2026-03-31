.PHONY: run migrate seed-sigs test test-unit test-integration

run:
	uv run python -m consumers.security_eval.consumer

migrate:
	uv run python scripts/run_migrations.py

seed-sigs:
	uv run python scripts/seed_signatures.py

test:
	uv run pytest tests/

test-unit:
	uv run pytest tests/unit/

test-integration:
	uv run pytest tests/integration/
