# dapplepot-security

**DapplePot — Security Engine**

FastAPI service that evaluates AI agent sessions for OWASP LLM Top 10 + Agentic AI (ASI) Top 10 threats. Receives events from `dapplepot-api` via HTTP, runs v3 confidence-weighted composite scoring, and writes findings and risk scores to Postgres.

**Stack:** Python 3.12, FastAPI, uvicorn, asyncpg, clickhouse-connect, redis.asyncio, pydantic-settings
**Scorer version:** 3.0.0 | **Signal count:** 20 signals, 196 sub-checks

## Quick Start

```bash
uv sync
cp .env.example .env   # fill in connection strings
make setup             # run migrations + seed signal registry + signatures
make run               # uvicorn server.main:app --port 8001
make test-unit         # ~1,000+ assertions, no infra (~2 min)
```

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `POSTGRES_DSN` | ✅ | `postgresql://user:pass@host:5432/db` |
| `CLICKHOUSE_HOST` | ✅ | ClickHouse host |
| `CLICKHOUSE_PORT` | — | Default `8123` |
| `CLICKHOUSE_USER` | — | Default `dapplepot` |
| `CLICKHOUSE_PASSWORD` | — | ClickHouse password |
| `REDIS_URL` | ✅ | `redis://localhost:6379/0` |
| `SCORER_VERSION` | — | Default `3.0.0` |
| `COMPOSITE_ALERT_THRESHOLD_V3` | — | Default `60` |

## HTTP Endpoint

`POST /v1/evaluate` — receives events forwarded from `dapplepot-api`. No Kafka; this is a direct HTTP call.

### Event Dispatch

| `event_type` | Action |
|-------------|--------|
| `graph_start` | `push_agent_defaults()` → seed per-agent security config in Redis (TTL 300s) |
| `security_finding` | Persist online finding from SDK immediately (no wait for session end) |
| `graph_end` | `score_session()` — full post-session scoring pipeline |
| `graph_error` | `score_session()` — same as graph_end |

All scoring and finding persistence run as `asyncio.create_task` (fire-and-forget from the HTTP handler).

## Scoring Pipeline (`score_session`)

```
score_session(tenant_id, session_id, agent_id)
  ├─ get_agent_security_config()   Redis cache (TTL 300s)
  ├─ Fetch all events              ClickHouse obs_events FINAL
  ├─ Fetch session                 Postgres (initial_input, graph_state, hitl_enabled)
  ├─ _run_per_event_detectors()    Replay events through detectors/
  ├─ Run 10 LLM signal functions   llm_signals.py
  ├─ Run 10 ASI signal functions   asi_signals.py
  ├─ Run cross-session signals     cross_session.py
  ├─ compute_ow_signal_score()     → signal_map
  ├─ detect_attack_chains()        7 patterns, max amplification
  ├─ compute_composite_score_v3()  → LLM composite + ASI composite
  ├─ write_findings()              → security_findings (Postgres)
  ├─ write_session_risk_score()    → session_risk_scores (Postgres, v3 JSONB)
  ├─ compute_agent_trust_score()   Bayesian Beta(α=2,β=8) + temporal decay
  └─ write_agent_risk_score()      → agent_risk_scores (Postgres)
```

## v3 Scoring Model

### Composite Score
```
raw = highest_signal × 0.60 + mean(rest) × 0.40   (2+ signals fired)
    = highest_signal                                (1 signal fired)
final = min(100, int(raw × amplification))
```

### Attack Chain Amplification (7 patterns)
| Chain | Signals | Amplification |
|-------|---------|---------------|
| indirect_injection_to_exfil | LLM01+ASI02+LLM02 | 1.25× |
| goal_hijack_to_rce | ASI01+ASI05 | 1.30× |
| supply_chain_to_backdoor | ASI04+ASI05+ASI10 | 1.35× |
| memory_poison_to_exfil | ASI06+ASI01+LLM02 | 1.25× |
| privilege_escalation_chain | ASI03+ASI02+LLM06 | 1.20× |
| trust_exploitation_to_fraud | ASI09+ASI01+LLM05 | 1.25× |
| cascading_failure_chain | ASI08+ASI07+ASI10 | 1.30× |

### Risk Bands
| Band | Score |
|------|-------|
| clean | 0–14 |
| low | 15–34 |
| medium | 35–59 |
| high | 60–84 |
| critical | 85–100 |

### Trust Score (Agent-level, Bayesian)
```
Prior: Beta(α=2, β=8) → ~80% starting trust
Per session: composite < 35 → α+=1 (clean); composite ≥ 35 → β+=1 (risky)
Temporal decay: weight_i = exp(-0.05 × days_ago_i)
trust_score = int(100 × (1 − α/(α+β)))
```

## Online Findings (SDK-initiated)

The SDK sends `security_finding` events with `{signal, reason}`. The security service maps these to full OWASP fields via `_ONLINE_SIGNAL_MAP` in `consumers/security_eval/consumer.py` before persisting:

| SDK signal | OWASP ID | Sub-check |
|------------|----------|-----------|
| `prompt_injection` | OW-LLM01 | llm-01-online |
| `insecure_output` | OW-LLM09 | llm-09-online |
| `pii_input` | OW-LLM02 | llm-02-online-in |
| `pii_output` | OW-LLM02 | llm-02-online-out |
| `sensitive_data_exfiltration` | OW-LLM02 | llm-02-online-exfil |
| `tool_misuse` | OW-LLM05 | llm-05-online |
| `resource_exhaustion` | OW-ASI08 | asi-08-online |
| `privilege_escalation` | OW-ASI05 | asi-05-online-priv |
| `unsafe_code_execution` | OW-ASI05 | asi-05-online-code |
| `supply_chain_tool` | OW-ASI04 | asi-04-online |

## Key Files

| File | Description |
|------|-------------|
| `server/main.py` | FastAPI app, `POST /v1/evaluate` route |
| `consumers/security_eval/consumer.py` | `_handle_event()` — all dispatch logic, `_ONLINE_SIGNAL_MAP` |
| `consumers/security_eval/findings.py` | `Finding` dataclass + `write_findings()`, `write_session_action()` |
| `consumers/security_eval/scorer/orchestrator.py` | `score_session()` — main scoring entry point |
| `consumers/security_eval/scorer/llm_signals.py` | OW-LLM01–10 signal functions (~1,000 LOC) |
| `consumers/security_eval/scorer/asi_signals.py` | OW-ASI01–10 signal functions (~1,300 LOC) |
| `consumers/security_eval/scorer/attack_chains.py` | 7 attack chain patterns |
| `consumers/security_eval/scorer/trust.py` | Bayesian agent trust scoring |
| `core/security_config.py` | `AgentSecurityConfig`, `push_agent_defaults()`, Redis cache |
| `db/postgres/` | 22 migration files |

## Make Targets

```bash
make run              # uvicorn server.main:app --host 0.0.0.0 --port 8001
make setup            # migrate + seed signal registry + seed signatures
make migrate          # run migrations only
make seed-registry    # upsert 156 sub-checks with confidence_tier
make test-unit        # no infra required, ~2 min
make test-integration # needs docker compose up
make test             # all tests
make health           # check consumer lag / service health
```

## Related Repos

| Repo | Role |
|------|------|
| [dapplepot-sdk](../dapplepot-sdk) | Python SDK — sends `security_finding` events |
| [dapplepot-api](../dapplepot-api) | Forwards events via `POST /v1/evaluate` |
| [dapplepot-ui](../dapplepot-ui) | Displays findings, risk scores, agent profiles |
