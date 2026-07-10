# dapplepot-security

**DapplePot — Security Engine**

FastAPI service that evaluates AI agent sessions for OWASP LLM Top 10 + Agentic AI (ASI) Top 10 threats. Receives events from `dapplepot-api` via HTTP, runs v3 confidence-weighted composite scoring, and writes findings and risk scores to Postgres.

**Stack:** Python 3.12, FastAPI, uvicorn, asyncpg, clickhouse-connect, redis.asyncio, pydantic-settings
**Scorer version:** 3.0.0 | **Signal count:** 20 signals, 196 sub-checks

## Quick Start

```bash
uv sync
cp .env.example .env   # fill in connection strings
make migrate           # run DB migrations
make server            # uvicorn server.main:app --port 8001 --reload
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
| `REFLEX_ENDPOINT_URL` | — | Reflex classifier URL (Cloud Run). Empty = tier off, regex fallback |
| `REFLEX_TIMEOUT_MS` | — | Reflex HTTP timeout. Default `50`; use `1000`+ for remote Cloud Run |
| `REFLEX_API_SECRET` | — | Shared secret sent as `X-Internal-Secret` to `dapplepot-reflex` |
| `NVIDIA_API_KEY` | — | Verdict LLM-judge key (NIM). Empty = tier off, heuristic fallback |
| `NVIDIA_BASE_URL` | — | Default `https://integrate.api.nvidia.com/v1` |
| `VERDICT_MODEL` | — | Default `meta/llama-3.1-8b-instruct` |
| `VERDICT_TIMEOUT_MS` | — | Default `5000` |
| `VERDICT_GATE_SCORE` | — | Skip Verdict when max rule-based effective score < this. Default `35` |
| `VERDICT_MAX_CONCURRENT` | — | In-flight NIM calls cap. Default `4` |
| `VERDICT_MAX_RETRIES` | — | Retry cap on 429/503. Default `3` |

## HTTP Endpoint

`POST /v1/evaluate` — receives events forwarded from `dapplepot-api`. Direct HTTP call (no Kafka).

### Event Dispatch

| `event_type` | Action |
|-------------|--------|
| `graph_start` | `push_agent_defaults()` → seed per-agent security config in Redis (TTL 300s) |
| `security_finding` | Persist online finding from SDK immediately (no wait for session end) |
| `graph_end` | `score_session()` — full post-session scoring pipeline |
| `graph_error` | `score_session()` — same as graph_end |

Online finding persistence tasks are tracked in `_pending_findings` per session. The scorer (`_run_scorer_after_findings`) waits for all in-flight finding-persist tasks to complete before querying the DB, ensuring online findings are visible to the post-session scoring pipeline.

## Online Findings (SDK-initiated)

The SDK sends `security_finding` events with `sub_check_id`, `trigger_event_id`, and `trigger_event_type`. The security service maps these via `_ONLINE_SIGNAL_MAP` (keyed by `sub_check_id`) before persisting. The `trigger_event_id`/`trigger_event_type` are stored so the UI can link findings to the originating event in the trace timeline.

| sub_check_id | OWASP ID | Severity | Confidence |
|-------------|----------|---------|------------|
| `PI-01a` | OW-LLM01 | high | high |
| `PI-01b` | OW-LLM01 | critical | deterministic |
| `PI-01c` | OW-LLM01 | high | high |
| `PI-02a` | OW-LLM01 | high | high |
| `PI-05a` | OW-LLM01 | high | high |
| `PI-08a` | OW-LLM01 | high | medium |
| `SID-01a` | OW-LLM02 | critical | deterministic |
| `SID-01c` | OW-LLM02 | critical | deterministic |
| `SID-02a` | OW-LLM02 | high | high |
| `IOH-01a` | OW-LLM05 | critical | deterministic |
| `EA-01a` | OW-LLM06 | high | deterministic |
| `EA-02b` | OW-LLM06 | high | deterministic |

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

## Model tiers — Reflex + Verdict

Two pluggable model backends. Each is authoritative for its routed
sub-checks when configured; falls back silently to regex/heuristic when not.

| Tier | Runs in | Enabled by | Routed | Actually judged today |
|---|---|---|---|---|
| **Reflex** | `/v1/online-check` (last, after all regex handlers) | `REFLEX_ENDPOINT_URL` | 45 sub-check IDs | ~15 (current classifier is Prompt-Guard-2-86M; covers the `prompt_injection` category + `IAC-01b`/`MCP-03a`. Other 30 routed IDs fall back to regex silently.) |
| **Verdict** | `orchestrator.score_session` (before v3 scoring) | `NVIDIA_API_KEY` | 46 sub-check IDs | 46 (LLM judge; a broader classifier can drop what's not attempted) |

Routing map: `registry/model_coverage.yaml`.
Verdict cost-gated by `VERDICT_GATE_SCORE` (default 35 = medium band); one
combined NIM call per session; retries 429/503; multi-turn sessions send
current-turn events only + prior findings summary.

Findings returned by `/v1/online-check` are sorted before response:
`alert < sanitize < block_call < terminate_session`, then `check_score` desc.

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

## Key Schema Changes (recent)

- **`agent_alert_config`** — added `tool_manifest JSONB DEFAULT '[]'` (allowed tool names for manifest sub-checks) and `max_tool_calls_per_session INT` (hard cap; NULL = statistical baseline)
- **`security_findings`** — uniqueness constraint is now `(session_id, sub_check_id, event_id)` — the same sub-check can fire multiple times per session and all firings are stored
- **`detection_phase`** — now accepts `'cross_session'` in addition to `'online'` and `'post_session'`
- **`alerts`** — `rule_id` column and FK to `policy_rules` removed (policy_rules table dropped — scaffolded for user-defined custom rules but never wired up). Alerts now have only `rule_name` + `payload->>'rule_type'` for grouping.

## Alert Types

The scorer produces three alert types via `security_eval/findings.py`. All share the same `alerts` table; consumers distinguish via `rule_name`.

| `rule_name` | Scope | Dedup | Notes |
|-------------|-------|-------|-------|
| `Security Risk Score` | session | once per `session_id` | Fires when composite ≥ `COMPOSITE_ALERT_THRESHOLD_V3` (default 60). Suppressed when every finding was already caught online (covered by online alert). |
| `Online Security Detection` | session | once per `session_id` | Bundles all online findings for the session with per-detection action (`sanitize` / `block_call` / `terminate_session` / `alert`). |
| `Agent Trust Degradation` | **agent** | once per `agent_id` per day | Agent-level — `session_id` is `NULL`. Fires when `trust_score < 50` for the last `AGENT_TRUST_CONSECUTIVE_SESSIONS` (default 3) scored sessions for the agent. Pre-check at insert time enforces the daily cap. |

## Key Files

| File | Description |
|------|-------------|
| `server/main.py` | FastAPI app, `POST /v1/evaluate` route |
| `security_eval/consumer.py` | `_handle_event()` — dispatch logic, `_ONLINE_SIGNAL_MAP` (keyed by sub_check_id) |
| `security_eval/findings.py` | `Finding` dataclass + `write_findings()`, `write_session_action()` |
| `security_eval/scorer/orchestrator.py` | `score_session()` — main scoring entry point |
| `security_eval/scorer/llm_signals.py` | OW-LLM01–10 signal functions (~1,000 LOC) |
| `security_eval/scorer/asi_signals.py` | OW-ASI01–10 signal functions (~1,300 LOC) |
| `security_eval/scorer/attack_chains.py` | 7 attack chain patterns |
| `security_eval/scorer/cross_session.py` | Cross-session signal functions (SID-03a, SID-04a, UBC-03a/05a, IPA-05a, MCP-02a/04a, RA-02a) |
| `security_eval/scorer/trust.py` | Bayesian agent trust scoring |
| `security_eval/scorer/probe.py` | Probe utilities used by signal functions |
| `security_eval/models/` | Reflex + Verdict clients (`reflex.py`, `verdict.py`, `prompts.py`) |
| `registry/model_coverage.yaml` | Reflex/Verdict sub-check routing |
| `core/security_config.py` | `AgentSecurityConfig`, `SubCheckOverride`, `push_agent_defaults()`, Redis cache |
| `db/postgres/` | 23 migration files |

## Make Targets

```bash
make server    # uvicorn server.main:app --host 0.0.0.0 --port 8001 --reload
make migrate   # run DB migrations
make health    # check Postgres + Redis connectivity
make lint      # ruff check
make format    # ruff format
make clean     # remove __pycache__ and .pyc files
```