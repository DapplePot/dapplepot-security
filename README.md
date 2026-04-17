# dapplepot_security

**Dapplepot — Security Engine**

Zone 6 of the Dapplepot observability platform. A standalone Python service
that runs OWASP LLM Top 10 **and** OWASP Agentic AI (ASI) Top 10 detection
against LangGraph agent sessions — prompt injection, output passthrough, PII
disclosure, agentic threat patterns, cross-session escalation, and post-session
risk scoring for both LLM and agent dimensions.

**Language: Python 3.12** | **Scorer: v3.0.0**

---

## What this service does

```
Kafka obs.events.v1  (same topic as dapplepot_pipeline, separate consumer group)
  └── dp-security-eval (30 workers)
        │
        ├── agent_created events → push default security config to Redis
        │
        ├── security_finding events (SDK online detections)
        │     └── Persist finding to security_findings (detection_phase='online')
        │           + write session_actions audit row for hard actions
        │               (sanitize / block_call / terminate_session)
        │
        └── On graph_end / graph_error — post-session scorer (async)
              │
              ├── Per-event detectors — replays session events from ClickHouse in order
              │     ├── llm_start   → injection.py      (OW-LLM01: PI-01a/b/c, PI-02a, PI-05a/07a/08a/09a)
              │     │               → agentic.py        (OW-ASI06: MCP-01a context injection)
              │     ├── llm_end     → disclosure.py     (OW-LLM02: SID-01a/c, SID-02a/b/c)
              │     │               → prompt_guard.py   (OW-LLM07: SPL-01a/b)
              │     ├── tool_start  → passthrough.py    (OW-LLM05: IOH-01a/b/c, IOH-02a)
              │     │               → agentic.py        (OW-ASI02: TME-01a, TME-03b)
              │     │               →                   (OW-ASI04: ASCV-02a, ASCV-04a)
              │     │               →                   (OW-ASI05: RCE-01b, RCE-03a/b, RCE-06a/08a)
              │     │               →                   (OW-ASI01: AGH-04a doc injection)
              │     │               →                   (OW-ASI10: RA-04a self-replication)
              │     └── tool_end    → disclosure.py     (OW-LLM02: PII patterns)
              │                     → agentic.py        (OW-ASI01: AGH-04a)
              │
              ├── LLM signals (OWASP LLM Top 10) — llm_signals.py
              │     ├── OW-LLM01: multi-turn jailbreak (PI-04b), payload splitting (PI-06a)
              │     ├── OW-LLM04: RAG integrity (DMP-01a/c) — excluded (pre-runtime)
              │     ├── OW-LLM05: insecure code in output (IOH-04a)
              │     ├── OW-LLM06: excessive tool calls vs baseline (EA-01a/02a/03a)
              │     ├── OW-LLM08: vector integrity — excluded (pre-runtime)
              │     ├── OW-LLM09: hallucinated packages (SAG-02a), high-stakes without grounding (SAG-03a)
              │     └── OW-LLM10: token/input size anomaly (UBC-01a/02a), cross-session probes (UBC-03a/05a)
              │
              ├── ASI signals (OWASP Agentic AI Top 10) — asi_signals.py
              │     ├── OW-ASI01: goal hijack (AGH-02a zero-click, AGH-03a drift)
              │     ├── OW-ASI02: tool misuse (TME-02a..08a)
              │     ├── OW-ASI03: identity & privilege (IPA-02a..05a)
              │     ├── OW-ASI04: supply chain (ASCV-02a..05a)
              │     ├── OW-ASI05: RCE (RCE-04a..08a)
              │     ├── OW-ASI06: memory poisoning (MCP-02a..05a)
              │     ├── OW-ASI07: inter-agent comms (IAC-02a..06a)
              │     ├── OW-ASI08: cascading failures (CF-02a..04a)
              │     ├── OW-ASI09: trust exploitation (HAT-02a..05a)
              │     └── OW-ASI10: rogue agents (RA-02a..05a)
              │
              ├── Cross-session signals — cross_session.py         ← v3 NEW
              │     ├── SID-03a: cross-user context bleed
              │     ├── UBC-03a/05a: request rate + cost spike
              │     ├── IPA-05a: identity sharing across users
              │     ├── MCP-02a/04a: cross-session escalation + cross-tenant retrieval
              │     └── RA-02a: persistent exfiltration pattern
              │
              ├── Scoring — orchestrator.py (v3)                   ← v3 CHANGED
              │     ├── Confidence-weighted per-signal scores
              │     ├── Attack chain detection + amplification (7 chains)
              │     ├── v3 composite score (0–100) per framework
              │     └── Alert fires when composite >= composite threshold (default 60, per-agent configurable)
              │
              └── Trust scoring — trust.py                         ← v3 NEW
                    Bayesian Beta(α=2,β=8) prior + temporal decay + trend detection
                    → agent_risk_scores.trust_score (0–100)
```

## Signal taxonomy

All signals use canonical OWASP identifiers: `OW-LLM01..OW-LLM10` and `OW-ASI01..OW-ASI10`.
Each signal has named sub-checks (e.g. `PI-01a`, `SID-02b`, `RCE-03a`) with individual
`check_score` (0–100) and `confidence_tier` (deterministic / high / medium / low / skeletal).

The effective sub-check score = `check_score × confidence_weight`. The parent signal score is
`max(effective_score)` across all fired sub-checks.

The full sub-check registry (156 entries) is stored in the `signal_registry` table
(seeded by `scripts/seed_signal_registry.py`).

---

## Event sources & payloads

### Kafka `obs.events.v1` — primary input

All events share a common envelope:

```json
{
  "event_id":    "<uuid>",
  "event_type":  "<string>",
  "session_id":  "<uuid>",
  "tenant_id":   "<uuid>",
  "agent_id":    "<uuid>",
  "node_run_id": "<uuid>",
  "payload":     { ... }
}
```

| `event_type` | Payload fields consumed | What runs |
|---|---|---|
| `agent_created` | `tenant_id`, `agent_id` | Push default security config to Redis (`dp:sec:{tenant_id}:agent:{agent_id}:cfg`) |
| `security_finding` | `payload.*` (full Finding fields), `emitted_at` | Persist SDK online finding to `security_findings`; write `session_actions` audit row for `sanitize`/`terminate_session` |
| `llm_start` | `payload.messages[].role`, `payload.messages[].content` | Prompt injection (PI-01a/b/c/05a/07a/08a/09a); context injection (MCP-01a) |
| `llm_end` | `payload.completion` | PII scanner (SID-*); system prompt leakage (SPL-01a/b); insecure output (IOH-04a) |
| `tool_start` | `payload.tool_input`, `payload.tool_name` | Output passthrough (IOH-*); tool misuse (TME-01a, TME-03b); code execution (RCE-01b, RCE-03a/b, RCE-06a/08a); supply chain (ASCV-02a/04a); doc injection (AGH-04a); self-replication (RA-04a) |
| `tool_end` | `payload.tool_output` | PII scanner; doc injection (AGH-04a); memory write checks |
| `graph_end` | (envelope only) | Triggers async `score_session()` |
| `graph_error` | (envelope only) | Same as `graph_end` |
| everything else | — | Consumed and committed, no detection |

### Postgres `sessions` table — queried during post-session scoring

| Column | Used by |
|---|---|
| `initial_input` | Write-on-read-intent detection (EA-03a) |
| `graph_state` | HITL gap detection (SAG-01a/03a) — checks `hitl_enabled` flag |
| `graph_runs` | Available for scoring context |
| `duration_ms` | Stale auth detection (IPA-04a) |

### ClickHouse `obs_events` table — queried during post-session scoring

| Column | Used by |
|---|---|
| `event_type` | All signals — filter to relevant event types |
| `tool_name` | EA-01a (count), EA-02a (scope), EA-03a (write pattern), SAG-01a (high-stakes), RCE-04a (loop) |
| `llm_input_tokens`, `llm_output_tokens` | UBC-01a (token spike), UBC-02a (input size) |
| `payload` | UBC-04a (cross-session cohort); cross-session signals (SID-03a, UBC-03a/05a, IPA-05a, MCP-02a/04a, RA-02a) |
| `emitted_at` | 7-day baseline windows; temporal decay in trust scoring |

---

## What it does NOT do

- It does not call `dapplepot_pipeline` or `dapplepot_api` over HTTP
- It does not modify any table owned by `dapplepot_pipeline`
- It does not change the Kafka topics or consumer groups of other services
- It has zero impact on the pipeline's throughput or latency

---

## Related repositories

| Repo | Zone | Language | What it is |
|------|------|----------|-----------|
| `dapplepot_sim` | 1 | Python | Simulation agent |
| `dapplepot_langgraph` | 2 | Python | SDK |
| `dapplepot_pipeline` | 3 | Python | Event ingestion + pipeline |
| `dapplepot_api` | 4 | TypeScript | Platform API — reads the tables we write |
| `dapplepot_ui` | 5 | TypeScript / React | Dashboard — shows security posture UI |
| **`dapplepot_security`** | **6** | **Python** | **This repo** |

---

## Changes made in other repos

**`dapplepot_pipeline`** — 3 changes:
- `db/postgres/008_tenant_notification_channels.sql` — new table for per-tenant
  notification channel config (webhook / slack / pagerduty).
- `consumers/policy_evaluator/alert_router.py` — `_get_tenant_channels()` and
  `_persist_alert()` added to upsert security alerts into the Postgres `alerts` table.

**`dapplepot_api`** — 4 changes:
- `queries/alerts.pg.ts` — `source` field extracted; `source` filter added to `getAlertList`.
- `queries/sessions.pg.ts` — `getSessionAlerts` includes `source`.
- `routes/alerts.ts` — `source` query param wired through.
- `types/common.ts` — `source` added to `AlertListParams`.

**`dapplepot_ui`** — 4 changes:
- `types/alert.ts` — `source: 'security' | 'policy'` added to `AlertSummary`.
- `stores/alertFilters.ts` — `source` filter state + `setSource` action.
- `components/detection/AlertFeed.tsx` — source filter pills; `SecurityDetail` section.
- `components/detection/AlertDrawer.tsx` — renders risk scores, top findings, signal badges.

---

## Repo layout

```
dapplepot_security/
├── agent.md                        ← full IDE agent context
├── README.md
├── pyproject.toml
├── .env.example
├── Makefile
│
├── consumers/
│   └── security_eval/              ← consumer group: dp-security-eval
│       ├── consumer.py             ← Kafka poll loop; handles agent_created, security_finding,
│       │                              and triggers score_session on graph_end/graph_error
│       ├── findings.py             ← Finding dataclass (with confidence_tier), PG batch writer,
│       │                              session_actions writer, alert producer
│       ├── detectors/              ← per-event detectors (replayed post-session from ClickHouse)
│       │   ├── injection.py        ← OW-LLM01: PI-01a/b/c, PI-02a, PI-05a, PI-07a, PI-08a, PI-09a
│       │   ├── disclosure.py       ← OW-LLM02: SID-01a/c, SID-02a/b/c
│       │   ├── passthrough.py      ← OW-LLM05: IOH-01a/b/c, IOH-02a (LCS passthrough)
│       │   ├── agentic.py          ← OW-ASI01/02/04/05/06/10: per-event agentic checks
│       │   └── prompt_guard.py     ← OW-LLM07: SPL-01a (prefix similarity), SPL-01b (probe)
│       └── scorer/
│           ├── orchestrator.py     ← score_session() v3: confidence weighting, attack chains, trust
│           ├── llm_signals.py      ← OW-LLM01..10 post-session signal functions
│           ├── asi_signals.py      ← OW-ASI01..10 post-session signal functions
│           ├── cross_session.py    ← cross-session signals (SID-03a, UBC-03a/05a, IPA-05a, MCP-02a/04a, RA-02a)
│           ├── attack_chains.py    ← detect_attack_chains(): 7 chains, max-amplification
│           ├── trust.py            ← compute_agent_trust_score(): Bayesian Beta, temporal decay, trend
│           └── probe.py            ← OW-LLM10: UBC-04a cross-session model theft probe
│
├── core/
│   ├── config.py                   ← pydantic-settings: Kafka, PG, CH, Redis, CONFIDENCE_WEIGHTS, thresholds
│   ├── security_config.py          ← AgentSecurityConfig: per-agent signal toggles, composite thresholds,
│   │                                  online sub-check detection; Redis-cached (TTL 300s)
│   └── infra/
│       ├── kafka.py
│       ├── postgres.py
│       ├── clickhouse.py
│       └── redis.py
│
├── db/
│   └── postgres/
│       ├── 001_security_findings.sql
│       ├── 002_session_risk_scores.sql
│       ├── 003_agent_risk_scores.sql
│       ├── 004_injection_signatures.sql
│       ├── 005_signal_registry.sql
│       ├── 006_indexes.sql
│       ├── 007_views.sql
│       ├── 008_findings_dedup.sql
│       ├── 013_v3_scoring.sql              ← v3: confidence_tier on signal_registry + findings, v3 composite JSONB
│       ├── 014_cross_session_indexes.sql
│       ├── 016_subcheck_online_toggle.sql  ← agent_subcheck_overrides table
│       ├── 017_agent_alert_config.sql      ← agent_alert_config table (per-agent thresholds)
│       ├── 018_split_composite_thresholds.sql ← llm/asi composite threshold columns
│       ├── 019_session_actions.sql         ← audit trail for online hard actions (sanitize / terminate_session)
│       ├── 020_findings_emitted_at.sql     ← emitted_at column on security_findings
│       └── 021_migrate_monitor_action.sql  ← back-fill monitor → alert action rename
│
├── tests/
│   ├── unit/
│   │   ├── test_prompt_injection.py        ← OW-LLM01 (PI-01a/b + PI-05a/07a/08a/09a)
│   │   ├── test_data_disclosure.py         ← OW-LLM02 disclosure detector
│   │   ├── test_output_handling.py         ← OW-LLM05 passthrough detector
│   │   ├── test_agentic_threats.py         ← OW-ASI agentic detectors (incl. AGH-04a, ASCV-02a/04a, RCE-06a/08a, RA-04a, MCP-03a)
│   │   ├── test_llm_signals.py             ← OW-LLM01..10 post-session signals (incl. PI-06a, IOH-04a, SAG-02a/03a, UBC-02a)
│   │   ├── test_asi_signals.py             ← OW-ASI01..10 post-session signals (all v3 sub-checks)
│   │   ├── test_scoring_v3.py              ← v3: confidence weighting, composite, attack chain amplification
│   │   ├── test_attack_chains.py           ← all 7 attack chains, max-amplification
│   │   ├── test_trust.py                   ← Bayesian trust: prior, update, decay, trend
│   │   ├── test_cross_session.py           ← SID-03a, UBC-03a/05a, IPA-05a, MCP-02a/04a, RA-02a
│   │   └── test_signal_registry.py         ← 156 entries, all 20 signals, confidence_tier coverage
│   └── integration/
│       ├── test_detectors.py               ← detector scenarios against Postgres
│       └── test_post_session_scorer.py     ← v3 end-to-end: composite, attack chains, trust, scorer_version
│
└── scripts/
    ├── run_migrations.py           ← runs db/postgres/ in order
    ├── seed_signatures.py          ← seeds injection_signatures for dapplepot_dev tenant
    ├── seed_signal_registry.py     ← upserts all 156 sub-checks with confidence_tier
    ├── seed_dev_scores.py          ← backfills security_findings + session_risk_scores for dev sessions
    └── health_check.py             ← consumer lag check (make health)
```

---

## Prerequisites

- Python 3.12+
- [uv](https://github.com/astral-sh/uv) (`pip install uv` or `curl -LsSf https://astral.sh/uv/install.sh | sh`)
- `dapplepot_pipeline` cloned with `docker compose up -d` running
  (shares Kafka, Postgres, ClickHouse, Redis)

> **Windows:** `make run` works on Windows — signal handling uses `signal.signal` instead of
> `loop.add_signal_handler` (which is Unix-only). The consumer also stubs out
> `platform.uname()` on import to prevent a WMI hang on some Windows machines.

---

## Setup

### 1. Clone and install dependencies

```bash
git clone https://github.com/dapplepot/dapplepot_security
cd dapplepot_security

uv sync
```

### 2. Configure environment

```bash
cp .env.example .env
```

Open `.env` and verify the connection strings match your running `dapplepot_pipeline` stack.
The defaults in `.env.example` work out of the box against the pipeline's `docker compose` services:

| Variable | Default | Notes |
|---|---|---|
| `KAFKA_BOOTSTRAP_SERVERS` | `localhost:9092` | Kafka broker from pipeline stack |
| `KAFKA_EVENTS_TOPIC` | `obs.events.v1` | Must match pipeline topic name exactly |
| `KAFKA_ALERTS_TOPIC` | `obs.alerts.v1` | Alert output topic |
| `KAFKA_DLQ_TOPIC` | `obs.dlq.v1` | Dead-letter queue (owned by pipeline) |
| `POSTGRES_DSN` | `postgresql://dapplepot:dapplepot@localhost:5432/dapplepot_pipeline` | Shared PG instance |
| `CLICKHOUSE_HOST` | `localhost` | ClickHouse from pipeline stack |
| `CLICKHOUSE_PORT` | `8123` | |
| `CLICKHOUSE_USER` | `dapplepot` | |
| `CLICKHOUSE_PASSWORD` | `dapplepot` | |
| `REDIS_URL` | `redis://localhost:6379/0` | Shared Redis (key namespace `dp:sec:*`) |
| `SECURITY_EVAL_WORKERS` | `4` | Async scoring concurrency |
| `SCORER_VERSION` | `3.0.0` | Written to `session_risk_scores.scorer_version` |
| `SIG_CACHE_TTL_S` | `300` | Redis TTL for injection signature cache |
| `SESSION_CTX_TTL_S` | `120` | Redis TTL for per-session LLM/tool output cache |
| `ALERT_ON_SCORE_GTE` | `65` | Legacy threshold (v3 uses per-signal + composite thresholds) |
| `LLM_INPUT_COST_PER_1K` | `0.01` | USD per 1k input tokens — used by UBC-05a (Denial of Wallet) |
| `LLM_OUTPUT_COST_PER_1K` | `0.03` | USD per 1k output tokens |
| `TOOL_MANIFESTS` | `{}` | JSON map of `agent_id → [allowed_tool_names]` — used by out-of-scope tool detection |

### 3. Run migrations and seed reference data

```bash
make setup
```

This runs (in order):
1. **`make migrate`** — applies all DB migrations in `db/postgres/` (001–021)
2. **`make seed-sigs`** — seeds `injection_signatures` patterns for the `dapplepot_dev` tenant
3. **`make seed-scores`** — backfills `security_findings` + `session_risk_scores` for the 5 dev sessions seeded by `dapplepot_pipeline`'s `make seed-dev`

> `make seed-scores` runs the post-session scorer directly against ClickHouse — no live Kafka events required. It must run **after** `dapplepot_pipeline`'s `make seed-dev`.

### 4. Start the consumer

```bash
make run
```

This starts the `dp-security-eval` Kafka consumer (`consumers.security_eval.consumer`).
It subscribes to `obs.events.v1` and begins scoring sessions as they close.

Stop with `Ctrl+C` (SIGINT). The consumer commits its offset before shutting down.

---

## Full platform startup sequence

```
Step 1  cd dapplepot_pipeline && docker compose up -d
Step 2  cd dapplepot_pipeline && make setup        # topics + PG migrations + ClickHouse
Step 2b cd dapplepot_pipeline && make seed-dev     # tenant · agent · sdk_key · sessions
Step 3  cd dapplepot_security && make setup        # PG migrations 001-021 + seed-sigs + seed-scores
Step 4  cd dapplepot_pipeline && make run-ingest   # + run-session-writer + run-event-appender
                                                   # + run-policy-evaluator + run-alert-router
Step 5  cd dapplepot_security && make run          # dp-security-eval consumer
Step 6  cd dapplepot_api      && <setup>
Step 7  cd dapplepot_ui       && pnpm dev
```

> **Note:** Steps 2–3 are one-time setup. On subsequent runs, only Steps 4–7 are needed.

---

## Makefile reference

| Target | Command | Description |
|--------|---------|-------------|
| `make run` | `uv run python -m consumers.security_eval.consumer` | Start the Kafka consumer |
| `make setup` | `migrate` + `seed-sigs` + `seed-scores` | One-time setup (Step 3 above) |
| `make migrate` | `uv run python scripts/run_migrations.py` | Apply all DB migrations |
| `make seed-sigs` | `uv run python scripts/seed_signatures.py` | Seed injection signatures for dev tenant |
| `make seed-scores` | `uv run python scripts/seed_dev_scores.py` | Backfill scoring data for dev sessions |
| `make health` | `uv run python scripts/health_check.py` | Check `dp-security-eval` consumer lag |
| `make test` | `uv run pytest tests/` | Run all tests |
| `make test-unit` | `uv run pytest tests/unit/` | Unit tests only (no infra required) |
| `make test-integration` | `uv run pytest tests/integration/` | Integration tests (requires pipeline stack) |

---

## Postgres tables this service owns

### `security_findings`

One row per detected sub-check per event. Written by the post-session scorer and by the
consumer when SDK online detections arrive (`security_finding` events).

Key columns: `session_id`, `event_id`, `owasp_signal_id` (`OW-LLM01`), `sub_check_id` (`PI-01a`),
`check_label`, `check_score` (0–100), `confidence_tier`, `confidence` (float),
`severity`, `matched_text` (always redacted), `detection_phase`, `emitted_at`.

### `session_risk_scores`

One row per session. Written by the post-session scorer. `ON CONFLICT DO UPDATE`.

Key columns: `session_id`, `risk_score` (0–100 LLM composite), `risk_band`,
`agent_risk_score` (0–100 ASI composite), `agent_risk_band`,
`ow_llm_signal_status` (JSONB), `ow_asi_signal_status` (JSONB),
`v3_llm_composite` (JSONB — effective scores, attack chains, amplification),
`v3_asi_composite` (JSONB), `scorer_version` (`"3.0.0"`).

### `agent_risk_scores`

One row per agent. Updated after every session.

Key columns: `agent_id`, `session_count`, `avg_llm_score`, `avg_asi_score`,
`max_llm_score`, `max_asi_score`, `trust_score` (0–100), `trust_trend`
(`improving` / `stable` / `degrading`), `last_scored_at`.

### `signal_registry`

One row per sub-check (156 total). Seeded by `scripts/seed_signal_registry.py`.

Key columns: `owasp_signal_id`, `sub_check_id` (PK), `label`, `owasp_category`,
`owasp_number`, `detection_phase`, `check_score`, `severity`, `confidence_tier`,
`excluded`, `exclusion_reason`.

### `injection_signatures`

Tenant-specific injection detection patterns. Cached in Redis at
`dp:sec:sigs:{tenant_id}`, TTL 300s.

### `agent_subcheck_overrides`

Per-agent sub-check online detection toggles. Key: `(tenant_id, agent_id)`.
`overrides` JSONB maps `sub_check_id → {online_detection: bool}`.
When a sub-check is toggled online, the post-session scorer skips it to avoid
double-counting with the SDK's real-time detection.

### `agent_alert_config`

Per-agent alert threshold overrides. Key: `(tenant_id, agent_id)`.
Columns: `composite_threshold` (shared fallback), `llm_composite_threshold`,
`asi_composite_threshold` (NULL = use shared fallback), `signal_thresholds` JSONB
(map of `signal_id → threshold` overrides). Absent entries fall back to platform
defaults in `SIGNAL_ALERT_THRESHOLDS_V3`.

### `session_actions`

Audit trail for online hard actions taken during live agent sessions. One row per
fired sub-check action of type `sanitize`, `block_call`, or `terminate_session`.
`monitor` and `alert` actions produce a `security_findings` row only — no action row.

Key columns: `session_id`, `tenant_id`, `agent_id`, `sub_check_id`, `owasp_signal_id`,
`severity`, `action_taken`, `triggered_at`.

---

## OWASP LLM Top 10 coverage

| Signal | Threat | Key sub-checks | Status |
|--------|--------|---------------|--------|
| OW-LLM01 | Prompt injection | PI-01a/b, PI-02a, PI-04b, PI-05a/06a/07a/08a/09a | Active |
| OW-LLM02 | Sensitive info disclosure | SID-01a/c, SID-02a/b/c, SID-03a (cross-session) | Active |
| OW-LLM03 | Training data poisoning | — | Excluded (not detectable at inference time) |
| OW-LLM04 | Data & model poisoning | DMP-01a/c | Excluded (pre-runtime) |
| OW-LLM05 | Insecure output handling | IOH-01a/b/c, IOH-02a, IOH-03a, IOH-04a | Active |
| OW-LLM06 | Excessive agency | EA-01a/b/c, EA-02a/b/c, EA-03a/b | Active |
| OW-LLM07 | System prompt leakage | SPL-01a/b, SPL-02a/b, SPL-03a/b | Active |
| OW-LLM08 | Vector & embedding weakness | VEW-01a/b, VEW-02a/b | VEW-01b/02a excluded (pre-runtime) |
| OW-LLM09 | Misinformation / overreliance | MIS-01a/b, MIS-02a, MIS-03a, SAG-02a/03a | Active |
| OW-LLM10 | Unbounded consumption | UBC-01a/b, UBC-02a/b, UBC-03a, UBC-04a, UBC-05a | Active |

## OWASP Agentic AI (ASI) Top 10 coverage

| Signal | Threat | Key sub-checks | Status |
|--------|--------|---------------|--------|
| OW-ASI01 | Agent goal hijacking | AGH-01a/b, AGH-02a, AGH-03a, AGH-04a | Active |
| OW-ASI02 | Tool misuse & exploitation | TME-01a..03b, TME-04a..08a | Active |
| OW-ASI03 | Identity & privilege abuse | IPA-01a..03b, IPA-04a/05a | Active |
| OW-ASI04 | Agentic supply chain | ASCV-01a..03b, ASCV-04a/05a | Active |
| OW-ASI05 | Unexpected code execution | RCE-01a..03b, RCE-04a..08a | Active |
| OW-ASI06 | Memory & context poisoning | MCP-01a/b, MCP-02a..05a | Active |
| OW-ASI07 | Insecure inter-agent comms | IAC-01a/b, IAC-02a..06a | Active |
| OW-ASI08 | Cascading failures | CF-01a/b, CF-02a..04a | Active |
| OW-ASI09 | Human-agent trust exploitation | HAT-01a/b, HAT-02a..05a | Active |
| OW-ASI10 | Rogue agents | RA-01a/b, RA-02a..05a | Active |

---

## v3 Scoring model

### Confidence tiers

Each sub-check has a `confidence_tier` that scales its effective score:

| Tier | Weight | Meaning |
|------|--------|---------| 
| `deterministic` | 1.0 | Regex / exact match — always fires correctly |
| `high` | 0.9 | Strong heuristic |
| `medium` | 0.7 | Statistical / ML pattern |
| `low` | 0.5 | Weak signal, context-dependent |
| `skeletal` | 0.3 | Placeholder — minimal detection logic |

### Per-signal score
`effective_score = max(check_score × confidence_weight)` across all fired sub-checks for that signal.

### Composite score
```
composite = highest_signal_effective_score × 0.6 + mean(remaining) × 0.4
composite = min(100, int(composite × attack_chain_amplification))
```
Computed separately for LLM (OW-LLM*) and ASI (OW-ASI*) frameworks.

### Attack chain amplification

7 chains are defined. When all signals in a chain fire, composite is amplified.
Amplification is `max(matching chains)` — never multiplicative.

| Chain | Signals | Amplification |
|-------|---------|---------------|
| `indirect_injection_to_exfil` | OW-LLM01 + OW-ASI02 + OW-LLM02 | 1.25× |
| `goal_hijack_to_rce` | OW-ASI01 + OW-ASI05 | 1.30× |
| `supply_chain_to_backdoor` | OW-ASI04 + OW-ASI05 + OW-ASI10 | 1.35× |
| `memory_poison_to_exfil` | OW-ASI06 + OW-ASI01 + OW-LLM02 | 1.25× |
| `privilege_escalation_chain` | OW-ASI03 + OW-ASI02 + OW-LLM06 | 1.20× |
| `trust_exploitation_to_fraud` | OW-ASI09 + OW-ASI01 + OW-LLM05 | 1.25× |
| `cascading_failure_chain` | OW-ASI08 + OW-ASI07 + OW-ASI10 | 1.30× |

### Risk bands (v3)

| Band | Score range |
|------|-------------|
| clean | 0–14 |
| low | 15–34 |
| medium | 35–59 |
| high | 60–84 |
| critical | 85–100 |

### Trust scoring

Bayesian Beta(α=2, β=8) prior gives new agents a starting trust of ~80%.
After each session: α += clean events, β += risky events.
Temporal decay: λ=0.05/day (older sessions contribute less).
Trend detection: linear regression on last 20 sessions → `improving` / `stable` / `degrading`.

### Alert thresholds
Alert fires when:
- Any individual signal score >= per-signal `alert_threshold` from `AgentSecurityConfig` (platform default in `SIGNAL_ALERT_THRESHOLDS_V3`), OR
- LLM composite >= `llm_composite_alert_threshold` (default 60), OR ASI composite >= `asi_composite_alert_threshold` (default 60), OR
- Agent `trust_score` < `AGENT_TRUST_ALERT_THRESHOLD` (50) for `AGENT_TRUST_CONSECUTIVE_SESSIONS` (3) consecutive sessions

Thresholds are configurable per-agent via `agent_alert_config` (Postgres) + Redis cache.

### Overlap dedup groups (v3)

| Group | Signals |
|-------|---------|
| injection | OW-LLM01, OW-ASI01, OW-ASI06 |
| output_exec | OW-LLM05, OW-ASI05, OW-ASI02 |
| supply_chain | OW-LLM03, OW-ASI04 |
| memory_vector | OW-LLM08, OW-ASI06 |
| excessive_agency | OW-LLM06, OW-ASI02, OW-ASI10 |
| pii_privilege | OW-LLM02, OW-ASI03 |
| trust_fraud | OW-ASI09, OW-ASI01 |
| cascade_rogue | OW-ASI08, OW-ASI10, OW-ASI07 |

---

## Redis key namespace

| Key pattern | Owner | TTL |
|-------------|-------|-----|
| `dp:sec:sigs:{tenant_id}` | `detectors/injection.py` | 300s |
| `dp:sec:defaults` | `core/security_config.py` | no expiry |
| `dp:sec:{tenant_id}:overrides` | `core/security_config.py` | no expiry (reserved) |
| `dp:sec:{tenant_id}:agent:{agent_id}:overrides` | `core/security_config.py` | no expiry (reserved) |
| `dp:sec:{tenant_id}:agent:{agent_id}:cfg` | `core/security_config.py` | 300s |

---

## Alert format on obs.alerts.v1

```json
{
  "alert_id":      "<uuid4>",
  "tenant_id":     "<uuid>",
  "session_id":    "<uuid>",
  "rule_id":       "00000000-0000-0000-0000-000000000001",
  "rule_name":     "Security Risk Score",
  "severity":      "warning",
  "triggered_at":  "<ISO 8601 UTC>",
  "dedup_key":     "security:<session_id>",
  "channels":      [],
  "payload": {
    "title":               "Security Risk: High (72/100)",
    "message":             "LLM: 3 signals fired · Agent: 2 signals fired",
    "rule_type":           "security_risk",
    "source":              "security",
    "agent_id":            "<uuid>",
    "llm_score":           72,
    "llm_band":            "high",
    "asi_score":           45,
    "asi_band":            "medium",
    "trust_score":         61,
    "trust_trend":         "degrading",
    "attack_chains_detected": ["indirect_injection_to_exfil"],
    "amplification":       1.25,
    "confidence_band":     "high",
    "signal_taxonomy_version": "3.0",
    "llm_signal_status": {
      "OW-LLM01": { "score": 85, "effective_score": 77, "status": "fired", "sub_checks": { "PI-01a": { ... } } }
    },
    "asi_signal_status": { ... },
    "top_findings": [
      { "owasp_signal_id": "OW-LLM01", "sub_check_id": "PI-01a", "check_score": 85, "confidence_tier": "high", ... }
    ],
    "summary": {
      "llm_signals_fired": 3,
      "llm_signals_clean": 7,
      "asi_signals_fired": 2,
      "asi_signals_clean": 8,
      "online_actioned_count": 1
    },
    "scorer_version": "3.0.0"
  }
}
```

A second alert type (`rule_id: ...000002`, `rule_name: "Online Security Detection"`) is produced
at session end to summarise all SDK online detections in one message, rather than one per sub-check.

---

## Dead letter queue (DLQ)

If the consumer fails to process an event, the raw message is forwarded to
`obs.dlq.v1` with metadata and the offset is committed so the consumer
doesn't stall. `obs.dlq.v1` is owned by `dapplepot_pipeline`.

---

## Consumer lag health check

```bash
make health                        # checks dp-security-eval lag, exits 1 if > 10,000
make health ARGS="--max-lag 5000"  # custom threshold
```

---

## Tests

```bash
make test-unit          # no infra (~150+ tests: detectors, v3 scoring, attack chains, trust, cross-session, registry)
make test-integration   # requires docker compose up from dapplepot_pipeline
make test               # all
```

Unit tests cover all detectors (no infra), v3 scoring model (confidence weighting, composites,
attack chain amplification), Bayesian trust, cross-session signals, and the full signal registry.
Integration tests run end-to-end session scenarios with mocked ClickHouse events.

---

## For IDE agents

Read `agent.md` in full before writing any code. It contains:
- Full algorithm implementations for all online detectors
- Post-session scorer orchestration with exact SQL
- All OW-LLM and OW-ASI signal function signatures and logic
- v3 scoring model: confidence weighting, attack chains, composite formula, trust scoring
- Complete Postgres DDL for all tables (including v3 migrations 013–021)
- Signal taxonomy: all 156 sub-check IDs, scores, severities, confidence tiers
- Exact env variables and Redis key patterns
