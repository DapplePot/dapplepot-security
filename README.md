# dapplepot_security

**Dapplepot — Security Engine**

Zone 6 of the Dapplepot observability platform. A standalone Python service
that runs OWASP LLM Top 10 **and** OWASP Agentic AI (ASI) Top 10 detection
against LangGraph agent sessions — prompt injection, output passthrough, PII
disclosure, agentic threat patterns, and post-session risk scoring for both
LLM and agent dimensions.

**Language: Python 3.12**

---

## What this service does

```
Kafka obs.events.v1  (same topic as dapplepot_pipeline, separate consumer group)
  └── dp-security-eval (30 workers)
        │
        └── On graph_end / graph_error — post-session scorer (async)
              │
              ├── Per-event detectors — replays session events from ClickHouse in order
              │     ├── llm_start   → injection.py      (OW-LLM01: PI-01a, PI-01b, PI-02a)
              │     │               → agentic.py        (OW-ASI06: MCP-01a context injection)
              │     ├── llm_end     → disclosure.py     (OW-LLM02: SID-01a/c, SID-02a/b/c)
              │     │               → prompt_guard.py   (OW-LLM07: SPL-01a/b)
              │     ├── tool_start  → passthrough.py    (OW-LLM05: IOH-01a/b/c, IOH-02a)
              │     │               → agentic.py        (OW-ASI02: TME-01a, TME-03b)
              │     │               →                   (OW-ASI05: RCE-01b, RCE-03a, RCE-03b)
              │     └── tool_end    → disclosure.py     (OW-LLM02: PII patterns)
              │
              ├── LLM signals (OWASP LLM Top 10) — llm_signals.py
              │     ├── OW-LLM01: multi-turn jailbreak accumulation (PI-04b)
              │     ├── OW-LLM04: RAG integrity (DMP-01a, DMP-01c)
              │     ├── OW-LLM06: excessive tool calls vs baseline (EAG-01a)
              │     ├── OW-LLM06: out-of-scope tool invocations (EAG-02a)
              │     ├── OW-LLM06: write action on read-intent session (EAG-03a)
              │     ├── OW-LLM09: high-stakes action without HITL (SAG-01a)
              │     └── OW-LLM10: token spike / cross-session probe (UBC-01a, UBC-04a)
              │
              ├── ASI signals (OWASP Agentic AI Top 10) — asi_signals.py
              │     ├── OW-ASI01: agent goal hijacking
              │     ├── OW-ASI03: identity & privilege abuse
              │     ├── OW-ASI04: agentic supply chain vulnerability
              │     ├── OW-ASI07: insecure inter-agent communication
              │     ├── OW-ASI08: cascading failures
              │     ├── OW-ASI09: human-agent trust exploitation
              │     └── OW-ASI10: rogue agent (tool usage anomaly)
              │
              └── Scoring — orchestrator.py
                    LLM composite score  0–100 → session_risk_scores.risk_score
                    ASI composite score  0–100 → session_risk_scores.agent_risk_score
                    Alert fires when any signal >= per-signal threshold
                    OR either composite >= COMPOSITE_ALERT_THRESHOLD (65)
```

## Signal taxonomy

All signals use canonical OWASP identifiers: `OW-LLM01..OW-LLM10` and `OW-ASI01..OW-ASI10`.
Each signal has named sub-checks (e.g. `PI-01a`, `SID-02b`, `RCE-03a`) with individual
`check_score` (0–100). The parent signal score is `max(check_score)` of all fired sub-checks.

The full sub-check registry (121 entries) is stored in the `signal_registry` table
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

The consumer only watches for `graph_end`/`graph_error`. All detection runs post-session
by replaying ClickHouse events through the detectors in sequence.

| `event_type` | Payload fields consumed (post-session replay) | What runs |
|---|---|---|
| `llm_start` | `payload.messages[].role`, `payload.messages[].content` | Prompt injection (PI-01a/b, PI-02a); context injection (MCP-01a) |
| `llm_end` | `payload.completion` | PII scanner (SID-*); system prompt leakage (SPL-01a/b) |
| `tool_start` | `payload.tool_input`, `payload.tool_name` | Output passthrough (IOH-*); tool misuse (TME-01a, TME-03b); code execution (RCE-01b, RCE-03a/b) |
| `tool_end` | `payload.tool_output` | PII scanner |
| `graph_end` | (envelope only) | Triggers async `score_session()` |
| `graph_error` | (envelope only) | Same as `graph_end` |
| everything else | — | Consumed and committed, no detection |

### Postgres `sessions` table — queried during post-session scoring

| Column | Used by |
|---|---|
| `initial_input` | Write-on-read-intent detection (EAG-03a) |
| `graph_state` | HITL gap detection (SAG-01a) — checks `hitl_enabled` flag |
| `graph_runs` | Available for scoring context |
| `duration_ms` | Available for scoring context |

### ClickHouse `obs_events` table — queried during post-session scoring

| Column | Used by |
|---|---|
| `event_type` | All signals — filter to relevant event types |
| `tool_name` | EAG-01a (count), EAG-02a (scope), EAG-03a (write pattern), SAG-01a (high-stakes) |
| `llm_input_tokens`, `llm_output_tokens` | UBC-01a (token spike) |
| `payload` | UBC-04a (cross-session cohort, extracts `user_context_id`) |
| `emitted_at` | 7-day baseline windows for EAG-01a and UBC-01a |

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
│       ├── consumer.py             ← Kafka poll loop; triggers score_session on graph_end/graph_error
│       ├── findings.py             ← Finding dataclass, PG batch writer, alert producer
│       ├── detectors/              ← per-event detectors (replayed post-session from ClickHouse)
│       │   ├── injection.py        ← OW-LLM01: PI-01a, PI-01b, PI-02a
│       │   ├── disclosure.py       ← OW-LLM02: SID-01a/c, SID-02a/b/c
│       │   ├── passthrough.py      ← OW-LLM05: IOH-01a/b/c, IOH-02a (LCS passthrough)
│       │   ├── agentic.py          ← OW-ASI02/05/06: TME-01a, RCE-01b/03a/03b, MCP-01a
│       │   └── prompt_guard.py     ← OW-LLM07: SPL-01a (prefix similarity), SPL-01b (probe)
│       └── scorer/
│           ├── orchestrator.py     ← score_session(): replays events, runs all signals, writes DB, fires alerts
│           ├── llm_signals.py      ← OW-LLM01..10 post-session signal functions + sub-check helpers
│           ├── asi_signals.py      ← OW-ASI01..10 post-session signal functions
│           └── probe.py            ← OW-LLM10 cross-session model theft probe (UBC-04a)
│
├── core/
│   ├── config.py                   ← pydantic-settings: Kafka, PG, CH, Redis, thresholds
│   └── infra/
│       ├── kafka.py
│       ├── postgres.py
│       ├── clickhouse.py
│       └── redis.py
│
├── db/
│   └── postgres/
│       ├── 001_security_findings.sql       ← security_findings table
│       ├── 002_session_risk_scores.sql     ← session_risk_scores table
│       ├── 003_injection_signatures.sql    ← injection_signatures table
│       ├── 004_indexes.sql
│       ├── 005_agent_security_schema.sql   ← owasp_framework column + agent_risk_scores
│       ├── 006_reporting_views.sql
│       ├── 007_signal_status.sql           ← llm_signal_status / agent_signal_status columns
│       ├── 008_agent_profile_views.sql
│       ├── 009_drop_session_fk.sql         ← drops sessions FK (race condition fix)
│       ├── 010_signal_id_upgrade.sql       ← adds owasp_signal_id, sub_check_id, check_score, check_label
│       ├── 011_signal_status_upgrade.sql   ← adds ow_llm_signal_status / ow_asi_signal_status JSONB
│       └── 012_signal_registry.sql         ← signal_registry table (all 121 sub-checks)
│
├── tests/
│   ├── unit/
│   │   ├── test_prompt_injection.py        ← OW-LLM01 injection detector
│   │   ├── test_data_disclosure.py         ← OW-LLM02 disclosure detector
│   │   ├── test_output_handling.py         ← OW-LLM05 passthrough detector
│   │   ├── test_agentic_threats.py         ← OW-ASI02/05/06 agentic detectors
│   │   ├── test_llm_signals.py             ← OW-LLM01..10 post-session signals
│   │   ├── test_asi_signals.py             ← OW-ASI01..10 post-session signals
│   │   ├── test_scoring.py                 ← v2 scoring model (max sub-check, composite)
│   │   └── test_signal_registry.py         ← REGISTRY coverage (no DB required)
│   └── integration/
│       ├── test_detectors.py               ← detector scenarios against Postgres
│       └── test_post_session_scorer.py     ← end-to-end scorer with mocked ClickHouse events
│
└── scripts/
    ├── run_migrations.py           ← runs db/postgres/ in order
    ├── seed_signatures.py          ← seeds injection_signatures for dapplepot_dev tenant
    ├── seed_signal_registry.py     ← upserts all 121 sub-checks into signal_registry
    ├── seed_dev_scores.py          ← backfills security_findings + session_risk_scores for dev sessions
    └── health_check.py             ← consumer lag check (make health)
```

---

## Prerequisites

- Python 3.12+
- uv
- `dapplepot_pipeline` cloned with `docker compose up -d` running
  (shares Kafka, Postgres, ClickHouse, Redis)

> **Windows:** `make run` works on Windows — signal handling uses `signal.signal` instead of
> `loop.add_signal_handler` (which is Unix-only).

---

## Setup

```bash
git clone https://github.com/dapplepot/dapplepot_security
cd dapplepot_security

uv sync
cp .env.example .env

make setup          # migrations 001-012 + seed-sigs + seed-signal-registry + seed-dev-scores
make run            # starts dp-security-eval Kafka consumer
```

---

## Postgres tables this service owns

### `security_findings`

One row per detected sub-check per event. Written entirely by the post-session scorer
(per-event detectors are replayed from ClickHouse; session-level signals run once).

Key columns: `session_id`, `event_id`, `signal_id` (`OW-LLM01:PI-01a` format),
`owasp_signal_id` (`OW-LLM01`), `sub_check_id` (`PI-01a`), `check_label`,
`check_score` (0–100), `sig_type`, `owasp_framework` (LLM | ASI), `severity`,
`matched_text` (always redacted), `detection_phase` (online | post_session).

### `session_risk_scores`

One row per session. Written by the post-session scorer. `ON CONFLICT DO UPDATE`.

Key columns: `session_id`, `risk_score` (0–100 LLM composite), `risk_band`,
`agent_risk_score` (0–100 ASI composite), `agent_risk_band`,
`ow_llm_signal_status` (JSONB — per OW-LLM signal with sub-checks and scores),
`ow_asi_signal_status` (JSONB — per OW-ASI signal with sub-checks and scores),
`llm_signal_status`, `agent_signal_status` (legacy JSONB, backward compat),
`scorer_version`.

### `agent_risk_scores`

One row per agent. Rolling aggregate updated after every session scoring.

Key columns: `agent_id`, `session_count`, `avg_llm_score`, `avg_agent_score`,
`max_llm_score`, `max_agent_score`, `last_scored_at`.

### `signal_registry`

One row per sub-check (121 total). Seeded by `scripts/seed_signal_registry.py`.

Key columns: `owasp_signal_id`, `sub_check_id` (PK), `label`, `owasp_category`,
`owasp_number`, `detection_phase`, `check_score`, `severity`, `excluded`,
`exclusion_reason`.

### `injection_signatures`

Tenant-specific injection detection patterns. Cached in Redis at
`dp:sec:sigs:{tenant_id}`, TTL 300s.

---

## OWASP LLM Top 10 coverage

| Signal | Threat | Sub-checks | Detection phase |
|--------|--------|-----------|-----------------|
| OW-LLM01 | Prompt injection | PI-01a/b, PI-02a, PI-04b | Post-session |
| OW-LLM02 | Sensitive info disclosure (PII) | SID-01a/c, SID-02a/b/c | Post-session |
| OW-LLM03 | Training data poisoning | — | Excluded (not detectable at inference time) |
| OW-LLM04 | Model denial of service | DMP-01a/c | Post-session |
| OW-LLM05 | Insecure output handling | IOH-01a/b/c, IOH-02a | Post-session |
| OW-LLM06 | Excessive agency | EAG-01a, EAG-02a, EAG-03a | Post-session |
| OW-LLM07 | System prompt leakage | SPL-01a/b, SPL-02a/b, SPL-03b | Post-session |
| OW-LLM08 | Vector / embedding weakness | VEW-01b, VEW-02a | Post-session |
| OW-LLM09 | Misinformation / overreliance | SAG-01a | Post-session |
| OW-LLM10 | Model theft / unbounded consumption | UBC-01a, UBC-04a | Post-session |

## OWASP Agentic AI (ASI) Top 10 coverage

| Signal | Threat | Sub-checks | Detection phase |
|--------|--------|-----------|-----------------|
| OW-ASI01 | Agent goal hijacking | AGH-01b | Post-session |
| OW-ASI02 | Tool misuse & exploitation | TME-01a, TME-03b | Post-session |
| OW-ASI03 | Identity & privilege abuse | IPA-01a | Post-session |
| OW-ASI04 | Agentic supply chain | ASCV-01a | Post-session |
| OW-ASI05 | Unexpected code execution | RCE-01b, RCE-03a, RCE-03b | Post-session |
| OW-ASI06 | Memory & context poisoning | MCP-01a | Post-session |
| OW-ASI07 | Insecure inter-agent comms | IAC-01a | Post-session |
| OW-ASI08 | Cascading failures | CF-01a | Post-session |
| OW-ASI09 | Human-agent trust exploitation | HAT-01a | Post-session |
| OW-ASI10 | Rogue agents | RA-01a | Post-session |

---

## v2 Scoring model

### Per-signal score
Parent signal score = `max(check_score)` across all fired sub-checks. Not additive.

### Composite score
```
composite = highest_signal_score × 0.6 + mean(remaining_signal_scores) × 0.4
```
Computed separately for LLM (OW-LLM*) and ASI (OW-ASI*) frameworks.

### Alert thresholds
Alert fires when:
- Any individual signal score >= `SIGNAL_ALERT_THRESHOLDS[signal_id]` (per-signal), OR
- Either composite score >= `COMPOSITE_ALERT_THRESHOLD` (default 65)

### Risk bands

| Band | Score range | Action |
|------|-------------|--------|
| clean | 0–19 | Logged only |
| low | 20–39 | Logged only |
| medium | 40–64 | Warning alert (platform inbox) |
| high | 65–84 | Alert → tenant notification channels |
| critical | 85–100 | Alert → tenant notification channels |

### Overlap dedup groups
When multiple related signals fire together, a shared `dedup_key` suffix is set
to prevent duplicate alerts for the same threat cluster:

| Group | Signals |
|-------|---------|
| injection | OW-LLM01, OW-ASI01, OW-ASI06 |
| output_exec | OW-LLM05, OW-ASI05, OW-ASI02 |
| supply_chain | OW-LLM03, OW-ASI04 |
| memory_vector | OW-LLM08, OW-ASI06 |
| excessive_agency | OW-LLM06, OW-ASI02, OW-ASI10 |
| pii_privilege | OW-LLM02, OW-ASI03 |

---

## Redis key namespace

| Key pattern | Owner | TTL |
|-------------|-------|-----|
| `dp:sec:sigs:{tenant_id}` | `detectors/injection.py` | 300s |

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
  "channel_config": {},
  "payload": {
    "title":               "Security Risk: High (72/100)",
    "message":             "LLM: 3 signals fired · Agent: 1 signals fired",
    "rule_type":           "security_risk",
    "source":              "security",
    "agent_id":            "<uuid>",
    "risk_score":          72,
    "risk_band":           "high",
    "agent_risk_score":    15,
    "agent_risk_band":     "low",
    "signal_taxonomy_version": "2.0",
    "ow_llm_signal_status": {
      "OW-LLM01": { "score": 85, "status": "fired", "sub_checks": { "PI-01a": { ... } } }
    },
    "ow_asi_signal_status": { ... },
    "top_findings": [
      { "owasp_signal_id": "OW-LLM01", "sub_check_id": "PI-01a", "check_score": 85, ... }
    ],
    "summary": { "llm_signals_fired": 3, "llm_signals_clean": 7, "agent_signals_fired": 1, "agent_signals_clean": 9 },
    "scorer_version": "2.0.0"
  }
}
```

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

## Full platform startup sequence

```
Step 1  cd dapplepot_pipeline && docker compose up -d
Step 2  cd dapplepot_pipeline && make setup        # topics + PG migrations + ClickHouse
Step 2b cd dapplepot_pipeline && make seed-dev     # tenant · agent · sdk_key · sessions
Step 3  cd dapplepot_security && make setup        # PG migrations 001-012 + seed-sigs + seed-scores
Step 4  cd dapplepot_pipeline && make run-ingest   # + run-session-writer + run-event-appender
                                                   # + run-policy-evaluator + run-alert-router
Step 5  cd dapplepot_security && make run          # dp-security-eval
Step 6  cd dapplepot_api      && <setup>
Step 7  cd dapplepot_ui       && pnpm dev
```

---

## Tests

```bash
make test-unit          # no infra (detectors + scoring model + signal registry)
make test-integration   # requires docker compose up from dapplepot_pipeline
make test               # all
```

Unit tests cover all detectors (no infra required), the v2 scoring model, and
the full signal registry. Integration tests run end-to-end session scenarios
against Postgres with mocked ClickHouse events.

---

## For IDE agents

Read `agent.md` in full before writing any code. It contains:
- Full algorithm implementations for all online detectors
- Post-session scorer orchestration with exact SQL
- All OW-LLM and OW-ASI signal function signatures and logic
- Complete Postgres DDL for all tables
- v2 scoring model spec (max sub-check, composite formula, alert thresholds)
- Signal taxonomy: all sub-check IDs, scores, severities
- Exact env variables and Redis key patterns
