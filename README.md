# dapplepot_security

**Dapplepot — Security Engine**

Zone 6 of the Dapplepot observability platform. A standalone Python service
that runs OWASP LLM Top 10 detection against LangGraph agent sessions —
prompt injection, output passthrough, PII disclosure, and post-session
risk scoring.

**Language: Python 3.12**

---

## What this service does

```
Kafka obs.events.v1  (same topic as dapplepot_pipeline, separate consumer group)
  └── dp-security-eval (30 workers)
        │
        ├── ONLINE (per event, real-time)
        │     ├── llm_start   → injection detector (regex + blocklist)
        │     ├── llm_end     → PII second-pass scanner
        │     ├── tool_start  → output passthrough detector
        │     └── tool_end    → PII second-pass scanner
        │
        └── POST-SESSION (after graph_end / graph_error arrives)
              ├── S-05: excessive tool calls vs baseline
              ├── S-06: out-of-scope tool invocations
              ├── S-07: write actions on read-intent sessions
              ├── S-08: high-stakes action without HITL
              ├── S-09: cross-session model theft probe
              └── S-10: token spike anomaly
                    ↓
              risk_score 0–100 → written to Postgres
              score ≥ 65       → alert produced to obs.alerts.v1
```

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

## Do other repos need changes?

**`dapplepot_pipeline`** — no changes. This service reads from the same
Kafka topic independently. The pipeline is completely unaware security exists.
Note: `dp-alert-router` (in pipeline) must be able to parse alerts from this
service — the alert format includes `source: "security"` so the router can
identify and route them correctly.

**`dapplepot_api`** — additive only. 5 new files + 2 line edits:
- `src/types/security.ts` — TypeScript types: `RiskBand`, `SessionRiskScore`, `SecurityFinding`, `SecurityOverview`, `RemediationCard`
- `src/types/index.ts` — one line: `export * from './security.js'`
- `src/queries/security.pg.ts` — read queries for findings + scores
- `src/routes/security.ts` — 5 new endpoints (see agent.md §12)
- `src/routes/index.ts` — one line: `app.route('/v1/security', securityRouter)`
- `src/lib/cache.ts` — 3 new TTL constants: `CACHE_TTL_SECURITY_OVERVIEW=120`, `CACHE_TTL_SESSION_SCORE=300`, `CACHE_TTL_REMEDIATION=300`

**`dapplepot_ui`** — additive only. 2 new files:
- `src/api/security.ts` — API client functions
- `src/hooks/useSecurity.ts` — TanStack Query hooks (`staleTime: 120_000` for overview, `300_000` for scores)
  (Security surface was already designed in `dapplepot_ui/agent.md`)

**`dapplepot_langgraph`** and **`dapplepot_sim`** — no changes.

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
│       ├── consumer.py             ← Kafka poll loop, routes events
│       ├── redis_ctx.py            ← session context: last LLM output per node_run_id
│       ├── findings.py             ← Finding builder, PG batch writer, alert producer
│       ├── online/
│       │   ├── injection.py        ← INJ-001 through INJ-005
│       │   ├── passthrough.py      ← LCS ratio diff
│       │   └── pii.py              ← PII-001 through PII-006
│       └── scorer/
│           ├── post_session.py     ← orchestrates all 10 signals
│           ├── signals.py          ← S-01 through S-10 pure functions
│           └── cohort.py           ← S-09 cross-session probe
│
├── core/
│   ├── config.py
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
│       ├── 003_injection_signatures.sql
│       └── 004_indexes.sql
│
├── tests/
│   ├── unit/                       ← no infra needed
│   └── integration/                ← requires docker compose from dapplepot_pipeline
│
└── scripts/
    ├── run_migrations.py
    ├── seed_signatures.py          ← seeds injection_signatures for dapplepot_dev tenant;
    │                                  fixed sig_ids (SIG_INJ001–SIG_INJ005) aligned with
    │                                  pipeline seed_dev.py; blocklist sig_ids via uuid5
    ├── seed_scores.py              ← backfills security_findings + session_risk_scores for
    │                                  the 5 seeded sessions by running the post-session scorer
    │                                  directly against ClickHouse (no Kafka required)
    └── health_check.py             ← dp-security-eval consumer lag check (make health)
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

make setup          # migrate + seed-sigs + seed-scores (Step 3 of platform startup)
make run            # starts dp-security-eval Kafka consumer
```

---

## The three Postgres tables this service owns

All three tables live in the same Postgres database as `dapplepot_pipeline`
(`dapplepot_pipeline` DB). They reference `sessions.session_id` via foreign key.

### `security_findings`

One row per detected signal per event. Written by both online detectors
(during session) and post-session scorer (after `session_end`).

Key columns: `session_id`, `event_id`, `signal_id` (INJ-001, PII-004, S-06…),
`owasp_id` (LLM01…LLM10), `severity`, `matched_text` (always redacted),
`score_contrib`, `detection_phase` (online | post_session).

### `session_risk_scores`

One row per session. Written by the post-session scorer within ~30 seconds
of `session_end`. `ON CONFLICT DO UPDATE` — safe to re-run.

Key columns: `session_id`, `risk_score` (0–100), `risk_band`
(clean/low/medium/high/critical), `signal_ids[]`, `scorer_version`.

### `injection_signatures`

Tenant-specific injection detection patterns.
Seeded with jailbreak strings for the `dapplepot_dev` tenant by `scripts/seed_signatures.py`.
Cached in Redis at `dp:sec:sigs:{tenant_id}`, TTL 300s.

---

## OWASP LLM Top 10 coverage

| ID | Threat | Coverage | Detection |
|----|--------|----------|-----------|
| LLM01 | Prompt injection | Full | Online — injection.py |
| LLM02 | Insecure output handling | Full | Online — passthrough.py |
| LLM03 | Training data poisoning | Blind spot | Not detectable at inference time |
| LLM04 | Model denial of service | Full | Post-session — S-10 token spike |
| LLM05 | Supply chain vulnerabilities | Blind spot | Runtime telemetry cannot detect |
| LLM06 | Sensitive info disclosure | Partial | Online — pii.py |
| LLM07 | Insecure plugin design | Partial | Post-session — S-06 tool scope |
| LLM08 | Excessive agency | Full | Post-session — S-05, S-06, S-07 |
| LLM09 | Overreliance | Partial | Post-session — S-08 HITL gap |
| LLM10 | Model theft | Partial | Post-session — S-09 cohort probe |

---

## Risk score model

10 signals, each with a point cap. Points are additive. Total hard-capped at 100.

| Signal | Max pts | Trigger |
|--------|---------|---------|
| S-01 | 40 | Confirmed injection (INJ-001/002) |
| S-02 | 20 | Indirect injection vector (INJ-004) |
| S-03 | 30 | Output passthrough to tool (OUT-001) |
| S-04 | 35 | PII in LLM or tool output |
| S-05 | 20 | Tool call count > p90 baseline for agent |
| S-06 | 25 | Tool invoked outside agent's declared manifest |
| S-07 | 30 | Write/delete tool used when intent was read-only |
| S-08 | 15 | High-stakes action completed without HITL interrupt |
| S-09 | 10 | Cross-session model theft probe pattern |
| S-10 | 10 | Token count > 4σ above agent baseline |

| Band | Score | Action |
|------|-------|--------|
| Clean | 0–19 | Logged only |
| Low | 20–39 | Logged only |
| Medium | 40–64 | Warning alert (platform inbox) |
| High | 65–84 | Critical alert → webhook / Slack / PD |
| Critical | 85–100 | Critical alert → all channels |

---

## Redis key namespace

This service uses the `dp:sec:*` prefix exclusively. No overlap with
`dapplepot_pipeline` which uses `dp:rules:*`.

| Key pattern | Owner | TTL |
|-------------|-------|-----|
| `dp:sec:sigs:{tenant_id}` | injection.py | `SIG_CACHE_TTL_S` (300s) |
| `dp:sec:llm_out:{session_id}:{node_run_id}` | redis_ctx.py | `SESSION_CTX_TTL_S` (120s) |
| `dp:sec:tool_out:{session_id}:{node_run_id}` | redis_ctx.py | `SESSION_CTX_TTL_S` (120s) |

---

## Alert format on obs.alerts.v1

When `risk_score >= ALERT_ON_SCORE_GTE` (default 65), the scorer produces
one message to `obs.alerts.v1`. The schema is designed to match what
`dp-alert-router` (in `dapplepot_pipeline`) expects:

```json
{
  "alert_id": "<uuid4>",
  "alert_type": "security_risk",
  "source": "security",
  "timestamp": "<ISO 8601 UTC>",
  "session_id": "...",
  "tenant_id": "...",
  "agent_id": "...",
  "risk_score": 72,
  "risk_band": "high",
  "signal_ids": ["INJ-001", "S-06"],
  "top_findings": [
    { "signal_id": "INJ-001", "owasp_id": "LLM01", "severity": "critical", "detail": "..." }
  ],
  "scorer_version": "1.0.0"
}
```

Required fields consumed by `dp-alert-router`: `alert_id`, `alert_type`,
`source`, `tenant_id`, `session_id`, `timestamp`.

---

## Dead letter queue (DLQ)

If the consumer fails to process an event (parse error, detector crash,
infra timeout), the raw message is forwarded to `obs.dlq.v1` with metadata:

```json
{
  "source": "dp-security-eval",
  "original_offset": 12345,
  "error": "...",
  "raw": "..."
}
```

The consumer then commits the offset so it doesn't stall on the same
message indefinitely. `obs.dlq.v1` is owned and monitored by
`dapplepot_pipeline`.

---

## Consumer lag health check

```bash
make health                        # checks dp-security-eval lag, exits 1 if > 10,000
make health ARGS="--max-lag 5000"  # custom threshold
```

Intended for use in liveness probes and the platform health check script.

---

## Full platform startup sequence

This service is **Step 3** in the platform startup order. Migrations
must run after `dapplepot_pipeline` migrations (Steps 1–2):

```
Step 1  cd dapplepot_pipeline && docker compose up -d
Step 2  cd dapplepot_pipeline && make setup        # topics + PG migrations 001-007
Step 2b cd dapplepot_pipeline && make seed-dev     # tenant · agent (langgraph_checkout) · sdk_key
                                                   # policy rules (8) · sessions SES_001–SES_005
Step 3  cd dapplepot_security && make setup
Step 4  cd dapplepot_pipeline && make run-ingest   # + other consumers
Step 5  cd dapplepot_security && make run          # this service
Step 6  cd dapplepot_api      && <setup>
Step 7  cd dapplepot_ui       && pnpm dev
```

Foreign key constraint: `security_findings.session_id` references
`sessions.session_id`, so pipeline migrations must complete first.

---

## Tests

```bash
make test-unit          # no infra (pure signal functions + detectors)
make test-integration   # requires docker compose up from dapplepot_pipeline
make test               # all
```

Unit tests cover all signal functions with mock event lists. Integration
tests run the full `inject_prompt` and `pii_in_output` simulation scenarios
and assert that findings land in Postgres with correct fields.

---

## For IDE agents

Read `agent.md` in full before writing any code. It contains:
- Full algorithm implementations for all three online detectors
- Post-session scorer orchestration with exact SQL
- All 10 signal function signatures and computation logic
- Complete Postgres DDL for all 3 new tables
- Build order across 5 phases
- Exact env variables and Redis key patterns
- All 10 locked architecture decisions
