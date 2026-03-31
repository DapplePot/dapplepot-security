# agent.md — dapplepot_security: Full Context for IDE Agent

> Read this file completely before writing any code.
> It contains the full security engine design, every algorithm,
> every schema, the exact repo structure, and the build order.
> Nothing here is aspirational — it is the agreed spec.

---

## 1. Company + product context

**Company:** Dapplepot
**Product:** A production-grade observability and security platform for
LangGraph-based AI agents.

This repository (`dapplepot_security`) is **Zone 6 — Security Engine**.
It is a standalone Python service that:
- Consumes events from the same Kafka topics as `dapplepot_pipeline`
- Runs online security detection on each event in real time
- Runs a post-session risk scorer after each session completes
- Writes findings and risk scores to Postgres tables it owns
- Produces critical findings as alerts to `obs.alerts.v1`

### All Dapplepot repositories

| Zone | Repo | Language | What it is |
|------|------|----------|-----------|
| 1 | `dapplepot_sim` | Python | Simulation agent |
| 2 | `dapplepot_langgraph` | Python | SDK |
| 3 | `dapplepot_pipeline` | Python | Event ingestion + data pipeline |
| 4 | `dapplepot_api` | TypeScript | Platform API |
| 5 | `dapplepot_ui` | TypeScript / React | Dashboard |
| **6** | **`dapplepot_security`** | **Python** | **This repo — security engine** |

### How this service fits into the system

```
Kafka obs.events.v1
  └── dp-security-eval (this service, 30 workers)
        ├── Online detection (per event, real-time)
        │     ├── Injection detector     → llm_start payloads
        │     ├── Output passthrough     → tool_start vs preceding llm_end
        │     └── PII second-pass        → llm_end + tool_end payloads
        │
        └── On graph_end (or graph_error) event:
              └── Post-session scorer (async, reads from ClickHouse)
                    ├── 10 signals computed → risk_score 0–100
                    ├── Writes to Postgres security_findings + session_risk_scores
                    └── Critical findings → obs.alerts.v1 → alert router → Slack/PD
```

### Service boundaries

- Reads from: Kafka `obs.events.v1`, Postgres (shared DB), ClickHouse (shared DB)
- Writes to: Postgres `security_findings`, `session_risk_scores`, `injection_signatures`
- Produces to: Kafka `obs.alerts.v1` (critical findings only)
- **No HTTP calls to or from `dapplepot_pipeline`**
- **No HTTP calls to or from `dapplepot_api`**
- `dapplepot_api` reads the tables this service writes — they share the same Postgres instance

---

## 2. Repo structure

```
dapplepot_security/
│
├── agent.md                                ← this file
├── README.md
├── docker-compose.yml                      ← only if running standalone; otherwise use
│                                              dapplepot_pipeline's compose (shares all infra)
├── .env.example
├── pyproject.toml                          ← uv-managed, same Python 3.12 as pipeline
├── Makefile
│
├── consumers/
│   └── security_eval/                      ← consumer group: dp-security-eval (30 workers)
│       ├── __init__.py
│       ├── consumer.py                     ← Kafka poll loop, routes each event to detectors
│       ├── redis_ctx.py                    ← session context cache in Redis (last LLM output etc.)
│       ├── findings.py                     ← Finding builder, Postgres batch writer, alert producer
│       │
│       ├── online/                         ← per-event detectors (zero async I/O except Redis ctx)
│       │   ├── __init__.py
│       │   ├── injection.py                ← regex + blocklist detection on llm_start
│       │   ├── passthrough.py              ← LCS ratio diff: llm_end output vs tool_start input
│       │   └── pii.py                      ← second-pass PII scan on llm_end + tool_end
│       │
│       └── scorer/                         ← post-session scorer (reads ClickHouse, writes PG)
│           ├── __init__.py
│           ├── post_session.py             ← orchestrator: fetch events → run signals → write score
│           ├── signals.py                  ← S-01 through S-10 signal functions (pure, testable)
│           └── cohort.py                   ← S-09 cross-session model theft probe
│
├── core/
│   ├── __init__.py
│   ├── config.py                           ← pydantic-settings: Kafka, PG, CH, Redis, flags
│   └── infra/
│       ├── __init__.py
│       ├── kafka.py                        ← confluent-kafka consumer + producer factory
│       ├── postgres.py                     ← asyncpg pool (same pattern as dapplepot_pipeline)
│       ├── clickhouse.py                   ← clickhouse-connect (reads obs_events for scoring)
│       └── redis.py                        ← redis.asyncio pool for session context cache
│
├── db/
│   └── postgres/
│       ├── 001_security_findings.sql       ← security_findings table
│       ├── 002_session_risk_scores.sql     ← session_risk_scores table
│       ├── 003_injection_signatures.sql    ← injection_signatures table
│       └── 004_indexes.sql                 ← all indexes
│
├── tests/
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_injection_detector.py
│   │   ├── test_passthrough_detector.py
│   │   ├── test_pii_detector.py
│   │   └── test_signal_functions.py
│   └── integration/
│       ├── test_online_detection.py
│       └── test_post_session_scorer.py
│
└── scripts/
    ├── run_migrations.py                   ← runs db/postgres/ in order
    ├── seed_signatures.py                  ← seeds injection_signatures table
    └── health_check.py                     ← consumer lag check for dp-security-eval (make health)
```

---

## 3. What the security consumer reads

The security consumer reads from **`obs.events.v1`** — the same Kafka topic
as `dapplepot_pipeline`'s three consumers. It uses a separate consumer group
(`dp-security-eval`) so it maintains its own offset and does not affect pipeline throughput.

Consumer group: `dp-security-eval`
Workers: 30
Source topic: `obs.events.v1`

Unlike the event appender (which processes all 17 event types), the security
consumer only activates full processing on 6 event types. For the rest it
maintains session context but does no detection:

| Event type | Processing |
|-----------|-----------|
| `llm_start` | Injection detector (online) |
| `llm_end` | PII second-pass (online) + store `completion` text in Redis context for passthrough |
| `tool_start` | Passthrough detector (online, compares against Redis context) |
| `tool_end` | PII second-pass (online) + store `tool_output` text in Redis context for indirect injection |
| `graph_end` | Triggers post-session scorer (async job) |
| `graph_error` | Triggers post-session scorer (async job, session exited with error) |
| All others | No action (context state is carried by llm_end/tool_end above) |

---

## 4. Online detection — algorithms

### 4.1 Session context in Redis (`redis_ctx.py`)

The passthrough detector needs to compare tool_start input against the
preceding llm_end output in the same `node_run_id`. This state is stored
in Redis with a 120-second TTL (enough to cover one node's execution).

```python
# Redis key patterns (all prefixed dp:sec:)
dp:sec:llm_out:{session_id}:{node_run_id}   → last llm_end output text (STRING, TTL 120s)
dp:sec:tool_out:{session_id}:{node_run_id}  → last tool_end output text (STRING, TTL 120s)

# On llm_end event — SDK payload field is "completion", not "output":
await redis.setex(
    f"dp:sec:llm_out:{session_id}:{node_run_id}",
    120,
    json.dumps(payload.get("completion", ""))
)

# On tool_end event — SDK payload field is "tool_output", store for indirect injection check:
await redis.setex(
    f"dp:sec:tool_out:{session_id}:{node_run_id}",
    120,
    json.dumps(payload.get("tool_output", ""))
)

# On tool_start event, the passthrough detector reads:
last_llm_out = await redis.get(f"dp:sec:llm_out:{session_id}:{node_run_id}")
```

### 4.2 Injection detector (`online/injection.py`)

Runs on every `llm_start` event. Checks the `messages` array in the payload
against the signature library loaded from Postgres `injection_signatures`
(Redis-cached at `dp:sec:sigs:{tenant_id}`, TTL 300s).

```python
INJECTION_SIGNATURES = [
    # Direct instruction override — INJ-001
    {
        "sig_id":   "INJ-001",
        "sig_type": "regex",
        "severity": "critical",
        "pattern":  r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)",
        "field":    "content",
    },
    # Role-play escape — INJ-002
    {
        "sig_id":   "INJ-002",
        "sig_type": "regex",
        "severity": "critical",
        "pattern":  r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)",
        "field":    "content",
    },
    # Known jailbreak blocklist — INJ-003 (2,400+ strings seeded by scripts/seed_signatures.py)
    {
        "sig_id":   "INJ-003",
        "sig_type": "blocklist",
        "severity": "critical",
        "field":    "content",
    },
    # System prompt injection via user turn — INJ-005
    {
        "sig_id":   "INJ-005",
        "sig_type": "regex",
        "severity": "warning",
        "pattern":  r"(?i)\[system\]|\<system\>|###\s*system",
        "field":    "content",
    },
    # Indirect injection from tool output — INJ-004
    # Handled separately: checks if tool_end output text appears in next llm_start
    # using Redis context. Requires min_overlap_chars=80 AND instruction-like pattern.
    {
        "sig_id":   "INJ-004",
        "sig_type": "indirect",
        "severity": "warning",
        "min_overlap_chars": 80,
    },
]

async def detect_injection(
    event: dict,
    session_ctx: SessionContext,
    signatures: list[dict],
) -> list[Finding]:
    findings = []
    messages = event["payload"].get("messages", [])

    for msg in messages:
        if msg.get("role") not in ("user", "tool"):
            continue
        content = str(msg.get("content", ""))

        for sig in signatures:
            if sig["sig_type"] == "regex":
                if re.search(sig["pattern"], content):
                    findings.append(build_finding(event, sig, matched_text=content[:200]))

            elif sig["sig_type"] == "blocklist":
                hit = blocklist_scan(content, BLOCKLIST_STRINGS)
                if hit:
                    findings.append(build_finding(event, sig, matched_text=hit[:200]))

            elif sig["sig_type"] == "indirect":
                last_tool_out = session_ctx.last_tool_output
                if (last_tool_out
                        and _overlap_chars(content, last_tool_out) >= sig["min_overlap_chars"]
                        and any(re.search(p, content) for p in INSTRUCTION_PATTERNS)):
                    findings.append(build_finding(event, sig, matched_text=content[:200]))

    return findings
```

### 4.3 Output passthrough detector (`online/passthrough.py`)

Runs on every `tool_start` event. Compares the tool input against the last
`llm_end` output stored in Redis context for the same `node_run_id`.

```python
def _lcs_ratio(a: str, b: str) -> float:
    """Longest common substring ratio relative to the shorter string."""
    if not a or not b:
        return 0.0
    # Normalise: strip whitespace, lowercase
    a = re.sub(r'\s+', ' ', a.lower().strip())
    b = re.sub(r'\s+', ' ', b.lower().strip())
    # SequenceMatcher is fast enough for payloads under 4KB
    return SequenceMatcher(None, a, b).ratio()

async def detect_passthrough(
    event: dict,
    session_ctx: SessionContext,
) -> Finding | None:
    # SDK tool_start payload field is "tool_input", not "input"
    tool_input = json.dumps(event["payload"].get("tool_input", {}))
    llm_output = session_ctx.last_llm_output  # from Redis

    if not llm_output:
        return None

    ratio = _lcs_ratio(tool_input, llm_output)

    if ratio >= 0.85:
        severity = "critical"
    elif ratio >= 0.60:
        severity = "warning"
    else:
        return None

    return build_finding(event, {
        "sig_id":   "OUT-001",
        "sig_type": "passthrough",
        "severity": severity,
        "detail":   f"tool_start input {ratio:.0%} similar to preceding llm_end output",
    }, matched_text=tool_input[:300])
```

### 4.4 PII second-pass scanner (`online/pii.py`)

Runs on `llm_end` and `tool_end` events. The SDK's PII scrubber runs
pre-emit (first pass). This is the server-side second pass.

```python
PII_PATTERNS = [
    {"sig_id": "PII-001", "name": "Credit card",
     "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b",
     "severity": "critical"},
    {"sig_id": "PII-002", "name": "US SSN",
     "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b",
     "severity": "critical"},
    {"sig_id": "PII-003", "name": "API key",
     "pattern": r"\b(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})\b",
     "severity": "critical"},
    {"sig_id": "PII-006", "name": "JWT token",
     "pattern": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+",
     "severity": "critical"},
    {"sig_id": "PII-004", "name": "Email address",
     "pattern": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b",
     "severity": "warning"},
    {"sig_id": "PII-005", "name": "Phone (E.164)",
     "pattern": r"\+?1?\s*[-.]?\s*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
     "severity": "warning"},
]

def detect_pii(event: dict) -> list[Finding]:
    # SDK payload fields differ by event type:
    #   llm_end  → "completion"   (NOT "output")
    #   tool_end → "tool_output"  (NOT "output")
    payload = event["payload"]
    if event["event_type"] == "llm_end":
        output_text = json.dumps(payload.get("completion", ""))
    else:  # tool_end
        output_text = json.dumps(payload.get("tool_output", ""))
    findings = []
    for sig in PII_PATTERNS:
        match = re.search(sig["pattern"], output_text)
        if match:
            findings.append(build_finding(event, sig,
                                          matched_text=_redact(match.group(0))))
    return findings

def _redact(matched: str) -> str:
    """Replace middle characters with * for safe storage in finding."""
    if len(matched) <= 4:
        return "****"
    return matched[:2] + "*" * (len(matched) - 4) + matched[-2:]
```

---

## 5. Post-session scorer (`scorer/post_session.py`)

Triggered when the consumer processes a `graph_end` or `graph_error` event.
Runs as an async task — does not block the Kafka poll loop.
(`session_end` does not exist in the SDK event schema; `graph_end` is the correct terminal event.)

```python
async def score_session(
    tenant_id: str,
    session_id: str,
    agent_id: str,
    online_findings: list[Finding],  # findings already emitted by online detectors this session
) -> SessionRiskScore:
    """
    1. Fetch full event list for session from ClickHouse (obs_events, bloom-filtered).
    2. Fetch session row from Postgres (for initial_input, tool_call_count, etc.).
    3. Compute all 10 signals.
    4. Sum signal points (capped per signal, total capped at 100).
    5. Write security_findings rows for new post-session findings.
    6. Write session_risk_scores row.
    7. If score >= 65 (high/critical): produce to obs.alerts.v1.
    """
    # Fetch from ClickHouse — bloom filter on session_id makes this fast
    events = await ch.fetch("""
        SELECT event_type, event_id, emitted_at, sequence_index,
               node_run_id, node_name, tool_name, llm_model,
               llm_input_tokens, llm_output_tokens, payload
        FROM obs_events
        WHERE tenant_id  = %(tenant_id)s
          AND session_id = %(session_id)s
        ORDER BY sequence_index ASC
    """, tenant_id=tenant_id, session_id=session_id)

    session = await pg.fetchrow("""
        SELECT initial_input, graph_state, graph_runs, duration_ms
        FROM sessions WHERE session_id = $1
    """, session_id)

    # Compute all signals
    all_findings = list(online_findings)  # start with what online detectors already found
    total_points = sum(f.score_contrib for f in online_findings)

    for signal_fn in SIGNAL_FUNCTIONS:
        finding = await signal_fn(events, session, tenant_id, session_id, agent_id)
        if finding:
            all_findings.append(finding)
            total_points = min(total_points + finding.score_contrib, 100)

    risk_score = min(total_points, 100)
    risk_band  = _band(risk_score)

    # Write findings
    await write_findings(all_findings)

    # Write risk score
    score_row = SessionRiskScore(
        session_id     = session_id,
        tenant_id      = tenant_id,
        agent_id       = agent_id,
        risk_score     = risk_score,
        risk_band      = risk_band,
        signal_count   = len(all_findings),
        signal_ids     = [f.signal_id for f in all_findings],
        scorer_version = SCORER_VERSION,
    )
    await pg.execute("""
        INSERT INTO session_risk_scores
            (session_id, tenant_id, agent_id, risk_score, risk_band,
             signal_count, signal_ids, scorer_version, scored_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
        ON CONFLICT (session_id) DO UPDATE SET
            risk_score     = EXCLUDED.risk_score,
            risk_band      = EXCLUDED.risk_band,
            signal_count   = EXCLUDED.signal_count,
            signal_ids     = EXCLUDED.signal_ids,
            scorer_version = EXCLUDED.scorer_version,
            scored_at      = now()
    """, *score_row.values())

    # Alert on high/critical
    if risk_score >= 65:
        await produce_security_alert(score_row, all_findings)

    return score_row

def _band(score: int) -> str:
    if score < 20:  return "clean"
    if score < 40:  return "low"
    if score < 65:  return "medium"
    if score < 85:  return "high"
    return "critical"
```

---

## 6. All 10 signal functions (`scorer/signals.py`)

Each function is a pure async function with signature:
```python
async def signal_NNN(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> Finding | None
```

| Signal | Max points | OWASP | Computation |
|--------|-----------|-------|------------|
| S-01 | 40 | LLM01 | Any INJ-001/002 finding already in online_findings → +40 |
| S-02 | 20 | LLM01 | Any INJ-004 (indirect injection) finding → +20 |
| S-03 | 30 | LLM02 | Any OUT-001 critical finding → +30 |
| S-04 | 35 | LLM06 | Any PII-001/002/003/006 finding → +35. PII-004/005 → +10. Cap 35. |
| S-05 | 20 | LLM08 | `tool_call_count` vs agent 7-day p90 baseline. +5 per σ above. Cap 20. |
| S-06 | 25 | LLM07/08 | Any `tool_name` not in agent's declared tool manifest → +25 first, +10 each extra |
| S-07 | 30 | LLM08 | Session initial_input classified as "read" intent BUT tool calls include write/delete/send tools → +30 |
| S-08 | 15 | LLM09 | Session completed a payment/deletion/send action without `interrupt_raised` event AND HITL is configured → +15 |
| S-09 | 10 | LLM10 | Cross-session: same `user_context_id` sends near-identical llm_start inputs across 5+ sessions. Computed in `scorer/cohort.py`. |
| S-10 | 10 | LLM04 | Session token total > 4 σ above agent 7-day baseline → +10 |

S-01 through S-04 are **already computed by the online detectors** during the
session. The scorer receives `online_findings` from the consumer and uses them
directly — it does not re-run the online detectors. S-05 through S-10 are
post-session computations that require the full event history from ClickHouse.

**Scoring formula:**
```python
# Per-signal caps apply first, then total is hard-capped at 100
risk_score = min(sum(min(signal_points, signal_max) for each signal), 100)
```

---

## 7. Postgres schema (tables owned by this service)

### security_findings

```sql
CREATE TABLE security_findings (
    finding_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    session_id      UUID        NOT NULL REFERENCES sessions(session_id),
    event_id        UUID        NOT NULL,          -- the event that triggered this finding
    event_type      TEXT        NOT NULL,
    signal_id       TEXT        NOT NULL,          -- INJ-001, OUT-001, PII-001, S-05, etc.
    sig_type        TEXT        NOT NULL,          -- injection | passthrough | pii | agency | tool_scope
    owasp_id        TEXT        NOT NULL,          -- LLM01 … LLM10
    severity        TEXT        NOT NULL CHECK (severity IN ('critical','warning','info')),
    matched_text    TEXT,                          -- redacted excerpt that triggered detection
    detail          TEXT,
    score_contrib   INT         NOT NULL DEFAULT 0,
    detection_phase TEXT        NOT NULL CHECK (detection_phase IN ('online','post_session')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_findings_session   ON security_findings (session_id, created_at DESC);
CREATE INDEX idx_findings_tenant    ON security_findings (tenant_id,  created_at DESC);
CREATE INDEX idx_findings_signal    ON security_findings (signal_id);
CREATE INDEX idx_findings_owasp     ON security_findings (owasp_id, tenant_id);
```

### session_risk_scores

```sql
CREATE TABLE session_risk_scores (
    session_id      UUID        PRIMARY KEY REFERENCES sessions(session_id),
    tenant_id       UUID        NOT NULL,
    agent_id        UUID,
    risk_score      INT         NOT NULL DEFAULT 0 CHECK (risk_score BETWEEN 0 AND 100),
    risk_band       TEXT        NOT NULL CHECK (risk_band IN ('clean','low','medium','high','critical')),
    signal_count    INT         NOT NULL DEFAULT 0,
    signal_ids      TEXT[]      NOT NULL DEFAULT '{}',
    scorer_version  TEXT        NOT NULL,
    scored_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_scores_tenant_band  ON session_risk_scores (tenant_id, risk_band, scored_at DESC);
CREATE INDEX idx_scores_tenant_score ON session_risk_scores (tenant_id, risk_score DESC);
```

### injection_signatures

```sql
CREATE TABLE injection_signatures (
    sig_id          UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        REFERENCES tenants(tenant_id),  -- NULL = platform-global
    signal_id       TEXT        NOT NULL,
    sig_type        TEXT        NOT NULL CHECK (sig_type IN ('regex','blocklist','indirect')),
    pattern         TEXT,
    severity        TEXT        NOT NULL,
    enabled         BOOLEAN     NOT NULL DEFAULT true,
    version         INT         NOT NULL DEFAULT 1,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX idx_sigs_tenant ON injection_signatures (tenant_id, enabled) WHERE enabled = true;
```

---

## 8. Technology stack

Same as `dapplepot_pipeline` — Python 3.12, same libraries:

| Layer | Library | Version |
|-------|---------|---------|
| Kafka | `confluent-kafka` | ≥ 2.3 |
| Postgres | `asyncpg` | ≥ 0.29 |
| ClickHouse | `clickhouse-connect` | ≥ 0.7 |
| Redis | `redis[asyncio]` | ≥ 5.0 |
| Validation | `pydantic` | v2 |
| Config | `pydantic-settings` | ≥ 2.0 |
| Testing | `pytest` + `pytest-asyncio` | latest |

---

## 9. Environment variables

Connects to the same infrastructure as `dapplepot_pipeline`:

```bash
KAFKA_BOOTSTRAP_SERVERS=localhost:9092

# Kafka topic names — must match topic names created by dapplepot_pipeline exactly
KAFKA_EVENTS_TOPIC=obs.events.v1
KAFKA_ALERTS_TOPIC=obs.alerts.v1
KAFKA_DLQ_TOPIC=obs.dlq.v1

POSTGRES_DSN=postgresql://dapplepot:dapplepot@localhost:5432/dapplepot_pipeline
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_DB=dapplepot_pipeline
CLICKHOUSE_USER=dapplepot
CLICKHOUSE_PASSWORD=dapplepot

# Shared Redis — this service owns the dp:sec:* namespace only
# Pipeline owns: dp:rules:{tenant_id}
# API owns:      dp:api:*
# This service:  dp:sec:sigs:{tenant_id}, dp:sec:llm_out:*, dp:sec:tool_out:*
REDIS_URL=redis://localhost:6379/0

SECURITY_EVAL_WORKERS=4
SCORER_VERSION=1.0.0
SIG_CACHE_TTL_S=300
SESSION_CTX_TTL_S=120

# Threshold for producing security alert to obs.alerts.v1
ALERT_ON_SCORE_GTE=65

# Tool manifest (JSON map of agent_id → allowed tool names list)
# Used by S-06 out-of-scope tool detection
TOOL_MANIFESTS={}
```

---

## 10. Local dev setup

This service is **Step 3** in the full platform startup. Always run after
`dapplepot_pipeline` migrations — `security_findings.session_id` has a FK
on `sessions.session_id` which the pipeline creates.

```bash
# Step 1: infrastructure (owned by dapplepot_pipeline)
cd ../dapplepot_pipeline && docker compose up -d
# Wait ~15 seconds for Kafka, Postgres, ClickHouse, Redis to be healthy

# Step 2: pipeline setup (topics + PG migrations 001-007 + ClickHouse schemas + seed tenant)
cd ../dapplepot_pipeline && make setup

# Step 3: THIS SERVICE — migrations must run after pipeline's
cd ../dapplepot_security
uv sync
cp .env.example .env
make migrate        # PG migrations 001-004 — run AFTER pipeline's
make seed-sigs      # seeds 2,400+ injection signatures

# Step 4: start pipeline consumers (separate terminals)
cd ../dapplepot_pipeline
make run-ingest          # Terminal 1 — port 8000
make run-session-writer  # Terminal 2
make run-event-appender  # Terminal 3
make run-policy-evaluator # Terminal 4

# Step 5: start this service
cd ../dapplepot_security
make run             # Terminal 5 — dp-security-eval

# Steps 6-7: dapplepot_api (port 3000) and dapplepot_ui (port 5173)

# Verify health
make health          # checks dp-security-eval consumer lag on obs.events.v1
```

---

## 11. Build order

### Phase 1 — Foundation
```
core/config.py
core/infra/kafka.py
core/infra/postgres.py
core/infra/clickhouse.py
core/infra/redis.py
db/postgres/001_security_findings.sql
db/postgres/002_session_risk_scores.sql
db/postgres/003_injection_signatures.sql
db/postgres/004_indexes.sql
scripts/run_migrations.py
scripts/seed_signatures.py
```

### Phase 2 — Online detectors
```
consumers/security_eval/redis_ctx.py
consumers/security_eval/online/injection.py
consumers/security_eval/online/passthrough.py
consumers/security_eval/online/pii.py
```

### Phase 3 — Post-session scorer
```
consumers/security_eval/scorer/signals.py
consumers/security_eval/scorer/cohort.py
consumers/security_eval/scorer/post_session.py
```

### Phase 4 — Consumer + findings writer
```
consumers/security_eval/findings.py
consumers/security_eval/consumer.py
```

### Phase 5 — Tests
```
tests/conftest.py
tests/unit/test_injection_detector.py
tests/unit/test_passthrough_detector.py
tests/unit/test_pii_detector.py
tests/unit/test_signal_functions.py
tests/integration/test_online_detection.py
tests/integration/test_post_session_scorer.py
```

---

## 12. Updates required in other repos

### dapplepot_api — 5 new files + 2 line edits

```
src/types/security.ts               NEW — RiskBand, SessionRiskScore, SecurityFinding, SecurityOverview, RemediationCard
src/types/index.ts                  EDIT — add one line to existing barrel: export * from './security.js'
                                    (do NOT create a new file — the barrel already re-exports session, alert,
                                     analytics, rule, channel, common; only append the security line)
src/queries/security.pg.ts          NEW — getSecurityOverview, getSessionScore, getSessionFindings, getRemediationStats
src/routes/security.ts              NEW — 5 security endpoints (with cached<T> wrapper; see cache TTL below)
src/routes/index.ts                 EDIT — add: app.route('/v1/security', securityRouter)  [1 line]
src/lib/cache.ts                    EDIT — add 3 TTL constants (see cache TTL below)
```

New endpoints in `dapplepot_api`:

| Method | Path | Source | Purpose |
|--------|------|--------|---------|
| GET | `/v1/security/overview` | PG | Tenant security summary: scores dist, OWASP freq, top-risk sessions |
| GET | `/v1/security/sessions/:id/score` | PG | Session risk score + signal breakdown |
| GET | `/v1/security/sessions/:id/findings` | PG | All findings for a session with matched text |
| GET | `/v1/security/remediation` | PG | Ranked remediation guidance by signal frequency |
| GET | `/v1/security/signatures` | PG | Tenant injection signature config (for management UI) |

### dapplepot_api — cache TTL additions

Add to `src/lib/cache.ts`:
```typescript
CACHE_TTL_SECURITY_OVERVIEW  = 120   // 2 minutes — matches UI staleTime
CACHE_TTL_SESSION_SCORE      = 300   // 5 minutes — stable once written
CACHE_TTL_REMEDIATION        = 300   // 5 minutes
```

Apply in `src/routes/security.ts` using the existing `cached<T>` helper:
```typescript
const data = await cached(
  `dp:api:security:overview:${tenantId}:${windowHours}`,
  CACHE_TTL_SECURITY_OVERVIEW,
  () => getSecurityOverview(tenantId, windowHours)
)
```
Apply the same pattern for the score and remediation routes using their respective TTL constants.

### dapplepot_api — TypeScript types to verify against this service's schema

The UI types must match what this service writes to Postgres exactly:

| UI type | Postgres source | Key fields from this service |
|---------|----------------|------------------------------|
| `RiskBand` | `session_risk_scores.risk_band` | `"clean" \| "low" \| "medium" \| "high" \| "critical"` |
| `SessionRiskScore` | `session_risk_scores` | `session_id`, `risk_score` (0–100), `risk_band`, `signal_ids[]`, `scorer_version` |
| `SecurityFinding` | `security_findings` | `signal_id`, `owasp_id`, `severity`, `matched_text`, `score_contrib`, `detection_phase` |
| `SecurityOverview` | aggregated from both tables | scores distribution, OWASP frequency, top-risk sessions |
| `RemediationCard` | aggregated from `security_findings` | ranked by signal frequency |

---

### dapplepot_ui — 2 new files

```
src/api/security.ts                 NEW — getSecurityOverview, getSessionScore, getSessionFindings, getRemediation
src/hooks/useSecurity.ts            NEW — useSecurityOverview, useSessionSecurity, useRemediation
```

staleTime per hook (must align with API cache TTLs above):
- `useSecurityOverview`: `staleTime: 120_000`, `refetchInterval: 120_000`
- `useSessionSecurity` (score + findings): `staleTime: 300_000` — stable once written, never re-fetch
- `useRemediation`: `staleTime: 300_000`

The Security surface (`pages/Security.tsx`) and all security components
were already designed and specced in `dapplepot_ui/agent.md`. They just
need these two files to wire up the data.

> **Note — signatures endpoint:** The API exposes `GET /v1/security/signatures` but
> no corresponding `getSignatures` API fn or `useSignatures` hook is defined for the UI.
> Signatures management UI is out of scope for the MVP frontend.

> **Note — control endpoint path:** The existing `dapplepot_api` agent context file uses
> `POST /v1/control/kill-switch` while the UI compact uses `POST /v1/control/kill`.
> This is a pre-existing discrepancy between Zone 4/5 docs and does not affect Zone 6.

---

### Alert format contract with dapplepot_pipeline

When `risk_score >= ALERT_ON_SCORE_GTE` this service produces to `obs.alerts.v1`.
The `dp-alert-router` consumer in `dapplepot_pipeline` reads this topic.
The alert envelope this service sends:

```json
{
  "alert_id":      "<uuid4>",
  "alert_type":    "security_risk",
  "source":        "security",
  "timestamp":     "<ISO 8601 UTC>",
  "session_id":    "...",
  "tenant_id":     "...",
  "agent_id":      "...",
  "risk_score":    72,
  "risk_band":     "high",
  "signal_ids":    ["INJ-001", "S-06"],
  "top_findings":  [{ "signal_id": "...", "owasp_id": "...", "severity": "...", "detail": "..." }],
  "scorer_version":"1.0.0"
}
```

Fields `alert_id`, `alert_type`, `source`, `tenant_id`, `session_id`, `timestamp`
are required by `dp-alert-router` for routing. If `dp-alert-router`'s schema changes,
update `findings.py::produce_security_alert` to match.

---

### Dead letter queue contract with dapplepot_pipeline

If the security consumer fails to process an event (parse error, detector crash,
infra timeout), it produces to `obs.dlq.v1` — the DLQ owned by `dapplepot_pipeline`:

```json
{
  "source":           "dp-security-eval",
  "original_offset":  12345,
  "error":            "...",
  "raw":              "..."
}
```

After DLQ produce, the offset is committed to prevent the consumer stalling.
`obs.dlq.v1` is monitored by `dapplepot_pipeline` — no changes needed there.

---

## 13. Locked architecture decisions — do not change

| # | Decision | Reason |
|---|----------|--------|
| 1 | Online detectors run per-event, scorer runs post-session | Online = latency sensitive (injection must fire immediately). Scorer = needs full ClickHouse history which isn't available mid-session. |
| 2 | S-01 through S-04 not re-computed in scorer | Online detectors already wrote these findings. Scorer receives them as `online_findings`. No duplicate work. |
| 3 | Redis session context TTL = 120s | Long enough for one node's execution window. Short enough that a long-running session doesn't accumulate stale context for every node it ever visited. |
| 4 | `ON CONFLICT DO UPDATE` on session_risk_scores | Scorer may re-run on retry. Idempotent upsert is safer than INSERT. |
| 5 | Produce to `obs.alerts.v1` only on score >= 65 (high/critical) | Clean/low/medium scores go into the security UI only. High+ warrants ops notification via existing alert router. |
| 6 | Separate `dp:sec:` Redis key prefix | Namespaced from pipeline's `dp:rules:*` and API's `dp:api:*` keys. No overlap verified. |
| 7 | Signal functions are pure + independently testable | Each signal function takes events + session, returns Finding or None. No side effects. Fully unit testable without infra. |
| 8 | No HTTP calls between this service and dapplepot_pipeline | Purely event-driven. Security service is invisible to the pipeline. |
| 9 | `matched_text` always redacted before storage | PII patterns store only `PII-001: 4***...1234` not the actual card number. Injection matches truncated to 200 chars. |
| 10 | Scorer version tracked in `session_risk_scores.scorer_version` | When signal weights change, old scores can be identified and re-scored by filtering on scorer_version. |
| 11 | Kafka topic names in config, not hardcoded | `kafka_events_topic`, `kafka_alerts_topic`, `kafka_dlq_topic` in `Settings`. Must match `dapplepot_pipeline` topic names. |
| 12 | Failed events go to DLQ + commit offset | Sending to `obs.dlq.v1` then committing prevents the consumer stalling on a poison-pill message indefinitely. Pipeline's DLQ topic is the shared mechanism for all consumers. |
| 13 | Alert payload includes `alert_id`, `source`, `timestamp` | Required by `dp-alert-router` for deduplication, routing, and audit. `source: "security"` distinguishes these from policy alerts (`source: "policy"`). |
| 14 | Security migrations run after pipeline migrations | FK: `security_findings.session_id → sessions.session_id`. Pipeline must create the `sessions` table first. |

---

## 14. What done looks like

**Unit tests pass** (`make test-unit`):
- Injection detector fires on INJ-001 pattern, silent on normal input
- Passthrough detector fires at ≥ 0.60 ratio, silent at 0.59
- PII detector fires on card number, redacts matched text correctly
- Signal S-05 correctly computes σ above baseline from mock event list

**Integration tests pass** (`make test-integration`):
- inject_prompt scenario → INJ-001 finding written to security_findings,
  session risk_score = 40+, risk_band = medium or high
- pii_in_output scenario → PII-001 + OUT-001 findings, risk_score ≥ 65,
  alert produced to obs.alerts.v1
- happy_checkout scenario → risk_score 0–10, risk_band = clean,
  no findings written (no false positives)

---

*Single source of truth for `dapplepot_security` MVP.
Build in phase order. Do not skip phases.*
