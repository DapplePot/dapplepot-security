# DapplePot Security — Agent Index

**Role:** Python security engine. Receives events from `dapplepot-api` via HTTP (`POST /v1/evaluate`), runs OWASP LLM Top 10 + Agentic AI (ASI) Top 10 post-session analysis, and writes risk scores + security findings to Postgres.

**Stack:** Python 3.12, FastAPI, uvicorn, asyncpg, clickhouse-connect, redis.asyncio, pydantic-settings
**Scorer version:** 3.0.0 | **Signal count:** 20 signals, 196 sub-checks

---

## Directory Map

```
core/
  config.py              Pydantic Settings: all connection strings + scoring constants
                         SIGNAL_ALERT_THRESHOLDS_V3, COMPOSITE_ALERT_THRESHOLD_V3=60,
                         CONFIDENCE_WEIGHTS, ATTACK_CHAINS (7 patterns), RISK_BANDS_V3
  security_config.py     AgentSecurityConfig: per-agent signal toggles, thresholds, subcheck overrides
                         SubCheckOverride: online_detection bool + action (alert/sanitize/block_call/terminate_session)
                         Redis-cached (TTL 300s). get_agent_security_config(), push_agent_defaults()
                         Two-level merge: platform defaults → tenant overrides → agent overrides → cached result
  infra/
    postgres.py          asyncpg connection pool
    clickhouse.py        clickhouse-connect client (compress=False)
    redis.py             redis.asyncio connection pool

consumers/security_eval/
  consumer.py            _handle_event() — all dispatch logic (called directly by HTTP server, not Kafka)
                         _ONLINE_SIGNAL_MAP: keyed by sub_check_id (SDK sends sub_check_id directly)
                         _pending_findings: tracks in-flight finding-persist tasks per session
                         _run_scorer_after_findings: waits for pending findings before scoring
                         Handles: graph_start, security_finding, graph_end, graph_error

  findings.py            Finding dataclass + write functions
                         write_findings(), write_agent_risk_score(), write_session_action()
                         Dedup: ON CONFLICT (session_id, sub_check_id, event_id) — multiple firings stored
                         produce_combined_online_alert: now includes trigger_event_id, trigger_event_type,
                           triggered_at per detection, and session_started_at in alert payload

  detectors/             Per-event detectors (run at graph_end by replaying ClickHouse events)
    injection.py         OW-LLM01: PI-01a/b (role-override, delimiter), PI-02a (indirect),
                         PI-05a/07a/08a/09a (code, multimodal, entropy, obfuscated)
    disclosure.py        OW-LLM02: SID-01a/c, SID-02a/b/c (PII patterns)
    passthrough.py       OW-LLM05: IOH-01a/b/c (LCS passthrough), IOH-02a
    agentic.py           OW-ASI01/02/04/05/06/10 per-event checks
    prompt_guard.py      OW-LLM07: SPL-01a/b (system prompt leakage)

  scorer/
    orchestrator.py      score_session() — main entry: fetch events, run all signals, write results
                         sdk_findings_all: undeduped list passed to combined alert (all firings shown)
                         sdk_findings: deduped by sub_check_id for scoring (highest score wins)
                         fetches started_at from sessions; passes session_started_at to alert
    llm_signals.py       OW-LLM01..10 signal functions + sub-check helpers (~1,000 LOC)
    asi_signals.py       OW-ASI01..10 signal functions including 75 v3 sub-checks (~1,300 LOC)
    cross_session.py     Cross-session signals: SID-03a, UBC-03a/05a, IPA-05a, MCP-02a/04a, RA-02a
    attack_chains.py     detect_attack_chains() — 7 patterns, max-amplification
    trust.py             compute_agent_trust_score() — Bayesian Beta, temporal decay λ=0.05/day
    probe.py             OW-LLM10: UBC-04a cross-session model theft

server/
  main.py                FastAPI app; POST /v1/evaluate → _handle_event()

db/postgres/             26 migrations (001–026)
  001_security_findings.sql     Main findings table
  002_session_risk_scores.sql   Per-session composite scores + v3 JSONB columns
  003_agent_risk_scores.sql     Per-agent aggregates + trust scoring
  004_injection_signatures.sql  Tenant-scoped injection patterns
  005_signal_registry.sql       156 entries: all OWASP signals + sub-checks
  013_v3_scoring.sql            v3: confidence_tier, v3_llm_composite/v3_asi_composite (JSONB)
  016_subcheck_online_toggle.sql agent_subcheck_overrides table
  017_agent_alert_config.sql    agent_alert_config table
  018_split_composite_thresholds.sql  llm_composite_alert_threshold + asi_composite_alert_threshold
  019_session_actions.sql       Audit trail: hard actions (sanitize, block_call, terminate)
  022_tool_manifest.sql         agent_alert_config: tool_manifest JSONB + max_tool_calls_per_session INT
  023_session_online_actions_view.sql  View: session_online_actions
  024_session_actions_session_id_uuid.sql  Fix session_actions.session_id to UUID
  025_detection_phase_cross_session.sql  Allow detection_phase = 'cross_session'
  026_findings_event_dedup.sql  Broaden findings uniqueness to (session_id, sub_check_id, event_id)

scripts/
  run_migrations.py      Execute all migrations in order
  seed_signatures.py     Populate injection_signatures for dev tenant
  seed_signal_registry.py Upsert 156 sub-checks with confidence_tier
  seed_dev_scores.py     Backfill scoring for SES_001–005
  health_check.py        Service health check (make health)

tests/
  unit/                  13 test files, ~1,000+ assertions, no infra required
  integration/
    test_detectors.py                End-to-end detector scenarios
    test_post_session_scorer.py      v3 end-to-end: composite, chains, trust, scorer_version

Makefile               server, setup, migrate, seed-*, health, lint, format, test
pyproject.toml         Python 3.12, asyncpg, clickhouse-connect, redis, pydantic, fastapi, uvicorn
.env.example           All vars documented
```

---

## HTTP Event Pipeline (Main Data Flow)

```
dapplepot-api → POST /v1/evaluate
  │
  ├─ event_type = graph_start
  │   └─ push_agent_defaults() → Redis cache (AgentSecurityConfig, TTL 300s)
  │
  ├─ event_type = security_finding  (online detection from SDK)
  │   └─ _ONLINE_SIGNAL_MAP[sub_check_id] → Finding fields
  │   └─ write_findings() → security_findings table
  │   └─ write_session_action() if action in [sanitize, block_call, terminate_session]
  │
  └─ event_type = graph_end | graph_error
      └─ asyncio.create_task(_run_scorer())
          └─ score_session(tenant_id, session_id, agent_id)
              ├─ get_agent_security_config() from Redis
              ├─ Fetch all events from ClickHouse (obs_events, FINAL)
              ├─ Fetch session from Postgres (for initial_input, graph_state, hitl_enabled)
              ├─ _run_per_event_detectors(events) — replay events through detectors/
              ├─ Run all 10 LLM signal functions (llm_signals.py)
              ├─ Run all 10 ASI signal functions (asi_signals.py)
              ├─ Run cross-session signals (cross_session.py)
              ├─ compute_ow_signal_score(all_findings) → signal_map
              ├─ detect_attack_chains(fired_signals) → chains, amplification
              ├─ compute_composite_score_v3(signal_map, framework, chains) → composite
              ├─ write_findings() → security_findings
              ├─ write_session_risk_score() → session_risk_scores (v3 JSONB)
              ├─ compute_agent_trust_score() → Bayesian update
              └─ write_agent_risk_score() → agent_risk_scores
```

---

## v3 Scoring Model

### Confidence Tiers
```
deterministic: 1.0  (regex match, exact pattern)
high:          0.9  (strong heuristic, embeddings)
medium:        0.7  (LLM judge, good recall)
low:           0.5  (weak heuristic, noisy)
skeletal:      0.3  (structural indicator only)
```

### Per-Signal Score
```
effective_score = check_score × confidence_weight
signal_score = max(effective_score) across all fired sub-checks
```

### Composite Score (LLM or ASI framework)
```
raw = highest_signal × 0.60 + mean(rest) × 0.40   (if 2+ signals)
    = highest_signal                                (if 1 signal)

Amplification (7 attack chains, take max):
  indirect_injection_to_exfil: LLM01 + ASI02 + LLM02 → 1.25×
  goal_hijack_to_rce:          ASI01 + ASI05          → 1.30×
  supply_chain_to_backdoor:    ASI04 + ASI05 + ASI10  → 1.35×
  memory_poison_to_exfil:      ASI06 + ASI01 + LLM02  → 1.25×
  privilege_escalation_chain:  ASI03 + ASI02 + LLM06  → 1.20×
  trust_exploitation_to_fraud: ASI09 + ASI01 + LLM05  → 1.25×
  cascading_failure_chain:     ASI08 + ASI07 + ASI10  → 1.30×

final_composite = min(100, int(raw × amplification))
```

### Risk Bands
| Band | Score | Meaning |
|------|-------|---------|
| clean | 0–14 | No concerning signals |
| low | 15–34 | Minor detections, low confidence |
| medium | 35–59 | Notable patterns, needs investigation |
| high | 60–84 | Critical findings, elevated risk |
| critical | 85–100 | Multiple high-confidence signals |

### Trust Scoring (Agent-level, Bayesian Beta)
```
Prior: Beta(α=2, β=8) → starting trust ≈ 80%
Update per session:
  composite < 35  → α += 1 (clean)
  composite ≥ 35  → β += 1 (risky)
Temporal decay: weight_i = exp(-0.05 × days_ago_i)
trust_score = int(100 × (1 − α/(α+β)))
Trend (linear regression, last 20 sessions):
  slope > 0.05 → "improving" | slope < -0.05 → "degrading" | else → "stable"
```

### Alert Logic
Alert fires when **any** of:
1. Individual signal `effective_score ≥ per-signal threshold` (from `agent_alert_config`)
2. LLM composite `≥ llm_composite_alert_threshold` (default 60)
3. ASI composite `≥ asi_composite_alert_threshold` (default 60)
4. Agent `trust_score < 50` for 3+ consecutive sessions

---

## Online Signal Map (`_ONLINE_SIGNAL_MAP`)

Keyed by `sub_check_id` — the SDK sends `sub_check_id` directly (not a signal name alias). Only sub-checks with `onlineCapable: true` in the signal registry are listed here.

| sub_check_id | OWASP ID | Label | Score | Confidence |
|-------------|----------|-------|-------|------------|
| `PI-01a` | OW-LLM01 | Role-override phrase match | 85 | high |
| `PI-01b` | OW-LLM01 | Delimiter smuggling | 90 | deterministic |
| `PI-01c` | OW-LLM01 | Encoded / obfuscated payload | 75 | high |
| `PI-02a` | OW-LLM01 | Web-fetched content with injection pattern | 70 | high |
| `PI-05a` | OW-LLM01 | Code injection pattern in prompt | 80 | high |
| `PI-08a` | OW-LLM01 | Adversarial suffix (high-entropy tail) | 75 | medium |
| `SID-01a` | OW-LLM02 | API key / token pattern in output | 95 | deterministic |
| `SID-01c` | OW-LLM02 | JWT / session token in agent message | 90 | deterministic |
| `SID-02a` | OW-LLM02 | Name + email + phone co-occurrence | 75 | high |
| `IOH-01a` | OW-LLM05 | Shell command pattern in output | 90 | deterministic |
| `EA-01a` | OW-LLM06 | Excessive agency — tool call count | — | — |

---

## The 20 OWASP Signals

### LLM Top 10
| Signal | Active | Online-capable | Key sub-checks |
|--------|--------|----------------|----------------|
| OW-LLM01 Prompt Injection | ✅ | ✅ | PI-01a/b/c, PI-02a, PI-04b, PI-05a/06a/07a/08a/09a |
| OW-LLM02 Sensitive Data Disclosure | ✅ | ✅ | SID-01a/c, SID-02a/b/c, SID-03a (cross-session) |
| OW-LLM03 Training Data Poisoning | ❌ excluded | — | Pre-runtime only |
| OW-LLM04 Data & Model Poisoning | ❌ excluded | — | Pre-runtime only |
| OW-LLM05 Insecure Output Handling | ✅ | ✅ | IOH-01a/b/c, IOH-02a, IOH-03a, IOH-04a |
| OW-LLM06 Excessive Agency | ✅ | ✅ | EA-01a/b/c, EA-02a/b/c, EA-03a/b |
| OW-LLM07 System Prompt Leakage | ✅ | ✅ | SPL-01a/b, SPL-02a/b, SPL-03a/b |
| OW-LLM08 Vector/Embedding Weakness | ❌ excluded | — | Pre-runtime only |
| OW-LLM09 Misinformation/Overreliance | ✅ | ✅ | SAG-01a, SAG-02a, SAG-03a |
| OW-LLM10 Unbounded Consumption | ✅ | — | UBC-01a/b, UBC-02a/b, UBC-03a, UBC-04a, UBC-05a |

### Agent AI (ASI) Top 10
| Signal | Active | Online-capable | Key sub-checks |
|--------|--------|----------------|----------------|
| OW-ASI01 Agent Goal Hijacking | ✅ | ✅ | AGH-01a/b, AGH-02a, AGH-03a, AGH-04a |
| OW-ASI02 Tool Misuse | ✅ | ✅ | TME-01a, TME-02a..08a, TME-03b |
| OW-ASI03 Identity & Privilege Abuse | ✅ | — | IPA-01a..03b, IPA-04a, IPA-05a |
| OW-ASI04 Agentic Supply Chain | ✅ | ✅ | ASCV-01a..03b, ASCV-04a/05a |
| OW-ASI05 Unexpected Code Execution | ✅ | ✅ | RCE-01a/b, RCE-03a/b, RCE-04a..08a |
| OW-ASI06 Memory & Context Poisoning | ✅ | ✅ | MCP-01a/b, MCP-02a..05a |
| OW-ASI07 Insecure Inter-Agent Comms | ✅ | — | IAC-01a/b, IAC-02a..06a |
| OW-ASI08 Cascading Failures | ✅ | ✅ | CF-01a/b, CF-02a..04a |
| OW-ASI09 Human-Agent Trust Exploitation | ✅ | — | HAT-01a/b, HAT-02a..05a |
| OW-ASI10 Rogue Agents | ✅ | — | RA-01a/b, RA-02a..05a |

---

## Key Dataclass: `Finding` (`consumers/security_eval/findings.py`)

```python
@dataclass
class Finding:
    tenant_id: str
    session_id: str
    event_id: str
    event_type: str
    owasp_signal_id: str       # "OW-LLM01"
    sub_check_id: str          # "PI-01a"
    check_label: str
    check_score: int           # 0–100
    category: str
    severity: str              # "critical" | "high" | "medium" | "low"
    detection_phase: str       # "online" | "post_session" | "cross_session"
    confidence_tier: str       # "deterministic" | "high" | "medium" | "low" | "skeletal"
    confidence: float          # derived from confidence_tier weight
    framework: str             # derived
    matched_text: str | None   # always redacted in storage
    detail: str | None
    emitted_at: str | None     # ISO 8601 UTC
```

---

## Postgres Schema (Key Tables)

### `security_findings`
```sql
finding_id UUID PK | tenant_id | session_id | event_id | event_type
owasp_signal_id TEXT | sub_check_id TEXT | check_label | check_score SMALLINT
framework TEXT | severity TEXT | detection_phase TEXT  -- 'online'|'post_session'|'cross_session'
matched_text TEXT (always redacted) | detail TEXT
confidence_tier TEXT | confidence NUMERIC(4,3)
emitted_at TIMESTAMPTZ | created_at TIMESTAMPTZ
-- Dedup: UNIQUE (session_id, sub_check_id, event_id) — multiple firings stored individually
```

### `session_risk_scores`
```sql
session_id UUID PK | tenant_id | agent_id
risk_score INT (LLM composite) | risk_band TEXT | signal_count | signal_ids TEXT[]
agent_risk_score INT (ASI composite) | agent_risk_band | agent_signal_ids TEXT[]
v3_llm_composite JSONB | v3_asi_composite JSONB
ow_llm_signal_status JSONB | ow_asi_signal_status JSONB
scorer_version TEXT | scored_at TIMESTAMPTZ
```

### `agent_risk_scores`
```sql
agent_id UUID PK | tenant_id | session_count
avg_llm_score | avg_asi_score | max_llm_score | max_asi_score
trust_score INT (0–100) | trust_trend TEXT | trust_alpha | trust_beta
trust_last_updated | last_scored_at
```

### `signal_registry` (156 rows, seeded once)
```sql
(owasp_signal_id, sub_check_id) PK | label | owasp_category (LLM/ASI)
owasp_number | detection_phase | check_score | severity
confidence_tier | excluded BOOLEAN | exclusion_reason
```

### `agent_alert_config`
```sql
(tenant_id, agent_id) PK | composite_alert_threshold INT DEFAULT 60
llm_composite_alert_threshold INT | asi_composite_alert_threshold INT
signal_thresholds JSONB         -- {"OW-LLM01": 70, ...}
tool_manifest JSONB DEFAULT '[]' -- allowed tool names; [] = no manifest configured
max_tool_calls_per_session INT   -- NULL = statistical baseline fallback
```

### `session_actions` (audit trail)
```sql
(session_id, sub_check_id) PK | tenant_id | agent_id
owasp_signal_id | severity
action_taken TEXT CHECK IN ('sanitize','block_call','terminate_session')
triggered_at TIMESTAMPTZ
```

---

## Redis Keys

| Key | TTL | Content |
|-----|-----|---------|
| `dp:sec:defaults` | none | Platform-default AgentSecurityConfig JSON |
| `dp:sec:{tenant_id}:agent:{agent_id}:cfg` | 300s | Merged AgentSecurityConfig |
| `dp:sec:sigs:{tenant_id}` | 300s | Injection signatures blocklist |

---

## Configuration Reference

```env
POSTGRES_DSN=postgresql://dapplepot:dapplepot@localhost:5432/dapplepot
CLICKHOUSE_HOST=localhost  CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=dapplepot  CLICKHOUSE_PASSWORD=dapplepot
REDIS_URL=redis://localhost:6379/0
SCORER_VERSION=3.0.0
SIG_CACHE_TTL_S=300
ALERT_ON_SCORE_GTE=65
AGENT_TRUST_ALERT_THRESHOLD=50
AGENT_TRUST_CONSECUTIVE_SESSIONS=3
LLM_INPUT_COST_PER_1K=0.01  LLM_OUTPUT_COST_PER_1K=0.03
```

---

## Build & Run

```bash
uv sync
cp .env.example .env
make setup           # migrate + seed signal registry + seed signatures + seed scores
make server          # uvicorn server.main:app --host 0.0.0.0 --port 8001 --reload
make health          # check Postgres + Redis connectivity
make test-unit       # ~1,000+ assertions, no infra (~2 min)
make test-integration # needs docker compose up
make test            # all
make lint            # ruff check
make format          # ruff format
```

---

## Finding Specific Code

| Need to... | File |
|-----------|------|
| Add a new LLM signal function | `scorer/llm_signals.py` + register in `orchestrator.py` |
| Add a new ASI signal function | `scorer/asi_signals.py` + register in `orchestrator.py` |
| Add a cross-session signal | `scorer/cross_session.py` + call in `orchestrator.py` |
| Add/modify an attack chain | `core/config.py` → `ATTACK_CHAINS` dict, then `scorer/attack_chains.py` |
| Add a new per-event detector | `consumers/security_eval/detectors/<signal>.py` + call in `consumer.py` |
| Add a new sub-check | Implement in signal file + add to `signal_registry` via `scripts/seed_signal_registry.py` |
| Add a new online signal mapping | `consumers/security_eval/consumer.py` → `_ONLINE_SIGNAL_MAP` (key = sub_check_id) |
| Change confidence weights | `core/config.py` → `CONFIDENCE_WEIGHTS` |
| Change risk band thresholds | `core/config.py` → `RISK_BANDS_V3` |
| Change alert thresholds | `core/config.py` → `SIGNAL_ALERT_THRESHOLDS_V3` + `COMPOSITE_ALERT_THRESHOLD_V3` |
| Change how trust decays | `scorer/trust.py` → λ parameter |
| Change SubCheckOverride actions | `core/security_config.py` → `SubCheckOverride.action` |
| Debug a missing finding | `scorer/orchestrator.py` → `score_session()` step-by-step |
| Add a DB column | New migration in `db/postgres/0NN_<name>.sql` |
