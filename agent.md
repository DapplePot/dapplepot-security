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
- On each `graph_end` / `graph_error` event, runs a post-session scorer that:
  - Replays all session events from ClickHouse through per-event detectors (in sequence, in memory)
  - Runs session-level signal functions across the full event history
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
        └── On graph_end / graph_error event:
              └── Post-session scorer (async, reads full session from ClickHouse)
                    ├── Per-event detectors — replayed in order with in-memory cross-event context
                    │     ├── llm_start  → injection.py   (OW-LLM01: PI-01a/b, PI-02a)
                    │     │              → agentic.py     (OW-ASI06: MCP-01a)
                    │     ├── llm_end    → disclosure.py  (OW-LLM02: SID-*)
                    │     │              → prompt_guard.py (OW-LLM07: SPL-01a/b)
                    │     ├── tool_start → passthrough.py (OW-LLM05: IOH-*)
                    │     │              → agentic.py     (OW-ASI02: TME-*, OW-ASI05: RCE-*)
                    │     └── tool_end   → disclosure.py  (OW-LLM02: SID-*)
                    │
                    ├── Session-level signals
                    │     ├── OW-LLM01..10 signals → LLM composite score 0–100
                    │     └── OW-ASI01..10 signals → ASI composite score 0–100
                    │
                    ├── Writes to Postgres security_findings + session_risk_scores
                    └── Critical findings → obs.alerts.v1 → alert router → Slack/PD
```

### Service boundaries

- Reads from: Kafka `obs.events.v1`, Postgres (shared DB), ClickHouse (shared DB)
- Writes to: Postgres `security_findings`, `session_risk_scores`, `agent_risk_scores`, `signal_registry`
- Produces to: Kafka `obs.alerts.v1` (on alert threshold breach)
- **No HTTP calls to or from `dapplepot_pipeline`**
- **No HTTP calls to or from `dapplepot_api`**

---

## 2. Repo structure

```
dapplepot_security/
│
├── agent.md                                ← this file
├── README.md
├── .env.example
├── pyproject.toml
├── Makefile
│
├── consumers/
│   └── security_eval/                      ← consumer group: dp-security-eval (30 workers)
│       ├── __init__.py
│       ├── consumer.py                     ← Kafka poll loop; triggers score_session on graph_end/graph_error
│       ├── findings.py                     ← Finding dataclass (with confidence_tier + confidence), PG batch writer, alert producer
│       │
│       ├── detectors/                      ← per-event detectors (replayed post-session from ClickHouse)
│       │   ├── __init__.py
│       │   ├── injection.py                ← OW-LLM01: PI-01a (role-override), PI-01b (delimiter),
│       │   │                                  PI-02a (indirect), PI-05a (code injection),
│       │   │                                  PI-07a (multimodal), PI-08a (adversarial suffix),
│       │   │                                  PI-09a (obfuscated/encoded)
│       │   ├── disclosure.py               ← OW-LLM02: SID-01a/c (API keys, JWT),
│       │   │                                  SID-02a/b/c (email, card, SSN)
│       │   ├── passthrough.py              ← OW-LLM05: IOH-01a/b/c (shell/XSS/SQL in output),
│       │   │                                  IOH-02a (raw LLM output as tool param, LCS ratio)
│       │   ├── agentic.py                  ← OW-ASI01: AGH-04a (doc injection on tool_end)
│       │   │                                  OW-ASI02: TME-01a (tool misuse), TME-03b (prod target)
│       │   │                                  OW-ASI04: ASCV-02a (MCP descriptor poisoning),
│       │   │                                             ASCV-04a (unknown package install)
│       │   │                                  OW-ASI05: RCE-01b (exec tool name), RCE-03a (escape path),
│       │   │                                             RCE-03b (Docker/K8s API), RCE-06a (unsafe deser),
│       │   │                                             RCE-08a (lockfile manipulation)
│       │   │                                  OW-ASI06: MCP-01a (context injection in messages)
│       │   │                                  OW-ASI10: RA-04a (self-replication via provisioning)
│       │   └── prompt_guard.py             ← OW-LLM07: SPL-01a (LCS vs system prefix),
│       │                                      SPL-01b (probe pattern + non-refusal)
│       │
│       └── scorer/                         ← post-session scorer (reads ClickHouse, writes PG)
│           ├── __init__.py
│           ├── orchestrator.py             ← score_session() v3: replays events, runs all signals,
│           │                                  confidence weighting, attack chains, trust, writes scores, fires alerts
│           ├── llm_signals.py              ← OW-LLM01..10 signal functions + sub-check helpers
│           │                                  (check_multi_turn_jailbreak, check_payload_splitting,
│           │                                   check_rag_integrity, check_system_prompt_leakage,
│           │                                   check_vector_integrity, check_insecure_code_output,
│           │                                   check_hallucinated_packages, check_ungrounded_high_stakes,
│           │                                   check_input_size_anomaly)
│           ├── asi_signals.py              ← OW-ASI01..10 signal functions (all v3 sub-checks)
│           ├── cross_session.py            ← cross-session signals: SID-03a, UBC-03a/05a,
│           │                                  IPA-05a, MCP-02a/04a, RA-02a
│           ├── attack_chains.py            ← detect_attack_chains(fired_signals) → (chains, amplification)
│           │                                  7 chains, max-not-product amplification
│           ├── trust.py                    ← compute_agent_trust_score(agent_id, sessions)
│           │                                  Bayesian Beta(2,8) prior + temporal decay (λ=0.05/day) + trend
│           └── probe.py                    ← OW-LLM10: UBC-04a cross-session model theft probe
│
├── core/
│   ├── __init__.py
│   ├── config.py                           ← pydantic-settings: Kafka, PG, CH, Redis, thresholds
│   └── infra/
│       ├── __init__.py
│       ├── kafka.py                        ← confluent-kafka consumer + producer factory
│       ├── postgres.py                     ← asyncpg pool
│       ├── clickhouse.py                   ← clickhouse-connect (compress=False — CH Cloud SSL bug)
│       └── redis.py                        ← redis.asyncio pool
│
├── db/
│   └── postgres/
│       ├── 001_security_findings.sql       ← security_findings table
│       ├── 002_session_risk_scores.sql     ← session_risk_scores table
│       ├── 003_injection_signatures.sql    ← injection_signatures table
│       ├── 004_indexes.sql                 ← all indexes
│       ├── 005_agent_security_schema.sql   ← owasp_framework column + agent_risk_scores table
│       ├── 006_reporting_views.sql
│       ├── 007_signal_status.sql           ← llm_signal_status + agent_signal_status columns
│       ├── 008_agent_profile_views.sql
│       ├── 009_drop_session_fk.sql         ← drops sessions FK (race condition fix)
│       ├── 010_signal_id_upgrade.sql       ← adds owasp_signal_id, sub_check_id, check_score, check_label
│       ├── 011_signal_status_upgrade.sql   ← adds ow_llm_signal_status / ow_asi_signal_status JSONB + GIN idx
│       ├── 012_signal_registry.sql         ← signal_registry table (PK: owasp_signal_id + sub_check_id)
│       ├── 013_v3_scoring.sql              ← v3: confidence_tier on signal_registry + security_findings;
│       │                                      v3_llm_composite / v3_asi_composite JSONB on session_risk_scores
│       └── 014_trust_scores.sql            ← v3: trust_score, trust_alpha, trust_beta, trust_trend,
│                                              trust_last_updated on agent_risk_scores
│
├── tests/
│   ├── conftest.py
│   ├── unit/
│   │   ├── test_prompt_injection.py        ← OW-LLM01 injection detector
│   │   ├── test_data_disclosure.py         ← OW-LLM02 disclosure detector
│   │   ├── test_output_handling.py         ← OW-LLM05 passthrough detector
│   │   ├── test_agentic_threats.py         ← OW-ASI agentic detectors (incl. AGH-04a, ASCV-02a/04a, RCE-06a/08a, RA-04a, MCP-03a)
│   │   ├── test_llm_signals.py             ← OW-LLM01..10 (incl. PI-06a, IOH-04a, SAG-02a/03a, UBC-02a, LLM04/08 exclusion)
│   │   ├── test_asi_signals.py             ← OW-ASI01..10 (all v3 sub-checks)
│   │   ├── test_scoring_v3.py              ← v3: confidence weighting, composite, attack chain amplification
│   │   ├── test_attack_chains.py           ← 7 chains fire/silent, max amplification
│   │   ├── test_trust.py                   ← Bayesian prior, update, decay, trend
│   │   ├── test_cross_session.py           ← SID-03a, UBC-03a/05a, IPA-05a, MCP-02a/04a, RA-02a
│   │   └── test_signal_registry.py         ← 156 entries, all 20 signals, confidence_tier coverage; runs without DB
│   └── integration/
│       ├── test_detectors.py               ← detector scenarios against Postgres
│       └── test_post_session_scorer.py     ← v3 end-to-end: composite, attack chains, trust, scorer_version
│
└── scripts/
    ├── run_migrations.py                   ← runs db/postgres/ in numeric order
    ├── seed_signatures.py                  ← seeds injection_signatures for dapplepot_dev tenant
    ├── seed_signal_registry.py             ← upserts all 156 sub-checks with confidence_tier
    ├── seed_dev_scores.py                  ← backfills security_findings + session_risk_scores
    │                                          for SES_001–SES_005 (calls score_session() directly)
    └── health_check.py                     ← consumer lag check (make health)
```

---

## 3. What the security consumer reads

Consumer group: `dp-security-eval` | Workers: 30 | Source topic: `obs.events.v1`

The consumer only watches for session-close events. All detection runs post-session.

| Event type | Consumer action |
|-----------|----------------|
| `graph_end` | Triggers async `score_session()` — replays all events from ClickHouse |
| `graph_error` | Same as `graph_end` |
| All others | Offset committed, no detection |

Detection runs inside `score_session()` by iterating ClickHouse events in order:

| Event type | Detectors called (in-memory context maintained across events) |
|-----------|--------------------------------------------------------------|
| `llm_start` | `injection.py` (PI-01a/b, PI-02a); `agentic.py` (MCP-01a); updates `last_user_turn` |
| `llm_end` | `disclosure.py` (SID-*); `prompt_guard.py` (SPL-01a/b); updates `last_llm_output[node_run_id]` |
| `tool_start` | `passthrough.py` (IOH-*, uses `last_llm_output`); `agentic.py` (TME-*, RCE-*) |
| `tool_end` | `disclosure.py` (SID-*); updates `last_tool_output[node_run_id]` |

---

## 4. Signal taxonomy

All signals use canonical OWASP identifiers. Signal IDs have the form:
- `OW-LLM01` through `OW-LLM10` (OWASP LLM Top 10)
- `OW-ASI01` through `OW-ASI10` (OWASP Agentic AI Top 10)

Each parent signal has named **sub-checks** with their own `sub_check_id` and `check_score`.
The `signal_id` stored in `security_findings` has the format `"OW-LLM01:PI-01a"`.

### Sub-check IDs by signal

All 20 signals are detected post-session. Per-event detectors run inside `score_session()`
by replaying ClickHouse events in sequence.

| Signal | Key sub-checks (score, confidence_tier) | Detector / signal function |
|--------|----------------------------------------|---------------------------|
| OW-LLM01 | PI-01a (85, high), PI-01b (90, deterministic), PI-02a (70, high), PI-04b (92, high), PI-05a (80, high), PI-06a (88, high), PI-07a (60, low), PI-08a (75, medium), PI-09a (82, high) | `injection.py` + `check_multi_turn_jailbreak` + `check_payload_splitting` |
| OW-LLM02 | SID-01a (95, deterministic), SID-01c (90, deterministic), SID-02a/b/c (75–95, deterministic), SID-03a (95, high, cross_session) | `disclosure.py` + `cross_session.py` |
| OW-LLM03 | — (excluded: not detectable at inference time) | — |
| OW-LLM04 | DMP-01a/c — **excluded** (pre-runtime) | `llm_signals.py` returns None |
| OW-LLM05 | IOH-01a/b/c (85–90, deterministic), IOH-02a (70, medium), IOH-03a (80, high), IOH-04a (70, medium) | `passthrough.py` + `check_insecure_code_output` |
| OW-LLM06 | EA-01a..03b (65–98, high) | `llm_signals.py` |
| OW-LLM07 | SPL-01a/b (70–85, medium), SPL-02a/b (50–60, medium), SPL-03a/b (80–88, medium/high) | `prompt_guard.py` + `llm_signals.py` |
| OW-LLM08 | VEW-01b/02a — **excluded** (pre-runtime). VEW-01a/02b/03a active | `llm_signals.py` returns None for excluded |
| OW-LLM09 | SAG-01a (65, high), SAG-02a (65, low), SAG-03a (60, medium) | `llm_signals.py` |
| OW-LLM10 | UBC-01a (55, medium), UBC-02a (50, medium), UBC-04a (70, high), UBC-03a/05a (cross_session) | `llm_signals.py` + `probe.py` + `cross_session.py` |
| OW-ASI01 | AGH-01a/b (80–92, high), AGH-02a (85, high), AGH-03a (70, medium), AGH-04a (80, high) | `agentic.py` + `asi_signals.py` |
| OW-ASI02 | TME-01a/03b (65–95), TME-02a..08a (65–90, high/medium) | `agentic.py` + `asi_signals.py` |
| OW-ASI03 | IPA-01a..03b (80–95, high), IPA-04a (65, medium), IPA-05a (75, high, cross_session) | `asi_signals.py` + `cross_session.py` |
| OW-ASI04 | ASCV-01a..03b (70–90), ASCV-02a (80, high), ASCV-04a (85, deterministic), ASCV-05a (70, skeletal) | `agentic.py` + `asi_signals.py` |
| OW-ASI05 | RCE-01a..03b (80–98, deterministic), RCE-04a..08a (75–92, high/deterministic) | `agentic.py` + `asi_signals.py` |
| OW-ASI06 | MCP-01a/b (85–88, high), MCP-02a (80, high, cross_session), MCP-03a..05a (75–95) | `agentic.py` + `asi_signals.py` + `cross_session.py` |
| OW-ASI07 | IAC-01a/b (75–88, high), IAC-02a..06a (65–85, deterministic/high/medium/skeletal) | `asi_signals.py` |
| OW-ASI08 | CF-01a/b (70–75, high), CF-02a..04a (65–75, high/skeletal) | `asi_signals.py` |
| OW-ASI09 | HAT-01a/b (60–65, high), HAT-02a..05a (75–90, high/medium) | `asi_signals.py` |
| OW-ASI10 | RA-01a/b (60–78, medium/high), RA-02a (90, high, cross_session), RA-03a..05a (85–95, high/deterministic) | `asi_signals.py` + `cross_session.py` |

---

## 5. Per-event detector algorithms

All detectors run inside `score_session()` via `_run_per_event_detectors()`, which
replays ClickHouse events in sequence. Cross-event context is maintained in memory
(no Redis): `last_llm_output[node_run_id]`, `last_tool_output[node_run_id]`, `last_user_turn`.

### 5.1 Prompt injection detector (`detectors/injection.py`)

Runs on `llm_start`. Checks `messages[].content` for `role in (user, human, tool)`.

```python
_REGEX_SIGNATURES = [
    {"sub_check_id": "PI-01a", "pattern": r"(?i)(ignore|disregard|forget).{0,30}(previous|prior|above|system).{0,30}(instruction|prompt|message)"},
    {"sub_check_id": "PI-01a", "pattern": r"(?i)(pretend|act|behave|you are now|you are a).{0,40}(without|no|ignore).{0,30}(restriction|limit|filter|rule)"},
    {"sub_check_id": "PI-01b", "pattern": r"(?i)\[system\]|\<system\>|###\s*system|</s>|<\|im_start\|>|<\|im_end\|>"},
]
# PI-02a: indirect injection — requires overlap_chars(content, last_tool_output) >= 80
#         AND content matches an INSTRUCTION_PATTERN
# Blocklist → PI-01a: loaded from injection_signatures (Redis-cached, TTL 300s)
```

`_SUB_CHECKS` dict maps sub_check_id → `{check_label, check_score, severity}`.

Also exports `matches_injection_pattern(text)` and `has_partial_injection_signal(text)` for
post-session helpers in `llm_signals.py`.

### 5.2 Data disclosure detector (`detectors/disclosure.py`)

Runs on `llm_end` (`payload.completion`) and `tool_end` (`payload.tool_output`).
Deduplicated per sub_check_id per event to prevent duplicate findings.

```python
PII_PATTERNS = [
    {"sub_check_id": "SID-02b", "pattern": r"\b(?:4[0-9]{12}(?:[0-9]{3})?|...)\b", "severity": "critical", "check_score": 90},  # credit card
    {"sub_check_id": "SID-02c", "pattern": r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b", "severity": "critical", "check_score": 95},  # SSN
    {"sub_check_id": "SID-01a", "pattern": r"\b(sk-[a-zA-Z0-9]{32,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})\b", "severity": "critical", "check_score": 95},  # API key
    {"sub_check_id": "SID-01c", "pattern": r"eyJ[a-zA-Z0-9_-]+\.eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+", "severity": "critical", "check_score": 90},  # JWT
    {"sub_check_id": "SID-02a", "pattern": r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b", "severity": "high", "check_score": 75},  # email
    {"sub_check_id": "SID-02a", "pattern": r"\+?1?\s*[-.]?\s*\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b", "severity": "high", "check_score": 75},  # phone
]
# matched_text always redacted: first 2 chars + *** + last 2 chars
```

### 5.3 Output passthrough detector (`detectors/passthrough.py`)

Runs on `tool_start`. Compares `payload.tool_input` against `last_llm_output[node_run_id]`
(maintained in memory across events).

```python
def _lcs_ratio(a: str, b: str) -> float:
    # SequenceMatcher ratio on normalised (strip+lowercase) strings
    return SequenceMatcher(None, a, b).ratio()

async def detect_passthrough(event, last_llm_output) -> list[Finding]:
    # IOH-02a: LCS ratio >= 0.60  → score 70, high
    # Also checks for IOH-01a (shell), IOH-01b (XSS), IOH-01c (SQL) patterns in tool_input
```

Returns `list[Finding]` (may be empty). All `owasp_framework = "LLM"`.

### 5.4 Agentic threats detector (`detectors/agentic.py`)

Runs on `tool_start` (`detect_agent_threats_on_tool_start`) and
`llm_start` (`detect_agent_threats_on_llm_start`). All `owasp_framework = "ASI"`.

```python
# tool_start checks:
_RCE_TOOL_PATTERNS = [r"(?i)(exec|execute|eval|shell|bash|sh|cmd|subprocess|...)"]
# RCE-01b: tool_name matches → score 95, critical
# RCE-03a: tool_input["path"] matches /proc, /sys, /etc, /host, /var/run/docker, /dev → score 98
# RCE-03b: tool_input["url"] matches docker.sock, /api/v1/pods, kubernetes.default → score 98
# TME-01a: tool_input JSON matches shell chain / base64 blob / code injection → score 65
# TME-03b: tool_input["url"] matches production URL pattern → score 95

# llm_start checks:
_CONTEXT_INJECTION_PATTERNS = [r"(?i)<(system_override|...)[\s/>]", ...]
# MCP-01a: user/tool message content matches context injection pattern → score 88, high
#          Only roles: user, tool (system role is trusted, never checked)
```

### 5.5 System prompt guard (`detectors/prompt_guard.py`)

Runs on `llm_end`. Checks completion against agent's declared system prompt prefix
and the preceding user turn (maintained in memory).

```python
def check_prompt_guard(event, last_user_turn, agent_manifest) -> list[Finding]:
    # SPL-01a: LCS_ratio(completion, system_prompt_prefix) >= 0.70 → score 85, high
    # SPL-01b: last_user_turn matches probe pattern AND completion doesn't contain refusal phrase → score 70
```

---

## 6. Post-session scorer (`scorer/orchestrator.py`)

Triggered on `graph_end` / `graph_error`. Runs as an async task off the Kafka poll loop.

```python
async def score_session(tenant_id, session_id, agent_id, online_findings) -> dict:
    """
    1. Fetch full event list from ClickHouse.
    2. Fetch session row from Postgres.
    3. Run OW-LLM signal functions (llm_signals.py) + sub-check helpers.
    4. Run OW-ASI signal functions (asi_signals.py).
    5. Compute per-signal scores (max sub-check model) + composites.
    6. Write post-session security_findings rows.
    7. Write session_risk_scores (both old + new JSONB columns).
    8. Upsert agent_risk_scores.
    9. Resolve dedup_key via resolve_overlap_group().
    10. Alert if any signal >= SIGNAL_ALERT_THRESHOLDS[sig] OR composite >= COMPOSITE_ALERT_THRESHOLD.
    """
```

### v3 Scoring model

**Confidence tiers** (`core/config.py CONFIDENCE_WEIGHTS`):
```python
CONFIDENCE_WEIGHTS = {
    "deterministic": 1.0,
    "high":          0.9,
    "medium":        0.7,
    "low":           0.5,
    "skeletal":      0.3,
}
```

**Per-signal score** = `max(check_score × confidence_weight)` across all fired sub-checks.
Not additive. `effective_score` is what drives the composite.

**Composite score** (per framework):
```python
def compute_composite_score_v3(signal_map, framework, attack_chains) -> int:
    fired = sorted(
        [sig["effective_score"] for sig in signal_map.values()
         if sig["status"] == "fired"],
        reverse=True
    )
    if not fired: return 0
    raw = fired[0] if len(fired) == 1 else int(fired[0] * 0.6 + (sum(fired[1:]) / len(fired[1:])) * 0.4)
    _, amp = detect_attack_chains(set(signal_map.keys()))
    return min(100, int(raw * amp))
```

**Attack chains** (`scorer/attack_chains.py`):
```python
ATTACK_CHAINS = {
    "indirect_injection_to_exfil":  ({"OW-LLM01","OW-ASI02","OW-LLM02"}, 1.25),
    "goal_hijack_to_rce":           ({"OW-ASI01","OW-ASI05"},             1.30),
    "supply_chain_to_backdoor":     ({"OW-ASI04","OW-ASI05","OW-ASI10"},  1.35),
    "memory_poison_to_exfil":       ({"OW-ASI06","OW-LLM02"},            1.20),
    "privilege_escalation_chain":   ({"OW-ASI03","OW-LLM06","OW-ASI02"}, 1.25),
    "trust_exploitation_to_fraud":  ({"OW-ASI09","OW-ASI01"},            1.20),
    "cascading_failure_chain":      ({"OW-ASI08","OW-ASI10","OW-ASI07"}, 1.15),
}
# amplification = max(amp for matching chains) — never multiplicative
```

**Risk bands (v3)**:
```python
def _band(score: int) -> str:
    if score <= 14:  return "clean"
    if score <= 34:  return "low"
    if score <= 59:  return "medium"
    if score <= 84:  return "high"
    return "critical"
```

**Trust scoring** (`scorer/trust.py`):
```python
def compute_agent_trust_score(agent_id, sessions) -> dict:
    # Beta(α=2, β=8) prior → starting trust ≈ 80%
    # Each session: α += clean_weight, β += risky_weight
    # Temporal decay: weight = exp(-λ × days_ago), λ = 0.05
    # Trend: linear regression on last 20 sessions → "improving" | "stable" | "degrading"
    # trust_score = round(α / (α + β) * 100)
```

**Alert logic:**
```python
# Alert fires if:
# (a) any individual signal effective_score >= SIGNAL_ALERT_THRESHOLDS.get(sig_id, 80), OR
# (b) either composite score >= COMPOSITE_ALERT_THRESHOLD (65), OR
# (c) agent trust_score < TRUST_ALERT_THRESHOLD for N consecutive sessions
```

**Overlap dedup groups v3** (resolved in `orchestrator.py`):
```python
OVERLAP_GROUPS_V3 = {
    "injection":        {"OW-LLM01", "OW-ASI01", "OW-ASI06"},
    "output_exec":      {"OW-LLM05", "OW-ASI05", "OW-ASI02"},
    "supply_chain":     {"OW-LLM03", "OW-ASI04"},
    "memory_vector":    {"OW-LLM08", "OW-ASI06"},
    "excessive_agency": {"OW-LLM06", "OW-ASI02", "OW-ASI10"},
    "pii_privilege":    {"OW-LLM02", "OW-ASI03"},
    "trust_fraud":      {"OW-ASI09", "OW-ASI01"},        # NEW
    "cascade_rogue":    {"OW-ASI08", "OW-ASI10", "OW-ASI07"},  # NEW
}
```

### score_session() v3 flow (`orchestrator.py`)

```python
async def score_session(tenant_id, session_id, agent_id, online_findings) -> dict:
    """
    1.  Fetch full event list from ClickHouse.
    2.  Fetch session row from Postgres.
    3.  Run per-event detectors (replay events) → per_event_findings.
    4.  Run OW-LLM signal functions → llm_findings.
    5.  Run OW-ASI signal functions → asi_findings.
    6.  Run cross-session signals → cross_session_findings.         ← v3 NEW
    7.  compute_ow_signal_score(all_findings) → per-signal scores   ← v3 CHANGED (confidence-weighted)
    8.  detect_attack_chains(fired_signals) → chains, amplification ← v3 NEW
    9.  compute_composite_score_v3() → composite (with amp)         ← v3 CHANGED
    10. Write security_findings (with confidence_tier + confidence). ← v3 CHANGED
    11. Write session_risk_scores (v3 composite JSONB columns).      ← v3 CHANGED
    12. compute_agent_trust_score() → trust_score, trend.           ← v3 NEW
    13. Upsert agent_risk_scores (with trust columns).              ← v3 CHANGED
    14. Resolve dedup_key via resolve_overlap_group().
    15. Alert if thresholds breached (score or trust).
    scorer_version = "3.0.0"
    """
```

### LLM signals (`llm_signals.py`)

Each is `async def signal_ow_llm0N(events, session, tenant_id, session_id, agent_id, online_findings) -> Finding | None`.
`signal_ow_llm04` and `signal_ow_llm08` always return `None` (pre-runtime exclusion).

| Function | Signal | Sub-check | Trigger |
|---|---|---|---|
| `signal_ow_llm01` | OW-LLM01 | PI-01a | Any INJ-type online finding |
| `signal_ow_llm01_indirect` | OW-LLM01 | PI-02a | Any passthrough-type finding in online_findings |
| `signal_ow_llm02` | OW-LLM02 | SID-02b | Any PII-type finding with critical severity |
| `signal_ow_llm04` | OW-LLM04 | — | **returns None** (pre-runtime excluded) |
| `signal_ow_llm05` | OW-LLM05 | IOH-02a | Any passthrough-type finding |
| `signal_ow_llm06_tool_count` | OW-LLM06 | EA-01a | Tool count > p90 baseline (ClickHouse 7-day) |
| `signal_ow_llm06_scope` | OW-LLM06 | EA-02a | Tool not in `settings.get_tool_manifests()[agent_id]` |
| `signal_ow_llm06_write_on_read` | OW-LLM06 | EA-03a | Write/delete tool + read-intent `initial_input` |
| `signal_ow_llm08` | OW-LLM08 | — | **returns None** (pre-runtime excluded) |
| `signal_ow_llm09` | OW-LLM09 | SAG-01a | High-stakes tool + no `interrupt_raised` event |
| `signal_ow_llm10_probe` | OW-LLM10 | UBC-04a | Delegated to `probe.py` |
| `signal_ow_llm10_token_spike` | OW-LLM10 | UBC-01a | Total tokens > 4σ above 7-day agent baseline |

**Sub-check helpers** (return `list[Finding]`, called after the signal loop):
- `check_multi_turn_jailbreak(events, ...)` → PI-04b: >= 3 turns with partial injection fragments that combine into a full pattern
- `check_payload_splitting(events, ...)` → PI-06a: >= 3 messages with fragmented injection that reassembles
- `check_rag_integrity(events, ...)` → DMP-01a/c (skipped when excluded=True)
- `check_system_prompt_leakage(events, ...)` → SPL-02a/b, SPL-03b
- `check_vector_integrity(events, ...)` → VEW-01b/02a (skipped when excluded=True)
- `check_insecure_code_output(events, ...)` → IOH-04a: eval/hardcoded-password/SQL in code fences
- `check_hallucinated_packages(events, ...)` → SAG-02a: known hallucinated package in pip install block
- `check_ungrounded_high_stakes(events, ...)` → SAG-03a: medical/financial domain without retrieval tool
- `check_input_size_anomaly(events, ...)` → UBC-02a: input size > 4σ above baseline

### ASI signals (`asi_signals.py`)

Same function signature as LLM signals. OW-ASI01..10. Online signals passed in
as `online_findings`. Post-session + cross-session signals read ClickHouse history.

### Cross-session signals (`cross_session.py`)

```python
async def check_cross_user_bleed(tenant_id, session_id, user_id) -> Finding | None
    # SID-03a: PII from user A present in user B session events (ClickHouse)

async def check_request_rate_spike(tenant_id, user_id) -> Finding | None
    # UBC-03a: user request rate > 5× their 7-day baseline (ClickHouse)

async def check_cost_spike(tenant_id, user_id) -> Finding | None
    # UBC-05a: session cost > 3× user's 30-day avg (ClickHouse)

async def check_identity_sharing(tenant_id, session_id) -> Finding | None
    # IPA-05a: same credential token appears across different user_ids (ClickHouse)

async def check_cross_session_escalation(tenant_id, agent_id) -> Finding | None
    # MCP-02a: blocked tool in prior session now succeeds (Postgres agent_risk_scores)

async def check_cross_tenant_retrieval(tenant_id, session_id) -> Finding | None
    # MCP-04a: retrieval result contains records from different tenant_id (ClickHouse)

async def check_persistent_exfil(tenant_id, agent_id) -> Finding | None
    # RA-02a: same external endpoint appears in >= 3 sessions (ClickHouse)
```

---

## 7. Finding dataclass

```python
@dataclass
class Finding:
    tenant_id:        str
    session_id:       str
    event_id:         str
    event_type:       str
    owasp_signal_id:  str    # "OW-LLM01"
    sub_check_id:     str    # "PI-01a"
    check_label:      str    # "Role-override phrase match"
    check_score:      int    # 0–100 (per-sub-check weight)
    category:         str    # "LLM" | "ASI"
    severity:         str    # critical | high | medium | low
    detection_phase:  str    # per_event | post_session | cross_session | excluded
    confidence_tier:  str    # deterministic | high | medium | low | skeletal
    confidence:       float  # = CONFIDENCE_WEIGHTS[confidence_tier]
    matched_text:     str | None = None   # always redacted
    detail:           str | None = None
    framework:        str = "LLM"   # "LLM" | "ASI"
    # Derived in __post_init__:
    signal_id: str = field(init=False)  # "OW-LLM01:PI-01a"
```

---

## 8. Postgres schema

### security_findings (v3 columns added by migration 013)

```sql
CREATE TABLE security_findings (
    finding_id      UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id       UUID        NOT NULL REFERENCES tenants(tenant_id),
    session_id      UUID        NOT NULL,   -- no FK (dropped in 009)
    event_id        UUID        NOT NULL,
    event_type      TEXT        NOT NULL,
    signal_id       TEXT        NOT NULL,   -- "OW-LLM01:PI-01a"
    sig_type        TEXT        NOT NULL,
    owasp_id        TEXT        NOT NULL,   -- "LLM01" (legacy)
    owasp_framework TEXT        NOT NULL DEFAULT 'LLM' CHECK (owasp_framework IN ('LLM','ASI')),
    severity        TEXT        NOT NULL CHECK (severity IN ('critical','high','medium','low','warning','info')),
    matched_text    TEXT,
    detail          TEXT,
    score_contrib   INT         NOT NULL DEFAULT 0,
    detection_phase TEXT        NOT NULL CHECK (detection_phase IN ('online','post_session','cross_session','excluded')),
    -- v2 columns (migration 010):
    owasp_signal_id TEXT,       -- "OW-LLM01"
    sub_check_id    TEXT,       -- "PI-01a"
    check_score     SMALLINT,   -- 0–100
    check_label     TEXT,
    -- v3 columns (migration 013):
    confidence_tier TEXT        CHECK (confidence_tier IN ('deterministic','high','medium','low','skeletal')),
    confidence      NUMERIC(4,3),  -- 0.000–1.000
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### session_risk_scores (v3 columns added by migration 013)

```sql
CREATE TABLE session_risk_scores (
    session_id            UUID  PRIMARY KEY,
    tenant_id             UUID  NOT NULL,
    agent_id              UUID,
    risk_score            INT   NOT NULL DEFAULT 0,   -- LLM composite
    risk_band             TEXT  NOT NULL,
    signal_count          INT   NOT NULL DEFAULT 0,
    signal_ids            TEXT[] NOT NULL DEFAULT '{}',
    agent_risk_score      INT   NOT NULL DEFAULT 0,   -- ASI composite
    agent_risk_band       TEXT  NOT NULL DEFAULT 'clean',
    agent_signal_ids      TEXT[] NOT NULL DEFAULT '{}',
    -- legacy JSONB (backward compat — still written)
    llm_signal_status     JSONB,
    agent_signal_status   JSONB,
    -- v2 JSONB (migration 011)
    ow_llm_signal_status  JSONB,
    ow_asi_signal_status  JSONB,
    -- v3 JSONB (migration 013): effective scores, attack chains, amplification
    v3_llm_composite      JSONB,  -- { "composite": 72, "amplification": 1.25, "attack_chains_detected": [...], "signals": {...} }
    v3_asi_composite      JSONB,
    scorer_version        TEXT  NOT NULL,   -- "3.0.0"
    scored_at             TIMESTAMPTZ NOT NULL DEFAULT now()
);
```

### agent_risk_scores (v3 columns added by migration 014)

```sql
CREATE TABLE agent_risk_scores (
    agent_id          UUID PRIMARY KEY,
    tenant_id         UUID NOT NULL,
    session_count     INT  NOT NULL DEFAULT 0,
    avg_llm_score     NUMERIC(5,2) NOT NULL DEFAULT 0,
    avg_agent_score   NUMERIC(5,2) NOT NULL DEFAULT 0,
    max_llm_score     INT  NOT NULL DEFAULT 0,
    max_agent_score   INT  NOT NULL DEFAULT 0,
    -- v3 trust columns (migration 014):
    trust_score       INT  NOT NULL DEFAULT 80,    -- 0–100 (Bayesian posterior × 100)
    trust_alpha       NUMERIC(8,3) NOT NULL DEFAULT 2,
    trust_beta        NUMERIC(8,3) NOT NULL DEFAULT 8,
    trust_trend       TEXT DEFAULT 'stable' CHECK (trust_trend IN ('improving','stable','degrading')),
    trust_last_updated TIMESTAMPTZ,
    last_scored_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- asyncpg: pass avg scores as float(), max scores as int() to avoid AmbiguousParameterError
```

### signal_registry (migrations 012 + 013)

```sql
CREATE TABLE signal_registry (
    owasp_signal_id  TEXT NOT NULL,
    sub_check_id     TEXT NOT NULL,
    label            TEXT NOT NULL,
    owasp_category   TEXT NOT NULL CHECK (owasp_category IN ('LLM', 'ASI')),
    owasp_number     INT  NOT NULL,
    detection_phase  TEXT NOT NULL CHECK (detection_phase IN ('online','post_session','both','cross_session','excluded')),
    check_score      SMALLINT NOT NULL CHECK (check_score BETWEEN 0 AND 100),
    severity         TEXT NOT NULL CHECK (severity IN ('critical','high','medium','low')),
    -- v3 column (migration 013):
    confidence_tier  TEXT NOT NULL DEFAULT 'high'
                     CHECK (confidence_tier IN ('deterministic','high','medium','low','skeletal')),
    excluded         BOOLEAN NOT NULL DEFAULT false,
    exclusion_reason TEXT,
    PRIMARY KEY (owasp_signal_id, sub_check_id)
);
-- 156 rows seeded by scripts/seed_signal_registry.py
-- Excluded: DMP-01a/c (LLM04 pre-runtime), VEW-01b/02a (LLM08 pre-runtime), LLM03 (all)
```

### injection_signatures

```sql
CREATE TABLE injection_signatures (
    sig_id      UUID  PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id   UUID  NOT NULL REFERENCES tenants(tenant_id),
    signal_id   TEXT  NOT NULL,
    sig_type    TEXT  NOT NULL CHECK (sig_type IN ('regex','blocklist','indirect')),
    pattern     TEXT,
    severity    TEXT  NOT NULL,
    enabled     BOOLEAN NOT NULL DEFAULT true,
    version     INT  NOT NULL DEFAULT 1,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
-- Redis-cached per tenant: dp:sec:sigs:{tenant_id}, TTL 300s
```

---

## 9. Technology stack

| Layer | Library |
|-------|---------|
| Kafka | `confluent-kafka` ≥ 2.3 |
| Postgres | `asyncpg` ≥ 0.29 |
| ClickHouse | `clickhouse-connect` ≥ 0.7 (compress=False — CH Cloud SSL resets on compression) |
| Redis | `redis` ≥ 5.0 |
| Config | `pydantic-settings` ≥ 2.0 |
| Testing | `pytest` + `anyio` (pytest-asyncio not used) |

---

## 10. Environment variables

```bash
KAFKA_BOOTSTRAP_SERVERS=localhost:9092
KAFKA_EVENTS_TOPIC=obs.events.v1
KAFKA_ALERTS_TOPIC=obs.alerts.v1
KAFKA_DLQ_TOPIC=obs.dlq.v1

POSTGRES_DSN=postgresql://dapplepot:dapplepot@localhost:5432/dapplepot_pipeline
CLICKHOUSE_HOST=localhost
CLICKHOUSE_PORT=8123
CLICKHOUSE_USER=dapplepot
CLICKHOUSE_PASSWORD=dapplepot

REDIS_URL=redis://localhost:6379/0

SECURITY_EVAL_WORKERS=4
SCORER_VERSION=3.0.0
SIG_CACHE_TTL_S=300
SESSION_CTX_TTL_S=120

# Alert thresholds (v3 model)
COMPOSITE_ALERT_THRESHOLD=65
TRUST_ALERT_THRESHOLD=40        # trust_score < this triggers alert
TRUST_ALERT_MIN_SESSIONS=3      # must be below threshold for N sessions
# Per-signal thresholds in core/config.py SIGNAL_ALERT_THRESHOLDS dict

# Confidence weights (in core/config.py CONFIDENCE_WEIGHTS dict)
# deterministic=1.0, high=0.9, medium=0.7, low=0.5, skeletal=0.3

# Tool manifest (JSON map agent_id → allowed tool names)
# Used by EA-02a out-of-scope tool detection
TOOL_MANIFESTS={}
```

---

## 11. Local dev setup

```bash
# Step 1: infrastructure
cd ../dapplepot_pipeline && docker compose up -d

# Step 2: pipeline setup + seed dev data
cd ../dapplepot_pipeline && make setup && make seed-dev

# Step 3: this service
cd ../dapplepot_security
uv sync && cp .env.example .env
make setup          # runs migrations 001-014 + seed-sigs + seed-signal-registry + seed-dev-scores

# Step 4-5: pipeline consumers + this service
cd ../dapplepot_pipeline && make run-ingest  # + run-session-writer, run-event-appender, etc.
cd ../dapplepot_security && make run         # dp-security-eval

# Verify
make health          # checks dp-security-eval consumer lag
```

---

## 12. Build order

### Phase 1 — Foundation
```
core/config.py                      ← add CONFIDENCE_WEIGHTS dict
core/infra/kafka.py, postgres.py, clickhouse.py, redis.py
db/postgres/001..014 (all migrations, including 013_v3_scoring + 014_trust_scores)
consumers/security_eval/findings.py ← add confidence_tier, confidence fields
scripts/run_migrations.py
scripts/seed_signatures.py
scripts/seed_signal_registry.py     ← 156 sub-checks with confidence_tier
scripts/seed_dev_scores.py
```

### Phase 2 — Per-event detectors (new sub-checks)
```
consumers/security_eval/detectors/injection.py        ← add PI-05a/07a/08a/09a
consumers/security_eval/detectors/agentic.py          ← add AGH-04a, ASCV-02a/04a, RCE-06a/08a, RA-04a
consumers/security_eval/detectors/disclosure.py       ← (unchanged)
consumers/security_eval/detectors/passthrough.py      ← (unchanged)
consumers/security_eval/detectors/prompt_guard.py     ← (unchanged)
```

### Phase 3 — Post-session signal functions (new sub-checks)
```
consumers/security_eval/scorer/llm_signals.py         ← add PI-06a, IOH-04a, SAG-02a/03a, UBC-02a;
                                                         signal_ow_llm04 + signal_ow_llm08 return None
consumers/security_eval/scorer/asi_signals.py         ← add all new ASI v3 sub-checks
consumers/security_eval/scorer/probe.py               ← (unchanged)
```

### Phase 4 — Cross-session signals (NEW)
```
consumers/security_eval/scorer/cross_session.py       ← SID-03a, UBC-03a/05a, IPA-05a, MCP-02a/04a, RA-02a
```

### Phase 5 — v3 Scoring engine (NEW)
```
consumers/security_eval/scorer/attack_chains.py       ← detect_attack_chains(): 7 chains, max amplification
consumers/security_eval/scorer/trust.py               ← compute_agent_trust_score(): Bayesian + decay + trend
consumers/security_eval/scorer/orchestrator.py        ← score_session() v3: confidence, chains, trust
consumers/security_eval/consumer.py                   ← (unchanged)
```

### Phase 6 — Tests
```
tests/conftest.py
tests/unit/test_prompt_injection.py         ← add PI-05a/07a/08a/09a
tests/unit/test_data_disclosure.py
tests/unit/test_output_handling.py
tests/unit/test_agentic_threats.py          ← add AGH-04a, ASCV-02a/04a, RCE-06a/08a, RA-04a, MCP-03a
tests/unit/test_llm_signals.py              ← add PI-06a, IOH-04a, SAG-02a/03a, UBC-02a, LLM04/08 exclusion
tests/unit/test_asi_signals.py              ← all new v3 ASI sub-checks
tests/unit/test_scoring_v3.py               ← NEW: confidence weighting, composite, attack chains
tests/unit/test_attack_chains.py            ← NEW: all 7 chains
tests/unit/test_trust.py                    ← NEW: Bayesian prior, update, decay, trend
tests/unit/test_cross_session.py            ← NEW: all 6 cross-session functions
tests/unit/test_signal_registry.py          ← update: 156 entries, confidence_tier, cross_session phase
tests/integration/test_detectors.py
tests/integration/test_post_session_scorer.py  ← update: v3 composite, attack chains, trust, scorer_version
```

---

## 13. Changes in other repos (already applied)

### dapplepot_pipeline — 3 changes

`db/postgres/008_tenant_notification_channels.sql` — new table for per-tenant channel config.

`consumers/policy_evaluator/alert_router.py` — `_get_tenant_channels()` + `_persist_alert()`:
security alerts (with `channels: []`) are routed and upserted into the `alerts` table.

### dapplepot_api — 4 changes

| File | Change |
|------|--------|
| `queries/alerts.pg.ts` | `source` extracted from payload; `source` filter in `getAlertList` |
| `queries/sessions.pg.ts` | `source` extracted in `getSessionAlerts` |
| `routes/alerts.ts` | `source` query param wired through |
| `types/common.ts` | `source?: 'security' \| 'policy'` added to `AlertListParams` |

### dapplepot_ui — 5 changes

| File | Change |
|------|--------|
| `types/alert.ts` | `source: 'security' \| 'policy'` on `AlertSummary` |
| `stores/alertFilters.ts` | `source` state + `setSource` action |
| `components/detection/AlertFeed.tsx` | Source filter pills; `SecurityDetail` section |
| `components/detection/AlertDrawer.tsx` | Renders risk scores, top findings (v2 format), signal chips |
| `pages/Detection.tsx` | `source` filter passed to `useAlerts` |

### Alert schema contract

| Field | Value |
|-------|-------|
| `rule_id` | `00000000-0000-0000-0000-000000000001` (sentinel, stored as NULL nullable FK) |
| `rule_name` | `"Security Risk Score"` |
| `dedup_key` | `"security:{session_id}"` or `"security:{session_id}:{overlap_group}"` |
| `channels` | `[]` — router looks up from `tenant_notification_channels` |
| `payload.source` | `"security"` |
| `payload.rule_type` | `"security_risk"` |
| `payload.signal_taxonomy_version` | `"2.0"` |
| `payload.ow_llm_signal_status` | Full per-signal map with sub-checks (v2) |
| `payload.top_findings` | Top 5 by `check_score` — includes `owasp_signal_id`, `sub_check_id`, `check_label` |
| `payload.scorer_version` | `"2.0.0"` |

---

## 14. Dev seed fixed IDs

| Constant | Value |
|----------|-------|
| `TEST_TENANT_ID` | `00000000-0000-0000-0000-000000000001` |
| `TEST_AGENT_ID` | `00000000-0000-0000-0000-000000000002` |
| `TEST_SDK_KEY` | `dp_dev_key_langgraph_checkout_local` |

### Sessions (seeded scores after upgrade)

| Session | Status | LLM score | Signals fired |
|---------|--------|-----------|---------------|
| `SES_001` (`…001001`) | finalised | 0 — clean | none |
| `SES_002` (`…001002`) | open | 0 — clean | none |
| `SES_003` (`…001003`) | interrupted | 85 — high | OW-LLM01:PI-01a |
| `SES_004` (`…001004`) | killed | 79 — high | OW-LLM01:PI-01a + OW-LLM05:IOH-02a |
| `SES_005` (`…001005`) | finalised | 90 — critical | OW-LLM02:SID-02b |

OW-LLM06 `EAG-01a` and `UBC-01a` token spike remain silent for seeded data — both require a
7-day ClickHouse baseline and the seeded obs_events rows store the agent name string while
`score_session` receives the UUID.

---

## 15. Locked architecture decisions — do not change

| # | Decision | Reason |
|---|----------|--------|
| 1 | Online detectors run per-event; scorer runs post-session | Online = latency-sensitive. Scorer = needs full ClickHouse history. |
| 2 | OW-LLM01/02/05 online findings passed into scorer as `online_findings` | Scorer aggregates them rather than re-running detectors. No duplicate work. |
| 3 | Redis session context TTL = 120s | Covers one node execution window without accumulating stale context. |
| 4 | `ON CONFLICT DO UPDATE` on `session_risk_scores` | Scorer may re-run on retry. Idempotent upsert. |
| 5 | Per-signal thresholds in `SIGNAL_ALERT_THRESHOLDS` dict | Different signals warrant different sensitivity. OW-LLM03 set to 999 (excluded). |
| 6 | `dp:sec:` Redis key prefix | Namespaced from pipeline's `dp:rules:*` and API's `dp:api:*`. |
| 7 | Signal functions are pure + independently testable | Each takes events + session, returns Finding or None. No side effects. |
| 8 | No HTTP calls between this service and dapplepot_pipeline | Purely event-driven. Security service is invisible to the pipeline. |
| 9 | `matched_text` always redacted before storage | PII stored as `41**...34`, never raw. Injection excerpts truncated to 200 chars. |
| 10 | `scorer_version` tracked in `session_risk_scores` | Old scores identifiable for re-scoring when signal weights change. |
| 11 | Kafka topic names in config, not hardcoded | Must match `dapplepot_pipeline` topic names. |
| 12 | Failed events → DLQ + commit offset | Prevents stalling on poison-pill messages. |
| 13 | `dedup_key` resolved in orchestrator, passed in `score_row` | Prevents circular import between `findings.py` and `orchestrator.py`. |
| 14 | Parent signal score = max(sub-check scores), not sum | Additive scoring inflated scores when multiple sub-checks fired for the same attack vector. |
| 15 | All infra imports lazy in `findings.py` and `orchestrator.py` | Allows unit tests to import signal/scoring logic without the full infra stack installed. |

---

## 16. What done looks like

**Unit tests pass** (`make test-unit`) — 81 tests, no infra required:
- Online detectors: all sub-check IDs fire correctly; signal_id format `"OW-LLM01:PI-01a"`
- Scoring model: `compute_ow_signal_score` takes max; `compute_composite_score` formula; `resolve_overlap_group`
- Signal registry: 121 entries, all 20 parent signals covered, no duplicate sub-check IDs

**Integration tests pass** (`make test-integration`):
- Injection scenario → `OW-LLM01:PI-01a` finding written; `risk_score >= 40`; `risk_band` medium/high
- PII + passthrough scenario → `risk_score >= 65`; alert produced to `obs.alerts.v1`
- Clean checkout → `risk_score` 0–10; no findings (no false positives)

*Single source of truth for `dapplepot_security`. Build in phase order.*
