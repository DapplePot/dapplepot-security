# dapplepot-security — What is this and how does it work?

## The one-line version

This is the brain of the security analysis. After an agent session ends, this service pulls all the events for that session, runs them through a battery of OWASP-based threat detectors, and produces a risk score. It also handles the real-time security findings that the SDK sends during a session.

---

## Why does this exist as a separate service?

The security analysis is the most computationally intensive part of the platform. Running 20 signal functions, replaying every event through multiple detectors, computing attack chains, and updating a Bayesian trust score — all of that takes time and shouldn't block the ingest path.

By keeping it separate, a slow scoring job has zero impact on the API's ability to receive events from agents.

---

## Two modes of operation

### 1. Online (real-time, from the SDK)

When the SDK's `OnlineCheckInterceptor` fires a check during a live session, it sends a `security_finding` event to the API, which forwards it here. This service just persists it immediately — no scoring needed, the SDK already did the detection.

### 2. Post-session (after the session ends)

When a `session_end` or `session_error` event arrives, this service kicks off the full scoring pipeline. It:
1. Fetches all events for that session from ClickHouse
2. Replays them through per-event detectors
3. Runs 10 LLM signal functions and 10 ASI signal functions
4. Checks for attack chains (combinations of signals that are more dangerous together)
5. Computes a composite risk score
6. Updates the agent's long-term trust score
7. Writes everything to Postgres

---

## The scoring model, in plain English

### Signals (20 total)
A "signal" maps to one OWASP category — e.g. OW-LLM01 is Prompt Injection, OW-LLM02 is Sensitive Data Disclosure. Each signal has multiple sub-checks underneath it.

### Confidence tiers
Not all detections are equally reliable. A regex match on a known API key pattern is `deterministic` (weight 1.0). An LLM-judge-based check is `medium` (weight 0.7). The score gets multiplied by this weight before being used.

### Composite score
The final score for a session is:
- Take the highest-scoring signal, weight it at 60%
- Average the rest, weight at 40%
- If multiple signals fired together in a known attack pattern, amplify the score (up to 1.35×)
- Cap at 100

### Risk bands
- 0–14: clean
- 15–34: low
- 35–59: medium
- 60–84: high
- 85–100: critical

### Agent trust score
Each agent has a long-term trust score that updates after every session. It uses a Bayesian model — clean sessions push the score up, risky sessions push it down. Sessions from longer ago have less influence (exponential decay). This gives you a sense of whether an agent is consistently well-behaved or has a pattern of risky activity.

---

## The attack chains

Seven specific combinations of signals get an amplification multiplier because they represent known multi-step attack patterns:

| Pattern | Signals involved | Why it's dangerous |
|---|---|---|
| Indirect injection → exfiltration | LLM01 + ASI02 + LLM02 | Attacker injects via tool output, agent exfiltrates data |
| Goal hijack → code execution | ASI01 + ASI05 | Agent's goal is redirected to run arbitrary code |
| Supply chain → backdoor | ASI04 + ASI05 + ASI10 | Compromised tool leads to persistent backdoor |
| Memory poisoning → exfiltration | ASI06 + ASI01 + LLM02 | Poisoned memory causes data leak |
| Privilege escalation chain | ASI03 + ASI02 + LLM06 | Agent escalates its own permissions |
| Trust exploitation → fraud | ASI09 + ASI01 + LLM05 | Agent exploits user trust for fraudulent output |
| Cascading failure | ASI08 + ASI07 + ASI10 | One failure triggers a chain of failures |

---

## Current state — important context

Right now, a lot of the security checks in this service are **MVP-level implementations**. They're built to demonstrate the concept and show how the platform works, but they're not yet at the level of rigor you'd want for a production security product. The UI makes them look polished, but the underlying detection logic is still being hardened.

The 11 online checks have been moved from `interceptor.py` in the SDK into `consumers/security_eval/detectors/online.py` here. The SDK now calls `POST /v1/sdk/security/online-check` on the API (proxied here as `POST /v1/online-check`) instead of running detection locally. The detection source code stays private inside this service — clients never see it.

---

## The files and what they do

- `server/main.py` — the FastAPI app. Two endpoints: `POST /v1/evaluate` (async, post-session) and `POST /v1/online-check` (sync, real-time checks from SDK).
- `consumers/security_eval/consumer.py` — receives events and decides what to do with each type.
- `consumers/security_eval/scorer/orchestrator.py` — the main scoring pipeline. Calls everything else.
- `consumers/security_eval/scorer/llm_signals.py` — the 10 OWASP LLM signal functions.
- `consumers/security_eval/scorer/asi_signals.py` — the 10 OWASP ASI (Agentic AI) signal functions.
- `consumers/security_eval/scorer/attack_chains.py` — the 7 attack chain patterns.
- `consumers/security_eval/scorer/trust.py` — the Bayesian agent trust scoring.
- `consumers/security_eval/detectors/online.py` — the 11 online check functions moved here from the SDK. Entry point is `run_online_checks()`. Called by `POST /v1/online-check`.
- `consumers/security_eval/findings.py` — the `Finding` dataclass and database write functions.
- `core/security_config.py` — per-agent security config, cached in Redis.
- `db/postgres/` — 22 migration files.

---

## Where this fits in the bigger picture

```
dapplepot-sdk          ← calls POST /v1/sdk/security/online-check (via API) for blocking checks
    ↓
dapplepot-api          ← forwards events here via POST /v1/evaluate
    ↓
dapplepot-security     ← you are here
    ↓ (writes findings + scores to Postgres)
dapplepot-ui           ← displays findings, risk scores, agent trust
```

---

## Running the tests

### Unit tests — no infra needed

Tests `run_online_checks()` directly. Covers all 11 sub-checks with fire/silent/edge cases.

```bash
uv run pytest tests/unit/test_online_checks.py -v
```

### Integration test for the online-check endpoint

Needs the security service running locally on port 8001.

```bash
uvicorn server.main:app --port 8001
# then in another terminal:
python tests/integration/test_online_check_endpoint.py
```
