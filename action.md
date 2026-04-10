# action.md — dapplepot_security v3 Upgrade

> **Purpose:** Complete build spec for upgrading dapplepot_security from v2 to v3.
> Read this file completely before writing any code.
> Cross-reference `agent.md` for existing implementations — do not duplicate or contradict it.
> `agent.md` remains the source of truth for all v2 code. This file specifies only what changes.

---

## 0. Upgrade summary

| Dimension | v2 (current) | v3 (this upgrade) |
|-----------|-------------|-------------------|
| Sub-checks | 121 | 196 (+75 new) |
| Scoring model | max(sub-check) + weighted composite | Confidence-weighted + attack-chain amplification + cross-session Bayesian |
| Multi-agent | Single agent only | Multi-agent graph support (ASI07/08/10) |
| Cross-session | UBC-04a probe only | Full cross-session trend scoring + agent trust decay |
| Not-observed signals | OW-LLM03 only | OW-LLM03, OW-LLM04, OW-LLM08 (all pre-runtime) |
| Scorer version | `2.0.0` | `3.0.0` |

---

## 1. Gap analysis — OWASP scenarios vs current sub-checks

### 1.1 LLM Top 10 gaps

| Signal | OWASP scenario | Current sub-check | Gap | New sub-check |
|--------|---------------|-------------------|-----|---------------|
| **OW-LLM01** | Scenario 5: Code injection (CVE-2024-5184) | — | No code-injection-in-prompt detection | PI-05a |
| OW-LLM01 | Scenario 6: Payload splitting | — | No split-payload reassembly | PI-06a |
| OW-LLM01 | Scenario 7: Multimodal injection | — | No image/multimodal content flag | PI-07a |
| OW-LLM01 | Scenario 8: Adversarial suffix | — | No entropy/gibberish tail detection | PI-08a |
| OW-LLM01 | Scenario 9: Multilingual/obfuscated | — | No base64/ROT13/unicode obfuscation detection | PI-09a |
| **OW-LLM02** | Scenario 1: Cross-user data exposure | — | No cross-user context bleed detection | SID-03a |
| **OW-LLM03** | All scenarios | Excluded | Correct — pre-runtime | — (stays excluded) |
| **OW-LLM04** | All scenarios | DMP-01a, DMP-01c | **Mark not-observed** — pre-runtime data/model poisoning | — |
| **OW-LLM05** | Scenario 5: Email template injection | — | No email-specific injection in output | IOH-03a |
| OW-LLM05 | Scenario 6: Code gen with vulns | — | No insecure code pattern in output | IOH-04a |
| **OW-LLM06** | — (already good) | EAG-01a/02a/03a | Covered | — |
| **OW-LLM07** | — (already good) | SPL-01a/b, SPL-02a/b, SPL-03b | Covered | — |
| **OW-LLM08** | All scenarios | VEW-01b, VEW-02a | **Mark not-observed** — pre-runtime vector/embedding integrity | — |
| **OW-LLM09** | Scenario 1: Hallucinated packages | SAG-01a only | No hallucinated dependency detection | SAG-02a |
| OW-LLM09 | Scenario 2: Medical/safety misinfo | — | No high-stakes domain without grounding | SAG-03a |
| **OW-LLM10** | Scenario 1: Uncontrolled input size | — | No input size anomaly | UBC-02a |
| OW-LLM10 | Scenario 2: Repeated requests | — | No request rate spike per user | UBC-03a |
| OW-LLM10 | Scenario 4: Denial of Wallet | — | No cost spike detection | UBC-05a |
| OW-LLM10 | Scenario 5: Model replication | UBC-04a | Covered | — |

### 1.2 ASI Top 10 gaps

| Signal | OWASP scenario | Current sub-check | Gap | New sub-check |
|--------|---------------|-------------------|-----|---------------|
| **OW-ASI01** | Scenario 1: Zero-click indirect PI | AGH-01b only | No zero-click detection (tool output triggers action without user turn) | AGH-02a |
| OW-ASI01 | Scenario 3: Goal-lock drift via scheduled prompts | — | No drift detection across turns (objective reweighting) | AGH-03a |
| OW-ASI01 | Scenario 4: Inception attack (doc injects instructions) | — | No document-sourced instruction detection | AGH-04a |
| **OW-ASI02** | Scenario 1: Tool poisoning (descriptor/schema tamper) | — | No tool descriptor integrity check | TME-02a |
| OW-ASI02 | Scenario 3: Over-privileged API | — | No write-capable tool on read-only intent (beyond EAG-03a) | TME-04a |
| OW-ASI02 | Scenario 4: Cross-tool exfiltration chain | — | No outbound tool following sensitive-read tool | TME-05a |
| OW-ASI02 | Scenario 5: Tool name typosquatting | — | No Levenshtein similarity check on tool names | TME-06a |
| OW-ASI02 | Scenario 6: EDR bypass via tool chaining | — | No detection of admin-tool chain to external endpoint | TME-07a |
| OW-ASI02 | Scenario 7: Approved tool misuse (data exfil via DNS/ping) | — | No repetitive benign-tool invocation anomaly | TME-08a |
| **OW-ASI03** | Scenario 1: Delegated privilege abuse | IPA-01a only | No delegation-with-full-perms detection | IPA-02a |
| OW-ASI03 | Scenario 2: Memory-based credential reuse | — | No cached-credential-in-later-turn detection | IPA-03a |
| OW-ASI03 | Scenario 5: Workflow authorization drift | — | No stale-auth-token detection across session duration | IPA-04a |
| OW-ASI03 | Scenario 7: Identity sharing | — | No same-identity multi-user detection | IPA-05a |
| **OW-ASI04** | Scenario 2: MCP descriptor poisoning | ASCV-01a only | No MCP metadata integrity check | ASCV-02a |
| OW-ASI04 | Scenario 3: Malicious MCP server impersonation | — | No MCP server name similarity check | ASCV-03a |
| OW-ASI04 | Scenario 5: Compromised dependency auto-installed | — | No unknown-package-install in tool args | ASCV-04a |
| OW-ASI04 | Scenario 6: Agent card spoofing | — | No agent card descriptor anomaly (multi-agent) | ASCV-05a |
| **OW-ASI05** | Scenario 1: Runaway execution (self-repair loop) | RCE-01b, RCE-03a/b | No exec-loop detection (same tool > N times) | RCE-04a |
| OW-ASI05 | Scenario 3: Code hallucination with backdoor | — | No backdoor-pattern in generated code | RCE-05a |
| OW-ASI05 | Scenario 4: Unsafe deserialization | — | No pickle/marshal/yaml.load in tool args | RCE-06a |
| OW-ASI05 | Scenario 5: Multi-tool chain exploitation | — | No file-upload→path-traversal→code-load chain | RCE-07a |
| OW-ASI05 | Scenario 8: Lockfile poisoning | — | No lockfile-regen in tool args | RCE-08a |
| **OW-ASI06** | Scenario 2: Context window exploitation (cross-session) | MCP-01a only | No cross-session escalation pattern | MCP-02a |
| OW-ASI06 | Scenario 4: Shared memory poisoning | — | No poisoned-fact-in-memory detection | MCP-03a |
| OW-ASI06 | Scenario 5: Cross-tenant vector bleed | — | No cross-tenant retrieval anomaly | MCP-04a |
| OW-ASI06 | Scenario 6: Assistant memory poisoning via indirect PI | — | No memory-write after indirect injection | MCP-05a |
| **OW-ASI07** | Scenario 1: Semantic injection via unencrypted comms | IAC-01a only | No unencrypted inter-agent channel detection | IAC-02a |
| OW-ASI07 | Scenario 3: Replay attack | — | No duplicate message ID detection | IAC-03a |
| OW-ASI07 | Scenario 5: MCP descriptor poisoning (inter-agent) | — | No MCP-routed inter-agent data flow anomaly | IAC-04a |
| OW-ASI07 | Scenario 6: A2A registration spoofing | — | No unknown agent ID in delegation chain | IAC-05a |
| OW-ASI07 | Scenario 7: Semantics split-brain | — | No divergent-intent detection across agents | IAC-06a |
| **OW-ASI08** | Scenario 1-5: Cross-agent cascade patterns | CF-01a only | No multi-node error propagation pattern | CF-02a |
| OW-ASI08 | Scenario 6: Auto-remediation feedback loop | — | No suppress-alert→widen-automation loop | CF-03a |
| OW-ASI08 | Scenario 8: Hallucination propagation | — | No false-positive cascade in defense agents | CF-04a |
| **OW-ASI09** | Scenario 2: Credential harvesting via deception | HAT-01a only | No credential-request in agent output | HAT-02a |
| OW-ASI09 | Scenario 3: Invoice/payment fraud | — | No payment-detail change in agent output | HAT-03a |
| OW-ASI09 | Scenario 4: Explainability fabrication | — | No fabricated-rationale-before-destructive-action | HAT-04a |
| OW-ASI09 | Scenario 6: Consent laundering | — | No side-effect-on-preview detection | HAT-05a |
| **OW-ASI10** | Scenario 1: Persistent autonomous data exfil | RA-01a only | No persistent-exfil-pattern across sessions | RA-02a |
| OW-ASI10 | Scenario 2: Impersonated observer agent | — | No fake-approval-agent in workflow | RA-03a |
| OW-ASI10 | Scenario 3: Self-replication via provisioning | — | No spawn/clone tool invocation detection | RA-04a |
| OW-ASI10 | Scenario 4: Reward hacking (destructive optimization) | — | No destructive-action-to-meet-metric pattern | RA-05a |

---

## 2. Not-observed signals (pre-runtime, mark excluded)

These signals detect threats at the training, data, or model layer — not observable from runtime session events.
Keep them in `signal_registry` but set `excluded = true` and `exclusion_reason`.

| Signal | Sub-checks | Exclusion reason |
|--------|-----------|-----------------|
| OW-LLM03 | — (already excluded) | Training data poisoning — not detectable at inference time |
| OW-LLM04 | DMP-01a, DMP-01c | Data/model poisoning — pre-runtime; RAG data integrity requires offline pipeline checks |
| OW-LLM08 | VEW-01b, VEW-02a | Vector/embedding weakness — pre-runtime; vector DB integrity requires offline audit |

**Implementation:**
- In `scripts/seed_signal_registry.py`: set `excluded=True`, `detection_phase='excluded'`, `exclusion_reason` for DMP-01a/c and VEW-01b/02a.
- In `scorer/llm_signals.py`: `signal_ow_llm04` and `signal_ow_llm08` return `None` immediately with a comment noting pre-runtime exclusion.
- In `scorer/orchestrator.py`: excluded signals report `{"status": "not_observed", "score": 0, "reason": "pre-runtime"}` in `ow_llm_signal_status`.
- In composite score calculation: excluded signals are omitted from the fired list AND the mean calculation.

---

## 3. New sub-check specifications (75 new sub-checks)

### 3.1 Detection phase classification

| Phase | Meaning | Where it runs |
|-------|---------|---------------|
| `per_event` | Runs inside `_run_per_event_detectors()` during ClickHouse replay | `detectors/*.py` |
| `post_session` | Runs as a signal function after all events replayed | `scorer/llm_signals.py` or `scorer/asi_signals.py` |
| `cross_session` | Requires historical data from prior sessions | `scorer/cross_session.py` (new file) |
| `excluded` | Not observable at runtime | Stored in registry, always returns `not_observed` |

### 3.2 New LLM sub-checks

---

#### PI-05a — Code injection pattern in prompt
**Signal:** OW-LLM01 | **Score:** 80 | **Severity:** high | **Phase:** per_event
**Detector:** `injection.py` | **Runs on:** `llm_start`

```
Logic:
  For each message with role in (user, human, tool):
    Match content against CODE_INJECTION_PATTERNS:
      - r"(?i)(import\s+os|import\s+subprocess|__import__|eval\s*\(|exec\s*\()"
      - r"(?i)(os\.system|subprocess\.\w+|open\s*\(.+['\"]w['\"])"
      - r"(?i)(require\s*\(\s*['\"]child_process|\.exec\s*\(|spawn\s*\()"
    If match AND message.role != 'system':
      Fire PI-05a with matched_text (redacted, 200 char truncation)
```

---

#### PI-06a — Payload splitting across messages
**Signal:** OW-LLM01 | **Score:** 88 | **Severity:** high | **Phase:** post_session
**Function:** `check_payload_splitting()` in `llm_signals.py`

```
Logic:
  Collect all user-role messages across llm_start events.
  For each sliding window of 3 consecutive user messages:
    Concatenate content (space-joined).
    Run concatenated text against _REGEX_SIGNATURES from injection.py.
    If match found but NO individual message matched alone:
      Fire PI-06a. Detail: "Split payload detected across messages {i}..{i+2}"
      check_score: 88
```

---

#### PI-07a — Multimodal content flag
**Signal:** OW-LLM01 | **Score:** 60 | **Severity:** medium | **Phase:** per_event
**Detector:** `injection.py` | **Runs on:** `llm_start`

```
Logic:
  For each message in payload.messages:
    If message.content is a list (multimodal) AND contains type=="image_url" or type=="image":
      AND any text-type content in same message matches has_partial_injection_signal():
        Fire PI-07a. Detail: "Multimodal message with injection-adjacent text"
  Note: We cannot inspect image bytes post-session. This flags co-occurrence only.
  Score is lower (60) to reflect reduced confidence.
```

---

#### PI-08a — Adversarial suffix (high-entropy tail)
**Signal:** OW-LLM01 | **Score:** 75 | **Severity:** high | **Phase:** per_event
**Detector:** `injection.py` | **Runs on:** `llm_start`

```
Logic:
  For each user/human message:
    Extract last 100 characters of content.
    Compute character-level entropy: H = -Σ p(c) log2 p(c)
    If H > 4.5 AND len(tail) >= 40 AND tail contains non-ASCII or repeated special chars:
      Fire PI-08a. Detail: "High-entropy suffix detected (H={H:.2f})"
  Rationale: Adversarial suffixes (GCG-style) have high entropy and low semantic content.
```

---

#### PI-09a — Obfuscated/encoded injection
**Signal:** OW-LLM01 | **Score:** 82 | **Severity:** high | **Phase:** per_event
**Detector:** `injection.py` | **Runs on:** `llm_start`

```
Logic:
  For each user/human/tool message:
    1. Attempt base64 decode of any substring matching r"[A-Za-z0-9+/]{20,}={0,2}"
       If decoded text matches _REGEX_SIGNATURES: Fire PI-09a
    2. Check for ROT13: apply ROT13 to full content, check against _REGEX_SIGNATURES
    3. Check for unicode homoglyph substitution:
       Normalize content with unicodedata.normalize('NFKC', content)
       If normalized != original AND normalized matches _REGEX_SIGNATURES: Fire PI-09a
    4. Check for hex-encoded sequences: r"(?:\\x[0-9a-f]{2}){4,}"
       Decode and check against _REGEX_SIGNATURES
  Detail: "Obfuscated injection detected (method: {base64|rot13|homoglyph|hex})"
```

---

#### SID-03a — Cross-user context bleed
**Signal:** OW-LLM02 | **Score:** 95 | **Severity:** critical | **Phase:** cross_session
**Function:** `check_cross_user_bleed()` in `cross_session.py`

```
Logic:
  Query ClickHouse for all llm_end events in this session.
  For each completion text:
    Extract PII matches (reuse disclosure.py patterns).
    For each PII match:
      Query ClickHouse obs_events for the same tenant_id but DIFFERENT user_context_id
      within the last 24 hours where payload contains the same PII pattern hash.
      If found: the model is leaking PII from user A to user B.
      Fire SID-03a. Detail: "PII pattern found in completion that matches another user's session"
  Note: Uses PII hash comparison, never raw PII. Requires user_context_id in obs_events.
```

---

#### IOH-03a — Email template injection in output
**Signal:** OW-LLM05 | **Score:** 80 | **Severity:** high | **Phase:** per_event
**Detector:** `passthrough.py` | **Runs on:** `tool_start`

```
Logic:
  If tool_name matches r"(?i)(email|mail|send|notify|message)":
    Check tool_input for:
      - r"(?i)<script|javascript:|on\w+\s*=" (XSS in email)
      - r"(?i)(href|src)\s*=\s*['\"]https?://(?!.*company_domain)" (external link injection)
      - r"(?i)<!--.*inject|hidden.*display:\s*none" (hidden content)
    If match: Fire IOH-03a
```

---

#### IOH-04a — Insecure code pattern in generated output
**Signal:** OW-LLM05 | **Score:** 70 | **Severity:** high | **Phase:** post_session
**Function:** `check_insecure_code_output()` in `llm_signals.py`

```
Logic:
  For each llm_end event where completion contains code fences (``` blocks):
    Extract code content.
    Check against INSECURE_CODE_PATTERNS:
      - r"eval\s*\(" (arbitrary eval)
      - r"(?i)password\s*=\s*['\"][^'\"]+['\"]" (hardcoded password)
      - r"(?i)verify\s*=\s*False" (disabled TLS verification)
      - r"(?i)shell\s*=\s*True" (subprocess shell=True)
      - r"(?i)innerHTML\s*=" (DOM XSS)
      - r"(?i)SELECT\s.+FROM\s.+WHERE\s.+['\"]?\s*\+\s*" (SQL concatenation)
      - r"(?i)pickle\.loads?\s*\(" (unsafe deserialization)
      - r"(?i)yaml\.load\s*\(" (unsafe YAML load)
    If >= 1 match: Fire IOH-04a. Detail lists matched patterns.
  Note: Lower score (70) — code generation is expected behavior; this flags risky patterns.
```

---

#### SAG-02a — Hallucinated package reference
**Signal:** OW-LLM09 | **Score:** 65 | **Severity:** medium | **Phase:** post_session
**Function:** `check_hallucinated_packages()` in `llm_signals.py`

```
Logic:
  For each llm_end completion containing code fences:
    Extract package install commands:
      - r"pip install\s+([\w\-]+)" → Python package name
      - r"npm install\s+([\w\-@/]+)" → npm package name
    For each extracted package:
      Check against KNOWN_HALLUCINATED_PACKAGES set (maintained in config, seeded with
      documented cases: e.g., "huggingface-cli", "openai-python", etc.)
      Also: flag any package name that is a single common English word (len < 4, in ENGLISH_WORDS set)
    If match: Fire SAG-02a. Detail: "Potentially hallucinated package: {name}"
  Note: This is heuristic. False positive rate expected ~5%. Score 65 reflects uncertainty.
  Future: integrate with PyPI/npm API for existence validation (requires network access).
```

---

#### SAG-03a — High-stakes domain output without grounding
**Signal:** OW-LLM09 | **Score:** 60 | **Severity:** medium | **Phase:** post_session
**Function:** `check_ungrounded_high_stakes()` in `llm_signals.py`

```
Logic:
  HIGH_STAKES_DOMAINS = {
    "medical": r"(?i)(dosage|prescri|diagnos|medication|symptom|treatment|drug\s+interact)",
    "legal":   r"(?i)(legal\s+advice|lawsuit|liability|statute|regulation\s+require)",
    "financial": r"(?i)(invest|buy\s+stock|sell\s+stock|financial\s+advice|guaranteed\s+return)"
  }
  For each llm_end completion:
    If any HIGH_STAKES_DOMAINS pattern matches:
      Check session events for presence of RAG/retrieval tool calls (tool_name matches
      r"(?i)(search|retrieve|lookup|query|fetch|rag)").
      If NO retrieval tool was used in this session AND no interrupt_raised event exists:
        Fire SAG-03a. Detail: "High-stakes {domain} output without retrieval grounding or HITL"
```

---

#### UBC-02a — Input size anomaly
**Signal:** OW-LLM10 | **Score:** 50 | **Severity:** medium | **Phase:** post_session
**Function:** `check_input_size_anomaly()` in `llm_signals.py`

```
Logic:
  For this session: sum(llm_input_tokens) from obs_events.
  Query 7-day baseline for this agent_id:
    SELECT avg(input_tokens), stddev(input_tokens) FROM obs_session_tokens
    WHERE tenant_id = $1 AND session_id IN (
      SELECT session_id FROM obs_events
      WHERE agent_id = $2 AND emitted_at > now() - INTERVAL 7 DAY
    )
  If session_input_tokens > baseline_avg + 4 * baseline_stddev:
    Fire UBC-02a. Score: 50. Detail: "Input tokens {n} exceeds 4σ above baseline {avg:.0f}"
```

---

#### UBC-03a — Request rate spike
**Signal:** OW-LLM10 | **Score:** 55 | **Severity:** medium | **Phase:** cross_session
**Function:** `check_request_rate_spike()` in `cross_session.py`

```
Logic:
  Count sessions for this user_context_id in the last 1 hour.
  Query baseline: avg sessions per hour for this user_context_id over 7 days.
  If current_hour_count > max(baseline_avg * 5, 20):
    Fire UBC-03a. Detail: "User session rate {n}/hr exceeds 5x baseline {avg:.1f}/hr"
```

---

#### UBC-05a — Cost spike (Denial of Wallet)
**Signal:** OW-LLM10 | **Score:** 60 | **Severity:** high | **Phase:** cross_session
**Function:** `check_cost_spike()` in `cross_session.py`

```
Logic:
  Compute session cost estimate:
    total_input_tokens * INPUT_COST_PER_1K + total_output_tokens * OUTPUT_COST_PER_1K
    (costs configurable in config.py, default to GPT-4 pricing as proxy)
  Query 7-day daily cost baseline for this agent_id.
  If today's cumulative cost > baseline_daily_avg * 3:
    Fire UBC-05a. Detail: "Estimated daily cost ${today:.2f} exceeds 3x baseline ${avg:.2f}/day"
```

---

### 3.3 New ASI sub-checks

---

#### AGH-02a — Zero-click goal hijack (tool output triggers action without intervening user turn)
**Signal:** OW-ASI01 | **Score:** 85 | **Severity:** high | **Phase:** post_session
**Function:** `signal_a01_zero_click()` in `asi_signals.py`

```
Logic:
  Replay events in order. Track:
    last_event_with_user_input = None  (llm_start where any message.role == 'user')
    tool_outputs_since_user = []
  For each event:
    If llm_start with user message: reset tool_outputs_since_user = []
    If tool_end: append to tool_outputs_since_user
    If tool_start AND len(tool_outputs_since_user) > 0 AND last_event_with_user_input is None:
      # Agent is invoking tools based purely on prior tool output, no user ever spoke
      Check if any tool in tool_outputs_since_user has output matching injection patterns
      If yes: Fire AGH-02a. Detail: "Tool invoked without user input; prior tool output contains injection pattern"
  Also fires if: > 5 consecutive tool_start events with no intervening llm_start containing user message.
```

---

#### AGH-03a — Goal drift detection (objective shift across turns)
**Signal:** OW-ASI01 | **Score:** 70 | **Severity:** medium | **Phase:** post_session
**Function:** `signal_a01_goal_drift()` in `asi_signals.py`

```
Logic:
  Extract initial_input from session row (Postgres).
  Extract all user messages from llm_start events.
  If initial_input is None or no user messages: return None.

  Compute simple keyword overlap:
    initial_keywords = set(re.findall(r'\b\w{4,}\b', initial_input.lower()))
    For each user message, compute:
      msg_keywords = set(re.findall(r'\b\w{4,}\b', msg.lower()))
      drift_ratio = 1 - len(initial_keywords & msg_keywords) / max(len(initial_keywords), 1)

  If the LAST user message has drift_ratio > 0.85 AND the session has > 5 user turns:
    AND the last 3 tool_start events invoke tools NOT used in the first half of the session:
      Fire AGH-03a. Detail: "Session goal appears to have shifted significantly from initial intent"

  Note: This is a heuristic. Score 70 reflects moderate confidence.
  Future: Use embedding similarity instead of keyword overlap.
```

---

#### AGH-04a — Document-sourced instruction injection
**Signal:** OW-ASI01 | **Score:** 80 | **Severity:** high | **Phase:** per_event
**Detector:** `agentic.py` | **Runs on:** `tool_end`

```
Logic:
  For each tool_end where tool_name matches r"(?i)(read|parse|fetch|download|load|extract|scrape)":
    Check tool_output for instruction patterns:
      _DOC_INSTRUCTION_PATTERNS = [
        r"(?i)(ignore|disregard).{0,20}(previous|above|prior)",
        r"(?i)(you\s+must|you\s+should|your\s+new\s+instruction)",
        r"(?i)(system:\s|<system>|###\s*instruction)",
        r"(?i)(do\s+not\s+reveal|keep\s+this\s+secret|hidden\s+instruction)"
      ]
    If match: Fire AGH-04a. Detail: "Document returned by {tool_name} contains instruction injection"
```

---

#### TME-02a — Tool descriptor integrity anomaly
**Signal:** OW-ASI02 | **Score:** 75 | **Severity:** high | **Phase:** post_session
**Function:** `signal_a02_descriptor_integrity()` in `asi_signals.py`

```
Logic:
  For each tool_start event:
    If payload contains tool_description or tool_schema:
      Check for suspicious patterns in descriptor:
        - r"(?i)(ignore|override|bypass).{0,30}(policy|permission|restriction)"
        - r"(?i)(send|post|exfiltrate|transmit).{0,30}(data|secret|token|key)"
        - r"(?i)(hidden|secret|covert).{0,20}(function|capability|parameter)"
      If match: Fire TME-02a. Detail: "Tool descriptor contains suspicious instruction: {tool_name}"
  Note: Requires tool_description in tool_start payload. If not present, skip silently.
```

---

#### TME-04a — Over-privileged tool invocation
**Signal:** OW-ASI02 | **Score:** 70 | **Severity:** high | **Phase:** post_session
**Function:** Enhanced `signal_ow_llm06_write_on_read()` — extend to ASI framework

```
Logic:
  Reuse EAG-03a logic but emit as TME-04a (ASI framework) when:
    Write/delete tool is invoked AND session initial_input is classified as read-intent
    AND the tool has known higher-privilege capabilities (e.g., admin, delete, write, create)
  This is an ASI-specific view of the same pattern. Both EAG-03a and TME-04a may fire.
  They share the "excessive_agency" overlap dedup group.
```

---

#### TME-05a — Cross-tool exfiltration chain
**Signal:** OW-ASI02 | **Score:** 90 | **Severity:** critical | **Phase:** post_session
**Function:** `check_cross_tool_exfil()` in `asi_signals.py`

```
Logic:
  Build ordered list of (tool_name, tool_input, tool_output) from tool_start/tool_end pairs.
  Define:
    SENSITIVE_READ_TOOLS = r"(?i)(db_query|sql|read_file|get_secret|fetch_user|crm|lookup)"
    OUTBOUND_TOOLS = r"(?i)(send_email|http_post|webhook|slack|api_call|upload|notify|curl)"

  For each pair of consecutive tool invocations (A, B):
    If A.tool_name matches SENSITIVE_READ_TOOLS AND B.tool_name matches OUTBOUND_TOOLS:
      Compute LCS ratio between A.tool_output and B.tool_input (if both available as text).
      If LCS_ratio >= 0.30:
        Fire TME-05a. Detail: "Sensitive data from {A.tool_name} forwarded to {B.tool_name} (LCS {ratio:.0%})"

  Also check non-consecutive pairs within a window of 5 tool invocations.
```

---

#### TME-06a — Tool name typosquatting
**Signal:** OW-ASI02 | **Score:** 70 | **Severity:** high | **Phase:** post_session
**Function:** `check_tool_typosquatting()` in `asi_signals.py`

```
Logic:
  Collect all unique tool_names invoked in session.
  Load TOOL_MANIFESTS[agent_id] (known-good tool names).
  For each invoked tool_name NOT in manifest:
    Compute Levenshtein distance to each manifest tool.
    If min_distance <= 2 AND min_distance > 0:
      Fire TME-06a. Detail: "Tool '{invoked}' not in manifest; similar to '{closest}' (edit distance {d})"
  Requires python-Levenshtein or builtin difflib.
```

---

#### TME-07a — Admin tool chain to external endpoint
**Signal:** OW-ASI02 | **Score:** 88 | **Severity:** critical | **Phase:** post_session
**Function:** `check_admin_chain_exfil()` in `asi_signals.py`

```
Logic:
  ADMIN_TOOLS = r"(?i)(powershell|cmd|bash|shell|admin|sudo|ssh|kubectl)"
  EXTERNAL_INDICATORS = r"(?i)(curl|wget|http://|https://|ftp://|\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)"

  For each tool_start where tool_name matches ADMIN_TOOLS:
    If tool_input (as string) matches EXTERNAL_INDICATORS:
      Fire TME-07a. Detail: "Admin tool {tool_name} invoked with external endpoint in args"
```

---

#### TME-08a — Repetitive benign tool misuse (data exfil via side-channel)
**Signal:** OW-ASI02 | **Score:** 65 | **Severity:** medium | **Phase:** post_session
**Function:** `check_repetitive_tool_misuse()` in `asi_signals.py`

```
Logic:
  Count invocations per tool_name in session.
  BENIGN_TOOLS = r"(?i)(ping|dns|nslookup|traceroute|health_check|status)"
  For each tool matching BENIGN_TOOLS:
    If invocation_count > 10:
      Fire TME-08a. Detail: "{tool_name} invoked {count} times — possible side-channel exfiltration"
```

---

#### IPA-02a — Delegation with full permissions
**Signal:** OW-ASI03 | **Score:** 80 | **Severity:** high | **Phase:** post_session
**Function:** `check_delegation_abuse()` in `asi_signals.py`

```
Logic:
  For each tool_start where tool_name matches r"(?i)(delegate|dispatch|invoke_agent|call_agent|forward)":
    Check tool_input for:
      - permissions/role field that includes "*", "admin", "all", or matches the parent agent's full permission set
      - absence of any scope restriction
    If found: Fire IPA-02a. Detail: "Delegation to sub-agent with unrestricted permissions"
  Note: Multi-agent prep — will fire once delegation tools appear in graphs.
```

---

#### IPA-03a — Cached credential reuse in later context
**Signal:** OW-ASI03 | **Score:** 85 | **Severity:** critical | **Phase:** post_session
**Function:** `check_credential_reuse()` in `asi_signals.py`

```
Logic:
  Scan all tool_start payloads for credential-like values:
    CREDENTIAL_PATTERNS = r"(?i)(password|token|secret|api_key|ssh_key|bearer)\s*[:=]\s*\S+"
  Track first_seen_event_id for each credential hash.
  If same credential hash appears in a tool_start > 5 events later:
    Fire IPA-03a. Detail: "Credential first seen at event {first} reused at event {current}"
  Note: Uses hash of matched credential, never stores raw value.
```

---

#### IPA-04a — Stale authorization (long-running session)
**Signal:** OW-ASI03 | **Score:** 65 | **Severity:** medium | **Phase:** post_session
**Function:** `check_stale_auth()` in `asi_signals.py`

```
Logic:
  If session.duration_ms > 3600000 (1 hour):
    Check for any tool_start with auth-related args after the first 30 minutes
    that reuses the same auth token from the session start.
    If yes AND no interrupt_raised/interrupt_resumed event in between:
      Fire IPA-04a. Detail: "Auth token from session start reused after {minutes}min without re-validation"
```

---

#### IPA-05a — Identity sharing across users
**Signal:** OW-ASI03 | **Score:** 75 | **Severity:** high | **Phase:** cross_session
**Function:** `check_identity_sharing()` in `cross_session.py`

```
Logic:
  Query obs_events for this agent_id in the last 24 hours.
  Group by user_context_id.
  If the same tool_name + tool_input credential hash appears across > 1 user_context_id:
    Fire IPA-05a. Detail: "Agent identity/credential shared across {n} distinct users"
```

---

#### ASCV-02a — MCP descriptor poisoning
**Signal:** OW-ASI04 | **Score:** 80 | **Severity:** high | **Phase:** per_event
**Detector:** `agentic.py` | **Runs on:** `tool_start`

```
Logic:
  If payload contains mcp_tool_description or tool_metadata:
    Check for injection patterns in descriptor text:
      - Reuse _CONTEXT_INJECTION_PATTERNS from agentic.py
      - Additional: r"(?i)(exfiltrate|steal|forward\s+to|send\s+to\s+http)"
    If match: Fire ASCV-02a. Detail: "MCP tool descriptor contains suspicious instructions"
```

---

#### ASCV-03a — MCP server impersonation (name similarity)
**Signal:** OW-ASI04 | **Score:** 75 | **Severity:** high | **Phase:** post_session
**Function:** `check_mcp_impersonation()` in `asi_signals.py`

```
Logic:
  Collect all MCP server names from tool_start payloads (if present in metadata).
  Compare each against KNOWN_MCP_SERVERS list (configurable, seeded with common services:
    "postmark", "stripe", "github", "slack", "asana", "gmail", "salesforce", etc.)
  For each server name:
    If Levenshtein distance to any known server <= 2 AND name != known server:
      Fire ASCV-03a. Detail: "MCP server name '{name}' similar to known service '{known}'"
```

---

#### ASCV-04a — Unknown package install in tool execution
**Signal:** OW-ASI04 | **Score:** 85 | **Severity:** critical | **Phase:** per_event
**Detector:** `agentic.py` | **Runs on:** `tool_start`

```
Logic:
  Check tool_input (as string) for package install commands:
    - r"(?i)(pip\s+install|npm\s+install|yarn\s+add|gem\s+install|cargo\s+install)\s+([\w\-@/]+)"
  If found: Fire ASCV-04a. Detail: "Package install command in tool execution: {command}"
  Rationale: Runtime package installation is a supply chain risk regardless of package name.
```

---

#### ASCV-05a — Agent card descriptor anomaly
**Signal:** OW-ASI04 | **Score:** 70 | **Severity:** high | **Phase:** post_session
**Function:** `check_agent_card_anomaly()` in `asi_signals.py`

```
Logic:
  Multi-agent prep. For each tool_start involving agent delegation:
    If payload contains agent_card or agent_descriptor:
      Check for capability claims that don't match known agent registry.
      Check for injection patterns in descriptor.
    If suspicious: Fire ASCV-05a.
  Note: This will be skeletal until multi-agent is fully supported.
  Returns None for single-agent sessions.
```

---

#### RCE-04a — Execution loop (same tool invoked > N times)
**Signal:** OW-ASI05 | **Score:** 80 | **Severity:** high | **Phase:** post_session
**Function:** `check_exec_loop()` in `asi_signals.py`

```
Logic:
  Count consecutive invocations of the same tool_name (allowing max 1 different tool in between).
  EXEC_TOOLS = r"(?i)(exec|execute|run|eval|shell|bash|sh|cmd|code_interpreter)"
  If any exec-matching tool has consecutive_count >= 5:
    Fire RCE-04a. Detail: "{tool_name} invoked {count} consecutive times — possible runaway execution"
```

---

#### RCE-05a — Backdoor pattern in generated code
**Signal:** OW-ASI05 | **Score:** 85 | **Severity:** critical | **Phase:** post_session
**Function:** `check_code_backdoor()` in `asi_signals.py`

```
Logic:
  For each llm_end completion containing code:
    BACKDOOR_PATTERNS = [
      r"(?i)reverse.{0,10}shell",
      r"(?i)socket\.connect\s*\(\s*\(",
      r"(?i)bind\s*\(\s*\(\s*['\"]0\.0\.0\.0",
      r"(?i)nc\s+-[lv]*\s+.*\d+",  # netcat listener
      r"(?i)subprocess\.Popen\s*\(\s*\[.*sh.*-c",
      r"(?i)crypto\.createCipher",  # deprecated, often used in backdoors
      r"(?i)btoa\s*\(.*document\.cookie",  # cookie exfil
      r"(?i)fetch\s*\(\s*['\"]https?://\d{1,3}\.\d{1,3}",  # IP-based exfil
    ]
    If match: Fire RCE-05a. Detail: "Potential backdoor pattern in generated code"
```

---

#### RCE-06a — Unsafe deserialization in tool args
**Signal:** OW-ASI05 | **Score:** 90 | **Severity:** critical | **Phase:** per_event
**Detector:** `agentic.py` | **Runs on:** `tool_start`

```
Logic:
  Check tool_input (as string) for:
    - r"(?i)(pickle\.loads?|marshal\.loads?|yaml\.load\s*\((?!.*Loader=SafeLoader))"
    - r"(?i)(shelve\.open|dill\.loads?|cloudpickle\.loads?)"
    - r"(?i)(__reduce__|__getstate__|__setstate__)"
  If match: Fire RCE-06a. Detail: "Unsafe deserialization in tool args: {tool_name}"
```

---

#### RCE-07a — Multi-tool chain exploitation (upload→traverse→execute)
**Signal:** OW-ASI05 | **Score:** 92 | **Severity:** critical | **Phase:** post_session
**Function:** `check_multi_tool_chain_exploit()` in `asi_signals.py`

```
Logic:
  Build ordered tool list from tool_start events.
  Look for chain pattern within any window of 5 consecutive tools:
    Step 1: tool_name matches r"(?i)(upload|write_file|save|store)"
    Step 2: tool_input contains path traversal: r"\.\./|\.\.\\|%2e%2e"
    Step 3: tool_name matches r"(?i)(exec|run|load|import|require|eval)"
  If all 3 steps present in window:
    Fire RCE-07a. Detail: "Multi-tool chain: upload→traversal→execution detected"
```

---

#### RCE-08a — Lockfile regeneration in tool args
**Signal:** OW-ASI05 | **Score:** 75 | **Severity:** high | **Phase:** per_event
**Detector:** `agentic.py` | **Runs on:** `tool_start`

```
Logic:
  Check tool_input for lockfile manipulation:
    - r"(?i)(rm|delete|remove).{0,20}(package-lock|yarn\.lock|Pipfile\.lock|poetry\.lock|Cargo\.lock)"
    - r"(?i)(npm\s+install|pip\s+install|yarn).{0,10}(--no-frozen|--force)"
  If match: Fire RCE-08a. Detail: "Lockfile manipulation in tool execution"
```

---

#### MCP-02a — Cross-session escalation pattern
**Signal:** OW-ASI06 | **Score:** 80 | **Severity:** high | **Phase:** cross_session
**Function:** `check_cross_session_escalation()` in `cross_session.py`

```
Logic:
  Query last 10 sessions for this user_context_id + agent_id.
  For each session, check if any tool_start was blocked (tool_error with permission/denied in error_message).
  Track the sequence: if blocked-tool-name appears as successfully invoked in a LATER session:
    Fire MCP-02a. Detail: "Tool '{tool}' blocked in session {old} but succeeded in session {current}"
  Rationale: Attacker probing permission boundaries across sessions.
```

---

#### MCP-03a — Poisoned fact in memory/context
**Signal:** OW-ASI06 | **Score:** 75 | **Severity:** high | **Phase:** per_event
**Detector:** `agentic.py` | **Runs on:** `tool_end`

```
Logic:
  For tool_end where tool_name matches r"(?i)(memory|remember|store_fact|add_context|update_memory)":
    Check tool_output AND tool_input for:
      - Contradicts common facts: not feasible without knowledge base
      - Contains injection patterns (reuse _CONTEXT_INJECTION_PATTERNS)
      - Contains URLs or encoded data: r"https?://\S+" or base64 patterns
    If injection pattern found in memory write: Fire MCP-03a
    Detail: "Memory/context write contains suspicious content"
```

---

#### MCP-04a — Cross-tenant retrieval anomaly
**Signal:** OW-ASI06 | **Score:** 95 | **Severity:** critical | **Phase:** cross_session
**Function:** `check_cross_tenant_retrieval()` in `cross_session.py`

```
Logic:
  For each tool_end where tool_name matches r"(?i)(retrieve|rag|search|vector_search|similarity)":
    Extract any identifiers from tool_output (UUIDs, tenant IDs, user IDs).
    If any extracted tenant_id != session.tenant_id:
      Fire MCP-04a. Detail: "Retrieval result contains cross-tenant identifier"
  Note: High score (95) — cross-tenant data leakage is critical.
```

---

#### MCP-05a — Memory write after indirect injection
**Signal:** OW-ASI06 | **Score:** 88 | **Severity:** critical | **Phase:** post_session
**Function:** `check_memory_write_after_injection()` in `asi_signals.py`

```
Logic:
  Replay events in order. Track:
    injection_detected = False (set when any PI-* or AGH-* finding fires)
  After injection_detected = True:
    If any subsequent tool_start matches r"(?i)(memory|remember|store|persist|save_context)":
      Fire MCP-05a. Detail: "Memory write occurred after injection signal at event {injection_event}"
  Rationale: Attacker poisoning persistent memory via indirect injection.
```

---

#### IAC-02a — Unencrypted inter-agent communication
**Signal:** OW-ASI07 | **Score:** 80 | **Severity:** high | **Phase:** post_session
**Function:** Enhanced `signal_a07()` in `asi_signals.py`

```
Logic:
  For each tool_start matching delegation/inter-agent patterns:
    If tool_input contains URL matching r"^http://" (not https):
      Fire IAC-02a. Detail: "Inter-agent communication over unencrypted HTTP"
    If tool_input contains raw credential in plaintext (reuse CREDENTIAL_PATTERNS):
      Fire IAC-02a. Detail: "Credential transmitted in plaintext during inter-agent call"
  Multi-agent prep — will activate when delegation tools appear.
```

---

#### IAC-03a — Replay attack (duplicate message/request IDs)
**Signal:** OW-ASI07 | **Score:** 75 | **Severity:** high | **Phase:** post_session
**Function:** `check_replay_attack()` in `asi_signals.py`

```
Logic:
  Collect all request_id / message_id / correlation_id from tool_start payloads.
  If any ID appears > 1 time within the session:
    Fire IAC-03a. Detail: "Duplicate request ID '{id}' detected — possible replay attack"
```

---

#### IAC-04a — MCP-routed inter-agent data anomaly
**Signal:** OW-ASI07 | **Score:** 80 | **Severity:** high | **Phase:** post_session

```
Logic:
  For tool invocations routed through MCP:
    If tool_output size > 10x tool_input size AND tool_name matches inter-agent pattern:
      Flag as potential data exfiltration via inter-agent channel.
      Fire IAC-04a. Detail: "Disproportionate data volume in inter-agent MCP call"
```

---

#### IAC-05a — Unknown agent in delegation chain
**Signal:** OW-ASI07 | **Score:** 85 | **Severity:** critical | **Phase:** post_session

```
Logic:
  For each tool_start matching delegation patterns:
    Extract target_agent_id from tool_input.
    Query Postgres agents table: does this agent_id exist for this tenant?
    If not: Fire IAC-05a. Detail: "Delegation to unknown agent ID '{id}'"
```

---

#### IAC-06a — Semantics split-brain
**Signal:** OW-ASI07 | **Score:** 65 | **Severity:** medium | **Phase:** post_session

```
Logic:
  Multi-agent prep. In multi-agent graphs:
    If two nodes receive the same input but produce contradictory tool invocations
    (e.g., one writes, one deletes the same resource):
      Fire IAC-06a.
  For single-agent: returns None. Skeleton implementation.
```

---

#### CF-02a — Multi-node error propagation
**Signal:** OW-ASI08 | **Score:** 75 | **Severity:** high | **Phase:** post_session

```
Logic:
  Count distinct node_names that have node_error events in this session.
  If >= 3 different nodes errored:
    Fire CF-02a. Detail: "{n} distinct nodes failed — possible cascading failure"
  Also: if a node_error is followed by > 3 tool_error events in subsequent nodes:
    Fire CF-02a with higher detail.
```

---

#### CF-03a — Auto-remediation feedback loop
**Signal:** OW-ASI08 | **Score:** 70 | **Severity:** high | **Phase:** post_session

```
Logic:
  Track error→retry→error patterns:
    If the same node_name appears in node_start→node_error→node_start→node_error
    more than 3 times:
      Fire CF-03a. Detail: "Node '{node}' in error-retry loop ({count} cycles)"
```

---

#### CF-04a — Hallucination propagation in defense agents
**Signal:** OW-ASI08 | **Score:** 65 | **Severity:** medium | **Phase:** post_session

```
Logic:
  Multi-agent prep. Skeleton for v3. Returns None for single-agent.
  When multi-agent is supported:
    Track if a hallucinated output from one agent is consumed by a security/defense agent
    leading to false-positive defensive actions.
```

---

#### HAT-02a — Credential request in agent output
**Signal:** OW-ASI09 | **Score:** 85 | **Severity:** critical | **Phase:** post_session

```
Logic:
  For each llm_end completion:
    CREDENTIAL_REQUEST_PATTERNS = [
      r"(?i)(please\s+)?(enter|provide|share|give|type|input).{0,20}(password|credential|token|api.?key|secret|ssn|social\s+security)",
      r"(?i)(what\s+is\s+your|can\s+you\s+share).{0,20}(password|login|credential)",
      r"(?i)(verify|confirm).{0,15}(identity|account).{0,20}(password|pin|security\s+code)"
    ]
    If match AND no interrupt_raised event in session:
      Fire HAT-02a. Detail: "Agent output requests user credentials without HITL safeguard"
```

---

#### HAT-03a — Payment detail manipulation
**Signal:** OW-ASI09 | **Score:** 90 | **Severity:** critical | **Phase:** post_session

```
Logic:
  For each llm_end completion:
    PAYMENT_PATTERNS = [
      r"(?i)(transfer|send|pay|wire).{0,30}(to\s+account|to\s+bank|IBAN|routing\s+number)",
      r"(?i)(urgent|immediate).{0,20}(payment|transfer|wire)",
      r"(?i)(updated?\s+)?bank.{0,10}(detail|account|info)"
    ]
    If match: Fire HAT-03a. Detail: "Agent output contains payment/transfer instruction"
```

---

#### HAT-04a — Fabricated rationale before destructive action
**Signal:** OW-ASI09 | **Score:** 80 | **Severity:** high | **Phase:** post_session

```
Logic:
  DESTRUCTIVE_TOOLS = r"(?i)(delete|drop|remove|purge|terminate|destroy|shutdown|wipe)"
  For each tool_start matching DESTRUCTIVE_TOOLS:
    Find the immediately preceding llm_end completion.
    If completion contains confident rationale language:
      r"(?i)(this is (necessary|required|safe|recommended)|I've (verified|confirmed|checked))"
      AND no retrieval/verification tool was called between the rationale and the destructive action:
        Fire HAT-04a. Detail: "Destructive action '{tool}' preceded by unverified rationale"
```

---

#### HAT-05a — Side-effect on preview/read-only action
**Signal:** OW-ASI09 | **Score:** 75 | **Severity:** high | **Phase:** post_session

```
Logic:
  For each tool_start where tool_name matches r"(?i)(preview|view|read|inspect|show|display)":
    If tool_input contains:
      - URL with query params matching r"(?i)(webhook|callback|notify|trigger)"
      - r"(?i)(POST|PUT|DELETE|PATCH)" in tool_input
    Fire HAT-05a. Detail: "Preview/read tool '{tool}' has side-effect indicators in args"
```

---

#### RA-02a — Persistent exfiltration pattern across sessions
**Signal:** OW-ASI10 | **Score:** 90 | **Severity:** critical | **Phase:** cross_session
**Function:** `check_persistent_exfil()` in `cross_session.py`

```
Logic:
  Query last 10 sessions for this agent_id.
  For each session, check if any OUTBOUND_TOOLS were invoked.
  If >= 3 sessions in a row contain outbound tool calls to the same external endpoint:
    Fire RA-02a. Detail: "Persistent outbound data flow to '{endpoint}' across {n} sessions"
```

---

#### RA-03a — Fake approval agent in workflow
**Signal:** OW-ASI10 | **Score:** 85 | **Severity:** critical | **Phase:** post_session

```
Logic:
  Multi-agent prep. For tool_start matching approval/review patterns:
    r"(?i)(approve|review|authorize|validate|sign_off)"
    If the approval tool is invoked AND the approving entity is the same agent (self-approval):
      Fire RA-03a. Detail: "Agent self-approved action without external validation"
    Also: if approval tool_input contains auto-generated justification from same session's llm_end:
      Fire RA-03a.
```

---

#### RA-04a — Self-replication via provisioning tools
**Signal:** OW-ASI10 | **Score:** 95 | **Severity:** critical | **Phase:** per_event
**Detector:** `agentic.py` | **Runs on:** `tool_start`

```
Logic:
  SPAWN_PATTERNS = [
    r"(?i)(spawn|clone|replicate|fork|create_agent|deploy_agent|provision)",
    r"(?i)(docker\s+run|kubectl\s+create|aws\s+lambda\s+create)",
    r"(?i)(start_instance|launch_instance|scale_up)"
  ]
  If tool_name or tool_input matches SPAWN_PATTERNS:
    Fire RA-04a. Detail: "Agent attempting to spawn/replicate via {tool_name}"
```

---

#### RA-05a — Destructive optimization (reward hacking)
**Signal:** OW-ASI10 | **Score:** 85 | **Severity:** critical | **Phase:** post_session

```
Logic:
  DESTRUCTIVE_COST_ACTIONS = [
    r"(?i)(delete|remove|drop).{0,20}(backup|replica|snapshot|archive|log|cache)",
    r"(?i)(terminate|shutdown|stop).{0,20}(instance|service|worker|replica)",
    r"(?i)(reduce|downgrade|remove).{0,20}(redundancy|replication|failover)"
  ]
  For each tool_start:
    If tool_input matches DESTRUCTIVE_COST_ACTIONS:
      Check session context: was the agent tasked with cost optimization or metric improvement?
      (Check initial_input for r"(?i)(optimize|reduce\s+cost|improve\s+metric|minimize)")
      If yes: Fire RA-05a. Detail: "Destructive action '{tool}' during optimization task"
```

---

## 4. v3 Scoring model — Enterprise grade

### 4.1 Design principles

| Principle | Rationale |
|-----------|-----------|
| **Confidence-weighted sub-checks** | Regex match = high confidence. Statistical anomaly = lower confidence. Score × confidence gives calibrated risk. |
| **Attack chain amplification** | When multiple signals fire in a pattern matching a known attack chain, the composite score is amplified. Isolated signals don't cascade. |
| **Cross-session Bayesian agent trust** | Agent risk starts at a neutral prior. Each session updates the posterior. New agents are treated with appropriate uncertainty. |
| **Temporal decay** | Older sessions contribute less to agent-level scores. Recent bad sessions weigh more than ancient ones. |
| **Severity-gated alerting** | Critical findings alert immediately. Medium findings only alert if sustained across sessions. |

### 4.2 Confidence tiers

Every sub-check is assigned a confidence tier based on its detection method:

| Tier | Confidence weight | Detection method | Examples |
|------|------------------|-----------------|----------|
| `deterministic` | 1.0 | Exact match, regex on known pattern | SID-01a (API key regex), RCE-03a (container escape path) |
| `high` | 0.9 | Strong heuristic, multi-factor | PI-01a (role-override phrase), TME-05a (cross-tool exfil with LCS) |
| `medium` | 0.7 | Statistical anomaly, threshold-based | EAG-01a (tool count vs baseline), UBC-01a (token spike 4σ) |
| `low` | 0.5 | Heuristic, single-factor, prone to FP | PI-07a (multimodal flag), SAG-02a (hallucinated package) |
| `skeletal` | 0.3 | Placeholder for future multi-agent | IAC-06a, CF-04a, ASCV-05a |

**Implementation:** Add `confidence_tier` column to `signal_registry` table (migration 013). Add to `Finding` dataclass as `confidence: float`.

### 4.3 Per-signal score (v3)

```python
def compute_signal_score_v3(sub_checks: list[Finding]) -> dict:
    """
    Returns:
      {
        "raw_score": int,          # max(check_score) — same as v2
        "confidence_score": float, # max(check_score * confidence_weight)
        "effective_score": int,    # round(confidence_score) — used in composite
        "confidence": float,       # highest confidence among fired sub-checks
        "fired_count": int
      }
    """
    if not sub_checks:
        return {"raw_score": 0, "confidence_score": 0.0, "effective_score": 0,
                "confidence": 0.0, "fired_count": 0}

    raw_score = max(sc.check_score for sc in sub_checks)
    best = max(sub_checks, key=lambda sc: sc.check_score * CONFIDENCE_WEIGHTS[sc.confidence_tier])
    confidence_score = best.check_score * CONFIDENCE_WEIGHTS[best.confidence_tier]
    confidence = CONFIDENCE_WEIGHTS[best.confidence_tier]

    return {
        "raw_score": raw_score,
        "confidence_score": confidence_score,
        "effective_score": round(confidence_score),
        "confidence": confidence,
        "fired_count": len(sub_checks)
    }
```

### 4.4 Attack chain amplification

Known attack chains that, when detected together, indicate a coordinated attack and warrant score amplification:

```python
ATTACK_CHAINS = {
    "indirect_injection_to_exfil": {
        "signals": {"OW-LLM01", "OW-ASI02", "OW-LLM02"},
        "description": "Injection → tool misuse → data exfiltration",
        "amplification": 1.25  # 25% boost to composite
    },
    "goal_hijack_to_rce": {
        "signals": {"OW-ASI01", "OW-ASI05"},
        "description": "Goal hijacking → code execution",
        "amplification": 1.30
    },
    "supply_chain_to_backdoor": {
        "signals": {"OW-ASI04", "OW-ASI05", "OW-ASI10"},
        "description": "Supply chain compromise → code execution → rogue behavior",
        "amplification": 1.35
    },
    "memory_poison_to_exfil": {
        "signals": {"OW-ASI06", "OW-ASI01", "OW-LLM02"},
        "description": "Memory poisoning → goal hijack → data disclosure",
        "amplification": 1.25
    },
    "privilege_escalation_chain": {
        "signals": {"OW-ASI03", "OW-ASI02", "OW-LLM06"},
        "description": "Privilege abuse → tool misuse → excessive agency",
        "amplification": 1.20
    },
    "trust_exploitation_to_fraud": {
        "signals": {"OW-ASI09", "OW-ASI01", "OW-LLM05"},
        "description": "Trust exploitation → goal hijack → insecure output",
        "amplification": 1.25
    },
    "cascading_failure_chain": {
        "signals": {"OW-ASI08", "OW-ASI07", "OW-ASI10"},
        "description": "Cascading failure → inter-agent compromise → rogue behavior",
        "amplification": 1.30
    }
}
```

### 4.5 Composite score (v3)

```python
def compute_composite_score_v3(signal_map: dict, framework: str, all_fired_signals: set) -> dict:
    """
    v3 composite with confidence weighting and attack chain amplification.

    Returns:
      {
        "composite_score": int,     # 0-100, used for alerting
        "raw_composite": float,     # before amplification
        "amplification_factor": float,
        "attack_chains_detected": list[str],
        "confidence_band": str      # "high" | "medium" | "low"
      }
    """
    prefix = f"OW-{framework}"
    fired = sorted(
        [(sig_id, sig_data["effective_score"], sig_data["confidence"])
         for sig_id, sig_data in signal_map.items()
         if sig_id.startswith(prefix) and sig_data["status"] == "fired"],
        key=lambda x: x[1], reverse=True
    )

    if not fired:
        return {"composite_score": 0, "raw_composite": 0.0,
                "amplification_factor": 1.0, "attack_chains_detected": [],
                "confidence_band": "high"}

    scores = [f[1] for f in fired]
    confidences = [f[2] for f in fired]

    if len(scores) == 1:
        raw = scores[0]
    else:
        raw = scores[0] * 0.6 + (sum(scores[1:]) / len(scores[1:])) * 0.4

    # Attack chain amplification
    fired_signal_ids = {f[0] for f in fired} | all_fired_signals
    amplification = 1.0
    chains_detected = []
    for chain_name, chain_def in ATTACK_CHAINS.items():
        if chain_def["signals"].issubset(fired_signal_ids):
            amplification = max(amplification, chain_def["amplification"])
            chains_detected.append(chain_name)

    composite = min(100, int(raw * amplification))

    # Confidence band
    avg_confidence = sum(confidences) / len(confidences)
    if avg_confidence >= 0.85:
        confidence_band = "high"
    elif avg_confidence >= 0.6:
        confidence_band = "medium"
    else:
        confidence_band = "low"

    return {
        "composite_score": composite,
        "raw_composite": round(raw, 2),
        "amplification_factor": amplification,
        "attack_chains_detected": chains_detected,
        "confidence_band": confidence_band
    }
```

### 4.6 Cross-session Bayesian agent trust score

```python
def compute_agent_trust_score(
    agent_id: str,
    new_session_llm_score: int,
    new_session_asi_score: int,
    historical_scores: list[dict],  # [{llm_score, asi_score, scored_at}, ...]
    session_count: int
) -> dict:
    """
    Bayesian update of agent trust.

    Prior: Beta(α=2, β=8) — slight trust bias (agents start somewhat trusted).
    Each session updates α (risk events) and β (clean events).

    Returns:
      {
        "trust_score": float,        # 0-100, higher = more trusted
        "trend": str,                # "improving" | "stable" | "degrading"
        "trend_slope": float,        # linear regression slope
        "sessions_evaluated": int,
        "decay_weighted_avg": float  # exponential decay weighted average
      }
    """
    ALPHA_PRIOR = 2.0
    BETA_PRIOR = 8.0
    DECAY_LAMBDA = 0.05  # per-day decay

    alpha = ALPHA_PRIOR
    beta = BETA_PRIOR

    now = datetime.utcnow()
    decay_weighted_scores = []

    for hist in sorted(historical_scores, key=lambda x: x["scored_at"]):
        days_ago = (now - hist["scored_at"]).total_seconds() / 86400
        weight = math.exp(-DECAY_LAMBDA * days_ago)

        # Score > 40 = risk event, contributes to alpha
        # Score <= 40 = clean event, contributes to beta
        max_score = max(hist["llm_score"], hist["asi_score"])
        if max_score > 40:
            alpha += weight * (max_score / 100)
        else:
            beta += weight * ((100 - max_score) / 100)

        decay_weighted_scores.append(max_score * weight)

    # Update with new session
    new_max = max(new_session_llm_score, new_session_asi_score)
    if new_max > 40:
        alpha += new_max / 100
    else:
        beta += (100 - new_max) / 100

    # Trust = 100 * (1 - E[Beta(α,β)])
    # E[Beta] = α/(α+β) represents risk probability
    risk_probability = alpha / (alpha + beta)
    trust_score = round(100 * (1 - risk_probability), 1)

    # Trend: linear regression on last 20 sessions
    recent = historical_scores[-20:] if len(historical_scores) >= 5 else []
    if len(recent) >= 5:
        x = list(range(len(recent)))
        y = [max(h["llm_score"], h["asi_score"]) for h in recent]
        n = len(x)
        slope = (n * sum(xi*yi for xi, yi in zip(x, y)) - sum(x)*sum(y)) / \
                (n * sum(xi**2 for xi in x) - sum(x)**2)
        if slope > 2.0:
            trend = "degrading"
        elif slope < -2.0:
            trend = "improving"
        else:
            trend = "stable"
    else:
        slope = 0.0
        trend = "stable"

    decay_avg = sum(decay_weighted_scores) / max(len(decay_weighted_scores), 1)

    return {
        "trust_score": trust_score,
        "trend": trend,
        "trend_slope": round(slope, 3),
        "sessions_evaluated": session_count + 1,
        "decay_weighted_avg": round(decay_avg, 2)
    }
```

### 4.7 Updated alert thresholds (v3)

```python
SIGNAL_ALERT_THRESHOLDS_V3 = {
    # LLM signals
    "OW-LLM01": 70,   # Prompt injection
    "OW-LLM02": 75,   # Sensitive info disclosure
    "OW-LLM03": 999,  # Excluded (pre-runtime)
    "OW-LLM04": 999,  # Excluded (pre-runtime)
    "OW-LLM05": 70,   # Insecure output handling
    "OW-LLM06": 65,   # Excessive agency
    "OW-LLM07": 70,   # System prompt leakage
    "OW-LLM08": 999,  # Excluded (pre-runtime)
    "OW-LLM09": 60,   # Misinformation
    "OW-LLM10": 55,   # Unbounded consumption

    # ASI signals
    "OW-ASI01": 70,   # Agent goal hijack
    "OW-ASI02": 65,   # Tool misuse
    "OW-ASI03": 70,   # Identity & privilege abuse
    "OW-ASI04": 70,   # Supply chain
    "OW-ASI05": 60,   # Unexpected code execution (lower threshold — critical risk)
    "OW-ASI06": 70,   # Memory & context poisoning
    "OW-ASI07": 75,   # Insecure inter-agent comms
    "OW-ASI08": 70,   # Cascading failures
    "OW-ASI09": 70,   # Human-agent trust exploitation
    "OW-ASI10": 65,   # Rogue agents
}

COMPOSITE_ALERT_THRESHOLD_V3 = 60  # lowered from 65 — attack chain amplification may push scores up

# NEW: Sustained-risk alert — fires if agent trust score < 50 for > 3 consecutive sessions
AGENT_TRUST_ALERT_THRESHOLD = 50
AGENT_TRUST_CONSECUTIVE_SESSIONS = 3
```

### 4.8 Updated risk bands

```python
RISK_BANDS_V3 = {
    "clean":    (0, 14),    # narrowed from 0-19
    "low":      (15, 34),   # narrowed from 20-39
    "medium":   (35, 59),   # narrowed from 40-64
    "high":     (60, 84),   # lowered from 65-84
    "critical": (85, 100),  # unchanged
}
```

### 4.9 Signal status output format (v3)

```json
{
  "OW-LLM01": {
    "score": 85,
    "effective_score": 76,
    "confidence": 0.9,
    "confidence_tier": "high",
    "status": "fired",
    "sub_checks": {
      "PI-01a": {
        "check_score": 85,
        "confidence_tier": "high",
        "confidence": 0.9,
        "effective_score": 76,
        "check_label": "Role-override phrase match",
        "severity": "high",
        "event_id": "...",
        "matched_text": "ig**...ns"
      }
    }
  },
  "OW-LLM04": {
    "score": 0,
    "effective_score": 0,
    "status": "not_observed",
    "reason": "pre-runtime"
  }
}
```

---

## 5. Multi-agent graph preparation

### 5.1 New event fields (payload extensions)

For multi-agent support, the following fields should be extracted from `payload` when present:

| Field | Type | Present in | Used by |
|-------|------|-----------|---------|
| `source_agent_id` | UUID | tool_start (delegation) | ASI03, ASI07, ASI10 |
| `target_agent_id` | UUID | tool_start (delegation) | ASI03, ASI07, ASI10 |
| `delegation_depth` | int | tool_start (delegation) | ASI03 (depth > 2 = warning) |
| `agent_card` | JSONB | tool_start (A2A) | ASI04 (ASCV-05a) |
| `mcp_server_name` | string | tool_start | ASI04 (ASCV-02a/03a) |
| `tool_description` | string | tool_start | ASI02 (TME-02a) |
| `request_id` | string | tool_start | ASI07 (IAC-03a replay) |

### 5.2 Skeletal vs active sub-checks

Sub-checks marked `skeletal` return `None` for single-agent sessions. They are structured so that when multi-agent event fields become available, they activate without code changes — only the payload field presence check needs to pass.

Skeletal sub-checks: IAC-06a, CF-04a, ASCV-05a, RA-03a (partial — self-approval works for single agent).

---

## 6. Database migrations

### Migration 013 — v3 scoring columns

```sql
-- Add confidence tier to signal_registry
ALTER TABLE signal_registry ADD COLUMN IF NOT EXISTS confidence_tier TEXT
    NOT NULL DEFAULT 'high'
    CHECK (confidence_tier IN ('deterministic','high','medium','low','skeletal'));

-- Add v3 columns to session_risk_scores
ALTER TABLE session_risk_scores
    ADD COLUMN IF NOT EXISTS v3_llm_composite JSONB,
    ADD COLUMN IF NOT EXISTS v3_asi_composite JSONB,
    ADD COLUMN IF NOT EXISTS attack_chains_detected TEXT[] NOT NULL DEFAULT '{}';

-- Add trust score columns to agent_risk_scores
ALTER TABLE agent_risk_scores
    ADD COLUMN IF NOT EXISTS trust_score NUMERIC(5,1) NOT NULL DEFAULT 80.0,
    ADD COLUMN IF NOT EXISTS trust_trend TEXT NOT NULL DEFAULT 'stable'
        CHECK (trust_trend IN ('improving','stable','degrading')),
    ADD COLUMN IF NOT EXISTS trust_trend_slope NUMERIC(6,3) NOT NULL DEFAULT 0.0,
    ADD COLUMN IF NOT EXISTS trust_alpha NUMERIC(8,3) NOT NULL DEFAULT 2.0,
    ADD COLUMN IF NOT EXISTS trust_beta NUMERIC(8,3) NOT NULL DEFAULT 8.0;

-- Add confidence to security_findings
ALTER TABLE security_findings
    ADD COLUMN IF NOT EXISTS confidence_tier TEXT,
    ADD COLUMN IF NOT EXISTS confidence NUMERIC(3,2);
```

### Migration 014 — cross-session support indexes

```sql
-- Index for cross-session queries
CREATE INDEX IF NOT EXISTS idx_risk_scores_agent_scored
    ON session_risk_scores (agent_id, scored_at DESC);

-- Index for user-context cross-session queries
CREATE INDEX IF NOT EXISTS idx_risk_scores_tenant_scored
    ON session_risk_scores (tenant_id, scored_at DESC);
```

---

## 7. New files

| File | Purpose |
|------|---------|
| `db/postgres/013_v3_scoring.sql` | Migration 013 |
| `db/postgres/014_cross_session_indexes.sql` | Migration 014 |
| `consumers/security_eval/scorer/cross_session.py` | Cross-session checks: SID-03a, UBC-03a, UBC-05a, IPA-05a, MCP-02a, MCP-04a, RA-02a |
| `consumers/security_eval/scorer/attack_chains.py` | ATTACK_CHAINS dict + `detect_attack_chains()` |
| `consumers/security_eval/scorer/trust.py` | `compute_agent_trust_score()` |
| `tests/unit/test_scoring_v3.py` | v3 scoring model tests |
| `tests/unit/test_cross_session.py` | Cross-session signal tests |
| `tests/unit/test_attack_chains.py` | Attack chain detection tests |
| `tests/unit/test_trust.py` | Bayesian trust score tests |

### Modified files

| File | Changes |
|------|---------|
| `consumers/security_eval/detectors/injection.py` | Add PI-05a, PI-07a, PI-08a, PI-09a |
| `consumers/security_eval/detectors/passthrough.py` | Add IOH-03a |
| `consumers/security_eval/detectors/agentic.py` | Add AGH-04a, ASCV-02a, ASCV-04a, RCE-06a, RCE-08a, RA-04a, MCP-03a |
| `consumers/security_eval/scorer/llm_signals.py` | Add PI-06a, IOH-04a, SAG-02a, SAG-03a, UBC-02a; mark LLM04/08 not-observed |
| `consumers/security_eval/scorer/asi_signals.py` | Add all new ASI sub-checks from section 3.3 |
| `consumers/security_eval/scorer/orchestrator.py` | v3 scoring model integration; attack chain detection; trust score computation |
| `consumers/security_eval/findings.py` | Add `confidence_tier` and `confidence` to Finding dataclass and PG writer |
| `core/config.py` | v3 thresholds, ATTACK_CHAINS, CONFIDENCE_WEIGHTS, cost config, KNOWN_MCP_SERVERS, KNOWN_HALLUCINATED_PACKAGES |
| `scripts/seed_signal_registry.py` | Add 75 new sub-checks with confidence tiers; mark DMP-01a/c, VEW-01b/02a as excluded |

---

## 8. Build order

### Phase 1 — Schema & registry (do first, everything depends on this)
```
db/postgres/013_v3_scoring.sql
db/postgres/014_cross_session_indexes.sql
scripts/seed_signal_registry.py  (update: +75 sub-checks, +confidence_tier, mark exclusions)
core/config.py                   (add v3 thresholds, ATTACK_CHAINS, CONFIDENCE_WEIGHTS, new config)
consumers/security_eval/findings.py  (add confidence_tier, confidence fields)
```

### Phase 2 — Per-event detectors (new sub-checks)
```
consumers/security_eval/detectors/injection.py      (+PI-05a, PI-07a, PI-08a, PI-09a)
consumers/security_eval/detectors/passthrough.py     (+IOH-03a)
consumers/security_eval/detectors/agentic.py         (+AGH-04a, ASCV-02a, ASCV-04a, RCE-06a, RCE-08a, RA-04a, MCP-03a)
```

### Phase 3 — Post-session signal functions (new sub-checks)
```
consumers/security_eval/scorer/llm_signals.py        (+PI-06a, IOH-04a, SAG-02a, SAG-03a, UBC-02a; mark LLM04/08 excluded)
consumers/security_eval/scorer/asi_signals.py         (+all new ASI sub-checks from section 3.3)
```

### Phase 4 — Cross-session signals
```
consumers/security_eval/scorer/cross_session.py       (NEW: SID-03a, UBC-03a, UBC-05a, IPA-05a, MCP-02a, MCP-04a, RA-02a)
```

### Phase 5 — v3 scoring engine
```
consumers/security_eval/scorer/attack_chains.py       (NEW)
consumers/security_eval/scorer/trust.py               (NEW)
consumers/security_eval/scorer/orchestrator.py         (MAJOR: integrate v3 scoring, attack chains, trust)
```

### Phase 6 — Tests
```
tests/unit/test_prompt_injection.py     (add PI-05a/07a/08a/09a cases)
tests/unit/test_agentic_threats.py      (add AGH-04a, ASCV-02a/04a, RCE-06a/08a, RA-04a, MCP-03a)
tests/unit/test_llm_signals.py          (add PI-06a, IOH-04a, SAG-02a/03a, UBC-02a; test LLM04/08 exclusion)
tests/unit/test_asi_signals.py          (add all new ASI sub-checks)
tests/unit/test_scoring_v3.py           (NEW: confidence weighting, effective scores)
tests/unit/test_cross_session.py        (NEW)
tests/unit/test_attack_chains.py        (NEW)
tests/unit/test_trust.py               (NEW)
tests/unit/test_signal_registry.py      (update: 196 sub-checks, confidence_tier coverage)
tests/integration/test_post_session_scorer.py  (update: v3 composite, attack chains, trust)
```

---

## 9. Signal registry seed data (75 new sub-checks)

Format: `(owasp_signal_id, sub_check_id, label, owasp_category, owasp_number, detection_phase, check_score, severity, confidence_tier, excluded)`

```python
NEW_SUB_CHECKS = [
    # OW-LLM01 additions
    ("OW-LLM01", "PI-05a", "Code injection pattern in prompt",             "LLM", 1, "both",         80, "high",     "high",          False),
    ("OW-LLM01", "PI-06a", "Payload splitting across messages",            "LLM", 1, "post_session",  88, "high",     "high",          False),
    ("OW-LLM01", "PI-07a", "Multimodal content with injection signal",     "LLM", 1, "both",         60, "medium",   "low",           False),
    ("OW-LLM01", "PI-08a", "Adversarial suffix (high-entropy tail)",       "LLM", 1, "both",         75, "high",     "medium",        False),
    ("OW-LLM01", "PI-09a", "Obfuscated/encoded injection",                 "LLM", 1, "both",         82, "high",     "high",          False),

    # OW-LLM02 additions
    ("OW-LLM02", "SID-03a", "Cross-user context bleed",                    "LLM", 2, "cross_session", 95, "critical", "high",          False),

    # OW-LLM04 — mark excluded
    # (DMP-01a, DMP-01c already exist — UPDATE excluded=True, detection_phase='excluded')

    # OW-LLM05 additions
    ("OW-LLM05", "IOH-03a", "Email template injection in output",          "LLM", 5, "both",         80, "high",     "high",          False),
    ("OW-LLM05", "IOH-04a", "Insecure code pattern in generated output",   "LLM", 5, "post_session",  70, "high",     "medium",        False),

    # OW-LLM08 — mark excluded
    # (VEW-01b, VEW-02a already exist — UPDATE excluded=True, detection_phase='excluded')

    # OW-LLM09 additions
    ("OW-LLM09", "SAG-02a", "Hallucinated package reference",              "LLM", 9, "post_session",  65, "medium",   "low",           False),
    ("OW-LLM09", "SAG-03a", "High-stakes domain without grounding",        "LLM", 9, "post_session",  60, "medium",   "medium",        False),

    # OW-LLM10 additions
    ("OW-LLM10", "UBC-02a", "Input size anomaly",                          "LLM", 10, "post_session", 50, "medium",   "medium",        False),
    ("OW-LLM10", "UBC-03a", "Request rate spike per user",                 "LLM", 10, "cross_session", 55, "medium",  "medium",        False),
    ("OW-LLM10", "UBC-05a", "Cost spike (Denial of Wallet)",               "LLM", 10, "cross_session", 60, "high",    "medium",        False),

    # OW-ASI01 additions
    ("OW-ASI01", "AGH-02a", "Zero-click goal hijack",                      "ASI", 1, "post_session",  85, "high",     "high",          False),
    ("OW-ASI01", "AGH-03a", "Goal drift across turns",                     "ASI", 1, "post_session",  70, "medium",   "medium",        False),
    ("OW-ASI01", "AGH-04a", "Document-sourced instruction injection",       "ASI", 1, "both",         80, "high",     "high",          False),

    # OW-ASI02 additions
    ("OW-ASI02", "TME-02a", "Tool descriptor integrity anomaly",           "ASI", 2, "post_session",  75, "high",     "high",          False),
    ("OW-ASI02", "TME-04a", "Over-privileged tool invocation",             "ASI", 2, "post_session",  70, "high",     "high",          False),
    ("OW-ASI02", "TME-05a", "Cross-tool exfiltration chain",               "ASI", 2, "post_session",  90, "critical", "high",          False),
    ("OW-ASI02", "TME-06a", "Tool name typosquatting",                     "ASI", 2, "post_session",  70, "high",     "medium",        False),
    ("OW-ASI02", "TME-07a", "Admin tool chain to external endpoint",       "ASI", 2, "post_session",  88, "critical", "high",          False),
    ("OW-ASI02", "TME-08a", "Repetitive benign tool misuse",               "ASI", 2, "post_session",  65, "medium",   "medium",        False),

    # OW-ASI03 additions
    ("OW-ASI03", "IPA-02a", "Delegation with full permissions",            "ASI", 3, "post_session",  80, "high",     "high",          False),
    ("OW-ASI03", "IPA-03a", "Cached credential reuse",                     "ASI", 3, "post_session",  85, "critical", "high",          False),
    ("OW-ASI03", "IPA-04a", "Stale authorization in long session",         "ASI", 3, "post_session",  65, "medium",   "medium",        False),
    ("OW-ASI03", "IPA-05a", "Identity sharing across users",               "ASI", 3, "cross_session", 75, "high",     "high",          False),

    # OW-ASI04 additions
    ("OW-ASI04", "ASCV-02a", "MCP descriptor poisoning",                   "ASI", 4, "both",         80, "high",     "high",          False),
    ("OW-ASI04", "ASCV-03a", "MCP server impersonation",                   "ASI", 4, "post_session",  75, "high",     "medium",        False),
    ("OW-ASI04", "ASCV-04a", "Unknown package install in tool execution",  "ASI", 4, "both",         85, "critical", "deterministic", False),
    ("OW-ASI04", "ASCV-05a", "Agent card descriptor anomaly",              "ASI", 4, "post_session",  70, "high",     "skeletal",      False),

    # OW-ASI05 additions
    ("OW-ASI05", "RCE-04a", "Execution loop (runaway)",                    "ASI", 5, "post_session",  80, "high",     "high",          False),
    ("OW-ASI05", "RCE-05a", "Backdoor pattern in generated code",          "ASI", 5, "post_session",  85, "critical", "high",          False),
    ("OW-ASI05", "RCE-06a", "Unsafe deserialization in tool args",         "ASI", 5, "both",         90, "critical", "deterministic", False),
    ("OW-ASI05", "RCE-07a", "Multi-tool chain exploitation",               "ASI", 5, "post_session",  92, "critical", "high",          False),
    ("OW-ASI05", "RCE-08a", "Lockfile manipulation in tool execution",     "ASI", 5, "both",         75, "high",     "deterministic", False),

    # OW-ASI06 additions
    ("OW-ASI06", "MCP-02a", "Cross-session escalation pattern",            "ASI", 6, "cross_session", 80, "high",     "high",          False),
    ("OW-ASI06", "MCP-03a", "Poisoned content in memory write",            "ASI", 6, "both",         75, "high",     "high",          False),
    ("OW-ASI06", "MCP-04a", "Cross-tenant retrieval anomaly",              "ASI", 6, "cross_session", 95, "critical", "deterministic", False),
    ("OW-ASI06", "MCP-05a", "Memory write after injection signal",         "ASI", 6, "post_session",  88, "critical", "high",          False),

    # OW-ASI07 additions
    ("OW-ASI07", "IAC-02a", "Unencrypted inter-agent communication",       "ASI", 7, "post_session",  80, "high",     "deterministic", False),
    ("OW-ASI07", "IAC-03a", "Replay attack (duplicate request ID)",        "ASI", 7, "post_session",  75, "high",     "high",          False),
    ("OW-ASI07", "IAC-04a", "MCP-routed inter-agent data anomaly",         "ASI", 7, "post_session",  80, "high",     "medium",        False),
    ("OW-ASI07", "IAC-05a", "Unknown agent in delegation chain",           "ASI", 7, "post_session",  85, "critical", "high",          False),
    ("OW-ASI07", "IAC-06a", "Semantics split-brain",                       "ASI", 7, "post_session",  65, "medium",   "skeletal",      False),

    # OW-ASI08 additions
    ("OW-ASI08", "CF-02a", "Multi-node error propagation",                 "ASI", 8, "post_session",  75, "high",     "high",          False),
    ("OW-ASI08", "CF-03a", "Auto-remediation feedback loop",               "ASI", 8, "post_session",  70, "high",     "high",          False),
    ("OW-ASI08", "CF-04a", "Hallucination propagation in defense agents",  "ASI", 8, "post_session",  65, "medium",   "skeletal",      False),

    # OW-ASI09 additions
    ("OW-ASI09", "HAT-02a", "Credential request in agent output",          "ASI", 9, "post_session",  85, "critical", "high",          False),
    ("OW-ASI09", "HAT-03a", "Payment detail manipulation",                 "ASI", 9, "post_session",  90, "critical", "high",          False),
    ("OW-ASI09", "HAT-04a", "Fabricated rationale before destructive act",  "ASI", 9, "post_session",  80, "high",     "medium",        False),
    ("OW-ASI09", "HAT-05a", "Side-effect on preview/read-only action",     "ASI", 9, "post_session",  75, "high",     "medium",        False),

    # OW-ASI10 additions
    ("OW-ASI10", "RA-02a", "Persistent exfiltration across sessions",      "ASI", 10, "cross_session", 90, "critical", "high",         False),
    ("OW-ASI10", "RA-03a", "Self-approval in workflow",                    "ASI", 10, "post_session",  85, "critical", "high",         False),
    ("OW-ASI10", "RA-04a", "Self-replication via provisioning tools",      "ASI", 10, "both",         95, "critical", "deterministic", False),
    ("OW-ASI10", "RA-05a", "Destructive optimization (reward hacking)",    "ASI", 10, "post_session",  85, "critical", "high",         False),
]

# UPDATES to existing sub-checks (mark excluded):
EXCLUSION_UPDATES = [
    ("OW-LLM04", "DMP-01a", True, "excluded", "Data/model poisoning — pre-runtime; requires offline pipeline audit"),
    ("OW-LLM04", "DMP-01c", True, "excluded", "RAG data integrity — pre-runtime; requires offline data validation"),
    ("OW-LLM08", "VEW-01b", True, "excluded", "Vector drift — pre-runtime; requires offline vector DB monitoring"),
    ("OW-LLM08", "VEW-02a", True, "excluded", "Poisoned retrieval — pre-runtime; requires offline retrieval audit"),
]

# UPDATES to ALL existing sub-checks: add confidence_tier
CONFIDENCE_TIER_UPDATES = {
    "PI-01a":  "high",
    "PI-01b":  "deterministic",
    "PI-02a":  "high",
    "PI-04b":  "high",
    "SID-01a": "deterministic",
    "SID-01c": "deterministic",
    "SID-02a": "deterministic",
    "SID-02b": "deterministic",
    "SID-02c": "deterministic",
    "DMP-01a": "medium",
    "DMP-01c": "high",
    "IOH-01a": "deterministic",
    "IOH-01b": "deterministic",
    "IOH-01c": "deterministic",
    "IOH-02a": "medium",
    "EAG-01a": "medium",
    "EAG-02a": "high",
    "EAG-03a": "high",
    "SPL-01a": "medium",
    "SPL-01b": "medium",
    "SPL-02a": "medium",
    "SPL-02b": "medium",
    "SPL-03b": "medium",
    "VEW-01b": "medium",
    "VEW-02a": "high",
    "SAG-01a": "high",
    "UBC-01a": "medium",
    "UBC-04a": "high",
    "AGH-01b": "high",
    "TME-01a": "high",
    "TME-03b": "deterministic",
    "IPA-01a": "high",
    "ASCV-01a": "medium",
    "RCE-01b": "deterministic",
    "RCE-03a": "deterministic",
    "RCE-03b": "deterministic",
    "MCP-01a": "high",
    "IAC-01a": "high",
    "CF-01a":  "high",
    "HAT-01a": "high",
    "RA-01a":  "medium",
}
```

---

## 10. Updated overlap dedup groups (v3)

```python
OVERLAP_GROUPS_V3 = {
    "injection":        {"OW-LLM01", "OW-ASI01", "OW-ASI06"},           # unchanged
    "output_exec":      {"OW-LLM05", "OW-ASI05", "OW-ASI02"},           # unchanged
    "supply_chain":     {"OW-LLM03", "OW-ASI04"},                       # unchanged
    "memory_vector":    {"OW-LLM08", "OW-ASI06"},                       # unchanged
    "excessive_agency": {"OW-LLM06", "OW-ASI02", "OW-ASI10"},           # unchanged
    "pii_privilege":    {"OW-LLM02", "OW-ASI03"},                       # unchanged
    "trust_fraud":      {"OW-ASI09", "OW-ASI01"},                       # NEW
    "cascade_rogue":    {"OW-ASI08", "OW-ASI10", "OW-ASI07"},           # NEW
}
```

---

## 11. Orchestrator integration (score_session v3)

```python
async def score_session(tenant_id, session_id, agent_id, online_findings) -> dict:
    """
    v3 flow — extends v2 with confidence, attack chains, trust scoring.

    1.  Fetch full event list from ClickHouse.
    2.  Fetch session row from Postgres.
    3.  Run per-event detectors (replay events) → per_event_findings.
    4.  Run OW-LLM signal functions → llm_findings.
    5.  Run OW-ASI signal functions → asi_findings.
    6.  Run cross-session signals → cross_session_findings.         ← NEW
    7.  Compute per-signal scores (v3: confidence-weighted).        ← CHANGED
    8.  Detect attack chains.                                       ← NEW
    9.  Compute composite scores (v3: with amplification).          ← CHANGED
    10. Write security_findings (with confidence fields).           ← CHANGED
    11. Write session_risk_scores (with v3 composite JSONB).        ← CHANGED
    12. Compute agent trust score (Bayesian update).                ← NEW
    13. Upsert agent_risk_scores (with trust columns).              ← CHANGED
    14. Resolve dedup_key.
    15. Alert if thresholds breached.
    16. Alert if agent trust < threshold for N sessions.            ← NEW
    """
```

---

## 12. Testing requirements

### Unit test coverage targets

| Test file | What to test |
|-----------|-------------|
| `test_scoring_v3.py` | `compute_signal_score_v3()`: confidence weighting produces correct effective_score. Deterministic sub-check at score 80 → effective 80. Medium sub-check at score 80 → effective 56. |
| `test_scoring_v3.py` | `compute_composite_score_v3()`: attack chain amplification caps at 100. No amplification when chains don't match. Both frameworks computed independently. |
| `test_attack_chains.py` | Each of the 7 defined chains fires when its signals are present. No false activation on partial overlap. |
| `test_trust.py` | Prior: new agent trust_score ≈ 80. After 10 clean sessions: trust > 85. After 3 critical sessions: trust < 50. Temporal decay: old bad sessions affect less than recent ones. Trend detection: 5 worsening sessions → "degrading". |
| `test_cross_session.py` | SID-03a: PII from user A found in user B's session → fires. UBC-03a: 5x rate spike → fires. MCP-02a: blocked tool in old session succeeds in new → fires. RA-02a: 3 sessions with same external endpoint → fires. |
| `test_signal_registry.py` | 196 total sub-checks. All 20 parent signals covered. No duplicate sub-check IDs. All confidence_tiers valid. DMP-01a/c and VEW-01b/02a marked excluded. |

### Integration test scenarios

| Scenario | Expected outcome |
|----------|-----------------|
| Clean checkout session | risk_score 0–10, no findings, trust stable |
| Injection + tool exfil chain | OW-LLM01 + OW-ASI02 + OW-LLM02 fire. Attack chain "indirect_injection_to_exfil" detected. Composite amplified. |
| Cross-session escalation | MCP-02a fires on second session where previously-blocked tool succeeds |
| Long-running session with stale auth | IPA-04a fires after 1 hour with no re-auth |
| Runaway execution loop | RCE-04a fires when exec tool called 5+ times consecutively |

---

## 13. Backward compatibility

| Concern | Mitigation |
|---------|-----------|
| v2 `session_risk_scores` rows | `ow_llm_signal_status` and `ow_asi_signal_status` columns still written in v2 format. New `v3_llm_composite` and `v3_asi_composite` JSONB columns added alongside. |
| v2 alert format | `payload.ow_llm_signal_status` continues to work. New fields (`attack_chains_detected`, `confidence_band`) added without breaking existing consumers. |
| `scorer_version` | Bumped to `"3.0.0"`. Dashboard can differentiate v2 vs v3 scored sessions. |
| Composite score meaning | v3 composites may be slightly higher due to amplification. Risk bands adjusted downward to compensate. |
| `dapplepot_api` | No API changes required — it reads JSONB columns as-is. New fields appear automatically. |
| `dapplepot_ui` | Optional: add attack chain badges, trust score display, confidence indicators. Not blocking for v3 launch. |

---

## 14. Locked decisions (v3 additions — do not change)

| # | Decision | Reason |
|---|----------|--------|
| 16 | Confidence tiers are assigned per sub-check, not per signal | Same signal can have deterministic and heuristic sub-checks. |
| 17 | Attack chain amplification is max(matching chain), not product | Prevents runaway score inflation when multiple chains match. |
| 18 | Bayesian trust uses Beta(2,8) prior | Agents start at ~80% trust. Reasonable for production deployments. |
| 19 | Cross-session queries use ClickHouse, not Postgres | ClickHouse has the full event history with tenant/agent/user partitioning. |
| 20 | Skeletal sub-checks return None, not score 0 | Prevents false "clean" status. They show as "not_applicable" in signal status. |
| 21 | `not_observed` vs `not_applicable` vs `clean` status | `not_observed`: pre-runtime, cannot detect. `not_applicable`: multi-agent only, single-agent session. `clean`: checked, nothing found. |
| 22 | v3 columns are additive, never replace v2 columns | Rolling upgrade safety. Old API/UI versions still work during deployment. |

---

## 15. What done looks like (v3)

**Unit tests pass** (`make test-unit`) — ~150+ tests:
- All 75 new sub-checks have at least 1 positive and 1 negative test case
- v3 scoring model: confidence weighting, attack chain amplification, composite calculation
- Bayesian trust: prior, update, decay, trend detection
- Signal registry: 196 entries, 20 parent signals, no duplicates, confidence_tiers valid
- Excluded signals: DMP-01a/c, VEW-01b/02a return not_observed

**Integration tests pass** (`make test-integration`):
- Attack chain scenario triggers amplification and correct composite score
- Cross-session escalation fires MCP-02a
- Clean session → trust improves
- Critical session → trust degrades
- Scorer version is `"3.0.0"` in all written rows

**Seed data works** (`make setup`):
- Migrations 013-014 applied
- 196 sub-checks seeded with confidence_tiers
- Existing dev sessions re-scored at v3

*Build in phase order. Test each phase before proceeding.*
