# Sub-Check Overlaps — Ownership & Dedup Rules

Some sub-checks legitimately overlap in what they detect. This doc records the
**intentional** ones — which check owns which failure mode, why we keep both,
and how the engine dedups.

Do not resolve an overlap by silently deleting one side. If you find a case
that isn't listed here, either add it or open a discussion.

---

## Deliberately partitioned (mutually exclusive by design)

### PI-01c ↔ PI-09a — encoded/obfuscated injections

Two checks look like duplicates ("Encoded / obfuscated payload" vs "Obfuscated
/ encoded injection") but are partitioned by *encoding family*:

| Check | Covers |
|---|---|
| **PI-01c** | base64-decodable blobs · hex-escape sequences (`\xNN` x4+) whose decoded text matches an injection phrase |
| **PI-09a** | ROT13 of the whole message · Unicode homoglyph substitution normalised via NFKC |

Enforced in code: `_check_pi09a()` in `security_eval/detectors/injection.py`
tests **only** ROT13 + homoglyph and its docstring calls out that base64/hex
"belong to PI-01c… intentionally excluded here to avoid duplicate findings."

**Do not merge.** Different customers ask about different obfuscation styles
and the split is what makes the "matches" chip on each card meaningful.

### EA-02a ↔ TME-03a — irreversible action without confirm

Same threat class ("something destructive ran without approval"), differentiated
by *what was missing*:

| Check | Fires when |
|---|---|
| **EA-02a** | Configured `irreversible_tools` / `tool_approval_policy` — a listed tool ran without a preceding *user turn* between consecutive tool calls (checks the LangGraph turn gap) |
| **TME-03a** | Signature-only (no config needed) — a destructive tool name (delete/drop/truncate/rm/…) ran anywhere in the session with no dedicated confirm-gate tool (confirm/approve/authorize/…) invoked first |

Different mechanisms (policy vs signature) and different missing-condition
semantics (turn gap vs confirm-gate tool). EA-02a is the precise "the customer
declared this and it happened anyway" version; TME-03a is the safety net when
nothing is declared.

**Do not merge.** Losing TME-03a would leave undeclared-tool customers blind;
losing EA-02a would remove the customer-configurable gate.

---

## Same content fires multiple checks — intended, feeds attack chains

These overlaps *are* the point — a single payload lighting up multiple signals
is corroborating evidence that composite scoring and attack-chain amplification
are designed to reward.

### The `eval(` / `exec(` cluster — PI-05a · IOH-01a · RCE-01b

One `eval(` in a message fires:
- **PI-05a** on `llm_start` (code-injection pattern in prompt) → OW-LLM01
- **IOH-01a** on `llm_end`/`tool_end` (shell/exec pattern in output) → OW-LLM05
- **RCE-01b** on `tool_start` (eval/exec with agent-generated string) → OW-ASI05

Three signals from one payload is *intended*. This is a genuinely severe
pattern (code-execution primitive appearing across the prompt→output→tool
boundary) and cross-signal amplification correctly weights it.

**Dedup rule:** the composite score is confidence-weighted per signal, so
one payload cannot fire the same signal twice. Cross-signal firing is
preserved and feeds attack-chain detection.

### Drift family — PI-04a · AGH-01a · AGH-03a

- **PI-04a** — goal vector drift across ≥ 3 turns (OW-LLM01, injection-driven)
- **AGH-01a** — semantic drift from initial instruction (OW-ASI01, goal-based)
- **AGH-03a** — goal drift across turns (OW-ASI01, turn-scoped)

Same underlying phenomenon (agent objective shifting), classified by *how* the
shift was caused (injection vs generic) and *what timescale* it manifests over.
Legitimate drift may fire only one; adversarial drift often fires all three,
which is the useful corroboration signal.

**No dedup between them.** Each speaks to a different customer question
("was my prompt attacked?" vs "did my agent lose the plot?").

### Retrieved-content injection — AGH-04a · PI-02a · PI-03a

Instruction text arriving through different retrieval channels:
- **PI-02a** — web-fetched content with injection pattern (fires on tool_end from HTTP/API tools)
- **PI-03a** — API response carries directives (fires on tool_end from api/http/fetch/request tools)
- **AGH-04a** — document-sourced instruction injection (fires on tool_end from document/file/RAG tools)

Overlap exists when a source is ambiguous (an API returning documents). Keep
all three because customers filter by threat vector — a customer investigating
"our RAG got poisoned" wants AGH-04a; one investigating "our webhook was
tampered with" wants PI-02a.

### Manifest twins — EA-01a ↔ TME-06a

A tool named `queery_db` (typosquat of `query_db`) fires **both**:
- **EA-01a** — not in manifest (deterministic policy check)
- **TME-06a** — typosquat suspected (edit-distance heuristic against manifest)

Intended: EA-01a says *what*, TME-06a says *why suspicious*. Combined they
give the analyst enough to distinguish "customer added a new tool but forgot
to update the manifest" from "attacker registered a lookalike."

### Package twins — ASCV-02b ↔ ASCV-04a

Same event (a package install), different lenses:
- **ASCV-02b** — package not in SBOM allowlist (policy)
- **ASCV-04a** — unknown package install pattern (signature)

Kept separate because ASCV-02b is silent without a declared SBOM and ASCV-04a
is the always-on baseline. Together they answer "should this have been
allowed?" and "did we know about it?" respectively.

### Memory poisoning — MCP-02c ↔ MCP-03a

- **MCP-02c** — memory record *stored* contains instruction text (fires on the record already in memory being read back)
- **MCP-03a** — poisoned content in memory *write* (fires on the writing tool_end)

Sequence pair: MCP-03a is upstream, MCP-02c is downstream. Both firing in one
session is confirmatory — the writer poisoned it and the reader observed it.

### Secret twins — SID-01a ↔ SID-01c

A `Bearer eyJ…` token in output fires:
- **SID-01a** — matches the `Bearer [32+]` regex (generic secret pattern)
- **SID-01c** — matches the JWT three-part regex

Same match span, two checks. **Dedup rule for presentation:** the UI collapses
to one finding card citing both sub-check IDs when the match spans are equal
(implementation deferred to Workstream G — session report). Scoring keeps
both because they represent different confidence levels of the same finding.

---

## Overlaps resolved by removal

### EA-01b (deleted) — fully redundant with IPA-01a

`EA-01b "Agent requests elevated permissions"` was retired because IPA-01a
(OW-ASI03 — Privilege Escalation) owns the same behaviour and is more precise.
Registry: `EA-01b` no longer exists. Catalog total: 155 (was 156).

---

## SDK online ↔ post-session scorer — race dedup

When a sub-check is Enforceable and the customer has flipped it to Enforce,
the SDK fires the finding online via `/v1/online-check` **and** the post-session
scorer would ordinarily fire it again during replay.

The orchestrator (`scorer/orchestrator.py`) resolves this by:
- Loading SDK online findings from the `security_findings` table, deduped by
  `sub_check_id`, keeping the max score.
- Adding online-configured sub-check IDs to `_per_event_skip` so
  `_run_per_event_detectors()` skips them entirely during replay.

**Do not disable this dedup.** Without it, an enforced check produces two
findings per event and doubles its contribution to the composite score.

The hardcoded `_SDK_ONLINE_CAPABLE` frozenset in `orchestrator.py` is a
copy of `_ONLINE_CAPABLE_SUB_CHECKS` from `detectors/online.py` — one of the
four registry copies I1 is killing. After Workstream I lands, the skip set
derives from `registry.ENFORCEABLE_SUBCHECK_IDS`.
