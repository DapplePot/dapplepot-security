"""Backfill security scores for the 5 seeded dev sessions.

The pipeline seed_dev.py writes sessions directly to Postgres and ClickHouse,
bypassing Kafka. This means the security consumer never sees those events and
security_findings / session_risk_scores stay empty.

This script:
  1. Builds realistic per-session online findings (simulating what the online
     detectors would have produced if the sessions had run live through Kafka).
  2. Writes those online findings to security_findings.
  3. Calls the post-session scorer directly against each session's ClickHouse
     event history so L-05–L-10 are also computed.

Why online_findings must be pre-built:
  - L-01–L-04 in the scorer only look at online_findings passed in — they do
    not re-run the online detectors. Passing [] means all four are silent.

Why L-05 and L-10 remain silent:
  - Both signals query ClickHouse with `agent_id = %(agent_id)s`. The seeded
    obs_events rows store the agent name string ("langgraph_checkout") but
    score_session receives the UUID (TEST_AGENT_ID). Zero rows match →
    no baseline → both signals return None.
  - Fixing this would require modifying post_session.py (which also writes
    agent_id to Postgres as a UUID FK). L-05/L-10 require a 7-day baseline
    anyway — they are silent in any fresh deployment until history accumulates.
    The pre-built online findings for SES_003/004/005 already give the UI
    meaningful OWASP signals and remediation data.

Expected scores after seeding:
  SES_001  clean    (score 0)   — successful checkout, no security issues
  SES_002  clean    (score 0)   — in-progress, no security issues
  SES_003  high     (score 85)  — OW-LLM01:PI-01a (role-override injection)
  SES_004  high     (score 79)  — OW-LLM01:PI-01a + OW-LLM05:IOH-02a (composite weighted)
  SES_005  critical (score 90)  — OW-LLM02:SID-02b (credit card in output)

Run automatically via: make setup  (after pipeline make seed-dev)
"""
import asyncio
import sys

sys.path.insert(0, ".")

# ---------------------------------------------------------------------------
# Fixed IDs — must match dapplepot-pipeline/scripts/seed_dev.py
# ---------------------------------------------------------------------------
TEST_TENANT_ID = "00000000-0000-0000-0000-000000000001"
TEST_AGENT_ID  = "00000000-0000-0000-0000-000000000002"

_NULL_UUID = "00000000-0000-0000-0000-000000000000"

SES_001 = "00000000-0000-0000-0000-000000001001"
SES_002 = "00000000-0000-0000-0000-000000001002"
SES_003 = "00000000-0000-0000-0000-000000001003"
SES_004 = "00000000-0000-0000-0000-000000001004"
SES_005 = "00000000-0000-0000-0000-000000001005"

# ---------------------------------------------------------------------------
# Per-session online findings
# Simulates what injection.py / passthrough.py / pii.py would have emitted
# during live processing. Written to security_findings before score_session
# runs, then passed into the scorer so S-01–S-04 can aggregate them.
# ---------------------------------------------------------------------------
def _make_online(session_id, owasp_signal_id, sub_check_id, check_label,
                 check_score, sig_type, severity, event_type,
                 matched_text, detail, owasp_framework="LLM"):
    from consumers.security_eval.findings import Finding
    return Finding(
        tenant_id=TEST_TENANT_ID,
        session_id=session_id,
        event_id=_NULL_UUID,
        event_type=event_type,
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label=check_label,
        check_score=check_score,
        sig_type=sig_type,
        severity=severity,
        score_contrib=check_score,
        detection_phase="online",
        matched_text=matched_text,
        detail=detail,
        owasp_framework=owasp_framework,
    )


def _build_online_findings() -> dict[str, list]:
    return {
        # SES_001, SES_002 — clean, no online findings
        SES_001: [],
        SES_002: [],

        # SES_003 — OW-LLM01:PI-01a (role-override injection)
        #           composite LLM score ~85 → high
        SES_003: [
            _make_online(
                SES_003,
                owasp_signal_id="OW-LLM01", sub_check_id="PI-01a",
                check_label="Role-override phrase match",
                check_score=85, sig_type="injection", severity="high",
                event_type="llm_start",
                matched_text="ignore all prev***uctions...",
                detail="Instruction override pattern matched in user message",
            ),
        ],

        # SES_004 — OW-LLM01:PI-01a + OW-LLM05:IOH-02a
        #           composite = max(85)×0.6 + mean(70)×0.4 = 51+28 = 79 → high
        SES_004: [
            _make_online(
                SES_004,
                owasp_signal_id="OW-LLM01", sub_check_id="PI-01a",
                check_label="Role-override phrase match",
                check_score=85, sig_type="injection", severity="high",
                event_type="llm_start",
                matched_text="disregard prev*** instructions...",
                detail="Instruction override pattern matched in user message",
            ),
            _make_online(
                SES_004,
                owasp_signal_id="OW-LLM05", sub_check_id="IOH-02a",
                check_label="Raw LLM output as tool param",
                check_score=70, sig_type="passthrough", severity="high",
                event_type="tool_start",
                matched_text="import os; os.sy***('ls')",
                detail="tool_start input 92% similar to preceding llm_end output",
            ),
        ],

        # SES_005 — OW-LLM02:SID-02b credit card
        #           composite = 90 → critical
        SES_005: [
            _make_online(
                SES_005,
                owasp_signal_id="OW-LLM02", sub_check_id="SID-02b",
                check_label="Financial identifiers in output",
                check_score=90, sig_type="pii", severity="critical",
                event_type="tool_end",
                matched_text="41**...1234",
                detail="Credit card number detected in tool output",
            ),
        ],
    }


SESSIONS = [
    (SES_001, "SES_001  finalised — success"),
    (SES_002, "SES_002  open      — in progress"),
    (SES_005, "SES_005  finalised — error path"),
]


async def seed() -> None:
    from consumers.security_eval.findings import write_findings
    from consumers.security_eval.scorer.orchestrator import score_session
    from core.infra.postgres import get_pool, close_pool

    online_findings_map = _build_online_findings()

    # Clear existing findings for these sessions so re-running is idempotent.
    pool = await get_pool()
    session_ids = [sid for sid, _ in SESSIONS]
    await pool.execute(
        "DELETE FROM security_findings  WHERE session_id = ANY($1::uuid[])",
        session_ids,
    )
    await pool.execute(
        "DELETE FROM session_risk_scores WHERE session_id = ANY($1::uuid[])",
        session_ids,
    )

    print(f"\n  security scores → backfill ({len(SESSIONS)} sessions):")
    for session_id, label in SESSIONS:
        online_findings = online_findings_map[session_id]

        # Write online findings now (score_session only writes post_session ones).
        if online_findings:
            await write_findings(online_findings)

        # Run post-session scorer with the UUID.
        # L-05/L-10 baseline queries will find no ClickHouse rows (name/UUID
        # mismatch) and return None — acceptable for seed data.
        score = await score_session(
            tenant_id=TEST_TENANT_ID,
            session_id=session_id,
            agent_id=TEST_AGENT_ID,
            online_findings=online_findings,
        )

        print(
            f"    {label:<42s}"
            f"  score={score['risk_score']:>3d}"
            f"  band={score['risk_band']:<8s}"
            f"  signals={score['signal_count']}"
        )

    await close_pool()


if __name__ == "__main__":
    print("Backfilling security scores for dev sessions...")
    asyncio.run(seed())
    print("\nDone.")
