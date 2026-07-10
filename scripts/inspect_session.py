"""Diagnostic script — inspect a session's events + findings and show what
the Verdict tier would see with the multi-turn slicing.

Usage:
    .venv/Scripts/python.exe scripts/inspect_session.py <session_id>

Reads from the same Postgres + ClickHouse the security service uses via
the .env file. No writes.
"""
from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

# Make the package importable when run from repo root.
sys.path.insert(0, str(Path(__file__).parent.parent))

from core.infra import clickhouse as ch
from core.infra.postgres import get_pool
from security_eval.models.prompts import build_user_prompt


_CH_QUERY = """
    SELECT event_type, event_id, emitted_at, sequence_index,
           node_run_id, node_name, tool_name, llm_model,
           llm_input_tokens, llm_output_tokens, user_context_id, payload
    FROM obs_events
    WHERE session_id = %(session_id)s
    ORDER BY sequence_index ASC
"""


async def main(session_id: str) -> None:
    # ─── Events from ClickHouse ─────────────────────────────────────────────
    events = await ch.fetch(_CH_QUERY, session_id=session_id)
    for ev in events:
        for uuid_col in ("event_id", "node_run_id"):
            if ev.get(uuid_col) is not None:
                ev[uuid_col] = str(ev[uuid_col])
        p = ev.get("payload")
        if isinstance(p, str):
            try:
                ev["payload"] = json.loads(p)
            except Exception:
                ev["payload"] = {}
        elif not p:
            ev["payload"] = {}

    print(f"session_id: {session_id}")
    print(f"total events: {len(events)}")
    print()
    print("Event timeline:")
    for i, ev in enumerate(events):
        et = ev["event_type"]
        eid = ev["event_id"]
        seq = ev.get("sequence_index", "?")
        marker = "◆" if et in ("graph_start", "session_start", "graph_end", "session_end") else " "
        print(f"  {marker} #{i+1:>3}  seq={seq}  {et:<20}  event_id={eid}")
    print()

    # ─── Findings from Postgres ─────────────────────────────────────────────
    pool = await get_pool()
    rows = await pool.fetch(
        """
        SELECT sub_check_id, owasp_signal_id, check_score, severity,
               detection_phase, matched_text, detail, event_id, event_type,
               created_at
        FROM security_findings
        WHERE session_id = $1
        ORDER BY created_at ASC
        """,
        session_id,
    )
    print(f"findings in Postgres: {len(rows)}")
    for r in rows:
        matched = (r.get("matched_text") or r.get("detail") or "")[:70]
        print(
            f"  [{r['sub_check_id']:<9}] {r['detection_phase']:<12} "
            f"score={r['check_score']:>3} sev={r['severity']:<8} "
            f"event_id={r['event_id']} — {matched.replace(chr(10),' ')}"
        )
    print()

    # ─── Compute multi-turn slice (what Verdict would see NOW) ─────────────
    turn_start = 0
    for idx in range(len(events) - 1, -1, -1):
        if events[idx].get("event_type") in ("graph_start", "session_start"):
            turn_start = idx
            break
    turn_events = events[turn_start:] if turn_start else events
    current_ids = {ev.get("event_id") for ev in turn_events if ev.get("event_id")}

    print(f"multi-turn slice starts at event #{turn_start + 1} "
          f"(event_type={events[turn_start].get('event_type') if events else '?'})")
    print(f"current turn: {len(turn_events)} events")
    print(f"prior turn(s): {len(events) - len(turn_events)} events")
    print()

    # Reconstruct Finding-like objects for the prompt builder — the builder
    # only reads attribute-style fields via getattr, so a SimpleNamespace works.
    from types import SimpleNamespace
    prior_findings = [
        SimpleNamespace(
            sub_check_id=r["sub_check_id"],
            check_label="",
            event_id=r["event_id"],
            matched_text=r.get("matched_text"),
            detail=r.get("detail"),
        )
        for r in rows
        if r["event_id"] not in current_ids
    ]
    print(f"prior findings that would be passed to Verdict: {len(prior_findings)}")
    for f in prior_findings:
        m = (f.matched_text or f.detail or "")[:60]
        print(f"  - [{f.sub_check_id}] event_id={f.event_id} — {m.replace(chr(10),' ')}")
    print()
    print("=" * 70)
    print("PROMPT VERDICT WOULD SEE (build_user_prompt output):")
    print("=" * 70)
    print(build_user_prompt(turn_events, prior_findings=prior_findings))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: python scripts/inspect_session.py <session_id>")
        sys.exit(1)
    asyncio.run(main(sys.argv[1]))
