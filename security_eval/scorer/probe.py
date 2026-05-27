"""L-09: Cross-session model theft probe detection."""
import json
import re
from difflib import SequenceMatcher
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from security_eval.findings import Finding

# Minimum sessions with near-identical inputs to flag as a theft probe
MIN_SESSIONS = 5
# Similarity threshold for "near-identical"
SIMILARITY_THRESHOLD = 0.85


async def detect_model_theft_probe(
    events: list[dict],
    session: dict,
    tenant_id: str,
    session_id: str,
    agent_id: str,
) -> "Finding | None":
    """
    Check if the same user_context_id has sent near-identical llm_start inputs
    across 5+ sessions — a pattern consistent with systematic model probing.
    """
    # Get user_context_id — top-level column first, then payload fallback for legacy events
    session_start = next(
        (e for e in events if e.get("event_type") in ("session_start", "graph_start")), None
    )
    if not session_start:
        return None

    user_context_id = session_start.get("user_context_id")
    if not user_context_id:
        raw = session_start.get("payload") or "{}"
        payload = json.loads(raw) if isinstance(raw, str) else (raw or {})
        user_context_id = payload.get("user_context_id")
    if not user_context_id:
        return None

    # Fetch recent llm_start inputs for this user_context_id from ClickHouse
    from core import infra
    from core.infra import clickhouse as ch

    recent_sessions = await ch.fetch(
        """
        SELECT DISTINCT session_id, argMin(payload, sequence_index) AS first_payload
        FROM obs_events
        WHERE tenant_id  = %(tenant_id)s
          AND event_type = 'llm_start'
          AND session_id != %(session_id)s
          AND emitted_at >= now() - INTERVAL 24 HOUR
          AND session_id IN (
              SELECT DISTINCT session_id
              FROM obs_events
              WHERE tenant_id     = %(tenant_id)s
                AND event_type    IN ('graph_start', 'session_start')
                AND user_context_id = %(user_context_id)s
                AND emitted_at    >= now() - INTERVAL 24 HOUR
          )
        GROUP BY session_id
        LIMIT 50
        """,
        tenant_id=tenant_id,
        user_context_id=str(user_context_id),
        session_id=session_id,
    )

    if len(recent_sessions) < MIN_SESSIONS - 1:
        return None

    # Get the current session's first llm_start input
    current_llm_start = next((e for e in events if e["event_type"] == "llm_start"), None)
    if not current_llm_start:
        return None

    raw_current = current_llm_start.get("payload") or "{}"
    current_payload = json.loads(raw_current) if isinstance(raw_current, str) else (raw_current or {})
    current_msgs = current_payload.get("messages", [])
    current_text = " ".join(
        str(m.get("content", "")) for m in current_msgs if m.get("role") == "user"
    ).lower()

    if not current_text:
        return None

    similar_count = 0
    for row in recent_sessions:
        try:
            other_payload = json.loads(row["first_payload"]) if isinstance(row["first_payload"], str) else row["first_payload"]
            other_msgs = other_payload.get("messages", [])
            other_text = " ".join(
                str(m.get("content", "")) for m in other_msgs if m.get("role") == "user"
            ).lower()
            if not other_text:
                continue
            ratio = SequenceMatcher(None, current_text, other_text).ratio()
            if ratio >= SIMILARITY_THRESHOLD:
                similar_count += 1
        except Exception:
            continue

    if similar_count < MIN_SESSIONS - 1:
        return None

    from security_eval.findings import Finding
    return Finding(
        tenant_id=tenant_id,
        session_id=session_id,
        event_id="00000000-0000-0000-0000-000000000000",
        event_type="post_session",
        owasp_signal_id="OW-LLM10",
        sub_check_id="UBC-04a",
        check_label="Cohort probe pattern detected",
        check_score=70,
        category="model_security",
        severity="high",
        matched_text=None,
        detail=f"Cross-session model theft probe: {similar_count + 1} near-identical sessions for user_context_id={user_context_id}",
        detection_phase="post_session",
    )
