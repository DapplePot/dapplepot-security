"""Verdict — LLM judge tier for post-session semantic checks.

Called from orchestrator.score_session immediately before the v3 scoring
model runs. Uses NVIDIA NIM's OpenAI-compatible /chat/completions endpoint
(matches the transport pattern in dapplepot-sdk-test/tests/examples/langgraph_agent.py).

One HTTPS call per Verdict category (goal_drift, deception, grounding_failure,
other) — at most four calls per session, each restricted to the routed IDs
in that category that are still active for this session.

Failure modes → empty list (silent fallback):
    * settings.nvidia_api_key empty
    * active_ids empty
    * connection error / timeout / non-200
    * body not JSON, or missing "findings" list
    * individual finding fields malformed
"""
from __future__ import annotations

import asyncio
import json
import logging
import random
import re
from typing import Any, TYPE_CHECKING

from core.config import settings
from security_eval.models._transport import SIGNAL_CATEGORY, make_client
from security_eval.models.prompts import build_combined_system_prompt, build_user_prompt
from security_eval.registry import CHECK_BY_ID

if TYPE_CHECKING:
    from security_eval.findings import Finding

logger = logging.getLogger(__name__)

_NULL_UUID = "00000000-0000-0000-0000-000000000000"

# Process-wide concurrency limit. Lazy-init because asyncio.Semaphore
# construction can fail if no running loop existed at import time on some
# Python versions; also lets us pick up settings changes deterministically.
_verdict_semaphore: asyncio.Semaphore | None = None


def _get_semaphore() -> asyncio.Semaphore:
    global _verdict_semaphore
    if _verdict_semaphore is None:
        _verdict_semaphore = asyncio.Semaphore(max(1, settings.verdict_max_concurrent))
    return _verdict_semaphore


class _RateLimitedError(RuntimeError):
    """Raised by _nim_chat on 429/503 so the caller can retry with backoff."""
    def __init__(self, status: int, retry_after: float | None):
        super().__init__(f"NIM {status}")
        self.status = status
        self.retry_after = retry_after


async def verdict_judge(
    events: list[dict[str, Any]],
    tenant_id: str,
    session_id: str,
    active_ids: frozenset[str] | set[str],
    prior_findings: list | None = None,
) -> list["Finding"]:
    """One combined NIM call covering every active Verdict sub-check across
    all categories. Returns parsed Finding objects.

    Categories are still grouped in the system prompt so the judge sees the
    same conceptual bins — the change is just that we make one HTTPS call
    per session instead of one per category (4× fewer requests → far less
    chance of hitting the NIM shared-endpoint rate limit).

    In multi-turn sessions the caller may pass a sliced `events` list (only
    the current turn) plus `prior_findings` accumulated from earlier turns.
    The judge sees prior findings as context so it can skip re-emitting them
    and focus on new evidence in the current turn's events."""
    if not settings.nvidia_api_key or not active_ids:
        return []
    if not events:
        return []

    from security_eval.findings import Finding

    active = frozenset(active_ids)
    system_prompt = build_combined_system_prompt(active)
    user_prompt = build_user_prompt(events, prior_findings=prior_findings)

    try:
        async with _get_semaphore():
            raw = await _nim_chat_with_retry(system_prompt, user_prompt)
    except Exception as exc:
        logger.warning(
            "verdict NIM call failed: %s: %s", type(exc).__name__, exc,
        )
        return []

    findings: list[Finding] = []
    for item in _parse_verdict_response(raw, active):
        f = _build_finding(item, tenant_id, session_id)
        if f is not None:
            findings.append(f)
    return findings


async def _nim_chat_with_retry(system_prompt: str, user_prompt: str) -> str:
    """Wrap _nim_chat with retry on 429/503.

    Retry-After header (seconds) is honoured when present. Otherwise
    exponential backoff with jitter: 1s, 2s, 4s, capped at 30s. Attempt
    budget is settings.verdict_max_retries."""
    max_retries = max(0, settings.verdict_max_retries)
    last_exc: Exception | None = None
    for attempt in range(max_retries + 1):
        try:
            return await _nim_chat(system_prompt, user_prompt)
        except _RateLimitedError as exc:
            last_exc = exc
            if attempt >= max_retries:
                break
            if exc.retry_after is not None:
                delay = min(30.0, max(0.5, exc.retry_after))
            else:
                delay = min(30.0, (2 ** attempt) + random.uniform(0.0, 1.0))
            logger.info(
                "NIM %d (attempt %d/%d), sleeping %.1fs",
                exc.status, attempt + 1, max_retries + 1, delay,
            )
            await asyncio.sleep(delay)
    assert last_exc is not None
    raise last_exc


async def _nim_chat(system_prompt: str, user_prompt: str) -> str:
    """One /chat/completions round trip. Returns the assistant message content
    string; raises _RateLimitedError on 429/503, RuntimeError on other
    non-200 responses."""
    url = f"{settings.nvidia_base_url.rstrip('/')}/chat/completions"
    body = {
        "model": settings.verdict_model,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_prompt},
        ],
        "temperature": 0.0,
        "max_tokens": 1024,
    }
    headers = {
        "Authorization": f"Bearer {settings.nvidia_api_key}",
        "Content-Type": "application/json",
    }
    async with make_client(settings.verdict_timeout_ms) as client:
        resp = await client.post(url, json=body, headers=headers)
    if resp.status_code in (429, 503):
        raw_ra = resp.headers.get("Retry-After")
        try:
            retry_after = float(raw_ra) if raw_ra is not None else None
        except (TypeError, ValueError):
            retry_after = None
        raise _RateLimitedError(resp.status_code, retry_after)
    if resp.status_code != 200:
        raise RuntimeError(f"NIM {resp.status_code}: {resp.text[:200]}")
    doc = resp.json()
    return doc["choices"][0]["message"]["content"]


def _parse_verdict_response(raw: str, allowed_ids: frozenset[str]) -> list[dict[str, Any]]:
    """Extract the findings list from the model's reply. Tolerates code
    fences and stray prose around the JSON body — matches what smaller models
    tend to emit even when asked for strict JSON."""
    match = re.search(r"\{.*\}", raw, re.DOTALL)
    if not match:
        return []
    try:
        parsed = json.loads(match.group(0))
    except Exception:
        return []
    items = parsed.get("findings") if isinstance(parsed, dict) else None
    if not isinstance(items, list):
        return []

    out: list[dict[str, Any]] = []
    for item in items:
        if not isinstance(item, dict):
            continue
        sid = item.get("sub_check_id")
        if not isinstance(sid, str) or sid not in allowed_ids:
            continue
        out.append(item)
    return out


def _build_finding(item: dict[str, Any], tenant_id: str, session_id: str) -> "Finding | None":
    """Convert one model verdict item into a Finding. Metadata comes from
    the registry — the model only supplies the ID, detail, cited events,
    and confidence."""
    from security_eval.findings import Finding

    sid = item["sub_check_id"]
    meta = CHECK_BY_ID.get(sid)
    if not meta:
        return None

    involved_raw = item.get("involved_event_ids") or []
    involved: list[str] = [str(x) for x in involved_raw if isinstance(x, (str, int))]
    primary_event_id = involved[0] if involved else _NULL_UUID

    detail_raw = item.get("detail")
    detail = str(detail_raw)[:500] if detail_raw else None

    return Finding(
        tenant_id=tenant_id,
        session_id=session_id,
        event_id=primary_event_id,
        event_type="post_session",
        owasp_signal_id=meta["signal_id"],
        sub_check_id=sid,
        check_label=meta["label"],
        check_score=meta["score"],
        category=SIGNAL_CATEGORY.get(meta["signal_id"], "unknown"),
        severity=meta["severity"],
        detection_phase="post_session",
        matched_text=None,
        detail=detail,
        involved_event_ids=involved,
        confidence_tier=_confidence_to_tier(item.get("confidence")),
    )


def _confidence_to_tier(conf: Any) -> str:
    """Map the model's [0,1] confidence to the tier enum used by Finding.
    Conservative bands — the model is a judge, not an oracle."""
    try:
        c = float(conf)
    except (TypeError, ValueError):
        return "medium"
    if c >= 0.9:
        return "high"
    if c >= 0.7:
        return "medium"
    if c >= 0.5:
        return "low"
    return "skeletal"
