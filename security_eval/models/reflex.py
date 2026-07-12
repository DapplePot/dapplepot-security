"""Reflex — HTTP client for the fast-classifier tier.

Called from the /v1/online-check endpoint after the regex-based detect_online
pass. Returns findings as plain dicts (same shape online detectors produce) so
the endpoint's existing per-finding action-attachment loop keeps working
unchanged.

Wire protocol
-------------
Request  (JSON):
    {
        "event": <the raw event dict passed to /v1/online-check>,
        "sub_check_ids": ["PI-01a", "SID-01c", ...],  # subset the SDK opted into
        "hint_texts":    ["ignore previous instructions", "<!--", ...]  # optional
    }
    hint_texts: strings this service has already matched via the regex pass
    (matched_text from detect_online findings). Reflex uses them as anchors
    when the classifier input has to be truncated, so it sees the regions
    that matter instead of a naive head+tail. Not used for classification
    routing — that stays event-shape driven on Reflex's side.

Response (JSON):
    {
        "findings": [
            {"sub_check_id": "PI-01a",
             "matched_text": "ignore previous instructions",   # optional
             "detail":       "…"                                # optional
            },
            ...
        ]
    }

The Reflex service is trusted to return only sub_check_ids from the requested
subset; unknown IDs are silently dropped. All check metadata (label, score,
severity, signal_id, category) is looked up from the local registry —
Reflex does not need to know it.

Failure modes → empty list (silent fallback):
    * settings.reflex_endpoint_url empty
    * active_ids empty
    * connection error / timeout / non-200
    * body not JSON, or missing "findings" list
"""
from __future__ import annotations

import logging
from typing import Any

from core.config import settings
from security_eval.models._transport import SIGNAL_CATEGORY, make_client
from security_eval.registry import CHECK_BY_ID

logger = logging.getLogger(__name__)


def _build_finding(sub_check_id: str, matched_text: str, detail: str) -> dict[str, Any] | None:
    """Assemble a finding dict matching detect_online's shape.

    Returns None if the sub_check_id is not in the registry (defensive — the
    Reflex service shouldn't emit unknown IDs but we don't trust the wire).
    """
    meta = CHECK_BY_ID.get(sub_check_id)
    if not meta:
        return None
    signal = meta["signal_id"]
    return {
        "owasp_signal_id": signal,
        "sub_check_id":    sub_check_id,
        "check_label":     meta["label"],
        "check_score":     meta["score"],
        "category":        SIGNAL_CATEGORY.get(signal, "unknown"),
        "severity":        meta["severity"],
        "matched_text":    matched_text[:300] if matched_text else None,
        "detail":          detail or None,
        "confidence_tier": meta.get("confidence_tier", "high"),
        "detection_phase": "online",
    }


async def reflex_classify(
    event: dict[str, Any],
    active_ids: frozenset[str] | set[str],
    hint_texts: list[str] | None = None,
) -> list[dict[str, Any]]:
    """POST the event to the configured Reflex endpoint and return findings.

    hint_texts: optional matched_text values from earlier regex findings on
    the same event. Reflex uses them as span anchors so its bounded input
    window doesn't miss injections that live past the naive truncation cut.
    Absence is fine — Reflex falls back to head+tail sampling.

    Returns [] on any failure — the caller keeps the rule-based findings it
    already computed for these IDs, so falling back is safe.
    """
    if not settings.reflex_endpoint_url or not active_ids:
        return []

    payload: dict[str, Any] = {"event": event, "sub_check_ids": sorted(active_ids)}
    if hint_texts:
        # Cap: keep the request body small and dedupe.
        seen: set[str] = set()
        uniq: list[str] = []
        for h in hint_texts:
            if not h or h in seen:
                continue
            seen.add(h)
            uniq.append(h)
            if len(uniq) >= 20:
                break
        if uniq:
            payload["hint_texts"] = uniq

    # Dedicated reflex secret — distinct from INTERNAL_API_SECRET so the
    # two upstream services (dapplepot-api, dapplepot-reflex) have scoped
    # blast radii. The reflex service ignores the header when it has no
    # secret configured (dev mode); production stacks set it on both sides.
    headers: dict[str, str] = {}
    if settings.reflex_api_secret:
        headers["X-Internal-Secret"] = settings.reflex_api_secret

    try:
        async with make_client(settings.reflex_timeout_ms) as client:
            resp = await client.post(
                settings.reflex_endpoint_url, json=payload, headers=headers
            )
        if resp.status_code != 200:
            logger.warning("reflex non-200: %s", resp.status_code)
            return []
        body = resp.json()
    except Exception as exc:
        logger.warning("reflex call failed: %s: %s", type(exc).__name__, exc)
        return []

    raw = body.get("findings") if isinstance(body, dict) else None
    if not isinstance(raw, list):
        return []

    findings: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        sid = item.get("sub_check_id")
        if not isinstance(sid, str) or sid not in active_ids:
            continue
        f = _build_finding(
            sid,
            str(item.get("matched_text") or ""),
            str(item.get("detail") or ""),
        )
        if f:
            findings.append(f)
    return findings
