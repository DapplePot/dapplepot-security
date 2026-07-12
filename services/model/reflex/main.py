"""dapplepot-reflex — HTTP wrapper around a small prompt-injection classifier.

Speaks the wire protocol expected by
`dapplepot-security/security_eval/models/reflex.py`:

    POST /
    {
        "event": {"event_type": "...", "payload": {...}, ...},
        "sub_check_ids": ["PI-01a", "PI-02c", ...]
    }
    ->
    {
        "findings": [
            {"sub_check_id": "PI-01a", "matched_text": "...", "detail": "..."}
        ]
    }

One Prompt-Guard-2 classification per request. Class output is mapped to the
most-specific requested sub-check ID based on the event's shape. Only IDs
that were requested (and that this service can honestly judge) are ever
returned — anything else falls back to the caller's regex.
"""
from __future__ import annotations

import logging
import math
import os
import re
import threading
import time
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from pydantic import BaseModel, Field
from transformers import pipeline

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
logger = logging.getLogger("dapplepot-reflex")

MODEL_ID = os.environ.get("MODEL_ID", "meta-llama/Llama-Prompt-Guard-2-86M")
# REFLEX_API_SECRET is the current name. REFLEX_INTERNAL_SECRET is accepted
# as a fallback so an already-deployed Cloud Run revision using the older
# env-var name keeps working until it's redeployed.
INTERNAL_SECRET = (
    os.environ.get("REFLEX_API_SECRET")
    or os.environ.get("REFLEX_INTERNAL_SECRET", "")
)

# The classifier does not own the "is this confident enough to fire" policy —
# that's a knob on the security service side (settings.reflex_threshold).
# This service emits a finding whenever the model's top non-BENIGN score
# beats BENIGN, always attaching the raw score. The caller decides whether
# to act on it.

# Sub-check IDs this service is willing to judge. Everything else the caller
# might ask for is silently ignored — those checks stay on the caller's
# regex path. This is the honest coverage boundary of a prompt-injection
# classifier; see README for the rationale.
JUDGEABLE_IDS: frozenset[str] = frozenset({
    # prompt_injection category (13)
    "PI-01a", "PI-01b", "PI-01c",
    "PI-02a", "PI-02c",
    "PI-03a", "PI-03b",
    "PI-05a", "PI-07a", "PI-08a", "PI-09a",
    "MCP-01a", "AGH-04a",
    # other category — same problem shape, different channel
    "IAC-01b", "MCP-03a",
})

# ─────────────────────────────────────────────────────────────────────────────
# Truncation — head + tail sampling
#
# Naive text[:N] misses injections that hide at the tail of long documents
# (HTML-comment footers, "silent" trailing instructions, etc.). Head+tail
# sampling keeps the same total budget but covers both document boundaries
# where indirect-injection payloads actually live.
#
# Note: we deliberately do NOT run a suspicion regex here. Those patterns
# already live in dapplepot-security/detectors/online.py — duplicating them
# in this service would drift out of sync. For a "point the classifier at
# suspicious spans" upgrade, extend the wire protocol so the caller passes
# in span hints; do not re-implement regex here.
# ─────────────────────────────────────────────────────────────────────────────

REFLEX_MAX_INPUT_CHARS = int(os.environ.get("REFLEX_MAX_INPUT_CHARS", "4000"))
REFLEX_HINT_CONTEXT_CHARS = int(os.environ.get("REFLEX_HINT_CONTEXT_CHARS", "150"))
_MAX_HINT_EXCERPTS = 5


def _hint_spans(text: str, hint_texts: list[str]) -> list[tuple[int, int]]:
    """Locate every occurrence of each hint string inside `text` and return
    merged, non-overlapping spans. Caller-provided hints only — no regex
    lives in this service (see notes at top of file)."""
    spans: list[tuple[int, int]] = []
    for h in hint_texts:
        if not h:
            continue
        start = 0
        while True:
            i = text.find(h, start)
            if i < 0:
                break
            spans.append((i, i + len(h)))
            start = i + 1
            if len(spans) > 50:
                break
    if not spans:
        return spans
    spans.sort()
    merged: list[tuple[int, int]] = [spans[0]]
    for s, e in spans[1:]:
        ps, pe = merged[-1]
        if s <= pe + 50:
            merged[-1] = (ps, max(pe, e))
        else:
            merged.append((s, e))
    return merged


def _smart_truncate(
    text: str,
    hint_texts: list[str] | None = None,
    cap: int | None = None,
) -> str:
    """Return a classifier-friendly view of `text`.

    Head + tail is always taken (fixed budget: cap // 2 each side). Hint
    excerpts are added ONLY for hints that fall in the middle region —
    hints already inside the head or tail are skipped as redundant.

    No ceiling on total output length: the caller (classifier pipeline)
    truncates to REFLEX_MAX_INPUT_TOKENS at inference time, which is the
    real gate. Skipping the char-level ceiling means every middle hint
    gets its context window regardless of how many there are.
    """
    cap = cap if cap is not None else REFLEX_MAX_INPUT_CHARS
    if len(text) <= cap:
        return text

    half = (cap - 20) // 2  # room for separators
    head_end = half
    tail_start = len(text) - half

    # If the head+tail regions already cover the whole doc, just return text.
    if head_end >= tail_start:
        return text
    head = text[:head_end]
    tail = text[tail_start:]

    # Middle excerpts — only for hints outside the head+tail regions.
    middle_excerpts: list[str] = []
    if hint_texts:
        ctx = REFLEX_HINT_CONTEXT_CHARS
        for s, e in _hint_spans(text, hint_texts):
            if s < head_end or e > tail_start:
                continue  # already covered by head or tail
            cs = max(head_end, s - ctx)
            ce = min(tail_start, e + ctx)
            middle_excerpts.append(text[cs:ce])
            if len(middle_excerpts) >= _MAX_HINT_EXCERPTS:
                break

    if middle_excerpts:
        middle = "\n<...>\n".join(middle_excerpts)
        return head + "\n<HEAD/MIDDLE>\n" + middle + "\n<MIDDLE/TAIL>\n" + tail
    return head + "\n<truncated>\n" + tail


# ─────────────────────────────────────────────────────────────────────────────
# Text extraction — mirrors dapplepot-security detectors/online.py._extract_content
# ─────────────────────────────────────────────────────────────────────────────

def _extract_text(
    event_type: str,
    payload: dict[str, Any],
    hint_texts: list[str] | None = None,
) -> str:
    """Flatten the parts of the event payload the classifier should judge.

    If `hint_texts` are provided (strings the caller has already flagged as
    suspicious via its regex pass), they're passed through to _smart_truncate
    so long inputs get sampled around those regions instead of a naive
    head+tail."""
    parts: list[str] = []
    if event_type in ("llm_start", "chat_model_start"):
        msgs = payload.get("messages") or []
        if isinstance(msgs, list):
            for m in msgs:
                if not isinstance(m, dict):
                    continue
                if m.get("role") not in ("user", "human", "tool"):
                    continue
                content = m.get("content", "")
                if isinstance(content, list):
                    for part in content:
                        if isinstance(part, dict):
                            t = part.get("text") or part.get("content")
                            if isinstance(t, str):
                                parts.append(t)
                        elif isinstance(part, str):
                            parts.append(part)
                elif isinstance(content, str):
                    parts.append(content)
    elif event_type == "llm_end":
        c = payload.get("completion")
        if isinstance(c, str):
            parts.append(c)
    elif event_type == "tool_start":
        for k in ("tool_input", "args", "input"):
            v = payload.get(k)
            if isinstance(v, str):
                parts.append(v)
            elif isinstance(v, dict):
                parts.append(str(v))
    elif event_type == "tool_end":
        v = payload.get("tool_output")
        if isinstance(v, str):
            parts.append(v)
        elif isinstance(v, (dict, list)):
            parts.append(str(v))
    # Truncate — the classifier caps at REFLEX_MAX_INPUT_TOKENS tokens anyway.
    # Use head+tail sampling (with hint anchors when the caller provided any)
    # so injections at the document tail aren't missed.
    return _smart_truncate("\n".join(parts), hint_texts=hint_texts)


# ─────────────────────────────────────────────────────────────────────────────
# Sub-check ID routing — pick the most specific ID for this event + class
# ─────────────────────────────────────────────────────────────────────────────

_DELIMITER_RE = re.compile(
    r"(?i)(\[/?(SYSTEM|USER|INSTRUCTION)\]|<\|im_(start|end)\|>|</?s>|<<SYS>>)"
)
_HEX_RE      = re.compile(r"(?:\\x[0-9a-fA-F]{2}|%[0-9a-fA-F]{2}){6,}")
_BASE64_RE   = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
_ROT13_HINT  = re.compile(r"[a-z]{20,}", re.IGNORECASE)  # long lowercase run (weak signal)
_CODE_RE     = re.compile(r"(?i)\b(eval|exec|__import__|subprocess|os\.system|compile)\s*\(")
_API_TOOL_RE = re.compile(r"(?i)(http|rest|api|fetch|request|call)")
_DB_TOOL_RE  = re.compile(r"(?i)(sql|query|postgres|mysql|mongo|db|database)")


def _char_entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _has_image_part(payload: dict[str, Any]) -> bool:
    msgs = payload.get("messages") or []
    if not isinstance(msgs, list):
        return False
    for m in msgs:
        if isinstance(m, dict) and isinstance(m.get("content"), list):
            for p in m["content"]:
                if isinstance(p, dict) and p.get("type") in ("image_url", "image"):
                    return True
    return False


def _has_document_part(payload: dict[str, Any]) -> bool:
    msgs = payload.get("messages") or []
    if not isinstance(msgs, list):
        return False
    for m in msgs:
        if isinstance(m, dict) and isinstance(m.get("content"), list):
            for p in m["content"]:
                if isinstance(p, dict) and p.get("type") in ("document", "file"):
                    return True
    return False


def _route_sub_check(
    event_type: str,
    payload: dict[str, Any],
    text: str,
    is_direct: bool,
    requested: set[str],
) -> str | None:
    """Pick the most-specific requested sub-check ID for this event shape.

    `is_direct` = the source of the text is a direct user turn (llm_start
    with a user-role message). Otherwise the source is external content
    (tool output, document, retrieval, etc.). This distinction drives which
    sub-check family the finding goes to; the model's label taxonomy
    (BENIGN/MALICIOUS in v2, BENIGN/INJECTION/JAILBREAK in v1, etc.) is
    intentionally not consulted here — event shape is the authoritative
    signal for routing.
    """
    def pick(*candidates: str) -> str | None:
        for cid in candidates:
            if cid in JUDGEABLE_IDS and cid in requested:
                return cid
        return None

    if is_direct:
        # Direct-user attack — sub-check by structural cue in the text.
        if _DELIMITER_RE.search(text):
            return pick("PI-01b", "PI-01a")
        if _HEX_RE.search(text) or _BASE64_RE.search(text):
            return pick("PI-01c", "PI-09a", "PI-01a")
        if len(text) > 80 and _char_entropy(text[-60:]) > 4.5:
            return pick("PI-08a", "PI-01a")
        if _CODE_RE.search(text):
            return pick("PI-05a", "PI-01a")
        return pick("PI-01a", "PI-09a")

    # Indirect — attack arrived via external content. Route by source shape.
    if event_type == "tool_end":
        tool_name = str((payload.get("tool_name") or "")).strip()
        if _DB_TOOL_RE.search(tool_name):
            return pick("PI-03b", "PI-02a")
        if _API_TOOL_RE.search(tool_name):
            return pick("PI-03a", "PI-02a")
        return pick("PI-02a", "PI-03a")
    if event_type in ("llm_start", "chat_model_start"):
        if _has_document_part(payload):
            return pick("PI-02c", "AGH-04a", "PI-02a")
        if _has_image_part(payload):
            return pick("PI-07a", "PI-02a")
        return pick("MCP-01a", "IAC-01b", "MCP-03a", "PI-02a", "AGH-04a")
    return pick("PI-02a", "MCP-01a", "AGH-04a")


def _is_direct_user_source(event_type: str, payload: dict[str, Any]) -> bool:
    """True iff the classified text came from a direct user turn (as opposed
    to retrieved / tool-supplied content). Determines routing family."""
    if event_type not in ("llm_start", "chat_model_start"):
        return False
    if _has_document_part(payload) or _has_image_part(payload):
        return False
    msgs = payload.get("messages") or []
    if not isinstance(msgs, list):
        return False
    for m in msgs:
        if isinstance(m, dict) and m.get("role") in ("user", "human"):
            return True
    return False


# ─────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ─────────────────────────────────────────────────────────────────────────────

class ClassifyRequest(BaseModel):
    event: dict[str, Any] = Field(default_factory=dict)
    sub_check_ids: list[str] = Field(default_factory=list)
    # Optional. Strings the caller (dapplepot-security) has already flagged as
    # suspicious via its regex pass. When the extracted text exceeds
    # REFLEX_MAX_INPUT_CHARS, _smart_truncate uses these as anchors so the
    # classifier sees the regions that matter instead of a naive head+tail.
    # No regex duplication in this service — hints come from the caller.
    hint_texts: list[str] = Field(default_factory=list)


app = FastAPI(title="dapplepot-reflex", version="0.1.0")
_PIPE = None  # populated at startup


KEEP_WARM_INTERVAL_MS = int(os.environ.get("REFLEX_KEEP_WARM_INTERVAL_MS", "30000"))


def _keep_warm_loop() -> None:
    """Background thread: pings the classifier every
    REFLEX_KEEP_WARM_INTERVAL_MS milliseconds so torch/transformers state
    stays hot in CPU cache. Without this, first inference after any idle
    period pays ~2-3s cold-start on small VMs, which blows past the SDK's
    5s online-check timeout."""
    interval_s = KEEP_WARM_INTERVAL_MS / 1000.0
    while True:
        try:
            if _PIPE is not None:
                _PIPE("keep warm")
        except Exception as exc:
            logger.warning("keep-warm ping failed: %s", exc)
        time.sleep(interval_s)


@app.on_event("startup")
def _load_model() -> None:
    global _PIPE
    logger.info("loading model %s", MODEL_ID)
    _PIPE = pipeline(
        "text-classification",
        model=MODEL_ID,
        truncation=True,
        max_length=512,
        top_k=None,      # return every class score
    )
    # Eager warm-up: force torch/tokenizer first-inference cost during
    # container start (inside the compose start_period) rather than on the
    # first real user request.
    t0 = time.time()
    _PIPE("warmup")
    logger.info("model ready and warmed in %.2fs", time.time() - t0)
    # Keep-warm heartbeat.
    threading.Thread(target=_keep_warm_loop, daemon=True).start()
    logger.info("keep-warm thread started (interval=%sms)", KEEP_WARM_INTERVAL_MS)


def _check_auth(x_internal_secret: str | None) -> None:
    if not INTERNAL_SECRET:
        return  # dev mode; auth disabled
    if x_internal_secret != INTERNAL_SECRET:
        raise HTTPException(status_code=401, detail="unauthorized")


@app.get("/health")
def health() -> dict[str, Any]:
    return {"status": "ok" if _PIPE is not None else "loading", "model": MODEL_ID}


@app.post("/")
async def classify(
    req: ClassifyRequest,
    x_internal_secret: str | None = Header(default=None, alias="X-Internal-Secret"),
) -> dict[str, Any]:
    _check_auth(x_internal_secret)
    if _PIPE is None:
        raise HTTPException(status_code=503, detail="model not ready")

    event = req.event or {}
    event_type = str(event.get("event_type", ""))
    payload = event.get("payload") if isinstance(event.get("payload"), dict) else {}
    requested = set(req.sub_check_ids or [])

    text = _extract_text(event_type, payload, hint_texts=req.hint_texts)
    if not text.strip():
        return {"findings": []}

    # Run the classifier once — top_k=None gives us the score for each class.
    try:
        raw = _PIPE(text)
    except Exception as exc:
        logger.exception("classifier failed: %s", exc)
        raise HTTPException(status_code=500, detail="classifier error")

    # transformers may return either a list of {label, score} or a list-of-lists
    # (when top_k=None). Normalise to a single list of dicts.
    scored = raw[0] if raw and isinstance(raw[0], list) else raw
    best: dict[str, float] = {}
    for item in scored:
        if isinstance(item, dict):
            best[str(item.get("label", "")).upper()] = float(item.get("score", 0.0))

    # Emit at most one finding when the top-scoring class is anything but
    # benign. We deliberately don't care whether the model labels the attack
    # class as INJECTION / JAILBREAK / MALICIOUS / LABEL_1 — different model
    # versions use different taxonomies, and the sub-check routing is driven
    # by event shape (direct user turn vs indirect content), not by the
    # model's label. That keeps this service model-swap-friendly.
    findings: list[dict[str, Any]] = []
    _BENIGN_LABELS = {"BENIGN", "SAFE", "LABEL_0", "0", "NEGATIVE", "NORMAL"}

    top_label, top_score = "", 0.0
    for label, score in best.items():
        if score > top_score:
            top_label, top_score = label, score

    if top_label and top_label.upper() not in _BENIGN_LABELS:
        is_direct = _is_direct_user_source(event_type, payload)
        sid = _route_sub_check(event_type, payload, text, is_direct, requested)
        if sid is not None:
            findings.append({
                "sub_check_id": sid,
                "matched_text": text[:300],
                "detail":       f"attack ({top_label.lower()}) score={top_score:.3f}",
                "score":        top_score,
            })

    return {"findings": findings}
