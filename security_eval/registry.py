"""Registry-derived facet sets.

Loads registry_snapshot.json (produced by registry/gen_seed.py from the
canonical checks.yaml) and exposes the facet-derived sets that orchestrator
and other consumers need. Kills hardcoded frozensets that previously had to
be updated in tandem with the registry.

Consumers should import from here rather than duplicating the sets. When the
registry changes, re-run `python registry/gen_seed.py`; this module picks up
the changes at next process start.

Structure:
    ALL_CHECKS               list[dict]        — every check, all facets, unchanged from snapshot
    CHECK_BY_ID              dict[str, dict]   — lookup by sub_check_id
    ENFORCEABLE_SUBCHECK_IDS frozenset[str]    — checks with enforceable == True
    EVENT_SCOPE_IDS          frozenset[str]    — scope == 'event'
    SESSION_SCOPE_IDS        frozenset[str]    — scope == 'session'
    HISTORY_SCOPE_IDS        frozenset[str]    — scope == 'history'
    SESSION_LEVEL_ONLY_IDS   frozenset[str]    — session-scope checks that must not
                                                 also fire per-event when running
                                                 post-session (their session scorer
                                                 owns the finding).

    Model routing (from registry/model_coverage.yaml):
        REFLEX_SUBCHECK_IDS      frozenset[str]
        VERDICT_SUBCHECK_IDS     frozenset[str]
        REFLEX_CATEGORY_OF       dict[str, str]              — id → category name
        VERDICT_CATEGORY_OF      dict[str, str]
        REFLEX_BY_CATEGORY       dict[str, frozenset[str]]   — category → set of ids
        VERDICT_BY_CATEGORY      dict[str, frozenset[str]]
"""
from __future__ import annotations

import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Snapshot is written alongside signal_registry_seed.py — see registry/gen_seed.py
_SNAPSHOT_PATH = Path(__file__).parent.parent / "scripts" / "registry_snapshot.json"


def _load_snapshot() -> dict:
    """Read the JSON snapshot. Fatal error if missing — the module has no
    meaningful fallback; every downstream sub-check ID lives here."""
    try:
        return json.loads(_SNAPSHOT_PATH.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise RuntimeError(
            f"registry_snapshot.json not found at {_SNAPSHOT_PATH}. "
            "Run: python registry/gen_seed.py"
        ) from exc


_SNAPSHOT = _load_snapshot()


# ─── Flat check list + lookup ─────────────────────────────────────────────────

ALL_CHECKS: list[dict] = [
    check
    for signal in _SNAPSHOT["signals"]
    for check in signal["checks"]
]

CHECK_BY_ID: dict[str, dict] = {c["id"]: c for c in ALL_CHECKS}


# ─── Facet-derived sets ───────────────────────────────────────────────────────

ENFORCEABLE_SUBCHECK_IDS: frozenset[str] = frozenset(
    c["id"] for c in ALL_CHECKS if c.get("enforceable")
)

EVENT_SCOPE_IDS: frozenset[str] = frozenset(
    c["id"] for c in ALL_CHECKS if c.get("scope") == "event"
)

SESSION_SCOPE_IDS: frozenset[str] = frozenset(
    c["id"] for c in ALL_CHECKS if c.get("scope") == "session"
)

HISTORY_SCOPE_IDS: frozenset[str] = frozenset(
    c["id"] for c in ALL_CHECKS if c.get("scope") == "history"
)


# ─── Legacy behavioral sets ───────────────────────────────────────────────────
#
# SESSION_LEVEL_ONLY_IDS
#   Checks whose authoritative implementation is a session-level scorer, not
#   a per-event detector. When these are NOT configured online, the scorer
#   emits the finding; the per-event routing must skip them regardless of
#   scope. Historically EA-01a and EA-02b: they have both online-inline logic
#   in server/main.py (fires from tool_start) AND session-level scorers
#   (`detect_ea_tool_call_limit` for EA-02b) — the per-event detectors path
#   would otherwise double-count.
#
#   For EA-01c / EA-02a / EA-03b, the online logic already IS the per-event
#   detector semantics — no separate double-count risk — so they stay OUT
#   of this set.
#
#   Kept as an explicit list rather than derived from a facet because it
#   captures an implementation quirk, not a taxonomy property.

SESSION_LEVEL_ONLY_IDS: frozenset[str] = frozenset({"EA-01a", "EA-02b"})


# ─── Model coverage (from registry/model_coverage.yaml) ──────────────────────
#
# Which sub-checks route to Reflex (fast classifier) vs Verdict (LLM judge)
# vs neither (policy/statistical/history/small-regex/excluded). Loaded from
# a separate YAML so this dimension can be maintained without touching the
# 155 check definitions in checks.yaml.

_COVERAGE_YAML = Path(__file__).parent.parent / "registry" / "model_coverage.yaml"


def _load_coverage() -> dict:
    try:
        import yaml
    except ImportError as exc:
        raise RuntimeError(
            "PyYAML is required to load model_coverage.yaml. "
            "Add pyyaml to the security service dependencies."
        ) from exc
    try:
        with _COVERAGE_YAML.open("r", encoding="utf-8") as f:
            return yaml.safe_load(f) or {}
    except FileNotFoundError:
        logger.warning(
            "model_coverage.yaml not found at %s — model routing sets will be empty",
            _COVERAGE_YAML,
        )
        return {}


_COVERAGE = _load_coverage()


def _flatten_service(section: dict | None) -> tuple[frozenset[str], dict[str, str], dict[str, frozenset[str]]]:
    """(id set, id→category, category→id set) for one service section."""
    all_ids: set[str] = set()
    by_id: dict[str, str] = {}
    by_cat: dict[str, frozenset[str]] = {}
    for category, ids in (section or {}).items():
        cat_ids = frozenset(ids or [])
        by_cat[category] = cat_ids
        for sid in cat_ids:
            all_ids.add(sid)
            by_id[sid] = category
    return frozenset(all_ids), by_id, by_cat


REFLEX_SUBCHECK_IDS, REFLEX_CATEGORY_OF, REFLEX_BY_CATEGORY = _flatten_service(
    _COVERAGE.get("reflex")
)
VERDICT_SUBCHECK_IDS, VERDICT_CATEGORY_OF, VERDICT_BY_CATEGORY = _flatten_service(
    _COVERAGE.get("verdict")
)

# Sanity: warn on IDs that reference checks not in the main registry, or that
# somehow appear in both services.
_unknown_reflex  = REFLEX_SUBCHECK_IDS  - CHECK_BY_ID.keys()
_unknown_verdict = VERDICT_SUBCHECK_IDS - CHECK_BY_ID.keys()
_double_routed   = REFLEX_SUBCHECK_IDS  & VERDICT_SUBCHECK_IDS
if _unknown_reflex:
    logger.error("model_coverage.yaml lists Reflex IDs not in registry: %s", sorted(_unknown_reflex))
if _unknown_verdict:
    logger.error("model_coverage.yaml lists Verdict IDs not in registry: %s", sorted(_unknown_verdict))
if _double_routed:
    logger.error("model_coverage.yaml routes to both services: %s", sorted(_double_routed))


# ─── Utility ──────────────────────────────────────────────────────────────────

def snapshot_summary() -> str:
    """One-line summary for startup logs."""
    return (
        f"registry: {len(ALL_CHECKS)} sub-checks · "
        f"{len(ENFORCEABLE_SUBCHECK_IDS)} enforceable · "
        f"{len(EVENT_SCOPE_IDS)} event / {len(SESSION_SCOPE_IDS)} session / {len(HISTORY_SCOPE_IDS)} history · "
        f"{len(REFLEX_SUBCHECK_IDS)} Reflex / {len(VERDICT_SUBCHECK_IDS)} Verdict"
    )


def model_tier_summary() -> str:
    """One-line summary of Reflex/Verdict tier configuration for startup logs."""
    # Local import — settings pulls in env parsing; keep registry import cheap.
    from core.config import settings
    reflex = settings.reflex_endpoint_url or "not configured (regex fallback)"
    verdict = (
        f"{settings.verdict_model} @ {settings.nvidia_base_url}"
        if settings.nvidia_api_key
        else "not configured (heuristic fallback)"
    )
    return f"Reflex: {reflex}  ·  Verdict: {verdict}"


def coverage_report() -> dict:
    """Return the full coverage breakdown by bucket.

    Buckets are MUTUALLY EXCLUSIVE and sum to len(ALL_CHECKS). Priority (a
    check belongs to the first bucket that matches):

        1. reflex          — routed to Reflex model
        2. verdict         — routed to Verdict model
        3. excluded        — status != active
        4. history_scoped  — scope == history (mechanism doesn't matter)
        5. policy          — mechanism == policy
        6. statistical     — mechanism == statistical
        7. signature       — mechanism == signature (small-regex bucket)
        8. behavioral      — mechanism == behavioral
    """
    buckets: dict[str, set[str]] = {
        "reflex":         set(),
        "verdict":        set(),
        "excluded":       set(),
        "history_scoped": set(),
        "policy":         set(),
        "statistical":    set(),
        "signature":      set(),
        "behavioral":     set(),
    }
    for c in ALL_CHECKS:
        cid = c["id"]
        if cid in REFLEX_SUBCHECK_IDS:
            buckets["reflex"].add(cid)
        elif cid in VERDICT_SUBCHECK_IDS:
            buckets["verdict"].add(cid)
        elif c["status"] != "active":
            buckets["excluded"].add(cid)
        elif c["scope"] == "history":
            buckets["history_scoped"].add(cid)
        elif c["mechanism"] == "policy":
            buckets["policy"].add(cid)
        elif c["mechanism"] == "statistical":
            buckets["statistical"].add(cid)
        elif c["mechanism"] == "signature":
            buckets["signature"].add(cid)
        elif c["mechanism"] == "behavioral":
            buckets["behavioral"].add(cid)
        else:
            # Fallback — shouldn't happen with the current registry.
            logger.warning("unclassified check in coverage_report: %s", cid)

    return {
        "total": len(ALL_CHECKS),
        **{k: frozenset(v) for k, v in buckets.items()},
    }


logger.info(snapshot_summary())
logger.info(model_tier_summary())
