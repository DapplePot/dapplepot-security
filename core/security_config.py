"""
Two-level security configuration system.

Level 1 – Platform defaults
    All 20 OWASP signals (OW-LLM01–10 and OW-ASI01–10) are enabled with
    platform thresholds that mirror SIGNAL_ALERT_THRESHOLDS_V3 in config.py.
    Pushed to Redis the first time an agent is created (agent_created Kafka
    event) and auto-seeded on first session if that event was missed.

Level 2 – Admin / tenant overrides  (future)
    Tenant admins will be able to write partial override dicts into Redis
    via an external API to adjust per-signal thresholds or the composite
    alert threshold.  The merge infrastructure is already wired; fields will
    be added to AgentSecurityConfig as features are released.

Redis key layout
────────────────
  dp:sec:defaults
      Platform-wide default AgentSecurityConfig JSON.  Written once; never
      expires so it survives Redis restarts.

  dp:sec:{tenant_id}:overrides
      Tenant-wide overrides (reserved for future use).

  dp:sec:{tenant_id}:agent:{agent_id}:overrides
      Agent-specific overrides (reserved for future use).

  dp:sec:{tenant_id}:agent:{agent_id}:cfg
      Cached merged config (TTL = CACHE_TTL_S).  Rebuilt automatically
      when stale.

Merge order (later wins):
  platform defaults → tenant overrides → agent overrides → cached result

Source of truth for signal IDs and excluded status:
  scripts/seed_signal_registry.py  (mirrors dapplepot-ui/src/data/signalRegistry.ts)
"""
from __future__ import annotations

import json
import logging
from typing import Literal
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ─── Cache TTL ───────────────────────────────────────────────────────────────
CACHE_TTL_S: int = 300   # 5 minutes

# ─── Config models ───────────────────────────────────────────────────────────

class SignalConfig(BaseModel):
    """Per-signal on/off switch + alert threshold override."""
    enabled: bool = True
    alert_threshold: int = 70


class SubCheckOverride(BaseModel):
    """Per-sub-check online detection toggle and action config.

    online_detection=True  → the langgraph-sdk runs this check in real time.
                             The post-session scorer will skip it to avoid double-counting.
    online_detection=False → default; post-session scorer handles it.

    action: what the SDK does when this sub-check fires (only relevant when
            online_detection=True).  Zone 6 reads action_taken from the emitted
            security_finding event to decide whether to alert.

        alert             → SDK continues; Zone 6 stores finding + fires combined alert.
        sanitize          → SDK strips the harmful content (e.g. PII, injected
                            directives) from the message/response in-flight and
                            allows the session to continue with the cleaned
                            content; Zone 6 stores finding + session_action
                            + fires combined alert.
        terminate_session → SDK raises SecurityViolationError to kill graph
                            execution; Zone 6 stores finding + session_action
                            + fires combined alert.
    """
    online_detection: bool = False
    action: Literal["alert", "sanitize", "block_call", "terminate_session"] = "alert"


class AgentSecurityConfig(BaseModel):
    """
    Effective security config for a single agent.

    Currently: 20 signals with platform defaults, all on.
    Future:     per-signal overrides, blocked_tools, custom_checkpoints, etc.
    """
    signals: dict[str, SignalConfig] = Field(default_factory=dict)
    # Composite thresholds: alert if the respective composite ≥ this value.
    # Mirrors COMPOSITE_ALERT_THRESHOLD_V3 = 60.
    # llm_composite_alert_threshold / asi_composite_alert_threshold can be set
    # independently; composite_alert_threshold is kept as a shared fallback.
    composite_alert_threshold:     int = 60
    llm_composite_alert_threshold: int = 60
    asi_composite_alert_threshold: int = 60
    # Per-sub-check online detection overrides.
    # Key = sub_check_id (e.g. "PI-01a"), value = SubCheckOverride.
    # Only populated for sub-checks that have been toggled; absent = post_session default.
    subcheck_overrides: dict[str, SubCheckOverride] = Field(default_factory=dict)
    # Tool manifest: list of allowed tool names for this agent.
    # Empty list = not configured → manifest-dependent sub-checks (EA-01a, ASCV-01a,
    # TME-06a) return None silently.
    tool_manifest: list[str] = Field(default_factory=list)
    # User-defined max tool calls per session (combination approach for EA-02b).
    # Not None → used as hard floor check before falling back to statistical baseline.
    max_tool_calls_per_session: int | None = None

    def is_online(self, sub_check_id: str) -> bool:
        """Return True if this sub-check should be handled by the SDK (not post-session)."""
        override = self.subcheck_overrides.get(sub_check_id)
        return override.online_detection if override else False

    def online_subcheck_ids(self) -> frozenset[str]:
        """Return the set of sub-check IDs configured for online (SDK) detection."""
        return frozenset(
            sid for sid, ov in self.subcheck_overrides.items()
            if ov.online_detection
        )


# ─── Platform default thresholds ─────────────────────────────────────────────
# Mirrors SIGNAL_ALERT_THRESHOLDS_V3 in core/config.py exactly.
# Threshold = 999 means the signal fires findings but never triggers a
# threshold-based alert (excluded or pre-runtime signals).

_DEFAULT_THRESHOLDS: dict[str, int] = {
    "OW-LLM01": 70,
    "OW-LLM02": 75,
    "OW-LLM03": 999,   # fully excluded (no observable sub-checks)
    "OW-LLM04": 999,   # fully excluded (pre-runtime only)
    "OW-LLM05": 70,
    "OW-LLM06": 65,
    "OW-LLM07": 70,
    "OW-LLM08": 999,   # mostly pre-runtime; threshold kept high to match config.py
    "OW-LLM09": 60,
    "OW-LLM10": 55,
    "OW-ASI01": 70,
    "OW-ASI02": 65,
    "OW-ASI03": 70,
    "OW-ASI04": 70,
    "OW-ASI05": 60,
    "OW-ASI06": 70,
    "OW-ASI07": 75,
    "OW-ASI08": 70,
    "OW-ASI09": 70,
    "OW-ASI10": 65,
}

# Signals with NO active sub-checks at runtime — enabled=False in default config.
# Source: seed_signal_registry.py — signals where every sub-check has excluded=True.
# OW-LLM03: SC-EXCL only, excluded.
# OW-LLM04: DMP-01a/b/c + DMP-02, all excluded.
# OW-LLM08 is NOT fully excluded — VEW-02b is active — so it stays enabled=True
# with alert_threshold=999 to prevent alerting on partial observations.
_FULLY_EXCLUDED_SIGNALS: set[str] = {"OW-LLM03", "OW-LLM04"}


def build_default_config() -> AgentSecurityConfig:
    """Return an AgentSecurityConfig seeded with all 20 platform defaults."""
    signals = {
        sig_id: SignalConfig(
            enabled=sig_id not in _FULLY_EXCLUDED_SIGNALS,
            alert_threshold=threshold,
        )
        for sig_id, threshold in _DEFAULT_THRESHOLDS.items()
    }
    return AgentSecurityConfig(signals=signals)


# ─── Redis key helpers ────────────────────────────────────────────────────────

_DEFAULTS_KEY = "dp:sec:defaults"


def _tenant_overrides_key(tenant_id: str) -> str:
    return f"dp:sec:{tenant_id}:overrides"


def _agent_overrides_key(tenant_id: str, agent_id: str) -> str:
    return f"dp:sec:{tenant_id}:agent:{agent_id}:overrides"


def _agent_cache_key(tenant_id: str, agent_id: str) -> str:
    return f"dp:sec:{tenant_id}:agent:{agent_id}:cfg"


# ─── Merge helper ─────────────────────────────────────────────────────────────

def _deep_merge(base: dict, override: dict) -> None:
    """
    Merge *override* into *base* in-place.
    Dicts are merged recursively; all other types are replaced wholesale.
    """
    for key, val in override.items():
        if key in base and isinstance(base[key], dict) and isinstance(val, dict):
            _deep_merge(base[key], val)
        else:
            base[key] = val


# ─── Public async API ─────────────────────────────────────────────────────────

async def ensure_platform_defaults(redis) -> None:
    """
    Seed the platform default config into Redis if absent.
    Safe to call multiple times (no-op when key already exists).
    """
    existing = await redis.get(_DEFAULTS_KEY)
    if not existing:
        cfg = build_default_config()
        await redis.set(_DEFAULTS_KEY, cfg.model_dump_json())
        logger.info('"security platform defaults seeded into Redis"')


async def push_agent_defaults(redis, tenant_id: str, agent_id: str) -> AgentSecurityConfig:
    """
    Called on agent_created: write the platform default config as the agent's
    effective cached config so the scorer never has to build it from scratch.

    Tenant-wide overrides (if any) are merged in at push time.
    """
    raw_defaults = await redis.get(_DEFAULTS_KEY)
    if raw_defaults:
        cfg_dict: dict = json.loads(raw_defaults)
    else:
        cfg_dict = build_default_config().model_dump()
        await redis.set(_DEFAULTS_KEY, json.dumps(cfg_dict))

    # Apply tenant-wide overrides if already configured
    raw_tenant = await redis.get(_tenant_overrides_key(tenant_id))
    if raw_tenant:
        _deep_merge(cfg_dict, json.loads(raw_tenant))

    cfg = AgentSecurityConfig.model_validate(cfg_dict)
    cache_key = _agent_cache_key(tenant_id, agent_id)
    await redis.set(cache_key, cfg.model_dump_json(), ex=CACHE_TTL_S)
    logger.info(
        '"agent security config pushed to Redis tenant_id=%s agent_id=%s"',
        tenant_id,
        agent_id,
    )
    return cfg


async def get_agent_security_config(
    redis,
    tenant_id: str,
    agent_id: str | None,
) -> AgentSecurityConfig:
    """
    Fetch the merged effective security config for (tenant_id, agent_id).

    Merge order (later overrides earlier):
      1. Platform defaults          dp:sec:defaults
      2. Tenant-wide overrides      dp:sec:{tenant_id}:overrides
      3. Agent-specific overrides   dp:sec:{tenant_id}:agent:{agent_id}:overrides
      4. Subcheck overrides         agent_subcheck_overrides (Postgres, loaded on cache miss)
      5. Cached merged result       dp:sec:{tenant_id}:agent:{agent_id}:cfg  (TTL 5 min)

    On cache miss the merge is recomputed and cached.
    If agent_id is None, falls back to tenant-merged defaults only.
    """
    if agent_id:
        cache_key = _agent_cache_key(tenant_id, agent_id)
        cached = await redis.get(cache_key)
        if cached:
            return AgentSecurityConfig.model_validate_json(cached)

    # Build merged config from scratch
    raw_defaults = await redis.get(_DEFAULTS_KEY)
    if raw_defaults:
        cfg_dict: dict = json.loads(raw_defaults)
    else:
        cfg_dict = build_default_config().model_dump()
        await redis.set(_DEFAULTS_KEY, json.dumps(cfg_dict))

    raw_tenant = await redis.get(_tenant_overrides_key(tenant_id))
    if raw_tenant:
        _deep_merge(cfg_dict, json.loads(raw_tenant))

    if agent_id:
        raw_agent = await redis.get(_agent_overrides_key(tenant_id, agent_id))
        if raw_agent:
            _deep_merge(cfg_dict, json.loads(raw_agent))

    # Fold in subcheck online toggles + alert threshold overrides from Postgres
    if agent_id:
        try:
            from core.infra.postgres import get_pool
            pool = await get_pool()

            # Sub-check online detection toggles
            sc_row = await pool.fetchrow(
                "SELECT overrides FROM agent_subcheck_overrides "
                "WHERE tenant_id = $1 AND agent_id = $2",
                tenant_id,
                agent_id,
            )
            if sc_row and sc_row["overrides"]:
                subcheck_overrides_raw = sc_row["overrides"]
                if isinstance(subcheck_overrides_raw, str):
                    subcheck_overrides_raw = json.loads(subcheck_overrides_raw)
                cfg_dict.setdefault("subcheck_overrides", {})
                cfg_dict["subcheck_overrides"].update(subcheck_overrides_raw)

            # Per-agent alert threshold overrides
            alert_row = await pool.fetchrow(
                "SELECT composite_threshold, "
                "       llm_composite_threshold, "
                "       asi_composite_threshold, "
                "       signal_thresholds, "
                "       tool_manifest, "
                "       max_tool_calls_per_session "
                "FROM agent_alert_config "
                "WHERE tenant_id = $1 AND agent_id = $2",
                tenant_id,
                agent_id,
            )
            if alert_row:
                composite = alert_row["composite_threshold"]
                cfg_dict["composite_alert_threshold"] = composite
                # Per-framework: NULL → fall back to shared composite_threshold
                cfg_dict["llm_composite_alert_threshold"] = (
                    alert_row["llm_composite_threshold"]
                    if alert_row["llm_composite_threshold"] is not None
                    else composite
                )
                cfg_dict["asi_composite_alert_threshold"] = (
                    alert_row["asi_composite_threshold"]
                    if alert_row["asi_composite_threshold"] is not None
                    else composite
                )
                sig_thresholds = alert_row["signal_thresholds"]
                if isinstance(sig_thresholds, str):
                    sig_thresholds = json.loads(sig_thresholds)
                if sig_thresholds:
                    cfg_dict.setdefault("signals", {})
                    for sig_id, threshold in sig_thresholds.items():
                        cfg_dict["signals"].setdefault(sig_id, {})
                        cfg_dict["signals"][sig_id]["alert_threshold"] = threshold
                # Tool manifest
                raw_manifest = alert_row["tool_manifest"]
                if isinstance(raw_manifest, str):
                    raw_manifest = json.loads(raw_manifest)
                cfg_dict["tool_manifest"] = raw_manifest or []
                # User-defined max tool calls
                cfg_dict["max_tool_calls_per_session"] = alert_row["max_tool_calls_per_session"]
        except Exception:
            logger.exception(
                '"failed to load agent overrides from postgres tenant_id=%s agent_id=%s"',
                tenant_id,
                agent_id,
            )

    cfg = AgentSecurityConfig.model_validate(cfg_dict)

    if agent_id:
        await redis.set(cache_key, cfg.model_dump_json(), ex=CACHE_TTL_S)

    return cfg


async def invalidate_agent_config_cache(redis, tenant_id: str, agent_id: str) -> None:
    """Delete the cached merged config so the next fetch rebuilds from scratch."""
    await redis.delete(_agent_cache_key(tenant_id, agent_id))
