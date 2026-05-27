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


# ─── cfg_dict sanitizer ──────────────────────────────────────────────────────
# Stale Redis cache entries may have list fields serialized as JSON strings
# (e.g. tool_manifest = '"[]"' instead of '[]').  Sanitize before model_validate
# so Pydantic never sees a str where it expects list.

_LIST_FIELDS = (
    "tool_manifest", "privilege_scope", "network_allowlist", "irreversible_tools",
    "sbom_allowlist", "mcp_endpoints", "connected_llms", "connected_agents",
    "mcp_backed_tools", "registered_mcp_server_names", "delegation_auth_fields",
)

_DICT_FIELDS = ("tool_schemas", "operating_hours", "tool_approval_policy")

def _sanitize_cfg_dict(cfg: dict) -> dict:
    for field in _LIST_FIELDS:
        val = cfg.get(field)
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                cfg[field] = parsed if isinstance(parsed, list) else None
            except Exception:
                cfg[field] = None
    for field in _DICT_FIELDS:
        val = cfg.get(field)
        if isinstance(val, str):
            try:
                parsed = json.loads(val)
                cfg[field] = parsed if isinstance(parsed, dict) else None
            except Exception:
                cfg[field] = None
    return cfg


# ─── JSONB helpers (used when loading agent profile fields from Postgres) ─────

def _coerce_to_list(val) -> list:
    """Return val as a list, handling up to two levels of JSON encoding."""
    for _ in range(2):
        if isinstance(val, list):
            return val
        if not isinstance(val, str):
            return []
        try:
            val = json.loads(val)
        except Exception:
            return []
    return val if isinstance(val, list) else []


def _load_jsonb_list(raw) -> list | None:
    """Parse a JSONB column that should be a list. Returns None when the column is NULL."""
    if raw is None:
        return None
    if isinstance(raw, list):
        return raw
    try:
        import json as _json
        return _json.loads(raw)
    except Exception:
        return None


def _load_jsonb_dict(raw) -> dict | None:
    """Parse a JSONB column that should be a dict. Returns None when the column is NULL."""
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    try:
        import json as _json
        return _json.loads(raw)
    except Exception:
        return None


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
    # Privilege scope: subset of tool_manifest that is explicitly authorized to
    # perform privilege-level operations (IAM role assumption, SQL DDL, K8s RBAC, etc.).
    # Set via agent profile UI — each manifest tool has a "Privilege-capable" checkbox.
    # Empty list = none authorized → IPA-01a flags all privilege operations (safe default).
    privilege_scope: list[str] = Field(default_factory=list)
    # User-defined max tool calls per session (combination approach for EA-02b).
    # Not None → used as hard floor check before falling back to statistical baseline.
    max_tool_calls_per_session: int | None = None
    # Per-tool approval policy.
    # "always_allow"   — tool may run without a HITL gate (e.g. read-only lookups).
    # "needs_approval" — a human-review node must appear before each run of this tool.
    # "always_block"   — tool is entirely forbidden; if it runs EA-01a fires.
    # Tools absent from this dict fall back to: irreversible_tools list, then
    # HIGH_STAKES_TOOL_PATTERNS heuristic (treated as needs_approval when matched).
    tool_approval_policy: dict[str, Literal["always_allow", "needs_approval", "always_block"]] | None = None
    # Agent profile fields (NULL = auto; non-NULL = manual declaration)
    system_prompt:      str | None        = None
    environment:        str | None        = None  # 'production' | 'staging'
    irreversible_tools: list[str] | None  = None
    network_allowlist:  list[str] | None  = None
    working_directory:  str | None        = None
    write_namespace:    str | None        = None
    operating_hours:    dict | None       = None  # {days: [...], from: "09:00", to: "18:00"}
    sbom_allowlist:     list[str] | None  = None
    mcp_endpoints:      list[str] | None  = None
    # Connected LLM models — loaded from agent_llm_models table.
    # None = auto (no declaration); list = manual (EA-04a + UBC-01b become active).
    connected_llms:        list[str] | None  = None   # model names
    connected_llm_details: list[dict] | None = None   # [{name, context_window_tokens, input_cost_per_1k, output_cost_per_1k}]
    # Connected agents — loaded from agent_connected_agents table.
    # None = auto (IAC-05a blind); list = manual (IAC-05a checks delegations against this list).
    connected_agents: list[str] | None = None   # agent names
    # Token budget cap in USD — None = UBC-02b is blind; non-None = fires when session cost exceeds this.
    token_budget_usd: float | None = None
    # Delegation auth fields — additional field names (beyond the platform default set) that
    # count as a valid auth signature in inter-agent tool_input for IAC-01a.
    # None = use platform defaults only; list = platform defaults + these extras.
    delegation_auth_fields: list[str] | None = None
    # Tool schemas — loaded from tools inventory table for tools in tool_manifest.
    # Maps tool_name → properties dict (keys = declared parameter names).
    # None = no schemas declared; TME-01a falls back to pattern matching.
    tool_schemas: dict[str, dict] | None = None
    # Tool descriptions — loaded from tools inventory table for tools in tool_manifest.
    # Maps tool_name → description string.
    # None = not loaded; TME-02a falls back to event-level tool_description only.
    tool_descriptions: dict[str, str] | None = None
    # Tool versions — maps tool_name → version string declared in inventory.
    # Used by ASCV-01c: a schema change accompanied by a matching version bump is
    # treated as a declared update and suppressed. None = no versions declared.
    tool_versions: dict[str, str] | None = None
    # MCP-backed tools — tool names in tool_manifest that have an mcp_server_id set.
    mcp_backed_tools: set[str] = Field(default_factory=set)
    # MCP server names registered in the tenant's inventory (mcp_servers table).
    # ASCV-03a compares tool_start.tool_input.mcp_server_name against this list using
    # Levenshtein distance to detect typosquatting. Empty = check is blind.
    registered_mcp_server_names: list[str] = Field(default_factory=list)

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

    # Fold in agent-specific subcheck online toggles from Postgres so the cached
    # config includes the current online detection settings.  Without this,
    # get_agent_security_config returns the cache on a hit and never sees the
    # subcheck_overrides — causing the post-session scorer to skip PI-01a etc.
    try:
        from core.infra.postgres import get_pool
        pool = await get_pool()
        sc_row = await pool.fetchrow(
            "SELECT overrides FROM agent_subcheck_overrides "
            "WHERE tenant_id = $1 AND agent_id = $2",
            tenant_id, agent_id,
        )
        if sc_row and sc_row["overrides"]:
            subcheck_overrides_raw = sc_row["overrides"]
            if isinstance(subcheck_overrides_raw, str):
                subcheck_overrides_raw = json.loads(subcheck_overrides_raw)
            cfg_dict.setdefault("subcheck_overrides", {})
            cfg_dict["subcheck_overrides"].update(subcheck_overrides_raw)

        alert_row = await pool.fetchrow(
            "SELECT composite_threshold, llm_composite_threshold, asi_composite_threshold, "
            "       signal_thresholds, tool_manifest, privilege_scope, tool_approval_policy, "
            "       max_tool_calls_per_session, "
            "       system_prompt, environment, irreversible_tools, network_allowlist, "
            "       working_directory, write_namespace, operating_hours, sbom_allowlist, mcp_endpoints, "
            "       token_budget_usd "
            "FROM agent_alert_config WHERE tenant_id = $1 AND agent_id = $2",
            tenant_id, agent_id,
        )
        if alert_row:
            composite = alert_row["composite_threshold"]
            cfg_dict["composite_alert_threshold"] = composite
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
            raw_manifest = alert_row["tool_manifest"]
            if isinstance(raw_manifest, str):
                raw_manifest = json.loads(raw_manifest)
            cfg_dict["tool_manifest"] = raw_manifest or []
            raw_priv = alert_row["privilege_scope"]
            if isinstance(raw_priv, str):
                raw_priv = json.loads(raw_priv)
            cfg_dict["privilege_scope"] = raw_priv or []
            cfg_dict["tool_approval_policy"] = _load_jsonb_dict(alert_row["tool_approval_policy"])
            cfg_dict["max_tool_calls_per_session"] = alert_row["max_tool_calls_per_session"]
            # Profile fields — stored as JSONB (lists/dicts) or plain TEXT in the DB
            cfg_dict["system_prompt"]      = alert_row["system_prompt"]
            cfg_dict["environment"]        = alert_row["environment"]
            cfg_dict["irreversible_tools"] = _load_jsonb_list(alert_row["irreversible_tools"])
            cfg_dict["network_allowlist"]  = _load_jsonb_list(alert_row["network_allowlist"])
            cfg_dict["working_directory"]  = alert_row["working_directory"]
            cfg_dict["write_namespace"]    = alert_row["write_namespace"]
            cfg_dict["operating_hours"]    = _load_jsonb_dict(alert_row["operating_hours"])
            cfg_dict["sbom_allowlist"]     = _load_jsonb_list(alert_row["sbom_allowlist"])
            cfg_dict["mcp_endpoints"]      = _load_jsonb_list(alert_row["mcp_endpoints"])
            cfg_dict["token_budget_usd"]   = float(alert_row["token_budget_usd"]) if alert_row["token_budget_usd"] is not None else None

    except Exception:
        logger.exception(
            '"push_agent_defaults failed to load Postgres overrides tenant_id=%s agent_id=%s"',
            tenant_id, agent_id,
        )

    # Load connected LLM models — separate try so a missing migration doesn't
    # affect the existing config fields above.
    try:
        from core.infra.postgres import get_pool as _get_pool
        _pool = await _get_pool()
        llm_rows = await _pool.fetch(
            """SELECT m.name, m.context_window_tokens,
                      m.input_cost_per_1k, m.output_cost_per_1k
               FROM agent_llm_models alm
               JOIN llm_models m ON m.model_id = alm.model_id
               WHERE alm.tenant_id = $1::uuid AND alm.agent_id = $2::uuid""",
            tenant_id, agent_id,
        )
        if llm_rows:
            cfg_dict["connected_llms"] = [r["name"] for r in llm_rows]
            cfg_dict["connected_llm_details"] = [
                {
                    "name":                  r["name"],
                    "context_window_tokens": r["context_window_tokens"],
                    "input_cost_per_1k":     float(r["input_cost_per_1k"])  if r["input_cost_per_1k"]  is not None else None,
                    "output_cost_per_1k":    float(r["output_cost_per_1k"]) if r["output_cost_per_1k"] is not None else None,
                }
                for r in llm_rows
            ]
    except Exception:
        logger.debug(
            '"push_agent_defaults: skipping connected_llms (table may not exist yet) tenant_id=%s"',
            tenant_id,
        )

    # Load connected agents — separate try so a missing migration doesn't affect existing fields.
    try:
        from core.infra.postgres import get_pool as _get_pool
        _pool = await _get_pool()
        agent_rows = await _pool.fetch(
            """SELECT a.name
               FROM agent_connected_agents aca
               JOIN agents a ON a.agent_id = aca.connected_agent_id
               WHERE aca.tenant_id = $1::uuid AND aca.agent_id = $2::uuid""",
            tenant_id, agent_id,
        )
        if agent_rows:
            cfg_dict["connected_agents"] = [r["name"] for r in agent_rows]
    except Exception:
        logger.debug(
            '"push_agent_defaults: skipping connected_agents (table may not exist yet) tenant_id=%s"',
            tenant_id,
        )

    # Load registered MCP server names — isolated try so a missing table doesn't break other fields.
    try:
        from core.infra.postgres import get_pool as _get_pool
        _pool = await _get_pool()
        mcp_rows = await _pool.fetch(
            "SELECT name FROM mcp_servers WHERE tenant_id = $1::uuid",
            tenant_id,
        )
        if mcp_rows:
            cfg_dict["registered_mcp_server_names"] = [r["name"] for r in mcp_rows]
    except Exception:
        logger.debug(
            '"push_agent_defaults: skipping registered_mcp_server_names (table may not exist yet) tenant_id=%s"',
            tenant_id,
        )

    # Load tool schemas and descriptions — isolated so a missing migration doesn't break existing fields.
    # Only loads for tools whose names appear in tool_manifest.
    try:
        manifest_names = _coerce_to_list(cfg_dict.get("tool_manifest"))
        if manifest_names:
            from core.infra.postgres import get_pool as _get_pool
            _pool = await _get_pool()
            rows = await _pool.fetch(
                """SELECT name, schema, description, mcp_server_id FROM tools
                   WHERE tenant_id = $1::uuid
                     AND name = ANY($2)""",
                tenant_id, manifest_names,
            )
            if rows:
                schemas: dict[str, dict] = {}
                descriptions: dict[str, str] = {}
                mcp_backed: list[str] = []
                for r in rows:
                    raw = r["schema"]
                    for _ in range(2):
                        if not isinstance(raw, str):
                            break
                        raw = json.loads(raw)
                    if isinstance(raw, dict) and raw:
                        schemas[r["name"]] = raw
                    if r["description"]:
                        descriptions[r["name"]] = r["description"]
                    if r["mcp_server_id"]:
                        mcp_backed.append(r["name"])
                if schemas:
                    cfg_dict["tool_schemas"] = schemas
                if descriptions:
                    cfg_dict["tool_descriptions"] = descriptions
                if mcp_backed:
                    cfg_dict["mcp_backed_tools"] = mcp_backed
    except Exception:
        logger.debug(
            '"push_agent_defaults: skipping tool_schemas/descriptions (table may not exist yet) tenant_id=%s"',
            tenant_id,
        )

    cfg = AgentSecurityConfig.model_validate(_sanitize_cfg_dict(cfg_dict))
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
                "SELECT composite_threshold, llm_composite_threshold, asi_composite_threshold, "
                "       signal_thresholds, tool_manifest, privilege_scope, tool_approval_policy, "
                "       max_tool_calls_per_session, "
                "       system_prompt, environment, irreversible_tools, network_allowlist, "
                "       working_directory, write_namespace, operating_hours, sbom_allowlist, mcp_endpoints, "
                "       token_budget_usd "
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
                raw_priv = alert_row["privilege_scope"]
                if isinstance(raw_priv, str):
                    raw_priv = json.loads(raw_priv)
                cfg_dict["privilege_scope"] = raw_priv or []
                cfg_dict["tool_approval_policy"] = _load_jsonb_dict(alert_row["tool_approval_policy"])
                # User-defined max tool calls
                cfg_dict["max_tool_calls_per_session"] = alert_row["max_tool_calls_per_session"]
                # Profile fields — stored as JSONB (lists/dicts) or plain TEXT in the DB
                cfg_dict["system_prompt"]      = alert_row["system_prompt"]
                cfg_dict["environment"]        = alert_row["environment"]
                cfg_dict["irreversible_tools"] = _load_jsonb_list(alert_row["irreversible_tools"])
                cfg_dict["network_allowlist"]  = _load_jsonb_list(alert_row["network_allowlist"])
                cfg_dict["working_directory"]  = alert_row["working_directory"]
                cfg_dict["write_namespace"]    = alert_row["write_namespace"]
                cfg_dict["operating_hours"]    = _load_jsonb_dict(alert_row["operating_hours"])
                cfg_dict["sbom_allowlist"]     = _load_jsonb_list(alert_row["sbom_allowlist"])
                cfg_dict["mcp_endpoints"]      = _load_jsonb_list(alert_row["mcp_endpoints"])
                cfg_dict["token_budget_usd"]   = float(alert_row["token_budget_usd"]) if alert_row["token_budget_usd"] is not None else None
        except Exception:
            logger.exception(
                '"failed to load agent overrides from postgres tenant_id=%s agent_id=%s"',
                tenant_id,
                agent_id,
            )

        # Load connected LLM models — isolated so a missing migration doesn't
        # break the existing config fields.
        try:
            from core.infra.postgres import get_pool as _get_pool
            _pool = await _get_pool()
            llm_rows = await _pool.fetch(
                """SELECT m.name, m.context_window_tokens,
                          m.input_cost_per_1k, m.output_cost_per_1k
                   FROM agent_llm_models alm
                   JOIN llm_models m ON m.model_id = alm.model_id
                   WHERE alm.tenant_id = $1::uuid AND alm.agent_id = $2::uuid""",
                tenant_id, agent_id,
            )
            if llm_rows:
                cfg_dict["connected_llms"] = [r["name"] for r in llm_rows]
                cfg_dict["connected_llm_details"] = [
                    {
                        "name":                  r["name"],
                        "context_window_tokens": r["context_window_tokens"],
                        "input_cost_per_1k":     float(r["input_cost_per_1k"])  if r["input_cost_per_1k"]  is not None else None,
                        "output_cost_per_1k":    float(r["output_cost_per_1k"]) if r["output_cost_per_1k"] is not None else None,
                    }
                    for r in llm_rows
                ]
        except Exception:
            logger.debug(
                '"get_agent_security_config: skipping connected_llms (table may not exist yet) tenant_id=%s"',
                tenant_id,
            )

        # Load connected agents — isolated so a missing migration doesn't break existing fields.
        try:
            from core.infra.postgres import get_pool as _get_pool
            _pool = await _get_pool()
            agent_rows = await _pool.fetch(
                """SELECT a.name
                   FROM agent_connected_agents aca
                   JOIN agents a ON a.agent_id = aca.connected_agent_id
                   WHERE aca.tenant_id = $1::uuid AND aca.agent_id = $2::uuid""",
                tenant_id, agent_id,
            )
            if agent_rows:
                cfg_dict["connected_agents"] = [r["name"] for r in agent_rows]
        except Exception:
            logger.debug(
                '"get_agent_security_config: skipping connected_agents (table may not exist yet) tenant_id=%s"',
                tenant_id,
            )

        # Load registered MCP server names.
        try:
            from core.infra.postgres import get_pool as _get_pool
            _pool = await _get_pool()
            mcp_rows = await _pool.fetch(
                "SELECT name FROM mcp_servers WHERE tenant_id = $1::uuid",
                tenant_id,
            )
            if mcp_rows:
                cfg_dict["registered_mcp_server_names"] = [r["name"] for r in mcp_rows]
        except Exception:
            logger.debug(
                '"get_agent_security_config: skipping registered_mcp_server_names (table may not exist yet) tenant_id=%s"',
                tenant_id,
            )

        # Load tool schemas and descriptions — isolated so a missing migration doesn't break existing fields.
        try:
            manifest_names = _coerce_to_list(cfg_dict.get("tool_manifest"))
            if manifest_names:
                from core.infra.postgres import get_pool as _get_pool
                _pool = await _get_pool()
                rows = await _pool.fetch(
                    """SELECT name, schema, description, mcp_server_id, version FROM tools
                       WHERE tenant_id = $1::uuid
                         AND name = ANY($2)""",
                    tenant_id, manifest_names,
                )
                if rows:
                    schemas: dict[str, dict] = {}
                    descriptions: dict[str, str] = {}
                    versions: dict[str, str] = {}
                    mcp_backed: list[str] = []
                    for r in rows:
                        raw = r["schema"]
                        for _ in range(2):
                            if not isinstance(raw, str):
                                break
                            raw = json.loads(raw)
                        if isinstance(raw, dict) and raw:
                            schemas[r["name"]] = raw
                        if r["description"]:
                            descriptions[r["name"]] = r["description"]
                        if r["version"]:
                            versions[r["name"]] = r["version"]
                        if r["mcp_server_id"]:
                            mcp_backed.append(r["name"])
                    if schemas:
                        cfg_dict["tool_schemas"] = schemas
                    if descriptions:
                        cfg_dict["tool_descriptions"] = descriptions
                    if versions:
                        cfg_dict["tool_versions"] = versions
                    if mcp_backed:
                        cfg_dict["mcp_backed_tools"] = mcp_backed
        except Exception:
            logger.debug(
                '"get_agent_security_config: skipping tool_schemas/descriptions (table may not exist yet) tenant_id=%s"',
                tenant_id,
            )

    cfg = AgentSecurityConfig.model_validate(_sanitize_cfg_dict(cfg_dict))

    if agent_id:
        await redis.set(cache_key, cfg.model_dump_json(), ex=CACHE_TTL_S)

    return cfg


async def invalidate_agent_config_cache(redis, tenant_id: str, agent_id: str) -> None:
    """Delete the cached merged config so the next fetch rebuilds from scratch."""
    await redis.delete(_agent_cache_key(tenant_id, agent_id))
