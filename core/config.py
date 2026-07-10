import json
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    postgres_dsn: str = "postgresql://dapplepot:dapplepot@localhost:5432/dapplepot_pipeline"
    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123
    clickhouse_user: str = "dapplepot"
    clickhouse_password: str = "dapplepot"
    redis_url: str = "redis://localhost:6379/0"

    security_eval_workers: int = 4
    scorer_version: str = "3.0.0"
    sig_cache_ttl_s: int = 300

    # Legacy single threshold kept for backward compat (now superseded by
    # SIGNAL_ALERT_THRESHOLDS_V3 below; composite check uses COMPOSITE_ALERT_THRESHOLD_V3).
    alert_on_score_gte: int = 65

    tool_manifests: str = "{}"
    internal_api_secret: str = ""
    api_service_url: str = "http://localhost:3000"

    # v3 cost config for UBC-05a (Denial of Wallet)
    llm_input_cost_per_1k: float = 0.01    # USD per 1k input tokens (default GPT-4 proxy)
    llm_output_cost_per_1k: float = 0.03   # USD per 1k output tokens

    # ─────────────────────────────────────────────────────────────────────
    # Reflex — fast classifier called on Runtime Guard hot path.
    # Empty URL = tier disabled; every Reflex-routed check falls back to
    # its existing regex/pattern implementation.
    # ─────────────────────────────────────────────────────────────────────
    reflex_endpoint_url: str = ""
    reflex_timeout_ms:   int = 50
    # Shared secret with the reflex service (must match REFLEX_API_SECRET
    # in dapplepot-reflex). Sent on every request as X-Internal-Secret.
    # Empty = no auth header attached (dev / self-hosted reflex without auth).
    reflex_api_secret:   str = ""

    # ─────────────────────────────────────────────────────────────────────
    # Verdict — LLM judge called at end of score_session.
    # Empty api_key = tier disabled; every Verdict-routed check falls back
    # to its existing heuristic scorer. NIM is OpenAI-compatible.
    # ─────────────────────────────────────────────────────────────────────
    nvidia_api_key:      str = ""
    nvidia_base_url:     str = "https://integrate.api.nvidia.com/v1"
    verdict_model:       str = "meta/llama-3.1-8b-instruct"
    verdict_timeout_ms:  int = 5000
    # Cost gate: skip Verdict on sessions whose rule-based max effective
    # score is below this. 35 = start of the medium band (RISK_BANDS_V3).
    # Clean/low-risk sessions never call the LLM; only risky ones do.
    verdict_gate_score:  int = 35
    # Concurrency cap: at most this many verdict_judge calls may be in-flight
    # to NIM at once (process-wide). Extras queue in-process.
    verdict_max_concurrent: int = 4
    # Retry cap on 429/503 responses. Retry-After header is honoured when
    # present; otherwise exponential backoff with jitter.
    verdict_max_retries: int = 3

    def get_tool_manifests(self) -> dict[str, list[str]]:
        return json.loads(self.tool_manifests)


settings = Settings()

# ─────────────────────────────────────────────────────────────────────────────
# Per-signal alert thresholds (v2 — kept for backward compat)
# ─────────────────────────────────────────────────────────────────────────────
SIGNAL_ALERT_THRESHOLDS: dict[str, int] = {
    "OW-LLM01": 70,
    "OW-LLM02": 70,
    "OW-ASI05": 65,
    "OW-ASI03": 65,
    "OW-ASI10": 70,
    "OW-LLM05": 75,
    "OW-LLM06": 75,
    "OW-LLM07": 75,
    "OW-ASI01": 75,
    "OW-ASI02": 75,
    "OW-ASI06": 75,
    "OW-ASI07": 75,
    "OW-ASI08": 75,
    "OW-ASI09": 78,
    "OW-LLM04": 80,
    "OW-LLM08": 80,
    "OW-LLM09": 80,
    "OW-LLM10": 80,
    "OW-ASI04": 80,
    "OW-LLM03": 999,
}

# v2 composite threshold — kept for backward compat
COMPOSITE_ALERT_THRESHOLD: int = 65

# ─────────────────────────────────────────────────────────────────────────────
# v3 per-signal alert thresholds
# ─────────────────────────────────────────────────────────────────────────────
SIGNAL_ALERT_THRESHOLDS_V3: dict[str, int] = {
    "OW-LLM01": 70,
    "OW-LLM02": 75,
    "OW-LLM03": 999,   # excluded
    "OW-LLM04": 999,   # excluded
    "OW-LLM05": 70,
    "OW-LLM06": 65,
    "OW-LLM07": 70,
    "OW-LLM08": 999,   # excluded
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

# v3 composite threshold — lowered from 65; attack chain amplification may push scores up
COMPOSITE_ALERT_THRESHOLD_V3: int = 60

# Sustained-risk / trust-degradation alert thresholds
AGENT_TRUST_ALERT_THRESHOLD: int = 50
AGENT_TRUST_CONSECUTIVE_SESSIONS: int = 3

# ─────────────────────────────────────────────────────────────────────────────
# v3 confidence weights per tier
# ─────────────────────────────────────────────────────────────────────────────
CONFIDENCE_WEIGHTS: dict[str, float] = {
    "deterministic": 1.0,
    "high":          0.9,
    "medium":        0.7,
    "low":           0.5,
    "skeletal":      0.3,
}

# ─────────────────────────────────────────────────────────────────────────────
# v3 risk bands (narrowed from v2)
# ─────────────────────────────────────────────────────────────────────────────
RISK_BANDS_V3: dict[str, tuple[int, int]] = {
    "clean":    (0,   14),
    "low":      (15,  34),
    "medium":   (35,  59),
    "high":     (60,  84),
    "critical": (85, 100),
}

# ─────────────────────────────────────────────────────────────────────────────
# v3 overlap dedup groups (extends v2)
# ─────────────────────────────────────────────────────────────────────────────
OVERLAP_GROUPS_V3: dict[str, set[str]] = {
    "injection":        {"OW-LLM01", "OW-ASI01", "OW-ASI06"},
    "output_exec":      {"OW-LLM05", "OW-ASI05", "OW-ASI02"},
    "supply_chain":     {"OW-LLM03", "OW-ASI04"},
    "memory_vector":    {"OW-LLM08", "OW-ASI06"},
    "excessive_agency": {"OW-LLM06", "OW-ASI02", "OW-ASI10"},
    "pii_privilege":    {"OW-LLM02", "OW-ASI03"},
    "trust_fraud":      {"OW-ASI09", "OW-ASI01"},
    "cascade_rogue":    {"OW-ASI08", "OW-ASI10", "OW-ASI07"},
}

# ─────────────────────────────────────────────────────────────────────────────
# Attack chains — coordinated multi-signal attack patterns (v3)
# ─────────────────────────────────────────────────────────────────────────────
ATTACK_CHAINS: dict[str, dict] = {
    "indirect_injection_to_exfil": {
        "signals": {"OW-LLM01", "OW-ASI02", "OW-LLM02"},
        "description": "Injection → tool misuse → data exfiltration",
        "amplification": 1.25,
    },
    "goal_hijack_to_rce": {
        "signals": {"OW-ASI01", "OW-ASI05"},
        "description": "Goal hijacking → code execution",
        "amplification": 1.30,
    },
    "supply_chain_to_backdoor": {
        "signals": {"OW-ASI04", "OW-ASI05", "OW-ASI10"},
        "description": "Supply chain compromise → code execution → rogue behavior",
        "amplification": 1.35,
    },
    "memory_poison_to_exfil": {
        "signals": {"OW-ASI06", "OW-ASI01", "OW-LLM02"},
        "description": "Memory poisoning → goal hijack → data disclosure",
        "amplification": 1.25,
    },
    "privilege_escalation_chain": {
        "signals": {"OW-ASI03", "OW-ASI02", "OW-LLM06"},
        "description": "Privilege abuse → tool misuse → excessive agency",
        "amplification": 1.20,
    },
    "trust_exploitation_to_fraud": {
        "signals": {"OW-ASI09", "OW-ASI01", "OW-LLM05"},
        "description": "Trust exploitation → goal hijack → insecure output",
        "amplification": 1.25,
    },
    "cascading_failure_chain": {
        "signals": {"OW-ASI08", "OW-ASI07", "OW-ASI10"},
        "description": "Cascading failure → inter-agent compromise → rogue behavior",
        "amplification": 1.30,
    },
}

# ─────────────────────────────────────────────────────────────────────────────
# Known hallucinated package names for SAG-02a
# ─────────────────────────────────────────────────────────────────────────────
KNOWN_HALLUCINATED_PACKAGES: set[str] = {
    "huggingface-cli",
    "openai-python",
    "langchain-community-tools",
    "transformers-extra",
    "sklearn-extra",
    "tensorflow-text-extra",
    "torch-utils",
    "pandas-ml",
    "numpy-ml",
    "flask-restx-plus",
}

# Short English words that are likely hallucinated if used as package names
HALLUCINATED_SHORT_WORDS: set[str] = {
    "lib", "pkg", "mod", "app", "api", "sdk", "cli", "bot",
    "io", "ai", "ml", "dl", "nn",
}
