import json
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    kafka_bootstrap_servers: str = "localhost:9092"
    kafka_events_topic: str = "obs.events.v1"
    kafka_alerts_topic: str = "obs.alerts.v1"
    kafka_dlq_topic: str = "obs.dlq.v1"

    postgres_dsn: str = "postgresql://dapplepot:dapplepot@localhost:5432/dapplepot_pipeline"
    clickhouse_host: str = "localhost"
    clickhouse_port: int = 8123
    clickhouse_user: str = "dapplepot"
    clickhouse_password: str = "dapplepot"
    redis_url: str = "redis://localhost:6379/0"

    security_eval_workers: int = 4
    scorer_version: str = "2.0.0"
    sig_cache_ttl_s: int = 300
    session_ctx_ttl_s: int = 120

    # Legacy single threshold kept for backward compat (now superseded by
    # SIGNAL_ALERT_THRESHOLDS below; composite check still uses this).
    alert_on_score_gte: int = 65

    tool_manifests: str = "{}"

    def get_tool_manifests(self) -> dict[str, list[str]]:
        return json.loads(self.tool_manifests)


settings = Settings()

# ─────────────────────────────────────────────────────────────────────────────
# Per-signal alert thresholds (v2 taxonomy)
# Alert fires when a signal's max sub-check score >= its threshold here.
# ─────────────────────────────────────────────────────────────────────────────
SIGNAL_ALERT_THRESHOLDS: dict[str, int] = {
    # CRITICAL signals — alert at 70
    "OW-LLM01": 70,    # Prompt Injection
    "OW-LLM02": 70,    # Sensitive Information Disclosure
    "OW-ASI05": 65,    # Unexpected Code Execution (RCE)
    "OW-ASI03": 65,    # Identity & Privilege Abuse
    "OW-ASI10": 70,    # Rogue Agents
    # HIGH signals — alert at 75
    "OW-LLM05": 75,    # Improper Output Handling
    "OW-LLM06": 75,    # Excessive Agency
    "OW-LLM07": 75,    # System Prompt Leakage
    "OW-ASI01": 75,    # Agent Goal Hijack
    "OW-ASI02": 75,    # Tool Misuse & Exploitation
    "OW-ASI06": 75,    # Memory & Context Poisoning
    "OW-ASI07": 75,    # Insecure Inter-Agent Communication
    "OW-ASI08": 75,    # Cascading Failures
    "OW-ASI09": 78,    # Human-Agent Trust Exploitation
    # MEDIUM signals — alert at 80
    "OW-LLM04": 80,    # Data & Model Poisoning
    "OW-LLM08": 80,    # Vector & Embedding Weakness
    "OW-LLM09": 80,    # Misinformation
    "OW-LLM10": 80,    # Unbounded Consumption
    "OW-ASI04": 80,    # Agentic Supply Chain Vulnerabilities
    # EXCLUDED — effectively never alert
    "OW-LLM03": 999,   # Supply Chain (not monitorable at runtime)
}

# Composite score threshold — alert when the weighted composite reaches this.
# Unchanged from v1 behaviour.
COMPOSITE_ALERT_THRESHOLD: int = 65
