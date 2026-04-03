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
    scorer_version: str = "1.0.0"
    sig_cache_ttl_s: int = 300
    session_ctx_ttl_s: int = 120
    alert_on_score_gte: int = 65

    tool_manifests: str = "{}"

    def get_tool_manifests(self) -> dict[str, list[str]]:
        return json.loads(self.tool_manifests)


settings = Settings()
