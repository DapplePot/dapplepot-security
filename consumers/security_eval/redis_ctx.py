"""Session context cache in Redis for the passthrough and indirect injection detectors."""
import json
from core.config import settings
from core.infra.redis import get_redis


async def store_llm_output(session_id: str, node_run_id: str, completion: str) -> None:
    redis = await get_redis()
    await redis.setex(
        f"dp:sec:llm_out:{session_id}:{node_run_id}",
        settings.session_ctx_ttl_s,
        json.dumps(completion),
    )


async def store_tool_output(session_id: str, node_run_id: str, tool_output: str) -> None:
    redis = await get_redis()
    await redis.setex(
        f"dp:sec:tool_out:{session_id}:{node_run_id}",
        settings.session_ctx_ttl_s,
        json.dumps(tool_output),
    )


async def get_llm_output(session_id: str, node_run_id: str) -> str | None:
    redis = await get_redis()
    value = await redis.get(f"dp:sec:llm_out:{session_id}:{node_run_id}")
    if value is None:
        return None
    return json.loads(value)


async def get_tool_output(session_id: str, node_run_id: str) -> str | None:
    redis = await get_redis()
    value = await redis.get(f"dp:sec:tool_out:{session_id}:{node_run_id}")
    if value is None:
        return None
    return json.loads(value)
