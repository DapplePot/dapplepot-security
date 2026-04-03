"""Kafka poll loop — routes events to online detectors and post-session scorer."""
import asyncio
import json
import logging
import logging.config
import signal as os_signal
import sys
from concurrent.futures import ThreadPoolExecutor

from confluent_kafka import KafkaError

from core.config import settings
from core.infra.kafka import make_consumer, make_producer
from core.infra.postgres import close_pool
from core.infra.redis import close_redis

from consumers.security_eval.findings import Finding, write_findings
from consumers.security_eval.redis_ctx import (
    get_llm_output,
    get_tool_output,
    store_llm_output,
    store_tool_output,
)
from consumers.security_eval.online.injection import detect_injection
from consumers.security_eval.online.passthrough import detect_passthrough
from consumers.security_eval.online.pii import detect_pii
from consumers.security_eval.scorer.post_session import score_session

LOGGING_CONFIG = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "json": {
            "()": "logging.Formatter",
            "fmt": '{"time":"%(asctime)s","level":"%(levelname)s","logger":"%(name)s","msg":%(message)s}',
        }
    },
    "handlers": {
        "stdout": {
            "class": "logging.StreamHandler",
            "formatter": "json",
        }
    },
    "root": {"handlers": ["stdout"], "level": "INFO"},
}

logging.config.dictConfig(LOGGING_CONFIG)
logger = logging.getLogger(__name__)

GROUP_ID = "dp-security-eval"

_dlq_producer = None


def _get_dlq_producer():
    global _dlq_producer
    if _dlq_producer is None:
        _dlq_producer = make_producer()
    return _dlq_producer


def _send_to_dlq(raw_bytes: bytes, error: Exception, offset: int) -> None:
    """Produce a failed message to obs.dlq.v1 so it isn't silently dropped."""
    try:
        dlq_record = json.dumps({
            "source": "dp-security-eval",
            "original_offset": offset,
            "error": str(error),
            "raw": raw_bytes.decode("utf-8", errors="replace"),
        }).encode()
        _get_dlq_producer().produce(settings.kafka_dlq_topic, value=dlq_record)
        _get_dlq_producer().poll(0)
    except Exception:
        logger.exception('"DLQ produce failed"')

# Per-session accumulator: session_id → list[Finding] (online findings only)
_session_findings: dict[str, list[Finding]] = {}


async def _handle_event(event: dict) -> None:
    event_type = event.get("event_type")
    session_id = event.get("session_id")
    node_run_id = event.get("node_run_id", "")
    tenant_id = event.get("tenant_id")

    if not session_id:
        return

    findings: list[Finding] = []

    if event_type == "llm_start":
        last_tool_out = await get_tool_output(session_id, node_run_id)
        findings = await detect_injection(event, last_tool_output=last_tool_out, tenant_id=tenant_id)

    elif event_type == "llm_end":
        completion = event["payload"].get("completion", "")
        await store_llm_output(session_id, node_run_id, completion)
        findings = detect_pii(event)

    elif event_type == "tool_start":
        last_llm_out = await get_llm_output(session_id, node_run_id)
        pt_finding = await detect_passthrough(event, last_llm_output=last_llm_out)
        if pt_finding:
            findings = [pt_finding]

    elif event_type == "tool_end":
        tool_output = event["payload"].get("tool_output", "")
        await store_tool_output(session_id, node_run_id, tool_output)
        findings = detect_pii(event)

    elif event_type in ("graph_end", "graph_error"):
        agent_id = event.get("agent_id")
        session_online_findings = _session_findings.pop(session_id, [])
        asyncio.create_task(
            score_session(
                tenant_id=tenant_id,
                session_id=session_id,
                agent_id=agent_id,
                online_findings=session_online_findings,
            )
        )
        return  # scorer handles its own writes

    if findings:
        # Accumulate for post-session scorer
        _session_findings.setdefault(session_id, []).extend(findings)
        await write_findings(findings)


async def run() -> None:
    topic = settings.kafka_events_topic
    consumer = make_consumer(GROUP_ID)
    consumer.subscribe([topic])
    logger.info('"dp-security-eval started, subscribed to %s"', topic)

    loop = asyncio.get_running_loop()
    stopped = loop.create_future()

    def _stop(*_):
        if not stopped.done():
            stopped.set_result(None)

    if sys.platform != "win32":
        loop.add_signal_handler(os_signal.SIGINT, _stop)
        loop.add_signal_handler(os_signal.SIGTERM, _stop)
    else:
        os_signal.signal(os_signal.SIGINT, _stop)
        os_signal.signal(os_signal.SIGTERM, _stop)

    executor = ThreadPoolExecutor(max_workers=1)

    try:
        while not stopped.done():
            # Poll Kafka in a thread to avoid blocking the event loop
            msg = await loop.run_in_executor(executor, lambda: consumer.poll(timeout=1.0))

            if msg is None:
                continue
            if msg.error():
                if msg.error().code() == KafkaError._PARTITION_EOF:
                    continue
                logger.error('"Kafka consumer error: %s"', msg.error())
                continue

            try:
                event = json.loads(msg.value().decode("utf-8"))
                await _handle_event(event)
                consumer.commit(msg)
            except Exception as exc:
                # Send to DLQ so the event isn't lost and commit so the consumer
                # doesn't stall on the same offset indefinitely.
                logger.exception('"Processing failed, sending to DLQ offset=%s"', msg.offset())
                _send_to_dlq(msg.value(), exc, msg.offset())
                consumer.commit(msg)

    finally:
        consumer.close()
        executor.shutdown(wait=False)
        await close_pool()
        await close_redis()
        logger.info('"dp-security-eval stopped"')


if __name__ == "__main__":
    asyncio.run(run())
