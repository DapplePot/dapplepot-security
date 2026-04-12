"""Kafka poll loop — triggers post-session scorer on graph_end / graph_error.

All detection runs post-session inside score_session(); the consumer's only
job is to fan out the scoring task when a session closes.
"""
# ── Windows: asyncpg.connect_utils calls platform.uname() at import time,
#    which triggers a WMI subprocess query that hangs on some Windows machines.
#    Stub it out before asyncpg is imported so the consumer can start.
import sys as _sys
if _sys.platform == "win32":
    import platform as _plat
    _plat.uname = lambda _r=_plat.uname_result("Windows", "", "", "", ""): _r
    del _plat
del _sys

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

from consumers.security_eval.scorer.orchestrator import score_session

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


async def _run_scorer(tenant_id: str, session_id: str, agent_id: str) -> None:
    """Wrapper so scorer exceptions are logged instead of silently dropped."""
    try:
        await score_session(tenant_id=tenant_id, session_id=session_id, agent_id=agent_id)
    except Exception:
        logger.exception('"score_session failed session_id=%s"', session_id)


async def _init_agent_security_config(tenant_id: str, agent_id: str) -> None:
    """
    Push platform default security config to Redis for a newly-created agent.
    Called on agent_created events so the config is ready before the first session.
    """
    try:
        from core.infra.redis import get_redis
        from core.security_config import push_agent_defaults
        redis = await get_redis()
        await push_agent_defaults(redis, tenant_id, agent_id)
    except Exception:
        logger.exception(
            '"failed to init security config tenant_id=%s agent_id=%s"',
            tenant_id,
            agent_id,
        )


async def _persist_sdk_finding(session_id: str, agent_id: str | None, payload: dict) -> None:
    """
    Process an SDK-emitted online security_finding event.

    Steps:
      1. Persist finding to security_findings (detection_phase='online').
      2. If action_taken is auditable (block_call / terminate_session):
         write an audit row to session_actions.
      3. If action_taken warrants an alert (alert / block_call / terminate_session):
         produce an immediate alert to obs.alerts.v1.

    The uq_findings_session_subcheck constraint prevents duplicate findings if
    the Kafka event is replayed.  The dedup_key on online alerts prevents the
    alert router from notifying twice for the same sub-check within one session.
    """
    try:
        import dataclasses
        from consumers.security_eval.findings import (
            Finding,
            write_findings,
            write_session_action,
            produce_online_alert,
            _ALERTABLE_ACTIONS,
            _AUDITABLE_ACTIONS,
        )

        action_taken: str = payload.get("action_taken", "monitor")

        _init_fields = {f.name for f in dataclasses.fields(Finding) if f.init}
        finding = Finding(**{k: v for k, v in payload.items() if k in _init_fields})

        # Step 1 — persist finding
        await write_findings([finding])

        # Step 2 — audit row for hard actions
        if action_taken in _AUDITABLE_ACTIONS:
            await write_session_action(finding, action_taken, agent_id=agent_id)

        # Step 3 — immediate alert
        if action_taken in _ALERTABLE_ACTIONS:
            await produce_online_alert(finding, action_taken, agent_id=agent_id)

    except Exception:
        logger.exception('"failed to persist SDK online finding session_id=%s"', session_id)


async def _handle_event(event: dict) -> None:
    event_type = event.get("event_type")
    session_id = event.get("session_id")
    tenant_id  = event.get("tenant_id")
    agent_id   = event.get("agent_id")

    # New agent created → push default security config to Redis immediately
    # so it's available before the first session scores.
    if event_type == "agent_created":
        if tenant_id and agent_id:
            asyncio.create_task(
                _init_agent_security_config(tenant_id=tenant_id, agent_id=agent_id)
            )
        return

    if not session_id:
        return

    # SDK online detection findings — write straight to Postgres (durable, no Redis buffer)
    if event_type == "security_finding":
        if session_id:
            asyncio.create_task(
                _persist_sdk_finding(
                    session_id=session_id,
                    agent_id=agent_id,
                    payload=event.get("payload") or {},
                )
            )
        return

    if event_type in ("graph_end", "graph_error"):
        asyncio.create_task(
            _run_scorer(
                tenant_id=tenant_id,
                session_id=session_id,
                agent_id=agent_id,
            )
        )


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
        # SIGTERM is not supported on Windows — only wire SIGINT (Ctrl+C).
        # Use call_soon_threadsafe so the Future is set from within the loop.
        os_signal.signal(
            os_signal.SIGINT,
            lambda *_: loop.call_soon_threadsafe(_stop),
        )

    executor = ThreadPoolExecutor(max_workers=1)

    try:
        while not stopped.done():
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
