"""
FastAPI HTTP server for dapplepot-security.

Replaces the Kafka consumer (consumers/security_eval/consumer.py) with
a simple HTTP endpoint. dapplepot-api forwards events here via HTTP POST
instead of producing to obs.events.v1.

Start:
    uvicorn server.main:app --host 0.0.0.0 --port 8001
"""
import asyncio
import logging
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.responses import JSONResponse

from core.infra.postgres import close_pool, get_pool
from core.infra.redis import close_redis, get_redis

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm up connection pools
    await get_pool()
    await get_redis()
    logger.info('dapplepot-security HTTP server started')
    yield
    await close_pool()
    await close_redis()
    logger.info('dapplepot-security HTTP server stopped')


app = FastAPI(title='dapplepot-security', lifespan=lifespan)


@app.get('/healthz')
async def health():
    return {'status': 'ok'}


@app.post('/v1/online-check')
async def online_check(request: Request):
    """
    Synchronous online check endpoint — called by the SDK (via API proxy)
    on every event that has blocking checks enabled.
    Runs detection logic and returns findings immediately. No DB writes here —
    the SDK sends a security_finding event through ingest which consumer.py persists.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({'error': 'invalid JSON'}, status_code=400)

    try:
        from consumers.security_eval.detectors.online import run_online_checks
        findings = run_online_checks(
            event_type=body.get('event_type', ''),
            payload=body.get('payload', {}),
            enabled_checks=body.get('enabled_checks', {}),
            tool_manifest=body.get('tool_manifest', []),
            max_tool_calls=body.get('max_tool_calls'),
            tool_call_count=body.get('tool_call_count', 0),
        )
    except Exception:
        logger.exception('online-check failed event_type=%s', body.get('event_type'))
        return JSONResponse({'error': 'internal error'}, status_code=500)

    return JSONResponse({'findings': findings})


@app.post('/v1/evaluate', status_code=202)
async def evaluate(request: Request):
    """
    Receive a single event forwarded from dapplepot-api.
    Dispatches the same logic as the former Kafka consumer's _handle_event().
    """
    try:
        event = await request.json()
    except Exception:
        return JSONResponse({'error': 'invalid JSON'}, status_code=400)

    try:
        # Import here to avoid circular import issues at module load time
        from consumers.security_eval.consumer import _handle_event
        # _handle_event schedules async tasks internally; run it in current loop
        await _handle_event(event)
    except Exception:
        logger.exception('evaluate failed for event_type=%s session_id=%s',
                         event.get('event_type'), event.get('session_id'))
        return JSONResponse({'error': 'internal error'}, status_code=500)

    return Response(status_code=202)
