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
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.infra.postgres import close_pool, get_pool
from core.infra.redis import close_redis, get_redis

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
)
logger = logging.getLogger(__name__)

ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')


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

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=['GET', 'POST'],
    allow_headers=['Authorization', 'Content-Type'],
)


@app.get('/healthz')
async def health():
    return {'status': 'ok'}


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


@app.post('/v1/online-check')
async def online_check(request: Request):
    """
    Real-time threat detection endpoint called by SDK via backend proxy.
    Fetches config, runs detection, adds actions, returns findings.
    """
    try:
        body = await request.json()
    except Exception:
        return JSONResponse({'error': 'invalid JSON'}, status_code=400)

    event_type = body.get('event_type')
    payload = body.get('payload')
    session_id = body.get('session_id')
    agent_id = body.get('agent_id')
    tenant_id = body.get('tenant_id')
    enabled_checks = body.get('enabled_checks', {})
    tool_manifest = body.get('tool_manifest', [])
    max_tool_calls = body.get('max_tool_calls')
    tool_call_count = body.get('tool_call_count', 0)
    redact_keys = body.get('redact_keys', [])

    if not all([event_type, payload, session_id, agent_id, tenant_id]):
        return JSONResponse({'error': 'missing required fields'}, status_code=400)

    findings = []

    # Run Python detector for PI/SID/IOH checks
    needs_detector = any(k.startswith(('PI-', 'SID-', 'IOH-')) for k in enabled_checks)
    if needs_detector:
        try:
            from consumers.security_eval.detectors.online import detect_online
            detected = detect_online(
                event={'event_type': event_type, 'payload': payload, 'session_id': session_id, 'tenant_id': tenant_id},
                redact_keys=set(redact_keys) if redact_keys else None
            )
            # Add action to each finding based on enabled_checks
            for f in detected:
                if f['sub_check_id'] in enabled_checks:
                    findings.append({**f, 'action': enabled_checks[f['sub_check_id']]})
        except Exception:
            logger.exception('online detector failed')

    # EA-01a: tool manifest enforcement
    if 'EA-01a' in enabled_checks and tool_manifest:
        tool_name = payload.get('tool_name', '')
        if tool_name and tool_name not in tool_manifest:
            findings.append({
                'sub_check_id': 'EA-01a',
                'owasp_signal_id': 'OW-LLM06',
                'check_label': 'Tool not in approved manifest invoked',
                'check_score': 80,
                'category': 'excessive_agency',
                'severity': 'high',
                'matched_text': tool_name[:200],
                'confidence_tier': 'deterministic',
                'detection_phase': 'online',
                'action': enabled_checks['EA-01a'],
            })

    # EA-02b: max tool calls per session
    if 'EA-02b' in enabled_checks and max_tool_calls is not None and tool_call_count > max_tool_calls:
        excess = tool_call_count - max_tool_calls
        check_score = min(65 + excess * 2, 85)
        findings.append({
            'sub_check_id': 'EA-02b',
            'owasp_signal_id': 'OW-LLM06',
            'check_label': 'Tool calls exceed configured session limit',
            'check_score': check_score,
            'category': 'excessive_agency',
            'severity': 'high',
            'matched_text': f'call #{tool_call_count} (limit: {max_tool_calls})',
            'confidence_tier': 'deterministic',
            'detection_phase': 'online',
            'action': enabled_checks['EA-02b'],
        })

    return JSONResponse({'findings': findings})
