"""
Security event handler.

Previously a Kafka consumer; now called directly by the HTTP server
(server/main.py) via POST /v1/evaluate.

_handle_event() is the single entry point — all dispatch logic lives here.
"""
import asyncio
import logging
import uuid

logger = logging.getLogger(__name__)

# Maps SDK online sub_check_id → Finding-compatible fields.
# Only the 11 sub-checks marked onlineCapable: true in signalRegistry.ts are listed.
# The SDK now sends sub_check_id directly so this map is keyed by sub_check_id.
_ONLINE_SIGNAL_MAP: dict[str, dict] = {
    'PI-01a': {
        'owasp_signal_id': 'OW-LLM01',
        'sub_check_id': 'PI-01a',
        'check_label': 'Role-override phrase match',
        'check_score': 85,
        'category': 'prompt_injection',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'PI-01b': {
        'owasp_signal_id': 'OW-LLM01',
        'sub_check_id': 'PI-01b',
        'check_label': 'Delimiter smuggling',
        'check_score': 90,
        'category': 'prompt_injection',
        'severity': 'critical',
        'confidence_tier': 'deterministic',
    },
    'PI-01c': {
        'owasp_signal_id': 'OW-LLM01',
        'sub_check_id': 'PI-01c',
        'check_label': 'Encoded / obfuscated payload',
        'check_score': 75,
        'category': 'prompt_injection',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'PI-02a': {
        'owasp_signal_id': 'OW-LLM01',
        'sub_check_id': 'PI-02a',
        'check_label': 'Web-fetched content with injection pattern',
        'check_score': 70,
        'category': 'prompt_injection',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'PI-05a': {
        'owasp_signal_id': 'OW-LLM01',
        'sub_check_id': 'PI-05a',
        'check_label': 'Code injection pattern in prompt',
        'check_score': 80,
        'category': 'prompt_injection',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'PI-08a': {
        'owasp_signal_id': 'OW-LLM01',
        'sub_check_id': 'PI-08a',
        'check_label': 'Adversarial suffix (high-entropy tail)',
        'check_score': 75,
        'category': 'prompt_injection',
        'severity': 'high',
        'confidence_tier': 'medium',
    },
    'SID-01a': {
        'owasp_signal_id': 'OW-LLM02',
        'sub_check_id': 'SID-01a',
        'check_label': 'API key / token pattern in output',
        'check_score': 95,
        'category': 'data_disclosure',
        'severity': 'critical',
        'confidence_tier': 'deterministic',
    },
    'SID-01c': {
        'owasp_signal_id': 'OW-LLM02',
        'sub_check_id': 'SID-01c',
        'check_label': 'JWT / session token in agent message',
        'check_score': 90,
        'category': 'data_disclosure',
        'severity': 'critical',
        'confidence_tier': 'deterministic',
    },
    'SID-02a': {
        'owasp_signal_id': 'OW-LLM02',
        'sub_check_id': 'SID-02a',
        'check_label': 'Name + email + phone co-occurrence',
        'check_score': 75,
        'category': 'data_disclosure',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'EA-01a': {
        'owasp_signal_id': 'OW-LLM06',
        'sub_check_id': 'EA-01a',
        'check_label': 'Tool not in approved manifest invoked',
        'check_score': 80,
        'category': 'excessive_agency',
        'severity': 'high',
        'confidence_tier': 'deterministic',
    },
    'EA-02b': {
        'owasp_signal_id': 'OW-LLM06',
        'sub_check_id': 'EA-02b',
        'check_label': 'Tool calls exceed configured session limit',
        'check_score': 75,
        'category': 'excessive_agency',
        'severity': 'high',
        'confidence_tier': 'deterministic',
    },
}


async def _init_agent_security_config(tenant_id: str, agent_id: str) -> None:
    try:
        from core.infra.redis import get_redis
        from core.security_config import push_agent_defaults
        redis = await get_redis()
        await push_agent_defaults(redis, tenant_id, agent_id)
    except Exception:
        logger.exception(
            'failed to init security config tenant_id=%s agent_id=%s',
            tenant_id,
            agent_id,
        )


async def _persist_sdk_finding(
    session_id: str,
    tenant_id: str,
    agent_id: str | None,
    payload: dict,
    emitted_at: str | None = None,
) -> None:
    try:
        from security_eval.findings import (
            Finding,
            write_findings,
            write_session_action,
            _AUDITABLE_ACTIONS,
        )

        action_taken: str = payload.get('action_taken', 'alert')

        # SDK sends {signal: sub_check_id, reason, matched_text, ...}; look up Finding fields.
        signal_name = payload.get('signal') or payload.get('sub_check_id', '')
        mapping = _ONLINE_SIGNAL_MAP.get(signal_name)

        if mapping is None:
            # SDK already sent Finding-compatible fields (future SDK versions)
            if 'owasp_signal_id' not in payload:
                logger.warning(
                    'unknown online signal %r for session %s — skipping',
                    signal_name, session_id,
                )
                return
            # Use payload as-is; filter to init fields
            import dataclasses
            _init_fields = {f.name for f in dataclasses.fields(Finding) if f.init}
            finding = Finding(**{k: v for k, v in payload.items() if k in _init_fields})
        else:
            matched = payload.get('matched_text') or payload.get('reason')
            finding = Finding(
                tenant_id=tenant_id,
                session_id=session_id,
                event_id=payload.get('trigger_event_id') or str(uuid.uuid4()),
                event_type=payload.get('trigger_event_type') or payload.get('dp_event_type', 'security_finding'),
                detection_phase='online',
                matched_text=matched,
                detail=matched,
                **mapping,
            )

        if emitted_at:
            finding.emitted_at = emitted_at

        await write_findings([finding])

        if action_taken in _AUDITABLE_ACTIONS:
            await write_session_action(finding, action_taken, agent_id=agent_id)

    except Exception:
        logger.exception('failed to persist SDK online finding session_id=%s', session_id)


# Tracks in-flight _persist_sdk_finding tasks per session so the scorer can
# wait for all findings to be committed before reading them from the DB.
_pending_findings: dict[str, set[asyncio.Task]] = {}


async def _run_scorer(tenant_id: str, session_id: str, agent_id: str) -> None:
    try:
        from security_eval.scorer.orchestrator import score_session
        await score_session(tenant_id=tenant_id, session_id=session_id, agent_id=agent_id)
    except Exception:
        logger.exception('score_session failed session_id=%s', session_id)


async def _run_scorer_after_findings(tenant_id: str, session_id: str, agent_id: str) -> None:
    """Wait for all pending finding-persist tasks before scoring."""
    pending = _pending_findings.pop(f"{tenant_id}:{session_id}", set())
    if pending:
        await asyncio.gather(*pending, return_exceptions=True)
    await _run_scorer(tenant_id=tenant_id, session_id=session_id, agent_id=agent_id)


async def _handle_event(event: dict) -> None:
    event_type = event.get('event_type')
    session_id = event.get('session_id')
    tenant_id  = event.get('tenant_id')
    agent_id   = event.get('agent_id')

    # graph_start = first event for a new session; initialise per-agent security config
    if event_type == 'graph_start':
        if tenant_id and agent_id:
            asyncio.create_task(
                _init_agent_security_config(tenant_id=tenant_id, agent_id=agent_id)
            )
        return

    if not session_id:
        return

    if event_type == 'security_finding':
        task = asyncio.create_task(
            _persist_sdk_finding(
                session_id=session_id,
                tenant_id=tenant_id or '',
                agent_id=agent_id,
                payload=event.get('payload') or {},
                emitted_at=event.get('emitted_at'),
            )
        )
        _key = f"{tenant_id or ''}:{session_id}"
        _pending_findings.setdefault(_key, set()).add(task)
        task.add_done_callback(
            lambda t, k=_key: _pending_findings.get(k, set()).discard(t)
        )
        return

    if event_type in ('graph_end', 'graph_error'):
        asyncio.create_task(
            _run_scorer_after_findings(
                tenant_id=tenant_id,
                session_id=session_id,
                agent_id=agent_id,
            )
        )
