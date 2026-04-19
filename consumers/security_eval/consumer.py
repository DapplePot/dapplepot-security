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

# Maps SDK online signal names → Finding-compatible fields.
# Keeps the SDK thin (sends just signal + reason) while giving the
# security service full OWASP context.
_ONLINE_SIGNAL_MAP: dict[str, dict] = {
    'prompt_injection': {
        'owasp_signal_id': 'OW-LLM01',
        'sub_check_id': 'llm-01-online',
        'check_label': 'Online prompt injection detection',
        'check_score': 75,
        'category': 'prompt_injection',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'insecure_output': {
        'owasp_signal_id': 'OW-LLM09',
        'sub_check_id': 'llm-09-online',
        'check_label': 'Online insecure output detection',
        'check_score': 70,
        'category': 'insecure_output',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'pii_input': {
        'owasp_signal_id': 'OW-LLM02',
        'sub_check_id': 'llm-02-online-in',
        'check_label': 'Online PII detected in input',
        'check_score': 65,
        'category': 'data_disclosure',
        'severity': 'medium',
        'confidence_tier': 'high',
    },
    'pii_output': {
        'owasp_signal_id': 'OW-LLM02',
        'sub_check_id': 'llm-02-online-out',
        'check_label': 'Online PII detected in output',
        'check_score': 65,
        'category': 'data_disclosure',
        'severity': 'medium',
        'confidence_tier': 'high',
    },
    'sensitive_data_exfiltration': {
        'owasp_signal_id': 'OW-LLM02',
        'sub_check_id': 'llm-02-online-exfil',
        'check_label': 'Online sensitive data exfiltration',
        'check_score': 80,
        'category': 'data_disclosure',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'tool_misuse': {
        'owasp_signal_id': 'OW-LLM05',
        'sub_check_id': 'llm-05-online',
        'check_label': 'Online dangerous tool argument detected',
        'check_score': 80,
        'category': 'tool_misuse',
        'severity': 'high',
        'confidence_tier': 'high',
    },
    'resource_exhaustion': {
        'owasp_signal_id': 'OW-ASI08',
        'sub_check_id': 'asi-08-online',
        'check_label': 'Online node call exhaustion',
        'check_score': 60,
        'category': 'resource_exhaustion',
        'severity': 'medium',
        'confidence_tier': 'medium',
    },
    'privilege_escalation': {
        'owasp_signal_id': 'OW-ASI05',
        'sub_check_id': 'asi-05-online-priv',
        'check_label': 'Online privilege escalation attempt',
        'check_score': 85,
        'category': 'privilege_escalation',
        'severity': 'critical',
        'confidence_tier': 'high',
    },
    'unsafe_code_execution': {
        'owasp_signal_id': 'OW-ASI05',
        'sub_check_id': 'asi-05-online-code',
        'check_label': 'Online unsafe code execution attempt',
        'check_score': 85,
        'category': 'unsafe_code',
        'severity': 'critical',
        'confidence_tier': 'high',
    },
    'supply_chain_tool': {
        'owasp_signal_id': 'OW-ASI04',
        'sub_check_id': 'asi-04-online',
        'check_label': 'Online unauthorized tool usage',
        'check_score': 70,
        'category': 'supply_chain',
        'severity': 'high',
        'confidence_tier': 'high',
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
        from consumers.security_eval.findings import (
            Finding,
            write_findings,
            write_session_action,
            _AUDITABLE_ACTIONS,
        )

        action_taken: str = payload.get('action_taken', 'alert')

        # SDK sends {signal, reason, ...original_payload}; map to Finding fields.
        signal_name = payload.get('signal') or payload.get('owasp_signal_id', '')
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
            finding = Finding(
                tenant_id=tenant_id,
                session_id=session_id,
                event_id=payload.get('event_id') or str(uuid.uuid4()),
                event_type=payload.get('dp_event_type', 'security_finding'),
                detection_phase='online',
                matched_text=payload.get('reason'),
                detail=payload.get('reason'),
                **mapping,
            )

        if emitted_at:
            finding.emitted_at = emitted_at

        await write_findings([finding])

        if action_taken in _AUDITABLE_ACTIONS:
            await write_session_action(finding, action_taken, agent_id=agent_id)

    except Exception:
        logger.exception('failed to persist SDK online finding session_id=%s', session_id)


async def _run_scorer(tenant_id: str, session_id: str, agent_id: str) -> None:
    try:
        from consumers.security_eval.scorer.orchestrator import score_session
        await score_session(tenant_id=tenant_id, session_id=session_id, agent_id=agent_id)
    except Exception:
        logger.exception('score_session failed session_id=%s', session_id)


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
        asyncio.create_task(
            _persist_sdk_finding(
                session_id=session_id,
                tenant_id=tenant_id or '',
                agent_id=agent_id,
                payload=event.get('payload') or {},
                emitted_at=event.get('emitted_at'),
            )
        )
        return

    if event_type in ('graph_end', 'graph_error'):
        asyncio.create_task(
            _run_scorer(
                tenant_id=tenant_id,
                session_id=session_id,
                agent_id=agent_id,
            )
        )
