"""
Alert persistence — writes alerts to the Postgres alerts table.
External delivery channels (webhook, Slack, PagerDuty) are not used.
"""
from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

log = logging.getLogger(__name__)


async def deliver_alert(alert: dict[str, Any]) -> None:
    triggered_at_raw = alert.get('triggered_at')
    if isinstance(triggered_at_raw, str):
        triggered_at = datetime.fromisoformat(triggered_at_raw.replace('Z', '+00:00'))
    else:
        triggered_at = triggered_at_raw

    if not triggered_at or not alert.get('rule_name'):
        log.warning('Skipping malformed alert %s', alert.get('alert_id'))
        return

    from core.infra.postgres import get_pool
    pool = await get_pool()
    async with pool.acquire() as conn:
        await conn.execute(
            """
            INSERT INTO alerts
                (alert_id, tenant_id, session_id, rule_name,
                 severity, triggered_at, dedup_key, payload)
            VALUES ($1, $2::uuid, $3::uuid, $4, $5, $6, $7, $8::jsonb)
            ON CONFLICT DO NOTHING
            """,
            alert.get('alert_id'),
            alert.get('tenant_id'),
            alert.get('session_id'),
            alert.get('rule_name'),
            alert.get('severity', 'medium'),
            triggered_at,
            alert.get('dedup_key', alert.get('alert_id', '')),
            json.dumps(alert.get('payload', {})),
        )

    from core.config import settings
    import urllib.request
    import asyncio

    def _trigger_delivery_sync() -> None:
        if not settings.internal_api_secret:
            return
        req = urllib.request.Request(
            f"{settings.api_service_url}/v1/internal/alerts/deliver",
            data=json.dumps({"alert_id": alert.get('alert_id'), "tenant_id": alert.get('tenant_id')}).encode('utf-8'),
            headers={'Content-Type': 'application/json', 'X-Internal-Secret': settings.internal_api_secret},
            method='POST'
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as response:
                response.read()
        except Exception as e:
            log.error("Failed to trigger delivery via internal API: %s", e)

    asyncio.create_task(asyncio.to_thread(_trigger_delivery_sync))


