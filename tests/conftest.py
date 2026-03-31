"""Shared fixtures for unit and integration tests."""
import pytest

SESSION_ID  = "00000000-0000-0000-0000-000000000001"
TENANT_ID   = "00000000-0000-0000-0000-000000000002"
AGENT_ID    = "00000000-0000-0000-0000-000000000003"
EVENT_ID    = "00000000-0000-0000-0000-000000000004"
NODE_RUN_ID = "00000000-0000-0000-0000-000000000005"


def make_event(event_type: str, payload: dict, **overrides) -> dict:
    base = {
        "event_id":    EVENT_ID,
        "event_type":  event_type,
        "session_id":  SESSION_ID,
        "tenant_id":   TENANT_ID,
        "agent_id":    AGENT_ID,
        "node_run_id": NODE_RUN_ID,
        "payload":     payload,
    }
    base.update(overrides)
    return base
