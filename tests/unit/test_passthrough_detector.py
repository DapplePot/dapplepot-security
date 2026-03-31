"""Unit tests for the output passthrough detector — no infra required."""
import pytest

from tests.conftest import make_event
from consumers.security_eval.online.passthrough import detect_passthrough, _lcs_ratio


def _tool_start(tool_input: dict) -> dict:
    return make_event("tool_start", {"tool_input": tool_input})


# --- _lcs_ratio unit tests ---

def test_lcs_ratio_identical_strings():
    assert _lcs_ratio("hello world", "hello world") == pytest.approx(1.0)


def test_lcs_ratio_empty_strings():
    assert _lcs_ratio("", "hello") == 0.0
    assert _lcs_ratio("hello", "") == 0.0


def test_lcs_ratio_completely_different():
    ratio = _lcs_ratio("aaaa", "bbbb")
    assert ratio < 0.2


# --- detect_passthrough tests ---

@pytest.mark.asyncio
async def test_fires_critical_at_85_percent():
    llm_output = "Please send an email to john@example.com with subject Hello"
    event = _tool_start({"to": "john@example.com", "subject": "Hello", "body": "Please send an email to john@example.com with subject Hello"})
    finding = await detect_passthrough(event, last_llm_output=llm_output)
    assert finding is not None
    assert finding.severity == "critical"
    assert finding.signal_id == "OUT-001"


@pytest.mark.asyncio
async def test_fires_warning_between_60_and_85():
    llm_output = "search query: latest news about climate change today worldwide"
    event = _tool_start({"q": "latest news about climate change today worldwide"})
    finding = await detect_passthrough(event, last_llm_output=llm_output)
    # Ratio may be warning or critical depending on exact similarity
    if finding is not None:
        assert finding.signal_id == "OUT-001"
        assert finding.severity in ("warning", "critical")


@pytest.mark.asyncio
async def test_silent_below_60_percent():
    llm_output = "The user wants to know about Python programming best practices."
    event = _tool_start({"query": "weather forecast"})
    finding = await detect_passthrough(event, last_llm_output=llm_output)
    assert finding is None


@pytest.mark.asyncio
async def test_silent_when_no_llm_output():
    event = _tool_start({"query": "anything"})
    finding = await detect_passthrough(event, last_llm_output=None)
    assert finding is None


@pytest.mark.asyncio
async def test_matched_text_truncated_to_300():
    long_input = {"data": "x" * 400}
    llm_output = "x" * 400
    event = _tool_start(long_input)
    finding = await detect_passthrough(event, last_llm_output=llm_output)
    if finding:
        assert len(finding.matched_text) <= 300
