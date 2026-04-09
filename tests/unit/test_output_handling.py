"""Unit tests for the output handling (passthrough) detector — no infra required."""
import pytest

from tests.conftest import make_event
from consumers.security_eval.detectors.passthrough import detect_passthrough, _lcs_ratio


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

@pytest.mark.anyio
async def test_fires_on_high_similarity():
    llm_output = "Please send an email to john@example.com with subject Hello"
    event = _tool_start({"to": "john@example.com", "subject": "Hello", "body": "Please send an email to john@example.com with subject Hello"})
    findings = await detect_passthrough(event, last_llm_output=llm_output)
    assert len(findings) > 0
    assert findings[0].owasp_signal_id == "OW-LLM05"
    assert findings[0].sub_check_id == "IOH-02a"


@pytest.mark.anyio
async def test_silent_below_threshold():
    llm_output = "The user wants to know about Python programming best practices."
    event = _tool_start({"query": "weather forecast"})
    findings = await detect_passthrough(event, last_llm_output=llm_output)
    assert findings == []


@pytest.mark.anyio
async def test_silent_when_no_llm_output():
    event = _tool_start({"query": "anything"})
    findings = await detect_passthrough(event, last_llm_output=None)
    assert findings == []


@pytest.mark.anyio
async def test_matched_text_truncated_to_300():
    long_input = {"data": "x" * 400}
    llm_output = "x" * 400
    event = _tool_start(long_input)
    findings = await detect_passthrough(event, last_llm_output=llm_output)
    for f in findings:
        assert len(f.matched_text) <= 300


@pytest.mark.anyio
async def test_signal_id_format():
    """signal_id must be 'OW-LLM05:IOH-02a' format."""
    llm_output = "Please send an email to john@example.com with subject Hello"
    event = _tool_start({"body": "Please send an email to john@example.com with subject Hello"})
    findings = await detect_passthrough(event, last_llm_output=llm_output)
    for f in findings:
        assert f.owasp_signal_id.startswith("OW-")
        assert f.sub_check_id
