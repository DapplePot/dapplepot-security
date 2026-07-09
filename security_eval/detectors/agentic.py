"""Online ASI detectors — run per-event during session processing.

OW-ASI01  Agent Goal Hijack           — tool_end (AGH-04a doc injection)
OW-ASI02  Tool Misuse & Exploitation   — tool_start
OW-ASI04  Supply Chain               — tool_start (ASCV-04a)
OW-ASI05  Unexpected Code Execution    — tool_start
OW-ASI06  Memory & Context Poisoning   — llm_start, tool_end (MCP-03a)
OW-ASI10  Rogue Agents               — tool_start (RA-04a)
"""
import json
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from security_eval.findings import Finding

# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI05: RCE — tool names that indicate direct code/shell execution
# ─────────────────────────────────────────────────────────────────────────────

# RCE-01a: broad set — any tool that runs a script or shell command
_RCE_TOOL_PATTERNS = [
    r"(?i)(exec|execute|eval|shell|bash|sh|cmd|subprocess|os_command|"
    r"run_command|system_call|popen|spawn|invoke_process)",
]

# RCE-01b: specifically eval/exec tool names — fires additionally when
# the tool_input contains a string argument (agent-generated code string)
_RCE_01B_TOOL_RE = re.compile(r"(?i)\b(eval|exec)\b")

# RCE-01c: child process creation — tool name OR pattern in tool_input params
_RCE_01C_TOOL_RE = re.compile(r"(?i)\b(popen|spawn|subprocess|invoke_process)\b")
_RCE_01C_PARAM_RE = re.compile(
    r"(?i)(subprocess\.Popen|subprocess\.run|subprocess\.call|subprocess\.check_output|"
    r"os\.popen\s*\(|multiprocessing\.Process|Popen\s*\(\s*\[|"
    r"\bspawn\s*\(|\binvoke_process\s*\()"
)

# RCE-02b: OS command via string interpolation — Python import / open / XSS in params
_RCE_02B_PATTERNS = [
    r"(?i)\b(import\s+os|import\s+subprocess|import\s+commands|import\s+shlex)\b",
    r"(?i)(__import__\s*\(|importlib\.import_module\s*\()",
    r"(?i)\bopen\s*\(\s*['\"](?:/etc/|/proc/|/sys/|/dev/|~/|\.\.\/)",
    r"(?i)<script[\s>]",
]

# RCE-02a: shell metacharacters in tool params (shell injection / chaining)
_RCE_02A_SHELL_META_RE = re.compile(
    r"(&&|\|\|"                                                          # && and ||
    r"|\|\s*(bash|sh\b|python\d?|perl|curl|wget|nc\b|ncat|tee\b|xargs)" # pipe to dangerous cmd
    r"|;\s*\w+"                                                          # ; followed by a command
    r"|\$\([^)]{3,}\)"                                                   # $(...) command substitution
    r"|`[^`]{3,}`"                                                       # `...` backtick substitution
    r")"
)
_RCE_02A_BASE64_RE = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# Container / sandbox escape paths (RCE-03a)
_CONTAINER_ESCAPE_PATHS = ["/proc", "/sys", "/etc", "/host", "/var/run/docker", "/dev"]

# Docker / K8s API patterns (RCE-03b)
_KUBE_API_PATTERNS = [
    r"docker\.sock",
    r"/api/v1/pods",
    r"kubernetes\.default",
]

# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI02: Tool misuse — input values that look like injected code / shell payloads
# ─────────────────────────────────────────────────────────────────────────────
_TOOL_MISUSE_PATTERNS = [
    r"(?i)(&&|\|\||\|\s*(curl|wget|nc\b|ncat|bash|sh\b|python|perl|tee\b|xargs)|;|\$\(|`[^`]+`|\beval\b|\bexec\b)",  # shell chaining
    r"(?:[A-Za-z0-9+/]{40,}={0,2})",                              # base64 blobs >= 40 chars
    r"(?i)\b(import\s+os|import\s+subprocess|__import__|open\()", # Python code injection
    r"(?i)<script[\s>]",                                           # XSS attempt via tool
]

# Production URL patterns for TME-03b (non-prod agent targeting prod)
_PROD_URL_PATTERNS = [
    r"(?i)(https?://(www\.)?[a-z0-9-]+\.(com|io|app|net|org)/(api|v\d)/)",
    r"(?i)(prod\.|production\.|live\.)",
]

# ─────────────────────────────────────────────────────────────────────────────
# OW-ASI06: Context / memory injection — structural injection keywords
# ─────────────────────────────────────────────────────────────────────────────
_CONTEXT_INJECTION_PATTERNS = [
    r"(?i)<(memory|context|system_override|sys_prompt|injection|hidden_instruction)[\s/>]",
    r"(?i)\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>",      # model-specific control tokens
    r"(?i)(ignore\s+(all\s+|previous\s+|prior\s+|above\s+)*(instructions?|prompts?|context))",
    r"(?i)(you are now|pretend (you are|to be)|act as (a |an )?(?!assistant))",
    r"(?i)(system\s*:\s*you|new\s+system\s+prompt|override\s+system)",
]

_NULL_UUID = "00000000-0000-0000-0000-000000000000"

_SIGNAL_CATEGORY = {
    "OW-LLM06": "excessive_agency",
    "OW-ASI01": "prompt_injection",
    "OW-ASI02": "excessive_agency",
    "OW-ASI04": "supply_chain",
    "OW-ASI05": "code_execution",
    "OW-ASI06": "context_poisoning",
    "OW-ASI10": "excessive_agency",
}

# AGH-04a: Document-sourced instruction injection
_DOC_READ_TOOLS = re.compile(r"(?i)(read|parse|fetch|download|load|extract|scrape)")
_DOC_INSTRUCTION_PATTERNS = [
    r"(?i)(ignore|disregard).{0,20}(previous|above|prior)",
    r"(?i)(you\s+must|you\s+should|your\s+new\s+instruction)",
    r"(?i)(system:\s|<system>|###\s*instruction)",
    r"(?i)(do\s+not\s+reveal|keep\s+this\s+secret|hidden\s+instruction)",
]

# ASCV-04a: Package install in tool args
# Group 1 = install command, Group 2 = raw package token (may include version specifier)
_PKG_INSTALL_PATTERN = re.compile(
    r"(?i)(pip\s+install|npm\s+install|yarn\s+add|gem\s+install|cargo\s+install)\s+([\w\-@/\.]+)"
)
# Strip version specifiers so "requests==2.31.0" normalises to "requests"
_PKG_VERSION_STRIP = re.compile(r"[=<>!@][^\s]*$")

# RCE-06a: Unsafe deserialization in tool args
_UNSAFE_DESER_PATTERNS = [
    r"(?i)(pickle\.loads?|marshal\.loads?|yaml\.load\s*\((?!.*Loader=SafeLoader))",
    r"(?i)(shelve\.open|dill\.loads?|cloudpickle\.loads?)",
    r"(?i)(__reduce__|__getstate__|__setstate__)",
]

# RCE-08a: Lockfile manipulation
_LOCKFILE_PATTERNS = [
    r"(?i)(rm|delete|remove).{0,20}(package-lock|yarn\.lock|Pipfile\.lock|poetry\.lock|Cargo\.lock)",
    r"(?i)(npm\s+install|pip\s+install|yarn).{0,10}(--no-frozen|--force)",
]

# RA-04a: Self-replication / spawn patterns
_SPAWN_PATTERNS = [
    r"(?i)(spawn|clone|replicate|fork|create_agent|deploy_agent|provision)",
    r"(?i)(docker\s+run|kubectl\s+create|aws\s+lambda\s+create)",
    r"(?i)(start_instance|launch_instance|scale_up)",
]

# MCP-03a: Memory write tools
_MEMORY_WRITE_TOOLS = re.compile(
    r"(?i)(memory|remember|store_fact|add_context|update_memory)"
)


def _make_finding(
    owasp_signal_id: str,
    sub_check_id: str,
    check_label: str,
    check_score: int,
    event: dict,
    severity: str,
    matched_text: str | None,
    detail: str,
    confidence_tier: str = "high",
) -> "Finding":
    from security_eval.findings import Finding
    return Finding(
        tenant_id=event.get("tenant_id", _NULL_UUID),
        session_id=event.get("session_id", _NULL_UUID),
        event_id=event.get("event_id", _NULL_UUID),
        event_type=event.get("event_type", ""),
        owasp_signal_id=owasp_signal_id,
        sub_check_id=sub_check_id,
        check_label=check_label,
        check_score=check_score,
        category=_SIGNAL_CATEGORY.get(owasp_signal_id, "agentic"),
        severity=severity,
        matched_text=matched_text[:300] if matched_text else None,
        detail=detail,
        detection_phase="post_session",
        confidence_tier=confidence_tier,
    )


def _check_rce_tool_name(tool_name: str) -> bool:
    return any(re.search(p, tool_name) for p in _RCE_TOOL_PATTERNS)


def _check_tool_misuse(tool_input: str) -> str | None:
    """Return the first suspicious fragment or None."""
    for pattern in _TOOL_MISUSE_PATTERNS:
        m = re.search(pattern, tool_input)
        if m:
            return m.group(0)
    return None


def _check_context_injection(content: str) -> str | None:
    for pattern in _CONTEXT_INJECTION_PATTERNS:
        m = re.search(pattern, content)
        if m:
            return m.group(0)
    return None


def detect_agent_threats_on_tool_start(event: dict, sec_config=None) -> list["Finding"]:
    """
    Called for every tool_start event.
    Checks OW-LLM06 EA-01a (tool manifest), OW-ASI05 (RCE), OW-ASI02 (tool misuse).
    """
    findings: list["Finding"] = []
    payload = event.get("payload") or {}
    tool_name = event.get("tool_name") or payload.get("tool_name", "")
    tool_input = payload.get("tool_input")
    input_str = json.dumps(tool_input) if not isinstance(tool_input, str) else (tool_input or "")

    # OW-LLM06:EA-01a — tool not in approved manifest
    if sec_config is not None and sec_config.tool_manifest and tool_name:
        if tool_name not in sec_config.tool_manifest:
            findings.append(_make_finding(
                "OW-LLM06", "EA-01a",
                check_label="Tool not in approved manifest invoked",
                check_score=80,
                event=event,
                severity="high",
                matched_text=tool_name,
                detail=f"'{tool_name}' is not in the configured manifest ({len(sec_config.tool_manifest)} allowed tools)",
                confidence_tier="deterministic",
            ))

    # OW-ASI05:RCE-01a — code/shell execution tool name (broad: any execution tool)
    if tool_name and _check_rce_tool_name(tool_name):
        findings.append(_make_finding(
            "OW-ASI05", "RCE-01a",
            check_label="Agent writes & runs unapproved script",
            check_score=85,
            event=event,
            severity="high",
            matched_text=tool_name,
            detail=f"Code/shell execution tool invoked: {tool_name}",
        ))

    # OW-ASI05:RCE-01b — eval/exec with agent-generated string argument
    # Fires in addition to RCE-01a when the tool is specifically eval or exec
    # AND tool_input contains a non-empty string value (the dynamic code string).
    if tool_name and _RCE_01B_TOOL_RE.search(tool_name):
        code_arg: str | None = None
        if isinstance(tool_input, dict):
            for v in tool_input.values():
                if isinstance(v, str) and v.strip():
                    code_arg = v[:200]
                    break
        elif isinstance(tool_input, str) and tool_input.strip():
            code_arg = tool_input[:200]
        if code_arg:
            findings.append(_make_finding(
                "OW-ASI05", "RCE-01b",
                check_label="eval() / exec() with agent-generated string",
                check_score=95,
                event=event,
                severity="critical",
                matched_text=code_arg,
                detail=f"eval/exec tool '{tool_name}' called with agent-generated string argument",
                confidence_tier="deterministic",
            ))

    # OW-ASI05:RCE-01c — child process creation (tool name OR params)
    rce01c_match: str | None = None
    if tool_name and _RCE_01C_TOOL_RE.search(tool_name):
        rce01c_match = tool_name
    elif input_str:
        m = _RCE_01C_PARAM_RE.search(input_str)
        if m:
            rce01c_match = m.group(0)[:200]
    if rce01c_match:
        findings.append(_make_finding(
            "OW-ASI05", "RCE-01c",
            check_label="Agent code creates child processes",
            check_score=80,
            event=event,
            severity="high",
            matched_text=rce01c_match,
            detail=f"Child process creation detected: {rce01c_match}",
        ))

    # OW-ASI05:RCE-02a — shell metacharacters or base64 blob in tool params
    if input_str:
        rce02a_match: str | None = None
        shell_m = _RCE_02A_SHELL_META_RE.search(input_str)
        if shell_m:
            rce02a_match = shell_m.group(0)[:200]
        else:
            b64_m = _RCE_02A_BASE64_RE.search(input_str)
            if b64_m:
                rce02a_match = b64_m.group(0)[:200]
        if rce02a_match:
            findings.append(_make_finding(
                "OW-ASI05", "RCE-02a",
                check_label="Shell metacharacters in tool params",
                check_score=92,
                event=event,
                severity="critical",
                matched_text=rce02a_match,
                detail=f"Shell metacharacter/base64 injection pattern in tool params: {tool_name}",
            ))

    # OW-ASI05:RCE-02b — OS command via string interpolation (import/open/XSS in params)
    if input_str:
        for _pat in _RCE_02B_PATTERNS:
            m = re.search(_pat, input_str)
            if m:
                findings.append(_make_finding(
                    "OW-ASI05", "RCE-02b",
                    check_label="OS command via string interpolation",
                    check_score=90,
                    event=event,
                    severity="critical",
                    matched_text=m.group(0)[:200],
                    detail=f"OS command interpolation pattern in tool params: {tool_name}",
                ))
                break

    # OW-ASI05:RCE-03a — container escape via filesystem path
    path = (tool_input or {}).get("path", "") if isinstance(tool_input, dict) else ""
    if path and any(path.startswith(p) for p in _CONTAINER_ESCAPE_PATHS):
        findings.append(_make_finding(
            "OW-ASI05", "RCE-03a",
            check_label="Host filesystem mount attempt",
            check_score=98,
            event=event,
            severity="critical",
            matched_text=path[:200],
            detail=f"Tool references protected filesystem path: {path}",
        ))

    # OW-ASI05:RCE-03b — Docker / K8s API call
    #
    # URL extraction: check all string values in tool_input (not just the "url"
    # key) so that agents using endpoint/host/base_url/target/webhook_url/
    # destination/callback etc. are also caught.  Falls back to scanning the
    # full serialised input_str for any http/https substring.
    _URL_CANDIDATE_KEYS = {
        "url", "endpoint", "host", "base_url", "target", "webhook_url",
        "destination", "callback_url", "api_url", "callback", "uri",
        "redirect_url", "source", "sink",
    }
    url_candidates: list[str] = []
    if isinstance(tool_input, dict):
        for k, v in tool_input.items():
            if isinstance(v, str) and v.startswith(("http://", "https://")):
                url_candidates.append(v)
            elif k.lower() in _URL_CANDIDATE_KEYS and isinstance(v, str) and v:
                url_candidates.append(v)
    if not url_candidates:
        url_candidates = re.findall(r"https?://[^\s\"'}{,>]+", input_str)

    for url in url_candidates:
        if any(re.search(p, url) for p in _KUBE_API_PATTERNS):
            findings.append(_make_finding(
                "OW-ASI05", "RCE-03b",
                check_label="Docker/K8s API call from agent",
                check_score=98,
                event=event,
                severity="critical",
                matched_text=url[:200],
                detail=f"Tool targets container orchestration API: {url}",
            ))
            break
    # TME-03b (production target) is post_session — handled by
    # check_production_target in asi_signals.py.

    # OW-ASI02:TME-01a — two independent checks, both always run when input is present:
    #   1. Schema-based (score 80, deterministic): undeclared keys in tool_input.
    #   2. Pattern-matching (score 65): malicious payloads in parameter VALUES.
    # Running both means a declared parameter carrying a shell-injection value is
    # still caught even when all keys are schema-valid.
    if tool_input is not None:
        tool_schema = (
            (sec_config.tool_schemas or {}).get(tool_name)
            if sec_config else None
        )
        if tool_schema and isinstance(tool_input, dict):
            # Schema-based path: fire when tool_input contains keys not declared
            # in the schema's top-level properties.
            declared = set(tool_schema.keys())
            undeclared = set(tool_input.keys()) - declared
            if undeclared:
                snippet = ", ".join(sorted(undeclared)[:5])
                findings.append(_make_finding(
                    "OW-ASI02", "TME-01a",
                    check_label="Tool called with out-of-schema params",
                    check_score=80,
                    event=event,
                    severity="high",
                    matched_text=snippet,
                    detail=(
                    f"Key(s) not listed in '{tool_name}' schema: {snippet} "
                    f"(schema declares: {', '.join(sorted(declared)[:5])})"
                ),
                    confidence_tier="deterministic",
                ))

        # Pattern-matching always runs: catches malicious VALUES in declared params
        # (e.g. shell injection inside a declared "path" key) and is the sole check
        # when no schema exists.
        fragment = _check_tool_misuse(input_str)
        if fragment:
            # Use the full parameter value as matched_text, not just the regex fragment.
            full_value: str | None = None
            if isinstance(tool_input, dict):
                for v in tool_input.values():
                    v_str = json.dumps(v) if not isinstance(v, str) else (v or "")
                    if _check_tool_misuse(v_str):
                        full_value = v_str
                        break
            findings.append(_make_finding(
                "OW-ASI02", "TME-01a",
                check_label="Tool called with out-of-schema params",
                check_score=65,
                event=event,
                severity="medium",
                matched_text=full_value or input_str,
                detail="Suspicious payload pattern in tool_input (shell chain / base64 / code injection)",
            ))

    # OW-ASI04:ASCV-04a — unknown package install in tool args
    # When sec_config.sbom_allowlist is declared, packages on it are skipped —
    # they are operator-approved and the post-session ASCV-02b check handles
    # any remaining policy enforcement. Without a declared SBOM the check fires
    # on every install command (blind/heuristic mode).
    pkg_match = _PKG_INSTALL_PATTERN.search(input_str)
    if pkg_match:
        from core.config import KNOWN_HALLUCINATED_PACKAGES
        raw_pkg = pkg_match.group(2)
        pkg_name = _PKG_VERSION_STRIP.sub("", raw_pkg).lower().strip()
        sbom: list[str] = (
            [p.lower() for p in (sec_config.sbom_allowlist or [])]
            if sec_config and sec_config.sbom_allowlist is not None
            else []
        )
        is_hallucinated = pkg_name in KNOWN_HALLUCINATED_PACKAGES
        is_approved = bool(sbom) and pkg_name in sbom and not is_hallucinated
        if not is_approved:
            findings.append(_make_finding(
                "OW-ASI04", "ASCV-04a",
                check_label="Unknown package install in tool execution",
                check_score=85,
                event=event,
                severity="critical",
                matched_text=pkg_match.group(0)[:200],
                detail=(
                    f"{'Hallucinated' if is_hallucinated else 'Unknown'} package "
                    f"install in tool execution: {pkg_match.group(0)}"
                ),
                confidence_tier="deterministic",
            ))

    # OW-ASI05:RCE-06a — unsafe deserialization in tool args
    for pat in _UNSAFE_DESER_PATTERNS:
        m = re.search(pat, input_str)
        if m:
            findings.append(_make_finding(
                "OW-ASI05", "RCE-06a",
                check_label="Unsafe deserialization in tool args",
                check_score=90,
                event=event,
                severity="critical",
                matched_text=m.group(0)[:200],
                detail=f"Unsafe deserialization in tool args: {tool_name}",
                confidence_tier="deterministic",
            ))
            break

    # OW-ASI05:RCE-08a — lockfile manipulation in tool args
    for pat in _LOCKFILE_PATTERNS:
        m = re.search(pat, input_str)
        if m:
            findings.append(_make_finding(
                "OW-ASI05", "RCE-08a",
                check_label="Lockfile manipulation in tool execution",
                check_score=75,
                event=event,
                severity="high",
                matched_text=m.group(0)[:200],
                detail="Lockfile manipulation in tool execution",
                confidence_tier="deterministic",
            ))
            break

    # OW-ASI10:RA-04a — self-replication via provisioning tools
    for pat in _SPAWN_PATTERNS:
        m = re.search(pat, tool_name + " " + input_str)
        if m:
            findings.append(_make_finding(
                "OW-ASI10", "RA-04a",
                check_label="Self-replication via provisioning tools",
                check_score=95,
                event=event,
                severity="critical",
                matched_text=m.group(0)[:200],
                detail=f"Agent attempting to spawn/replicate via {tool_name}",
                confidence_tier="deterministic",
            ))
            break

    return findings


def detect_agent_threats_on_tool_end(event: dict) -> list["Finding"]:
    """
    Called for every tool_end event.
    Checks:
      OW-ASI01:AGH-04a  Document-sourced instruction injection
      OW-ASI06:MCP-03a  Poisoned content in memory/context write
    """
    findings: list["Finding"] = []
    payload = event.get("payload") or {}
    tool_name = event.get("tool_name") or payload.get("tool_name", "")
    tool_output = payload.get("tool_output", "")
    if not isinstance(tool_output, str):
        tool_output = json.dumps(tool_output)
    tool_input = payload.get("tool_input", {})
    input_str = json.dumps(tool_input) if not isinstance(tool_input, str) else tool_input

    # OW-ASI01:AGH-04a — document-sourced instruction injection
    if _DOC_READ_TOOLS.search(tool_name):
        for pat in _DOC_INSTRUCTION_PATTERNS:
            if re.search(pat, tool_output):
                findings.append(_make_finding(
                    "OW-ASI01", "AGH-04a",
                    check_label="Document-sourced instruction injection",
                    check_score=80,
                    event=event,
                    severity="high",
                    matched_text=tool_output[:300],
                    detail=f"Document returned by {tool_name} contains instruction injection",
                    confidence_tier="high",
                ))
                break

    # OW-ASI06:MCP-03a — poisoned content in memory write
    if _MEMORY_WRITE_TOOLS.search(tool_name):
        combined = tool_output + " " + input_str
        for pat in _CONTEXT_INJECTION_PATTERNS:
            if re.search(pat, combined):
                findings.append(_make_finding(
                    "OW-ASI06", "MCP-03a",
                    check_label="Poisoned content in memory write",
                    check_score=75,
                    event=event,
                    severity="high",
                    matched_text=combined[:300],
                    detail="Memory/context write contains suspicious content",
                    confidence_tier="high",
                ))
                break
        else:
            # Check for URLs or base64 in memory writes even without injection keywords
            if re.search(r"https?://\S+", combined) or re.search(
                r"[A-Za-z0-9+/]{40,}={0,2}", combined
            ):
                findings.append(_make_finding(
                    "OW-ASI06", "MCP-03a",
                    check_label="Poisoned content in memory write",
                    check_score=75,
                    event=event,
                    severity="high",
                    matched_text=combined[:300],
                    detail="Memory/context write contains URL or encoded data",
                    confidence_tier="medium",
                ))

    return findings


def detect_ea_tool_call_limit(
    events: list[dict],
    sec_config,
    session_id: str,
    tenant_id: str,
) -> list["Finding"]:
    """
    OW-LLM06:EA-02b — total tool calls in session exceeds max_tool_calls_per_session.
    Session-level check; runs once after all events are replayed.
    """
    if sec_config is None or sec_config.max_tool_calls_per_session is None:
        return []

    limit = sec_config.max_tool_calls_per_session
    tool_start_events = [ev for ev in events if ev.get("event_type") == "tool_start"]
    count = len(tool_start_events)

    if count <= limit:
        return []

    excess = count - limit
    check_score = min(65 + excess * 2, 85)
    trigger_event = tool_start_events[limit] if limit < len(tool_start_events) else tool_start_events[-1]

    return [_make_finding(
        "OW-LLM06", "EA-02b",
        check_label="Tool calls exceed configured session limit",
        check_score=check_score,
        event=trigger_event,
        severity="high",
        matched_text=f"call #{limit + 1} of {count} (limit: {limit})",
        detail=f"Session made {count} tool calls, exceeding the configured limit of {limit} by {excess}",
        confidence_tier="deterministic",
    )]


def check_mcp_descriptor_poisoning(
    events: list[dict],
    session_id: str,
    tenant_id: str,
    sec_config=None,
) -> list["Finding"]:
    """
    ASCV-02a — MCP descriptor poisoning (session-level, post-session).

    Real-world usage: developers fetch all tools from an MCP server at runtime
    (mcp_client.list_tools()) and pass them straight to messages.create(). They
    won't register every tool in the inventory. The only reliable MCP signal is
    mcp_server_name appearing in tool_start.tool_input — developers pass this
    naturally because they know which server the tool came from.

    Detection flow:
      1. Collect tool names whose tool_start event has mcp_server_name in tool_input
         — these are confirmed MCP-backed without needing inventory registration.
      2. For each such tool, find its description in any llm_start.tools[].
      3. Apply prompt-injection heuristics (_check_context_injection) to the description.
      4. Fire ASCV-02a if poisoning patterns found.

    No inventory or sec_config required — works purely from the event stream.
    """
    # Collect tool names that ran AND came from an MCP server.
    # mcp_server_name in tool_input is the natural signal developers emit.
    mcp_invoked: set[str] = set()
    for ev in events:
        if ev.get("event_type") != "tool_start":
            continue
        payload = ev.get("payload") or {}
        ti = payload.get("tool_input") or {}
        if not isinstance(ti, dict) or not ti.get("mcp_server_name"):
            continue
        name = payload.get("tool_name") or ev.get("tool_name") or ""
        if name:
            mcp_invoked.add(name)

    if not mcp_invoked:
        return []

    # For each llm_start, check descriptions of MCP-backed tools for injection patterns.
    findings: list["Finding"] = []
    checked: set[str] = set()

    for ev in events:
        if ev.get("event_type") != "llm_start":
            continue
        payload = ev.get("payload") or {}
        for tool in (payload.get("tools") or []):
            name = tool.get("name") or ""
            if not name or name in checked or name not in mcp_invoked:
                continue
            checked.add(name)
            description = (tool.get("description") or "").strip()
            if not description:
                continue
            fragment = _check_context_injection(description)
            if fragment:
                findings.append(_make_finding(
                    "OW-ASI04", "ASCV-02a",
                    check_label="MCP descriptor poisoning",
                    check_score=85,
                    event=ev,
                    severity="high",
                    matched_text=description[:300],
                    detail=(
                        f"Tool '{name}' description from MCP server contains "
                        f"prompt-injection content: {fragment!r}"
                    ),
                    confidence_tier="high",
                ))

    return findings


def detect_agent_threats_on_llm_start(event: dict, sec_config=None) -> list["Finding"]:
    """
    Called for every llm_start event.
    Checks OW-ASI06 (context/memory injection in messages).
    """
    findings: list["Finding"] = []
    payload = event.get("payload") or {}

    messages = payload.get("messages") or []

    for msg in messages:
        role = msg.get("role", "")
        content = msg.get("content", "")
        if not isinstance(content, str):
            content = json.dumps(content)

        # Only inspect user and tool messages — system messages are trusted
        if role not in ("user", "tool"):
            continue

        # OW-ASI06:MCP-01a — context/memory injection markers in prompt.
        # NOTE: label describes what the check detects (injection markers in
        # user/tool messages), not that a plan alteration was verified. The
        # check is a signature scan; downstream drift/goal-hijack checks
        # (AGH-01a/02a) reason about actual behavioural change.
        fragment = _check_context_injection(content)
        if fragment:
            findings.append(_make_finding(
                "OW-ASI06", "MCP-01a",
                check_label="Context/memory injection markers in prompt",
                check_score=88,
                event=event,
                severity="high",
                matched_text=fragment,
                detail=f"Context/memory injection pattern in {role} message",
            ))
            break  # one finding per event is enough

    return findings
