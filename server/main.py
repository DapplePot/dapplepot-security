"""
FastAPI HTTP server for dapplepot-security.

Replaces the Kafka consumer (security_eval/consumer.py) with
a simple HTTP endpoint. dapplepot-api forwards events here via HTTP POST
instead of producing to obs.events.v1.

Start:
    uvicorn server.main:app --host 0.0.0.0 --port 8001
"""
import asyncio
import logging
import os
import re
from contextlib import asynccontextmanager
from urllib.parse import urlparse

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from core.config import settings
from core.infra.postgres import close_pool, get_pool
from core.infra.redis import close_redis, get_redis


# ─────────────────────────────────────────────────────────────────────────────
# Guard check helpers (EA-01c / EA-02a / EA-03b)
# ─────────────────────────────────────────────────────────────────────────────

# Path-like tool_input keys inspected by EA-01c to detect writes leaving the
# declared namespace. Mirrors scorer/llm_signals.py check_ea_01c_write_namespace.
_EA01C_PATH_KEYS = ('path', 'file_path', 'destination', 'key', 'namespace', 'bucket', 'prefix')

# Confirm-gate tool name regex — a call to a tool matching this in the current
# session means EA-02a's approval condition is satisfied.
_EA02A_CONFIRM_GATE = re.compile(
    r"(?i)(confirm|approve|authorize|sign_off|validate_action|review_action)"
)

# Fallback irreversible tool-name regex used when tool_approval_policy is
# not declared but irreversible_tools list is empty. Same pattern as
# scorer/asi_signals.py _IRREVERSIBLE_ACTION_TOOLS (unified in patterns/ later).
_EA02A_IRREVERSIBLE_HEURISTIC = re.compile(
    r"(?i)(delete|drop|truncate|purge|wipe|destroy|erase|terminate|"
    r"remove_all|clear_all|format|shred)"
)

# URL-shaped host patterns pulled from tool_input for EA-03b.
_EA03B_URL_KEYS  = ('url', 'endpoint', 'host', 'target', 'destination', 'uri')

def _extract_hosts(tool_input: dict) -> list[str]:
    """Return the set of hostnames referenced in a tool_input dict.

    Covers both explicit fields ('url', 'host', ...) and inline http(s):// URLs
    found in any string value. Returned lowercase, without ports.
    """
    hosts: set[str] = set()
    def _from_val(val):
        if not isinstance(val, str):
            return
        # Explicit URL / hostname
        try:
            parsed = urlparse(val if '://' in val else 'x://' + val)
            if parsed.hostname:
                hosts.add(parsed.hostname.lower())
        except Exception:
            pass
        # Inline URLs
        for m in re.finditer(r'https?://([^/\s"\'<>]+)', val):
            hosts.add(m.group(1).split(':', 1)[0].lower())
    for key in _EA03B_URL_KEYS:
        _from_val(tool_input.get(key))
    # Also scan any nested string values (up to one level) — SDKs often nest
    # the URL under `params`, `body`, or `config`.
    for v in tool_input.values():
        if isinstance(v, dict):
            for nested in v.values():
                _from_val(nested)
    return sorted(hosts)


# ─── tool_start signature checks ───────────────────────────────────────────
# Deterministic-confidence patterns applied to tool_name + tool_input.
# Each returns (label, matched_text) or None. All patterns are intentionally
# tight — a false positive in Guard mode blocks a legitimate action.

_RCE_01B_EVAL_EXEC = re.compile(r"(?i)\b(eval|exec)\s*\(")
_RCE_03A_HOST_PATHS = re.compile(
    r"(?i)(/proc(?:/|\b)|/sys(?:/|\b)|/etc(?:/|\b)|/host(?:/|\b)|"
    r"/var/run/docker\.sock|/dev(?:/|\b))"
)
_RCE_03B_ORCH_API = re.compile(
    r"(?i)(docker\.sock|/api/v1/pods|/api/v1/nodes|kubernetes\.default|"
    r"/api/v1/namespaces|/apis/apps/v1)"
)
_RCE_06A_DESERIALIZATION = re.compile(
    r"(?i)(pickle\.(loads|load)|marshal\.(loads|load)|yaml\.(unsafe_)?load|"
    r"cPickle\.(loads|load)|jsonpickle)"
)
_RCE_08A_LOCKFILE = re.compile(
    r"(?i)(package-lock\.json|yarn\.lock|Pipfile\.lock|poetry\.lock|Gemfile\.lock|"
    r"composer\.lock|go\.sum|Cargo\.lock)"
)
# RCE-01a: broad code / shell execution tool-name match — mirrors
# _RCE_TOOL_PATTERNS in security_eval/detectors/agentic.py. Any tool whose
# name looks like it runs a script or shell command trips the check.
_RCE_01A_TOOL_NAME = re.compile(
    r"(?i)(exec|execute|eval|shell|bash|sh|cmd|subprocess|os_command|"
    r"run_command|system_call|popen|spawn|invoke_process)"
)
# RCE-01c: child-process creation — tool name OR param signature.
_RCE_01C_TOOL_NAME = re.compile(r"(?i)\b(popen|spawn|subprocess|invoke_process)\b")
_RCE_01C_PARAM     = re.compile(
    r"(?i)(subprocess\.Popen|subprocess\.run|subprocess\.call|subprocess\.check_output|"
    r"os\.popen\s*\(|multiprocessing\.Process|Popen\s*\(\s*\[|"
    r"\bspawn\s*\(|\binvoke_process\s*\()"
)
# RCE-02a: shell metacharacters / injection chains in tool_input.
_RCE_02A_SHELL_META = re.compile(
    r"(&&|\|\|"
    r"|\|\s*(bash|sh\b|python\d?|perl|curl|wget|nc\b|ncat|tee\b|xargs)"
    r"|;\s*\w+"
    r"|\$\([^)]{3,}\)"
    r"|`[^`]{3,}`"
    r")"
)
_RCE_02A_BASE64_BLOB = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
# RCE-02b: OS command via string interpolation in tool_input.
_RCE_02B_PATTERNS = [
    re.compile(r"(?i)\b(import\s+os|import\s+subprocess|import\s+commands|import\s+shlex)\b"),
    re.compile(r"(?i)(__import__\s*\(|importlib\.import_module\s*\()"),
    re.compile(r"(?i)\bopen\s*\(\s*['\"](?:/etc/|/proc/|/sys/|/dev/|~/|\.\.\/)"),
    re.compile(r"(?i)<script[\s>]"),
]
# RCE-05a: backdoor signatures inside fenced code blocks in llm_end output.
# Mirrors _BACKDOOR_PATTERNS in security_eval/scorer/asi_signals.py.
_RCE_05A_CODE_FENCE = re.compile(r"```[\s\S]*?```")
_RCE_05A_BACKDOOR_PATTERNS = [
    re.compile(r"(?i)reverse.{0,10}shell"),
    re.compile(r"(?i)socket\.connect\s*\(\s*\("),
    re.compile(r"(?i)bind\s*\(\s*\(\s*['\"]0\.0\.0\.0"),
    re.compile(r"(?i)nc\s+-[lv]*\s+.*\d+"),
    re.compile(r"(?i)subprocess\.Popen\s*\(\s*\[.*sh.*-c"),
    re.compile(r"(?i)crypto\.createCipher"),
    re.compile(r"(?i)btoa\s*\(.*document\.cookie"),
    re.compile(r"(?i)fetch\s*\(\s*['\"]https?://\d{1,3}\.\d{1,3}"),
]

# ─────────────────────────────────────────────────────────────────────────────
# Signature-only ports from post-session detectors. Every pattern mirrors its
# source in security_eval/detectors/agentic.py or security_eval/scorer/
# asi_signals.py 1:1 to keep both pipelines aligned.
# ─────────────────────────────────────────────────────────────────────────────

# AGH-04a — document-sourced instruction injection (tool_end).
_AGH_04A_DOC_READ_TOOL = re.compile(r"(?i)(read|parse|fetch|download|load|extract|scrape)")
_AGH_04A_DOC_INSTRUCTION_PATTERNS = [
    re.compile(r"(?i)(ignore|disregard).{0,20}(previous|above|prior)"),
    re.compile(r"(?i)(you\s+must|you\s+should|your\s+new\s+instruction)"),
    re.compile(r"(?i)(system:\s|<system>|###\s*instruction)"),
    re.compile(r"(?i)(do\s+not\s+reveal|keep\s+this\s+secret|hidden\s+instruction)"),
]

# MCP-01a / MCP-03a — shared context/memory injection markers.
_MCP_CONTEXT_INJECTION_PATTERNS = [
    re.compile(r"(?i)<(memory|context|system_override|sys_prompt|injection|hidden_instruction)[\s/>]"),
    re.compile(r"(?i)\[INST\]|\[\/INST\]|<\|im_start\|>|<\|im_end\|>"),
    re.compile(r"(?i)(ignore\s+(all\s+|previous\s+|prior\s+|above\s+)*(instructions?|prompts?|context))"),
    re.compile(r"(?i)(you are now|pretend (you are|to be)|act as (a |an )?(?!assistant))"),
    re.compile(r"(?i)(system\s*:\s*you|new\s+system\s+prompt|override\s+system)"),
]
_MCP_03A_MEMORY_WRITE_TOOL = re.compile(
    r"(?i)(memory|remember|store_fact|add_context|update_memory)"
)
# MCP-03a fallback: URL or base64 blob in a memory write (no injection keywords).
_MCP_03A_URL = re.compile(r"https?://\S+")
_MCP_03A_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")

# IPA-02a — delegation with full/unrestricted permissions (tool_start).
_IPA_02A_DELEGATION_TOOL = re.compile(r"(?i)(delegate|dispatch|invoke_agent|call_agent|forward)")
_IPA_02A_FULL_PERMS      = re.compile(r"(?i)(\*|admin|all\s+permissions?|full\s+access)")

# IPA-02b — credential written to a shared memory namespace (tool_start).
# Online variant covers Layer 1 (known shared-memory-write tool + credential
# in tool_input, with no agent_id/session_id marker in the key value) —
# Layer 2 (arbitrary tool with an explicit shared namespace) stays post-session.
_IPA_02B_SHARED_MEMORY_WRITE_TOOL = re.compile(
    r"(?i)(memory_write|kv_set|cache_set|shared_store|redis_set|set_context|"
    r"save_context|store_memory|write_memory|put_memory|memory_put|"
    r"write_shared|set_shared|shared_write|context_store|store_context)"
)
_IPA_02B_CREDENTIAL_PATTERN = re.compile(
    r"(?i)(password|token|secret|api_key|ssh_key|bearer)\s*[:=]\s*\S+"
)
_IPA_02B_MEMORY_KEY_FIELD = re.compile(
    r"(?i)\b(namespace|key|path|scope|bucket|prefix|collection|store)\b"
)
_IPA_02B_AGENT_SCOPED = re.compile(
    r"(?i)(agent[_\-]id|session[_\-]id|agent[_\-]scoped|private[_\-])"
)

# IAC-02b — sensitive agent message payload logged in plaintext (tool_start).
_IAC_02B_LOG_TOOL = re.compile(
    r"(?i)\b(write_log|log_event|log_message|append_log|audit_log|audit_event|"
    r"record_event|record_log|send_log|emit_log|debug_log|error_log|info_log|"
    r"warn_log|send_trace|emit_trace|observability_log|telemetry_log|log)\b"
)
_IAC_02B_SENSITIVE = [
    ("credential", re.compile(r"(?i)(password|token|secret|api_key|ssh_key|bearer)\s*[:=]\s*\S+")),
    ("JWT",        re.compile(r"eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}")),
    ("api_key",    re.compile(r"\b(sk-[a-zA-Z0-9]{24,}|ghp_[a-zA-Z0-9]{36}|AKIA[A-Z0-9]{16})\b")),
    ("email",      re.compile(r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b")),
    ("phone",      re.compile(r"\b\d{3}[-.]\d{3}[-.]\d{4}\b")),
    ("SSN",        re.compile(r"\b(?!000|666|9\d{2})\d{3}-(?!00)\d{2}-(?!0000)\d{4}\b")),
    ("credit_card",re.compile(r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13})\b")),
]

# ASCV-03b — third-party fetch tool + executable content in tool_output.
_ASCV_03B_FETCH_TOOL = re.compile(
    r"(?i)\b(fetch|http[_]?get|http[_]?post|web[_]?fetch|url[_]?fetch|download|"
    r"get[_]?url|read[_]?url|api[_]?call|external[_]?request|browse|crawl|"
    r"scrape|retrieve[_]?url|pull[_]?data|get[_]?remote)\b"
)
_ASCV_03B_EXTERNAL_URL = re.compile(
    r"https?://(?!(localhost|127\.0\.0\.1|0\.0\.0\.0|"
    r"10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
    r"172\.(1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|"
    r"192\.168\.\d{1,3}\.\d{1,3}))"
)
_ASCV_03B_EXECUTABLE_PATTERNS = [
    re.compile(r"(?m)^#!(/usr/bin/env\s+\S+|/bin/(bash|sh|python\d?|perl|ruby))"),
    re.compile(r"(?i)\b(curl|wget)\s+\S+\s*\|\s*(bash|sh|python\d?)\b"),
    re.compile(r"(?i)base64\s+(--decode|-d)\s*\|\s*(bash|sh|python\d?)"),
    re.compile(r"(?i)(IEX|Invoke-Expression)\s*\(\s*(New-Object|iwr|Invoke-WebRequest)"),
    re.compile(r"(?i)\beval\s*\(\s*(base64_decode|atob|b64decode)"),
    re.compile(r"(?i)\bexec\s*\(\s*(compile\s*\(|__import__|base64|requests\.get)"),
    re.compile(r"(?i)(msfvenom|meterpreter|(?:reverse|bind)[\s_-]?shell)"),
    re.compile(r"(?i)\bnc\s+\S+\s+\d+\s+-e\s+/bin/(sh|bash)"),
    re.compile(r"(?i)\$\((curl|wget)\s+https?://\S+\)"),
    re.compile(r"(?i)(chmod\s+\+x|chmod\s+777)\s+\S+\s*&&"),
]

# TME-06a — Optimal String Alignment distance for tool-name typosquatting.
# Mirrors _osa_distance in security_eval/scorer/asi_signals.py. Handles
# insert/delete/substitute/transpose; transpose costs 1 so "delet" vs "delete"
# comes out at distance 1 rather than 2 (Levenshtein would give 2).
def _tme_06a_osa_distance(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 2:
        return 99
    m, n = len(a), len(b)
    dp = [[0] * (n + 1) for _ in range(m + 1)]
    for i in range(m + 1): dp[i][0] = i
    for j in range(n + 1): dp[0][j] = j
    for i in range(1, m + 1):
        for j in range(1, n + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            dp[i][j] = min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                dp[i][j] = min(dp[i][j], dp[i - 2][j - 2] + 1)
    return dp[m][n]


# HAT-02a / HAT-03a — credential-request / payment-manipulation in llm_end output.
_HAT_02A_PATTERNS = [
    re.compile(r"(?i)(please\s+)?(enter|provide|share|give|type|input).{0,20}(password|credential|token|api.?key|secret|ssn|social\s+security)"),
    re.compile(r"(?i)(what\s+is\s+your|can\s+you\s+share).{0,20}(password|login|credential)"),
    re.compile(r"(?i)(verify|confirm).{0,15}(identity|account).{0,20}(password|pin|security\s+code)"),
]
_HAT_03A_PATTERNS = [
    re.compile(r"(?i)(transfer|send|pay|wire).{0,30}(to\s+account|to\s+bank|IBAN|routing\s+number)"),
    re.compile(r"(?i)(urgent|immediate).{0,20}(payment|transfer|wire)"),
    re.compile(r"(?i)(updated?\s+)?bank.{0,10}(detail|account|info)"),
]

# EA-03a — file-read tool name; fires when its path arg leaves working_directory.
_EA_03A_READ_TOOL = re.compile(
    r"(?i)\b(read|open|load|get|fetch|parse|cat|head|tail)[\w_]*(file|doc|content|text|data)?\b"
)
_EA_03A_PATH_KEYS = ("path", "file_path", "filename", "filepath", "source")

# TME-03b — production-URL patterns + candidate URL keys.
_TME_03B_PROD_URL_PATTERNS = [
    re.compile(r"(?i)(https?://(www\.)?[a-z0-9-]+\.(com|io|app|net|org)/(api|v\d)/)"),
    re.compile(r"(?i)(prod\.|production\.|live\.)"),
]
_TME_03B_URL_KEYS = frozenset({
    "url", "endpoint", "host", "base_url", "target", "webhook_url",
    "destination", "callback_url", "api_url", "callback", "uri",
    "redirect_url", "source", "sink",
})

# IPA-01a — privilege-escalation tool-name + payload patterns.
_IPA_01A_PRIV_TOOL_PATTERNS = [
    re.compile(r"(?i)\b(admin|sudo|su|impersonate|elevate|assume_role|"
               r"switch_user|become|run_as|escalate|grant_access|set_permissions)\b"),
]
_IPA_01A_ESCALATION_PAYLOAD = re.compile(
    r"(?i)("
    r"GRANT\s+(ALL|PRIVILEGES|SELECT|INSERT|UPDATE|DELETE|EXECUTE|\w+\s+ON)\b|"
    r"ALTER\s+ROLE\b|CREATE\s+ROLE\b|"
    r"assume.?role|AssumeRole|"
    r"attach.{0,20}[Pp]olicy|[Pp]ut.{0,20}[Pp]olicy|setIamPolicy|"
    r"set.{0,20}iam\b|create.{0,20}access.?key|CreateAccessKey|"
    r"cluster-admin|clusterrolebinding|ClusterRoleBinding|"
    r"add.{0,20}cluster.{0,20}role|"
    r"sp_addrolemember|sp_addsrvrolemember"
    r")"
)

# ASCV-01a — MCP-shaped tool name + URL param keys.
_ASCV_01A_MCP_TOOL = re.compile(r"(?i)(mcp|tool|call|invoke|request)")
_ASCV_01A_URL_KEYS = ("url", "endpoint", "server", "base_url")

# ASCV-02b — package install command patterns for extracting installed name.
_ASCV_02B_PKG_INSTALL = re.compile(
    r"(?i)(pip\s+install|npm\s+install|yarn\s+add|gem\s+install|cargo\s+install)"
    r"\s+((?:@[\w\-]+/)?[\w][\w\-]*)"
)
_ASCV_02B_VERSION_STRIP = re.compile(r"[=<>!~@].*$")

# IAC-01a / IAC-05a — inter-agent tool patterns + auth-field allowlist +
# agent-id key set for target extraction.
_IAC_INTER_AGENT_PATTERNS = [
    re.compile(r"(?i)\b(agent_handoff|delegate|sub_agent|call_agent|"
               r"invoke_agent|spawn_agent|agent_call|forward_to_agent)\b"),
]
_IAC_01A_AUTH_FIELDS = frozenset({
    "signature", "hmac", "auth_token", "authorization",
    "signed_by", "jwt", "bearer_token", "x_agent_sig",
    "agent_signature", "request_signature", "message_signature",
    "auth", "x_signature", "sig",
})
_IAC_05A_AGENT_ID_KEYS = (
    "agent_id", "target_agent_id", "agent", "target",
    "agent_name", "delegate_to", "sub_agent_id", "recipient_agent",
)

# RA-01b — day-of-week names in the order Python's weekday() returns.
_RA_01B_DAY_NAMES = ("Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun")
_ASCV_04A_PKG_INSTALL = re.compile(
    r"(?i)\b(pip|pip3|npm|yarn|pnpm|apt|apt-get|dnf|yum|brew|gem|cargo|go)\s+"
    r"(install|add|get)\b"
)
_RA_04A_PROVISIONING = re.compile(
    r"(?i)(create_agent|spawn_agent|register_service|clone_instance|"
    r"replicate_agent|provision_agent|deploy_agent|instantiate_agent)"
)
_IAC_02A_ENCRYPTION = re.compile(
    r"(?i)(insecure|no.?encryption|plaintext|unencrypted|tls_disabled|"
    r"skip_ssl|verify\s*=\s*false)"
)
# MCP-04a already uses _TENANT_FIELD_PAT-style logic; simpler online form.
_MCP_04A_TENANT_FIELD = re.compile(
    r'(?i)["\']?(tenant(?:_?id)?)["\']?\s*[:=]\s*["\']?([A-Za-z0-9\-_]{4,})["\']?'
)


def _host_in_allowlist(host: str, allowlist: list[str]) -> bool:
    """host matches an allowlist entry via exact match or suffix (`.example.com`)."""
    host = host.lower().strip()
    for entry in allowlist:
        entry = entry.lower().strip()
        if not entry:
            continue
        if entry == host or host.endswith('.' + entry):
            return True
    return False

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s %(message)s',
)
logger = logging.getLogger(__name__)

ALLOWED_ORIGINS = os.getenv('ALLOWED_ORIGINS', 'http://localhost:3000').split(',')
_INTERNAL_SECRET = settings.internal_api_secret


def _require_internal_secret(request: Request) -> None:
    if not _INTERNAL_SECRET or request.headers.get('X-Internal-Secret') != _INTERNAL_SECRET:
        raise HTTPException(status_code=403, detail='forbidden')


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Warm up connection pools
    await get_pool()
    await get_redis()

    # Daily scheduled trust recompute so dormant agents' trust ages naturally
    # instead of freezing at their last session's value.
    trust_task = asyncio.create_task(_trust_decay_scheduler(), name="trust_decay_scheduler")

    logger.info('dapplepot-security HTTP server started')
    yield

    trust_task.cancel()
    try:
        await trust_task
    except asyncio.CancelledError:
        pass

    await close_pool()
    await close_redis()
    logger.info('dapplepot-security HTTP server stopped')


# ─────────────────────────────────────────────────────────────────────────────
# Scheduled trust recompute
# ─────────────────────────────────────────────────────────────────────────────

# Interval between recompute passes. 24h is intentional — trust changes on
# session boundaries and via slow decay; sub-day recomputes waste DB cycles.
_TRUST_RECOMPUTE_INTERVAL_S    = 24 * 60 * 60
# Agents whose trust score hasn't been updated in this many days are eligible
# for decay-only recompute. Recently-active agents get their update via
# score_session and don't need the sweep.
_TRUST_STALE_THRESHOLD_DAYS    = 1
# Cap per-tick agent count so a slow DB doesn't back up the event loop.
_TRUST_RECOMPUTE_BATCH_LIMIT   = 500


async def _trust_decay_scheduler() -> None:
    """Long-running task: sleep, then recompute trust for stale agents.

    Runs forever until server shutdown cancels it. Any exception is caught
    and logged so a single bad iteration doesn't kill the loop.
    """
    # Startup delay so the recompute doesn't fight for the pool during boot.
    await asyncio.sleep(60)
    while True:
        try:
            await _run_trust_decay_sweep()
        except asyncio.CancelledError:
            raise
        except Exception:
            logger.exception('trust decay sweep failed; continuing')
        await asyncio.sleep(_TRUST_RECOMPUTE_INTERVAL_S)


async def _run_trust_decay_sweep() -> None:
    """Recompute trust for every agent whose trust hasn't updated in
    >= _TRUST_STALE_THRESHOLD_DAYS days."""
    pool = await get_pool()

    # Find candidate agents. `agent_risk_scores.last_scored_at` is the last
    # time any session-driven update landed. If the agent has no sessions at
    # all they don't appear in the table; that's fine — no history means the
    # prior (~80) applies at query time.
    try:
        rows = await pool.fetch(
            """
            SELECT tenant_id, agent_id
            FROM agent_risk_scores
            WHERE last_scored_at < now() - ($1 || ' days')::interval
            LIMIT $2
            """,
            str(_TRUST_STALE_THRESHOLD_DAYS),
            _TRUST_RECOMPUTE_BATCH_LIMIT,
        )
    except Exception:
        logger.exception('trust sweep candidate query failed')
        return

    if not rows:
        logger.debug('trust decay sweep: no stale agents')
        return

    logger.info('trust decay sweep starting for %d agent(s)', len(rows))
    from security_eval.scorer.trust import recompute_trust_decay_only

    for r in rows:
        tenant_id = r['tenant_id']
        agent_id  = r['agent_id']
        try:
            hist = await pool.fetch(
                """
                SELECT llm_score, asi_score, scored_at
                FROM session_risk_scores
                WHERE agent_id = $1 AND tenant_id = $2
                ORDER BY scored_at DESC
                LIMIT 50
                """,
                agent_id, tenant_id,
            )
            historical = [
                {'llm_score': h['llm_score'], 'asi_score': h['asi_score'], 'scored_at': h['scored_at']}
                for h in hist
            ]
            if not historical:
                continue

            result = recompute_trust_decay_only(agent_id=str(agent_id), historical_scores=historical)

            await pool.execute(
                """
                UPDATE agent_risk_scores
                   SET trust_score       = $3,
                       trust_trend       = $4,
                       trust_alpha       = $5,
                       trust_beta        = $6,
                       last_scored_at    = now()
                 WHERE tenant_id = $1 AND agent_id = $2
                """,
                tenant_id, agent_id,
                result['trust_score'], result['trend'],
                result['alpha'], result['beta'],
            )
        except Exception:
            logger.exception('trust recompute failed for agent %s/%s', tenant_id, agent_id)

    logger.info('trust decay sweep complete')


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


# ─────────────────────────────────────────────────────────────────────────────
# Shadow evidence — sub-check firing counts per agent per window.
#
# Powers the "would have blocked N sessions in the last 7 days" trust-building
# prompt in the Enforce confirmation modal, and the ambient "fired N× last 7d"
# stat on each row of the Checks tab.
# ─────────────────────────────────────────────────────────────────────────────

@app.get('/v1/agents/{agent_id}/subcheck-firings')
async def subcheck_firings(
    agent_id: str,
    tenant_id: str,
    window_days: int = 7,
    _: None = Depends(_require_internal_secret),
):
    """Return {sub_check_id → { count, distinct_sessions }} for the window.

    Powers the "N fired in last 7 days" ambient stat and the Enforce
    confirmation modal ("this would have blocked 3 sessions — review →").
    """
    if window_days <= 0 or window_days > 90:
        return JSONResponse({'error': 'window_days must be 1..90'}, status_code=400)

    pool = await get_pool()
    try:
        rows = await pool.fetch(
            """
            SELECT sub_check_id,
                   COUNT(*)                    AS count,
                   COUNT(DISTINCT session_id)  AS distinct_sessions,
                   MAX(created_at)             AS last_fired_at
            FROM security_findings
            WHERE tenant_id = $1
              AND agent_id  = $2
              AND created_at >= now() - ($3 || ' days')::interval
            GROUP BY sub_check_id
            """,
            tenant_id, agent_id, str(window_days),
        )
    except Exception:
        logger.exception('subcheck_firings query failed agent_id=%s', agent_id)
        return JSONResponse({'error': 'internal error'}, status_code=500)

    result = {
        r['sub_check_id']: {
            'count':             int(r['count']),
            'distinct_sessions': int(r['distinct_sessions']),
            'last_fired_at':     r['last_fired_at'].isoformat() if r['last_fired_at'] else None,
        }
        for r in rows
    }
    return {'window_days': window_days, 'firings': result}


@app.get('/v1/agents/{agent_id}/subcheck-firings/{sub_check_id}/sessions')
async def subcheck_firing_sessions(
    agent_id: str,
    sub_check_id: str,
    tenant_id: str,
    window_days: int = 7,
    limit: int = 25,
    _: None = Depends(_require_internal_secret),
):
    """Return the sessions in which a specific sub-check fired.

    Used by the Enforce confirmation modal to list "these are the sessions
    this check would have affected" with click-through links.
    """
    if window_days <= 0 or window_days > 90:
        return JSONResponse({'error': 'window_days must be 1..90'}, status_code=400)
    limit = max(1, min(200, limit))

    pool = await get_pool()
    try:
        rows = await pool.fetch(
            """
            SELECT DISTINCT ON (session_id)
                   session_id, event_type, matched_text, created_at, severity
            FROM security_findings
            WHERE tenant_id     = $1
              AND agent_id      = $2
              AND sub_check_id  = $3
              AND created_at   >= now() - ($4 || ' days')::interval
            ORDER BY session_id, created_at DESC
            LIMIT $5
            """,
            tenant_id, agent_id, sub_check_id, str(window_days), limit,
        )
    except Exception:
        logger.exception(
            'subcheck_firing_sessions query failed agent_id=%s sub_check_id=%s',
            agent_id, sub_check_id,
        )
        return JSONResponse({'error': 'internal error'}, status_code=500)

    return {
        'window_days':  window_days,
        'sub_check_id': sub_check_id,
        'sessions': [
            {
                'session_id':   r['session_id'],
                'event_type':   r['event_type'],
                'severity':     r['severity'],
                'matched_text': (r['matched_text'] or '')[:200],
                'created_at':   r['created_at'].isoformat() if r['created_at'] else None,
            }
            for r in rows
        ],
    }


@app.post('/v1/evaluate', status_code=202)
async def evaluate(request: Request, _: None = Depends(_require_internal_secret)):
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
        from security_eval.consumer import _handle_event
        # _handle_event schedules async tasks internally; run it in current loop
        await _handle_event(event)
    except Exception:
        logger.exception('evaluate failed for event_type=%s session_id=%s',
                         event.get('event_type'), event.get('session_id'))
        return JSONResponse({'error': 'internal error'}, status_code=500)

    return Response(status_code=202)


@app.post('/v1/online-check')
async def online_check(request: Request, _: None = Depends(_require_internal_secret)):
    """
    Real-time threat detection endpoint called by SDK via backend proxy.
    Fetches config, runs detection, adds actions, returns findings.

    Latency budget (target — enforced in a follow-up):
      * p50   ≤  15 ms
      * p95   ≤  60 ms
      * p99   ≤ 100 ms
      * timeout in the SDK client is 5 s.
    All checks below run inline on the request path — do not add any I/O here
    without measuring and updating the budget.
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
    # ─── Policy fields for EA-01c / EA-02a / EA-03b ────────────────────────
    write_namespace       = body.get('write_namespace') or None
    network_allowlist     = body.get('network_allowlist')  or []
    irreversible_tools    = body.get('irreversible_tools') or []
    tool_approval_policy  = body.get('tool_approval_policy') or {}
    # Running-in-session confirm-tool flag: True iff a confirm-gate tool has
    # been invoked earlier in this session (SDK maintains the flag; sending
    # over the wire avoids server-side per-session state).
    confirm_gate_seen     = bool(body.get('confirm_gate_seen', False))

    # ─── Policy fields for the remaining SDK-fed online checks ─────────────
    # Every check is silent when its field is empty / None — declaring the
    # field is the customer's explicit opt-in, matching the pattern above.
    working_directory     = body.get('working_directory') or None
    connected_llms        = body.get('connected_llms')    or []
    environment           = body.get('environment')       or None
    privilege_scope       = body.get('privilege_scope')   or []
    mcp_endpoints         = body.get('mcp_endpoints')     or []
    sbom_allowlist        = body.get('sbom_allowlist')    or []
    connected_agents      = body.get('connected_agents')  or []
    operating_hours       = body.get('operating_hours')   or None

    if not all([event_type, payload, session_id, agent_id, tenant_id]):
        return JSONResponse({'error': 'missing required fields'}, status_code=400)

    findings = []

    # Run Python detector for PI/SID/IOH checks
    needs_detector = any(k.startswith(('PI-', 'SID-', 'IOH-')) for k in enabled_checks)
    if needs_detector:
        try:
            from security_eval.detectors.online import detect_online
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

    # ─── Guard-side policy checks (EA-01c / EA-02a / EA-03b) ───────────────
    #
    # These fire on tool_start only, and only when the customer has declared
    # the relevant Governance field. If a field is not declared, the check is
    # silent (returns no finding) — enforcing on an undeclared policy would
    # surprise the customer.
    #
    # Manual/auto mode split: manual mode (policy field set) is enforceable
    # here; auto mode (regex heuristics) stays in post-session where the whole
    # session is available.
    if event_type == 'tool_start':
        tool_name  = str(payload.get('tool_name', '') or '')
        tool_input = payload.get('tool_input') or {}
        if isinstance(tool_input, str):
            try:
                import json as _json_mod
                tool_input = _json_mod.loads(tool_input)
            except Exception:
                tool_input = {}
        if not isinstance(tool_input, dict):
            tool_input = {}

        # ── EA-01c: write outside declared namespace ──────────────────────
        if 'EA-01c' in enabled_checks and write_namespace:
            for key in _EA01C_PATH_KEYS:
                val = tool_input.get(key)
                if not isinstance(val, str) or not val:
                    continue
                if not val.startswith(write_namespace):
                    findings.append({
                        'sub_check_id': 'EA-01c',
                        'owasp_signal_id': 'OW-LLM06',
                        'check_label': 'Data written outside designated namespace',
                        'check_score': 75,
                        'category': 'excessive_agency',
                        'severity': 'high',
                        'matched_text': f"{tool_name}({key}={val[:120]})",
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action': enabled_checks['EA-01c'],
                    })
                    break  # one finding per tool_start is enough

        # ── EA-02a: irreversible action without confirm gate ──────────────
        if 'EA-02a' in enabled_checks and not confirm_gate_seen:
            # Two ways a tool qualifies as "irreversible":
            #   1. Explicitly listed in irreversible_tools
            #   2. tool_approval_policy marks it needs_approval / always_block
            #   3. Fallback heuristic on the tool name
            policy_verdict = tool_approval_policy.get(tool_name) if isinstance(tool_approval_policy, dict) else None
            is_listed      = tool_name in irreversible_tools if irreversible_tools else False
            is_needs_gate  = policy_verdict in ('needs_approval', 'always_block')
            is_heuristic   = (not irreversible_tools and not policy_verdict
                              and bool(_EA02A_IRREVERSIBLE_HEURISTIC.search(tool_name)))
            # If the tool being invoked IS itself the confirm-gate tool, skip.
            is_confirm_call = bool(_EA02A_CONFIRM_GATE.search(tool_name))

            if not is_confirm_call and (is_listed or is_needs_gate or is_heuristic):
                findings.append({
                    'sub_check_id': 'EA-02a',
                    'owasp_signal_id': 'OW-LLM06',
                    'check_label': 'Irreversible action without confirm gate',
                    'check_score': 85,
                    'category': 'excessive_agency',
                    'severity': 'high',
                    'matched_text': tool_name[:200],
                    'confidence_tier': 'high',
                    'detection_phase': 'online',
                    'action': enabled_checks['EA-02a'],
                })

        # ── EA-03b: network call to host not in allowlist ─────────────────
        if 'EA-03b' in enabled_checks and network_allowlist:
            hosts = _extract_hosts(tool_input)
            for host in hosts:
                if not _host_in_allowlist(host, network_allowlist):
                    findings.append({
                        'sub_check_id': 'EA-03b',
                        'owasp_signal_id': 'OW-LLM06',
                        'check_label': 'Network call to host not in allowlist',
                        'check_score': 75,
                        'category': 'excessive_agency',
                        'severity': 'high',
                        'matched_text': f"{tool_name} → {host}",
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action': enabled_checks['EA-03b'],
                    })
                    break  # one finding per tool_start is enough

        # ── Deterministic-confidence tool_start signature checks ──
        # Each does a single regex over tool_name + serialised tool_input and
        # emits at most one finding per event. Table-driven to keep the
        # per-check plumbing consistent.
        _tool_input_str = str(tool_input) if not isinstance(tool_input, str) else tool_input
        _combined = f"{tool_name} {_tool_input_str}"

        _WAVE2_TOOL_START = [
            ('RCE-01a',  'OW-ASI05', 'Agent writes & runs unapproved script',          85, 'high',     'code_execution',   _RCE_01A_TOOL_NAME),
            ('RCE-01b',  'OW-ASI05', 'eval() / exec() with agent-generated string',    95, 'critical', 'code_execution',   _RCE_01B_EVAL_EXEC),
            ('RCE-02a',  'OW-ASI05', 'Shell metacharacters in tool params',            92, 'critical', 'code_execution',   _RCE_02A_SHELL_META),
            ('RCE-03a',  'OW-ASI05', 'Agent mounts host filesystem paths',             98, 'critical', 'code_execution',   _RCE_03A_HOST_PATHS),
            ('RCE-03b',  'OW-ASI05', 'Agent calls Docker / K8s API',                   98, 'critical', 'code_execution',   _RCE_03B_ORCH_API),
            ('RCE-06a',  'OW-ASI05', 'Unsafe deserialization in tool args',            90, 'critical', 'code_execution',   _RCE_06A_DESERIALIZATION),
            ('RCE-08a',  'OW-ASI05', 'Lockfile manipulation in tool execution',        75, 'high',     'code_execution',   _RCE_08A_LOCKFILE),
            ('ASCV-04a', 'OW-ASI04', 'Unknown package install in tool execution',      85, 'critical', 'supply_chain',     _ASCV_04A_PKG_INSTALL),
            ('RA-04a',   'OW-ASI10', 'Self-replication via provisioning tools',        95, 'critical', 'rogue_behavior',   _RA_04A_PROVISIONING),
            ('IAC-02a',  'OW-ASI07', 'Unencrypted inter-agent communication',          80, 'high',     'inter_agent',      _IAC_02A_ENCRYPTION),
        ]
        for cid, sig, label, score, sev, cat, pat in _WAVE2_TOOL_START:
            if cid not in enabled_checks:
                continue
            m = pat.search(_combined)
            if not m:
                continue
            findings.append({
                'sub_check_id': cid,
                'owasp_signal_id': sig,
                'check_label': label,
                'check_score': score,
                'category': cat,
                'severity': sev,
                'matched_text': m.group()[:200],
                'confidence_tier': 'deterministic',
                'detection_phase': 'online',
                'action': enabled_checks[cid],
            })

        # ── RCE-01c: child-process creation (tool name OR param pattern) ──
        # Kept out of the table because it has two independent gates that
        # produce two different matched_text sources.
        if 'RCE-01c' in enabled_checks:
            rce01c_match: str | None = None
            if _RCE_01C_TOOL_NAME.search(tool_name):
                rce01c_match = tool_name
            elif _tool_input_str:
                m = _RCE_01C_PARAM.search(_tool_input_str)
                if m:
                    rce01c_match = m.group(0)[:200]
            if rce01c_match:
                findings.append({
                    'sub_check_id':    'RCE-01c',
                    'owasp_signal_id': 'OW-ASI05',
                    'check_label':     'Agent code creates child processes',
                    'check_score':     80,
                    'category':        'code_execution',
                    'severity':        'high',
                    'matched_text':    rce01c_match[:200],
                    'confidence_tier': 'high',
                    'detection_phase': 'online',
                    'action':          enabled_checks['RCE-01c'],
                })

        # ── RCE-02b: OS command via string interpolation (multi-pattern) ──
        if 'RCE-02b' in enabled_checks and _tool_input_str:
            for pat in _RCE_02B_PATTERNS:
                m = pat.search(_tool_input_str)
                if m:
                    findings.append({
                        'sub_check_id':    'RCE-02b',
                        'owasp_signal_id': 'OW-ASI05',
                        'check_label':     'OS command via string interpolation',
                        'check_score':     90,
                        'category':        'code_execution',
                        'severity':        'critical',
                        'matched_text':    m.group(0)[:200],
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['RCE-02b'],
                    })
                    break

        # ── RCE-02a companion: base64 blob in params (rides same event). ──
        # RCE-02a already dispatched via the table on shell metachars — this
        # supplements it with the base64-blob branch from the source detector.
        if 'RCE-02a' in enabled_checks and _tool_input_str:
            if not _RCE_02A_SHELL_META.search(_combined):
                b64_m = _RCE_02A_BASE64_BLOB.search(_tool_input_str)
                if b64_m:
                    findings.append({
                        'sub_check_id':    'RCE-02a',
                        'owasp_signal_id': 'OW-ASI05',
                        'check_label':     'Shell metacharacters in tool params',
                        'check_score':     92,
                        'category':        'code_execution',
                        'severity':        'critical',
                        'matched_text':    b64_m.group(0)[:200],
                        'confidence_tier': 'medium',
                        'detection_phase': 'online',
                        'action':          enabled_checks['RCE-02a'],
                    })

        # ── IPA-02a: delegation to sub-agent with full permissions ──
        if 'IPA-02a' in enabled_checks and tool_name and _IPA_02A_DELEGATION_TOOL.search(tool_name):
            m = _IPA_02A_FULL_PERMS.search(_tool_input_str) if _tool_input_str else None
            if m:
                findings.append({
                    'sub_check_id':    'IPA-02a',
                    'owasp_signal_id': 'OW-ASI03',
                    'check_label':     'Delegation with full permissions',
                    'check_score':     80,
                    'category':        'privilege_escalation',
                    'severity':        'high',
                    'matched_text':    m.group(0)[:200],
                    'confidence_tier': 'high',
                    'detection_phase': 'online',
                    'action':          enabled_checks['IPA-02a'],
                })

        # ── IPA-02b: credential written to a shared memory namespace ──
        # Online variant covers Layer 1 only — the shared-memory-write tool
        # path. Layer 2 (arbitrary tool with an explicit shared namespace) is
        # slower and stays in post-session.
        if 'IPA-02b' in enabled_checks and tool_name and _IPA_02B_SHARED_MEMORY_WRITE_TOOL.search(tool_name):
            cred_m = _IPA_02B_CREDENTIAL_PATTERN.search(_tool_input_str) if _tool_input_str else None
            if cred_m:
                key_val = ""
                if isinstance(tool_input, dict):
                    for field, val in tool_input.items():
                        if _IPA_02B_MEMORY_KEY_FIELD.search(field):
                            key_val = str(val)
                            break
                if not _IPA_02B_AGENT_SCOPED.search(key_val):
                    findings.append({
                        'sub_check_id':    'IPA-02b',
                        'owasp_signal_id': 'OW-ASI03',
                        'check_label':     'Credential cached in shared memory namespace',
                        'check_score':     85,
                        'category':        'privilege_escalation',
                        'severity':        'high',
                        'matched_text':    cred_m.group(0)[:200],
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['IPA-02b'],
                    })

        # ── IAC-02b: sensitive payload written to a logging tool in plaintext ──
        if 'IAC-02b' in enabled_checks and tool_name and _IAC_02B_LOG_TOOL.search(tool_name):
            for _label, _pat in _IAC_02B_SENSITIVE:
                m = _pat.search(_tool_input_str) if _tool_input_str else None
                if m:
                    findings.append({
                        'sub_check_id':    'IAC-02b',
                        'owasp_signal_id': 'OW-ASI07',
                        'check_label':     'Agent message payload logged in plaintext',
                        'check_score':     65,
                        'category':        'inter_agent',
                        'severity':        'medium',
                        'matched_text':    f'{_label}: {m.group(0)[:80]}',
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['IAC-02b'],
                    })
                    break

        # ── TME-06a: tool-name typosquatting against the declared manifest ──
        # Fires only when the tool isn't in the manifest (EA-01a's job) but is
        # within edit-distance 2 of a manifest entry — the classic typosquat
        # signature. Skips when the manifest is empty (nothing to compare to).
        if 'TME-06a' in enabled_checks and tool_manifest and tool_name and tool_name not in tool_manifest:
            _tn_lower = tool_name.lower()
            _match: str | None = None
            _dist = 0
            for _known in tool_manifest:
                _d = _tme_06a_osa_distance(_tn_lower, _known.lower())
                if 0 < _d <= 2:
                    _match = _known
                    _dist = _d
                    break
            if _match:
                findings.append({
                    'sub_check_id':    'TME-06a',
                    'owasp_signal_id': 'OW-ASI02',
                    'check_label':     'Tool name typosquatting',
                    'check_score':     70,
                    'category':        'excessive_agency',
                    'severity':        'high',
                    'matched_text':    f"'{tool_name}' vs '{_match}' (dist {_dist})",
                    'confidence_tier': 'high',
                    'detection_phase': 'online',
                    'action':          enabled_checks['TME-06a'],
                })

        # ── EA-03a: reads outside declared working directory ──
        # Fires only when working_directory is declared. Regex-matches the
        # tool name against a read-shaped pattern, then checks path-like keys.
        if 'EA-03a' in enabled_checks and working_directory and tool_name and _EA_03A_READ_TOOL.search(tool_name):
            for key in _EA_03A_PATH_KEYS:
                val = str(tool_input.get(key, '')) if isinstance(tool_input, dict) else ''
                if val and not val.startswith(working_directory):
                    findings.append({
                        'sub_check_id':    'EA-03a',
                        'owasp_signal_id': 'OW-LLM06',
                        'check_label':     'Reads outside working directory',
                        'check_score':     65,
                        'category':        'excessive_agency',
                        'severity':        'medium',
                        'matched_text':    f"{tool_name}({key}={val[:120]})",
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['EA-03a'],
                    })
                    break

        # ── TME-03b: production URL from non-prod agent (suppressed when
        # environment == 'production'). Extract URL candidates from tool_input
        # then match against production-shaped URL patterns. ──
        if 'TME-03b' in enabled_checks and environment != 'production':
            url_candidates: list[str] = []
            if isinstance(tool_input, dict):
                for k, v in tool_input.items():
                    if isinstance(v, str) and v.startswith(('http://', 'https://')):
                        url_candidates.append(v)
                    elif isinstance(v, str) and v and k.lower() in _TME_03B_URL_KEYS:
                        url_candidates.append(v)
            if not url_candidates and _tool_input_str:
                url_candidates = re.findall(r"https?://[^\s\"'}{,>]+", _tool_input_str)
            for url in url_candidates:
                if any(p.search(url) for p in _TME_03B_PROD_URL_PATTERNS):
                    findings.append({
                        'sub_check_id':    'TME-03b',
                        'owasp_signal_id': 'OW-ASI02',
                        'check_label':     'Production target from non-prod agent',
                        'check_score':     95,
                        'category':        'excessive_agency',
                        'severity':        'critical',
                        'matched_text':    f"{tool_name} → {url[:160]}",
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['TME-03b'],
                    })
                    break

        # ── IPA-01a: privilege-escalation tool name OR escalation payload. ──
        # Skips tools the customer has declared as privilege-capable via
        # privilege_scope. Fires when either signal hits.
        if 'IPA-01a' in enabled_checks and tool_name and tool_name not in privilege_scope:
            _priv_hit: str | None = None
            for pat in _IPA_01A_PRIV_TOOL_PATTERNS:
                m = pat.search(tool_name)
                if m:
                    _priv_hit = tool_name
                    break
            if _priv_hit is None and _tool_input_str:
                m = _IPA_01A_ESCALATION_PAYLOAD.search(_tool_input_str)
                if m:
                    _priv_hit = f"{tool_name}(payload:{m.group()[:40]})"
            if _priv_hit:
                findings.append({
                    'sub_check_id':    'IPA-01a',
                    'owasp_signal_id': 'OW-ASI03',
                    'check_label':     'Agent requests scope beyond role definition',
                    'check_score':     80,
                    'category':        'privilege_escalation',
                    'severity':        'high',
                    'matched_text':    _priv_hit[:200],
                    'confidence_tier': 'high',
                    'detection_phase': 'online',
                    'action':          enabled_checks['IPA-01a'],
                })

        # ── ASCV-01a: MCP call to an undeclared endpoint URL. ──
        if 'ASCV-01a' in enabled_checks and mcp_endpoints and tool_name and _ASCV_01A_MCP_TOOL.search(tool_name):
            for key in _ASCV_01A_URL_KEYS:
                raw = str(tool_input.get(key, '')) if isinstance(tool_input, dict) else ''
                if raw and not any(raw.startswith(ep) or ep.startswith(raw) for ep in mcp_endpoints):
                    findings.append({
                        'sub_check_id':    'ASCV-01a',
                        'owasp_signal_id': 'OW-ASI04',
                        'check_label':     'MCP server endpoint URL changed',
                        'check_score':     85,
                        'category':        'supply_chain',
                        'severity':        'high',
                        'matched_text':    f"{tool_name} → {raw[:160]}",
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['ASCV-01a'],
                    })
                    break

        # ── ASCV-02b: package install of a package not in the declared SBOM. ──
        # Extracts `pip install X` / `npm install X` etc. from tool_input, then
        # normalises (strip version pins, lowercase) before comparing.
        if 'ASCV-02b' in enabled_checks and sbom_allowlist and _tool_input_str:
            def _norm(name: str) -> str:
                return _ASCV_02B_VERSION_STRIP.sub('', name.strip()).lower()
            _sbom_normed = {_norm(e) for e in sbom_allowlist if isinstance(e, str) and e.strip()}
            for m in _ASCV_02B_PKG_INSTALL.finditer(_tool_input_str):
                raw_pkg = m.group(2).strip()
                pkg = _norm(raw_pkg)
                if pkg and pkg not in _sbom_normed:
                    findings.append({
                        'sub_check_id':    'ASCV-02b',
                        'owasp_signal_id': 'OW-ASI04',
                        'check_label':     'Package not in approved SBOM',
                        'check_score':     88,
                        'category':        'supply_chain',
                        'severity':        'high',
                        'matched_text':    f"install {raw_pkg[:120]}",
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['ASCV-02b'],
                    })
                    break

        # ── IAC-01a: inter-agent delegation without an auth signature field. ──
        # Fires per-event on the first unsigned delegation. Extendable auth
        # field set stays server-side; not customer-configurable via SDK today.
        if 'IAC-01a' in enabled_checks and tool_name and any(p.search(tool_name) for p in _IAC_INTER_AGENT_PATTERNS):
            _has_auth = False
            if isinstance(tool_input, dict):
                _has_auth = any(tool_input.get(f) for f in _IAC_01A_AUTH_FIELDS)
            if not _has_auth:
                findings.append({
                    'sub_check_id':    'IAC-01a',
                    'owasp_signal_id': 'OW-ASI07',
                    'check_label':     'Sub-agent message lacks auth signature',
                    'check_score':     75,
                    'category':        'inter_agent',
                    'severity':        'high',
                    'matched_text':    tool_name[:200],
                    'confidence_tier': 'high',
                    'detection_phase': 'online',
                    'action':          enabled_checks['IAC-01a'],
                })

        # ── IAC-05a: delegation to an agent not in the connected-agents list. ──
        # Runs on every tool_start (tool name isn't filtered — source of truth
        # is any agent-id key in tool_input). Blind when connected_agents empty.
        if 'IAC-05a' in enabled_checks and connected_agents and isinstance(tool_input, dict):
            _declared_lower = {n.lower() for n in connected_agents}
            _target_id = next(
                (str(tool_input[k]) for k in _IAC_05A_AGENT_ID_KEYS if tool_input.get(k)),
                None,
            )
            if _target_id and _target_id.lower() not in _declared_lower:
                findings.append({
                    'sub_check_id':    'IAC-05a',
                    'owasp_signal_id': 'OW-ASI07',
                    'check_label':     'Unknown agent in delegation chain',
                    'check_score':     85,
                    'category':        'inter_agent',
                    'severity':        'critical',
                    'matched_text':    f"{tool_name} → {_target_id[:120]}",
                    'confidence_tier': 'high',
                    'detection_phase': 'online',
                    'action':          enabled_checks['IAC-05a'],
                })

    # ── EA-04a: fires on llm_start when the model isn't in connected_llms. ──
    # Same "blind unless declared" pattern as EA-01a. Compares against both
    # payload.model and payload.llm_model (SDK adapter uses payload.model).
    if event_type == 'llm_start' and 'EA-04a' in enabled_checks and connected_llms:
        _model = str(payload.get('model') or payload.get('llm_model') or '').strip()
        if _model and _model not in connected_llms:
            findings.append({
                'sub_check_id':    'EA-04a',
                'owasp_signal_id': 'OW-LLM06',
                'check_label':     'Undeclared LLM model used',
                'check_score':     70,
                'category':        'excessive_agency',
                'severity':        'medium',
                'matched_text':    _model[:200],
                'confidence_tier': 'deterministic',
                'detection_phase': 'online',
                'action':          enabled_checks['EA-04a'],
            })

    # ── RA-01b: session started outside declared operating hours. ──
    # Fires on session_start only. `operating_hours` schema: {days, from, to}
    # with times in UTC. Missing/malformed values → silent no-op.
    if event_type == 'session_start' and 'RA-01b' in enabled_checks and operating_hours:
        import datetime as _dt
        _started = payload.get('started_at') or body.get('ts')
        if _started:
            try:
                _s = _started if isinstance(_started, _dt.datetime) else _dt.datetime.fromisoformat(
                    str(_started).replace('Z', '+00:00')
                )
                if _s.tzinfo is None:
                    _s = _s.replace(tzinfo=_dt.timezone.utc)
                _day = _RA_01B_DAY_NAMES[_s.weekday()]
                _declared_days = operating_hours.get('days', list(_RA_01B_DAY_NAMES))
                _from = _dt.time.fromisoformat(operating_hours.get('from', '00:00'))
                _to   = _dt.time.fromisoformat(operating_hours.get('to',   '23:59'))
                _now  = _s.time()
                _out_day = _day not in _declared_days
                if _from <= _to:
                    _out_hr = not (_from <= _now <= _to)
                else:
                    _out_hr = not (_now >= _from or _now <= _to)
                if _out_day or _out_hr:
                    _rea = []
                    if _out_day: _rea.append(f"day={_day} not in {_declared_days}")
                    if _out_hr:  _rea.append(f"time={_now.strftime('%H:%M')} UTC outside {operating_hours.get('from')}-{operating_hours.get('to')}")
                    findings.append({
                        'sub_check_id':    'RA-01b',
                        'owasp_signal_id': 'OW-ASI10',
                        'check_label':     'Agent active outside declared operating hours',
                        'check_score':     60,
                        'category':        'rogue_behavior',
                        'severity':        'medium',
                        'matched_text':    '; '.join(_rea)[:200],
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['RA-01b'],
                    })
            except Exception:
                pass  # silent on malformed operating_hours

    # ── llm_start: MCP-01a context/memory injection markers in messages ──
    if event_type == 'llm_start' and 'MCP-01a' in enabled_checks:
        messages = payload.get('messages') or []
        if isinstance(messages, list):
            for msg in messages:
                if not isinstance(msg, dict) or msg.get('role') not in ('user', 'tool'):
                    continue
                content = msg.get('content', '')
                if not isinstance(content, str):
                    try:
                        import json as _json_mod
                        content = _json_mod.dumps(content)
                    except Exception:
                        content = str(content)
                _hit = None
                for pat in _MCP_CONTEXT_INJECTION_PATTERNS:
                    m = pat.search(content)
                    if m:
                        _hit = m.group(0)[:200]
                        break
                if _hit:
                    findings.append({
                        'sub_check_id':    'MCP-01a',
                        'owasp_signal_id': 'OW-ASI06',
                        'check_label':     'Context/memory injection markers in prompt',
                        'check_score':     88,
                        'category':        'context_poisoning',
                        'severity':        'high',
                        'matched_text':    _hit,
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['MCP-01a'],
                    })
                    break

    # ── tool_end signature-only dispatch (AGH-04a, MCP-03a, ASCV-03b) ──
    if event_type == 'tool_end':
        _tool_name = str(payload.get('tool_name', '') or '')
        _tool_input = payload.get('tool_input') or {}
        _tool_output = payload.get('tool_output', '')
        if not isinstance(_tool_output, str):
            try:
                import json as _json_mod
                _tool_output = _json_mod.dumps(_tool_output)
            except Exception:
                _tool_output = str(_tool_output)
        _tool_input_str_e = _tool_input if isinstance(_tool_input, str) else (str(_tool_input) if _tool_input else '')

        # AGH-04a: document-sourced instruction injection
        if 'AGH-04a' in enabled_checks and _tool_name and _AGH_04A_DOC_READ_TOOL.search(_tool_name):
            for pat in _AGH_04A_DOC_INSTRUCTION_PATTERNS:
                m = pat.search(_tool_output)
                if m:
                    findings.append({
                        'sub_check_id':    'AGH-04a',
                        'owasp_signal_id': 'OW-ASI01',
                        'check_label':     'Document-sourced instruction injection',
                        'check_score':     80,
                        'category':        'goal_hijack',
                        'severity':        'high',
                        'matched_text':    m.group(0)[:200],
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['AGH-04a'],
                    })
                    break

        # MCP-03a: poisoned content in memory write (injection keywords first,
        # URL/base64 fallback second — mirrors the source detector).
        if 'MCP-03a' in enabled_checks and _tool_name and _MCP_03A_MEMORY_WRITE_TOOL.search(_tool_name):
            combined = _tool_output + ' ' + _tool_input_str_e
            _hit_text = None
            _hit_conf = 'high'
            for pat in _MCP_CONTEXT_INJECTION_PATTERNS:
                m = pat.search(combined)
                if m:
                    _hit_text = m.group(0)[:200]
                    break
            if _hit_text is None:
                m = _MCP_03A_URL.search(combined) or _MCP_03A_B64.search(combined)
                if m:
                    _hit_text = m.group(0)[:200]
                    _hit_conf = 'medium'
            if _hit_text:
                findings.append({
                    'sub_check_id':    'MCP-03a',
                    'owasp_signal_id': 'OW-ASI06',
                    'check_label':     'Poisoned content in memory write',
                    'check_score':     75,
                    'category':        'context_poisoning',
                    'severity':        'high',
                    'matched_text':    _hit_text,
                    'confidence_tier': _hit_conf,
                    'detection_phase': 'online',
                    'action':          enabled_checks['MCP-03a'],
                })

        # ASCV-03b: third-party fetch tool returns executable content
        if 'ASCV-03b' in enabled_checks and _tool_output:
            _is_external = bool(
                (_tool_name and _ASCV_03B_FETCH_TOOL.search(_tool_name))
                or (_tool_input_str_e and _ASCV_03B_EXTERNAL_URL.search(_tool_input_str_e))
            )
            if _is_external:
                for pat in _ASCV_03B_EXECUTABLE_PATTERNS:
                    m = pat.search(_tool_output)
                    if m:
                        findings.append({
                            'sub_check_id':    'ASCV-03b',
                            'owasp_signal_id': 'OW-ASI04',
                            'check_label':     'Third-party data source returns executable',
                            'check_score':     90,
                            'category':        'supply_chain',
                            'severity':        'critical',
                            'matched_text':    m.group(0)[:200],
                            'confidence_tier': 'high',
                            'detection_phase': 'online',
                            'action':          enabled_checks['ASCV-03b'],
                        })
                        break

    # ── llm_end signature-only dispatch (HAT-02a, HAT-03a) ──
    if event_type == 'llm_end':
        _completion = payload.get('completion', '') if isinstance(payload, dict) else ''
        if _completion and not isinstance(_completion, str):
            try:
                import json as _json_mod
                _completion = _json_mod.dumps(_completion)
            except Exception:
                _completion = str(_completion)

        # HAT-02a: credential request in agent output
        if 'HAT-02a' in enabled_checks and _completion:
            for pat in _HAT_02A_PATTERNS:
                m = pat.search(_completion)
                if m:
                    findings.append({
                        'sub_check_id':    'HAT-02a',
                        'owasp_signal_id': 'OW-ASI09',
                        'check_label':     'Credential request in agent output',
                        'check_score':     85,
                        'category':        'human_trust',
                        'severity':        'critical',
                        'matched_text':    m.group(0)[:200],
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['HAT-02a'],
                    })
                    break

        # HAT-03a: payment / transfer manipulation in agent output
        if 'HAT-03a' in enabled_checks and _completion:
            for pat in _HAT_03A_PATTERNS:
                m = pat.search(_completion)
                if m:
                    findings.append({
                        'sub_check_id':    'HAT-03a',
                        'owasp_signal_id': 'OW-ASI09',
                        'check_label':     'Payment detail manipulation',
                        'check_score':     90,
                        'category':        'human_trust',
                        'severity':        'critical',
                        'matched_text':    m.group(0)[:200],
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['HAT-03a'],
                    })
                    break

    # ── RCE-05a fires on llm_end (backdoor pattern in generated code) ──
    if event_type == 'llm_end' and 'RCE-05a' in enabled_checks:
        completion = payload.get('completion', '') if isinstance(payload, dict) else ''
        if completion and not isinstance(completion, str):
            try:
                import json as _json_mod
                completion = _json_mod.dumps(completion)
            except Exception:
                completion = str(completion)
        if completion:
            # Only scan fenced code blocks — matches the source detector's
            # behaviour and cuts noise from prose that happens to mention
            # "reverse shell" etc.
            for block in _RCE_05A_CODE_FENCE.findall(completion):
                _matched = None
                for pat in _RCE_05A_BACKDOOR_PATTERNS:
                    m = pat.search(block)
                    if m:
                        _matched = m.group(0)[:200]
                        break
                if _matched:
                    findings.append({
                        'sub_check_id':    'RCE-05a',
                        'owasp_signal_id': 'OW-ASI05',
                        'check_label':     'Backdoor pattern in generated code',
                        'check_score':     85,
                        'category':        'code_execution',
                        'severity':        'critical',
                        'matched_text':    _matched,
                        'confidence_tier': 'high',
                        'detection_phase': 'online',
                        'action':          enabled_checks['RCE-05a'],
                    })
                    break

    # ── MCP-04a fires on tool_end retrieval output (tenant leak) ──
    if event_type == 'tool_end' and 'MCP-04a' in enabled_checks:
        _output = payload.get('tool_output')
        if _output is not None:
            _output_str = str(_output) if not isinstance(_output, str) else _output
            _current_tenant = str(tenant_id).lower()
            for m in _MCP_04A_TENANT_FIELD.finditer(_output_str):
                found = m.group(2).lower()
                if found and found != _current_tenant:
                    findings.append({
                        'sub_check_id': 'MCP-04a',
                        'owasp_signal_id': 'OW-ASI06',
                        'check_label': 'Cross-tenant retrieval anomaly',
                        'check_score': 95,
                        'category': 'context_poisoning',
                        'severity': 'critical',
                        'matched_text': f'tenant_id={found}',
                        'confidence_tier': 'deterministic',
                        'detection_phase': 'online',
                        'action': enabled_checks['MCP-04a'],
                    })
                    break

    # ── Reflex — fast-classifier override for routed sub-checks ──
    # If REFLEX_ENDPOINT_URL is configured, replace regex findings for every
    # Reflex-routed sub-check ID with the model's verdict. Runs LAST so it
    # can filter output from every standalone signature handler above
    # (MCP-01a, AGH-04a, MCP-03a etc.), not just detect_online(). If not
    # configured, this block is a no-op and the regex findings stand.
    if settings.reflex_endpoint_url:
        try:
            from security_eval.registry import REFLEX_SUBCHECK_IDS
            from security_eval.models import reflex_classify
            reflex_active = REFLEX_SUBCHECK_IDS & set(enabled_checks.keys())
            if reflex_active:
                findings = [f for f in findings if f['sub_check_id'] not in reflex_active]
                reflex_findings = await reflex_classify(
                    event={'event_type': event_type, 'payload': payload,
                           'session_id': session_id, 'tenant_id': tenant_id},
                    active_ids=reflex_active,
                )
                for f in reflex_findings:
                    findings.append({**f, 'action': enabled_checks[f['sub_check_id']]})
        except Exception:
            logger.exception('reflex dispatch failed')

    # ── Sort findings for a coherent timeline in the SDK ──────────────────
    # Handler chain order (regex → EA-* → MCP-* → Reflex-last) is not
    # meaningful to a viewer; the SDK emits findings in the order we return
    # them, so the story on the dashboard reads however we sort them here.
    # Order by ACTION SEVERITY ASCENDING (least invasive first) so a session
    # with both a sanitize and a block reads as "we cleaned it up, then had
    # to block anyway" rather than "blocked (also sanitized?)". Tiebreak by
    # check_score desc + sub_check_id for stable, deterministic ordering.
    _ACTION_ORDER = {'alert': 0, 'sanitize': 1, 'block_call': 2, 'terminate_session': 3}
    findings.sort(key=lambda f: (
        _ACTION_ORDER.get(f.get('action', 'alert'), 0),
        -int(f.get('check_score', 0) or 0),
        str(f.get('sub_check_id', '')),
    ))

    return JSONResponse({'findings': findings})
