"""Seed the signal_registry table with all OW-LLM / OW-ASI sub-checks.

Run after migration 013_v3_scoring.sql:
    python scripts/seed_signal_registry.py

v3: adds new sub-checks, confidence_tier column, and marks
    DMP-01a/c and VEW-01b/02a as pre-runtime excluded.

Expected row count: >= 156 sub-checks across 20 parent signals.

Row format:
    (owasp_signal_id, sub_check_id, check_label, owasp_category,
     owasp_number, detection_phase, check_score, severity,
     confidence_tier, excluded, exclusion_reason)
"""
import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─────────────────────────────────────────────────────────────────────────────
# Full sub-check registry — 11 columns per row
# ─────────────────────────────────────────────────────────────────────────────
REGISTRY: list[tuple] = [
    # ── OW-LLM01 Prompt Injection ────────────────────────────────────────────
    ("OW-LLM01","PI-01a","Role-override phrase match",                   "LLM",1,"online",         85,"high",     "high",          False,None),
    ("OW-LLM01","PI-01b","Delimiter smuggling",                          "LLM",1,"online",         90,"critical", "deterministic", False,None),
    ("OW-LLM01","PI-01c","Encoded / obfuscated payload",                 "LLM",1,"online",         75,"high",     "high",          False,None),
    ("OW-LLM01","PI-02a","Web-fetched content with injection pattern",   "LLM",1,"online",         70,"high",     "high",          False,None),
    ("OW-LLM01","PI-02b","Retrieved doc causes goal-shift",              "LLM",1,"post_session",   95,"critical", "high",          False,None),
    ("OW-LLM01","PI-02c","File / attachment payload injection",          "LLM",1,"online",         80,"high",     "high",          False,None),
    ("OW-LLM01","PI-03a","API response carries directives",              "LLM",1,"online",         88,"high",     "high",          False,None),
    ("OW-LLM01","PI-03b","DB query result embeds prompt fragment",       "LLM",1,"online",         82,"high",     "high",          False,None),
    ("OW-LLM01","PI-04a","Goal vector drift across >= 3 turns",          "LLM",1,"post_session",   65,"medium",   "high",          False,None),
    ("OW-LLM01","PI-04b","Jailbreak built incrementally",                "LLM",1,"post_session",   92,"critical", "high",          False,None),
    ("OW-LLM01","PI-05a","Code injection pattern in prompt",             "LLM",1,"both",           80,"high",     "high",          False,None),
    ("OW-LLM01","PI-06a","Payload splitting across messages",            "LLM",1,"post_session",   88,"high",     "high",          False,None),
    ("OW-LLM01","PI-07a","Multimodal content with injection signal",     "LLM",1,"both",           60,"medium",   "low",           False,None),
    ("OW-LLM01","PI-08a","Adversarial suffix (high-entropy tail)",       "LLM",1,"both",           75,"high",     "medium",        False,None),
    ("OW-LLM01","PI-09a","Obfuscated/encoded injection",                 "LLM",1,"both",           82,"high",     "high",          False,None),

    # ── OW-LLM02 Sensitive Information Disclosure ────────────────────────────
    ("OW-LLM02","SID-01a","API key / token pattern in output",           "LLM",2,"online",         95,"critical", "deterministic", False,None),
    ("OW-LLM02","SID-01b","Secret in tool call params",                  "LLM",2,"online",         95,"critical", "high",          False,None),
    ("OW-LLM02","SID-01c","JWT / session token in agent message",        "LLM",2,"online",         90,"critical", "deterministic", False,None),
    ("OW-LLM02","SID-02a","Name + email + phone co-occurrence",          "LLM",2,"online",         75,"high",     "deterministic", False,None),
    ("OW-LLM02","SID-02b","Financial identifiers in output",             "LLM",2,"online",         90,"critical", "deterministic", False,None),
    ("OW-LLM02","SID-02c","Health / biometric data in output",           "LLM",2,"online",         95,"critical", "deterministic", False,None),
    ("OW-LLM02","SID-03a","Cross-user context bleed",                    "LLM",2,"cross_session",  95,"critical", "high",          False,None),
    ("OW-LLM02","SID-03b","Error stack trace forwarded to user",         "LLM",2,"post_session",   60,"medium",   "high",          False,None),
    ("OW-LLM02","SID-04a","Output references data from diff session",    "LLM",2,"post_session",   92,"critical", "high",          False,None),
    ("OW-LLM02","SID-04b","Shared memory returns cross-tenant record",   "LLM",2,"post_session",   92,"critical", "high",          False,None),

    # ── OW-LLM03 Supply Chain (EXCLUDED) ────────────────────────────────────
    ("OW-LLM03","SC-EXCL","All LLM03 sub-checks excluded",               "LLM",3,"excluded",        0,"low",      "high",          True, "Not observable from Kafka event stream or LangGraph telemetry"),

    # ── OW-LLM04 Data & Model Poisoning ─────────────────────────────────────
    ("OW-LLM04","DMP-01a","Vector store record count anomaly",            "LLM",4,"excluded",       60,"medium",   "medium",        True, "Data/model poisoning — pre-runtime; requires offline pipeline audit"),
    ("OW-LLM04","DMP-01b","Retrieval cosine distance outlier",            "LLM",4,"post_session",   70,"high",     "high",          True, "Requires embedding model to log cosine distance in tool_end"),
    ("OW-LLM04","DMP-01c","Ingested chunk contains instruction text",     "LLM",4,"excluded",       85,"high",     "high",          True, "RAG data integrity — pre-runtime; requires offline data validation"),
    ("OW-LLM04","DMP-02", "Pre-training / weight poisoning",              "LLM",4,"excluded",        0,"low",      "high",          True, "Not detectable at inference time via event stream"),

    # ── OW-LLM05 Improper Output Handling ───────────────────────────────────
    ("OW-LLM05","IOH-01a","Shell command pattern in output",              "LLM",5,"online",         90,"critical", "deterministic", False,None),
    ("OW-LLM05","IOH-01b","HTML/JS in output without escaping",           "LLM",5,"online",         85,"high",     "deterministic", False,None),
    ("OW-LLM05","IOH-01c","SQL fragment in output passed to DB",          "LLM",5,"online",         90,"critical", "deterministic", False,None),
    ("OW-LLM05","IOH-02a","Raw LLM output as tool param",                 "LLM",5,"online",         70,"high",     "medium",        False,None),
    ("OW-LLM05","IOH-02b","No schema validation on tool input",           "LLM",5,"online",         55,"medium",   "high",          False,None),
    ("OW-LLM05","IOH-03a","Email template injection in output",           "LLM",5,"both",           80,"high",     "high",          False,None),
    ("OW-LLM05","IOH-03b","Sub-agent receives broken structured output",  "LLM",5,"post_session",   65,"medium",   "high",          False,None),
    ("OW-LLM05","IOH-04a","Insecure code pattern in generated output",    "LLM",5,"post_session",   70,"high",     "medium",        False,None),

    # ── OW-LLM06 Excessive Agency ────────────────────────────────────────────
    ("OW-LLM06","EA-01a","Tool not in approved manifest invoked",         "LLM",6,"post_session",   80,"high",     "high",          False,None),
    ("OW-LLM06","EA-01b","Agent requests elevated permissions",           "LLM",6,"post_session",   90,"critical", "high",          False,None),
    ("OW-LLM06","EA-01c","Data written outside designated namespace",     "LLM",6,"post_session",   75,"high",     "high",          False,None),
    ("OW-LLM06","EA-02a","Irreversible action without confirm gate",      "LLM",6,"post_session",   85,"high",     "high",          False,None),
    ("OW-LLM06","EA-02b","Sub-agents spawned > fan-out limit",            "LLM",6,"post_session",   70,"high",     "high",          False,None),
    ("OW-LLM06","EA-02c","Agent self-modifies system prompt",             "LLM",6,"post_session",   98,"critical", "high",          False,None),
    ("OW-LLM06","EA-03a","Reads outside working directory",               "LLM",6,"post_session",   65,"medium",   "high",          False,None),
    ("OW-LLM06","EA-03b","Network call to host not in allowlist",         "LLM",6,"post_session",   75,"high",     "high",          False,None),

    # ── OW-LLM07 System Prompt Leakage ──────────────────────────────────────
    ("OW-LLM07","SPL-01a","Verbatim system prompt segment in output",     "LLM",7,"online",         85,"high",     "medium",        False,None),
    ("OW-LLM07","SPL-01b","Agent confirms system prompt on probe",        "LLM",7,"online",         70,"high",     "medium",        False,None),
    ("OW-LLM07","SPL-02a","Reveals role name / persona name",             "LLM",7,"post_session",   50,"medium",   "medium",        False,None),
    ("OW-LLM07","SPL-02b","Error message exposes instruction variables",  "LLM",7,"post_session",   60,"medium",   "medium",        False,None),
    ("OW-LLM07","SPL-03a","System prompt in unprotected log",             "LLM",7,"post_session",   80,"high",     "high",          False,None),
    ("OW-LLM07","SPL-03b","System prompt forwarded in inter-agent msg",   "LLM",7,"post_session",   88,"high",     "medium",        False,None),

    # ── OW-LLM08 Vector & Embedding Weakness ────────────────────────────────
    ("OW-LLM08","VEW-01a","Query retrieves semantically distant doc",     "LLM",8,"post_session",   60,"medium",   "high",          True, "Requires embedding distance logged in tool_end payload"),
    ("OW-LLM08","VEW-01b","Repeated near-duplicate RAG queries",          "LLM",8,"excluded",       75,"high",     "medium",        True, "Vector drift — pre-runtime; requires offline vector DB monitoring"),
    ("OW-LLM08","VEW-02a","Unauthorised write to vector namespace",       "LLM",8,"excluded",       92,"critical", "high",          True, "Poisoned retrieval — pre-runtime; requires offline retrieval audit"),
    ("OW-LLM08","VEW-02b","Record count or centroid drift anomaly",       "LLM",8,"post_session",   70,"high",     "high",          False,None),
    ("OW-LLM08","VEW-03a","Embedding model at query != ingest model",     "LLM",8,"post_session",   88,"high",     "high",          True, "Requires tool_end payload to carry embedding_model field"),

    # ── OW-LLM09 Misinformation ──────────────────────────────────────────────
    ("OW-LLM09","MIS-01a","Cited URL returns 404 / non-matching",         "LLM",9,"post_session",   65,"medium",   "high",          False,None),
    ("OW-LLM09","MIS-01b","Claim attributed to source not in tool output","LLM",9,"post_session",   70,"high",     "high",          False,None),
    ("OW-LLM09","MIS-02a","Output contradicts own tool result",           "LLM",9,"post_session",   75,"high",     "high",          False,None),
    ("OW-LLM09","MIS-03a","High-stakes action without interrupt gate",    "LLM",9,"post_session",   65,"medium",   "high",          False,None),
    ("OW-LLM09","SAG-02a","Hallucinated package reference",               "LLM",9,"post_session",   65,"medium",   "low",           False,None),
    ("OW-LLM09","SAG-03a","High-stakes domain without grounding",         "LLM",9,"post_session",   60,"medium",   "medium",        False,None),

    # ── OW-LLM10 Unbounded Consumption ──────────────────────────────────────
    ("OW-LLM10","UBC-01a","Single session token count > 4σ baseline",     "LLM",10,"post_session",  55,"medium",   "medium",        False,None),
    ("OW-LLM10","UBC-01b","Context window stuffing attack",               "LLM",10,"post_session",  70,"high",     "high",          False,None),
    ("OW-LLM10","UBC-02a","Input size anomaly",                           "LLM",10,"post_session",  50,"medium",   "medium",        False,None),
    ("OW-LLM10","UBC-02b","Session token cost > budget cap",              "LLM",10,"post_session",  80,"high",     "high",          False,None),
    ("OW-LLM10","UBC-03a","Request rate spike per user",                  "LLM",10,"cross_session", 55,"medium",   "medium",        False,None),
    ("OW-LLM10","UBC-04a","Cohort probe pattern detected",                "LLM",10,"post_session",  70,"high",     "high",          False,None),
    ("OW-LLM10","UBC-05a","Cost spike (Denial of Wallet)",                "LLM",10,"cross_session", 60,"high",     "medium",        False,None),

    # ── OW-ASI01 Agent Goal Hijack ───────────────────────────────────────────
    ("OW-ASI01","AGH-01a","Semantic drift from initial instruction",       "ASI",1,"post_session",   80,"high",     "high",          False,None),
    ("OW-ASI01","AGH-01b","Agent states a different goal explicitly",      "ASI",1,"post_session",   92,"critical", "high",          False,None),
    ("OW-ASI01","AGH-02a","Zero-click goal hijack",                        "ASI",1,"post_session",   85,"high",     "high",          False,None),
    ("OW-ASI01","AGH-02b","Webhook / scheduled trigger with tampered payload","ASI",1,"post_session",88,"high",    "high",          False,None),
    ("OW-ASI01","AGH-03a","Goal drift across turns",                       "ASI",1,"post_session",   70,"medium",   "medium",        False,None),
    ("OW-ASI01","AGH-03b","Sub-agent goal not in parent decomposition",    "ASI",1,"post_session",   70,"high",     "high",          False,None),
    ("OW-ASI01","AGH-04a","Document-sourced instruction injection",        "ASI",1,"both",           80,"high",     "high",          False,None),

    # ── OW-ASI02 Tool Misuse ────────────────────────────────────────────────
    ("OW-ASI02","TME-01a","Tool called with out-of-schema params",         "ASI",2,"online",         65,"medium",   "high",          False,None),
    ("OW-ASI02","TME-01b","Tool call frequency spike (> 3x baseline)",     "ASI",2,"online",         70,"high",     "high",          False,None),
    ("OW-ASI02","TME-01c","Tool call sequence deviates from workflow",     "ASI",2,"online",         80,"high",     "high",          False,None),
    ("OW-ASI02","TME-02a","Tool descriptor integrity anomaly",             "ASI",2,"post_session",   75,"high",     "high",          False,None),
    ("OW-ASI02","TME-02b","Tool chaining to bypass restrictions",          "ASI",2,"post_session",   90,"critical", "high",          False,None),
    ("OW-ASI02","TME-03a","Irreversible action without confirm",           "ASI",2,"online",         92,"critical", "high",          False,None),
    ("OW-ASI02","TME-03b","Production target from non-prod agent",         "ASI",2,"online",         95,"critical", "deterministic", False,None),
    ("OW-ASI02","TME-04a","Over-privileged tool invocation",               "ASI",2,"post_session",   70,"high",     "high",          False,None),
    ("OW-ASI02","TME-05a","Cross-tool exfiltration chain",                 "ASI",2,"post_session",   90,"critical", "high",          False,None),
    ("OW-ASI02","TME-06a","Tool name typosquatting",                       "ASI",2,"post_session",   70,"high",     "medium",        False,None),
    ("OW-ASI02","TME-07a","Admin tool chain to external endpoint",         "ASI",2,"post_session",   88,"critical", "high",          False,None),
    ("OW-ASI02","TME-08a","Repetitive benign tool misuse",                 "ASI",2,"post_session",   65,"medium",   "medium",        False,None),

    # ── OW-ASI03 Identity & Privilege ───────────────────────────────────────
    ("OW-ASI03","IPA-01a","Agent requests scope beyond role definition",   "ASI",3,"post_session",   80,"high",     "high",          False,None),
    ("OW-ASI03","IPA-01b","Agent uses credentials of another agent",       "ASI",3,"post_session",   95,"critical", "high",          False,None),
    ("OW-ASI03","IPA-01c","Agent impersonates human identity",             "ASI",3,"post_session",   95,"critical", "high",          False,None),
    ("OW-ASI03","IPA-02a","Delegation with full permissions",              "ASI",3,"post_session",   80,"high",     "high",          False,None),
    ("OW-ASI03","IPA-02b","Credential cached in shared memory namespace",  "ASI",3,"post_session",   85,"high",     "high",          False,None),
    ("OW-ASI03","IPA-03a","Cached credential reuse",                       "ASI",3,"post_session",   85,"critical", "high",          False,None),
    ("OW-ASI03","IPA-03b","Agent presents as different agent",             "ASI",3,"post_session",   90,"critical", "high",          False,None),
    ("OW-ASI03","IPA-04a","Stale authorization in long session",           "ASI",3,"post_session",   65,"medium",   "medium",        False,None),
    ("OW-ASI03","IPA-05a","Identity sharing across users",                 "ASI",3,"cross_session",  75,"high",     "high",          False,None),

    # ── OW-ASI04 Agentic Supply Chain ────────────────────────────────────────
    ("OW-ASI04","ASCV-01a","MCP server endpoint URL changed",              "ASI",4,"post_session",   85,"high",     "medium",        False,None),
    ("OW-ASI04","ASCV-01b","MCP server TLS cert anomaly",                  "ASI",4,"post_session",   90,"critical", "high",          False,None),
    ("OW-ASI04","ASCV-01c","MCP tool schema changed without bump",         "ASI",4,"post_session",   70,"high",     "high",          False,None),
    ("OW-ASI04","ASCV-02a","MCP descriptor poisoning",                     "ASI",4,"both",           80,"high",     "high",          False,None),
    ("OW-ASI04","ASCV-02b","Package not in approved SBOM",                 "ASI",4,"post_session",   88,"high",     "high",          False,None),
    ("OW-ASI04","ASCV-03a","MCP server impersonation",                     "ASI",4,"post_session",   75,"high",     "medium",        False,None),
    ("OW-ASI04","ASCV-03b","Third-party data source returns executable",   "ASI",4,"post_session",   90,"critical", "high",          False,None),
    ("OW-ASI04","ASCV-04a","Unknown package install in tool execution",    "ASI",4,"both",           85,"critical", "deterministic", False,None),
    ("OW-ASI04","ASCV-05a","Agent card descriptor anomaly",                "ASI",4,"post_session",   70,"high",     "skeletal",      False,None),

    # ── OW-ASI05 RCE ────────────────────────────────────────────────────────
    ("OW-ASI05","RCE-01a","Agent writes & runs unapproved script",         "ASI",5,"online",         85,"high",     "high",          False,None),
    ("OW-ASI05","RCE-01b","eval() / exec() with agent-generated string",   "ASI",5,"online",         95,"critical", "deterministic", False,None),
    ("OW-ASI05","RCE-01c","Agent code creates child processes",            "ASI",5,"online",         80,"high",     "high",          False,None),
    ("OW-ASI05","RCE-02a","Shell metacharacters in tool params",           "ASI",5,"online",         92,"critical", "high",          False,None),
    ("OW-ASI05","RCE-02b","OS command via string interpolation",           "ASI",5,"online",         90,"critical", "high",          False,None),
    ("OW-ASI05","RCE-03a","Agent mounts host filesystem paths",            "ASI",5,"online",         98,"critical", "deterministic", False,None),
    ("OW-ASI05","RCE-03b","Agent calls Docker/K8s API",                    "ASI",5,"online",         98,"critical", "deterministic", False,None),
    ("OW-ASI05","RCE-04a","Execution loop (runaway)",                      "ASI",5,"post_session",   80,"high",     "high",          False,None),
    ("OW-ASI05","RCE-05a","Backdoor pattern in generated code",            "ASI",5,"post_session",   85,"critical", "high",          False,None),
    ("OW-ASI05","RCE-06a","Unsafe deserialization in tool args",           "ASI",5,"both",           90,"critical", "deterministic", False,None),
    ("OW-ASI05","RCE-07a","Multi-tool chain exploitation",                 "ASI",5,"post_session",   92,"critical", "high",          False,None),
    ("OW-ASI05","RCE-08a","Lockfile manipulation in tool execution",       "ASI",5,"both",           75,"high",     "deterministic", False,None),

    # ── OW-ASI06 Memory & Context Poisoning ─────────────────────────────────
    ("OW-ASI06","MCP-01a","Injected content alters current plan",          "ASI",6,"online",         88,"high",     "high",          False,None),
    ("OW-ASI06","MCP-01b","Conversation history hash mismatch",            "ASI",6,"online",         85,"high",     "high",          False,None),
    ("OW-ASI06","MCP-02a","Cross-session escalation pattern",              "ASI",6,"cross_session",  80,"high",     "high",          False,None),
    ("OW-ASI06","MCP-02b","Memory record not written by this session",     "ASI",6,"post_session",   80,"high",     "high",          False,None),
    ("OW-ASI06","MCP-02c","Memory record contains instruction text",       "ASI",6,"post_session",   88,"high",     "high",          False,None),
    ("OW-ASI06","MCP-03a","Poisoned content in memory write",              "ASI",6,"both",           75,"high",     "high",          False,None),
    ("OW-ASI06","MCP-03b","Shared scratchpad has stale/adversarial data",  "ASI",6,"post_session",   75,"high",     "high",          False,None),
    ("OW-ASI06","MCP-04a","Cross-tenant retrieval anomaly",                "ASI",6,"cross_session",  95,"critical", "deterministic", False,None),
    ("OW-ASI06","MCP-05a","Memory write after injection signal",           "ASI",6,"post_session",   88,"critical", "high",          False,None),

    # ── OW-ASI07 Insecure Inter-Agent Communication ──────────────────────────
    ("OW-ASI07","IAC-01a","Sub-agent message lacks auth signature",        "ASI",7,"post_session",   75,"high",     "high",          False,None),
    ("OW-ASI07","IAC-01b","Injected directive in inter-agent message",     "ASI",7,"post_session",   88,"high",     "high",          False,None),
    ("OW-ASI07","IAC-02a","Unencrypted inter-agent communication",         "ASI",7,"post_session",   80,"high",     "deterministic", False,None),
    ("OW-ASI07","IAC-02b","Agent message payload logged in plaintext",     "ASI",7,"post_session",   65,"medium",   "high",          False,None),
    ("OW-ASI07","IAC-03a","Replay attack (duplicate request ID)",          "ASI",7,"post_session",   75,"high",     "high",          False,None),
    ("OW-ASI07","IAC-04a","MCP-routed inter-agent data anomaly",           "ASI",7,"post_session",   80,"high",     "medium",        False,None),
    ("OW-ASI07","IAC-05a","Unknown agent in delegation chain",             "ASI",7,"post_session",   85,"critical", "high",          False,None),
    ("OW-ASI07","IAC-06a","Semantics split-brain",                         "ASI",7,"post_session",   65,"medium",   "skeletal",      False,None),

    # ── OW-ASI08 Cascading Failures ──────────────────────────────────────────
    ("OW-ASI08","CF-01a","Tool retry count exceeds threshold",             "ASI",8,"post_session",   70,"high",     "high",          False,None),
    ("OW-ASI08","CF-01b","Graph error → restart loop detected",            "ASI",8,"post_session",   75,"high",     "high",          False,None),
    ("OW-ASI08","CF-02a","Multi-node error propagation",                   "ASI",8,"post_session",   75,"high",     "high",          False,None),
    ("OW-ASI08","CF-02b","Error message causes secondary injection",       "ASI",8,"post_session",   85,"high",     "high",          False,None),
    ("OW-ASI08","CF-03a","Auto-remediation feedback loop",                 "ASI",8,"post_session",   70,"high",     "high",          False,None),
    ("OW-ASI08","CF-04a","Hallucination propagation in defense agents",    "ASI",8,"post_session",   65,"medium",   "skeletal",      False,None),

    # ── OW-ASI09 Human-Agent Trust Exploitation ──────────────────────────────
    ("OW-ASI09","HAT-01a","Agent mimics human communication style",        "ASI",9,"post_session",   65,"medium",   "high",          False,None),
    ("OW-ASI09","HAT-01b","Agent suppresses uncertainty markers",          "ASI",9,"post_session",   60,"medium",   "high",          False,None),
    ("OW-ASI09","HAT-02a","Credential request in agent output",            "ASI",9,"post_session",   85,"critical", "high",          False,None),
    ("OW-ASI09","HAT-02b","Agent overrides user safety concern",           "ASI",9,"post_session",   80,"high",     "high",          False,None),
    ("OW-ASI09","HAT-03a","Payment detail manipulation",                   "ASI",9,"post_session",   90,"critical", "high",          False,None),
    ("OW-ASI09","HAT-04a","Fabricated rationale before destructive act",   "ASI",9,"post_session",   80,"high",     "medium",        False,None),
    ("OW-ASI09","HAT-05a","Side-effect on preview/read-only action",       "ASI",9,"post_session",   75,"high",     "medium",        False,None),

    # ── OW-ASI10 Rogue Agents ───────────────────────────────────────────────
    ("OW-ASI10","RA-01a","Tool usage pattern deviates from agent profile", "ASI",10,"post_session",  78,"high",     "medium",        False,None),
    ("OW-ASI10","RA-01b","Agent active outside declared operating hours",  "ASI",10,"post_session",  60,"medium",   "high",          False,None),
    ("OW-ASI10","RA-02a","Persistent exfiltration across sessions",        "ASI",10,"cross_session", 90,"critical", "high",          False,None),
    ("OW-ASI10","RA-02b","Agent resists shutdown / interruption",          "ASI",10,"post_session",  95,"critical", "high",          False,None),
    ("OW-ASI10","RA-03a","Self-approval in workflow",                      "ASI",10,"post_session",  85,"critical", "high",          False,None),
    ("OW-ASI10","RA-04a","Self-replication via provisioning tools",        "ASI",10,"both",          95,"critical", "deterministic", False,None),
    ("OW-ASI10","RA-05a","Destructive optimization (reward hacking)",      "ASI",10,"post_session",  85,"critical", "high",          False,None),
]


async def seed():
    import asyncpg
    from core.config import settings
    pool = await asyncpg.create_pool(settings.postgres_dsn)
    async with pool.acquire() as conn:
        inserted = 0
        updated = 0
        for row in REGISTRY:
            (owasp_signal_id, sub_check_id, check_label, owasp_category,
             owasp_number, detection_phase, check_score, severity,
             confidence_tier, excluded, exclusion_reason) = row
            result = await conn.execute(
                """
                INSERT INTO signal_registry
                    (owasp_signal_id, sub_check_id, check_label, owasp_category,
                     owasp_number, detection_phase, check_score, severity,
                     confidence_tier, excluded, exclusion_reason)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
                ON CONFLICT (owasp_signal_id, sub_check_id) DO UPDATE SET
                    check_label      = EXCLUDED.check_label,
                    detection_phase  = EXCLUDED.detection_phase,
                    check_score      = EXCLUDED.check_score,
                    severity         = EXCLUDED.severity,
                    confidence_tier  = EXCLUDED.confidence_tier,
                    excluded         = EXCLUDED.excluded,
                    exclusion_reason = EXCLUDED.exclusion_reason
                """,
                owasp_signal_id, sub_check_id, check_label, owasp_category,
                owasp_number, detection_phase, check_score, severity,
                confidence_tier, excluded, exclusion_reason,
            )
            if result == "INSERT 0 1":
                inserted += 1
            else:
                updated += 1

        total = await conn.fetchval("SELECT COUNT(*) FROM signal_registry")

    await pool.close()
    print(f"Seed complete: {inserted} inserted, {updated} updated. "
          f"Total rows in signal_registry: {total}")
    if total < 156:
        print(f"WARNING: expected >= 156 rows, got {total}")
    else:
        print("OK: >= 156 rows present")


if __name__ == "__main__":
    asyncio.run(seed())
