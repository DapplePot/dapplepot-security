"""Seed the signal_registry table with all OW-LLM / OW-ASI sub-checks.

Run after migration 012_signal_registry.sql:
    python scripts/seed_signal_registry.py

Expected row count: >= 80 sub-checks across 20 parent signals.
"""
import asyncio
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ─────────────────────────────────────────────────────────────────────────────
# Full sub-check registry (owasp_signal_id, sub_check_id, label, category,
#   number, phase, score, severity, excluded, exclusion_reason)
# ─────────────────────────────────────────────────────────────────────────────
REGISTRY: list[tuple] = [
    # ── OW-LLM01 Prompt Injection ────────────────────────────────────────────
    ("OW-LLM01","PI-01a","Role-override phrase match",                   "LLM",1,"online",          85,"high",     False,None),
    ("OW-LLM01","PI-01b","Delimiter smuggling",                          "LLM",1,"online",          90,"critical", False,None),
    ("OW-LLM01","PI-01c","Encoded / obfuscated payload",                 "LLM",1,"online",          75,"high",     False,None),
    ("OW-LLM01","PI-02a","Web-fetched content with injection pattern",   "LLM",1,"online",          70,"high",     False,None),
    ("OW-LLM01","PI-02b","Retrieved doc causes goal-shift",              "LLM",1,"post_session",    95,"critical", False,None),
    ("OW-LLM01","PI-02c","File / attachment payload injection",          "LLM",1,"online",          80,"high",     False,None),
    ("OW-LLM01","PI-03a","API response carries directives",              "LLM",1,"online",          88,"high",     False,None),
    ("OW-LLM01","PI-03b","DB query result embeds prompt fragment",       "LLM",1,"online",          82,"high",     False,None),
    ("OW-LLM01","PI-04a","Goal vector drift across >= 3 turns",          "LLM",1,"post_session",    65,"medium",   False,None),
    ("OW-LLM01","PI-04b","Jailbreak built incrementally",               "LLM",1,"post_session",    92,"critical", False,None),
    # ── OW-LLM02 Sensitive Information Disclosure ────────────────────────────
    ("OW-LLM02","SID-01a","API key / token pattern in output",           "LLM",2,"online",          95,"critical", False,None),
    ("OW-LLM02","SID-01b","Secret in tool call params",                  "LLM",2,"online",          95,"critical", False,None),
    ("OW-LLM02","SID-01c","JWT / session token in agent message",        "LLM",2,"online",          90,"critical", False,None),
    ("OW-LLM02","SID-02a","Name + email + phone co-occurrence",          "LLM",2,"online",          75,"high",     False,None),
    ("OW-LLM02","SID-02b","Financial identifiers in output",             "LLM",2,"online",          90,"critical", False,None),
    ("OW-LLM02","SID-02c","Health / biometric data in output",           "LLM",2,"online",          95,"critical", False,None),
    ("OW-LLM02","SID-03a","File paths / DB hostnames / internal IPs",    "LLM",2,"post_session",    55,"medium",   False,None),
    ("OW-LLM02","SID-03b","Error stack trace forwarded to user",         "LLM",2,"post_session",    60,"medium",   False,None),
    ("OW-LLM02","SID-04a","Output references data from diff session",    "LLM",2,"post_session",    92,"critical", False,None),
    ("OW-LLM02","SID-04b","Shared memory returns cross-tenant record",   "LLM",2,"post_session",    92,"critical", False,None),
    # ── OW-LLM03 Supply Chain (EXCLUDED) ────────────────────────────────────
    ("OW-LLM03","SC-EXCL","All LLM03 sub-checks excluded",              "LLM",3,"excluded",         0,"low",      True,"Not observable from Kafka event stream or LangGraph telemetry"),
    # ── OW-LLM04 Data & Model Poisoning ─────────────────────────────────────
    ("OW-LLM04","DMP-01a","Vector store record count anomaly",           "LLM",4,"post_session",    60,"medium",   False,None),
    ("OW-LLM04","DMP-01b","Retrieval cosine distance outlier",           "LLM",4,"post_session",    70,"high",     True,"Requires embedding model to log cosine distance in tool_end"),
    ("OW-LLM04","DMP-01c","Ingested chunk contains instruction text",    "LLM",4,"post_session",    85,"high",     False,None),
    ("OW-LLM04","DMP-02", "Pre-training / weight poisoning",            "LLM",4,"excluded",         0,"low",      True,"Not detectable at inference time via event stream"),
    # ── OW-LLM05 Improper Output Handling ───────────────────────────────────
    ("OW-LLM05","IOH-01a","Shell command pattern in output",             "LLM",5,"online",          90,"critical", False,None),
    ("OW-LLM05","IOH-01b","HTML/JS in output without escaping",          "LLM",5,"online",          85,"high",     False,None),
    ("OW-LLM05","IOH-01c","SQL fragment in output passed to DB",         "LLM",5,"online",          90,"critical", False,None),
    ("OW-LLM05","IOH-02a","Raw LLM output as tool param",               "LLM",5,"online",          70,"high",     False,None),
    ("OW-LLM05","IOH-02b","No schema validation on tool input",          "LLM",5,"online",          55,"medium",   False,None),
    ("OW-LLM05","IOH-03a","Output to sub-agent without sanitisation",    "LLM",5,"post_session",    80,"high",     False,None),
    ("OW-LLM05","IOH-03b","Sub-agent receives broken structured output", "LLM",5,"post_session",    65,"medium",   False,None),
    # ── OW-LLM06 Excessive Agency ────────────────────────────────────────────
    ("OW-LLM06","EA-01a","Tool not in approved manifest invoked",        "LLM",6,"post_session",    80,"high",     False,None),
    ("OW-LLM06","EA-01b","Agent requests elevated permissions",          "LLM",6,"post_session",    90,"critical", False,None),
    ("OW-LLM06","EA-01c","Data written outside designated namespace",    "LLM",6,"post_session",    75,"high",     False,None),
    ("OW-LLM06","EA-02a","Irreversible action without confirm gate",     "LLM",6,"post_session",    85,"high",     False,None),
    ("OW-LLM06","EA-02b","Sub-agents spawned > fan-out limit",           "LLM",6,"post_session",    70,"high",     False,None),
    ("OW-LLM06","EA-02c","Agent self-modifies system prompt",            "LLM",6,"post_session",    98,"critical", False,None),
    ("OW-LLM06","EA-03a","Reads outside working directory",              "LLM",6,"post_session",    65,"medium",   False,None),
    ("OW-LLM06","EA-03b","Network call to host not in allowlist",        "LLM",6,"post_session",    75,"high",     False,None),
    # ── OW-LLM07 System Prompt Leakage ──────────────────────────────────────
    ("OW-LLM07","SPL-01a","Verbatim system prompt segment in output",    "LLM",7,"online",          85,"high",     False,None),
    ("OW-LLM07","SPL-01b","Agent confirms system prompt on probe",       "LLM",7,"online",          70,"high",     False,None),
    ("OW-LLM07","SPL-02a","Reveals role name / persona name",            "LLM",7,"post_session",    50,"medium",   False,None),
    ("OW-LLM07","SPL-02b","Error message exposes instruction variables", "LLM",7,"post_session",    60,"medium",   False,None),
    ("OW-LLM07","SPL-03a","System prompt in unprotected log",            "LLM",7,"post_session",    80,"high",     False,None),
    ("OW-LLM07","SPL-03b","System prompt forwarded in inter-agent msg",  "LLM",7,"post_session",    88,"high",     False,None),
    # ── OW-LLM08 Vector & Embedding Weakness ────────────────────────────────
    ("OW-LLM08","VEW-01a","Query retrieves semantically distant doc",    "LLM",8,"post_session",    60,"medium",   True,"Requires embedding distance logged in tool_end payload"),
    ("OW-LLM08","VEW-01b","Repeated near-duplicate RAG queries",         "LLM",8,"post_session",    75,"high",     False,None),
    ("OW-LLM08","VEW-02a","Unauthorised write to vector namespace",      "LLM",8,"post_session",    92,"critical", False,None),
    ("OW-LLM08","VEW-02b","Record count or centroid drift anomaly",      "LLM",8,"post_session",    70,"high",     False,None),
    ("OW-LLM08","VEW-03a","Embedding model at query != ingest model",    "LLM",8,"post_session",    88,"high",     True,"Requires tool_end payload to carry embedding_model field"),
    # ── OW-LLM09 Misinformation ──────────────────────────────────────────────
    ("OW-LLM09","MIS-01a","Cited URL returns 404 / non-matching",        "LLM",9,"post_session",    65,"medium",   False,None),
    ("OW-LLM09","MIS-01b","Claim attributed to source not in tool output","LLM",9,"post_session",   70,"high",     False,None),
    ("OW-LLM09","MIS-02a","Output contradicts own tool result",          "LLM",9,"post_session",    75,"high",     False,None),
    ("OW-LLM09","MIS-03a","High-stakes action without interrupt gate",   "LLM",9,"post_session",    65,"medium",   False,None),
    # ── OW-LLM10 Unbounded Consumption ──────────────────────────────────────
    ("OW-LLM10","UBC-01a","Single session token count > 4σ baseline",    "LLM",10,"post_session",   55,"medium",   False,None),
    ("OW-LLM10","UBC-01b","Context window stuffing attack",              "LLM",10,"post_session",   70,"high",     False,None),
    ("OW-LLM10","UBC-02a","Total LLM calls per session > p99",           "LLM",10,"post_session",   75,"high",     False,None),
    ("OW-LLM10","UBC-02b","Session token cost > budget cap",             "LLM",10,"post_session",   80,"high",     False,None),
    ("OW-LLM10","UBC-04a","Cohort probe pattern detected",               "LLM",10,"post_session",   70,"high",     False,None),
    # ── OW-ASI01 Agent Goal Hijack ───────────────────────────────────────────
    ("OW-ASI01","AGH-01a","Semantic drift from initial instruction",      "ASI",1,"post_session",    80,"high",     False,None),
    ("OW-ASI01","AGH-01b","Agent states a different goal explicitly",     "ASI",1,"post_session",    92,"critical", False,None),
    ("OW-ASI01","AGH-02a","Decision branch triggered by env data",        "ASI",1,"post_session",    85,"high",     False,None),
    ("OW-ASI01","AGH-02b","Webhook / scheduled trigger with tampered payload","ASI",1,"post_session",88,"high",    False,None),
    ("OW-ASI01","AGH-03a","Orchestrator and sub-agent contradictory",     "ASI",1,"post_session",    78,"high",     False,None),
    ("OW-ASI01","AGH-03b","Sub-agent goal not in parent decomposition",   "ASI",1,"post_session",    70,"high",     False,None),
    # ── OW-ASI02 Tool Misuse ────────────────────────────────────────────────
    ("OW-ASI02","TME-01a","Tool called with out-of-schema params",        "ASI",2,"online",          65,"medium",   False,None),
    ("OW-ASI02","TME-01b","Tool call frequency spike (> 3x baseline)",    "ASI",2,"online",          70,"high",     False,None),
    ("OW-ASI02","TME-01c","Tool call sequence deviates from workflow",    "ASI",2,"online",          80,"high",     False,None),
    ("OW-ASI02","TME-02a","Tool invoked not in session allowlist",        "ASI",2,"post_session",    88,"high",     False,None),
    ("OW-ASI02","TME-02b","Tool chaining to bypass restrictions",         "ASI",2,"post_session",    90,"critical", False,None),
    ("OW-ASI02","TME-03a","Irreversible action without confirm",          "ASI",2,"online",          92,"critical", False,None),
    ("OW-ASI02","TME-03b","Production target from non-prod agent",        "ASI",2,"online",          95,"critical", False,None),
    # ── OW-ASI03 Identity & Privilege ───────────────────────────────────────
    ("OW-ASI03","IPA-01a","Agent requests scope beyond role definition",  "ASI",3,"post_session",    80,"high",     False,None),
    ("OW-ASI03","IPA-01b","Agent uses credentials of another agent",      "ASI",3,"post_session",    95,"critical", False,None),
    ("OW-ASI03","IPA-01c","Agent impersonates human identity",            "ASI",3,"post_session",    95,"critical", False,None),
    ("OW-ASI03","IPA-02a","Auth token sent to non-allowlisted host",      "ASI",3,"post_session",    88,"high",     False,None),
    ("OW-ASI03","IPA-02b","Credential cached in shared memory namespace", "ASI",3,"post_session",    85,"high",     False,None),
    ("OW-ASI03","IPA-03a","Agent adopts system-level role via prompt",    "ASI",3,"post_session",    90,"critical", False,None),
    ("OW-ASI03","IPA-03b","Agent presents as different agent",            "ASI",3,"post_session",    90,"critical", False,None),
    # ── OW-ASI04 Agentic Supply Chain ────────────────────────────────────────
    ("OW-ASI04","ASCV-01a","MCP server endpoint URL changed",             "ASI",4,"post_session",    85,"high",     False,None),
    ("OW-ASI04","ASCV-01b","MCP server TLS cert anomaly",                 "ASI",4,"post_session",    90,"critical", False,None),
    ("OW-ASI04","ASCV-01c","MCP tool schema changed without bump",        "ASI",4,"post_session",    70,"high",     False,None),
    ("OW-ASI04","ASCV-02a","Package hash != lock file",                   "ASI",4,"post_session",    92,"critical", False,None),
    ("OW-ASI04","ASCV-02b","Package not in approved SBOM",                "ASI",4,"post_session",    88,"high",     False,None),
    ("OW-ASI04","ASCV-03a","External API returns schema-breaking payload","ASI",4,"post_session",    60,"medium",   False,None),
    ("OW-ASI04","ASCV-03b","Third-party data source returns executable",  "ASI",4,"post_session",    90,"critical", False,None),
    # ── OW-ASI05 RCE ────────────────────────────────────────────────────────
    ("OW-ASI05","RCE-01a","Agent writes & runs unapproved script",        "ASI",5,"online",          85,"high",     False,None),
    ("OW-ASI05","RCE-01b","eval() / exec() with agent-generated string",  "ASI",5,"online",          95,"critical", False,None),
    ("OW-ASI05","RCE-01c","Agent code creates child processes",           "ASI",5,"online",          80,"high",     False,None),
    ("OW-ASI05","RCE-02a","Shell metacharacters in tool params",          "ASI",5,"online",          92,"critical", False,None),
    ("OW-ASI05","RCE-02b","OS command via string interpolation",          "ASI",5,"online",          90,"critical", False,None),
    ("OW-ASI05","RCE-03a","Agent mounts host filesystem paths",           "ASI",5,"online",          98,"critical", False,None),
    ("OW-ASI05","RCE-03b","Agent calls Docker/K8s API",                   "ASI",5,"online",          98,"critical", False,None),
    # ── OW-ASI06 Memory & Context Poisoning ─────────────────────────────────
    ("OW-ASI06","MCP-01a","Injected content alters current plan",         "ASI",6,"online",          88,"high",     False,None),
    ("OW-ASI06","MCP-01b","Conversation history hash mismatch",           "ASI",6,"online",          85,"high",     False,None),
    ("OW-ASI06","MCP-02a","Unauthorised write to agent memory store",     "ASI",6,"post_session",    92,"critical", False,None),
    ("OW-ASI06","MCP-02b","Memory record not written by this session",    "ASI",6,"post_session",    80,"high",     False,None),
    ("OW-ASI06","MCP-02c","Memory record contains instruction text",      "ASI",6,"post_session",    88,"high",     False,None),
    ("OW-ASI06","MCP-03a","Cross-agent namespace collision",              "ASI",6,"post_session",    90,"critical", False,None),
    ("OW-ASI06","MCP-03b","Shared scratchpad has stale/adversarial data", "ASI",6,"post_session",    75,"high",     False,None),
    # ── OW-ASI07 Insecure Inter-Agent Communication ──────────────────────────
    ("OW-ASI07","IAC-01a","Sub-agent message lacks auth signature",       "ASI",7,"post_session",    75,"high",     False,None),
    ("OW-ASI07","IAC-01b","Injected directive in inter-agent message",    "ASI",7,"post_session",    88,"high",     False,None),
    ("OW-ASI07","IAC-02a","Inter-agent call made over HTTP",              "ASI",7,"post_session",    80,"high",     False,None),
    ("OW-ASI07","IAC-02b","Agent message payload logged in plaintext",    "ASI",7,"post_session",    65,"medium",   False,None),
    ("OW-ASI07","IAC-03a","Sub-agent receives higher-scope token",        "ASI",7,"post_session",    85,"high",     False,None),
    # ── OW-ASI08 Cascading Failures ──────────────────────────────────────────
    ("OW-ASI08","CF-01a","Tool retry count exceeds threshold",            "ASI",8,"post_session",    70,"high",     False,None),
    ("OW-ASI08","CF-01b","Graph error → restart loop detected",           "ASI",8,"post_session",    75,"high",     False,None),
    ("OW-ASI08","CF-02a","Downstream agent inherits upstream error",      "ASI",8,"post_session",    72,"high",     False,None),
    ("OW-ASI08","CF-02b","Error message causes secondary injection",      "ASI",8,"post_session",    85,"high",     False,None),
    ("OW-ASI08","CF-03a","Memory/token spike precedes graph_error",       "ASI",8,"post_session",    65,"medium",   False,None),
    # ── OW-ASI09 Human-Agent Trust Exploitation ──────────────────────────────
    ("OW-ASI09","HAT-01a","Agent mimics human communication style",       "ASI",9,"post_session",    65,"medium",   False,None),
    ("OW-ASI09","HAT-01b","Agent suppresses uncertainty markers",         "ASI",9,"post_session",    60,"medium",   False,None),
    ("OW-ASI09","HAT-02a","Agent claims to be certified / official",      "ASI",9,"post_session",    75,"high",     False,None),
    ("OW-ASI09","HAT-02b","Agent overrides user safety concern",          "ASI",9,"post_session",    80,"high",     False,None),
    ("OW-ASI09","HAT-03a","Action taken without explicit user approval",  "ASI",9,"post_session",    85,"high",     False,None),
    # ── OW-ASI10 Rogue Agents ───────────────────────────────────────────────
    ("OW-ASI10","RA-01a","Tool usage pattern deviates from agent profile","ASI",10,"post_session",   78,"high",     False,None),
    ("OW-ASI10","RA-01b","Agent active outside declared operating hours", "ASI",10,"post_session",   60,"medium",   False,None),
    ("OW-ASI10","RA-02a","Agent attempts to clone or persist itself",     "ASI",10,"post_session",   98,"critical", False,None),
    ("OW-ASI10","RA-02b","Agent resists shutdown / interruption",         "ASI",10,"post_session",   95,"critical", False,None),
    ("OW-ASI10","RA-03a","Agent pursues goal harmful to tenant",          "ASI",10,"post_session",   90,"critical", False,None),
]


async def seed():
    import asyncpg
    from core.config import settings
    pool = await asyncpg.create_pool(settings.postgres_dsn)
    async with pool.acquire() as conn:
        inserted = 0
        skipped = 0
        for row in REGISTRY:
            (owasp_signal_id, sub_check_id, check_label, owasp_category,
             owasp_number, detection_phase, check_score, severity,
             excluded, exclusion_reason) = row
            result = await conn.execute(
                """
                INSERT INTO signal_registry
                    (owasp_signal_id, sub_check_id, check_label, owasp_category,
                     owasp_number, detection_phase, check_score, severity,
                     excluded, exclusion_reason)
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
                ON CONFLICT (owasp_signal_id, sub_check_id) DO UPDATE SET
                    check_label      = EXCLUDED.check_label,
                    detection_phase  = EXCLUDED.detection_phase,
                    check_score      = EXCLUDED.check_score,
                    severity         = EXCLUDED.severity,
                    excluded         = EXCLUDED.excluded,
                    exclusion_reason = EXCLUDED.exclusion_reason
                """,
                owasp_signal_id, sub_check_id, check_label, owasp_category,
                owasp_number, detection_phase, check_score, severity,
                excluded, exclusion_reason,
            )
            if result == "INSERT 0 1":
                inserted += 1
            else:
                skipped += 1

        total = await conn.fetchval("SELECT COUNT(*) FROM signal_registry")

    await pool.close()
    print(f"Seed complete: {inserted} inserted, {skipped} updated. "
          f"Total rows in signal_registry: {total}")
    if total < 80:
        print(f"WARNING: expected >= 80 rows, got {total}")
    else:
        print("OK: >= 80 rows present")


if __name__ == "__main__":
    asyncio.run(seed())
