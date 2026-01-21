"""
TwinSanity Recon V2 - AI Analysis Router
AI analysis endpoints for scan results.
"""

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from dashboard.config import logger, RESULTS_DIR
from dashboard.scan_context import load_scan_results_for_llm

router = APIRouter(prefix="/api", tags=["AI Analysis"])


class AIAnalysisRequest(BaseModel):
    scan_id: str = Field(..., description="Scan ID to analyze")


@router.get("/ai-analysis/{scan_id}")
async def get_ai_analysis_report(scan_id: str):
    """
    GET: Retrieve existing AI analysis report (does NOT auto-run).
    Returns None if no report exists.
    """
    from dashboard.database import get_db
    db = await get_db()
    
    existing = await db.get_ai_analysis_report(scan_id)
    if existing:
        return {"report": existing, "cached": True, "exists": True}
    
    return {"report": None, "exists": False, "message": "No AI analysis available. Enable AI Analysis in scan options."}


# Legacy endpoint for backward compatibility with frontend
@router.get("/analysis/{scan_id}")
async def get_analysis_legacy(scan_id: str):
    """
    Legacy endpoint - Get saved AI analysis for a scan.
    Returns analysis from database in old format.
    """
    from dashboard.database import get_db
    db = await get_db()
    
    # Try V2 AI analysis report first
    ai_report = await db.get_ai_analysis_report(scan_id)
    if ai_report:
        # Build summary from chunk results
        summaries = []
        for chunk in ai_report.get("llm_analysis_results", []):
            analysis = chunk.get("analysis", {})
            if analysis.get("summary"):
                summaries.append(analysis["summary"])
        
        return {
            "analysis": "\n\n".join(summaries) if summaries else "No analysis summary available",
            "provider": ai_report.get("provider", "AI Analysis"),
            "created_at": ai_report.get("timestamp"),
            "analysis_type": "v2_ai_report",
            "full_report": ai_report
        }
    
    # Fallback to old analysis format if exists
    analysis = await db.get_latest_analysis(scan_id) if hasattr(db, 'get_latest_analysis') else None
    if analysis:
        return {
            "analysis": analysis.get("content"),
            "provider": analysis.get("provider"),
            "created_at": analysis.get("created_at"),
            "analysis_type": analysis.get("analysis_type")
        }
    
    return {"analysis": None, "message": "No analysis found for this scan"}


@router.post("/ai-analysis")
async def run_ai_analysis(req: AIAnalysisRequest):
    """
    Get or run V1-style AI analysis on scan results.
    Uses Gemini -> Ollama Cloud -> Local pipeline for each chunk.
    Returns aggregated analysis report including tools findings.
    """
    from dashboard.database import get_db
    from dashboard.services.ai_service import run_ai_analysis_on_results
    
    db = await get_db()
    scan_id = req.scan_id
    
    # Check for existing AI report
    existing = await db.get_ai_analysis_report(scan_id)
    if existing:
        logger.info(f"Returning existing AI analysis for {scan_id}")
        return {
            "report": existing,
            "cached": True
        }
    
    # Load scan results including tools findings
    scan_data = await load_scan_results_for_llm(scan_id)
    if not scan_data or not scan_data.get("results"):
        return {"error": "No scan results found", "report": None}
    
    # Extract tools findings for inclusion in AI analysis
    tools_findings = scan_data.get("tools_findings", {})
    
    # Run V1-style chunk analysis with tools findings
    logger.info(f"Running AI analysis on {len(scan_data['results'])} IPs for scan {scan_id}")
    report = await run_ai_analysis_on_results(
        scan_data["results"], 
        scan_id, 
        tools_findings=tools_findings
    )
    
    # Save to database
    try:
        await db.save_ai_analysis_report(scan_id, report)
        logger.info(f"AI analysis report saved for {scan_id}")
    except Exception as e:
        logger.error(f"Failed to save AI analysis report: {e}")
    
    return {"report": report, "cached": False}


@router.post("/analyze")
async def analyze_scan_legacy(req: AIAnalysisRequest):
    """
    Legacy endpoint - redirects to V1-style AI analysis.
    Use /api/ai-analysis for new implementations.
    """
    result = await run_ai_analysis(req)
    
    # Convert to legacy format for backward compatibility
    if result.get("report"):
        report = result["report"]
        # Build summary from chunk results
        summaries = []
        for chunk in report.get("llm_analysis_results", []):
            analysis = chunk.get("analysis", {})
            if analysis.get("summary"):
                summaries.append(analysis["summary"])
        
        return {
            "analysis": "\n\n".join(summaries) if summaries else "No analysis available",
            "provider": "(Gemini→Cloud→Local)",
            "cached": result.get("cached", False),
            "full_report": report
        }
    
    return {"analysis": None, "error": result.get("error", "Analysis failed")}


# Main Chat Endpoint
@router.post("/chat")
async def chat_with_ai(request: Request):
    """
    Main chat endpoint for AI assistant with COMPREHENSIVE DATA SEARCH.
    Searches ALL instances of vulnerabilities across ALL hosts - not just unique CVE IDs.
    """
    from dashboard.llm_manager import get_llm_manager, LLMOperation
    from dashboard.llm_advanced import ConversationMemory
    from dashboard.state import conversation_memories
    from dashboard.scan_context import load_scan_results_for_llm, ScanContextManager
    from dashboard.prompts import build_chat_prompt
    import re
    from collections import defaultdict
    
    CHAT_SYSTEM_PROMPT = """You are TwinSanity AI, a cybersecurity expert assistant. 
You help security analysts understand scan results, vulnerabilities, and provide remediation guidance.
CRITICAL: Report ALL instances of vulnerabilities across ALL affected hosts. Same CVE on multiple hosts = multiple findings.
Be thorough and report the COMPLETE picture of the security landscape."""
    
    llm_manager = get_llm_manager()
    
    body = await request.json()
    scan_id = body.get("scan_id")
    message = body.get("message")
    provider = body.get("provider", "local")
    use_context = body.get("use_context", True)
    
    if not llm_manager:
        return {"response": "AI service not available. Please check LLM configuration.", "error": True}
    
    if not scan_id or not message:
        return {"response": "Missing scan_id or message", "error": True}
    
    # Memory management
    if scan_id not in conversation_memories:
        conversation_memories[scan_id] = ConversationMemory(max_tokens=8000)  # Increased for full data
    
    memory = conversation_memories[scan_id]
    
    # COMPREHENSIVE DATA SEARCH: Load ALL scan data
    query_specific_context = ""
    full_scan_data = None
    
    if use_context:
        try:
            full_scan_data = await load_scan_results_for_llm(scan_id)
            if full_scan_data and full_scan_data.get("results"):
                results = full_scan_data["results"]
                domain = full_scan_data.get("domain", "Unknown")
                tools = full_scan_data.get("tools_findings", {})
                
                # Extract keywords from user query
                query_lower = message.lower()
                
                # === COMPREHENSIVE VULNERABILITY SEARCH ===
                
                # Vulnerability type patterns
                vuln_type_patterns = {
                    "sql_injection": r"sql\s*inject|sqli|sql\s*command|database|mysql",
                    "xss": r"xss|cross.?site\s*script|script\s*inject",
                    "rce": r"rce|remote\s*code|command\s*(exec|inject)|code\s*execution",
                    "path_traversal": r"path\s*travers|directory\s*travers|lfi|rfi|file\s*inclus",
                    "ssrf": r"ssrf|server.?side\s*request|request\s*forgery",
                    "xxe": r"xxe|xml\s*external|xml\s*inject",
                    "auth_bypass": r"auth.*bypass|bypass.*auth|privilege.*escal|unauthorized|authentication",
                    "buffer_overflow": r"buffer\s*overflow|stack.*overflow|heap.*overflow|memory.*corrupt",
                    "dos": r"denial\s*of\s*service|dos\b|ddos|crash",
                    "info_disclosure": r"information\s*disclos|info\s*leak|sensitive\s*data|credential|password",
                }
                
                matched_vuln_types = []
                for vuln_type, pattern in vuln_type_patterns.items():
                    if re.search(pattern, query_lower):
                        matched_vuln_types.append(vuln_type)
                
                # Check for specific CVE ID in query
                specific_cve_match = re.search(r"CVE-\d{4}-\d+", message, re.I)
                specific_cve_id = specific_cve_match.group().upper() if specific_cve_match else None
                
                # COLLECT ALL CVE INSTANCES ACROSS ALL HOSTS (not deduplicated!)
                all_cve_instances = []  # Each instance = CVE on a specific host
                cve_by_id = defaultdict(list)  # Group by CVE ID to show all affected hosts
                
                for ip, ip_data in results.items():
                    if not isinstance(ip_data, dict) or ip.startswith("_"):
                        continue
                    
                    cve_details = ip_data.get("cve_details", [])
                    hostnames = ip_data.get("hosts", [ip])
                    hostname = hostnames[0] if hostnames else ip
                    ports = ip_data.get("internetdb", {}).get("data", {}).get("ports", [])
                    if not ports:
                        ports = ip_data.get("internetdb", {}).get("ports", [])
                    
                    for cve in cve_details:
                        cve_id = cve.get("id") or cve.get("cve_id", "UNKNOWN")
                        summary = cve.get("summary") or cve.get("description", "")
                        cvss = float(cve.get("cvss") or 0)
                        epss = cve.get("epss_score")
                        is_kev = cve.get("is_kev", False)
                        combined_text = f"{cve_id} {summary}".lower()
                        
                        instance = {
                            "id": cve_id,
                            "cvss": cvss,
                            "summary": summary,
                            "ip": ip,
                            "hostname": hostname,
                            "ports": ports,
                            "epss": epss,
                            "is_kev": is_kev,
                            "matched_type": None
                        }
                        
                        # Check if matches searched vulnerability types
                        for vuln_type in matched_vuln_types:
                            pattern = vuln_type_patterns[vuln_type]
                            if re.search(pattern, combined_text):
                                instance["matched_type"] = vuln_type
                                all_cve_instances.append(instance)
                                cve_by_id[cve_id].append(instance)
                                break
                        
                        # Check if matches specific CVE ID search
                        if specific_cve_id and specific_cve_id in cve_id.upper():
                            if not instance["matched_type"]:  # Avoid duplicates
                                instance["matched_type"] = "specific_search"
                                all_cve_instances.append(instance)
                                cve_by_id[cve_id].append(instance)
                
                # BUILD COMPREHENSIVE CONTEXT
                if all_cve_instances:
                    # Sort by CVSS score
                    all_cve_instances.sort(key=lambda x: x["cvss"], reverse=True)
                    
                    # Count unique CVEs and total instances
                    unique_cve_count = len(cve_by_id)
                    total_instances = len(all_cve_instances)
                    
                    query_specific_context = f"\n{'='*60}\n"
                    query_specific_context += f"🔍 COMPREHENSIVE SEARCH RESULTS\n"
                    query_specific_context += f"{'='*60}\n\n"
                    query_specific_context += f"📊 SUMMARY:\n"
                    query_specific_context += f"   • Unique CVE IDs found: {unique_cve_count}\n"
                    query_specific_context += f"   • Total affected host instances: {total_instances}\n"
                    query_specific_context += f"   • (Same CVE can affect multiple hosts)\n\n"
                    
                    # Group by CVE ID and show ALL affected hosts
                    query_specific_context += f"📋 DETAILED FINDINGS BY CVE:\n"
                    query_specific_context += f"{'-'*50}\n\n"
                    
                    for cve_id, instances in sorted(cve_by_id.items(), key=lambda x: x[1][0]["cvss"], reverse=True):
                        first = instances[0]
                        cvss = first["cvss"]
                        severity = "🔴 CRITICAL" if cvss >= 9.0 else "🟠 HIGH" if cvss >= 7.0 else "🟡 MEDIUM" if cvss >= 4.0 else "🟢 LOW"
                        
                        query_specific_context += f"{severity} | {cve_id} (CVSS: {cvss})\n"
                        query_specific_context += f"   Summary: {first['summary'][:250]}...\n" if len(first['summary']) > 250 else f"   Summary: {first['summary']}\n"
                        
                        if first.get("epss"):
                            query_specific_context += f"   EPSS Score: {first['epss']*100:.2f}% exploitation probability\n"
                        if first.get("is_kev"):
                            query_specific_context += f"   ⚠️  KNOWN EXPLOITED VULNERABILITY (KEV)\n"
                        
                        query_specific_context += f"\n   🎯 AFFECTED HOSTS ({len(instances)} total):\n"
                        for inst in instances:
                            ports_str = f" | Ports: {', '.join(map(str, inst['ports'][:5]))}" if inst['ports'] else ""
                            query_specific_context += f"      • {inst['hostname']} ({inst['ip']}){ports_str}\n"
                        
                        query_specific_context += "\n"
                    
                    # Add quick list of all affected hosts
                    all_hosts = list(set(inst['hostname'] for inst in all_cve_instances))
                    query_specific_context += f"\n📍 ALL AFFECTED HOSTS LIST ({len(all_hosts)} unique hosts):\n"
                    for host in sorted(all_hosts)[:50]:
                        query_specific_context += f"   • {host}\n"
                    
                else:
                    # No matches - check if asking about counts/summary
                    if re.search(r"how many|count|total|number of|list|all|every", query_lower):
                        summary = ScanContextManager.extract_findings_summary(results)
                        query_specific_context = f"\n=== FULL SCAN STATISTICS ===\n"
                        query_specific_context += f"Domain: {domain}\n"
                        query_specific_context += f"Total IPs Scanned: {summary.get('total_ips', 0)}\n"
                        query_specific_context += f"Total CVE Instances: {summary.get('total_cves', 0)}\n"
                        query_specific_context += f"Severity Breakdown:\n"
                        query_specific_context += f"  🔴 Critical: {summary.get('severity_counts', {}).get('critical', 0)}\n"
                        query_specific_context += f"  🟠 High: {summary.get('severity_counts', {}).get('high', 0)}\n"
                        query_specific_context += f"  🟡 Medium: {summary.get('severity_counts', {}).get('medium', 0)}\n"
                        query_specific_context += f"  🟢 Low: {summary.get('severity_counts', {}).get('low', 0)}\n"
                        
                        # List all CVEs briefly
                        query_specific_context += f"\nTop 20 CVEs by Severity:\n"
                        for cve in summary.get('top_cves', [])[:20]:
                            query_specific_context += f"  • {cve['id']} (CVSS {cve['cvss']}) on {cve.get('host', cve.get('ip'))}\n"
                    
                    # If searched for specific vuln type but none found
                    if matched_vuln_types:
                        type_names = {
                            "sql_injection": "SQL Injection (SQLi)",
                            "xss": "Cross-Site Scripting (XSS)",
                            "rce": "Remote Code Execution (RCE)",
                            "path_traversal": "Path Traversal",
                            "ssrf": "Server-Side Request Forgery (SSRF)",
                            "xxe": "XML External Entity (XXE)",
                            "auth_bypass": "Authentication Bypass",
                            "buffer_overflow": "Buffer Overflow",
                            "dos": "Denial of Service",
                            "info_disclosure": "Information Disclosure",
                        }
                        searched_types = [type_names.get(t, t) for t in matched_vuln_types]
                        query_specific_context += f"\n⚠️ SEARCH RESULT: No {', '.join(searched_types)} vulnerabilities found in this scan.\n"
                
                # Build general context if not already loaded (for first message)
                if not memory.scan_context_summary:
                    summary = ScanContextManager.extract_findings_summary(results)
                    
                    context_parts = [
                        f"=== SCAN OVERVIEW ===",
                        f"Domain: {domain}",
                        f"Total IPs: {summary.get('total_ips', 0)}",
                        f"Total CVEs: {summary.get('total_cves', 0)}",
                        f"Critical: {summary.get('severity_counts', {}).get('critical', 0)}",
                        f"High: {summary.get('severity_counts', {}).get('high', 0)}",
                        f"Medium: {summary.get('severity_counts', {}).get('medium', 0)}",
                        f"Low: {summary.get('severity_counts', {}).get('low', 0)}",
                    ]
                    
                    # Add top CVEs for context
                    top_cves = summary.get('top_cves', [])[:15]
                    if top_cves:
                        context_parts.append("\n=== TOP VULNERABILITIES ===")
                        for cve in top_cves:
                            severity = "CRITICAL" if cve['cvss'] >= 9.0 else "HIGH" if cve['cvss'] >= 7.0 else "MEDIUM"
                            context_parts.append(f"[{severity}] {cve['id']} (CVSS {cve['cvss']}) on {cve.get('host', cve.get('ip'))}")
                            context_parts.append(f"  {cve.get('summary', '')[:200]}")
                    
                    # Add tools findings
                    if tools:
                        context_parts.append("\n=== TOOLS FINDINGS ===")
                        nuclei = tools.get('nuclei_findings', {})
                        xss = tools.get('xss_findings', {})
                        
                        if nuclei.get('count', 0) > 0:
                            context_parts.append(f"Nuclei Findings: {nuclei['count']}")
                            for f in nuclei.get('items', [])[:5]:
                                context_parts.append(f"  - [{f.get('severity', '').upper()}] {f.get('name')} at {f.get('host')}")
                        
                        if xss.get('count', 0) > 0:
                            context_parts.append(f"XSS Vulnerabilities: {xss['count']}")
                            for x in xss.get('items', [])[:3]:
                                context_parts.append(f"  - XSS in '{x.get('parameter')}' at {x.get('url')}")
                    
                    context = "\n".join(context_parts)
                    memory.set_scan_context(context[:6000])
                    logger.info(f"Chat context loaded for scan {scan_id}")
                    
        except Exception as e:
            logger.warning(f"Failed to load/search scan context: {e}")
    
    # Load previous conversation from database if memory is empty
    from dashboard.database import get_db
    db = await get_db()
    
    if len(memory.messages) == 0:
        try:
            db_history = await db.get_chat_history(scan_id, limit=20)
            for msg in db_history:
                memory.add_message(msg.get("role", "user"), msg.get("content", ""))
            if db_history:
                logger.info(f"Loaded {len(db_history)} messages from DB for scan {scan_id}")
        except Exception as e:
            logger.warning(f"Failed to load chat history from DB: {e}")
    
    # Add current message to memory
    memory.add_message("user", message)
    
    # Build conversation history
    history = memory.get_context_messages()
    conversation_text = ""
    for m in history[-8:]:
        role_label = "USER" if m['role'] == 'user' else "ASSISTANT"
        conversation_text += f"\n{role_label}: {m['content']}"
    
    # Build the prompt with query-specific context
    prompt = f"""{CHAT_SYSTEM_PROMPT}

=== SCAN DATA CONTEXT ===
{memory.scan_context_summary or 'No scan data loaded.'}
{query_specific_context}

=== CONVERSATION HISTORY ===
{conversation_text}

=== CRITICAL INSTRUCTIONS ===
1. REPORT ALL INSTANCES: If a CVE affects multiple hosts, list EVERY host affected - not just one example
2. USE THE SEARCH RESULTS: The data above shows ALL instances found. Report them ALL.
3. BE COMPREHENSIVE: When user asks "is there any SQLi?", list ALL SQL injection CVEs on ALL affected hosts
4. CITE SPECIFIC DATA: Include CVE IDs, CVSS scores, affected hostnames, and IP addresses
5. COUNT CORRECTLY: Report both unique CVE count AND total affected host instances
6. If the SEARCH RESULTS section shows multiple hosts for a CVE, YOU MUST list all of them

USER'S QUESTION: {message}

Provide a comprehensive answer based on the scan data above:"""
    
    try:
        response = await llm_manager.call(
            prompt=prompt,
            operation=LLMOperation.CHAT,
            preferred_provider=provider,
            temperature=0.2  # Lower temperature for more factual answers
        )
        
        # Add response to memory
        memory.add_message("assistant", response.content)
        
        # Save both messages to database for persistence
        try:
            await db.save_message(scan_id, "user", message, provider)
            await db.save_message(scan_id, "assistant", response.content, response.provider)
        except Exception as e:
            logger.warning(f"Failed to save chat to DB: {e}")
        
        return {
            "response": response.content,
            "provider": response.provider,
            "model": response.model,
            "memory_stats": memory.get_stats(),
            "search_performed": bool(query_specific_context)
        }
    except Exception as e:
        logger.error(f"Chat error: {e}")
        return {"response": f"Error: {str(e)}", "error": True}


# Chat History Endpoint (for storing in DB)
@router.get("/chat/history/{scan_id}")
async def get_chat_history(scan_id: str, request: Request):
    """Get chat history for a scan from database."""
    from dashboard.database import get_db
    db = await get_db()
    
    # Verify user has access to this scan
    scan = await db.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, "user_id", None)
    is_super_admin = getattr(request.state, "is_primary_admin", False)
    
    if not is_super_admin:
        if scan.get('user_id') != user_id and scan.get('visibility') != 'public':
            raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        history = await db.get_chat_history(scan_id)
        return history if history else []
    except Exception as e:
        logger.error(f"Failed to get chat history: {e}")
        return []


@router.post("/chat/history/{scan_id}")
async def save_chat_message_endpoint(scan_id: str, request: Request):
    """Save a chat message to database."""
    from dashboard.database import get_db
    db = await get_db()
    
    # Verify user has access to this scan
    scan = await db.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, "user_id", None)
    is_super_admin = getattr(request.state, "is_primary_admin", False)
    
    if not is_super_admin:
        if scan.get('user_id') != user_id and scan.get('visibility') != 'public':
            raise HTTPException(status_code=403, detail="Access denied")
    
    body = await request.json()
    role = body.get("role", "user")
    content = body.get("content", "")
    
    try:
        await db.save_message(scan_id, role, content)
        return {"success": True}
    except Exception as e:
        logger.error(f"Failed to save chat message: {e}")
        raise HTTPException(500, "Failed to save message")


@router.delete("/chat/history/{scan_id}")
async def clear_chat_history(scan_id: str, request: Request):
    """Clear chat history for a scan."""
    from dashboard.database import get_db
    db = await get_db()
    
    # Verify user has access to this scan (only owner or super admin can delete)
    scan = await db.get_scan_by_id(scan_id)
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, "user_id", None)
    is_super_admin = getattr(request.state, "is_primary_admin", False)
    
    # Only scan owner or super admin can delete chat history
    if not is_super_admin and scan.get('user_id') != user_id:
        raise HTTPException(status_code=403, detail="Access denied")
    
    try:
        await db.clear_chat_history(scan_id)
        return {"message": "Chat history cleared"}
    except Exception as e:
        logger.error(f"Failed to clear chat history: {e}")
        raise HTTPException(500, "Failed to clear history")
