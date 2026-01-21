"""
TwinSanity Recon V2 - AI Service
Handles AI analysis, LLM calls, and chunk processing.
"""
import time
import json
import re
import asyncio
import aiohttp
from typing import Dict, List, Optional, Tuple, Any

from dashboard.config import (
    logger, GEMINI_API_KEY, GEMINI_MODEL, GEMINI_URL, GEMINI_MAX_RETRIES, GEMINI_BACKOFF,
    OLLAMA_CLOUD_HOST, OLLAMA_CLOUD_MODELS, OLLAMA_API_KEY, CLOUD_MAX_RETRIES,
    OLLAMA_LOCAL_HOST, OLLAMA_LOCAL_MODELS, REDACTION_ENABLED, ANALYSIS_CHUNK_SIZE
)
from dashboard.config import log_llm_call
from dashboard.websocket.manager import manager
from dashboard.database import get_db

# Global state for rate limits (module level)
gemini_disabled_until = 0.0
cloud_disabled_until = 0.0

# V1 JSON extraction regex
CODEFENCE_RE = re.compile(r"```(?:json)?\s*(\{[\s\S]*\})\s*```", re.IGNORECASE | re.MULTILINE)

# V1 Analysis Prompt Schema
ANALYSIS_PROMPT_SCHEMA = r"""
You are a senior cybersecurity analyst. Your task is to analyze a chunk of Shodan scan results.
Your response MUST be a single, valid JSON object and nothing else. Do not include markdown fences or any conversational text.

**JSON Schema:**
{
  "summary": "<string: A brief, high-level overview of the findings in this chunk. Mention the most critical issues found.>",
  "high_risk_assets": [
    {
      "ip": "<string>", "hostname": "<string>", "reason": "<string: Why this asset is high-risk>", "severity": "<string: low|medium|high|critical>"
    }
  ],
  "key_vulnerabilities": [
    {
      "cve": "<string>", "summary": "<string>", "cvss_score": <float>, "affected_ips": ["<string>"]
    }
  ],
  "recommended_actions": [
    {
      "action": "<string: A specific, actionable recommendation>", "priority": "<string: low|medium|high|critical>", "justification": "<string>"
    }
  ]
}

**Rules:**
1.  **JSON Only:** Your entire output must be the JSON object described above.
2.  **Prioritize:** Focus on the most significant risks. Do not list every minor finding.
3.  **Actionable:** Recommendations must be clear and concise.
"""

# Tools Findings Analysis Prompt - For analyzing Nuclei, XSS, API discovery results
TOOLS_ANALYSIS_PROMPT_SCHEMA = r"""
You are a senior bug bounty hunter and penetration tester. Your task is to analyze reconnaissance tool findings from a security scan.
Your response MUST be a single, valid JSON object and nothing else. Do not include markdown fences or any conversational text.

**JSON Schema:**
{
  "executive_summary": "<string: A 2-3 sentence summary of the overall security posture based on tool findings>",
  "nuclei_analysis": {
    "risk_assessment": "<string: Overall risk level from Nuclei findings: critical|high|medium|low|none>",
    "key_findings": ["<string: Most significant Nuclei vulnerability findings>"],
    "attack_scenarios": ["<string: How an attacker could chain/exploit these findings>"],
    "recommendations": ["<string: Specific remediation steps>"]
  },
  "xss_analysis": {
    "risk_assessment": "<string: Risk level from XSS findings: critical|high|medium|low|none>",
    "exploitability": "<string: How easy these XSS vulnerabilities are to exploit>",
    "impact": "<string: Potential damage from XSS exploitation>",
    "recommendations": ["<string: How to fix these XSS issues>"]
  },
  "api_analysis": {
    "exposure_level": "<string: How exposed the API surface is: critical|high|medium|low|minimal>",
    "sensitive_endpoints": ["<string: Most sensitive/risky API endpoints discovered>"],
    "attack_vectors": ["<string: Potential attacks against discovered APIs>"],
    "recommendations": ["<string: API security improvements>"]
  },
  "url_analysis": {
    "attack_surface": "<string: Assessment of the URL attack surface>",
    "interesting_patterns": ["<string: Notable URL patterns that indicate vulnerabilities>"],
    "priority_targets": ["<string: URLs that should be prioritized for further testing>"]
  },
  "overall_opinion": "<string: Your professional opinion on the security state, prioritized next steps, and what a bug bounty hunter should focus on>"
}

**Rules:**
1.  **JSON Only:** Your entire output must be the JSON object described above.
2.  **Be Critical:** Give honest assessments, not just listing findings.
3.  **Actionable:** Provide specific, prioritized recommendations.
4.  **Context-Aware:** Consider how findings relate to each other and can be chained.
"""

def extract_json_from_text(text: str) -> Optional[Dict]:
    """Extract JSON from LLM response (handles markdown code fences)"""
    if not isinstance(text, str):
        return None
    match = CODEFENCE_RE.search(text)
    candidate = match.group(1) if match else text
    try:
        start = candidate.find("{")
        end = candidate.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(candidate[start:end+1])
    except json.JSONDecodeError:
        logger.warning("Failed to extract valid JSON from LLM response")
    return None


async def call_gemini(prompt: str, _for_analysis: bool = False, scan_id: str = None) -> Tuple[Optional[str], Optional[str], Optional[int]]:
    """
    Call Gemini API using V1 compatible REST endpoint.
    Returns (response, error, retry_after)
    """
    global gemini_disabled_until
    
    if not GEMINI_API_KEY:
        return None, "GEMINI_API_KEY not configured", None
    
    # Check rate limit cooldown
    if time.time() < gemini_disabled_until:
        wait_time = int(gemini_disabled_until - time.time())
        return None, f"Gemini rate limited, wait {wait_time}s", wait_time
    
    # Audit log (redact for logging only, not for actual LLM prompt)
    log_llm_call("gemini", scan_id or "unknown", len(prompt), False)
    
    # Try SDK first (non-blocking with executor)
    try:
        import google.generativeai as genai
        genai.configure(api_key=GEMINI_API_KEY)
        model = genai.GenerativeModel(GEMINI_MODEL)
        
        # Run in executor to avoid blocking
        loop = asyncio.get_event_loop()
        response = await loop.run_in_executor(
            None, 
            lambda: model.generate_content(prompt)
        )
        return response.text, None, None
    except ImportError:
        pass  # Fall back to REST
    except Exception as e:
        msg = str(e)
        # Check for rate limit in error
        retry_match = re.search(r"retry_delay\s*{\s*seconds:\s*(\d+)\s*}", msg, re.IGNORECASE)
        if retry_match:
            retry_after = int(retry_match.group(1))
            gemini_disabled_until = time.time() + retry_after
            return None, f"Gemini rate limited: {msg[:100]}", retry_after
        return None, f"Gemini SDK error: {msg[:100]}", None
    
    # REST API fallback
    try:
        timeout = aiohttp.ClientTimeout(total=90)
        async with aiohttp.ClientSession(timeout=timeout) as session:
            url = GEMINI_URL.format(model=GEMINI_MODEL)
            headers = {
                "Content-Type": "application/json",
                "x-goog-api-key": GEMINI_API_KEY
            }
            payload = {"contents": [{"parts": [{"text": prompt}]}]}
            
            async with session.post(url, json=payload, headers=headers) as resp:
                if resp.status == 200:
                    j = await resp.json()
                    text = j.get('candidates', [{}])[0].get('content', {}).get('parts', [{}])[0].get('text', '')
                    return text, None, None
                else:
                    msg = await resp.text()
                    retry_match = re.search(r"retry_delay\s*{\s*seconds:\s*(\d+)\s*}", msg, re.IGNORECASE)
                    if retry_match:
                        retry_after = int(retry_match.group(1))
                        gemini_disabled_until = time.time() + retry_after
                        return None, f"HTTP {resp.status}: Rate limited", retry_after
                    return None, f"HTTP {resp.status}: {msg[:200]}", None
    except Exception as e:
        return None, f"Gemini REST error: {str(e)[:100]}", None


async def call_ollama_cloud(prompt: str, _for_analysis: bool = False) -> Tuple[Optional[str], Optional[str]]:
    """Call Ollama Cloud API."""
    global cloud_disabled_until
    
    if not OLLAMA_CLOUD_HOST:
        return None, "OLLAMA_CLOUD_HOST not configured"
    
    if time.time() < cloud_disabled_until:
        return None, "Ollama Cloud temporarily disabled due to errors"
    
    try:
        from ollama import Client as OllamaClient
        
        client_kwargs = {"host": OLLAMA_CLOUD_HOST}
        if OLLAMA_API_KEY:
            client_kwargs["headers"] = {"Authorization": OLLAMA_API_KEY}
        
        client = OllamaClient(**client_kwargs)
        errors = []
        
        for model_name in OLLAMA_CLOUD_MODELS:
            for attempt in range(1, CLOUD_MAX_RETRIES + 1):
                try:
                    logger.info(f"[Ollama Cloud] Trying {model_name} (attempt {attempt})")
                    response = client.chat(
                        model=model_name,
                        messages=[{"role": "user", "content": prompt}]
                    )
                    logger.info(f"[Ollama Cloud] Success with {model_name}")
                    return response["message"]["content"], None
                except Exception as e:
                    errors.append(f"{model_name}: {str(e)[:60]}")
                    if attempt < CLOUD_MAX_RETRIES:
                        await asyncio.sleep(3 ** attempt)
                    continue
        
        return None, f"All cloud models failed: {'; '.join(errors[-3:])}"
    except ImportError:
        return None, "Ollama SDK not installed (pip install ollama)"
    except Exception as e:
        return None, f"Ollama Cloud error: {str(e)[:100]}"


async def call_ollama_local(prompt: str, scan_id: str = None, timeout: int = 120) -> Tuple[Optional[str], Optional[str]]:
    """Call Local Ollama."""
    try:
        from ollama import Client
        import httpx
        
        try:
            async with httpx.AsyncClient(timeout=2) as client:
                await client.get(OLLAMA_LOCAL_HOST)
        except Exception:
            return None, f"Local Ollama not running at {OLLAMA_LOCAL_HOST}"
        
        available = set()
        try:
            async with httpx.AsyncClient(timeout=3) as client:
                models_resp = await client.get(f"{OLLAMA_LOCAL_HOST}/api/tags")
                if models_resp.status_code == 200:
                    for m in models_resp.json().get("models", []):
                        if m.get("name"):
                            available.add(m["name"])
        except:
            pass
        
        ollama_client = Client(host=OLLAMA_LOCAL_HOST)
        errors = []
        
        log_llm_call("ollama_local", scan_id or "unknown", len(prompt), False)
        
        for model_name in OLLAMA_LOCAL_MODELS:
            if available and model_name not in available:
                errors.append(f"{model_name} not available")
                continue
            try:
                def _sync_ollama_call():
                    return ollama_client.chat(
                        model=model_name,
                        messages=[
                            {"role": "system", "content": "You are a cybersecurity analyst. Answer questions based ONLY on the provided scan data. Always quote exact numbers from the QUICK REFERENCE section when asked about counts."},
                            {"role": "user", "content": prompt}
                        ],
                        options={
                            "num_ctx": 32768,
                            "temperature": 0.1,
                        }
                    )
                
                loop = asyncio.get_event_loop()
                response = await asyncio.wait_for(
                    loop.run_in_executor(None, _sync_ollama_call),
                    timeout=timeout + 10
                )
                logger.info(f"[Ollama Local] Success with {model_name}")
                return response["message"]["content"], None
            except asyncio.TimeoutError:
                errors.append(f"{model_name}: timeout after {timeout}s")
                continue
            except Exception as e:
                errors.append(f"{model_name}: {str(e)[:50]}")
                continue
        return None, f"Local models failed: {'; '.join(errors)}"
    except ImportError:
        return None, "Ollama SDK not installed (pip install ollama)"
    except Exception as e:
        return None, f"Local Ollama error: {str(e)[:100]}"


def normalize_analysis(raw: Dict) -> Dict:
    """Normalize LLM analysis output to canonical format (V1 compatible)"""
    canonical = {
        "summary": "No summary provided.",
        "high_risk_assets": [],
        "key_vulnerabilities": [],
        "recommended_actions": []
    }
    if not isinstance(raw, dict):
        return canonical
    
    canonical["summary"] = raw.get("summary", "No summary provided.")
    
    for asset in raw.get("high_risk_assets", []):
        if isinstance(asset, dict):
            canonical["high_risk_assets"].append({
                "ip": asset.get("ip", "N/A"),
                "hostname": asset.get("hostname", "N/A"),
                "reason": asset.get("reason", "No reason provided."),
                "severity": asset.get("severity", "medium")
            })
    
    for vuln in raw.get("key_vulnerabilities", []):
        if isinstance(vuln, dict):
            canonical["key_vulnerabilities"].append({
                "cve": vuln.get("cve", "N/A"),
                "summary": vuln.get("summary", "No summary provided."),
                "cvss_score": vuln.get("cvss_score", 0.0),
                "affected_ips": vuln.get("affected_ips", [])
            })
    
    for action in raw.get("recommended_actions", []):
        if isinstance(action, dict):
            canonical["recommended_actions"].append({
                "action": action.get("action", "No action specified."),
                "priority": action.get("priority", "medium"),
                "justification": action.get("justification", "No justification provided.")
            })
    
    return canonical


def estimate_tokens(text: str) -> int:
    """Rough token estimate."""
    return len(text) // 4


def truncate_chunk_for_llm(chunk: List[Dict], max_tokens: int = 6000) -> str:
    """Truncate chunk data to fit within token limits."""
    compressed_entries = []
    token_budget = max_tokens - 500
    
    for entry in chunk:
        if not isinstance(entry, dict):
            continue
            
        compressed = {
            "ip": entry.get("ip", "unknown"),
            "hosts": entry.get("hosts", [])[:3],
        }
        
        idb = entry.get("internetdb", {})
        if idb.get("ok"):
            idb_data = idb.get("data", {})
            compressed["ports"] = idb_data.get("ports", [])[:10]
            compressed["tags"] = idb_data.get("tags", [])[:5]
            vulns = idb_data.get("vulns", [])
            if isinstance(vulns, list):
                compressed["vulns"] = vulns[:10]
        
        cve_details = entry.get("cve_details", [])
        critical_cves = [c for c in cve_details if (c.get("cvss") or 0) >= 9.0][:3]
        high_cves = [c for c in cve_details if 7.0 <= (c.get("cvss") or 0) < 9.0][:2]
        
        top_cves = []
        for cve in critical_cves + high_cves:
            top_cves.append({
                "id": cve.get("id", "N/A"),
                "cvss": cve.get("cvss", 0),
                "summary": (cve.get("summary") or "")[:200]
            })
        
        if top_cves:
            compressed["top_cves"] = top_cves
        
        entry_json = json.dumps(compressed)
        entry_tokens = estimate_tokens(entry_json)
        
        if entry_tokens > token_budget:
            compressed_entries.append({"note": f"[{len(chunk) - len(compressed_entries)} more entries truncated]"})
            break
        
        compressed_entries.append(compressed)
        token_budget -= entry_tokens
    
    return json.dumps(compressed_entries, indent=2)


async def analyze_chunk_with_llm(chunk: List[Dict], chunk_idx: int, max_tokens: int = 6000) -> Dict:
    """Analyze a chunk of scan results using the V1 pipeline."""
    truncated_chunk = truncate_chunk_for_llm(chunk, max_tokens)
    prompt = ANALYSIS_PROMPT_SCHEMA + "\n\n**Shodan Scan Results Chunk:**\n" + truncated_chunk
    
    prompt_tokens = estimate_tokens(prompt)
    logger.info(f"[Chunk {chunk_idx}] Prompt size: {len(prompt)} chars (~{prompt_tokens} tokens)")
    
    # 1. Try Gemini
    if GEMINI_API_KEY and time.time() >= gemini_disabled_until:
        logger.info(f"[Chunk {chunk_idx}] Trying Gemini...")
        for attempt in range(1, GEMINI_MAX_RETRIES + 1):
            text, err, retry_after = await call_gemini(prompt, _for_analysis=True)
            if text:
                parsed = extract_json_from_text(text)
                if parsed:
                    logger.info(f"[Gemini] Chunk {chunk_idx} OK (attempt {attempt})")
                    return normalize_analysis(parsed)
            logger.warning(f"[Gemini] Chunk {chunk_idx} attempt {attempt} failed: {err}")
            if retry_after:
                break
            if attempt < GEMINI_MAX_RETRIES:
                await asyncio.sleep(GEMINI_BACKOFF ** attempt)
    
    # 2. Try Ollama Cloud
    if OLLAMA_API_KEY and time.time() >= cloud_disabled_until:
        logger.info(f"[Chunk {chunk_idx}] Trying Ollama Cloud...")
        log_llm_call("ollama_cloud", f"chunk_{chunk_idx}", len(prompt), False)
        text, err = await call_ollama_cloud(prompt, _for_analysis=True)
        if text:
            parsed = extract_json_from_text(text)
            if parsed:
                logger.info(f"[Ollama Cloud] Chunk {chunk_idx} OK")
                return normalize_analysis(parsed)
        logger.warning(f"[Ollama Cloud] Chunk {chunk_idx} failed: {err}")
    
    # 3. Try Ollama Local
    logger.info(f"[Chunk {chunk_idx}] Trying Ollama Local...")
    text, err = await call_ollama_local(prompt, scan_id=f"chunk_{chunk_idx}")
    if text:
        parsed = extract_json_from_text(text)
        if parsed:
            logger.info(f"[Ollama Local] Chunk {chunk_idx} OK")
            return normalize_analysis(parsed)
    logger.warning(f"[Ollama Local] Chunk {chunk_idx} failed: {err}")
    
    # All failed
    logger.error(f"All LLM providers failed for chunk {chunk_idx}")
    return {
        "summary": f"Analysis failed for chunk {chunk_idx} - no LLM providers were successful.",
        "high_risk_assets": [],
        "key_vulnerabilities": [],
        "recommended_actions": []
    }


async def analyze_tools_findings_with_llm(tools_findings: Dict, scan_id: str) -> Dict:
    """
    Analyze tools findings (Nuclei, XSS, API Discovery, URLs) using AI.
    Provides expert opinion and recommendations on the findings.
    """
    if not tools_findings:
        return {
            "executive_summary": "No tools findings available for analysis.",
            "nuclei_analysis": {"risk_assessment": "none", "key_findings": [], "attack_scenarios": [], "recommendations": []},
            "xss_analysis": {"risk_assessment": "none", "exploitability": "N/A", "impact": "N/A", "recommendations": []},
            "api_analysis": {"exposure_level": "minimal", "sensitive_endpoints": [], "attack_vectors": [], "recommendations": []},
            "url_analysis": {"attack_surface": "Unknown", "interesting_patterns": [], "priority_targets": []},
            "overall_opinion": "No reconnaissance tool findings available to analyze."
        }
    
    # Build context from tools findings
    findings_context = "=== BUG BOUNTY TOOLS FINDINGS ===\n\n"
    
    # Nuclei findings
    nuclei = tools_findings.get('nuclei_findings', {})
    if nuclei.get('count', 0) > 0:
        findings_context += f"## NUCLEI VULNERABILITY SCAN ({nuclei['count']} findings)\n"
        findings_context += f"By Severity: {json.dumps(nuclei.get('by_severity', {}))}\n"
        for item in nuclei.get('items', [])[:20]:
            findings_context += f"- [{item.get('severity', 'unknown').upper()}] {item.get('name')}: {item.get('host')}\n"
            if item.get('description'):
                findings_context += f"  Description: {item.get('description')[:150]}\n"
        findings_context += "\n"
    
    # XSS findings
    xss = tools_findings.get('xss_findings', {})
    if xss.get('count', 0) > 0:
        findings_context += f"## XSS VULNERABILITIES ({xss['count']} findings)\n"
        for item in xss.get('items', [])[:10]:
            findings_context += f"- Parameter: '{item.get('parameter')}' at {item.get('url')}\n"
            if item.get('payload'):
                findings_context += f"  Payload: {item.get('payload')[:100]}\n"
        findings_context += "\n"
    
    # API discoveries
    api = tools_findings.get('api_discoveries', {})
    if api.get('count', 0) > 0:
        findings_context += f"## API ENDPOINTS DISCOVERED ({api['count']} endpoints)\n"
        for item in api.get('items', [])[:15]:
            findings_context += f"- [{item.get('type', 'unknown')}] {item.get('url')} (Status: {item.get('status')})\n"
        findings_context += "\n"
    
    # Alive hosts
    alive = tools_findings.get('alive_hosts', {})
    if alive.get('count', 0) > 0:
        findings_context += f"## ALIVE HOSTS ({alive['count']} total)\n"
        for item in alive.get('sample', [])[:10]:
            findings_context += f"- {item.get('url')} [{item.get('status')}] - {item.get('title', 'No title')}\n"
            if item.get('technologies'):
                findings_context += f"  Technologies: {', '.join(item.get('technologies', []))}\n"
        findings_context += "\n"
    
    # Harvested URLs
    urls = tools_findings.get('harvested_urls', {})
    if urls.get('count', 0) > 0:
        findings_context += f"## HARVESTED URLs ({urls['count']} total, {urls.get('with_params', 0)} with parameters)\n"
        for url in urls.get('sample', [])[:15]:
            findings_context += f"- {url}\n"
        findings_context += "\n"
    
    # Check if we have any meaningful content
    has_content = any([
        nuclei.get('count', 0) > 0,
        xss.get('count', 0) > 0,
        api.get('count', 0) > 0,
        alive.get('count', 0) > 0,
        urls.get('count', 0) > 0
    ])
    
    if not has_content:
        return {
            "executive_summary": "No significant tools findings to analyze. The reconnaissance tools did not discover notable vulnerabilities or attack surface.",
            "nuclei_analysis": {"risk_assessment": "none", "key_findings": [], "attack_scenarios": [], "recommendations": []},
            "xss_analysis": {"risk_assessment": "none", "exploitability": "N/A", "impact": "N/A", "recommendations": []},
            "api_analysis": {"exposure_level": "minimal", "sensitive_endpoints": [], "attack_vectors": [], "recommendations": []},
            "url_analysis": {"attack_surface": "Minimal", "interesting_patterns": [], "priority_targets": []},
            "overall_opinion": "The reconnaissance scan did not reveal significant attack surface. Consider running additional tools or checking target scope."
        }
    
    prompt = TOOLS_ANALYSIS_PROMPT_SCHEMA + "\n\n" + findings_context
    
    logger.info(f"[Tools Analysis] Analyzing tools findings for scan {scan_id}")
    
    # Try each LLM provider in order
    # 1. Try Gemini
    if GEMINI_API_KEY and time.time() >= gemini_disabled_until:
        logger.info(f"[Tools Analysis] Trying Gemini...")
        text, err, retry_after = await call_gemini(prompt, _for_analysis=True, scan_id=scan_id)
        if text:
            parsed = extract_json_from_text(text)
            if parsed:
                logger.info(f"[Gemini] Tools analysis OK")
                return parsed
        logger.warning(f"[Gemini] Tools analysis failed: {err}")
    
    # 2. Try Ollama Cloud
    if OLLAMA_API_KEY and time.time() >= cloud_disabled_until:
        logger.info(f"[Tools Analysis] Trying Ollama Cloud...")
        text, err = await call_ollama_cloud(prompt, _for_analysis=True)
        if text:
            parsed = extract_json_from_text(text)
            if parsed:
                logger.info(f"[Ollama Cloud] Tools analysis OK")
                return parsed
        logger.warning(f"[Ollama Cloud] Tools analysis failed: {err}")
    
    # 3. Try Ollama Local
    logger.info(f"[Tools Analysis] Trying Ollama Local...")
    text, err = await call_ollama_local(prompt, scan_id=scan_id)
    if text:
        parsed = extract_json_from_text(text)
        if parsed:
            logger.info(f"[Ollama Local] Tools analysis OK")
            return parsed
    logger.warning(f"[Ollama Local] Tools analysis failed: {err}")
    
    # All failed - return default structure
    logger.error(f"All LLM providers failed for tools analysis")
    return {
        "executive_summary": "AI analysis could not be completed - all LLM providers failed.",
        "nuclei_analysis": {"risk_assessment": "unknown", "key_findings": ["Analysis unavailable"], "attack_scenarios": [], "recommendations": []},
        "xss_analysis": {"risk_assessment": "unknown", "exploitability": "Unknown", "impact": "Unknown", "recommendations": []},
        "api_analysis": {"exposure_level": "unknown", "sensitive_endpoints": [], "attack_vectors": [], "recommendations": []},
        "url_analysis": {"attack_surface": "Unknown", "interesting_patterns": [], "priority_targets": []},
        "overall_opinion": "AI analysis failed. Manual review of the raw findings is recommended."
    }


async def run_ai_analysis_on_results(scan_results: Dict, scan_id: str, tools_findings: Dict = None) -> Dict:
    """Run V1-style chunk-based AI analysis on scan results including tools findings."""
    # Convert results dict to list of entries
    entries = list(scan_results.values()) if isinstance(scan_results, dict) else scan_results
    total_entries = len(entries)
    
    if total_entries == 0:
        return {"error": "No scan results to analyze"}
    
    # Initialize tools findings if not provided
    if tools_findings is None:
        tools_findings = {}
    
    # Broadcast: AI analysis starting
    await manager.broadcast(scan_id, {
        "type": "ai_analysis",
        "status": "starting",
        "message": f"🤖 AI Analysis starting for {total_entries} IPs...",
        "progress": 0
    })
    
    # Extract all CVEs for comprehensive reporting
    all_discovered_cves = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        ip = entry.get('ip', 'Unknown')
        for cve_detail in entry.get("cve_details", []):
            cve_id = cve_detail.get("id") or cve_detail.get("cve_id")
            if not cve_id or not cve_detail.get("summary"):
                continue
            if cve_id not in all_discovered_cves:
                all_discovered_cves[cve_id] = {
                    "id": cve_id,
                    "summary": cve_detail.get("summary"),
                    "cvss": cve_detail.get("cvss") or cve_detail.get("cvss3"),
                    "affected_ips": set()
                }
            all_discovered_cves[cve_id]["affected_ips"].add(ip)
    
    # Convert sets to lists
    final_cve_list = list(all_discovered_cves.values())
    for cve in final_cve_list:
        cve["affected_ips"] = sorted(list(cve["affected_ips"]))
    
    # Chunk the entries
    chunk_size = max(1, ANALYSIS_CHUNK_SIZE)
    chunks = [entries[i:i + chunk_size] for i in range(0, total_entries, chunk_size)]
    total_chunks = len(chunks)
    
    logger.info(f"[AI Analysis] Processing {total_chunks} chunks of size {chunk_size}")
    
    await manager.broadcast(scan_id, {
        "type": "ai_analysis",
        "status": "processing",
        "message": f"📊 Processing {total_chunks} chunks ({chunk_size} IPs each)...",
        "progress": 5,
        "total_chunks": total_chunks
    })
    
    # Analyze each chunk with progress updates
    chunk_results = []
    for i, chunk in enumerate(chunks, 1):
        logger.info(f"[AI Analysis] Processing chunk {i}/{total_chunks}")
        
        chunk_progress = 5 + int((i / total_chunks) * 90)
        
        await manager.broadcast(scan_id, {
            "type": "ai_analysis",
            "status": "chunk_processing",
            "message": f"🔍 Analyzing chunk {i}/{total_chunks}...",
            "progress": chunk_progress,
            "current_chunk": i,
            "total_chunks": total_chunks
        })
        
        start_time = time.time()
        analysis = await analyze_chunk_with_llm(chunk, i)
        elapsed = time.time() - start_time
        
        await manager.broadcast(scan_id, {
            "type": "ai_analysis",
            "status": "chunk_complete",
            "message": f"✅ Chunk {i}/{total_chunks} complete ({elapsed:.1f}s)",
            "progress": chunk_progress,
            "current_chunk": i,
            "processing_time": elapsed
        })
        
        chunk_results.append({
            "chunk_id": i,
            "source_ips": [e.get("ip", "N/A") for e in chunk if isinstance(e, dict)],
            "analysis": analysis,
            "processing_time_seconds": round(elapsed, 2)
        })
    
    # Analyze tools findings with AI (if tools findings are available)
    tools_analysis = None
    has_tools_data = any([
        tools_findings.get("nuclei_findings", {}).get("count", 0) > 0,
        tools_findings.get("xss_findings", {}).get("count", 0) > 0,
        tools_findings.get("api_discoveries", {}).get("count", 0) > 0,
        tools_findings.get("alive_hosts", {}).get("count", 0) > 0,
        tools_findings.get("harvested_urls", {}).get("count", 0) > 0
    ])
    
    if has_tools_data:
        await manager.broadcast(scan_id, {
            "type": "ai_analysis",
            "status": "tools_analysis",
            "message": "🔧 Analyzing reconnaissance tool findings...",
            "progress": 95
        })
        
        logger.info(f"[AI Analysis] Running tools findings analysis for scan {scan_id}")
        tools_analysis = await analyze_tools_findings_with_llm(tools_findings, scan_id)
        
        await manager.broadcast(scan_id, {
            "type": "ai_analysis",
            "status": "tools_analysis_complete",
            "message": "✅ Tools analysis complete!",
            "progress": 98
        })
    
    # Aggregate results
    aggregated = {
        "report_generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "scan_id": scan_id,
        "total_ips_analyzed": total_entries,
        "chunks_processed": total_chunks,
        "llm_analysis_results": chunk_results,
        "all_discovered_cves": final_cve_list,
        "all_cves": final_cve_list,  # Alias for backward compatibility
        "tools_findings": {
            "nuclei_findings": tools_findings.get("nuclei_findings", {"count": 0, "by_severity": {}, "items": []}),
            "xss_findings": tools_findings.get("xss_findings", {"count": 0, "items": []}),
            "api_discoveries": tools_findings.get("api_discoveries", {"count": 0, "items": []}),
            "alive_hosts": tools_findings.get("alive_hosts", {"count": 0, "sample": []}),
            "harvested_urls": tools_findings.get("harvested_urls", {"count": 0, "with_params": 0, "sample": []})
        },
        "tools_analysis": tools_analysis  # AI opinion on tools findings
    }
    
    # Save report to database
    db = await get_db()
    await db.save_ai_analysis_report(scan_id, aggregated)
    logger.info(f"[AI Analysis] Saved report for scan {scan_id}")
    
    total_findings = sum(
        len(cr.get("analysis", {}).get("high_risk_assets", []))
        for cr in chunk_results
    )
    await manager.broadcast(scan_id, {
        "type": "ai_analysis",
        "status": "complete",
        "message": f"🎉 AI Analysis complete! {total_findings} high-risk findings identified.",
        "progress": 100,
        "total_ips": total_entries,
        "total_cves": len(final_cve_list),
        "chunks_processed": total_chunks
    })
    
    return aggregated
