"""
TwinSanity Recon V2 - Scan Context Management
Utilities for loading, processing, and summarizing scan results for AI contexts and reports.
"""
import json
import re
from pathlib import Path
from typing import Dict, List, Optional, Set
from dashboard.config import PROJECT_ROOT, logger
from dashboard.state import state

class ScanContextManager:
    """
    RAG-based context manager for feeding scan results to LLMs.
    Implements chunking, relevance scoring, and smart context building.
    """
    
    @staticmethod
    def read_scan_file(file_path: str) -> Optional[dict]:
        """
        Read scan results from JSON file with multiple encoding support.
        Returns the parsed JSON data or None on failure.
        """
        path = Path(file_path)
        if not path.exists():
            logger.error(f"Scan file not found: {file_path}")
            return None
        
        # Try multiple encodings
        for encoding in ["utf-8", "utf-8-sig", "latin-1", "cp1252"]:
            try:
                with open(path, "r", encoding=encoding) as f:
                    data = json.load(f)
                    logger.info(f"Successfully loaded scan file: {file_path} ({len(data)} entries)")
                    return data
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue
            except Exception as e:
                logger.error(f"Unexpected error reading {file_path}: {e}")
                return None
        
        logger.error(f"Failed to decode scan file with any encoding: {file_path}")
        return None
    
    @staticmethod
    def extract_findings_summary(results: dict) -> dict:
        """
        Extract a compact summary of findings for global AI context.
        This summary is included in every request to ensure AI knows the findings.
        """
        if not results:
            return {"error": "No results available"}
        
        # Metadata keys to exclude from IP counting
        metadata_keys = {"timestamp", "domain", "result_file", "findings_summary", "_metadata"}
        
        summary = {
            "total_ips": 0,
            "total_cves": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "top_cves": [],
            "affected_hosts": [],
            "open_ports": {},
            "technologies": set()
        }
        
        all_cves = []
        
        for ip, data in results.items():
            # Skip metadata keys
            if ip in metadata_keys or not isinstance(data, dict):
                continue
            
            summary["total_ips"] += 1
            hostname = data.get("hosts", [ip])[0] if data.get("hosts") else ip
            cves = data.get("cve_details", [])
            
            # Count CVEs by severity
            host_critical = 0
            for cve in cves:
                cvss = float(cve.get("cvss") or cve.get("cvss3") or 0)
                cve_entry = {
                    "id": cve.get("cve_id", cve.get("id", "Unknown")),
                    "cvss": cvss,
                    "summary": (cve.get("summary") or "")[:200],
                    "ip": ip,
                    "host": hostname
                }
                all_cves.append(cve_entry)
                
                if cvss >= 9.0:
                    summary["severity_counts"]["critical"] += 1
                    host_critical += 1
                elif cvss >= 7.0:
                    summary["severity_counts"]["high"] += 1
                elif cvss >= 4.0:
                    summary["severity_counts"]["medium"] += 1
                else:
                    summary["severity_counts"]["low"] += 1
            
            # Collect ports and technologies
            idb = data.get("internetdb", {})
            if idb.get("ok"):
                idb_data = idb.get("data", {})
                for port in idb_data.get("ports", []):
                    summary["open_ports"][port] = summary["open_ports"].get(port, 0) + 1
                for tag in idb_data.get("tags", []):
                    summary["technologies"].add(tag)
            
            # Track affected hosts
            if cves:
                summary["affected_hosts"].append({
                    "ip": ip,
                    "hostname": hostname,
                    "cve_count": len(cves),
                    "critical_count": host_critical
                })
        
        summary["total_cves"] = len(all_cves)
        
        # Sort and limit top CVEs
        all_cves.sort(key=lambda x: x["cvss"], reverse=True)
        summary["top_cves"] = all_cves[:25]  # Top 25 CVEs
        
        # Sort affected hosts by vulnerability count
        summary["affected_hosts"].sort(key=lambda x: x["cve_count"], reverse=True)
        summary["affected_hosts"] = summary["affected_hosts"][:15]  # Top 15 hosts
        
        # Convert set to list for JSON serialization
        summary["technologies"] = list(summary["technologies"])[:20]
        
        # Convert ports to sorted list
        top_ports = sorted(summary["open_ports"].items(), key=lambda x: x[1], reverse=True)[:15]
        summary["open_ports"] = [{"port": p, "count": c} for p, c in top_ports]
        
        return summary
    
    @staticmethod
    def build_global_ai_context(findings_summary: dict, user_question: str, domain: str = "Unknown", tools_findings: dict = None) -> str:
        """
        Build context for GLOBAL AI services (Gemini, Cloud).
        Includes full findings summary and tools findings so AI understands the security landscape.
        """
        context = f"""=== SECURITY RECONNAISSANCE FINDINGS ===
Target Domain: {domain}
Total IPs Discovered: {findings_summary.get('total_ips', 0)}
Total Vulnerabilities: {findings_summary.get('total_cves', 0)}

SEVERITY DISTRIBUTION:
- Critical (CVSS >= 9.0): {findings_summary.get('severity_counts', {}).get('critical', 0)}
- High (CVSS 7.0-8.9): {findings_summary.get('severity_counts', {}).get('high', 0)}
- Medium (CVSS 4.0-6.9): {findings_summary.get('severity_counts', {}).get('medium', 0)}
- Low (CVSS < 4.0): {findings_summary.get('severity_counts', {}).get('low', 0)}

MOST VULNERABLE HOSTS:
"""
        for host in findings_summary.get('affected_hosts', [])[:10]:
            context += f"• {host.get('hostname', host.get('ip'))} ({host.get('ip')}) - {host.get('cve_count')} CVEs ({host.get('critical_count')} critical)\n"
        
        context += "\nTOP VULNERABILITIES:\n"
        for cve in findings_summary.get('top_cves', [])[:15]:
            severity = "CRITICAL" if cve['cvss'] >= 9 else "HIGH" if cve['cvss'] >= 7 else "MEDIUM"
            context += f"• [{severity}] {cve['id']} (CVSS {cve['cvss']}) on {cve['host']}\n"
            context += f"  {cve['summary'][:150]}...\n"
        
        context += "\nDETECTED TECHNOLOGIES:\n"
        techs = findings_summary.get('technologies', [])
        context += ", ".join(techs[:15]) if techs else "Unknown"
        
        context += "\n\nOPEN PORTS:\n"
        for p in findings_summary.get('open_ports', [])[:10]:
            context += f"• Port {p['port']}: {p['count']} hosts\n"
        
        # Add tools findings if available
        if tools_findings:
            context += "\n\n=== BUG BOUNTY TOOLS FINDINGS ===\n"
            
            # Alive hosts
            alive = tools_findings.get('alive_hosts', {})
            if alive.get('count', 0) > 0:
                context += f"\nALIVE HOSTS ({alive['count']} total):\n"
                for h in alive.get('sample', [])[:10]:
                    context += f"• {h.get('url')} (Status: {h.get('status')}) - {h.get('title', 'No title')}\n"
            
            # Nuclei vulnerability findings
            nuclei = tools_findings.get('nuclei_findings', {})
            if nuclei.get('count', 0) > 0:
                context += f"\nVULNERABILITY SCAN FINDINGS ({nuclei['count']} total):\n"
                sev = nuclei.get('by_severity', {})
                if sev:
                    context += f"By Severity: {', '.join([f'{k}: {v}' for k, v in sev.items()])}\n"
                for f in nuclei.get('items', [])[:15]:
                    context += f"• [{f.get('severity', 'unknown').upper()}] {f.get('name')} - {f.get('host')}\n"
            
            # XSS findings
            xss = tools_findings.get('xss_findings', {})
            if xss.get('count', 0) > 0:
                context += f"\nXSS VULNERABILITIES FOUND ({xss['count']} total):\n"
                for x in xss.get('items', [])[:5]:
                    context += f"• XSS in parameter '{x.get('parameter')}' at {x.get('url')}\n"
            
            # API discoveries
            api = tools_findings.get('api_discoveries', {})
            if api.get('count', 0) > 0:
                context += f"\nAPI ENDPOINTS DISCOVERED ({api['count']} total):\n"
                for a in api.get('items', [])[:10]:
                    context += f"• {a.get('url')} (Type: {a.get('type')}, Status: {a.get('status')})\n"
            
            # Harvested URLs summary
            urls = tools_findings.get('harvested_urls', {})
            if urls.get('count', 0) > 0:
                context += f"\nHARVESTED URLs: {urls['count']} total ({urls.get('with_params', 0)} with parameters)\n"
        
        context += f"\n\n=== USER QUESTION ===\n{user_question}"
        
        return context


async def load_scan_results_for_llm(scan_id: str) -> dict:
    """
    Load scan results from memory, database, or file.
    PRIORITY: File-based loading is most reliable for LLM context.
    Returns dict with 'results', 'domain', 'result_file', 'findings_summary', and 'tools_findings'.
    """
    from dashboard.database import get_db
    
    results = None
    domain = "Unknown"
    result_file = None
    
    # PRIORITY 1: Try to load directly from results file (most reliable)
    results_dir = PROJECT_ROOT / "results"
    possible_files = [
        results_dir / f"scan_{scan_id}.json",
        results_dir / f"{scan_id}.json",
    ]
    
    # Also search for any file containing the scan_id
    if results_dir.exists():
        for json_file in results_dir.glob("*.json"):
            if scan_id in json_file.name and "cache" not in json_file.name.lower():
                possible_files.insert(0, json_file)
    
    for file_path in possible_files:
        if file_path.exists():
            loaded = ScanContextManager.read_scan_file(str(file_path))
            if loaded and len(loaded) > 0:
                results = loaded
                result_file = str(file_path)
                logger.info(f"[LLM Context] Loaded {len(results)} IPs from file: {file_path.name}")
                break
    
    # PRIORITY 2: Check memory state
    if not results:
        scan = state.get_scan(scan_id)
        if scan and scan.get("results"):
            results = scan["results"]
            domain = scan.get("config", {}).get("domain", scan.get("domain", "Unknown"))
            result_file = scan.get("result_file")
            logger.info(f"[LLM Context] Loaded {len(results)} IPs from memory state")
    
    # PRIORITY 3: Load from database and find file
    if not results:
        db = await get_db()
        db_scan = await db.get_scan_by_id(scan_id)
        
        if db_scan:
            domain = db_scan.get("domain", "Unknown")
            result_file = db_scan.get("result_file")
            
            if result_file:
                # Try to load from the database's recorded file path
                for try_path in [Path(result_file), results_dir / Path(result_file).name]:
                    if try_path.exists():
                        loaded = ScanContextManager.read_scan_file(str(try_path))
                        if loaded:
                            results = loaded
                            logger.info(f"[LLM Context] Loaded from DB path: {try_path}")
                            break
    
    if not results:
        logger.warning(f"[LLM Context] No results found for scan_id: {scan_id}")
        return None
    
    # Extract domain from hostnames if not set
    if domain == "Unknown":
        for ip, data in results.items():
            hosts = data.get("hosts", [])
            if hosts:
                hostname = hosts[0]
                parts = hostname.split(".")
                if len(parts) >= 2:
                    domain = ".".join(parts[-2:])
                    break
    
    # Build findings summary with proper CVE counting
    findings_summary = ScanContextManager.extract_findings_summary(results)
    
    # Load tools findings (nuclei, XSS, API discovery, alive hosts, harvested URLs)
    tools_findings = await load_tools_findings_for_llm(scan_id)
    
    return {
        "results": results,
        "domain": domain,
        "result_file": result_file,
        "findings_summary": findings_summary,
        "tools_findings": tools_findings
    }


async def load_tools_findings_for_llm(scan_id: str) -> dict:
    """
    Load all tools findings for a scan from the database.
    Returns dict with nuclei findings, XSS findings, API discoveries, alive hosts, and harvested URLs.
    """
    try:
        from dashboard.services.httpx_prober import get_alive_hosts
        from dashboard.services.nuclei_scanner import get_nuclei_findings
        from dashboard.services.url_harvester import get_harvested_urls
        from dashboard.services.xss_scanner import get_xss_findings
        from dashboard.services.api_discovery import get_api_discoveries
        
        # Load all tools findings
        alive_hosts = await get_alive_hosts(scan_id) or []
        nuclei_findings = await get_nuclei_findings(scan_id) or []
        xss_findings = await get_xss_findings(scan_id) or []
        api_discoveries = await get_api_discoveries(scan_id) or []
        harvested_urls = await get_harvested_urls(scan_id) or []
        
        # Build summary for AI (with null checks)
        summary = {
            "alive_hosts": {
                "count": len(alive_hosts),
                "sample": [
                    {"url": h.get("url") if h else "", "status": h.get("status_code") if h else 0, "title": (h.get("title", "") or "")[:50] if h else ""}
                    for h in alive_hosts[:15] if h
                ]
            },
            "nuclei_findings": {
                "count": len(nuclei_findings),
                "by_severity": {},
                "items": [
                    {"name": f.get("name"), "severity": f.get("severity"), "host": f.get("host")}
                    for f in nuclei_findings[:30]  # Top 30 findings for AI
                ]
            },
            "xss_findings": {
                "count": len(xss_findings),
                "items": [
                    {"url": f.get("url"), "parameter": f.get("parameter"), "payload": f.get("payload", "")[:50]}
                    for f in xss_findings[:10]
                ]
            },
            "api_discoveries": {
                "count": len(api_discoveries),
                "items": [
                    {"url": d.get("url"), "path": d.get("path"), "status": d.get("status_code"), "type": d.get("api_type")}
                    for d in api_discoveries[:20]
                ]
            },
            "harvested_urls": {
                "count": len(harvested_urls),
                "with_params": len([u for u in harvested_urls if u.get("has_params")]),
                "sample": [u.get("url") for u in harvested_urls]  # Include ALL URLs for reports, not limited
            }
        }
        
        # Count nuclei findings by severity
        for f in nuclei_findings:
            sev = f.get("severity", "unknown")
            summary["nuclei_findings"]["by_severity"][sev] = summary["nuclei_findings"]["by_severity"].get(sev, 0) + 1
        
        logger.info(f"[LLM Context] Loaded tools findings for {scan_id}: "
                    f"{len(alive_hosts)} alive, {len(nuclei_findings)} nuclei, "
                    f"{len(xss_findings)} XSS, {len(api_discoveries)} APIs")
        
        return summary
        
    except Exception as e:
        logger.warning(f"Failed to load tools findings for LLM: {e}")
        return {
            "alive_hosts": {"count": 0, "sample": []},
            "nuclei_findings": {"count": 0, "by_severity": {}, "items": []},
            "xss_findings": {"count": 0, "items": []},
            "api_discoveries": {"count": 0, "items": []},
            "harvested_urls": {"count": 0, "with_params": 0, "sample": []}
        }


# CVE Type Classification Patterns
CVE_TYPE_PATTERNS = {
    "sql_injection": [
        r"sql\s*injection", r"sqli", r"sql\s*inj", r"blind\s*sql", 
        r"union\s*based", r"error.based\s*sql", r"time.based\s*sql",
        r"database\s*injection", r"mysql\s*injection", r"postgres.*injection"
    ],
    "xss": [
        r"cross.site\s*scripting", r"\bxss\b", r"reflected\s*xss", 
        r"stored\s*xss", r"dom.based\s*xss", r"script\s*injection"
    ],
    "rce": [
        r"remote\s*code\s*execution", r"\brce\b", r"command\s*injection",
        r"code\s*injection", r"arbitrary\s*code", r"os\s*command",
        r"shell\s*injection", r"command\s*execution"
    ],
    "path_traversal": [
        r"path\s*traversal", r"directory\s*traversal", r"file\s*inclusion",
        r"lfi\b", r"rfi\b", r"local\s*file\s*inclusion", r"\.\./", 
        r"arbitrary\s*file\s*read"
    ],
    "ssrf": [
        r"server.side\s*request\s*forgery", r"\bssrf\b", 
        r"request\s*forgery", r"url\s*redirect"
    ],
    "xxe": [
        r"xml\s*external\s*entity", r"\bxxe\b", r"xml\s*injection"
    ],
    "auth_bypass": [
        r"authentication\s*bypass", r"auth\s*bypass", r"privilege\s*escalation",
        r"unauthorized\s*access", r"improper\s*authentication"
    ],
    "info_disclosure": [
        r"information\s*disclosure", r"sensitive\s*data", r"data\s*exposure",
        r"information\s*leak", r"credential\s*disclosure"
    ],
    "dos": [
        r"denial\s*of\s*service", r"\bdos\b", r"\bddos\b", 
        r"resource\s*exhaustion", r"crash", r"null\s*pointer"
    ],
    "buffer_overflow": [
        r"buffer\s*overflow", r"stack\s*overflow", r"heap\s*overflow",
        r"memory\s*corruption", r"out.of.bounds"
    ]
}


def classify_cve_type(cve_id: str, summary: str) -> List[str]:
    """
    Classify a CVE into vulnerability types based on its summary.
    Returns a list of matching types (can be multiple).
    """
    types = []
    text_to_search = f"{cve_id} {summary}".lower()
    
    for vuln_type, patterns in CVE_TYPE_PATTERNS.items():
        for pattern in patterns:
            if re.search(pattern, text_to_search, re.IGNORECASE):
                types.append(vuln_type)
                break  # Found a match for this type, move to next type
    
    return types if types else ["other"]


def get_cves_by_type(cves: List[dict]) -> Dict[str, List[dict]]:
    """
    Group CVEs by their vulnerability type.
    Returns a dict mapping type -> list of CVEs
    """
    cves_by_type = {}
    
    for cve in cves:
        cve_id = cve.get("id", cve.get("cve_id", ""))
        summary = cve.get("summary", cve.get("description", ""))
        types = classify_cve_type(cve_id, summary)
        
        for t in types:
            if t not in cves_by_type:
                cves_by_type[t] = []
            cves_by_type[t].append(cve)
    
    return cves_by_type
