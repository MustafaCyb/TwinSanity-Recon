"""
LLM Results Reader Module for TwinSanity Recon

This module provides functionality to read, parse, and prepare scan results
for analysis by LLM (Large Language Model) providers.

Classes:
    ScanSummary: Dataclass containing aggregate scan statistics
    ScanFinding: Dataclass representing a single vulnerability finding
    LLMResultsReader: Main class for reading and processing scan results
"""

from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
import json
import re


@dataclass
class ScanSummary:
    """Aggregate statistics from a scan"""
    domain: str = ""
    total_ips: int = 0
    total_cves: int = 0
    critical_count: int = 0
    high_count: int = 0
    medium_count: int = 0
    low_count: int = 0
    total_ports: int = 0
    unique_ports: List[int] = field(default_factory=list)
    technologies: List[str] = field(default_factory=list)
    hostnames: List[str] = field(default_factory=list)
    scan_timestamp: str = ""


@dataclass
class ScanFinding:
    """A single vulnerability finding"""
    cve_id: str
    cvss: float
    severity: str
    summary: str
    ip: str
    hostname: str = ""
    port: Optional[int] = None
    tags: List[str] = field(default_factory=list)
    
    def __post_init__(self):
        # Normalize severity
        if self.cvss >= 9.0:
            self.severity = "critical"
        elif self.cvss >= 7.0:
            self.severity = "high"
        elif self.cvss >= 4.0:
            self.severity = "medium"
        else:
            self.severity = "low"


class LLMResultsReader:
    """
    Reader class for processing TwinSanity scan results for LLM analysis.
    
    This class loads JSON scan results, parses vulnerability data,
    and builds context strings optimized for LLM consumption.
    
    Attributes:
        results_dir: Base directory for scan results
        data: Raw loaded JSON data
        summary: Aggregated scan statistics
        findings: List of parsed vulnerability findings
    """
    
    # Regex patterns for CVE type classification
    CVE_TYPE_PATTERNS = {
        "sql_injection": re.compile(r"sql\s*inject|sqli|sql\s*command|database\s*query|mysql|postgres|oracle\s*sql", re.I),
        "xss": re.compile(r"cross.?site\s*script|xss|script\s*inject|javascript\s*inject|html\s*inject", re.I),
        "rce": re.compile(r"remote\s*code\s*exec|rce|command\s*exec|code\s*inject|arbitrary\s*code|shell\s*command", re.I),
        "path_traversal": re.compile(r"path\s*travers|directory\s*travers|\.\.\/|\.\.\\|file\s*inclus|lfi|rfi|local\s*file", re.I),
        "ssrf": re.compile(r"ssrf|server.?side\s*request|request\s*forgery|url\s*redirect", re.I),
        "xxe": re.compile(r"xxe|xml\s*external\s*entity|xml\s*inject|entity\s*expans", re.I),
        "auth_bypass": re.compile(r"auth.*bypass|bypass\s*auth|privilege\s*escal|access\s*control|permission|unauthorized", re.I),
        "dos": re.compile(r"denial\s*of\s*service|dos\b|ddos|resource\s*exhaust|infinite\s*loop|crash", re.I),
        "buffer_overflow": re.compile(r"buffer\s*overflow|stack\s*overflow|heap\s*overflow|memory\s*corrupt|out.?of.?bounds", re.I),
        "information_disclosure": re.compile(r"information\s*disclos|info\s*leak|sensitive\s*data|credential|password\s*expos", re.I),
    }
    
    TYPE_DISPLAY_NAMES = {
        "sql_injection": "SQL Injection (SQLi)",
        "xss": "Cross-Site Scripting (XSS)",
        "rce": "Remote Code Execution (RCE)",
        "path_traversal": "Path Traversal",
        "ssrf": "Server-Side Request Forgery (SSRF)",
        "xxe": "XML External Entity (XXE)",
        "auth_bypass": "Authentication Bypass",
        "dos": "Denial of Service (DoS)",
        "buffer_overflow": "Buffer Overflow",
        "information_disclosure": "Information Disclosure",
    }
    
    def __init__(self, results_dir: Optional[str] = None):
        """
        Initialize the reader.
        
        Args:
            results_dir: Base directory for scan results. If None, uses current directory.
        """
        self.results_dir = Path(results_dir) if results_dir else Path.cwd()
        self.data: Dict = {}
        self.summary: Optional[ScanSummary] = None
        self.findings: List[ScanFinding] = []
        self._ip_to_hostnames: Dict[str, List[str]] = {}
        self._hostname_to_ip: Dict[str, str] = {}
        
    def load_results_file(self, file_path: str) -> Tuple[bool, str]:
        """
        Load and parse a scan results JSON file.
        
        Args:
            file_path: Path to the JSON file (absolute or relative to results_dir)
            
        Returns:
            Tuple of (success: bool, message: str)
        """
        path = Path(file_path)
        
        # Try multiple locations
        if not path.is_absolute():
            candidates = [
                self.results_dir / path,
                self.results_dir / path.name,
                Path.cwd() / path,
            ]
        else:
            candidates = [path]
            
        # Find the file
        found_path = None
        for candidate in candidates:
            if candidate.exists():
                found_path = candidate
                break
                
        if not found_path:
            return False, f"File not found: {file_path}"
            
        # Read the file
        try:
            for encoding in ["utf-8", "utf-8-sig", "latin-1"]:
                try:
                    content = found_path.read_text(encoding=encoding)
                    self.data = json.loads(content)
                    break
                except UnicodeDecodeError:
                    continue
            else:
                return False, f"Failed to decode file with any encoding: {file_path}"
        except json.JSONDecodeError as e:
            return False, f"Invalid JSON in file: {e}"
        except Exception as e:
            return False, f"Error reading file: {e}"
            
        # Parse the data
        self._parse_data()
        return True, f"Loaded {len(self.findings)} findings from {found_path.name}"
    
    def _parse_data(self):
        """Parse the loaded JSON data into structured findings."""
        self.findings = []
        self._ip_to_hostnames = {}
        self._hostname_to_ip = {}
        
        # Initialize summary
        self.summary = ScanSummary()
        
        # Try different data structures
        results = None
        if "results" in self.data:
            results = self.data["results"]
            self.summary.domain = self.data.get("domain", "")
        elif "scan_results" in self.data:
            results = self.data["scan_results"]
            self.summary.domain = self.data.get("target_domain", "")
        elif isinstance(self.data, dict):
            # Assume the data itself is the results dict (IP -> data)
            results = self.data
            
        if not results:
            return
            
        all_ports = set()
        all_technologies = set()
        all_hostnames = []
        
        for ip, ip_data in results.items():
            if not isinstance(ip_data, dict):
                continue
                
            # Extract hostnames
            hosts = ip_data.get("hosts", [])
            if isinstance(hosts, str):
                hosts = [hosts]
            self._ip_to_hostnames[ip] = hosts
            for host in hosts:
                self._hostname_to_ip[host.lower()] = ip
                all_hostnames.append(host)
                
            # Extract ports and technologies from InternetDB
            idb = ip_data.get("internetdb", {})
            if isinstance(idb, dict) and idb.get("ok"):
                idb_data = idb.get("data", {})
                for port in idb_data.get("ports", []):
                    all_ports.add(port)
                for tag in idb_data.get("tags", []):
                    all_technologies.add(tag)
                    
            # Extract CVE details
            cve_details = ip_data.get("cve_details", [])
            for cve in cve_details:
                cve_id = cve.get("id") or cve.get("cve_id", "")
                cvss = float(cve.get("cvss") or cve.get("cvss_score") or 0)
                summary = cve.get("summary") or cve.get("description", "")
                
                finding = ScanFinding(
                    cve_id=cve_id,
                    cvss=cvss,
                    severity="",  # Will be set in __post_init__
                    summary=summary[:500],  # Truncate long summaries
                    ip=ip,
                    hostname=hosts[0] if hosts else "",
                    tags=list(all_technologies)
                )
                self.findings.append(finding)
                
        # Update summary
        self.summary.total_ips = len(results)
        self.summary.total_cves = len(self.findings)
        self.summary.critical_count = sum(1 for f in self.findings if f.severity == "critical")
        self.summary.high_count = sum(1 for f in self.findings if f.severity == "high")
        self.summary.medium_count = sum(1 for f in self.findings if f.severity == "medium")
        self.summary.low_count = sum(1 for f in self.findings if f.severity == "low")
        self.summary.unique_ports = sorted(all_ports)
        self.summary.total_ports = len(all_ports)
        self.summary.technologies = list(all_technologies)[:20]
        self.summary.hostnames = all_hostnames[:50]
        
        # Sort findings by CVSS descending
        self.findings.sort(key=lambda f: f.cvss, reverse=True)
        
    def classify_cve_type(self, cve_id: str, summary: str) -> List[str]:
        """
        Classify a CVE based on its ID and summary text.
        
        Args:
            cve_id: The CVE identifier
            summary: Description/summary of the CVE
            
        Returns:
            List of vulnerability type identifiers
        """
        types = []
        combined = f"{cve_id} {summary}"
        
        for vuln_type, pattern in self.CVE_TYPE_PATTERNS.items():
            if pattern.search(combined):
                types.append(vuln_type)
                
        return types if types else ["other"]
    
    def get_findings_by_type(self) -> Dict[str, List[ScanFinding]]:
        """
        Group findings by vulnerability type.
        
        Returns:
            Dict mapping vulnerability type to list of findings
        """
        by_type: Dict[str, List[ScanFinding]] = {}
        
        for finding in self.findings:
            types = self.classify_cve_type(finding.cve_id, finding.summary)
            for t in types:
                if t not in by_type:
                    by_type[t] = []
                by_type[t].append(finding)
                
        return by_type
    
    def get_findings_for_host(self, hostname_or_ip: str) -> List[ScanFinding]:
        """
        Get all findings for a specific host.
        
        Args:
            hostname_or_ip: Either a hostname or IP address
            
        Returns:
            List of findings for that host
        """
        # Try direct IP match
        if hostname_or_ip in self._ip_to_hostnames:
            return [f for f in self.findings if f.ip == hostname_or_ip]
            
        # Try hostname lookup
        hostname_lower = hostname_or_ip.lower()
        if hostname_lower in self._hostname_to_ip:
            ip = self._hostname_to_ip[hostname_lower]
            return [f for f in self.findings if f.ip == ip]
            
        # Try partial hostname match
        for hostname, ip in self._hostname_to_ip.items():
            if hostname_lower in hostname or hostname in hostname_lower:
                return [f for f in self.findings if f.ip == ip]
                
        return []
    
    def extract_query_keywords(self, query: str) -> Dict[str, Any]:
        """
        Extract relevant keywords and entities from a user query.
        
        Args:
            query: User's natural language query
            
        Returns:
            Dict containing extracted entities
        """
        query_lower = query.lower()
        extracted = {
            "cve_ids": [],
            "hostnames": [],
            "ips": [],
            "severity_filter": None,
            "vuln_types": [],
        }
        
        # Extract CVE IDs
        cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.I)
        extracted["cve_ids"] = cve_pattern.findall(query)
        
        # Extract severity filters
        if "critical" in query_lower:
            extracted["severity_filter"] = "critical"
        elif "high" in query_lower:
            extracted["severity_filter"] = "high"
        elif "medium" in query_lower:
            extracted["severity_filter"] = "medium"
        elif "low" in query_lower:
            extracted["severity_filter"] = "low"
            
        # Extract vulnerability types
        type_keywords = {
            "sql_injection": ["sqli", "sql injection", "sql-injection"],
            "xss": ["xss", "cross-site scripting"],
            "rce": ["rce", "remote code execution", "command injection"],
            "path_traversal": ["path traversal", "directory traversal", "lfi", "rfi"],
            "ssrf": ["ssrf", "request forgery"],
            "xxe": ["xxe", "xml injection"],
            "auth_bypass": ["auth bypass", "privilege escalation"],
            "dos": ["dos", "denial of service"],
            "buffer_overflow": ["buffer overflow", "overflow"],
        }
        
        for vuln_type, keywords in type_keywords.items():
            for kw in keywords:
                if kw in query_lower:
                    extracted["vuln_types"].append(vuln_type)
                    break
                    
        # Extract hostnames/IPs mentioned in query
        for hostname in self._hostname_to_ip.keys():
            if hostname in query_lower or hostname.split('.')[0] in query_lower:
                extracted["hostnames"].append(hostname)
                extracted["ips"].append(self._hostname_to_ip[hostname])
                
        return extracted
    
    def build_context_for_llm(
        self,
        query: Optional[str] = None,
        max_findings: int = 30,
        include_full_summary: bool = True,
        max_tokens: int = 8000
    ) -> str:
        """
        Build a context string optimized for LLM analysis with token budgeting.
        
        Args:
            query: Optional user query to focus the context
            max_findings: Maximum number of findings to include
            include_full_summary: Whether to include full summary stats
            max_tokens: Maximum tokens for the context (4 chars ≈ 1 token)
            
        Returns:
            Formatted context string for LLM consumption
        """
        # Token estimation helper
        def estimate_tokens(text: str) -> int:
            return len(text) // 4
        
        max_chars = max_tokens * 4  # Convert to character limit
        

        lines = []
        
        # Header
        lines.append("=" * 60)
        lines.append("TWINSANITY SECURITY SCAN RESULTS")
        lines.append("=" * 60)
        lines.append("")
        
        # Summary section
        if self.summary and include_full_summary:
            lines.append("=== SCAN SUMMARY ===")
            lines.append(f"Target Domain: {self.summary.domain}")
            lines.append(f"Total IPs Scanned: {self.summary.total_ips}")
            lines.append(f"Total CVEs Found: {self.summary.total_cves}")
            lines.append(f"  • Critical (CVSS >= 9.0): {self.summary.critical_count}")
            lines.append(f"  • High (CVSS 7.0-8.9): {self.summary.high_count}")
            lines.append(f"  • Medium (CVSS 4.0-6.9): {self.summary.medium_count}")
            lines.append(f"  • Low (CVSS < 4.0): {self.summary.low_count}")
            lines.append(f"Open Ports: {', '.join(map(str, self.summary.unique_ports[:15]))}")
            lines.append(f"Technologies: {', '.join(self.summary.technologies[:10])}")
            lines.append("")
            
        # Host mapping section
        lines.append("=== HOST MAPPINGS ===")
        for ip, hosts in list(self._ip_to_hostnames.items())[:20]:
            host_findings = [f for f in self.findings if f.ip == ip]
            if hosts:
                lines.append(f"• {ip} → {', '.join(hosts[:3])} ({len(host_findings)} CVEs)")
        lines.append("")
        
        # Process query if provided
        query_context = ""
        relevant_findings = self.findings
        
        if query:
            extracted = self.extract_query_keywords(query)
            
            # Filter by specific host if mentioned
            if extracted["hostnames"]:
                hostname = extracted["hostnames"][0]
                ip = extracted["ips"][0] if extracted["ips"] else None
                host_findings = self.get_findings_for_host(hostname)
                
                lines.append(f"=== CVEs FOR {hostname.upper()} ===")
                lines.append(f"IP: {ip}")
                lines.append(f"Total CVEs: {len(host_findings)}")
                lines.append("")
                
                for f in host_findings[:max_findings]:
                    types = self.classify_cve_type(f.cve_id, f.summary)
                    type_str = f" [{', '.join(types)}]" if types and types != ["other"] else ""
                    lines.append(f"[{f.severity.upper()}] {f.cve_id} (CVSS: {f.cvss}){type_str}")
                    lines.append(f"  {f.summary[:200]}")
                    lines.append("")
                    
                relevant_findings = host_findings
                
            # Filter by vulnerability type if mentioned
            if extracted["vuln_types"]:
                for vuln_type in extracted["vuln_types"]:
                    type_findings = []
                    for f in self.findings:
                        types = self.classify_cve_type(f.cve_id, f.summary)
                        if vuln_type in types:
                            type_findings.append(f)
                            
                    display_name = self.TYPE_DISPLAY_NAMES.get(vuln_type, vuln_type)
                    lines.append(f"=== {display_name} VULNERABILITIES ===")
                    
                    if type_findings:
                        lines.append(f"Found {len(type_findings)} CVEs:")
                        lines.append("")
                        for f in type_findings[:max_findings]:
                            lines.append(f"• {f.cve_id} (CVSS {f.cvss}) - {f.hostname or f.ip}")
                            lines.append(f"  {f.summary[:150]}")
                            lines.append("")
                    else:
                        lines.append("No CVEs of this type found in scan results.")
                    lines.append("")
                    
            # Filter by severity if mentioned
            if extracted["severity_filter"]:
                sev = extracted["severity_filter"]
                sev_findings = [f for f in relevant_findings if f.severity == sev]
                lines.append(f"=== {sev.upper()} SEVERITY FINDINGS ===")
                lines.append(f"Count: {len(sev_findings)}")
                lines.append("")
                for f in sev_findings[:max_findings]:
                    lines.append(f"• {f.cve_id} (CVSS {f.cvss}) - {f.hostname or f.ip}")
                    lines.append(f"  {f.summary[:150]}")
                    lines.append("")
                    
            # If specific CVE mentioned
            if extracted["cve_ids"]:
                for cve_id in extracted["cve_ids"]:
                    cve_findings = [f for f in self.findings if cve_id.upper() in f.cve_id.upper()]
                    if cve_findings:
                        f = cve_findings[0]
                        lines.append(f"=== DETAILS FOR {f.cve_id} ===")
                        lines.append(f"CVSS Score: {f.cvss}")
                        lines.append(f"Severity: {f.severity.upper()}")
                        lines.append(f"Affected Host: {f.hostname or f.ip} ({f.ip})")
                        lines.append(f"Description: {f.summary}")
                        lines.append("")
        
        # General vulnerability listing (if no specific query focus)
        if not query or (query and not any([
            self.extract_query_keywords(query)["hostnames"],
            self.extract_query_keywords(query)["vuln_types"],
            self.extract_query_keywords(query)["severity_filter"],
            self.extract_query_keywords(query)["cve_ids"]
        ])):
            lines.append("=== TOP VULNERABILITIES ===")
            for f in self.findings[:max_findings]:
                types = self.classify_cve_type(f.cve_id, f.summary)
                type_str = f" [{', '.join(types)}]" if types and types != ["other"] else ""
                lines.append(f"[{f.severity.upper()}] {f.cve_id} (CVSS: {f.cvss}){type_str}")
                lines.append(f"  Host: {f.hostname or f.ip}")
                lines.append(f"  {f.summary[:180]}")
                lines.append("")
                
        # CVE Type Summary
        by_type = self.get_findings_by_type()
        if by_type:
            lines.append("=== CVE CLASSIFICATION BY TYPE ===")
            for vuln_type, type_findings in sorted(by_type.items(), key=lambda x: len(x[1]), reverse=True):
                display_name = self.TYPE_DISPLAY_NAMES.get(vuln_type, vuln_type)
                lines.append(f"• {display_name}: {len(type_findings)} CVEs")
            lines.append("")
        
        # Build result with token budget enforcement
        result = "\n".join(lines)
        
        # Truncate if exceeding token budget
        if len(result) > max_chars:
            # Find a good breaking point
            truncate_at = max_chars - 100
            result = result[:truncate_at]
            # Try to break at a newline
            last_newline = result.rfind("\n")
            if last_newline > truncate_at - 500:
                result = result[:last_newline]
            result += f"\n\n[Context truncated at ~{estimate_tokens(result)} tokens]"
            
        return result
    
    def calculate_relevance_score(self, finding: ScanFinding, query: str) -> float:
        """
        Calculate a relevance score for a finding based on a query.
        
        Args:
            finding: The finding to score
            query: User query string
            
        Returns:
            Relevance score (higher = more relevant)
        """
        score = 0.0
        query_lower = query.lower()
        
        # CVSS contributes to base score
        score += finding.cvss * 0.5
        
        # CVE ID match
        if finding.cve_id.lower() in query_lower:
            score += 10.0
            
        # Hostname match
        if finding.hostname and finding.hostname.lower() in query_lower:
            score += 5.0
            
        # IP match
        if finding.ip in query:
            score += 3.0
            
        # Summary keyword match
        query_words = set(query_lower.split())
        summary_words = set(finding.summary.lower().split())
        common = query_words & summary_words
        score += len(common) * 0.5
        
        # Type match
        types = self.classify_cve_type(finding.cve_id, finding.summary)
        type_keywords = {
            "sql_injection": ["sqli", "sql", "injection", "database"],
            "xss": ["xss", "script", "scripting"],
            "rce": ["rce", "code", "execution", "command"],
        }
        for vuln_type, keywords in type_keywords.items():
            if vuln_type in types:
                for kw in keywords:
                    if kw in query_lower:
                        score += 3.0
                        break
                        
        return score
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get comprehensive statistics about the scan.
        
        Returns:
            Dict containing various statistics
        """
        by_type = self.get_findings_by_type()
        
        return {
            "domain": self.summary.domain if self.summary else "",
            "total_ips": self.summary.total_ips if self.summary else 0,
            "total_cves": len(self.findings),
            "severity_breakdown": {
                "critical": self.summary.critical_count if self.summary else 0,
                "high": self.summary.high_count if self.summary else 0,
                "medium": self.summary.medium_count if self.summary else 0,
                "low": self.summary.low_count if self.summary else 0,
            },
            "type_breakdown": {k: len(v) for k, v in by_type.items()},
            "top_affected_hosts": self._get_top_affected_hosts(),
            "ports": self.summary.unique_ports[:20] if self.summary else [],
            "technologies": self.summary.technologies if self.summary else [],
        }
        
    def _get_top_affected_hosts(self, limit: int = 10) -> List[Dict]:
        """Get hosts with the most vulnerabilities."""
        host_counts: Dict[str, Dict] = {}
        
        for finding in self.findings:
            key = finding.ip
            if key not in host_counts:
                host_counts[key] = {
                    "ip": finding.ip,
                    "hostname": finding.hostname,
                    "cve_count": 0,
                    "critical": 0,
                    "high": 0,
                }
            host_counts[key]["cve_count"] += 1
            if finding.severity == "critical":
                host_counts[key]["critical"] += 1
            elif finding.severity == "high":
                host_counts[key]["high"] += 1
                
        sorted_hosts = sorted(
            host_counts.values(),
            key=lambda x: (x["critical"], x["high"], x["cve_count"]),
            reverse=True
        )
        
        return sorted_hosts[:limit]


# Convenience function for quick context building
def build_llm_context_from_file(
    file_path: str,
    query: Optional[str] = None,
    results_dir: Optional[str] = None
) -> Tuple[bool, str, Optional[ScanSummary]]:
    """
    Convenience function to quickly build LLM context from a file.
    
    Args:
        file_path: Path to the JSON results file
        query: Optional user query
        results_dir: Base directory for results
        
    Returns:
        Tuple of (success, context_or_error, summary)
    """
    reader = LLMResultsReader(results_dir=results_dir)
    success, msg = reader.load_results_file(file_path)
    
    if not success:
        return False, msg, None
        
    context = reader.build_context_for_llm(query=query)
    return True, context, reader.summary


if __name__ == "__main__":
    # Test the reader
    import sys
    
    if len(sys.argv) < 2:
        print("Usage: python llm_results_reader.py <results_file.json> [query]")
        sys.exit(1)
        
    reader = LLMResultsReader()
    success, msg = reader.load_results_file(sys.argv[1])
    
    if not success:
        print(f"Error: {msg}")
        sys.exit(1)
        
    print(f"Loaded: {msg}")
    print()
    
    query = " ".join(sys.argv[2:]) if len(sys.argv) > 2 else None
    context = reader.build_context_for_llm(query=query, max_findings=20)
    print(context)
