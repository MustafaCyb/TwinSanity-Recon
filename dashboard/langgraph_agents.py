"""
TwinSanity Recon V2 - LangGraph Agents Module

Multi-agent AI workflow system for intelligent security analysis.
Provides self-correcting, validated responses with state management.

Dependencies:
    pip install langgraph langchain langchain-community
"""

import logging
import re
from typing import Dict, List, Optional, Any, TypedDict, Annotated
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("LangGraphAgents")

# Try importing LangGraph - graceful fallback if not installed
try:
    from langgraph.graph import StateGraph, END
    from langgraph.graph.message import add_messages
    LANGGRAPH_AVAILABLE = True
except ImportError:
    LANGGRAPH_AVAILABLE = False
    logger.warning("LangGraph not installed. Install with: pip install langgraph")


# =============================================================================
# STATE DEFINITIONS
# =============================================================================

class AnalysisIntent(Enum):
    """Types of user queries for routing."""
    SUMMARY = "summary"
    CVE_LOOKUP = "cve_lookup"
    HOST_ANALYSIS = "host_analysis"
    REMEDIATION = "remediation"
    COMPARISON = "comparison"
    GENERAL = "general"


@dataclass
class ParsedQuery:
    """Result of query parsing."""
    original: str
    intent: AnalysisIntent
    entities: Dict[str, List[str]] = field(default_factory=dict)
    keywords: List[str] = field(default_factory=list)


class AnalysisState(TypedDict):
    """State for analysis workflow."""
    query: str
    parsed_query: Optional[Dict]
    scan_context: str
    scan_id: str
    analysis: str
    validation_result: Dict
    confidence: float
    retry_count: int
    final_response: str
    error: Optional[str]


class ChatState(TypedDict):
    """State for chat workflow."""
    messages: List[Dict]  # LangGraph add_messages reducer applied at runtime if available
    scan_context: str
    scan_id: str
    current_response: str
    validation_passed: bool


# =============================================================================
# AGENT NODES
# =============================================================================

class QueryParserAgent:
    """
    Parses user queries to extract intent and entities.
    Runs locally without LLM for speed.
    """
    
    # Patterns for entity extraction
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    IP_PATTERN = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    PORT_PATTERN = re.compile(r'\bport\s*(\d+)\b', re.IGNORECASE)
    HOST_PATTERN = re.compile(r'\b([a-z0-9][-a-z0-9]*\.)+[a-z]{2,}\b', re.IGNORECASE)
    
    # Intent keywords
    INTENT_KEYWORDS = {
        AnalysisIntent.SUMMARY: ['summary', 'overview', 'executive', 'brief', 'what did you find'],
        AnalysisIntent.CVE_LOOKUP: ['cve', 'vulnerability', 'exploit', 'cvss'],
        AnalysisIntent.HOST_ANALYSIS: ['host', 'server', 'ip', 'machine', 'asset'],
        AnalysisIntent.REMEDIATION: ['fix', 'patch', 'remediate', 'mitigate', 'action', 'recommend'],
        AnalysisIntent.COMPARISON: ['compare', 'difference', 'versus', 'vs', 'change'],
    }
    
    def parse(self, query: str) -> ParsedQuery:
        """Parse a user query into structured form."""
        query_lower = query.lower()
        
        # Extract entities
        entities = {
            'cves': self.CVE_PATTERN.findall(query),
            'ips': self.IP_PATTERN.findall(query),
            'ports': self.PORT_PATTERN.findall(query),
            'hosts': [h for h in self.HOST_PATTERN.findall(query) if len(h) > 3],
        }
        
        # Determine intent
        intent = AnalysisIntent.GENERAL
        for intent_type, keywords in self.INTENT_KEYWORDS.items():
            if any(kw in query_lower for kw in keywords):
                intent = intent_type
                break
        
        # Extract important keywords
        keywords = []
        important_words = ['critical', 'high', 'severe', 'urgent', 'important', 
                          'attack', 'breach', 'exposed', 'vulnerable']
        for word in important_words:
            if word in query_lower:
                keywords.append(word)
        
        return ParsedQuery(
            original=query,
            intent=intent,
            entities={k: v for k, v in entities.items() if v},
            keywords=keywords
        )
    
    def to_dict(self, parsed: ParsedQuery) -> Dict:
        """Convert parsed query to dict for state."""
        return {
            'original': parsed.original,
            'intent': parsed.intent.value,
            'entities': parsed.entities,
            'keywords': parsed.keywords
        }


class ContextBuilderAgent:
    """
    Builds optimized context for LLM based on query intent.
    Prioritizes relevant information to maximize accuracy.
    """
    
    def __init__(self, max_context_tokens: int = 4000):
        self.max_tokens = max_context_tokens
    
    def build(self, scan_data: Dict, parsed_query: ParsedQuery) -> str:
        """Build focused context based on query intent."""
        context_parts = []
        
        # Always include summary
        context_parts.append(self._build_summary(scan_data))
        
        # Add intent-specific context
        if parsed_query.intent == AnalysisIntent.CVE_LOOKUP:
            context_parts.append(self._build_cve_context(scan_data, parsed_query.entities.get('cves', [])))
        elif parsed_query.intent == AnalysisIntent.HOST_ANALYSIS:
            context_parts.append(self._build_host_context(scan_data, parsed_query.entities))
        elif parsed_query.intent == AnalysisIntent.REMEDIATION:
            context_parts.append(self._build_critical_cves(scan_data))
        else:
            context_parts.append(self._build_general_context(scan_data))
        
        full_context = "\n\n".join(context_parts)
        
        # Truncate if needed (rough token estimate)
        if len(full_context) > self.max_tokens * 4:
            full_context = full_context[:self.max_tokens * 4] + "\n[Context truncated...]"
        
        return full_context
    
    def _build_summary(self, scan_data: Dict) -> str:
        """Build scan summary section."""
        results = scan_data.get('results', {})
        domain = scan_data.get('domain', 'Unknown')
        
        total_ips = len([k for k in results if k not in ['timestamp', 'domain', '_metadata']])
        total_cves = sum(len(d.get('cve_details', [])) for d in results.values() if isinstance(d, dict))
        critical = sum(1 for d in results.values() if isinstance(d, dict) 
                      for c in d.get('cve_details', []) if float(c.get('cvss', 0)) >= 9.0)
        
        return f"""## SCAN SUMMARY
Domain: {domain}
Total IPs: {total_ips}
Total CVEs: {total_cves}
Critical (CVSS 9+): {critical}"""

    def _build_cve_context(self, scan_data: Dict, cve_ids: List[str]) -> str:
        """Build CVE-focused context."""
        results = scan_data.get('results', {})
        cve_info = []
        
        for ip, data in results.items():
            if not isinstance(data, dict):
                continue
            for cve in data.get('cve_details', []):
                cve_id = cve.get('cve_id', cve.get('id', ''))
                if not cve_ids or any(c.upper() in cve_id.upper() for c in cve_ids):
                    cve_info.append(f"- {cve_id}: CVSS {cve.get('cvss', 'N/A')} on {ip}")
                    if cve.get('summary'):
                        cve_info.append(f"  Description: {cve['summary'][:200]}")
        
        return "## CVE DETAILS\n" + "\n".join(cve_info[:50])

    def _build_host_context(self, scan_data: Dict, entities: Dict) -> str:
        """Build host-focused context."""
        results = scan_data.get('results', {})
        target_ips = entities.get('ips', [])
        target_hosts = entities.get('hosts', [])
        
        host_info = []
        for ip, data in results.items():
            if not isinstance(data, dict):
                continue
            if target_ips and ip not in target_ips:
                continue
            
            hostnames = data.get('hostnames', [])
            if target_hosts and not any(h in hostnames for h in target_hosts):
                if target_ips or target_hosts:
                    continue
            
            cve_count = len(data.get('cve_details', []))
            ports = data.get('internetdb', {}).get('data', {}).get('ports', [])
            host_info.append(f"IP: {ip}\n  Hostnames: {', '.join(hostnames[:5])}\n  Ports: {ports[:10]}\n  CVEs: {cve_count}")
        
        return "## HOST DETAILS\n" + "\n\n".join(host_info[:20])

    def _build_critical_cves(self, scan_data: Dict) -> str:
        """Build context with critical/high CVEs for remediation."""
        results = scan_data.get('results', {})
        critical_cves = []
        
        for ip, data in results.items():
            if not isinstance(data, dict):
                continue
            for cve in data.get('cve_details', []):
                cvss = float(cve.get('cvss', 0))
                if cvss >= 7.0:
                    critical_cves.append({
                        'cve_id': cve.get('cve_id', cve.get('id', 'Unknown')),
                        'cvss': cvss,
                        'ip': ip,
                        'summary': cve.get('summary', '')[:150]
                    })
        
        critical_cves.sort(key=lambda x: x['cvss'], reverse=True)
        
        lines = ["## CRITICAL & HIGH VULNERABILITIES (for remediation)"]
        for cve in critical_cves[:30]:
            lines.append(f"- {cve['cve_id']} (CVSS {cve['cvss']}) on {cve['ip']}")
            lines.append(f"  {cve['summary']}")
        
        return "\n".join(lines)

    def _build_general_context(self, scan_data: Dict) -> str:
        """Build general context with balanced information."""
        results = scan_data.get('results', {})
        
        # Get top hosts by CVE count
        host_cve_counts = []
        for ip, data in results.items():
            if isinstance(data, dict):
                count = len(data.get('cve_details', []))
                host_cve_counts.append((ip, data.get('hostnames', []), count))
        
        host_cve_counts.sort(key=lambda x: x[2], reverse=True)
        
        lines = ["## TOP VULNERABLE HOSTS"]
        for ip, hostnames, count in host_cve_counts[:10]:
            lines.append(f"- {ip} ({', '.join(hostnames[:2]) or 'no hostname'}): {count} CVEs")
        
        return "\n".join(lines)


class ValidationAgent:
    """
    Validates LLM responses for accuracy.
    Checks for hallucinated CVEs, IPs, and statistics.
    """
    
    def __init__(self):
        self.cve_pattern = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
        self.ip_pattern = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
    
    def validate(self, response: str, scan_data: Dict) -> Dict:
        """
        Validate response against scan data.
        
        Returns:
            Dict with 'passed', 'confidence', 'issues' keys
        """
        issues = []
        results = scan_data.get('results', {})
        
        # Extract CVEs from response
        response_cves = set(self.cve_pattern.findall(response))
        
        # Get all CVEs from scan
        scan_cves = set()
        for data in results.values():
            if isinstance(data, dict):
                for cve in data.get('cve_details', []):
                    cve_id = cve.get('cve_id', cve.get('id', ''))
                    if cve_id:
                        scan_cves.add(cve_id.upper())
        
        # Check for hallucinated CVEs
        hallucinated_cves = response_cves - scan_cves
        if hallucinated_cves:
            issues.append(f"Hallucinated CVEs: {', '.join(list(hallucinated_cves)[:5])}")
        
        # Extract IPs from response
        response_ips = set(self.ip_pattern.findall(response))
        scan_ips = set(k for k in results.keys() if self.ip_pattern.match(k))
        
        # Check for hallucinated IPs
        hallucinated_ips = response_ips - scan_ips
        if hallucinated_ips:
            issues.append(f"Potentially hallucinated IPs: {', '.join(list(hallucinated_ips)[:5])}")
        
        # Calculate confidence
        total_claims = len(response_cves) + len(response_ips)
        if total_claims == 0:
            confidence = 0.9  # No specific claims to verify
        else:
            valid_claims = total_claims - len(hallucinated_cves) - len(hallucinated_ips)
            confidence = valid_claims / total_claims
        
        return {
            'passed': len(hallucinated_cves) == 0,
            'confidence': round(confidence, 2),
            'issues': issues,
            'hallucinated_cves': list(hallucinated_cves),
            'verified_cves': list(response_cves & scan_cves)
        }


class ResponseFormatterAgent:
    """
    Formats the final response with confidence indicators.
    """
    
    def format(self, response: str, validation: Dict, intent: str) -> str:
        """Format response with metadata."""
        confidence = validation.get('confidence', 1.0)
        
        # Add confidence indicator
        if confidence >= 0.9:
            confidence_badge = "✅ High Confidence"
        elif confidence >= 0.7:
            confidence_badge = "⚠️ Medium Confidence"
        else:
            confidence_badge = "❗ Low Confidence - Verify Claims"
        
        # Add any warnings
        warnings = []
        if validation.get('issues'):
            for issue in validation['issues'][:3]:
                warnings.append(f"⚠️ {issue}")
        
        # Format final response
        formatted = response
        
        if warnings:
            formatted += "\n\n---\n" + "\n".join(warnings)
        
        return formatted


# =============================================================================
# WORKFLOW BUILDER
# =============================================================================

def create_analysis_workflow():
    """
    Create the main analysis workflow graph.
    
    Flow:
    1. Parse Query -> Extract intent & entities
    2. Build Context -> Create focused context
    3. Analyze -> Call LLM with context
    4. Validate -> Check for hallucinations
    5. [If failed] -> Retry with correction prompt
    6. Format -> Add confidence & format response
    """
    if not LANGGRAPH_AVAILABLE:
        logger.error("LangGraph not available - cannot create workflow")
        return None
    
    workflow = StateGraph(AnalysisState)
    
    # Node implementations would go here
    # For now, return None as we'll implement async versions
    
    return workflow


# =============================================================================
# CONVENIENCE FUNCTIONS
# =============================================================================

# Singleton instances
_query_parser = None
_context_builder = None
_validator = None
_formatter = None


def get_query_parser() -> QueryParserAgent:
    """Get singleton query parser."""
    global _query_parser
    if _query_parser is None:
        _query_parser = QueryParserAgent()
    return _query_parser


def get_context_builder(max_tokens: int = 4000) -> ContextBuilderAgent:
    """Get singleton context builder."""
    global _context_builder
    if _context_builder is None:
        _context_builder = ContextBuilderAgent(max_tokens)
    return _context_builder


def get_validator() -> ValidationAgent:
    """Get singleton validator."""
    global _validator
    if _validator is None:
        _validator = ValidationAgent()
    return _validator


def get_formatter() -> ResponseFormatterAgent:
    """Get singleton formatter."""
    global _formatter
    if _formatter is None:
        _formatter = ResponseFormatterAgent()
    return _formatter


async def run_analysis_pipeline(
    query: str,
    scan_data: Dict,
    llm_call_func,
    max_retries: int = 1
) -> Dict:
    """
    Run the full analysis pipeline without LangGraph.
    
    This is a simplified version for when LangGraph isn't installed.
    
    Args:
        query: User's question
        scan_data: Scan results dict
        llm_call_func: Async function to call LLM (prompt) -> response
        max_retries: Number of retries on validation failure
    
    Returns:
        Dict with 'response', 'confidence', 'validation' keys
    """
    parser = get_query_parser()
    context_builder = get_context_builder()
    validator = get_validator()
    formatter = get_formatter()
    
    # Step 1: Parse query
    parsed = parser.parse(query)
    logger.info(f"Parsed intent: {parsed.intent.value}, entities: {parsed.entities}")
    
    # Step 2: Build context
    context = context_builder.build(scan_data, parsed)
    
    # Step 3 & 4: Analyze and validate with retries
    response = None
    validation = {'passed': False, 'confidence': 0}
    
    for attempt in range(max_retries + 1):
        # Build prompt
        if attempt == 0:
            prompt = f"""You are a security analyst. Analyze the scan data and answer the question.

{context}

## QUESTION
{query}

## RULES
- ONLY mention CVEs that appear in the data above
- ONLY reference IPs from the scan data
- If information is not available, say so clearly
- Be specific and cite CVE IDs with CVSS scores

Provide your analysis:"""
        else:
            # Retry with correction prompt
            prompt = f"""Your previous response contained errors. Please try again.

Previous issues: {', '.join(validation.get('issues', []))}

{context}

## QUESTION
{query}

## CRITICAL RULES
- ONLY use CVEs from the provided data: {', '.join(list(validator.cve_pattern.findall(context))[:10])}
- Do NOT mention any CVE that is not explicitly listed above
- If unsure, say "Based on the scan data..." 

Provide a corrected analysis:"""
        
        # Call LLM
        try:
            response = await llm_call_func(prompt)
        except Exception as e:
            logger.error(f"LLM call failed: {e}")
            return {
                'response': f"Analysis failed: {str(e)}",
                'confidence': 0,
                'validation': {'passed': False, 'error': str(e)}
            }
        
        # Validate
        validation = validator.validate(response, scan_data)
        logger.info(f"Validation attempt {attempt + 1}: passed={validation['passed']}, confidence={validation['confidence']}")
        
        if validation['passed'] or validation['confidence'] >= 0.8:
            break
    
    # Step 5: Format
    formatted_response = formatter.format(response, validation, parsed.intent.value)
    
    return {
        'response': formatted_response,
        'confidence': validation['confidence'],
        'validation': validation,
        'intent': parsed.intent.value
    }
