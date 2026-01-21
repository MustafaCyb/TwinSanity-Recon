"""
TwinSanity Recon V2 - Advanced LLM Features

This module provides advanced features for improved reasoning:
- Hallucination detection by validating against scan data
- Self-consistency prompting for higher accuracy
- Conversation memory with smart summarization
- Response validation and confidence scoring
"""

import re
import time
import logging
from typing import Dict, List, Optional, Any, Set, Tuple
from dataclasses import dataclass, field

logger = logging.getLogger("LLMAdvanced")


# =============================================================================
# HALLUCINATION DETECTION
# =============================================================================

@dataclass
class ValidationResult:
    """Result of response validation against scan data."""
    is_valid: bool
    confidence: float
    issues: List[str] = field(default_factory=list)
    mentioned_cves: List[str] = field(default_factory=list)
    mentioned_ips: List[str] = field(default_factory=list)
    hallucinated_cves: List[str] = field(default_factory=list)
    hallucinated_ips: List[str] = field(default_factory=list)


class HallucinationDetector:
    """
    Detect potential hallucinations in LLM responses.
    
    Validates that CVE IDs, IPs, and other facts mentioned
    in the response actually exist in the scan data.
    """
    
    # Regex patterns for extraction
    CVE_PATTERN = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
    IP_PATTERN = re.compile(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b')
    CVSS_PATTERN = re.compile(r'CVSS[:\s]*(\d+\.?\d*)', re.IGNORECASE)
    
    def __init__(self, scan_results: Dict):
        """
        Initialize with scan results for validation.
        
        Args:
            scan_results: The scan results dictionary
        """
        self.scan_results = scan_results
        self.valid_ips: Set[str] = set()
        self.valid_cves: Set[str] = set()
        self.cve_to_cvss: Dict[str, float] = {}
        
        self._extract_valid_entities()
    
    def _extract_valid_entities(self):
        """Extract all valid CVEs and IPs from scan data."""
        for ip, data in self.scan_results.items():
            if not isinstance(data, dict):
                continue
            
            # Add IP
            self.valid_ips.add(ip)
            
            # Add CVEs
            for cve in data.get("cve_details", []):
                cve_id = cve.get("cve_id") or cve.get("id", "")
                if cve_id:
                    self.valid_cves.add(cve_id.upper())
                    cvss = float(cve.get("cvss") or cve.get("cvss3") or 0)
                    self.cve_to_cvss[cve_id.upper()] = cvss
            
            # Add raw vulns from internetdb
            idb = data.get("internetdb", {})
            if isinstance(idb, dict) and idb.get("ok"):
                for vuln in idb.get("data", {}).get("vulns", []):
                    self.valid_cves.add(vuln.upper())
    
    def validate_response(self, response: str) -> ValidationResult:
        """
        Validate an LLM response against scan data.
        
        Args:
            response: The LLM response text
        
        Returns:
            ValidationResult with confidence and issues
        """
        issues = []
        
        # Extract mentioned entities
        mentioned_cves = list(set(self.CVE_PATTERN.findall(response.upper())))
        mentioned_ips = list(set(self.IP_PATTERN.findall(response)))
        
        # Check for hallucinated CVEs
        hallucinated_cves = []
        for cve in mentioned_cves:
            if cve not in self.valid_cves:
                hallucinated_cves.append(cve)
                issues.append(f"CVE {cve} not found in scan data")
        
        # Check for hallucinated IPs
        hallucinated_ips = []
        for ip in mentioned_ips:
            # Skip common non-scan IPs
            if ip.startswith("127.") or ip.startswith("0.") or ip == "255.255.255.255":
                continue
            if ip not in self.valid_ips:
                hallucinated_ips.append(ip)
                issues.append(f"IP {ip} not in scan results")
        
        # Check for incorrect CVSS scores
        cvss_mentions = self.CVSS_PATTERN.findall(response)
        for score_str in cvss_mentions:
            score = float(score_str)
            # This is a rough check - could be improved with context
            if score > 10.0:
                issues.append(f"Invalid CVSS score mentioned: {score}")
        
        # Calculate confidence score
        total_entities = len(mentioned_cves) + len(mentioned_ips)
        hallucinated = len(hallucinated_cves) + len(hallucinated_ips)
        
        if total_entities == 0:
            confidence = 0.9  # No specific entities mentioned - neutral
        else:
            confidence = 1.0 - (hallucinated / total_entities) * 0.5
        
        # Penalize for each issue
        confidence = max(0.0, confidence - len(issues) * 0.1)
        
        return ValidationResult(
            is_valid=len(issues) == 0,
            confidence=round(confidence, 2),
            issues=issues,
            mentioned_cves=mentioned_cves,
            mentioned_ips=mentioned_ips,
            hallucinated_cves=hallucinated_cves,
            hallucinated_ips=hallucinated_ips
        )


# =============================================================================
# SELF-CONSISTENCY PROMPTING
# =============================================================================

class SelfConsistencyChecker:
    """
    Improve accuracy by generating multiple responses
    and finding consensus.
    """
    
    def __init__(self, llm_call_func):
        """
        Initialize with LLM call function.
        
        Args:
            llm_call_func: Async function(prompt, temperature) -> str
        """
        self.llm_call = llm_call_func
    
    async def get_consistent_response(
        self,
        prompt: str,
        n_samples: int = 3,
        base_temperature: float = 0.2
    ) -> Tuple[str, float]:
        """
        Generate multiple responses and find consensus.
        
        Args:
            prompt: The prompt to send
            n_samples: Number of responses to generate
            base_temperature: Starting temperature (increases per sample)
        
        Returns:
            Tuple of (consensus_response, consistency_score)
        """
        responses = []
        
        # Generate N responses with varying temperatures
        for i in range(n_samples):
            temp = base_temperature + (i * 0.1)
            try:
                response = await self.llm_call(prompt, temp)
                responses.append(response)
            except Exception as e:
                logger.warning(f"Sample {i+1} failed: {e}")
        
        if len(responses) < 2:
            # Not enough responses for consistency check
            return responses[0] if responses else "", 0.5
        
        # Find consensus using another LLM call
        consensus = await self._find_consensus(responses)
        
        # Calculate consistency score based on similarity
        score = self._calculate_consistency(responses)
        
        return consensus, score
    
    async def _find_consensus(self, responses: List[str]) -> str:
        """Use LLM to find consensus among responses."""
        n = len(responses)
        
        # Build comparison prompt
        response_text = ""
        for i, resp in enumerate(responses, 1):
            # Truncate long responses
            truncated = resp[:800] if len(resp) > 800 else resp
            response_text += f"\n--- RESPONSE {i} ---\n{truncated}\n"
        
        consensus_prompt = f"""You received {n} AI responses to the same security question.

{response_text}

Your task:
1. Identify FACTS that appear in MULTIPLE responses (likely accurate)
2. Identify claims that appear in only ONE response (potentially errors)
3. Synthesize a single, accurate answer from the common facts
4. Ignore any contradictions or unsupported claims

Return the consolidated, verified answer:"""
        
        return await self.llm_call(consensus_prompt, 0.1)
    
    def _calculate_consistency(self, responses: List[str]) -> float:
        """Calculate how consistent the responses are."""
        if len(responses) < 2:
            return 1.0
        
        # Simple word overlap calculation
        word_sets = [set(r.lower().split()) for r in responses]
        
        total_overlap = 0
        comparisons = 0
        
        for i in range(len(word_sets)):
            for j in range(i + 1, len(word_sets)):
                intersection = len(word_sets[i] & word_sets[j])
                union = len(word_sets[i] | word_sets[j])
                if union > 0:
                    total_overlap += intersection / union
                    comparisons += 1
        
        if comparisons == 0:
            return 0.5
        
        return round(total_overlap / comparisons, 2)


# =============================================================================
# CONVERSATION MEMORY
# =============================================================================

@dataclass
class Message:
    """A single conversation message."""
    role: str  # "user" or "assistant"
    content: str
    timestamp: float = field(default_factory=time.time)
    tokens: int = 0
    
    def __post_init__(self):
        self.tokens = len(self.content) // 4


class ConversationMemory:
    """
    Manage conversation history with token-aware summarization.
    
    Features:
    - Automatic compression when approaching token limit
    - Maintains recent context for coherent conversations
    - Summarizes old messages to preserve key information
    """
    
    def __init__(
        self,
        max_tokens: int = 4000,
        keep_recent: int = 5,
        summarize_func = None
    ):
        """
        Initialize conversation memory.
        
        Args:
            max_tokens: Maximum tokens for history
            keep_recent: Number of recent messages to always keep
            summarize_func: Optional async function for summarization
        """
        self.max_tokens = max_tokens
        self.keep_recent = keep_recent
        self.summarize_func = summarize_func
        
        self.messages: List[Message] = []
        self.summary: str = ""
        self.scan_context_summary: str = ""
    
    def add_message(self, role: str, content: str):
        """Add a new message to the conversation."""
        msg = Message(role=role, content=content)
        self.messages.append(msg)
        
        # Check if we need to compress
        if self._total_tokens() > self.max_tokens:
            self._compress_history()
    
    def _total_tokens(self) -> int:
        """Calculate total tokens in history."""
        msg_tokens = sum(m.tokens for m in self.messages)
        summary_tokens = len(self.summary) // 4
        return msg_tokens + summary_tokens
    
    def _compress_history(self):
        """Compress old messages into summary."""
        if len(self.messages) <= self.keep_recent:
            return
        
        # Split into old and recent
        old_messages = self.messages[:-self.keep_recent]
        self.messages = self.messages[-self.keep_recent:]
        
        # Summarize old messages
        old_text = "\n".join(
            f"{m.role.upper()}: {m.content[:100]}..."
            for m in old_messages
        )
        
        self.summary = f"[Previous conversation summary: Discussed {len(old_messages)} prior messages about security analysis. Key topics: {old_text[:300]}...]"
        
        logger.debug(f"Compressed {len(old_messages)} messages into summary")
    
    def get_context_messages(self) -> List[Dict[str, str]]:
        """
        Get messages formatted for LLM context.
        
        Returns:
            List of message dictionaries
        """
        result = []
        
        # Add summary as system message if exists
        if self.summary:
            result.append({
                "role": "system",
                "content": self.summary
            })
        
        # Add scan context if set
        if self.scan_context_summary:
            result.append({
                "role": "system",
                "content": f"Current scan context:\n{self.scan_context_summary}"
            })
        
        # Add recent messages
        for msg in self.messages:
            result.append({
                "role": msg.role,
                "content": msg.content
            })
        
        return result
    
    def set_scan_context(self, context_summary: str):
        """Set abbreviated scan context for conversation."""
        self.scan_context_summary = context_summary
    
    def clear(self):
        """Clear all conversation history."""
        self.messages = []
        self.summary = ""
    
    def get_stats(self) -> Dict[str, Any]:
        """Get memory statistics."""
        return {
            "total_messages": len(self.messages),
            "total_tokens": self._total_tokens(),
            "max_tokens": self.max_tokens,
            "has_summary": bool(self.summary),
            "has_scan_context": bool(self.scan_context_summary)
        }


# =============================================================================
# RESPONSE ENHANCEMENT
# =============================================================================

def add_confidence_to_response(
    response: str,
    validation: ValidationResult,
    include_warnings: bool = True
) -> str:
    """
    Add confidence indicator and warnings to response.
    
    Args:
        response: Original LLM response
        validation: Validation result from hallucination detection
        include_warnings: Whether to include specific issue warnings
    
    Returns:
        Enhanced response with confidence info
    """
    # Confidence badge
    if validation.confidence >= 0.9:
        badge = "✅ High Confidence"
    elif validation.confidence >= 0.7:
        badge = "⚠️ Moderate Confidence"
    else:
        badge = "❌ Low Confidence - Please Verify"
    
    enhanced = f"{response}\n\n---\n**{badge}** (Score: {validation.confidence:.0%})"
    
    if include_warnings and validation.issues:
        enhanced += "\n\n**⚠️ Potential Issues:**"
        for issue in validation.issues[:3]:  # Max 3 warnings
            enhanced += f"\n- {issue}"
    
    return enhanced
