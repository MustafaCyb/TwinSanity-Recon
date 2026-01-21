"""
TwinSanity Recon V2 - LangGraph Workflows Module

Defines complete AI workflows for security analysis.
Integrates with existing LLM providers and adds validation.
"""


import logging
from typing import Dict, Optional, Callable, Awaitable

from dashboard.langgraph_agents import (
    get_query_parser, get_context_builder, get_validator, get_formatter,
    run_analysis_pipeline, LANGGRAPH_AVAILABLE
)

logger = logging.getLogger("LangGraphWorkflows")


class SecurityAnalysisWorkflow:
    """
    Complete workflow for security analysis with validation.
    
    Features:
    - Query parsing for intent detection
    - Context optimization based on query type
    - Response validation with retry
    - Confidence scoring
    """
    
    def __init__(self, llm_call_func: Callable[[str], Awaitable[str]], max_retries: int = 1):
        """
        Initialize workflow.
        
        Args:
            llm_call_func: Async function to call LLM with prompt
            max_retries: Number of retry attempts on validation failure
        """
        self.llm_call = llm_call_func
        self.max_retries = max_retries
        self.parser = get_query_parser()
        self.context_builder = get_context_builder()
        self.validator = get_validator()
        self.formatter = get_formatter()
    
    async def run(self, query: str, scan_data: Dict) -> Dict:
        """
        Run the analysis workflow.
        
        Args:
            query: User's question
            scan_data: Scan results from database
        
        Returns:
            Dict with 'response', 'confidence', 'intent', 'validation'
        """
        return await run_analysis_pipeline(
            query=query,
            scan_data=scan_data,
            llm_call_func=self.llm_call,
            max_retries=self.max_retries
        )


class ChatWorkflow:
    """
    Stateful chat workflow with memory and validation.
    """
    
    def __init__(self, llm_call_func: Callable[[str], Awaitable[str]]):
        self.llm_call = llm_call_func
        self.validator = get_validator()
        self.history: list = []
    
    async def chat(self, message: str, scan_data: Dict) -> Dict:
        """
        Process a chat message with history.
        
        Args:
            message: User's message
            scan_data: Current scan context
        
        Returns:
            Dict with 'response', 'confidence'
        """
        # Build context with history
        context_builder = get_context_builder(max_tokens=3000)
        parsed = get_query_parser().parse(message)
        context = context_builder.build(scan_data, parsed)
        
        # Include recent history
        history_text = ""
        if self.history:
            recent = self.history[-6:]  # Last 3 exchanges
            history_lines = []
            for msg in recent:
                role = msg.get('role', 'user').upper()
                content = msg.get('content', '')[:200]
                history_lines.append(f"{role}: {content}")
            history_text = "\n--- RECENT CONVERSATION ---\n" + "\n".join(history_lines)
        
        prompt = f"""You are TwinSanity AI assistant. Answer the user's question about scan results.

{context}

{history_text}

USER: {message}

RULES:
- ONLY cite data from the scan context above
- Be concise and specific
- If data isn't available, say so

ASSISTANT:"""
        
        try:
            response = await self.llm_call(prompt)
            
            # Add to history
            self.history.append({'role': 'user', 'content': message})
            self.history.append({'role': 'assistant', 'content': response})
            
            # Validate
            validation = self.validator.validate(response, scan_data)
            
            return {
                'response': response,
                'confidence': validation['confidence'],
                'validation': validation
            }
        except Exception as e:
            logger.error(f"Chat failed: {e}")
            return {
                'response': f"Error: {str(e)}",
                'confidence': 0,
                'validation': {'passed': False, 'error': str(e)}
            }
    
    def clear_history(self):
        """Clear conversation history."""
        self.history = []


class DeepDiveWorkflow:
    """
    Multi-step deep analysis workflow for complex investigations.
    """
    
    def __init__(self, llm_call_func: Callable[[str], Awaitable[str]]):
        self.llm_call = llm_call_func
        self.validator = get_validator()
    
    async def investigate_cve(self, cve_id: str, scan_data: Dict) -> Dict:
        """
        Deep dive investigation of a specific CVE.
        
        Steps:
        1. Find all affected hosts
        2. Analyze impact
        3. Generate remediation steps
        """
        results = scan_data.get('results', {})
        
        # Step 1: Find affected hosts
        affected_hosts = []
        cve_details = None
        
        for ip, data in results.items():
            if not isinstance(data, dict):
                continue
            for cve in data.get('cve_details', []):
                cve_found = cve.get('cve_id', cve.get('id', ''))
                if cve_id.upper() in cve_found.upper():
                    affected_hosts.append({
                        'ip': ip,
                        'hostnames': data.get('hostnames', []),
                        'ports': data.get('internetdb', {}).get('data', {}).get('ports', [])
                    })
                    if not cve_details:
                        cve_details = cve
        
        if not affected_hosts:
            return {
                'response': f"CVE {cve_id} was not found in this scan.",
                'confidence': 1.0,
                'affected_hosts': []
            }
        
        # Step 2: Build investigation context
        host_list = "\n".join([
            f"- {h['ip']} ({', '.join(h['hostnames'][:2]) or 'no hostname'}): ports {h['ports'][:5]}"
            for h in affected_hosts[:20]
        ])
        
        prompt = f"""Investigate this vulnerability in detail:

## CVE: {cve_id}
CVSS: {cve_details.get('cvss', 'Unknown')}
Description: {cve_details.get('summary', 'No description available')}

## AFFECTED HOSTS ({len(affected_hosts)} total)
{host_list}

## INVESTIGATION TASKS
1. Explain what this vulnerability does technically
2. Describe the potential attack scenario
3. List the most critical affected hosts (highest risk)
4. Provide specific remediation steps
5. Suggest temporary mitigations

Provide a detailed security investigation report:"""
        
        try:
            response = await self.llm_call(prompt)
            validation = self.validator.validate(response, scan_data)
            
            return {
                'response': response,
                'cve_id': cve_id,
                'affected_hosts': affected_hosts,
                'cvss': cve_details.get('cvss'),
                'confidence': validation['confidence']
            }
        except Exception as e:
            return {
                'response': f"Investigation failed: {str(e)}",
                'cve_id': cve_id,
                'affected_hosts': affected_hosts,
                'confidence': 0
            }


# =============================================================================
# WORKFLOW FACTORY
# =============================================================================

_workflows: Dict[str, object] = {}


def get_analysis_workflow(llm_call_func: Callable) -> SecurityAnalysisWorkflow:
    """Get or create analysis workflow."""
    key = "analysis"
    if key not in _workflows:
        _workflows[key] = SecurityAnalysisWorkflow(llm_call_func)
    return _workflows[key]


def get_chat_workflow(llm_call_func: Callable) -> ChatWorkflow:
    """Get or create chat workflow."""
    key = "chat"
    if key not in _workflows:
        _workflows[key] = ChatWorkflow(llm_call_func)
    return _workflows[key]


def get_deep_dive_workflow(llm_call_func: Callable) -> DeepDiveWorkflow:
    """Get or create deep dive workflow."""
    key = "deep_dive"
    if key not in _workflows:
        _workflows[key] = DeepDiveWorkflow(llm_call_func)
    return _workflows[key]


def reset_workflows():
    """Reset all workflow instances."""
    global _workflows
    _workflows = {}
