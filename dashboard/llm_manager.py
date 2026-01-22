"""
TwinSanity Recon V2 - Flexible LLM Provider Manager

This module provides flexible, controlled LLM provider management with:
- Priority-based provider fallback chain
- Per-operation default providers
- Async non-blocking calls
- Rate limiting and error handling
- Audit logging for all LLM calls

"""

import asyncio
import logging
import time
import re
import os
from dataclasses import dataclass, field
from typing import Optional, List, Dict, Callable, Awaitable, Any, Tuple
from pathlib import Path
from enum import Enum

import aiohttp

# Try to import optional dependencies
try:
    from ollama import AsyncClient as OllamaAsyncClient
    OLLAMA_AVAILABLE = True
except ImportError:
    OLLAMA_AVAILABLE = False
    OllamaAsyncClient = None

try:
    import google.generativeai as genai
    GENAI_AVAILABLE = True
except ImportError:
    GENAI_AVAILABLE = False
    genai = None

logger = logging.getLogger("LLMManager")


def strip_thinking_tags(content: str) -> Tuple[str, Optional[str]]:
    """
    Strip <think>...</think> tags from LLM response content.
    
    Args:
        content: Raw LLM response content
        
    Returns:
        Tuple of (clean_content, thinking_content or None)
    """
    if not content:
        return "", None
    
    thinking = None
    
    # Extract thinking content if present
    think_match = re.search(r"<think>(.*?)</think>", content, re.DOTALL | re.IGNORECASE)
    if think_match:
        thinking = think_match.group(1).strip()
    
    # Remove all think tag variants
    cleaned = re.sub(r"<think>.*?</think>", "", content, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"<\|think\|>.*?<\|end_think\|>", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = re.sub(r"\[think\].*?\[/think\]", "", cleaned, flags=re.DOTALL | re.IGNORECASE)
    cleaned = cleaned.strip()
    
    return cleaned, thinking


class LLMOperation(Enum):
    """Types of LLM operations with different default providers."""
    ANALYSIS = "analysis"      # Scan result analysis
    CHAT = "chat"              # Interactive chat
    DEEP_ANALYSIS = "deep_analysis"  # Complex reasoning with thinking mode


@dataclass
class ProviderStatus:
    """Track provider health and rate limits."""
    name: str
    enabled: bool = True
    available: bool = True
    disabled_until: float = 0.0
    error_count: int = 0
    last_error: str = ""
    total_calls: int = 0
    total_tokens: int = 0


@dataclass
class LLMResponse:
    """Standardized LLM response container."""
    content: str
    provider: str
    model: str
    tokens_used: int = 0
    thinking: Optional[str] = None  # For thinking mode
    latency_ms: int = 0
    cached: bool = False
    confidence: float = 1.0


class LLMManager:
    """
    Flexible LLM provider management with fallback chain.
    
    Features:
    - Multiple providers: Gemini, Ollama Cloud, Local Ollama
    - Priority-based fallback when providers fail
    - Per-operation default providers (analysis vs chat)
    - Rate limit handling with exponential backoff
    - Streaming support via async generators
    - Audit logging for all calls
    """
    
    def __init__(self, config: Dict, api_keys: Optional[Dict] = None):
        """
        Initialize the LLM Manager.
        
        Args:
            config: LLM configuration from config.yaml
            api_keys: API keys from config.yaml (preferred) or will fallback to env
        """
        self.config = config
        self.providers: Dict[str, ProviderStatus] = {}
        self.audit_log: List[Dict] = []
        
        # Load API keys from config (preferred) or fallback to environment
        if api_keys:
            self.gemini_api_key = api_keys.get("gemini", "") or os.getenv("GEMINI_API_KEY", "")
            self.ollama_api_key = api_keys.get("ollama_cloud", "") or os.getenv("OLLAMA_API_KEY", "")
        else:
            self.gemini_api_key = os.getenv("GEMINI_API_KEY", "")
            self.ollama_api_key = os.getenv("OLLAMA_API_KEY", "")
        
        # Initialize providers
        self._setup_providers()
        
        logger.info(f"LLMManager initialized with {len(self.providers)} providers")
    
    def _setup_providers(self):
        """Initialize provider configurations and status."""
        providers_config = self.config.get("providers", {})
        
        # Gemini
        gemini_cfg = providers_config.get("gemini", {})
        if gemini_cfg.get("enabled") and self.gemini_api_key:
            self.providers["gemini"] = ProviderStatus(
                name="gemini",
                enabled=True,
                available=True
            )
            if GENAI_AVAILABLE:
                genai.configure(api_key=self.gemini_api_key)
            logger.info(f"Gemini provider enabled: {gemini_cfg.get('model', 'gemini-2.0-flash')}")
        
        # Ollama Cloud
        cloud_cfg = providers_config.get("ollama_cloud", {})
        if cloud_cfg.get("enabled"):
            self.providers["ollama_cloud"] = ProviderStatus(
                name="ollama_cloud",
                enabled=True,
                available=True
            )
            logger.info(f"Ollama Cloud enabled: {cloud_cfg.get('host', 'https://ollama.com')}")
        
        # Local Ollama
        local_cfg = providers_config.get("local", {})
        if local_cfg.get("enabled", True):  # Enabled by default
            self.providers["local"] = ProviderStatus(
                name="local",
                enabled=True,
                available=OLLAMA_AVAILABLE
            )
            logger.info(f"Local Ollama enabled: {local_cfg.get('host', 'http://127.0.0.1:11434')}")
    
    def get_fallback_chain(self) -> List[str]:
        """Get ordered list of providers to try."""
        chain = self.config.get("fallback_chain", ["gemini", "ollama_cloud", "local"])
        # Filter to only enabled and available providers
        return [p for p in chain if p in self.providers and self.providers[p].enabled]
    
    def get_default_provider(self, operation: LLMOperation) -> str:
        """Get the default provider for an operation type."""
        defaults = self.config.get("defaults", {})
        return defaults.get(operation.value, "local")
    
    def is_provider_available(self, provider: str) -> bool:
        """Check if a provider is currently available (not rate-limited)."""
        if provider not in self.providers:
            return False
        status = self.providers[provider]
        if not status.enabled or not status.available:
            return False
        if time.time() < status.disabled_until:
            return False
        return True
    
    async def call(
        self,
        prompt: str,
        operation: LLMOperation = LLMOperation.CHAT,
        preferred_provider: Optional[str] = None,
        model_override: Optional[str] = None,
        temperature: float = 0.1,
        max_tokens: int = 4096,
        timeout: int = 120,
        enable_thinking: bool = False,
        structured_output: Optional[Dict] = None
    ) -> LLMResponse:
        """
        Call LLM with flexible provider selection and fallback.
        
        Args:
            prompt: The prompt to send
            operation: Type of operation (affects default provider)
            preferred_provider: Specific provider to try first
            model_override: Override the default model
            temperature: Sampling temperature (lower = more deterministic)
            max_tokens: Maximum tokens in response
            timeout: Request timeout in seconds
            enable_thinking: Enable thinking mode for supported models
            structured_output: JSON schema for structured output
        
        Returns:
            LLMResponse with content and metadata
        
        Raises:
            HTTPException: If all providers fail
        """
        start_time = time.time()
        
        # Determine provider order
        if preferred_provider and self.is_provider_available(preferred_provider):
            providers_to_try = [preferred_provider]
        else:
            providers_to_try = []
        
        # Add default for this operation
        default = self.get_default_provider(operation)
        if default not in providers_to_try and self.is_provider_available(default):
            providers_to_try.append(default)
        
        # Add remaining from fallback chain
        for p in self.get_fallback_chain():
            if p not in providers_to_try and self.is_provider_available(p):
                providers_to_try.append(p)
        
        if not providers_to_try:
            raise Exception("No LLM providers available")
        
        errors = []
        
        for provider in providers_to_try:
            try:
                logger.info(f"Trying provider: {provider}")
                
                if provider == "gemini":
                    response = await self._call_gemini(
                        prompt, model_override, temperature, max_tokens, timeout
                    )
                elif provider == "ollama_cloud":
                    response = await self._call_ollama_cloud(
                        prompt, model_override, temperature, max_tokens, timeout
                    )
                elif provider == "local":
                    response = await self._call_ollama_local(
                        prompt, model_override, temperature, max_tokens, timeout,
                        enable_thinking, structured_output
                    )
                else:
                    continue
                
                # Success - update stats
                self.providers[provider].total_calls += 1
                self.providers[provider].error_count = 0
                
                response.latency_ms = int((time.time() - start_time) * 1000)
                
                # Audit log
                self._log_call(provider, operation, len(prompt), response)
                
                return response
                
            except Exception as e:
                error_msg = str(e)[:100]
                errors.append(f"{provider}: {error_msg}")
                logger.warning(f"Provider {provider} failed: {error_msg}")
                
                # Update provider status
                self.providers[provider].error_count += 1
                self.providers[provider].last_error = error_msg
                
                # Check for rate limiting
                if "rate" in error_msg.lower() or "429" in error_msg:
                    # Disable for 60 seconds
                    self.providers[provider].disabled_until = time.time() + 60
                    logger.warning(f"Provider {provider} rate limited, disabled for 60s")
        
        # All providers failed
        raise Exception(f"All LLM providers failed: {'; '.join(errors)}")
    
    async def _call_gemini(
        self,
        prompt: str,
        model: Optional[str],
        temperature: float,
        max_tokens: int,
        timeout: int
    ) -> LLMResponse:
        """Call Gemini API."""
        if not self.gemini_api_key:
            raise Exception("GEMINI_API_KEY not configured")
        
        gemini_cfg = self.config.get("providers", {}).get("gemini", {})
        model_name = model or gemini_cfg.get("model", "gemini-2.0-flash")
        
        # Try SDK first (with executor to avoid blocking)
        if GENAI_AVAILABLE:
            try:
                loop = asyncio.get_event_loop()
                model_obj = genai.GenerativeModel(model_name)
                
                response = await asyncio.wait_for(
                    loop.run_in_executor(
                        None,
                        lambda: model_obj.generate_content(
                            prompt,
                            generation_config=genai.GenerationConfig(
                                temperature=temperature,
                                max_output_tokens=max_tokens
                            )
                        )
                    ),
                    timeout=timeout
                )
                
                # Safely extract text
                text = ""
                if hasattr(response, 'text') and response.text:
                    text = response.text
                elif hasattr(response, 'candidates') and response.candidates:
                    for candidate in response.candidates:
                        if hasattr(candidate, 'content') and candidate.content:
                            parts = getattr(candidate.content, 'parts', [])
                            for part in parts:
                                if hasattr(part, 'text') and part.text:
                                    text = part.text
                                    break
                
                if not text:
                    raise Exception("Gemini returned empty response")
                
                return LLMResponse(
                    content=text,
                    provider="gemini",
                    model=model_name,
                    tokens_used=len(text) // 4
                )
            except asyncio.TimeoutError:
                raise Exception(f"Gemini SDK timeout after {timeout}s")
            except Exception as e:
                if "quota" in str(e).lower() or "429" in str(e):
                    raise Exception("Gemini quota exceeded")
                raise
        
        # REST API fallback
        import httpx
        
        url = gemini_cfg.get("url", "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent")
        url = url.format(model=model_name)
        
        headers = {
            "Content-Type": "application/json",
            "x-goog-api-key": self.gemini_api_key
        }
        
        payload = {
            "contents": [{"parts": [{"text": prompt}]}],
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens
            }
        }
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=15)) as client:
            response = await client.post(url, json=payload, headers=headers)
            
            if response.status_code == 200:
                data = response.json()
                candidates = data.get('candidates', [])
                text = ""
                if candidates:
                    content = candidates[0].get('content', {})
                    parts = content.get('parts', [])
                    if parts:
                        text = parts[0].get('text', '')
                
                if not text:
                    raise Exception("Gemini REST returned empty response")
                
                # Strip any thinking tags from response
                clean_text, _ = strip_thinking_tags(text)
                return LLMResponse(
                    content=clean_text,
                    provider="gemini",
                    model=model_name
                )
            elif response.status_code == 429:
                raise Exception("Gemini rate limited (429)")
            else:
                error_text = response.text[:100]
                raise Exception(f"Gemini API error {response.status_code}: {error_text}")
    
    async def _call_ollama_cloud(
        self,
        prompt: str,
        model: Optional[str],
        temperature: float,
        max_tokens: int,
        timeout: int
    ) -> LLMResponse:
        """Call Ollama Cloud API using async HTTP."""
        import httpx
        
        cloud_cfg = self.config.get("providers", {}).get("ollama_cloud", {})
        host = cloud_cfg.get("host", "https://ollama.com")
        model_name = model or cloud_cfg.get("model", "llama3.1:latest")
        
        headers = {"Content-Type": "application/json"}
        if self.ollama_api_key:
            headers["Authorization"] = f"Bearer {self.ollama_api_key}"
        
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "stream": False,
            "options": {
                "temperature": temperature,
                "num_predict": max_tokens
            }
        }
        
        async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=15)) as client:
            response = await client.post(
                f"{host}/api/chat",
                json=payload,
                headers=headers
            )
            
            if response.status_code == 200:
                data = response.json()
                content = data.get("message", {}).get("content", "")
                if not content:
                    raise Exception("Empty response from Ollama Cloud")
                # Strip any thinking tags from response
                clean_content, _ = strip_thinking_tags(content)
                return LLMResponse(
                    content=clean_content,
                    provider="ollama_cloud",
                    model=model_name
                )
            elif response.status_code == 429:
                raise Exception("Rate limited by Ollama Cloud")
            elif response.status_code == 404:
                raise Exception(f"Model '{model_name}' not found on Ollama Cloud")
            else:
                error_text = response.text[:100]
                raise Exception(f"Ollama Cloud error {response.status_code}: {error_text}")
    
    async def _call_ollama_local(
        self,
        prompt: str,
        model: Optional[str],
        temperature: float,
        max_tokens: int,
        timeout: int,
        enable_thinking: bool = False,
        structured_output: Optional[Dict] = None
    ) -> LLMResponse:
        """Call local Ollama with async HTTP client."""
        import httpx
        
        local_cfg = self.config.get("providers", {}).get("local", {})
        host = local_cfg.get("host", "http://127.0.0.1:11434")
        
        # Select model based on operation
        if enable_thinking:
            model_name = model or local_cfg.get("models", {}).get("reasoning", "deepseek-r1:8b")
        else:
            model_name = model or local_cfg.get("models", {}).get("default", "llama3.2:3b")
        
        # Build options with memory-safe defaults
        options = {
            "temperature": temperature,
            "num_predict": min(max_tokens, 2048),
            "num_ctx": 4096,  # Conservative for memory safety
        }
        
        # Build messages
        messages = [{"role": "user", "content": prompt}]
        
        # Build payload
        payload = {
            "model": model_name,
            "messages": messages,
            "stream": False,
            "options": options
        }
        
        # Add structured output if provided
        if structured_output:
            payload["format"] = structured_output
        
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(timeout, connect=10)) as client:
                response = await client.post(
                    f"{host}/api/chat",
                    json=payload
                )
                
                if response.status_code == 200:
                    result = response.json()
                    content = result.get("message", {}).get("content", "")
                    
                    if not content:
                        raise Exception("Empty response from Ollama")
                    
                    # Use centralized think tag stripping
                    clean_content, thinking = strip_thinking_tags(content)
                    
                    return LLMResponse(
                        content=clean_content,
                        provider="local",
                        model=model_name,
                        thinking=thinking
                    )
                elif response.status_code == 404:
                    raise Exception(f"Model '{model_name}' not found. Run: ollama pull {model_name}")
                else:
                    error_text = response.text[:100]
                    if "alloc" in error_text.lower() or "memory" in error_text.lower():
                        raise Exception(f"Out of memory - try a smaller model")
                    raise Exception(f"Ollama error {response.status_code}: {error_text}")
                    
        except httpx.TimeoutException:
            raise Exception(f"Local Ollama timeout after {timeout}s - model may be loading")
        except httpx.ConnectError:
            raise Exception(f"Cannot connect to Ollama at {host}. Run: ollama serve")
    
    async def stream(
        self,
        prompt: str,
        model_override: Optional[str] = None,
        provider: str = "local"
    ):
        """
        Stream LLM response tokens using async HTTP.
        
        Yields:
            Dict with 'token' key for each token
        """
        import httpx
        
        if provider != "local":
            # Non-streaming fallback
            response = await self.call(prompt, preferred_provider=provider)
            yield {"token": response.content, "done": True}
            return
        
        local_cfg = self.config.get("providers", {}).get("local", {})
        host = local_cfg.get("host", "http://127.0.0.1:11434")
        model_name = model_override or local_cfg.get("models", {}).get("default", "llama3.2:3b")
        
        payload = {
            "model": model_name,
            "messages": [{"role": "user", "content": prompt}],
            "stream": True,
            "options": {
                "num_ctx": 4096,
                "num_predict": 2048,
            }
        }
        
        try:
            async with httpx.AsyncClient(timeout=httpx.Timeout(120, connect=10)) as client:
                async with client.stream(
                    "POST",
                    f"{host}/api/chat",
                    json=payload
                ) as response:
                    if response.status_code != 200:
                        yield {"token": f"Error: HTTP {response.status_code}", "done": True}
                        return
                    
                    import json as json_mod
                    async for line in response.aiter_lines():
                        if line.strip():
                            try:
                                chunk = json_mod.loads(line)
                                content = chunk.get("message", {}).get("content", "")
                                done = chunk.get("done", False)
                                yield {
                                    "token": content,
                                    "done": done
                                }
                            except json_mod.JSONDecodeError:
                                continue
        except httpx.TimeoutException:
            yield {"token": "Error: Request timeout", "done": True}
        except httpx.ConnectError:
            yield {"token": "Error: Cannot connect to Ollama", "done": True}
        except Exception as e:
            yield {"token": f"Error: {str(e)[:50]}", "done": True}
    
    def _log_call(self, provider: str, operation: LLMOperation, prompt_size: int, response: LLMResponse):
        """Log LLM call for auditing."""
        log_entry = {
            "timestamp": time.time(),
            "provider": provider,
            "operation": operation.value,
            "prompt_chars": prompt_size,
            "response_chars": len(response.content),
            "latency_ms": response.latency_ms,
            "model": response.model
        }
        self.audit_log.append(log_entry)
        
        # Keep only last 1000 entries
        if len(self.audit_log) > 1000:
            self.audit_log = self.audit_log[-1000:]
        
        logger.info(f"LLM call: {provider}/{response.model} - {prompt_size} chars in, {len(response.content)} chars out, {response.latency_ms}ms")
    
    def get_provider_status(self) -> Dict[str, Dict]:
        """Get current status of all providers."""
        return {
            name: {
                "enabled": status.enabled,
                "available": status.available and time.time() >= status.disabled_until,
                "error_count": status.error_count,
                "last_error": status.last_error,
                "total_calls": status.total_calls
            }
            for name, status in self.providers.items()
        }
    
    def get_audit_summary(self) -> Dict:
        """Get summary of recent LLM calls."""
        if not self.audit_log:
            return {"total_calls": 0}
        
        by_provider = {}
        for entry in self.audit_log:
            p = entry["provider"]
            if p not in by_provider:
                by_provider[p] = {"count": 0, "total_latency": 0}
            by_provider[p]["count"] += 1
            by_provider[p]["total_latency"] += entry["latency_ms"]
        
        return {
            "total_calls": len(self.audit_log),
            "by_provider": {
                p: {
                    "count": stats["count"],
                    "avg_latency_ms": stats["total_latency"] // stats["count"] if stats["count"] > 0 else 0
                }
                for p, stats in by_provider.items()
            }
        }


# Singleton instance
_llm_manager: Optional[LLMManager] = None


def get_llm_manager(config: Optional[Dict] = None, api_keys: Optional[Dict] = None) -> LLMManager:
    """Get or create the global LLM manager instance."""
    global _llm_manager
    if _llm_manager is None:
        if config is None:
            raise ValueError("Config required for first initialization")
        _llm_manager = LLMManager(config, api_keys)
    return _llm_manager
