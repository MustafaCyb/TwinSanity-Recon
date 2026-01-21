"""
TwinSanity Recon V2 - Chat & AI Router
LLM analysis and chat endpoints.
"""
import json
import re
from fastapi import APIRouter, HTTPException, Request, Depends

from dashboard.config import logger
from dashboard.llm_manager import LLMOperation
from dashboard.dependencies import require_auth

router = APIRouter(prefix="/api/llm", tags=["AI & Chat"])

# Maximum message length to prevent DoS
MAX_MESSAGE_LENGTH = 10000

# Prompt injection protection patterns
PROMPT_INJECTION_PATTERNS = [
    r'ignore\s+(previous|all|above|prior)\s+(instructions?|prompts?|messages?)',
    r'disregard\s+(the\s+)?(above|previous|prior)',
    r'forget\s+(everything|all|previous)',
    r'new\s+instructions?:',
    r'system\s*:\s*',
    r'<\|.*?\|>',  # Common LLM control tokens
    r'\[INST\]',
    r'\[/INST\]',
    r'<<SYS>>',
    r'<</SYS>>',
    r'assistant:\s*ignore',
    r'human:\s*ignore',
]

def sanitize_user_message(message: str) -> str:
    """
    Sanitize user input to mitigate prompt injection attacks.
    Returns sanitized message with potentially harmful patterns removed.
    """
    if not message:
        return ""
    
    # Truncate overly long messages
    sanitized = message[:MAX_MESSAGE_LENGTH]
    
    # Remove or neutralize common injection patterns
    for pattern in PROMPT_INJECTION_PATTERNS:
        sanitized = re.sub(pattern, '[filtered]', sanitized, flags=re.IGNORECASE)
    
    # Escape any remaining angle brackets that might be interpreted as control tokens
    # But preserve legitimate HTML-like content by only escaping specific patterns
    sanitized = re.sub(r'<\|(.*?)\|>', r'[|\1|]', sanitized)
    
    return sanitized.strip()



@router.get("/status")
async def get_llm_status(_request: Request, _session: dict = Depends(require_auth)):
    """Get status of LLM availability and configured providers."""
    from dashboard.llm_manager import get_llm_manager
    from dashboard.config import (
        GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, 
        GITHUB_TOKEN, OLLAMA_API_KEY, OLLAMA_CLOUD_HOST,
        GEMINI_MODEL, OLLAMA_CLOUD_MODEL, OLLAMA_LOCAL_MODEL
    )
    import httpx
    from dashboard.config import OLLAMA_LOCAL_HOST
    
    llm_manager = get_llm_manager()
    
    # Check local Ollama availability
    local_available = False
    local_models = []
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{OLLAMA_LOCAL_HOST}/api/tags")
            if r.status_code == 200:
                local_available = True
                local_models = [m.get("name") for m in r.json().get("models", [])]
    except Exception:
        pass
    
    # Check Ollama Cloud - available if API key is configured
    ollama_cloud_available = bool(OLLAMA_API_KEY and OLLAMA_CLOUD_HOST)
    
    # Use actual model names from config.yaml
    providers = {
        "local": {
            "available": local_available, 
            "name": "Ollama (Local)",
            "models": local_models,
            "running_models": local_models[:3] if local_models else [],
            "model": local_models[0] if local_models else OLLAMA_LOCAL_MODEL
        },
        "ollama_cloud": {
            "available": ollama_cloud_available, 
            "name": "Ollama (Cloud)",
            "configured": bool(OLLAMA_API_KEY),
            "model": OLLAMA_CLOUD_MODEL  # From config.yaml: deepseek-v3.1:671b
        },
        "gemini": {
            "available": bool(GEMINI_API_KEY), 
            "name": "Google Gemini",
            "configured": bool(GEMINI_API_KEY),
            "model": GEMINI_MODEL  # From config.yaml: gemini-2.5-flash
        },
        "openai": {
            "available": bool(OPENAI_API_KEY), 
            "name": "OpenAI GPT-4",
            "configured": bool(OPENAI_API_KEY),
            "model": "gpt-4o-mini"
        },
        "anthropic": {
            "available": bool(ANTHROPIC_API_KEY), 
            "name": "Claude 3.5 Sonnet",
            "configured": bool(ANTHROPIC_API_KEY),
            "model": "claude-3.5-sonnet"
        },
        "github": {
            "available": bool(GITHUB_TOKEN), 
            "name": "GitHub Models",
            "configured": bool(GITHUB_TOKEN),
            "model": "gpt-4o-mini"
        }
    }
        
    return {
        "status": "online" if llm_manager else "offline",
        "providers": providers,
        "active_provider": "local" if local_available else ("ollama_cloud" if ollama_cloud_available else "gemini"),
        "module_loaded": bool(llm_manager)
    }


@router.get("/provider-models")
async def get_provider_models(_request: Request, _session: dict = Depends(require_auth)):
    """
    Get available models per provider from config.yaml.
    Used for dynamic model selection in the UI.
    """
    from dashboard.config import (
        GEMINI_API_KEY, OPENAI_API_KEY, ANTHROPIC_API_KEY, 
        GITHUB_TOKEN, OLLAMA_API_KEY, OLLAMA_CLOUD_HOST,
        GEMINI_MODEL, OLLAMA_CLOUD_MODEL, OLLAMA_LOCAL_MODEL,
        load_config
    )
    import httpx
    from dashboard.config import OLLAMA_LOCAL_HOST
    
    # Load config to get provider-specific models
    config = load_config()
    llm_config = config.get('llm', {}).get('providers', {})
    
    # Get local Ollama models (from running instance)
    local_models = []
    local_available = False
    try:
        async with httpx.AsyncClient(timeout=3) as client:
            r = await client.get(f"{OLLAMA_LOCAL_HOST}/api/tags")
            if r.status_code == 200:
                local_available = True
                local_models = [m.get("name") for m in r.json().get("models", [])]
    except Exception:
        pass
    
    # Build models for each provider
    result = {}
    
    # Local Ollama - from running instance or config
    local_config = llm_config.get('local', {})
    local_config_models = local_config.get('models', {})
    result['local'] = {
        'available': local_available,
        'name': 'Ollama (Local)',
        'models': []
    }
    if local_models:
        for model in local_models[:10]:  # Limit to 10
            is_default = model == OLLAMA_LOCAL_MODEL or model == local_config_models.get('default')
            result['local']['models'].append({
                'id': model,
                'name': model.replace(':latest', '').replace(':', ' ').title(),
                'default': is_default
            })
    elif local_config_models:
        # Use config models if Ollama not running
        for key, model in local_config_models.items():
            result['local']['models'].append({
                'id': model,
                'name': f"{model.split(':')[0].title()} ({key.title()})",
                'default': key == 'default'
            })
    
    # --- Helper to parse config models ---
    def get_models_list(config_key, default_models=None):
        """
        Parses 'models' from config, which can be a list or a dict (id: name).
        Falls back to default_models (list of dicts) if config is missing.
        """
        provider_conf = llm_config.get(config_key, {})
        config_models = provider_conf.get('models')
        
        # If config is empty, fallback
        if not config_models:
            # Special case for legacy single 'model' key (backward compatibility)
            single_model = provider_conf.get('model')
            if single_model:
                return [{'id': single_model, 'name': single_model.replace('-', ' ').title(), 'default': True}]
            return default_models or []

        # Parse config models
        models_list = []
        
        # Case A: List of strings (ID only)
        if isinstance(config_models, list):
            for i, mid in enumerate(config_models):
                models_list.append({
                    'id': mid,
                    'name': mid.replace('-', ' ').replace(':', ' ').title(),
                    'default': i == 0
                })
                
        # Case B: Dict (ID -> Name)
        elif isinstance(config_models, dict):
            first = True
            for mid, mname in config_models.items():
                models_list.append({
                    'id': mid,
                    'name': mname,
                    'default': first
                })
                first = False
                
        return models_list

    # --- Ollama Cloud ---
    result['ollama_cloud'] = {
        'available': bool(OLLAMA_API_KEY and OLLAMA_CLOUD_HOST),
        'name': 'Ollama (Cloud)',
        'models': get_models_list('ollama_cloud', [
            {'id': OLLAMA_CLOUD_MODEL, 'name': OLLAMA_CLOUD_MODEL.replace(':', ' ').title(), 'default': True}
        ])
    }
    
    # --- Gemini ---
    result['gemini'] = {
        'available': bool(GEMINI_API_KEY),
        'name': 'Google Gemini',
        'models': get_models_list('gemini', [
            {'id': GEMINI_MODEL, 'name': GEMINI_MODEL.replace('-', ' ').title(), 'default': True}
        ])
    }
    
    # --- OpenAI ---
    result['openai'] = {
        'available': bool(OPENAI_API_KEY),
        'name': 'OpenAI',
        'models': get_models_list('openai', [
            {'id': 'gpt-4o', 'name': 'GPT-4o (Best)', 'default': True},
            {'id': 'gpt-4o-mini', 'name': 'GPT-4o Mini (Fast)'},
            {'id': 'gpt-4-turbo', 'name': 'GPT-4 Turbo'}
        ])
    }
    
    # --- Anthropic ---
    result['anthropic'] = {
        'available': bool(ANTHROPIC_API_KEY),
        'name': 'Claude',
        'models': get_models_list('anthropic', [
            {'id': 'claude-3-5-sonnet-20241022', 'name': 'Claude 3.5 Sonnet', 'default': True},
            {'id': 'claude-3-haiku-20240307', 'name': 'Claude 3 Haiku'}
        ])
    }
    
    # --- GitHub Models ---
    result['github'] = {
        'available': bool(GITHUB_TOKEN),
        'name': 'GitHub Models',
        'models': get_models_list('github', [
            {'id': 'gpt-4o', 'name': 'GPT-4o (GitHub)', 'default': True},
            {'id': 'gpt-4o-mini', 'name': 'GPT-4o Mini (GitHub)'}
        ])
    }
    
    return result


@router.post("/validate")
async def validate_llm_provider(request: Request, _session: dict = Depends(require_auth)):
    """
    Validate connectivity to a specific LLM provider and model.
    Attempts a minimal generation to verified credentials and model access.
    """
    from dashboard.llm_manager import get_llm_manager
    import time
    
    try:
        data = await request.json()
        provider = data.get('provider')
        model = data.get('model')
        
        if not provider or not model:
            return {"success": False, "message": "Missing provider or model"}
            
        print(f"Validating connection to {provider}:{model}...")
        
        # Get LLM manager
        llm = get_llm_manager()
        if not llm:
            return {"success": False, "message": "LLM Manager not initialized"}
            
        # Specific minimal test logic per provider
        start_time = time.time()
        
        # Test prompt - minimal to save tokens/time
        test_message = "Hi"
        
        # We need to temporarily force the provider to test it without changing system state
        # Or we can reuse the analyze method but with a dummy prompt
        # Better: use the underlying provider logic directly if possible, or simple analysis call
        
        # For simplicity and robustness, we'll try to generate a very short response
        # Using the existing analyze_chunk or similar method might be overkill
        # Let's use the unified generate_content method if available, or fallback
        
        # We'll use a direct provider check based on the 'provider' string
        success = False
        message = ""
        
        if provider == 'openai':
            from dashboard.config import OPENAI_API_KEY
            if not OPENAI_API_KEY:
                return {"success": False, "message": "API Key not configured"}
            
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://api.openai.com/v1/chat/completions",
                    headers={"Authorization": f"Bearer {OPENAI_API_KEY}"},
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": "Hi"}],
                        "max_tokens": 5
                    }
                )
                if resp.status_code == 200:
                    success = True
                else:
                    message = f"Error {resp.status_code}: {resp.text}"
                    
        elif provider == 'anthropic':
            from dashboard.config import ANTHROPIC_API_KEY
            if not ANTHROPIC_API_KEY:
                return {"success": False, "message": "API Key not configured"}
                
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    "https://api.anthropic.com/v1/messages",
                    headers={
                        "x-api-key": ANTHROPIC_API_KEY,
                        "anthropic-version": "2023-06-01",
                        "content-type": "application/json"
                    },
                    json={
                        "model": model,
                        "max_tokens": 5,
                        "messages": [{"role": "user", "content": "Hi"}]
                    }
                )
                if resp.status_code == 200:
                    success = True
                else:
                    message = f"Error {resp.status_code}: {resp.text}"

        elif provider == 'gemini':
            from dashboard.config import GEMINI_API_KEY
            if not GEMINI_API_KEY:
                return {"success": False, "message": "API Key not configured"}
            
            # Simple check via URL construction
            url = f"https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent?key={GEMINI_API_KEY}"
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                resp = await client.post(
                    url,
                    json={"contents": [{"parts": [{"text": "Hi"}]}]}
                )
                if resp.status_code == 200:
                    success = True
                elif resp.status_code == 429:
                    success = False
                    message = "Rate Limited (429)"
                else:
                    message = f"Error {resp.status_code}: {resp.text[:100]}"

        elif provider == 'ollama_cloud':
            from dashboard.config import OLLAMA_API_KEY, OLLAMA_CLOUD_HOST
            if not OLLAMA_API_KEY or not OLLAMA_CLOUD_HOST:
                return {"success": False, "message": "Host or API Key not configured"}
                
            import httpx
            async with httpx.AsyncClient(timeout=20.0) as client:
                resp = await client.post(
                    f"{OLLAMA_CLOUD_HOST}/api/generate",
                    headers={"Authorization": f"Bearer {OLLAMA_API_KEY}"},
                    json={"model": model, "prompt": "Hi", "stream": False}
                )
                if resp.status_code == 200:
                    success = True
                elif resp.status_code == 404:
                    message = f"Model '{model}' not found on server"
                else:
                    message = f"Error {resp.status_code}"

        elif provider == 'github':
            from dashboard.config import GITHUB_TOKEN
            if not GITHUB_TOKEN:
                return {"success": False, "message": "GitHub Token not configured"}
                
            import httpx
            async with httpx.AsyncClient(timeout=15.0) as client:
                # GitHub Models endpoint structure varies, using Azure AI inference format
                resp = await client.post(
                    "https://models.inference.ai.azure.com/chat/completions",
                    headers={"Authorization": f"Bearer {GITHUB_TOKEN}"},
                    json={
                        "model": model,
                        "messages": [{"role": "user", "content": "Hi"}],
                        "max_tokens": 5
                    }
                )
                if resp.status_code == 200:
                    success = True
                else:
                    message = f"Error {resp.status_code}: {resp.text[:100]}"
                    
        elif provider == 'local':
             # Local is usually safe if it shows up, but we can verify
             from dashboard.config import OLLAMA_LOCAL_HOST
             import httpx
             # Increased timeout for local models that need to load into VRAM
             async with httpx.AsyncClient(timeout=60.0) as client:
                try:
                    r = await client.post(
                        f"{OLLAMA_LOCAL_HOST}/api/generate",
                        json={"model": model, "prompt": "Hi", "stream": False}
                    )
                    if r.status_code == 200:
                        success = True
                    else:
                        message = f"Error {r.status_code}"
                except httpx.TimeoutException:
                     message = "Timeout (Model Loading)"
                except Exception as e:
                    message = str(e)
        
        latency = (time.time() - start_time) * 1000
        return {
            "success": success,
            "latency": f"{latency:.0f}ms",
            "message": message or "Connected"
        }
        
    except Exception as e:
        print(f"Validation error: {e}")
        return {"success": False, "message": str(e)}
    from dashboard.llm_manager import get_llm_manager
    from dashboard.llm_cache import get_llm_cache
    from dashboard.scan_context import load_scan_results_for_llm
    from dashboard.prompts import build_analysis_prompt
    from dashboard.llm_advanced import HallucinationDetector
    
    llm_manager = get_llm_manager()
    llm_cache = get_llm_cache()
    
    # Check if LLM modules are functional
    LLM_MODULES_AVAILABLE = llm_manager is not None
    
    body = await request.json()
    # Simple adapter for request body to namespace object
    class AnalysisRequestAdapter:
        def __init__(self, d):
            self.scan_id = d.get("scan_id")
            self.query = d.get("query", "Analyze the security posture based on these findings")
            self.provider = d.get("provider", "gemini")
            self.enable_thinking_mode = d.get("enable_thinking_mode", False)
            self.use_chain_of_thought = d.get("use_chain_of_thought", False)
            self.validate_response = d.get("validate_response", False)
    
    req_adapter = AnalysisRequestAdapter(body)
    
    if not LLM_MODULES_AVAILABLE or not llm_manager:
        raise HTTPException(503, "Enhanced LLM features not available")
    
    # Load scan data
    scan_data = await load_scan_results_for_llm(req_adapter.scan_id)
    if not scan_data:
        raise HTTPException(404, "Scan not found or no results")
    
    # Build Context
    max_tokens = 25000 if req_adapter.provider == "gemini" else 8000
    if req_adapter.provider == "anthropic":
        max_tokens = 90000
    
    try:
        from dashboard.llm_results_reader import LLMResultsReader
        reader = LLMResultsReader("")
        reader.raw_data = scan_data
        reader._parse_scan_data()
        context = reader.build_context_for_llm(
            query=req_adapter.query,
            max_findings=50,
            max_tokens=max_tokens
        )
    except Exception as e:
        logger.warning(f"LLMResultsReader failed, using simple context: {e}")
        context = json.dumps(scan_data, indent=2)[:max_tokens * 4]
    
    # Build prompt
    prompt = build_analysis_prompt(context, req_adapter.query, use_cot=req_adapter.use_chain_of_thought)
    
    # Check cache
    cache_key = f"{req_adapter.scan_id}:{req_adapter.query[:100]}"
    cached_response = None
    if llm_cache:
        cached_response = llm_cache.get(cache_key, "analysis")
    
    if cached_response:
        return {
            "response": cached_response,
            "provider": "cache",
            "cached": True,
            "validation": None
        }
    
    # Determine operation type
    operation = LLMOperation.DEEP_ANALYSIS if req_adapter.enable_thinking_mode else LLMOperation.ANALYSIS
    
    # Call LLM
    try:
        response = await llm_manager.call(
            prompt=prompt,
            operation=operation,
            preferred_provider=req_adapter.provider,
            enable_thinking=req_adapter.enable_thinking_mode,
            temperature=0.1
        )
    except Exception as e:
        raise HTTPException(503, f"LLM call failed: {e}")
    
    # Cache response
    if llm_cache:
        llm_cache.put(cache_key, "analysis", response.content, response.provider)
    
    # Validate response
    validation_result = None
    if req_adapter.validate_response:
        try:
            detector = HallucinationDetector(scan_data)
            validation_result = detector.validate_response(response.content)
        except Exception as e:
            logger.warning(f"Hallucination detection failed: {e}")
    
    return {
        "response": response.content,
        "provider": response.provider,
        "model": response.model,
        "latency_ms": response.latency_ms,
        "thinking": response.thinking,
        "cached": False,
        "validation": {
            "confidence": validation_result.confidence if validation_result else None,
            "is_valid": validation_result.is_valid if validation_result else None,
            "issues": validation_result.issues if validation_result else []
        } if validation_result else None
    }


@router.post("/chat")
async def enhanced_llm_chat(request: Request):
    """
    Enhanced chat with conversation memory and context.
    """
    from dashboard.llm_manager import get_llm_manager
    from dashboard.llm_advanced import ConversationMemory
    from dashboard.state import conversation_memories
    from dashboard.config import RESULTS_DIR
    from dashboard.llm_manager import LLMOperation
    from dashboard.prompts import build_chat_prompt
    
    # Simple system prompt if not imported
    CHAT_SYSTEM_PROMPT = "You are TwinSanity AI, a cybersecurity expert."
    
    llm_manager = get_llm_manager()
    LLM_MODULES_AVAILABLE = llm_manager is not None
    
    body = await request.json()
    
    # Simple Adapter
    class ChatRequestAdapter:
        def __init__(self, d):
            self.scan_id = d.get("scan_id")
            self.message = d.get("message")
            self.provider = d.get("provider", "gemini")
            self.use_context = d.get("use_context", True)

    req_adapter = ChatRequestAdapter(body)
    
    # Security: Validate and sanitize user message
    if not req_adapter.message or not req_adapter.message.strip():
        raise HTTPException(400, "Message cannot be empty")
    
    if len(req_adapter.message) > MAX_MESSAGE_LENGTH:
        raise HTTPException(400, f"Message too long. Maximum {MAX_MESSAGE_LENGTH} characters")
    
    # Sanitize message to prevent prompt injection
    sanitized_message = sanitize_user_message(req_adapter.message)
    
    if not LLM_MODULES_AVAILABLE or not llm_manager:
        raise HTTPException(503, "Enhanced LLM features not available")
    
    # Memory management
    if req_adapter.scan_id not in conversation_memories:
        conversation_memories[req_adapter.scan_id] = ConversationMemory(max_tokens=4000)
    
    memory = conversation_memories[req_adapter.scan_id]
    
    # Load scan context if needed
    if req_adapter.use_context and not memory.scan_context_summary:
        scan_dir = RESULTS_DIR / req_adapter.scan_id
        combined_file = scan_dir / "combined_results.json"
        
        if combined_file.exists():
            try:
                with open(combined_file, 'r', encoding='utf-8') as f:
                    scan_data = json.load(f)
                
                from dashboard.llm_results_reader import LLMResultsReader  
                reader = LLMResultsReader("")
                reader.raw_data = scan_data
                reader._parse_scan_data()
                context = reader.build_context_for_llm(max_tokens=2000)
                memory.set_scan_context(context[:3000])
            except Exception as e:
                logger.warning(f"Failed to load scan context: {e}")
    
    # Use sanitized message
    memory.add_message("user", sanitized_message)
    
    history = memory.get_context_messages()
    prompt = f"""{CHAT_SYSTEM_PROMPT}

{chr(10).join(f"{m['role'].upper()}: {m['content']}" for m in history[-6:])}

Respond to the user's latest message helpfully."""
    
    try:
        response = await llm_manager.call(
            prompt=prompt,
            operation=LLMOperation.CHAT,
            preferred_provider=req_adapter.provider,
            temperature=0.3
        )
    except Exception as e:
        raise HTTPException(503, f"Chat failed: {e}")
    
    memory.add_message("assistant", response.content)
    
    return {
        "response": response.content,
        "provider": response.provider,
        "model": response.model,
        "memory_stats": memory.get_stats()
    }


@router.delete("/chat/{scan_id}")
async def clear_chat_memory(scan_id: str):
    """Clear conversation memory for a scan."""
    from dashboard.state import conversation_memories
    if scan_id in conversation_memories:
        conversation_memories[scan_id].clear()
        return {"message": "Chat memory cleared"}
    return {"message": "No memory found for scan"}


@router.get("/cache/stats")
async def get_cache_stats():
    """Get LLM cache statistics."""
    from dashboard.llm_cache import get_llm_cache
    llm_cache = get_llm_cache()
    if not llm_cache:
        return {"error": "Cache not enabled"}
    return llm_cache.get_stats()


@router.post("/cache/clear")
async def clear_llm_cache():
    """Clear the LLM response cache."""
    from dashboard.llm_cache import get_llm_cache
    llm_cache = get_llm_cache()
    if not llm_cache:
        return {"error": "Cache not enabled"}
    llm_cache.invalidate()
    return {"message": "Cache cleared"}
