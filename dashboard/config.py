"""
TwinSanity Recon V2 - Configuration Module
Centralized configuration loading and constants.
"""
import logging
import os
import re
import json
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional
import yaml

# =============================================================================
# Path Configuration
# =============================================================================
PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_FILE = PROJECT_ROOT / "config.yaml"
LOGS_DIR = PROJECT_ROOT / "logs"
LOGS_DIR.mkdir(exist_ok=True)

BASE_DIR = Path(__file__).parent
STATIC_DIR = BASE_DIR / "static"
TEMPLATES_DIR = BASE_DIR / "templates"
RESULTS_DIR = PROJECT_ROOT / "results"
DATA_DIR = PROJECT_ROOT / "data"

# Create directories if they don't exist
RESULTS_DIR.mkdir(exist_ok=True)
DATA_DIR.mkdir(exist_ok=True)

# =============================================================================
# Configure Logging
# =============================================================================
logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("TwinSanityDashboard")

# =============================================================================
# Load YAML Config
# =============================================================================
def load_config() -> dict:
    """Load configuration from config.yaml"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                return yaml.safe_load(f) or {}
        except Exception as e:
            logger.warning(f"Failed to load config.yaml: {e}")
    return {}

CONFIG = load_config()

# =============================================================================
# App/Server Configuration (from config.yaml)
# =============================================================================
APP_CONFIG = CONFIG.get('app', {})
APP_NAME = APP_CONFIG.get('name', 'TwinSanity Recon V2')
APP_VERSION = APP_CONFIG.get('version', '2.0.0')
APP_DESCRIPTION = APP_CONFIG.get('description', 'Security Reconnaissance Dashboard with LLM Analysis')
APP_DEBUG = APP_CONFIG.get('debug', False)
SERVER_HOST = APP_CONFIG.get('host', '127.0.0.1')
SERVER_PORT = APP_CONFIG.get('port', 8888)
PRODUCTION_MODE = APP_CONFIG.get('production', False)

# =============================================================================
# Database Configuration (from config.yaml)
# =============================================================================
DB_CONFIG = CONFIG.get('database', {})
DB_PATH = PROJECT_ROOT / DB_CONFIG.get('path', 'data/twinsanity.db')
DB_CACHE_TTL_DAYS = DB_CONFIG.get('cache_ttl_days', 7)

# =============================================================================
# Scan Configuration (from config.yaml)
# =============================================================================
SCAN_CONFIG = CONFIG.get('scan', {})
DNS_CONCURRENCY = SCAN_CONFIG.get('dns_concurrency', 50)
IP_CONCURRENCY = SCAN_CONFIG.get('ip_concurrency', 20)
MAX_CVES_PER_IP = SCAN_CONFIG.get('max_cves_per_ip', 20)
SCAN_VALIDATE_DNS = SCAN_CONFIG.get('validate_dns', False)
SCAN_TIMEOUT = SCAN_CONFIG.get('timeout', 15)

# =============================================================================
# UI Configuration (from config.yaml)
# =============================================================================
UI_CONFIG = CONFIG.get('ui', {})
UI_THEME = UI_CONFIG.get('theme', 'dark')
UI_AUTO_REFRESH = UI_CONFIG.get('auto_refresh', 0)
UI_VERBOSE_LOGS = UI_CONFIG.get('verbose_logs', True)

# =============================================================================
# HTTP Probing Configuration (from config.yaml)
# =============================================================================
HTTP_PROBING_CONFIG = CONFIG.get('http_probing', {})
HTTP_PROBING_ENABLED = HTTP_PROBING_CONFIG.get('enabled', True)
HTTP_PROBING_CONCURRENCY = HTTP_PROBING_CONFIG.get('concurrency', 50)
HTTP_PROBING_TIMEOUT = HTTP_PROBING_CONFIG.get('timeout', 10)
HTTP_PROBING_PROTOCOLS = HTTP_PROBING_CONFIG.get('protocols', ['https', 'http'])
HTTP_PROBING_TECH_DETECTION = HTTP_PROBING_CONFIG.get('tech_detection', True)
HTTP_PROBING_FOLLOW_REDIRECTS = HTTP_PROBING_CONFIG.get('follow_redirects', True)

# =============================================================================
# Nuclei Configuration (from config.yaml)
# =============================================================================
NUCLEI_CONFIG = CONFIG.get('nuclei', {})
NUCLEI_ENABLED = NUCLEI_CONFIG.get('enabled', False)
NUCLEI_TEMPLATES = NUCLEI_CONFIG.get('templates', ['cves', 'exposed-panels'])
NUCLEI_SEVERITY = NUCLEI_CONFIG.get('severity', 'critical,high')
NUCLEI_RATE_LIMIT = NUCLEI_CONFIG.get('rate_limit', 150)
NUCLEI_CONCURRENCY = NUCLEI_CONFIG.get('concurrency', 25)
NUCLEI_PYTHON_FALLBACK = NUCLEI_CONFIG.get('python_fallback', True)

# =============================================================================
# URL Harvesting Configuration (from config.yaml)
# =============================================================================
URL_HARVESTING_CONFIG = CONFIG.get('url_harvesting', {})
URL_HARVESTING_ENABLED = URL_HARVESTING_CONFIG.get('enabled', True)
URL_HARVESTING_SOURCES = URL_HARVESTING_CONFIG.get('sources', ['wayback', 'commoncrawl', 'alienvault'])
URL_HARVESTING_TIMEOUT = URL_HARVESTING_CONFIG.get('timeout', 60)
URL_HARVESTING_FILTER_INTERESTING = URL_HARVESTING_CONFIG.get('filter_interesting', True)
URL_HARVESTING_EXTENSIONS = URL_HARVESTING_CONFIG.get('interesting_extensions', ['js', 'json', 'xml', 'php'])

# =============================================================================
# XSS Scan Configuration (from config.yaml)
# =============================================================================
XSS_SCAN_CONFIG = CONFIG.get('xss_scan', {})
XSS_SCAN_ENABLED = XSS_SCAN_CONFIG.get('enabled', False)
XSS_SCAN_PAYLOADS = XSS_SCAN_CONFIG.get('payloads', ['<script>alert(1)</script>'])
XSS_SCAN_MAX_URLS = XSS_SCAN_CONFIG.get('max_urls', 100)
XSS_SCAN_TIMEOUT = XSS_SCAN_CONFIG.get('timeout', 10)
XSS_SCAN_CONCURRENCY = XSS_SCAN_CONFIG.get('concurrency', 10)

# =============================================================================
# API Discovery Configuration (from config.yaml)
# =============================================================================
API_DISCOVERY_CONFIG = CONFIG.get('api_discovery', {})
API_DISCOVERY_ENABLED = API_DISCOVERY_CONFIG.get('enabled', True)
API_DISCOVERY_SCAN_JS = API_DISCOVERY_CONFIG.get('scan_js_files', True)
API_DISCOVERY_SCAN_WAYBACK = API_DISCOVERY_CONFIG.get('scan_wayback', True)
API_DISCOVERY_PATTERNS = API_DISCOVERY_CONFIG.get('patterns', ['/api/', '/v1/', '/v2/'])
API_DISCOVERY_MAX_ENDPOINTS = API_DISCOVERY_CONFIG.get('max_endpoints', 500)
API_DISCOVERY_TIMEOUT = API_DISCOVERY_CONFIG.get('timeout', 30)

# =============================================================================
# Reports Configuration (from config.yaml)
# =============================================================================
REPORTS_CONFIG = CONFIG.get('reports', {})
REPORTS_DIR = PROJECT_ROOT / REPORTS_CONFIG.get('directory', 'reports')
REPORTS_DEFAULT_FORMAT = REPORTS_CONFIG.get('default_format', 'html')
REPORTS_INCLUDE = REPORTS_CONFIG.get('include', {})
REPORTS_MAX_DETAILED = REPORTS_CONFIG.get('max_detailed_findings', 100)
REPORTS_ORGANIZATION = REPORTS_CONFIG.get('organization', '')
REPORTS_DISCLAIMER = REPORTS_CONFIG.get('disclaimer', 'This report is confidential.')

# =============================================================================
# Proxy Configuration (from config.yaml)
# =============================================================================
PROXY_CONFIG = CONFIG.get('proxy', {})
PROXY_ENABLED = PROXY_CONFIG.get('enabled', False)
PROXY_ROTATION_MODE = PROXY_CONFIG.get('rotation_mode', 'round_robin')
PROXY_VALIDATE_ON_LOAD = PROXY_CONFIG.get('validate_on_load', False)
PROXY_VALIDATION_TIMEOUT = PROXY_CONFIG.get('validation_timeout', 10)
PROXY_REMOVE_INVALID = PROXY_CONFIG.get('remove_invalid', True)
PROXY_SINGLE = PROXY_CONFIG.get('single_proxy', '')
PROXY_FILE = PROXY_CONFIG.get('proxy_file', '')

# =============================================================================
# Wordlist Configuration (from config.yaml)
# =============================================================================
WORDLIST_CONFIG = CONFIG.get('wordlist', {})
WORDLIST_DEFAULT = WORDLIST_CONFIG.get('default', 'small')
WORDLIST_DIRECTORY = PROJECT_ROOT / WORDLIST_CONFIG.get('directory', 'wordlists')
WORDLIST_RATE_LIMIT = WORDLIST_CONFIG.get('rate_limit', 50)
WORDLIST_CONCURRENCY = WORDLIST_CONFIG.get('concurrency', 100)
WORDLIST_DNS_TIMEOUT = WORDLIST_CONFIG.get('dns_timeout', 5)
WORDLIST_FILTER_HTTP = WORDLIST_CONFIG.get('filter_http', False)
WORDLIST_FILTER_DNS = WORDLIST_CONFIG.get('filter_dns', True)

# =============================================================================
# Subdomain Sources Configuration (from config.yaml)
# =============================================================================
SUBDOMAIN_SOURCES_CONFIG = CONFIG.get('subdomain_sources', {})
SUBDOMAIN_GLOBAL_CONFIG = SUBDOMAIN_SOURCES_CONFIG.get('global', {})
SUBDOMAIN_MAX_RETRIES = SUBDOMAIN_GLOBAL_CONFIG.get('max_retries', 2)
SUBDOMAIN_RETRY_DELAY = SUBDOMAIN_GLOBAL_CONFIG.get('retry_delay', 1.0)
SUBDOMAIN_VALIDATE_DNS = SUBDOMAIN_GLOBAL_CONFIG.get('validate_dns', False)
SUBDOMAIN_CONCURRENCY = SUBDOMAIN_GLOBAL_CONFIG.get('concurrency', 10)

# =============================================================================
# CVE Sources Configuration (from config.yaml)
# =============================================================================
CVE_SOURCES_CONFIG = CONFIG.get('cve_sources', [])

# =============================================================================
# Security Configuration
# =============================================================================
SECURITY_CONFIG = CONFIG.get('security', {})
AUTH_ENABLED = SECURITY_CONFIG.get('auth_enabled', False)
API_KEY_HASH = os.getenv("DASHBOARD_API_KEY_HASH")

# Rate limiting config
RATE_LIMIT_CONFIG = SECURITY_CONFIG.get('rate_limiting', {})

# Allowed providers config
ALLOWED_PROVIDERS_CONFIG = SECURITY_CONFIG.get('allowed_providers', {})
ALLOWED_ANALYSIS_PROVIDERS = ALLOWED_PROVIDERS_CONFIG.get('analysis', ['local', 'gemini'])
ALLOWED_CHAT_PROVIDERS = ALLOWED_PROVIDERS_CONFIG.get('chat', ['local'])

# Data redaction config
REDACTION_CONFIG = SECURITY_CONFIG.get('data_redaction', {})
REDACTION_ENABLED = REDACTION_CONFIG.get('enabled', True)
REDACT_IPS = REDACTION_CONFIG.get('redact_ips', True)
REDACT_HOSTNAMES = REDACTION_CONFIG.get('redact_hostnames', False)

# Password/Session config (from config.yaml)
SESSION_CONFIG = SECURITY_CONFIG.get('session', {})
PASSWORD_MIN_LENGTH = SESSION_CONFIG.get('password_min_length', 8)
MAX_LOGIN_ATTEMPTS = SESSION_CONFIG.get('max_login_attempts', 5)
LOCKOUT_MINUTES = SESSION_CONFIG.get('lockout_minutes', 15)
SESSION_HOURS = SESSION_CONFIG.get('session_hours', 24)
REMEMBER_ME_DAYS = SESSION_CONFIG.get('remember_me_days', 30)

# =============================================================================
# Audit Logging
# =============================================================================
audit_logger = logging.getLogger("audit")
audit_handler = logging.FileHandler(LOGS_DIR / "audit.log")
audit_handler.setFormatter(logging.Formatter("%(asctime)s %(message)s"))
audit_logger.addHandler(audit_handler)
audit_logger.setLevel(logging.INFO)

def log_llm_call(provider: str, scan_id: str, prompt_size: int, redacted: bool):
    """Audit log for LLM API calls."""
    audit_logger.info(json.dumps({
        "timestamp": datetime.utcnow().isoformat(),
        "event": "llm_call",
        "provider": provider,
        "scan_id": scan_id,
        "prompt_chars": prompt_size,
        "data_redacted": redacted
    }))

# =============================================================================
# API Keys from config.yaml
# =============================================================================
API_KEYS = CONFIG.get('api_keys', {})

GEMINI_API_KEY = API_KEYS.get('gemini', '')
OLLAMA_API_KEY = API_KEYS.get('ollama_cloud', '')
SHODAN_API_KEY = API_KEYS.get('shodan', '')
NVD_API_KEY = API_KEYS.get('nvd', '')
GITHUB_API_KEY = API_KEYS.get('github', '')
GITHUB_TOKEN = API_KEYS.get('github_token', '') or API_KEYS.get('github', '')
OPENAI_API_KEY = API_KEYS.get('openai', '')
ANTHROPIC_API_KEY = API_KEYS.get('anthropic', '')

# =============================================================================
# LLM Configuration
# =============================================================================
LLM_CONFIG = CONFIG.get('llm', {})
PROVIDERS_CONFIG = LLM_CONFIG.get('providers', {})

# Gemini settings
GEMINI_CONFIG = PROVIDERS_CONFIG.get('gemini', LLM_CONFIG.get('gemini', {}))
GEMINI_URL = GEMINI_CONFIG.get('url', "https://generativelanguage.googleapis.com/v1beta/models/{model}:generateContent")
GEMINI_MODEL = GEMINI_CONFIG.get('model', "gemini-2.5-flash")
GEMINI_MAX_RETRIES = GEMINI_CONFIG.get('max_retries', 4)
GEMINI_BACKOFF = GEMINI_CONFIG.get('backoff_base', 3)

# Ollama Cloud settings
CLOUD_CONFIG = PROVIDERS_CONFIG.get('ollama_cloud', LLM_CONFIG.get('cloud', {}))
OLLAMA_CLOUD_HOST = CLOUD_CONFIG.get('host', "https://ollama.com")
OLLAMA_CLOUD_MODEL = CLOUD_CONFIG.get('model', 'deepseek-v3.1:671b')
OLLAMA_CLOUD_MODELS = CLOUD_CONFIG.get('models', [OLLAMA_CLOUD_MODEL])
CLOUD_MAX_RETRIES = CLOUD_CONFIG.get('max_retries', 4)

# Local Ollama settings - using smaller default models for better compatibility
LOCAL_CONFIG = PROVIDERS_CONFIG.get('local', LLM_CONFIG.get('local', {}))
OLLAMA_LOCAL_HOST = LOCAL_CONFIG.get('host', 'http://127.0.0.1:11434')
LOCAL_MODELS = LOCAL_CONFIG.get('models', {})
if isinstance(LOCAL_MODELS, dict):
    # Default to smaller, more memory-efficient models
    OLLAMA_LOCAL_MODEL = LOCAL_MODELS.get('default', 'llama3.2:3b')
    OLLAMA_REASONING_MODEL = LOCAL_MODELS.get('reasoning', 'deepseek-r1:1.5b')
else:
    OLLAMA_LOCAL_MODEL = LOCAL_MODELS[0] if LOCAL_MODELS else 'llama3.2:3b'
    OLLAMA_REASONING_MODEL = 'deepseek-r1:1.5b'
OLLAMA_LOCAL_MODELS = [OLLAMA_LOCAL_MODEL]

# Analysis settings
ANALYSIS_CONFIG = LLM_CONFIG.get('analysis', {})
AI_ANALYSIS_ENABLED = ANALYSIS_CONFIG.get('enabled', False)
ANALYSIS_CHUNK_SIZE = ANALYSIS_CONFIG.get('chunk_size', 30)  # Increased for faster AI analysis

# Reasoning/Caching settings
REASONING_CONFIG = LLM_CONFIG.get('reasoning', {})
USE_CHAIN_OF_THOUGHT = REASONING_CONFIG.get('use_chain_of_thought', True)
ENABLE_THINKING_MODE = REASONING_CONFIG.get('enable_thinking_mode', False)

CACHE_CONFIG = LLM_CONFIG.get('cache', {})
CACHE_ENABLED = CACHE_CONFIG.get('enabled', True)
CACHE_TTL_HOURS = CACHE_CONFIG.get('ttl_hours', 6)

# =============================================================================
# Path Validation for Security
# =============================================================================
ALLOWED_DIRS = [PROJECT_ROOT / "results", PROJECT_ROOT / "data"]

# =============================================================================
# Utility Functions
# =============================================================================
def get_config() -> dict:
    """Get the current configuration dictionary."""
    return CONFIG

def update_config(key_path: str, value: Any) -> bool:
    """
    Update a configuration value and save to config.yaml.
    
    Args:
        key_path: Dot-separated path (e.g., "api_keys.shodan")
        value: New value to set
    
    Returns:
        True if successful
    """
    global CONFIG
    
    try:
        # Navigate to the key
        keys = key_path.split('.')
        current = CONFIG
        
        # Navigate to parent
        for key in keys[:-1]:
            if key not in current:
                current[key] = {}
            current = current[key]
        
        # Set the value
        current[keys[-1]] = value
        
        # Save to file
        with open(CONFIG_FILE, 'w') as f:
            yaml.safe_dump(CONFIG, f, default_flow_style=False, sort_keys=False)
        
        logger.info(f"Config updated: {key_path}")
        return True
    except Exception as e:
        logger.error(f"Failed to update config {key_path}: {e}")
        return False

def redact_sensitive_data(text: str) -> str:
    """Redact IPs and optionally hostnames before sending to cloud."""
    if not REDACTION_ENABLED:
        return text
    result = text
    if REDACT_IPS:
        result = re.sub(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', '[REDACTED_IP]', result)
    if REDACT_HOSTNAMES:
        result = re.sub(r'\b[a-zA-Z0-9]([a-zA-Z0-9\-]*[a-zA-Z0-9])?\.[a-zA-Z]{2,}\b', '[REDACTED_HOST]', result)
    return result

def check_provider_allowed(provider: str, operation: str = "chat") -> bool:
    """Check if a provider is allowed for the operation."""
    if operation == "analysis":
        allowed = ALLOWED_ANALYSIS_PROVIDERS
    else:
        allowed = ALLOWED_CHAT_PROVIDERS
    return provider in allowed or provider == "local"

# =============================================================================
# Log Configuration Status
# =============================================================================
if not GEMINI_API_KEY:
    logger.warning("Gemini API key not configured in config.yaml")
else:
    logger.info(f"Gemini configured: model={GEMINI_MODEL}")
if OLLAMA_CLOUD_HOST:
    logger.info(f"Ollama Cloud: {OLLAMA_CLOUD_HOST}")
if OLLAMA_API_KEY:
    logger.info("Ollama Cloud API key configured")
logger.info(f"Local Ollama: {OLLAMA_LOCAL_HOST}, model={OLLAMA_LOCAL_MODEL}")
