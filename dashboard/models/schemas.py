"""
TwinSanity Recon V2 - Pydantic Models
Request and response models for API endpoints.
"""
from pydantic import BaseModel, Field, field_validator
from typing import Dict, List, Optional

# =============================================================================
# Authentication Models
# =============================================================================
class SetupRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8)

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=32)
    password: str = Field(..., min_length=8)

class LoginRequest(BaseModel):
    username: str
    password: str
    remember_me: bool = False

# =============================================================================
# Scan Models
# =============================================================================
class ScanConfig(BaseModel):
    domain: str = Field(..., description="Target domain to scan")
    subdomain_discovery: bool = Field(True, description="Enable subdomain discovery")
    shodan_lookup: bool = Field(True, description="Enable Shodan/InternetDB lookup")
    cve_enrichment: bool = Field(True, description="Enrich CVE details")
    brute_force: bool = Field(False, description="Enable brute force subdomain discovery")
    wordlist: Optional[str] = Field(None, description="Wordlist for brute force")
    use_proxies: bool = Field(False, description="Enable proxy rotation for requests")
    subdomain_sources: Optional[Dict[str, bool]] = Field(None, description="Selected subdomain sources")
    cve_sources: Optional[List[str]] = Field(None, description="Selected CVE data sources")
    validate_dns: bool = Field(False, description="Filter subdomains by DNS resolution")
    delta_only: bool = Field(False, description="Only scan subdomains not seen before")
    baseline_subdomains: Optional[List[str]] = Field(None, description="Subdomains from previous scan")
    ai_analysis: bool = Field(False, description="Enable AI analysis")
    # New options for advanced scanning
    http_probing: bool = Field(False, description="Enable HTTP probing to find alive hosts")
    nuclei_scan: bool = Field(False, description="Enable Nuclei vulnerability scanning")
    url_harvesting: bool = Field(False, description="Enable URL harvesting from Wayback/CommonCrawl")
    xss_scan: bool = Field(False, description="Enable XSS vulnerability testing on harvested URLs")
    api_discovery: bool = Field(False, description="Enable API endpoint discovery")
    
    @field_validator('domain')
    @classmethod
    def validate_domain(cls, v: str) -> str:
        """Validate domain format to prevent injection attacks."""
        import re
        # Clean the input
        v = v.lower().strip()
        # Remove protocol if present
        v = re.sub(r'^https?://', '', v)
        # Remove trailing slash and path
        v = v.split('/')[0]
        # Validate domain format
        pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
        if not re.match(pattern, v):
            raise ValueError(f'Invalid domain format: {v}')
        # Check for dangerous characters
        if any(c in v for c in ['..', ';', '|', '&', '$', '`', '(', ')', '{', '}']):
            raise ValueError('Domain contains invalid characters')
        return v

class ScanResponse(BaseModel):
    scan_id: str
    status: str
    message: str

class VisibilityUpdate(BaseModel):
    visibility: str

# =============================================================================
# Chat Models
# =============================================================================
class ChatMessage(BaseModel):
    scan_id: str
    message: str
    provider: str = "local"

# =============================================================================
# Proxy Models
# =============================================================================
class ProxyAddRequest(BaseModel):
    proxy: str

class ProxyUploadRequest(BaseModel):
    content: str

# =============================================================================
# Wordlist Models
# =============================================================================
class WordlistUploadRequest(BaseModel):
    content: str
    name: str = "custom"

# =============================================================================
# Constants
# =============================================================================
METADATA_KEYS = {"timestamp", "domain", "result_file", "findings_summary", "_metadata"}

def count_actual_ips(results: dict) -> int:
    """Count actual IP addresses in results, excluding metadata keys."""
    if not results:
        return 0
    return sum(1 for k in results.keys() if k not in METADATA_KEYS and isinstance(results.get(k), dict))
