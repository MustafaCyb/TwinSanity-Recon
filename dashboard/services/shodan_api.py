"""
TwinSanity Recon V2 - Shodan API Integration
Comprehensive Shodan integration with proper tier detection and security.

Note: Named 'shodan_api' to avoid conflicts with the 'shodan' pip package.
"""
import asyncio
import aiohttp
import logging
import re
from typing import Dict, List, Optional, Any, Tuple
from dataclasses import dataclass, field
from enum import Enum

logger = logging.getLogger("ShodanAPI")


class ShodanPlan(Enum):
    """Shodan subscription plans - detected from API response."""
    FREE = "free"
    DEV = "dev"  # Developer plan - one-time purchase
    PLUS = "plus"
    CORP = "corp"
    ENTERPRISE = "enterprise"
    UNKNOWN = "unknown"
    
    @classmethod
    def from_string(cls, plan_str: str) -> "ShodanPlan":
        """Convert plan string from API to enum."""
        if not plan_str:
            return cls.FREE
        plan_lower = plan_str.lower().strip()
        for plan in cls:
            if plan.value == plan_lower:
                return plan
        if "dev" in plan_lower:
            return cls.DEV
        if "plus" in plan_lower:
            return cls.PLUS
        if "corp" in plan_lower:
            return cls.CORP
        if "enterprise" in plan_lower or "ent" in plan_lower:
            return cls.ENTERPRISE
        return cls.UNKNOWN


@dataclass
class ShodanAccountStatus:
    """Shodan account status from API."""
    valid: bool = False
    configured: bool = False
    plan: ShodanPlan = ShodanPlan.FREE
    plan_name: str = "Free"
    query_credits: int = 0
    scan_credits: int = 0
    monitored_ips: int = 0
    monitored_ips_limit: int = 0
    unlocked: bool = False
    unlocked_left: int = 0
    https_enabled: bool = False
    telnet_enabled: bool = False
    error: Optional[str] = None
    
    def to_dict(self) -> Dict:
        return {
            "valid": self.valid,
            "configured": self.configured,
            "plan": self.plan.value,
            "plan_display": self.plan_name,
            "query_credits": self.query_credits,
            "scan_credits": self.scan_credits,
            "monitored_ips": self.monitored_ips,
            "monitored_ips_limit": self.monitored_ips_limit,
            "unlocked": self.unlocked,
            "unlocked_left": self.unlocked_left,
            "https_enabled": self.https_enabled,
            "telnet_enabled": self.telnet_enabled,
            "error": self.error
        }


# Rate limits by plan (requests per second)
PLAN_RATE_LIMITS = {
    ShodanPlan.FREE: 1,
    ShodanPlan.DEV: 1,
    ShodanPlan.PLUS: 1,
    ShodanPlan.CORP: 5,
    ShodanPlan.ENTERPRISE: 10,
    ShodanPlan.UNKNOWN: 1,
}

# Features by plan
PLAN_FEATURES = {
    ShodanPlan.FREE: {
        "host_lookup": False,
        "search": False,
        "search_facets": False,
        "scan": False,
        "alerts": False,
        "dns_resolve": True,
        "dns_reverse": True,
        "internetdb": True,
        "exploits": True,
        "my_ip": True,
    },
    ShodanPlan.DEV: {
        "host_lookup": True,
        "search": True,
        "search_facets": True,
        "scan": True,
        "alerts": True,
        "dns_resolve": True,
        "dns_reverse": True,
        "internetdb": True,
        "exploits": True,
        "my_ip": True,
    },
    ShodanPlan.PLUS: {
        "host_lookup": True,
        "search": True,
        "search_facets": True,
        "scan": True,
        "alerts": True,
        "dns_resolve": True,
        "dns_reverse": True,
        "internetdb": True,
        "exploits": True,
        "my_ip": True,
    },
    ShodanPlan.CORP: {
        "host_lookup": True,
        "search": True,
        "search_facets": True,
        "scan": True,
        "alerts": True,
        "dns_resolve": True,
        "dns_reverse": True,
        "internetdb": True,
        "exploits": True,
        "my_ip": True,
        "bulk_lookup": True,
        "streaming": True,
    },
    ShodanPlan.ENTERPRISE: {
        "host_lookup": True,
        "search": True,
        "search_facets": True,
        "scan": True,
        "alerts": True,
        "dns_resolve": True,
        "dns_reverse": True,
        "internetdb": True,
        "exploits": True,
        "my_ip": True,
        "bulk_lookup": True,
        "streaming": True,
        "on_demand_scan": True,
    },
}


class ShodanAPIClient:
    """
    Shodan API client with proper tier detection, rate limiting, and security.
    """
    
    BASE_URL = "https://api.shodan.io"
    INTERNETDB_URL = "https://internetdb.shodan.io"
    EXPLOITS_URL = "https://exploits.shodan.io/api"
    
    def __init__(self, api_key: str = ""):
        self._api_key = api_key.strip() if api_key else ""
        self._status: Optional[ShodanAccountStatus] = None
        self._session: Optional[aiohttp.ClientSession] = None
        self._last_request_time: float = 0
        self._initialized: bool = False
        
    @property
    def api_key(self) -> str:
        return self._api_key
    
    @api_key.setter
    def api_key(self, value: str):
        if value and not self._is_valid_key_format(value):
            raise ValueError("Invalid API key format")
        self._api_key = value.strip() if value else ""
        self._status = None
        self._initialized = False
    
    def _is_valid_key_format(self, key: str) -> bool:
        """Validate API key format."""
        if not key:
            return False
        return bool(re.match(r'^[a-zA-Z0-9]{20,64}$', key.strip()))
    
    @property
    def is_configured(self) -> bool:
        return bool(self._api_key)
    
    async def _get_session(self) -> aiohttp.ClientSession:
        """Get or create aiohttp session."""
        if self._session is None or self._session.closed:
            timeout = aiohttp.ClientTimeout(total=30, connect=10)
            self._session = aiohttp.ClientSession(
                timeout=timeout,
                headers={
                    "User-Agent": "TwinSanity-Recon/2.0",
                    "Accept": "application/json",
                }
            )
        return self._session
    
    async def close(self):
        """Close the session."""
        if self._session and not self._session.closed:
            await self._session.close()
            self._session = None
    
    async def _rate_limit(self):
        """Apply rate limiting based on plan."""
        if self._status:
            limit = PLAN_RATE_LIMITS.get(self._status.plan, 1)
        else:
            limit = 1
        
        min_interval = 1.0 / limit
        now = asyncio.get_event_loop().time()
        elapsed = now - self._last_request_time
        
        if elapsed < min_interval:
            await asyncio.sleep(min_interval - elapsed)
        
        self._last_request_time = asyncio.get_event_loop().time()
    
    async def _request(
        self,
        url: str,
        params: Dict = None,
        method: str = "GET",
        include_key: bool = True
    ) -> Tuple[Optional[Any], Optional[str]]:
        """Make an API request with rate limiting. Returns (data, error)."""
        await self._rate_limit()
        session = await self._get_session()
        
        if params is None:
            params = {}
        
        if include_key and self._api_key:
            params["key"] = self._api_key
        
        try:
            async with session.request(method, url, params=params) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    return data, None
                elif resp.status == 401:
                    return None, "Invalid API key"
                elif resp.status == 402:
                    return None, "Upgrade required - this feature requires a paid plan"
                elif resp.status == 403:
                    return None, "Access denied"
                elif resp.status == 404:
                    return None, "Not found"
                elif resp.status == 429:
                    return None, "Rate limit exceeded - please wait"
                elif resp.status == 503:
                    return None, "Shodan service temporarily unavailable"
                else:
                    text = await resp.text()
                    return None, f"API error ({resp.status}): {text[:100]}"
        except asyncio.TimeoutError:
            return None, "Request timeout"
        except aiohttp.ClientError as e:
            return None, f"Connection error: {str(e)}"
        except Exception as e:
            logger.error(f"Shodan API error: {e}")
            return None, f"Unexpected error: {str(e)}"
    
    # =========================================================================
    # Account & Status
    # =========================================================================
    
    async def initialize(self, force: bool = False) -> ShodanAccountStatus:
        """Initialize and validate API key, detect plan."""
        if self._initialized and self._status and not force:
            return self._status
        
        self._status = ShodanAccountStatus()
        
        if not self._api_key:
            self._status.error = "No API key configured"
            return self._status
        
        self._status.configured = True
        
        data, error = await self._request(f"{self.BASE_URL}/api-info")
        
        if error:
            self._status.error = error
            self._status.valid = False
            return self._status
        
        if data:
            self._status.valid = True
            plan_str = data.get("plan", "")
            self._status.plan = ShodanPlan.from_string(plan_str)
            self._status.plan_name = plan_str.upper() if plan_str else "FREE"
            
            self._status.query_credits = data.get("query_credits", 0)
            self._status.scan_credits = data.get("scan_credits", 0)
            self._status.monitored_ips = data.get("monitored_ips", 0)
            
            usage_limits = data.get("usage_limits", {})
            self._status.monitored_ips_limit = usage_limits.get("monitored_ips", 0)
            
            self._status.unlocked = data.get("unlocked", False)
            self._status.unlocked_left = data.get("unlocked_left", 0)
            self._status.https_enabled = data.get("https", False)
            self._status.telnet_enabled = data.get("telnet", False)
            
            self._initialized = True
            logger.info(f"Shodan initialized: plan={self._status.plan_name}")
        
        return self._status
    
    async def get_status(self) -> ShodanAccountStatus:
        """Get current status (initializes if needed)."""
        if not self._initialized:
            await self.initialize()
        return self._status or ShodanAccountStatus()
    
    def get_features(self) -> Dict[str, bool]:
        """Get available features for current plan."""
        if self._status:
            return PLAN_FEATURES.get(self._status.plan, PLAN_FEATURES[ShodanPlan.FREE])
        return PLAN_FEATURES[ShodanPlan.FREE]
    
    # =========================================================================
    # Host Lookup
    # =========================================================================
    
    async def host_lookup(self, ip: str, history: bool = False, minify: bool = True) -> Tuple[Optional[Dict], Optional[str]]:
        """Get all available information on an IP. Requires DEV plan or higher."""
        if not self._is_valid_ip(ip):
            return None, "Invalid IP address format"
        
        params = {"minify": str(minify).lower()}
        if history:
            params["history"] = "true"
        
        return await self._request(f"{self.BASE_URL}/shodan/host/{ip}", params)
    
    async def internetdb_lookup(self, ip: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Free IP lookup via InternetDB (no API key required)."""
        if not self._is_valid_ip(ip):
            return None, "Invalid IP address format"
        
        return await self._request(f"{self.INTERNETDB_URL}/{ip}", include_key=False)
    
    def _is_valid_ip(self, ip: str) -> bool:
        """Validate IPv4 address format."""
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) <= 255 for p in parts)
        except ValueError:
            return False
    
    # =========================================================================
    # Search
    # =========================================================================
    
    async def search(
        self,
        query: str,
        page: int = 1,
        facets: str = None,
        minify: bool = True
    ) -> Tuple[Optional[Dict], Optional[str]]:
        """Search Shodan. Requires DEV plan or higher, uses query credits."""
        if not query or len(query.strip()) < 2:
            return None, "Search query too short"
        
        query = self._sanitize_query(query)
        
        params = {
            "query": query,
            "page": page,
            "minify": str(minify).lower(),
        }
        if facets:
            params["facets"] = facets
        
        return await self._request(f"{self.BASE_URL}/shodan/host/search", params)
    
    async def search_count(self, query: str, facets: str = None) -> Tuple[Optional[Dict], Optional[str]]:
        """Get search result count without using query credits."""
        if not query or len(query.strip()) < 2:
            return None, "Search query too short"
        
        query = self._sanitize_query(query)
        params = {"query": query}
        if facets:
            params["facets"] = facets
        
        return await self._request(f"{self.BASE_URL}/shodan/host/count", params)
    
    def _sanitize_query(self, query: str) -> str:
        """Sanitize search query for security."""
        query = query.strip()
        query = re.sub(r'[^\w\s:."\'@\-/,*]', '', query)
        return query[:500]
    
    # =========================================================================
    # DNS
    # =========================================================================
    
    async def dns_resolve(self, hostnames: List[str]) -> Tuple[Optional[Dict], Optional[str]]:
        """Resolve hostnames to IPs."""
        if not hostnames:
            return None, "No hostnames provided"
        
        valid_hostnames = []
        for h in hostnames[:100]:
            h = h.strip().lower()
            if self._is_valid_hostname(h):
                valid_hostnames.append(h)
        
        if not valid_hostnames:
            return None, "No valid hostnames provided"
        
        params = {"hostnames": ",".join(valid_hostnames)}
        return await self._request(f"{self.BASE_URL}/dns/resolve", params)
    
    async def dns_reverse(self, ips: List[str]) -> Tuple[Optional[Dict], Optional[str]]:
        """Reverse DNS lookup for IPs."""
        if not ips:
            return None, "No IPs provided"
        
        valid_ips = [ip for ip in ips[:100] if self._is_valid_ip(ip.strip())]
        if not valid_ips:
            return None, "No valid IPs provided"
        
        params = {"ips": ",".join(valid_ips)}
        return await self._request(f"{self.BASE_URL}/dns/reverse", params)
    
    async def dns_domain(self, domain: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Get DNS records for a domain."""
        if not self._is_valid_hostname(domain):
            return None, "Invalid domain format"
        
        return await self._request(f"{self.BASE_URL}/dns/domain/{domain}")
    
    def _is_valid_hostname(self, hostname: str) -> bool:
        """Validate hostname format."""
        if not hostname or len(hostname) > 255:
            return False
        pattern = r'^[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]{0,61}[a-z0-9])?)*$'
        return bool(re.match(pattern, hostname.lower()))
    
    # =========================================================================
    # Scanning
    # =========================================================================
    
    async def scan(self, ips: List[str]) -> Tuple[Optional[Dict], Optional[str]]:
        """Request on-demand scan. Uses scan credits."""
        if not ips:
            return None, "No IPs provided"
        
        valid_ips = [ip for ip in ips[:100] if self._is_valid_ip(ip.strip())]
        if not valid_ips:
            return None, "No valid IPs provided"
        
        status = await self.get_status()
        if status.scan_credits <= 0:
            return None, "No scan credits remaining"
        
        params = {"ips": ",".join(valid_ips)}
        return await self._request(f"{self.BASE_URL}/shodan/scan", params, method="POST")
    
    async def get_scan_status(self, scan_id: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Get status of a scan request."""
        if not scan_id:
            return None, "No scan ID provided"
        
        return await self._request(f"{self.BASE_URL}/shodan/scan/{scan_id}")
    
    # =========================================================================
    # Exploits
    # =========================================================================
    
    async def search_exploits(self, query: str, page: int = 1) -> Tuple[Optional[Dict], Optional[str]]:
        """Search for exploits (free, no credits)."""
        if not query or len(query.strip()) < 2:
            return None, "Search query too short"
        
        query = self._sanitize_query(query)
        params = {"query": query, "page": page}
        
        return await self._request(f"{self.EXPLOITS_URL}/search", params)
    
    # =========================================================================
    # Alerts
    # =========================================================================
    
    async def list_alerts(self) -> Tuple[Optional[List], Optional[str]]:
        """List all network alerts."""
        return await self._request(f"{self.BASE_URL}/shodan/alert/info")
    
    async def create_alert(self, name: str, ip_or_cidr: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Create a network alert."""
        if not name or not ip_or_cidr:
            return None, "Name and IP/CIDR required"
        
        if "/" in ip_or_cidr:
            ip_part = ip_or_cidr.split("/")[0]
        else:
            ip_part = ip_or_cidr
        
        if not self._is_valid_ip(ip_part):
            return None, "Invalid IP/CIDR format"
        
        params = {"name": name[:50], "filters": {"ip": ip_or_cidr}}
        return await self._request(f"{self.BASE_URL}/shodan/alert", params, method="POST")
    
    async def delete_alert(self, alert_id: str) -> Tuple[Optional[Dict], Optional[str]]:
        """Delete a network alert."""
        if not alert_id:
            return None, "No alert ID provided"
        
        return await self._request(f"{self.BASE_URL}/shodan/alert/{alert_id}", method="DELETE")
    
    # =========================================================================
    # Utilities
    # =========================================================================
    
    async def get_my_ip(self) -> Tuple[Optional[str], Optional[str]]:
        """Get your public IP address."""
        data, error = await self._request(f"{self.BASE_URL}/tools/myip")
        if error:
            return None, error
        return data, None
    
    async def get_available_ports(self) -> Tuple[Optional[List[int]], Optional[str]]:
        """Get list of ports that Shodan scans."""
        return await self._request(f"{self.BASE_URL}/shodan/ports")
    
    async def get_protocols(self) -> Tuple[Optional[Dict], Optional[str]]:
        """Get list of protocols Shodan can detect."""
        return await self._request(f"{self.BASE_URL}/shodan/protocols")


# =============================================================================
# Global Service Instance
# =============================================================================

_client: Optional[ShodanAPIClient] = None


def get_shodan_client() -> ShodanAPIClient:
    """Get global Shodan client instance (auto-loads API key from config)."""
    global _client
    if _client is None:
        from dashboard.config import get_config
        config = get_config()
        api_key = config.get("api_keys", {}).get("shodan", "")
        _client = ShodanAPIClient(api_key)
        logger.info(f"Shodan client initialized: {'configured' if api_key else 'no key'}")
    return _client


async def reinitialize_shodan_client(api_key: str = None) -> ShodanAPIClient:
    """Reinitialize Shodan client, optionally with a new API key."""
    global _client
    if _client:
        await _client.close()
    
    if api_key is None:
        from dashboard.config import get_config
        config = get_config()
        api_key = config.get("api_keys", {}).get("shodan", "")
    
    _client = ShodanAPIClient(api_key)
    await _client.initialize()
    return _client


# Backwards compatibility
get_shodan_service = get_shodan_client
reinitialize_shodan_service = reinitialize_shodan_client
ShodanService = ShodanAPIClient
