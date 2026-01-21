"""
TwinSanity Recon V2 - Proxy Manager
===================================
Handles proxy configuration, validation, and rotation for scanning operations.
Supports multiple proxy formats and automatic format detection.
"""

import re
import random
import logging
import asyncio
import aiohttp
from typing import List, Dict, Optional, Tuple
from dataclasses import dataclass
from enum import Enum
from pathlib import Path

logger = logging.getLogger(__name__)


class ProxyType(Enum):
    HTTP = "http"
    HTTPS = "https"
    SOCKS4 = "socks4"
    SOCKS5 = "socks5"


class ProxyRotationMode(Enum):
    """Proxy rotation strategies"""
    ROUND_ROBIN = "round_robin"
    RANDOM = "random"
    LEAST_USED = "least_used"
    FASTEST = "fastest"


@dataclass
class Proxy:
    """Represents a single proxy configuration"""
    host: str
    port: int
    proxy_type: ProxyType = ProxyType.HTTP
    username: Optional[str] = None
    password: Optional[str] = None
    is_valid: bool = True
    fail_count: int = 0
    success_count: int = 0
    avg_response_time: float = 0.0
    
    def to_url(self) -> str:
        """Convert proxy to URL format"""
        scheme = self.proxy_type.value
        if self.username and self.password:
            return f"{scheme}://{self.username}:{self.password}@{self.host}:{self.port}"
        return f"{scheme}://{self.host}:{self.port}"
    
    def to_aiohttp_proxy(self) -> str:
        """Get proxy URL for aiohttp"""
        return self.to_url()
    
    def to_requests_dict(self) -> Dict[str, str]:
        """Get proxy dict for requests library"""
        url = self.to_url()
        return {
            "http": url,
            "https": url
        }
    
    def __str__(self):
        if self.username:
            return f"{self.proxy_type.value}://{self.username}:***@{self.host}:{self.port}"
        return f"{self.proxy_type.value}://{self.host}:{self.port}"


class ProxyManager:
    """
    Manages proxy list, rotation, and validation.
    Supports various proxy formats and automatic detection.
    """
    
    # Regex patterns for proxy format detection
    PATTERNS = {
        # Format: protocol://user:pass@host:port
        'full_url': re.compile(
            r'^(https?|socks[45])://(?:([^:]+):([^@]+)@)?([^:]+):(\d+)/?$',
            re.IGNORECASE
        ),
        # Format: host:port:user:pass
        'host_port_user_pass': re.compile(
            r'^([^:]+):(\d+):([^:]+):(.+)$'
        ),
        # Format: user:pass@host:port
        'user_pass_at_host': re.compile(
            r'^([^:]+):([^@]+)@([^:]+):(\d+)$'
        ),
        # Format: host:port (simple)
        'host_port': re.compile(
            r'^([^:]+):(\d+)$'
        ),
    }
    
    def __init__(self, rotation_mode: ProxyRotationMode = ProxyRotationMode.ROUND_ROBIN):
        """
        Initialize proxy manager.
        
        Args:
            rotation_mode: ProxyRotationMode enum value
        """
        self.proxies: List[Proxy] = []
        self._rotation_mode = rotation_mode
        self.current_index = 0
        self.enabled = False
        self.test_url = "https://httpbin.org/ip"
        self._lock = asyncio.Lock()
    
    @property
    def rotation_mode(self) -> ProxyRotationMode:
        return self._rotation_mode
    
    @rotation_mode.setter
    def rotation_mode(self, value):
        if isinstance(value, str):
            self._rotation_mode = ProxyRotationMode(value)
        elif isinstance(value, ProxyRotationMode):
            self._rotation_mode = value
        else:
            raise ValueError(f"Invalid rotation mode: {value}")

    def parse_proxy_line(self, line: str, default_type: ProxyType = ProxyType.HTTP) -> Optional[Proxy]:
        """
        Parse a single proxy line and return a Proxy object.
        Automatically detects the format.
        """
        line = line.strip()
        if not line or line.startswith('#'):
            return None
        
        # Try full URL format first
        match = self.PATTERNS['full_url'].match(line)
        if match:
            protocol, user, password, host, port = match.groups()
            proxy_type = ProxyType(protocol.lower().replace('socks4', 'socks4').replace('socks5', 'socks5'))
            return Proxy(
                host=host,
                port=int(port),
                proxy_type=proxy_type,
                username=user,
                password=password
            )
        
        # Try host:port:user:pass format
        match = self.PATTERNS['host_port_user_pass'].match(line)
        if match:
            host, port, user, password = match.groups()
            return Proxy(
                host=host,
                port=int(port),
                proxy_type=default_type,
                username=user,
                password=password
            )
        
        # Try user:pass@host:port format
        match = self.PATTERNS['user_pass_at_host'].match(line)
        if match:
            user, password, host, port = match.groups()
            return Proxy(
                host=host,
                port=int(port),
                proxy_type=default_type,
                username=user,
                password=password
            )
        
        # Try simple host:port format
        match = self.PATTERNS['host_port'].match(line)
        if match:
            host, port = match.groups()
            return Proxy(
                host=host,
                port=int(port),
                proxy_type=default_type
            )
        
        logger.warning(f"Could not parse proxy line: {line}")
        return None
    
    def load_from_text(self, text: str, default_type: ProxyType = ProxyType.HTTP) -> int:
        """
        Load proxies from text (multiple lines).
        Returns number of proxies loaded.
        """
        count = 0
        for line in text.strip().split('\n'):
            proxy = self.parse_proxy_line(line, default_type)
            if proxy:
                self.proxies.append(proxy)
                count += 1
        
        if count > 0:
            self.enabled = True
            logger.info(f"Loaded {count} proxies")
        
        return count
    
    def load_from_file(self, filepath: str, default_type: ProxyType = ProxyType.HTTP) -> int:
        """Load proxies from a file"""
        path = Path(filepath)
        if not path.exists():
            logger.error(f"Proxy file not found: {filepath}")
            return 0
        
        # Try different encodings
        for encoding in ['utf-8', 'latin-1', 'cp1252']:
            try:
                text = path.read_text(encoding=encoding)
                return self.load_from_text(text, default_type)
            except UnicodeDecodeError:
                continue
        
        logger.error(f"Could not read proxy file with any encoding: {filepath}")
        return 0
    
    def add_single_proxy(self, proxy_string: str, default_type: ProxyType = ProxyType.HTTP) -> bool:
        """Add a single proxy from string"""
        proxy = self.parse_proxy_line(proxy_string, default_type)
        if proxy:
            self.proxies.append(proxy)
            self.enabled = True
            return True
        return False
    
    def clear(self):
        """Clear all proxies"""
        self.proxies = []
        self.current_index = 0
        self.enabled = False
    
    async def get_next_proxy(self) -> Optional[Proxy]:
        """Get next proxy based on rotation mode"""
        async with self._lock:
            if not self.proxies:
                return None
            
            valid_proxies = [p for p in self.proxies if p.is_valid]
            if not valid_proxies:
                # Reset all proxies if none are valid
                for p in self.proxies:
                    p.is_valid = True
                    p.fail_count = 0
                valid_proxies = self.proxies
            
            if self._rotation_mode == ProxyRotationMode.RANDOM:
                return random.choice(valid_proxies)
            
            elif self._rotation_mode == ProxyRotationMode.LEAST_USED:
                return min(valid_proxies, key=lambda p: p.success_count + p.fail_count)
            
            elif self._rotation_mode == ProxyRotationMode.FASTEST:
                # Filter proxies with response time data
                timed_proxies = [p for p in valid_proxies if p.avg_response_time > 0]
                if timed_proxies:
                    return min(timed_proxies, key=lambda p: p.avg_response_time)
                return valid_proxies[0]
            
            else:  # ROUND_ROBIN
                proxy = valid_proxies[self.current_index % len(valid_proxies)]
                self.current_index += 1
                return proxy
    
    def mark_proxy_result(self, proxy: Proxy, success: bool, response_time: float = 0):
        """Update proxy statistics after use"""
        if success:
            proxy.success_count += 1
            if response_time > 0:
                # Running average
                if proxy.avg_response_time == 0:
                    proxy.avg_response_time = response_time
                else:
                    proxy.avg_response_time = (proxy.avg_response_time + response_time) / 2
        else:
            proxy.fail_count += 1
            if proxy.fail_count >= 3:
                proxy.is_valid = False
                logger.warning(f"Proxy {proxy} marked as invalid after {proxy.fail_count} failures")
    
    async def validate_proxy(self, proxy: Proxy, timeout: int = 10) -> Tuple[bool, float]:
        """
        Test if a proxy is working.
        Returns (is_valid, response_time)
        """
        import time
        start_time = time.time()
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    self.test_url,
                    proxy=proxy.to_aiohttp_proxy(),
                    timeout=aiohttp.ClientTimeout(total=timeout),
                    ssl=False
                ) as response:
                    if response.status == 200:
                        elapsed = time.time() - start_time
                        return True, elapsed
        except Exception as e:
            logger.debug(f"Proxy validation failed for {proxy}: {e}")
        
        return False, 0
    
    async def validate_all_proxies(self, max_concurrent: int = 10) -> Dict[str, int]:
        """
        Validate all proxies concurrently.
        Returns dict with 'valid' and 'invalid' counts.
        """
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def validate_with_semaphore(proxy):
            async with semaphore:
                is_valid, response_time = await self.validate_proxy(proxy)
                proxy.is_valid = is_valid
                if is_valid:
                    proxy.avg_response_time = response_time
                return is_valid
        
        results = await asyncio.gather(
            *[validate_with_semaphore(p) for p in self.proxies],
            return_exceptions=True
        )
        
        valid_count = sum(1 for r in results if r is True)
        invalid_count = len(self.proxies) - valid_count
        
        logger.info(f"Proxy validation complete: {valid_count} valid, {invalid_count} invalid")
        
        return {
            "valid": valid_count,
            "invalid": invalid_count,
            "total": len(self.proxies)
        }
    
    def get_stats(self) -> Dict:
        """Get proxy manager statistics"""
        valid_count = sum(1 for p in self.proxies if p.is_valid)
        return {
            "enabled": self.enabled,
            "total_proxies": len(self.proxies),
            "valid_proxies": valid_count,
            "invalid_proxies": len(self.proxies) - valid_count,
            "rotation_mode": self._rotation_mode.value,
            "current_index": self.current_index
        }
    
    def to_list(self) -> List[Dict]:
        """Export proxies as list of dicts"""
        return [
            {
                "host": p.host,
                "port": p.port,
                "type": p.proxy_type.value,
                "has_auth": bool(p.username),
                "is_valid": p.is_valid,
                "success_count": p.success_count,
                "fail_count": p.fail_count,
                "avg_response_time": round(p.avg_response_time, 2)
            }
            for p in self.proxies
        ]


# Global proxy manager instance
proxy_manager = ProxyManager()


def get_proxy_manager() -> ProxyManager:
    """Get the global proxy manager instance"""
    return proxy_manager
