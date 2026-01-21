"""
TwinSanity Recon V2 - Multi-Source Subdomain Enumeration
Fixed version with proper async handling, rate limiting, and caching
"""
import asyncio
import aiohttp
import logging
import socket
import re
import time
import json
from pathlib import Path
from typing import Set, Optional, Dict
from dataclasses import dataclass
from datetime import datetime, timedelta

import yaml

logger = logging.getLogger("SubdomainSources")

# Load config for rate limits
CONFIG_FILE = Path(__file__).parent.parent / "config.yaml"
CACHE_DIR = Path(__file__).parent.parent / "results"

def load_subdomain_config() -> dict:
    """Load subdomain source configuration from config.yaml"""
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, 'r') as f:
                config = yaml.safe_load(f) or {}
                return config.get('subdomain_sources', {})
        except Exception as e:
            logger.warning(f"Failed to load config.yaml: {e}")
    return {}

SUBDOMAIN_CONFIG = load_subdomain_config()

# Track last call times for rate limiting (HIGH-2 fix)
_last_call_times: Dict[str, float] = {}

# Simple in-memory cache for subdomains (persists during runtime)
_subdomain_cache: Dict[str, Dict] = {}


def get_cached_subdomains(domain: str, max_age_hours: int = 24) -> Optional[Set[str]]:
    """Get cached subdomains if available and not expired."""
    cache_key = domain.lower().strip()
    
    # Check in-memory cache first
    if cache_key in _subdomain_cache:
        cached = _subdomain_cache[cache_key]
        cache_time = datetime.fromisoformat(cached.get("timestamp", "2000-01-01"))
        if datetime.now() - cache_time < timedelta(hours=max_age_hours):
            logger.info(f"Using cached subdomains for {domain} ({len(cached['subdomains'])} subdomains)")
            return set(cached.get("subdomains", []))
    
    # Check file cache
    cache_file = CACHE_DIR / f"subdomain_cache_{cache_key.replace('.', '_')}.json"
    if cache_file.exists():
        try:
            with open(cache_file, 'r') as f:
                cached = json.load(f)
                cache_time = datetime.fromisoformat(cached.get("timestamp", "2000-01-01"))
                if datetime.now() - cache_time < timedelta(hours=max_age_hours):
                    # Update in-memory cache
                    _subdomain_cache[cache_key] = cached
                    logger.info(f"Loaded cached subdomains for {domain} ({len(cached['subdomains'])} subdomains)")
                    return set(cached.get("subdomains", []))
        except Exception as e:
            logger.debug(f"Failed to load cache: {e}")
    
    return None


def save_subdomain_cache(domain: str, subdomains: Set[str]):
    """Save subdomains to cache."""
    cache_key = domain.lower().strip()
    cache_data = {
        "domain": domain,
        "subdomains": list(subdomains),
        "timestamp": datetime.now().isoformat(),
        "count": len(subdomains)
    }
    
    # Update in-memory cache
    _subdomain_cache[cache_key] = cache_data
    
    # Save to file cache
    try:
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cache_file = CACHE_DIR / f"subdomain_cache_{cache_key.replace('.', '_')}.json"
        with open(cache_file, 'w') as f:
            json.dump(cache_data, f, indent=2)
        logger.info(f"Cached {len(subdomains)} subdomains for {domain}")
    except Exception as e:
        logger.debug(f"Failed to save cache: {e}")


def clear_subdomain_cache(domain: str) -> bool:
    """Clear cached subdomains for a specific domain (used by rescan)."""
    cache_key = domain.lower().strip()
    cleared = False
    
    # Clear in-memory cache
    if cache_key in _subdomain_cache:
        del _subdomain_cache[cache_key]
        cleared = True
        logger.info(f"Cleared in-memory cache for {domain}")
    
    # Clear file cache
    try:
        cache_file = CACHE_DIR / f"subdomain_cache_{cache_key.replace('.', '_')}.json"
        if cache_file.exists():
            cache_file.unlink()
            cleared = True
            logger.info(f"Deleted cache file for {domain}")
    except Exception as e:
        logger.warning(f"Failed to delete cache file for {domain}: {e}")
    
    return cleared


async def rate_limited_call(source_name: str):
    """Enforce per-source rate limits from config (HIGH-2 fix)."""
    source_config = SUBDOMAIN_CONFIG.get(source_name, {})
    rate_limit = source_config.get('rate_limit', 0.5)  # Default 0.5s between calls
    
    now = time.time()
    last_call = _last_call_times.get(source_name, 0)
    wait_time = max(0, rate_limit - (now - last_call))
    
    if wait_time > 0:
        logger.debug(f"[{source_name}] Rate limit: waiting {wait_time:.2f}s")
        await asyncio.sleep(wait_time)
    
    _last_call_times[source_name] = time.time()


@dataclass
class SourceResult:
    source: str
    subdomains: Set[str]
    success: bool
    error: Optional[str] = None


class SubdomainEnumerator:
    def __init__(self, timeout: int = 30):
        self.timeout = aiohttp.ClientTimeout(total=timeout, connect=10)
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }

    async def enumerate(
        self,
        domain: str,
        sources: Dict[str, bool] = None,
        validate_dns: bool = False,
        use_cache: bool = True,
        cache_max_age_hours: int = 24
    ) -> Set[str]:
        # Check cache first if enabled
        if use_cache:
            cached = get_cached_subdomains(domain, cache_max_age_hours)
            if cached:
                return cached
        
        if sources is None:
            sources = {
                "crtsh": True,
                "hackertarget": True,
                "rapiddns": True,
                "urlscan": True,
                "webarchive": True,
                "bufferover": True,
                "certspotter": True,
            }

        all_subdomains: Set[str] = set()
        
        # Always include base domain
        all_subdomains.add(domain)

        async with aiohttp.ClientSession(timeout=self.timeout, headers=self.headers) as session:
            tasks = []
            
            if sources.get("crtsh"):
                tasks.append(self._crtsh(session, domain))
            if sources.get("hackertarget"):
                tasks.append(self._hackertarget(session, domain))
            if sources.get("rapiddns"):
                tasks.append(self._rapiddns(session, domain))
            if sources.get("urlscan"):
                tasks.append(self._urlscan(session, domain))
            if sources.get("webarchive"):
                tasks.append(self._webarchive(session, domain))
            if sources.get("bufferover"):
                tasks.append(self._bufferover(session, domain))
            if sources.get("certspotter"):
                tasks.append(self._certspotter(session, domain))
            if sources.get("alienvault"):
                tasks.append(self._alienvault(session, domain))
            if sources.get("anubis"):
                tasks.append(self._anubis(session, domain))
            if sources.get("dnsdumpster"):
                tasks.append(self._dnsdumpster(session, domain))
            if sources.get("shodan"):
                tasks.append(self._shodan(session, domain))
            if sources.get("securitytrails"):
                tasks.append(self._securitytrails(session, domain))
            if sources.get("virustotal"):
                tasks.append(self._virustotal(session, domain))
            if sources.get("threatcrowd"):
                tasks.append(self._threatcrowd(session, domain))
            if sources.get("chaos"):
                tasks.append(self._chaos(session, domain))

            if tasks:
                results = await asyncio.gather(*tasks, return_exceptions=True)
                
                failed_sources = []
                for result in results:
                    if isinstance(result, SourceResult):
                        if result.success:
                            logger.info(f"[{result.source}] Found {len(result.subdomains)} subdomains")
                            all_subdomains.update(result.subdomains)
                        else:
                            logger.warning(f"[{result.source}] Failed: {result.error}")
                            # Track failed sources for retry (only for recoverable errors)
                            if result.error and ("503" in result.error or "Timeout" in result.error or "429" in result.error):
                                failed_sources.append(result.source)
                    elif isinstance(result, Exception):
                        logger.warning(f"Source exception: {result}")
                
                # Retry failed sources once after a delay (improves consistency)
                if failed_sources:
                    logger.info(f"Retrying {len(failed_sources)} failed sources after delay...")
                    await asyncio.sleep(3)  # Wait before retry
                    
                    retry_tasks = []
                    source_map = {
                        "crt.sh": (sources.get("crtsh"), self._crtsh),
                        "hackertarget": (sources.get("hackertarget"), self._hackertarget),
                        "rapiddns": (sources.get("rapiddns"), self._rapiddns),
                        "urlscan": (sources.get("urlscan"), self._urlscan),
                        "virustotal": (sources.get("virustotal"), self._virustotal),
                        "chaos": (sources.get("chaos"), self._chaos),
                        "certspotter": (sources.get("certspotter"), self._certspotter),
                    }
                    
                    for src_name in failed_sources:
                        if src_name in source_map and source_map[src_name][0]:
                            retry_tasks.append(source_map[src_name][1](session, domain))
                    
                    if retry_tasks:
                        retry_results = await asyncio.gather(*retry_tasks, return_exceptions=True)
                        for result in retry_results:
                            if isinstance(result, SourceResult) and result.success:
                                logger.info(f"[{result.source}] Retry success: {len(result.subdomains)} subdomains")
                                all_subdomains.update(result.subdomains)

        # Filter valid subdomains
        valid_subs = self._filter_valid(all_subdomains, domain)
        logger.info(f"Total unique subdomains: {len(valid_subs)}")

        # Optional DNS validation
        if validate_dns and len(valid_subs) > 1:
            valid_subs = await self._validate_dns_batch(valid_subs)
            logger.info(f"After DNS validation: {len(valid_subs)}")

        # Save to cache for consistency in future scans
        if use_cache and len(valid_subs) > 0:
            save_subdomain_cache(domain, valid_subs)

        return valid_subs

    def _filter_valid(self, subdomains: Set[str], domain: str) -> Set[str]:
        valid = set()
        domain_lower = domain.lower().strip()

        for sub in subdomains:
            if not sub:
                continue
            sub = sub.strip().lower()
            
            # Remove wildcards
            while sub.startswith("*."):
                sub = sub[2:]
            sub = sub.lstrip(".")

            # Basic validation
            if not re.match(r'^[a-z0-9]([a-z0-9\-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9\-]*[a-z0-9])?)*$', sub):
                continue

            # Must be target domain or subdomain
            if sub == domain_lower or sub.endswith(f".{domain_lower}"):
                valid.add(sub)

        return valid

    async def _validate_dns_batch(self, subdomains: Set[str], concurrency: int = 50) -> Set[str]:
        semaphore = asyncio.Semaphore(concurrency)
        
        async def check(sub: str) -> Optional[str]:
            async with semaphore:
                try:
                    loop = asyncio.get_event_loop()
                    await asyncio.wait_for(
                        loop.run_in_executor(None, socket.gethostbyname, sub),
                        timeout=3.0
                    )
                    return sub
                except:
                    return None

        results = await asyncio.gather(*[check(s) for s in subdomains])
        return {r for r in results if r}

    # =========================================================================
    # Source Implementations (with rate limiting - HIGH-2 fix)
    # =========================================================================

    async def _crtsh(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """crt.sh Certificate Transparency"""
        try:
            await rate_limited_call("crtsh")  # Apply rate limit
            url = f"https://crt.sh/?q=%25.{domain}&output=json"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("crt.sh", set(), False, f"HTTP {resp.status}")
                
                try:
                    data = await resp.json(content_type=None)
                except:
                    return SourceResult("crt.sh", set(), False, "Invalid JSON")

                subdomains = set()
                if isinstance(data, list):
                    for entry in data:
                        name = entry.get("name_value") or entry.get("common_name") or ""
                        for line in name.split("\n"):
                            line = line.strip().lower().replace("*.", "")
                            if line and domain.lower() in line:
                                subdomains.add(line)

                return SourceResult("crt.sh", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("crt.sh", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("crt.sh", set(), False, str(e)[:80])

    async def _hackertarget(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """HackerTarget API"""
        try:
            await rate_limited_call("hackertarget")  # Apply rate limit
            url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("hackertarget", set(), False, f"HTTP {resp.status}")
                
                text = await resp.text()
                
                if "error" in text.lower() or "API count exceeded" in text:
                    return SourceResult("hackertarget", set(), False, "Rate limited")

                subdomains = set()
                for line in text.split("\n"):
                    if "," in line:
                        sub = line.split(",")[0].strip().lower()
                        if sub and domain.lower() in sub:
                            subdomains.add(sub)

                return SourceResult("hackertarget", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("hackertarget", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("hackertarget", set(), False, str(e)[:80])

    async def _rapiddns(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """RapidDNS"""
        try:
            await rate_limited_call("rapiddns")  # Apply rate limit
            url = f"https://rapiddns.io/subdomain/{domain}?full=1"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("rapiddns", set(), False, f"HTTP {resp.status}")
                
                text = await resp.text()
                subdomains = set()

                # Extract from table cells
                pattern = rf'<td>([a-zA-Z0-9][-a-zA-Z0-9.]*\.{re.escape(domain)})</td>'
                matches = re.findall(pattern, text, re.IGNORECASE)
                for match in matches:
                    subdomains.add(match.lower())

                # Also try generic pattern
                pattern2 = rf'>([a-zA-Z0-9][-a-zA-Z0-9.]*\.{re.escape(domain)})<'
                matches2 = re.findall(pattern2, text, re.IGNORECASE)
                for match in matches2:
                    subdomains.add(match.lower())

                return SourceResult("rapiddns", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("rapiddns", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("rapiddns", set(), False, str(e)[:80])

    async def _urlscan(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """URLScan.io"""
        try:
            await rate_limited_call("urlscan")  # Apply rate limit
            url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=1000"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("urlscan", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()

                for result in data.get("results", []):
                    page = result.get("page", {})
                    if page.get("domain"):
                        sub = page["domain"].lower()
                        if domain.lower() in sub:
                            subdomains.add(sub)
                    task = result.get("task", {})
                    if task.get("domain"):
                        sub = task["domain"].lower()
                        if domain.lower() in sub:
                            subdomains.add(sub)

                return SourceResult("urlscan", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("urlscan", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("urlscan", set(), False, str(e)[:80])

    async def _webarchive(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """Web Archive / Wayback Machine"""
        try:
            await rate_limited_call("webarchive")  # Apply rate limit
            url = f"https://web.archive.org/cdx/search/cdx?url=*.{domain}&output=json&fl=original&collapse=urlkey&limit=3000"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("webarchive", set(), False, f"HTTP {resp.status}")
                
                try:
                    data = await resp.json(content_type=None)
                except:
                    return SourceResult("webarchive", set(), False, "Invalid JSON")

                subdomains = set()
                if isinstance(data, list) and len(data) > 1:
                    from urllib.parse import urlparse
                    for row in data[1:]:  # Skip header
                        if row and len(row) > 0:
                            try:
                                parsed = urlparse(row[0])
                                host = parsed.netloc.lower().split(":")[0]
                                if host and domain.lower() in host:
                                    subdomains.add(host)
                            except:
                                pass

                return SourceResult("webarchive", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("webarchive", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("webarchive", set(), False, str(e)[:80])

    async def _bufferover(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """BufferOver DNS"""
        try:
            await rate_limited_call("bufferover")  # Apply rate limit
            url = f"https://dns.bufferover.run/dns?q=.{domain}"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("bufferover", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()

                # FDNS records
                for record in data.get("FDNS_A", []) or []:
                    if isinstance(record, str) and "," in record:
                        sub = record.split(",")[1].strip().lower()
                        if sub and domain.lower() in sub:
                            subdomains.add(sub)

                # RDNS records
                for record in data.get("RDNS", []) or []:
                    if isinstance(record, str) and "," in record:
                        sub = record.split(",")[1].strip().lower()
                        if sub and domain.lower() in sub:
                            subdomains.add(sub)

                return SourceResult("bufferover", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("bufferover", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("bufferover", set(), False, str(e)[:80])

    async def _certspotter(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """CertSpotter"""
        try:
            await rate_limited_call("certspotter")  # Apply rate limit
            url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
            async with session.get(url) as resp:
                if resp.status == 429:
                    return SourceResult("certspotter", set(), False, "Rate limited")
                if resp.status != 200:
                    return SourceResult("certspotter", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()

                if isinstance(data, list):
                    for cert in data:
                        dns_names = cert.get("dns_names", []) or []
                        for name in dns_names:
                            name = name.strip().lower().replace("*.", "")
                            if name and domain.lower() in name:
                                subdomains.add(name)

                return SourceResult("certspotter", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("certspotter", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("certspotter", set(), False, str(e)[:80])

    async def _alienvault(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """AlienVault OTX - Open Threat Exchange"""
        try:
            await rate_limited_call("alienvault")
            url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
            async with session.get(url) as resp:
                if resp.status == 429:
                    return SourceResult("alienvault", set(), False, "Rate limited")
                if resp.status != 200:
                    return SourceResult("alienvault", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()

                for record in data.get("passive_dns", []):
                    hostname = record.get("hostname", "").strip().lower()
                    if hostname and domain.lower() in hostname:
                        subdomains.add(hostname)

                return SourceResult("alienvault", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("alienvault", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("alienvault", set(), False, str(e)[:80])

    async def _anubis(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """Anubis-DB - Subdomain database"""
        try:
            await rate_limited_call("anubis")
            url = f"https://jldc.me/anubis/subdomains/{domain}"
            async with session.get(url) as resp:
                if resp.status == 429:
                    return SourceResult("anubis", set(), False, "Rate limited")
                if resp.status != 200:
                    return SourceResult("anubis", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()

                if isinstance(data, list):
                    for subdomain in data:
                        sub = subdomain.strip().lower()
                        if sub and domain.lower() in sub:
                            subdomains.add(sub)

                return SourceResult("anubis", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("anubis", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("anubis", set(), False, str(e)[:80])

    async def _dnsdumpster(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """DNSdumpster - DNS recon"""
        try:
            await rate_limited_call("dnsdumpster")
            # DNSdumpster requires CSRF token and more complex handling
            # Using a simpler API endpoint alternative
            url = f"https://api.hackertarget.com/dnslookup/?q={domain}"
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("dnsdumpster", set(), False, f"HTTP {resp.status}")
                
                text = await resp.text()
                subdomains = set()

                # Parse DNS records for subdomains
                for line in text.split("\n"):
                    if domain.lower() in line.lower():
                        # Extract potential hostnames
                        parts = line.split()
                        for part in parts:
                            part = part.strip().lower().rstrip(".")
                            if part.endswith(domain.lower()):
                                subdomains.add(part)

                return SourceResult("dnsdumpster", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("dnsdumpster", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("dnsdumpster", set(), False, str(e)[:80])

    async def _shodan(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """Shodan - Internet search engine (requires API key from config)"""
        try:
            await rate_limited_call("shodan")
            
            # Load Shodan API key from config
            config = load_subdomain_config()
            api_keys = {}
            if CONFIG_FILE.exists():
                try:
                    with open(CONFIG_FILE, 'r') as f:
                        full_config = yaml.safe_load(f) or {}
                        api_keys = full_config.get('api_keys', {})
                except:
                    pass
            
            shodan_key = api_keys.get('shodan', '')
            if not shodan_key:
                return SourceResult("shodan", set(), False, "No API key configured")
            
            url = f"https://api.shodan.io/dns/domain/{domain}?key={shodan_key}"
            async with session.get(url) as resp:
                if resp.status == 401:
                    return SourceResult("shodan", set(), False, "Invalid API key")
                if resp.status == 429:
                    return SourceResult("shodan", set(), False, "Rate limited")
                if resp.status != 200:
                    return SourceResult("shodan", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()

                # Extract from Shodan DNS response
                for subdomain in data.get("subdomains", []):
                    full_sub = f"{subdomain}.{domain}".lower()
                    subdomains.add(full_sub)
                
                # Also add the base domain and any other records
                for record in data.get("data", []):
                    if "subdomain" in record:
                        sub = record["subdomain"]
                        if sub:
                            full_sub = f"{sub}.{domain}".lower()
                            subdomains.add(full_sub)

                return SourceResult("shodan", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("shodan", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("shodan", set(), False, str(e)[:80])

    # =========================================================================
    # NEW HIGH-VALUE SOURCES FOR BETTER ACCURACY
    # =========================================================================

    async def _securitytrails(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """SecurityTrails - High-value subdomain source (requires API key)."""
        try:
            await rate_limited_call("securitytrails")
            
            # Load API key from config
            api_keys = {}
            if CONFIG_FILE.exists():
                try:
                    with open(CONFIG_FILE, 'r') as f:
                        full_config = yaml.safe_load(f) or {}
                        api_keys = full_config.get('api_keys', {})
                except:
                    pass
            
            api_key = api_keys.get('securitytrails', '')
            if not api_key:
                return SourceResult("securitytrails", set(), False, "No API key")
            
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": api_key}
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 401:
                    return SourceResult("securitytrails", set(), False, "Invalid API key")
                if resp.status == 429:
                    return SourceResult("securitytrails", set(), False, "Rate limited")
                if resp.status != 200:
                    return SourceResult("securitytrails", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()
                
                for subdomain in data.get("subdomains", []):
                    full_sub = f"{subdomain}.{domain}".lower()
                    subdomains.add(full_sub)
                
                return SourceResult("securitytrails", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("securitytrails", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("securitytrails", set(), False, str(e)[:80])

    async def _virustotal(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """VirusTotal - Subdomain enumeration using VT API."""
        try:
            await rate_limited_call("virustotal")
            
            # Load API key from config
            api_keys = {}
            if CONFIG_FILE.exists():
                try:
                    with open(CONFIG_FILE, 'r') as f:
                        full_config = yaml.safe_load(f) or {}
                        api_keys = full_config.get('api_keys', {})
                except:
                    pass
            
            api_key = api_keys.get('virustotal', '')
            if not api_key:
                return SourceResult("virustotal", set(), False, "No API key")
            
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"
            headers = {"x-apikey": api_key}
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 401:
                    return SourceResult("virustotal", set(), False, "Invalid API key")
                if resp.status == 429:
                    return SourceResult("virustotal", set(), False, "Rate limited")
                if resp.status != 200:
                    return SourceResult("virustotal", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()
                
                for item in data.get("data", []):
                    subdomain_id = item.get("id", "")
                    if subdomain_id and domain.lower() in subdomain_id.lower():
                        subdomains.add(subdomain_id.lower())
                
                return SourceResult("virustotal", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("virustotal", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("virustotal", set(), False, str(e)[:80])

    async def _threatcrowd(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """ThreatCrowd - Free threat intelligence API."""
        try:
            await rate_limited_call("threatcrowd")
            
            url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
            
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("threatcrowd", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()
                
                for subdomain in data.get("subdomains", []):
                    sub = subdomain.strip().lower()
                    if sub and domain.lower() in sub:
                        subdomains.add(sub)
                
                return SourceResult("threatcrowd", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("threatcrowd", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("threatcrowd", set(), False, str(e)[:80])

    async def _chaos(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """ProjectDiscovery Chaos - Bug bounty subdomain data (requires API key)."""
        try:
            await rate_limited_call("chaos")
            
            # Load API key from config
            api_keys = {}
            if CONFIG_FILE.exists():
                try:
                    with open(CONFIG_FILE, 'r') as f:
                        full_config = yaml.safe_load(f) or {}
                        api_keys = full_config.get('api_keys', {})
                except:
                    pass
            
            api_key = api_keys.get('chaos', '')
            if not api_key:
                return SourceResult("chaos", set(), False, "No API key")
            
            url = f"https://dns.projectdiscovery.io/dns/{domain}/subdomains"
            headers = {"Authorization": api_key}
            
            async with session.get(url, headers=headers) as resp:
                if resp.status == 401:
                    return SourceResult("chaos", set(), False, "Invalid API key")
                if resp.status == 404:
                    return SourceResult("chaos", set(), True)  # Domain not in database
                if resp.status != 200:
                    return SourceResult("chaos", set(), False, f"HTTP {resp.status}")
                
                data = await resp.json()
                subdomains = set()
                
                for subdomain in data.get("subdomains", []):
                    full_sub = f"{subdomain}.{domain}".lower()
                    subdomains.add(full_sub)
                
                return SourceResult("chaos", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("chaos", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("chaos", set(), False, str(e)[:80])

    async def _crtsh_with_wildcards(self, session: aiohttp.ClientSession, domain: str) -> SourceResult:
        """Enhanced crt.sh query that also captures wildcard certificates."""
        try:
            await rate_limited_call("crtsh")
            
            # Query for wildcards specifically
            url = f"https://crt.sh/?q=%.{domain}&output=json"
            
            async with session.get(url) as resp:
                if resp.status != 200:
                    return SourceResult("crtsh_wildcards", set(), False, f"HTTP {resp.status}")
                
                try:
                    data = await resp.json(content_type=None)
                except:
                    return SourceResult("crtsh_wildcards", set(), False, "Invalid JSON")

                subdomains = set()
                if isinstance(data, list):
                    for entry in data:
                        name = entry.get("name_value") or entry.get("common_name") or ""
                        for line in name.split("\n"):
                            line = line.strip().lower()
                            # Track wildcards for later analysis
                            if line.startswith("*."):
                                line = line[2:]  # Remove *. prefix
                            if line and domain.lower() in line:
                                subdomains.add(line)

                return SourceResult("crtsh_wildcards", subdomains, True)
        except asyncio.TimeoutError:
            return SourceResult("crtsh_wildcards", set(), False, "Timeout")
        except Exception as e:
            return SourceResult("crtsh_wildcards", set(), False, str(e)[:80])


# Convenience function
async def enumerate_subdomains(
    domain: str,
    sources: Dict[str, bool] = None,
    validate_dns: bool = False,
    timeout: int = 30
) -> Set[str]:
    enumerator = SubdomainEnumerator(timeout=timeout)
    return await enumerator.enumerate(domain, sources=sources, validate_dns=validate_dns)


