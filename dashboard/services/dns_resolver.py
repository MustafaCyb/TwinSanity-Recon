"""
TwinSanity Recon V2 - Enhanced DNS Resolution Service
Provides comprehensive DNS resolution beyond simple A records.
"""
import asyncio
import logging
from typing import Dict, List, Optional, Tuple
from dataclasses import dataclass
import dns.resolver
import dns.exception

logger = logging.getLogger("DNSResolver")


@dataclass
class DNSResult:
    """Complete DNS resolution result for a hostname."""
    hostname: str
    a_records: List[str]
    aaaa_records: List[str]
    cname_chain: List[str]
    mx_records: List[str]
    txt_records: List[str]
    ns_records: List[str]
    is_wildcard: bool = False
    response_time_ms: int = 0


async def resolve_dns_full(
    hostname: str,
    timeout: float = 5.0
) -> DNSResult:
    """
    Perform comprehensive DNS resolution for a hostname.
    Resolves A, AAAA, CNAME, MX, TXT, NS records.
    """
    loop = asyncio.get_event_loop()
    
    result = DNSResult(
        hostname=hostname,
        a_records=[],
        aaaa_records=[],
        cname_chain=[],
        mx_records=[],
        txt_records=[],
        ns_records=[]
    )
    
    # Create resolver with timeout
    resolver = dns.resolver.Resolver()
    resolver.timeout = timeout
    resolver.lifetime = timeout
    
    async def query_record(record_type: str) -> List[str]:
        """Query a specific record type."""
        try:
            answers = await loop.run_in_executor(
                None, 
                lambda: resolver.resolve(hostname, record_type)
            )
            return [str(rdata) for rdata in answers]
        except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers):
            return []
        except dns.exception.Timeout:
            logger.debug(f"DNS timeout for {hostname} {record_type}")
            return []
        except Exception as e:
            logger.debug(f"DNS error for {hostname} {record_type}: {e}")
            return []
    
    import time
    start = time.time()
    
    # Query all record types concurrently
    tasks = {
        'A': query_record('A'),
        'AAAA': query_record('AAAA'),
        'CNAME': query_record('CNAME'),
        'MX': query_record('MX'),
        'TXT': query_record('TXT'),
        'NS': query_record('NS'),
    }
    
    results = await asyncio.gather(*tasks.values(), return_exceptions=True)
    
    result.response_time_ms = int((time.time() - start) * 1000)
    
    for record_type, res in zip(tasks.keys(), results):
        if isinstance(res, list):
            if record_type == 'A':
                result.a_records = res
            elif record_type == 'AAAA':
                result.aaaa_records = res
            elif record_type == 'CNAME':
                result.cname_chain = res
            elif record_type == 'MX':
                result.mx_records = [r.split()[-1].rstrip('.') if ' ' in r else r.rstrip('.') for r in res]
            elif record_type == 'TXT':
                result.txt_records = res
            elif record_type == 'NS':
                result.ns_records = [ns.rstrip('.') for ns in res]
    
    return result


async def resolve_hosts_enhanced(
    hostnames: List[str],
    concurrency: int = 50
) -> Dict[str, DNSResult]:
    """
    Resolve multiple hostnames with full DNS information.
    """
    results = {}
    semaphore = asyncio.Semaphore(concurrency)
    
    async def resolve_with_semaphore(hostname: str) -> Tuple[str, DNSResult]:
        async with semaphore:
            result = await resolve_dns_full(hostname)
            return hostname, result
    
    tasks = [resolve_with_semaphore(h) for h in hostnames]
    resolved = await asyncio.gather(*tasks, return_exceptions=True)
    
    for item in resolved:
        if isinstance(item, tuple):
            hostname, result = item
            results[hostname] = result
    
    logger.info(f"Resolved {len(results)} hostnames with full DNS info")
    return results


async def detect_wildcard(domain: str) -> bool:
    """
    Detect if a domain has wildcard DNS configured.
    Check if random subdomains resolve.
    """
    import random
    import string
    
    # Generate random subdomain
    random_sub = ''.join(random.choices(string.ascii_lowercase, k=12))
    test_hostname = f"{random_sub}.{domain}"
    
    result = await resolve_dns_full(test_hostname, timeout=3.0)
    
    if result.a_records or result.cname_chain:
        logger.warning(f"Wildcard DNS detected for {domain}")
        return True
    
    return False


async def follow_cname_chain(hostname: str, max_depth: int = 10) -> List[str]:
    """
    Follow CNAME chain to find the final target.
    Useful for detecting CDNs, proxies, and cloud services.
    """
    chain = [hostname]
    current = hostname
    
    resolver = dns.resolver.Resolver()
    resolver.timeout = 3.0
    resolver.lifetime = 3.0
    
    loop = asyncio.get_event_loop()
    
    for _ in range(max_depth):
        try:
            answers = await loop.run_in_executor(
                None,
                lambda h=current: resolver.resolve(h, 'CNAME')
            )
            cname = str(list(answers)[0]).rstrip('.')
            chain.append(cname)
            current = cname
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            break
        except Exception:
            break
    
    return chain


def detect_cdn_from_cname(cname_chain: List[str]) -> Optional[str]:
    """
    Detect CDN/hosting provider from CNAME chain.
    """
    cdn_patterns = {
        'cloudflare': ['cloudflare.com', 'cloudflare.net'],
        'cloudfront': ['cloudfront.net', 'amazonaws.com'],
        'akamai': ['akamai.net', 'akamaiedge.net', 'akamaitechnologies.com'],
        'fastly': ['fastly.net', 'fastlylb.net'],
        'azure': ['azurewebsites.net', 'azure-dns.com', 'azurefd.net', 'azure.com'],
        'google': ['googlehosted.com', 'google.com', 'googleapis.com'],
        'aws': ['amazonaws.com', 'awsdns-'],
        'incapsula': ['incapdns.net', 'imperva.com'],
        'sucuri': ['sucuri.net'],
        'stackpath': ['stackpath.com', 'stackpathdns.com'],
        'vercel': ['vercel.app', 'now.sh', 'vercel-dns.com'],
        'netlify': ['netlify.app', 'netlify.com'],
        'github': ['github.io', 'githubusercontent.com'],
        'heroku': ['herokuapp.com', 'herokussl.com'],
    }
    
    for cname in cname_chain:
        cname_lower = cname.lower()
        for cdn_name, patterns in cdn_patterns.items():
            for pattern in patterns:
                if pattern in cname_lower:
                    return cdn_name
    
    return None


def extract_ips_from_results(dns_results: Dict[str, DNSResult]) -> Dict[str, List[str]]:
    """
    Extract IP addresses from DNS results.
    Compatible with existing code that expects simple IP lists.
    """
    ip_map = {}
    
    for hostname, result in dns_results.items():
        ips = []
        
        # Add IPv4 addresses
        ips.extend(result.a_records)
        
        # Optionally add IPv6 (uncomment if needed)
        # ips.extend(result.aaaa_records)
        
        if ips:
            ip_map[hostname] = ips
    
    return ip_map
