"""
TwinSanity Recon V2 - Scanner Service
Handles the main scan orchestration background task.
Enhanced with granular progress tracking and real-time statistics broadcasting.
"""
import sys
import asyncio
import json
import time
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional, Tuple

from dashboard.config import (
    PROJECT_ROOT, logger, RESULTS_DIR, DNS_CONCURRENCY, IP_CONCURRENCY, 
    MAX_CVES_PER_IP, SCAN_TIMEOUT, HTTP_PROBING_CONCURRENCY, HTTP_PROBING_TIMEOUT,
    XSS_SCAN_CONCURRENCY, XSS_SCAN_MAX_URLS, SCAN_VALIDATE_DNS,
    NUCLEI_TEMPLATES, NUCLEI_SEVERITY, NUCLEI_RATE_LIMIT, NUCLEI_CONCURRENCY,
    URL_HARVESTING_SOURCES, URL_HARVESTING_TIMEOUT, API_DISCOVERY_MAX_ENDPOINTS
)
from dashboard.models import ScanConfig
from dashboard.database import get_db
from dashboard.state import state
from dashboard.websocket.manager import manager, MessageType
from dashboard.subdomain_sources import enumerate_subdomains
from dashboard.services.ai_service import run_ai_analysis_on_results


# =====================================================================
# SCAN PHASE DEFINITIONS
# =====================================================================
class ScanPhase:
    """Defines all scan phases with their progress ranges."""
    INIT = ("Initialization", 1, 0, 5)
    SUBDOMAIN_DISCOVERY = ("Subdomain Discovery", 2, 5, 20)
    BRUTE_FORCE = ("Brute Force Discovery", 3, 20, 30)
    DNS_RESOLUTION = ("DNS Resolution", 4, 30, 40)
    INTERNETDB_LOOKUP = ("InternetDB Lookup", 5, 40, 55)
    CVE_ENRICHMENT = ("CVE Enrichment", 6, 55, 70)
    EPSS_KEV = ("EPSS/KEV Analysis", 7, 70, 75)
    HTTP_PROBING = ("HTTP Probing", 8, 75, 82)
    URL_HARVESTING = ("URL Harvesting", 9, 82, 86)
    NUCLEI_SCAN = ("Vulnerability Scanning", 10, 86, 90)
    XSS_SCAN = ("XSS Detection", 11, 90, 93)
    API_DISCOVERY = ("API Discovery", 12, 93, 96)
    AI_ANALYSIS = ("AI Analysis", 13, 96, 99)
    COMPLETE = ("Complete", 14, 100, 100)
    
    TOTAL_PHASES = 14


def calculate_phase_progress(phase: Tuple, current: int, total: int) -> int:
    """Calculate overall progress based on phase progress."""
    _, _, start_pct, end_pct = phase
    if total == 0:
        return start_pct
    phase_progress = (current / total)
    return int(start_pct + (end_pct - start_pct) * phase_progress)


# Helper to count IPs excluding metadata
def count_actual_ips(results: Dict) -> int:
    metadata_keys = {"timestamp", "domain", "result_file", "findings_summary", "_metadata"}
    return len([ip for ip in results if ip not in metadata_keys])

async def run_scan(scan_id: str, config: ScanConfig, user_id: int):
    """
    Background task that runs the actual scan using:
    - Multi-source subdomain enumeration (async)
    - SQLite database for persistence
    - InternetDB for port/CVE data
    - Real-time progress tracking with granular phase updates
    """
    # Ensure project root is in path for TwinSanity_Recon imports
    sys.path.insert(0, str(PROJECT_ROOT))
    
    # Initialize database
    db = await get_db()
    
    # Create scan in database
    await db.create_scan(scan_id, config.domain, config.model_dump(), user_id)
    
    # Phase timing tracker
    phase_timings: Dict[str, float] = {}
    
    # Helper to check if scan was cancelled
    def is_cancelled() -> bool:
        return state.is_cancelled(scan_id)
    
    # Helper for phase broadcasts with timing
    async def start_phase(phase: Tuple, description: str = ""):
        """Start a new scan phase with broadcast."""
        phase_name, phase_num, start_pct, _ = phase
        phase_timings[phase_name] = time.time()
        
        state.update_scan(scan_id, status="running", progress=start_pct, current_phase=phase_name)
        await db.update_scan(scan_id, progress=start_pct)
        
        await manager.broadcast_phase_start(
            scan_id, 
            phase_name, 
            phase_num, 
            ScanPhase.TOTAL_PHASES,
            description or f"Starting {phase_name}..."
        )
        await manager.broadcast(scan_id, {
            "type": "status", 
            "status": "running", 
            "progress": start_pct,
            "message": description or f"Starting {phase_name}...",
            "phase": phase_name,
            "phase_num": phase_num,
            "total_phases": ScanPhase.TOTAL_PHASES
        })
    
    async def update_phase_progress(phase: Tuple, current: int, total: int, item: str = ""):
        """Update progress within a phase with throttling."""
        phase_name, _, _, _ = phase
        progress = calculate_phase_progress(phase, current, total)
        
        state.update_scan(scan_id, progress=progress)
        
        # Throttle WebSocket updates - only send every 5th update or on significant milestones
        # This prevents browser lag from too many updates
        should_broadcast = (
            current <= 5 or  # First 5 updates
            current == total or  # Last update
            current % max(1, total // 20) == 0 or  # Every ~5% progress
            current % 10 == 0  # Every 10 items
        )
        
        if should_broadcast:
            await manager.broadcast_phase_progress(scan_id, phase_name, current, total, item)
            
            # Also send legacy status message for backwards compatibility
            await manager.broadcast(scan_id, {
                "type": "progress",
                "progress": progress,
                "message": f"{phase_name}: {current}/{total}" + (f" - {item}" if item else ""),
                "current": current,
                "total": total
            })
    
    async def complete_phase(phase: Tuple, results_count: int):
        """Complete a phase with timing info."""
        phase_name, _, _, end_pct = phase
        duration_ms = int((time.time() - phase_timings.get(phase_name, time.time())) * 1000)
        
        state.update_scan(scan_id, progress=end_pct)
        await db.update_scan(scan_id, progress=end_pct)
        await manager.broadcast_phase_complete(scan_id, phase_name, results_count, duration_ms)
    
    # Initialize statistics tracking
    manager.update_stats(scan_id, 
        total_subdomains=0, 
        live_subdomains=0,
        total_ips=0, 
        total_cves=0,
        critical_cves=0,
        high_cves=0,
        medium_cves=0,
        low_cves=0
    )
    
    # =====================================================================
    # Phase 1: INITIALIZATION
    # =====================================================================
    await start_phase(ScanPhase.INIT, "Initializing scan environment...")
    
    try:
        # Check for cancellation early
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # Import legacy functions we still need
        from TwinSanity_Recon import (
            create_session, fetch_internetdb, fetch_cve_details,
            load_cve_cache, save_cve_cache, resolve_hosts_concurrent
        )
        
        session = create_session()
        domain = config.domain
        
        # Initialize proxy support
        proxy_dict = None
        if config.use_proxies:
            from dashboard.proxy_manager import get_proxy_manager
            proxy_mgr = get_proxy_manager()
            if proxy_mgr.enabled and proxy_mgr.proxies:
                proxy = await proxy_mgr.get_next_proxy()
                if proxy:
                    proxy_dict = proxy.to_requests_dict()
                    await manager.broadcast(scan_id, {
                        "type": "log",
                        "message": f"🔒 Proxy enabled: {proxy.host}:{proxy.port}"
                    })
        
        # Get event loop for executor calls
        loop = asyncio.get_event_loop()
        
        await complete_phase(ScanPhase.INIT, 1)
        
        # Check cancellation between phases
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        loop = asyncio.get_event_loop()
        
        # =====================================================================
        # Phase 2: Multi-Source Subdomain Discovery (ASYNC)
        # =====================================================================
        await start_phase(ScanPhase.SUBDOMAIN_DISCOVERY, f"Discovering subdomains for {domain}...")
        
        # Build sources config from scan config (user-selected sources)
        user_sources = getattr(config, 'subdomain_sources', None) or {}
        sources = {
            "crtsh": user_sources.get("crtsh", True) if config.subdomain_discovery else False,
            "hackertarget": user_sources.get("hackertarget", True) if config.subdomain_discovery else False,
            "rapiddns": user_sources.get("rapiddns", True) if config.subdomain_discovery else False,
            "urlscan": user_sources.get("urlscan", True) if config.subdomain_discovery else False,
            "webarchive": user_sources.get("webarchive", True) if config.subdomain_discovery else False,
            "bufferover": user_sources.get("bufferover", True) if config.subdomain_discovery else False,
            "certspotter": user_sources.get("certspotter", True) if config.subdomain_discovery else False,
            # New high-value sources
            "securitytrails": user_sources.get("securitytrails", True) if config.subdomain_discovery else False,
            "virustotal": user_sources.get("virustotal", True) if config.subdomain_discovery else False,
            "threatcrowd": user_sources.get("threatcrowd", True) if config.subdomain_discovery else False,
            "chaos": user_sources.get("chaos", True) if config.subdomain_discovery else False,
        }
        
        # DNS validation option (use config default if not specified in scan config)
        validate_dns = getattr(config, 'validate_dns', SCAN_VALIDATE_DNS)
        
        # Run async subdomain enumeration
        if config.subdomain_discovery:
            active_sources = [k for k, v in sources.items() if v]
            await manager.broadcast(scan_id, {
                "type": "log",
                "message": f"🔍 Querying {len(active_sources)} sources: {', '.join(active_sources)}"
            })
            
            subdomains = await enumerate_subdomains(
                domain,
                sources=sources,
                validate_dns=validate_dns,
                timeout=SCAN_TIMEOUT
            )
            
            # Update statistics
            manager.update_stats(scan_id, total_subdomains=len(subdomains))
            await manager.broadcast_stats(scan_id)
            
            # Broadcast each subdomain found (for real-time UI update)
            for i, subdomain in enumerate(list(subdomains)[:50]):  # First 50 for UI
                await manager.broadcast_typed(scan_id, MessageType.SUBDOMAIN_FOUND, {
                    "subdomain": subdomain,
                    "index": i + 1,
                    "total": len(subdomains)
                })
            
            # In delta-only mode, skip subdomains observed previously.
            baseline = {s.lower() for s in (config.baseline_subdomains or [])}
            if config.delta_only and baseline:
                before = len(subdomains)
                subdomains = {s for s in subdomains if s.lower() not in baseline}
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"Δ Delta scan: filtered {before - len(subdomains)} previously seen subdomains"
                })
            
            await manager.broadcast(scan_id, {
                "type": "log",
                "message": f"✅ Found {len(subdomains)} subdomains from multiple sources"
            })
        else:
            subdomains = {domain}
            manager.update_stats(scan_id, total_subdomains=1)
            await manager.broadcast(scan_id, {
                "type": "log",
                "message": "Subdomain discovery disabled, using target domain only"
            })
        
        await complete_phase(ScanPhase.SUBDOMAIN_DISCOVERY, len(subdomains))
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 3: Brute Force Subdomain Discovery (if enabled)
        # =====================================================================
        if config.brute_force and config.wordlist:
            await start_phase(ScanPhase.BRUTE_FORCE, f"Brute forcing subdomains with wordlist: {config.wordlist}...")
            
            from TwinSanity_Recon import brute_force_subdomains
            from dashboard.wordlist_manager import wordlist_manager, WORDLIST_DIR
            
            # Get wordlist path or generate temporary file for builtin wordlists
            wordlist_id = config.wordlist
            if wordlist_id.startswith("custom:"):
                wl_path = WORDLIST_DIR / f"{wordlist_id.replace('custom:', '')}.txt"
            else:
                # Generate temporary file from builtin wordlist
                import tempfile
                temp_wl = tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False)
                entries = list(wordlist_manager.get_wordlist_entries(wordlist_id))
                total_entries = len(entries)
                for entry in entries:
                    temp_wl.write(entry + '\n')
                temp_wl.close()
                wl_path = Path(temp_wl.name)
                
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"📝 Loaded {total_entries} entries from {wordlist_id} wordlist"
                })
            
            if wl_path.exists():
                # Run brute force in executor (it's synchronous)
                bf_subdomains = await loop.run_in_executor(
                    None,
                    lambda: brute_force_subdomains(domain, wl_path, concurrency=DNS_CONCURRENCY)
                )
                
                # Merge with discovered subdomains
                new_from_bf = bf_subdomains - subdomains
                subdomains.update(bf_subdomains)
                
                # Update statistics
                manager.update_stats(scan_id, total_subdomains=len(subdomains))
                await manager.broadcast_stats(scan_id)
                
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"✅ Brute force found {len(new_from_bf)} additional subdomains ({len(bf_subdomains)} total resolved)"
                })
                
                # Clean up temp file if created
                if not wordlist_id.startswith("custom:"):
                    try:
                        wl_path.unlink()
                    except Exception as e:
                        logger.debug(f"Failed to cleanup temp wordlist file: {e}")
                
                await complete_phase(ScanPhase.BRUTE_FORCE, len(new_from_bf))
            else:
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"⚠️ Wordlist not found: {wl_path}"
                })
                await complete_phase(ScanPhase.BRUTE_FORCE, 0)
            
            # Check cancellation
            if is_cancelled():
                raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 4: DNS Resolution
        # =====================================================================
        await start_phase(ScanPhase.DNS_RESOLUTION, f"Resolving {len(subdomains)} hosts...")
        await db.update_scan(scan_id, subdomains_count=len(subdomains))
        
        # Use run_in_executor for sync DNS resolution
        resolved = await loop.run_in_executor(
            None,
            lambda: resolve_hosts_concurrent(list(subdomains), concurrency=DNS_CONCURRENCY)
        )
        
        # Build IP map
        ip_map: Dict[str, List[str]] = {}
        for host, ips in resolved.items():
            for ip in ips:
                ip_map.setdefault(ip, [])
                if host not in ip_map[ip]:
                    ip_map[ip].append(host)
        
        # Update statistics
        manager.update_stats(scan_id, 
            total_ips=len(ip_map),
            live_subdomains=len(resolved)
        )
        await manager.broadcast_stats(scan_id)
        
        # Broadcast IP resolution results
        for i, (ip, hosts) in enumerate(ip_map.items()):
            await manager.broadcast_typed(scan_id, MessageType.IP_RESOLVED, {
                "ip": ip,
                "hosts": hosts,
                "index": i + 1,
                "total": len(ip_map)
            })
            await update_phase_progress(ScanPhase.DNS_RESOLUTION, i + 1, len(ip_map), ip)
        
        await manager.broadcast(scan_id, {
            "type": "log",
            "message": f"✅ Resolved to {len(ip_map)} unique IPs from {len(resolved)} live hosts"
        })
        
        await complete_phase(ScanPhase.DNS_RESOLUTION, len(ip_map))
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 5: Shodan/InternetDB Lookup (PARALLEL with progress)
        # =====================================================================
        results = {}
        if config.shodan_lookup and ip_map:
            await start_phase(ScanPhase.INTERNETDB_LOOKUP, f"Querying InternetDB for {len(ip_map)} IPs...")
            await db.update_scan(scan_id, ips_count=len(ip_map))
            
            total_ips = len(ip_map)
            ip_list = list(ip_map.items())
            
            # Semaphore to limit concurrent requests (avoid overwhelming API)
            sem = asyncio.Semaphore(IP_CONCURRENCY)  # Max concurrent IP requests from config
            completed_count = [0]  # Mutable counter for progress tracking
            
            async def fetch_ip_data(ip: str, hosts: list, max_retries: int = 3) -> tuple:
                """Fetch InternetDB data for a single IP with semaphore and retry logic"""
                async with sem:
                    # Check cancellation before each IP
                    if is_cancelled():
                        return ip, hosts, {"ok": False, "error": "cancelled"}
                    
                    result = None
                    for attempt in range(max_retries):
                        try:
                            result = await loop.run_in_executor(
                                None, lambda i=ip, p=proxy_dict: fetch_internetdb(session, i, proxies=p)
                            )
                            # If successful or 404 (no data), don't retry
                            if result.get("ok") or result.get("status") == 404:
                                break
                            # Retry on other errors after delay
                            if attempt < max_retries - 1:
                                await asyncio.sleep(1.0 * (attempt + 1))
                        except Exception as e:
                            if attempt == max_retries - 1:
                                result = {"source": "internetdb", "ok": False, "error": str(e)}
                            else:
                                await asyncio.sleep(1.0 * (attempt + 1))
                    
                    completed_count[0] += 1
                    
                    # Update progress and broadcast
                    await update_phase_progress(ScanPhase.INTERNETDB_LOOKUP, completed_count[0], total_ips, ip)
                    
                    # Broadcast host scanned event for real-time UI
                    if result and result.get("ok"):
                        ports = result.get("data", {}).get("ports", [])
                        vulns = result.get("data", {}).get("vulns", [])
                        await manager.broadcast_typed(scan_id, MessageType.HOST_SCANNED, {
                            "ip": ip,
                            "hosts": hosts,
                            "ports_count": len(ports),
                            "vulns_count": len(vulns),
                            "ports": ports[:10]  # First 10 ports
                        })
                    
                    return ip, hosts, result
            
            # Run all InternetDB queries in parallel
            tasks = [fetch_ip_data(ip, hosts) for ip, hosts in ip_list]
            fetched_results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Process results
            successful_lookups = 0
            for item in fetched_results:
                if isinstance(item, Exception):
                    logger.warning(f"InternetDB fetch error: {item}")
                    continue
                ip, hosts, result = item
                results[ip] = {
                    "ip": ip,
                    "hosts": hosts,
                    "internetdb": result,
                    "cve_details": []
                }
                if result and result.get("ok"):
                    successful_lookups += 1
            
            await manager.broadcast(scan_id, {
                "type": "log",
                "message": f"✅ InternetDB lookup complete: {successful_lookups}/{total_ips} IPs returned data"
            })
            
            await complete_phase(ScanPhase.INTERNETDB_LOOKUP, successful_lookups)
        else:
            # Just build basic results without InternetDB
            for ip, hosts in ip_map.items():
                results[ip] = {"ip": ip, "hosts": hosts, "internetdb": {}, "cve_details": []}
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 6: CVE Enrichment (with caching)
        # =====================================================================
        total_cves = 0
        if config.cve_enrichment and results:
            await start_phase(ScanPhase.CVE_ENRICHMENT, "Enriching CVE details...")
            
            cache_path = RESULTS_DIR / "cve_cache.json"
            cve_cache = load_cve_cache(cache_path) if cache_path.exists() else {}
            
            findings_to_save = []
            
            # Collect all unique CVEs to fetch
            cve_to_ips: Dict[str, List[str]] = {}  # CVE -> list of IPs that have it
            ip_cve_ports: Dict[str, list] = {}  # IP -> ports
            
            for ip, data in results.items():
                idb = data.get("internetdb", {})
                if idb.get("ok"):
                    vulns = idb.get("data", {}).get("vulns", [])
                    ports = idb.get("data", {}).get("ports", [])
                    ip_cve_ports[ip] = ports
                    
                    if isinstance(vulns, list):
                        # Process ALL CVEs - no artificial limit
                        for cve in vulns:
                            if cve not in cve_to_ips:
                                cve_to_ips[cve] = []
                            cve_to_ips[cve].append(ip)
            
            # Check which CVEs need fetching (not in cache)
            cves_to_fetch = []
            cve_details_map: Dict[str, Dict] = {}
            
            for cve in cve_to_ips:
                cached = await db.get_cached_cve(cve)
                if cached:
                    cve_details_map[cve] = cached
                else:
                    cves_to_fetch.append(cve)
            
            await manager.broadcast(scan_id, {
                "type": "log",
                "message": f"📊 {len(cve_to_ips)} unique CVEs found, {len(cves_to_fetch)} need fetching"
            })
            
            # Parallel CVE fetching with semaphore
            if cves_to_fetch:
                cve_sem = asyncio.Semaphore(min(MAX_CVES_PER_IP, 10))  # Limit concurrent CVE API calls from config
                # Prioritize sources that return CVSS scores: shodan > nvd > circl
                selected_sources = getattr(config, 'cve_sources', None) or ["shodan", "nvd", "circl"]
                fetched_count = [0]
                total_to_fetch = len(cves_to_fetch)
                
                async def fetch_single_cve(cve: str) -> tuple:
                    """Fetch a single CVE with semaphore"""
                    async with cve_sem:
                        detail = await loop.run_in_executor(
                            None,
                            lambda c=cve, p=proxy_dict: fetch_cve_details(
                                session, c, cve_cache, cve_sources=selected_sources, proxies=p
                            )
                        )
                        fetched_count[0] += 1
                        # Progress update every 10 CVEs
                        if fetched_count[0] % 10 == 0 or fetched_count[0] == total_to_fetch:
                            await manager.broadcast(scan_id, {
                                "type": "log",
                                "message": f"🔍 Fetched {fetched_count[0]}/{total_to_fetch} CVE details..."
                            })
                        # Small delay to respect rate limits
                        await asyncio.sleep(0.3)
                        return cve, detail
                
                # Fetch all CVEs in parallel
                cve_tasks = [fetch_single_cve(cve) for cve in cves_to_fetch]
                cve_results = await asyncio.gather(*cve_tasks, return_exceptions=True)
                
                # Process fetched results
                for item in cve_results:
                    if isinstance(item, Exception):
                        logger.warning(f"CVE fetch error: {item}")
                        continue
                    cve, detail = item
                    cve_details_map[cve] = detail
                    # Cache in database only if we have a valid CVSS score
                    cvss_to_cache = detail.get("cvss") or detail.get("cvss3")
                    if detail.get("summary") and cvss_to_cache and float(cvss_to_cache) > 0:
                        await db.cache_cve(
                            cve,
                            cvss=float(cvss_to_cache),
                            summary=detail.get("summary"),
                            source=detail.get("source")
                        )
            
            # Map CVE details back to IPs and track severity counts
            critical_count = 0
            high_count = 0
            medium_count = 0
            low_count = 0
            
            for cve, ips in cve_to_ips.items():
                detail = cve_details_map.get(cve, {})
                if detail.get("summary"):
                    for ip in ips:
                        if ip in results:
                            results[ip]["cve_details"].append(detail)
                            total_cves += 1
                            
                            # Prepare finding for database with severity
                            cvss_val = float(detail.get("cvss") or detail.get("cvss3") or 0)
                            if cvss_val >= 9.0:
                                severity = "critical"
                                critical_count += 1
                            elif cvss_val >= 7.0:
                                severity = "high"
                                high_count += 1
                            elif cvss_val >= 4.0:
                                severity = "medium"
                                medium_count += 1
                            else:
                                severity = "low"
                                low_count += 1
                            
                            # Broadcast CVE found event
                            await manager.broadcast_typed(scan_id, MessageType.CVE_FOUND, {
                                "cve_id": cve,
                                "cvss": cvss_val,
                                "severity": severity,
                                "ip": ip,
                                "summary": detail.get("summary", "")[:100]
                            })
                                
                            findings_to_save.append({
                                "scan_id": scan_id,
                                "ip": ip,
                                "hostname": results[ip]["hosts"][0] if results[ip]["hosts"] else None,
                                "finding_type": "cve",
                                "cve_id": cve,
                                "cvss": cvss_val,
                                "severity": severity,
                                "summary": detail.get("summary"),
                                "ports": ip_cve_ports.get(ip, []),
                            })
            
            # Update statistics
            manager.update_stats(scan_id,
                total_cves=total_cves,
                critical_cves=critical_count,
                high_cves=high_count,
                medium_cves=medium_count,
                low_cves=low_count
            )
            await manager.broadcast_stats(scan_id)
            
            # Save findings to database
            if findings_to_save:
                await db.save_findings_batch(findings_to_save)
            
            # Save legacy cache
            save_cve_cache(cache_path, cve_cache)
            
            await complete_phase(ScanPhase.CVE_ENRICHMENT, total_cves)
            
            # Check cancellation
            if is_cancelled():
                raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 7: CVE Enrichment (EPSS + KEV)
        # =====================================================================
        if config.cve_enrichment and total_cves > 0:
            await start_phase(ScanPhase.EPSS_KEV, "Enriching CVEs with EPSS scores and KEV status...")
            
            try:
                from dashboard.services.cve_enrichment import enrich_cves, calculate_risk_score
                
                # Collect all CVEs for enrichment
                all_cves = []
                for ip, data in results.items():
                    if ip.startswith("_"):
                        continue
                    for cve_detail in data.get("cve_details", []):
                        if cve_detail not in all_cves:
                            all_cves.append(cve_detail)
                
                if all_cves:
                    enriched = await enrich_cves(all_cves, verify=False)
                    
                    # Build CVE enrichment map
                    enrichment_map = {}
                    kev_count = 0
                    high_epss_count = 0
                    
                    for ecve in enriched:
                        enrichment_map[ecve.cve_id] = {
                            "epss_score": ecve.epss_score,
                            "epss_percentile": ecve.epss_percentile,
                            "is_kev": ecve.is_kev,
                            "kev_due_date": ecve.kev_due_date,
                            "risk_score": calculate_risk_score(ecve)
                        }
                        if ecve.is_kev:
                            kev_count += 1
                        if ecve.epss_score > 0.1:
                            high_epss_count += 1
                    
                    # Apply enrichment back to results
                    for ip, data in results.items():
                        if ip.startswith("_"):
                            continue
                        for cve_detail in data.get("cve_details", []):
                            cve_id = cve_detail.get("id") or cve_detail.get("cve_id")
                            if cve_id and cve_id in enrichment_map:
                                cve_detail.update(enrichment_map[cve_id])
                    
                    await manager.broadcast(scan_id, {
                        "type": "log",
                        "message": f"✅ CVE enrichment complete: {kev_count} KEV, {high_epss_count} high-EPSS"
                    })
                    logger.info(f"Scan {scan_id}: CVE enrichment - {kev_count} KEV, {high_epss_count} high-EPSS")
                    
                    await complete_phase(ScanPhase.EPSS_KEV, len(enriched))
            except Exception as enrich_err:
                logger.warning(f"CVE enrichment failed: {enrich_err}")
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"⚠️ CVE enrichment skipped: {str(enrich_err)[:100]}"
                })
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # INTERMEDIATE: Save results before tool phases
        # =====================================================================
        # Count actual IPs (exclude metadata keys)
        actual_ip_count = count_actual_ips(results)
        
        # Update database with current progress
        await db.update_scan(
            scan_id,
            subdomains_count=len(subdomains),
            ips_count=actual_ip_count,
            cves_count=total_cves
        )
        
        # Save results file with metadata including all discovered subdomains
        RESULTS_DIR.mkdir(parents=True, exist_ok=True)
        results_file = RESULTS_DIR / f"scan_{scan_id}.json"
        
        # Add _metadata section with all discovered subdomains
        results_with_meta = {
            "_metadata": {
                "scan_id": scan_id,
                "domain": domain,
                "total_subdomains_discovered": len(subdomains),
                "all_subdomains": sorted(list(subdomains)),
                "resolved_ips": len(results),
                "total_cves": total_cves
            },
            **results
        }
        
        results_file.write_text(json.dumps(results_with_meta, indent=2, ensure_ascii=False), encoding="utf-8")
        await db.update_scan(scan_id, result_file=str(results_file))
        
        # =====================================================================
        # Phase 8: HTTP Probing (if enabled) - MUST RUN BEFORE AI ANALYSIS
        # =====================================================================
        http_probing_enabled = getattr(config, 'http_probing', False)
        if http_probing_enabled and subdomains:
            await start_phase(ScanPhase.HTTP_PROBING, f"HTTP probing {len(subdomains)} subdomains...")
            
            try:
                from dashboard.services.httpx_prober import probe_hosts, save_probe_results
                
                probe_results = await probe_hosts(
                    list(subdomains),
                    concurrency=HTTP_PROBING_CONCURRENCY,
                    timeout=HTTP_PROBING_TIMEOUT
                )
                
                if probe_results:
                    await save_probe_results(scan_id, probe_results)
                    
                    # Update statistics
                    manager.update_stats(scan_id, http_live=len(probe_results))
                    await manager.broadcast_stats(scan_id)
                    
                    # Broadcast each HTTP result
                    for i, result in enumerate(probe_results[:20]):  # First 20 for UI
                        await manager.broadcast_typed(scan_id, MessageType.HTTPX_RESULT, {
                            "url": result.get("url"),
                            "status_code": result.get("status_code"),
                            "title": result.get("title", ""),
                            "tech": result.get("tech", [])
                        })
                    
                    await manager.broadcast(scan_id, {
                        "type": "log",
                        "message": f"✅ HTTP probing complete: {len(probe_results)} alive hosts found"
                    })
                    logger.info(f"Scan {scan_id}: HTTP probing found {len(probe_results)} alive hosts")
                    
                    await complete_phase(ScanPhase.HTTP_PROBING, len(probe_results))
            except Exception as probe_err:
                logger.error(f"Scan {scan_id}: HTTP probing failed: {probe_err}")
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"⚠️ HTTP probing failed: {str(probe_err)[:100]}"
                })
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 9: URL Harvesting (if enabled)
        # =====================================================================
        url_harvesting_enabled = getattr(config, 'url_harvesting', False)
        if url_harvesting_enabled:
            await start_phase(ScanPhase.URL_HARVESTING, f"Harvesting historical URLs for {domain}...")
            
            try:
                from dashboard.services.url_harvester import harvest_urls, save_harvested_urls
                
                harvest_results = await harvest_urls(
                    domain,
                    sources=URL_HARVESTING_SOURCES,
                    timeout=URL_HARVESTING_TIMEOUT
                )
                
                total_urls = sum(len(v) for v in harvest_results.values())
                if total_urls > 0:
                    await save_harvested_urls(scan_id, harvest_results)
                    
                    # Update statistics
                    manager.update_stats(scan_id, urls_found=total_urls)
                    await manager.broadcast_stats(scan_id)
                    
                    await manager.broadcast(scan_id, {
                        "type": "log",
                        "message": f"✅ URL harvesting complete: {total_urls} URLs found"
                    })
                    logger.info(f"Scan {scan_id}: URL harvesting found {total_urls} URLs")
                    
                    await complete_phase(ScanPhase.URL_HARVESTING, total_urls)
            except Exception as harvest_err:
                logger.error(f"Scan {scan_id}: URL harvesting failed: {harvest_err}")
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"⚠️ URL harvesting failed: {str(harvest_err)[:100]}"
                })
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 10: Nuclei Vulnerability Scanning (if enabled)
        # =====================================================================
        nuclei_scan_enabled = getattr(config, 'nuclei_scan', False)
        if nuclei_scan_enabled:
            await start_phase(ScanPhase.NUCLEI_SCAN, "Running vulnerability scanning...")
            
            try:
                from dashboard.services.nuclei_scanner import (
                    check_nuclei_installed, run_nuclei_scan, run_python_vuln_checks, save_nuclei_findings
                )
                from dashboard.services.httpx_prober import get_alive_hosts
                
                # Get alive hosts to scan
                alive = await get_alive_hosts(scan_id)
                targets = [h["url"] for h in alive if h.get("url")]
                
                # If no alive hosts from probing, use subdomains with https
                if not targets:
                    targets = [f"https://{s}" for s in list(subdomains)[:100]]  # Limit to 100
                
                if targets:
                    nuclei_installed = check_nuclei_installed()
                    
                    if nuclei_installed:
                        findings = await run_nuclei_scan(
                            targets,
                            templates=NUCLEI_TEMPLATES,
                            severity=NUCLEI_SEVERITY,
                            rate_limit=NUCLEI_RATE_LIMIT,
                            concurrency=NUCLEI_CONCURRENCY,
                            timeout=300
                        )
                    else:
                        # Use Python fallback
                        findings = await run_python_vuln_checks(targets)
                    
                    if findings:
                        await save_nuclei_findings(scan_id, findings)
                        critical_count = len([f for f in findings if f.get("severity") == "critical"])
                        high_count = len([f for f in findings if f.get("severity") == "high"])
                        
                        # Update statistics
                        manager.update_stats(scan_id, 
                            nuclei_findings=len(findings),
                            total_vulnerabilities=len(findings)
                        )
                        await manager.broadcast_stats(scan_id)
                        
                        # Broadcast nuclei findings
                        for finding in findings[:10]:  # First 10 for UI
                            await manager.broadcast_typed(scan_id, MessageType.NUCLEI_RESULT, {
                                "template_id": finding.get("template_id"),
                                "severity": finding.get("severity"),
                                "host": finding.get("host"),
                                "matched": finding.get("matched_at", "")
                            })
                        
                        await manager.broadcast(scan_id, {
                            "type": "log",
                            "message": f"✅ Vuln scan complete: {len(findings)} findings ({critical_count} critical, {high_count} high)"
                        })
                        logger.info(f"Scan {scan_id}: Nuclei found {len(findings)} vulnerabilities")
                        
                        await complete_phase(ScanPhase.NUCLEI_SCAN, len(findings))
            except Exception as nuclei_err:
                logger.error(f"Scan {scan_id}: Nuclei scan failed: {nuclei_err}")
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"⚠️ Vulnerability scanning failed: {str(nuclei_err)[:100]}"
                })
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 11: XSS Scanning (if enabled)
        # =====================================================================
        xss_scan_enabled = getattr(config, 'xss_scan', False)
        if xss_scan_enabled:
            await start_phase(ScanPhase.XSS_SCAN, "Testing for XSS vulnerabilities...")
            
            try:
                from dashboard.services.xss_scanner import scan_urls_for_xss, save_xss_findings
                from dashboard.services.url_harvester import get_harvested_urls
                
                # Get harvested URLs for XSS testing
                harvested = await get_harvested_urls(scan_id)
                urls_with_params = [u["url"] for u in harvested if u.get("has_params")]
                
                if urls_with_params:
                    # Limit URLs based on config (XSS_SCAN_MAX_URLS)
                    xss_results = await scan_urls_for_xss(
                        urls_with_params[:XSS_SCAN_MAX_URLS],
                        concurrency=XSS_SCAN_CONCURRENCY
                    )
                    if xss_results:
                        await save_xss_findings(scan_id, xss_results)
                        
                        # Update statistics
                        manager.update_stats(scan_id, xss_findings=len(xss_results))
                        await manager.broadcast_stats(scan_id)
                        
                        # Broadcast XSS findings
                        for xss in xss_results[:5]:  # First 5 for UI
                            await manager.broadcast_typed(scan_id, MessageType.XSS_RESULT, {
                                "url": xss.get("url"),
                                "parameter": xss.get("parameter"),
                                "payload": xss.get("payload", "")[:50]
                            })
                        
                        await manager.broadcast(scan_id, {
                            "type": "log",
                            "message": f"✅ XSS scan complete: {len(xss_results)} potential XSS found"
                        })
                        logger.info(f"Scan {scan_id}: XSS scan found {len(xss_results)} vulnerabilities")
                        
                        await complete_phase(ScanPhase.XSS_SCAN, len(xss_results))
                else:
                    await manager.broadcast(scan_id, {
                        "type": "log",
                        "message": "ℹ️ No URLs with parameters found for XSS testing"
                    })
            except Exception as xss_err:
                logger.error(f"Scan {scan_id}: XSS scan failed: {xss_err}")
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"⚠️ XSS scanning failed: {str(xss_err)[:100]}"
                })
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 12: API Discovery (if enabled)
        # =====================================================================
        api_discovery_enabled = getattr(config, 'api_discovery', False)
        if api_discovery_enabled:
            await start_phase(ScanPhase.API_DISCOVERY, "Discovering API endpoints...")
            
            try:
                from dashboard.services.api_discovery import discover_apis, save_api_discoveries
                from dashboard.services.httpx_prober import get_alive_hosts
                
                # Get alive hosts for API discovery
                alive = await get_alive_hosts(scan_id)
                base_urls = [h["url"] for h in alive if h.get("url")]
                
                # If no alive hosts, use subdomains with https
                if not base_urls:
                    base_urls = [f"https://{s}" for s in list(subdomains)[:20]]
                
                if base_urls:
                    # Limit endpoints based on config
                    max_hosts = min(API_DISCOVERY_MAX_ENDPOINTS // 50, 10)  # Roughly 50 paths per host
                    api_results = await discover_apis(base_urls[:max_hosts])
                    if api_results:
                        await save_api_discoveries(scan_id, api_results)
                        
                        # Update statistics
                        manager.update_stats(scan_id, api_endpoints=len(api_results))
                        await manager.broadcast_stats(scan_id)
                        
                        # Broadcast API endpoints
                        for api in api_results[:10]:  # First 10 for UI
                            await manager.broadcast_typed(scan_id, MessageType.API_ENDPOINT, {
                                "url": api.get("url"),
                                "method": api.get("method", "GET"),
                                "status": api.get("status_code")
                            })
                        
                        await manager.broadcast(scan_id, {
                            "type": "log",
                            "message": f"✅ API discovery complete: {len(api_results)} endpoints found"
                        })
                        logger.info(f"Scan {scan_id}: API discovery found {len(api_results)} endpoints")
                        
                        await complete_phase(ScanPhase.API_DISCOVERY, len(api_results))
            except Exception as api_err:
                logger.error(f"Scan {scan_id}: API discovery failed: {api_err}")
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"⚠️ API discovery failed: {str(api_err)[:100]}"
                })
        
        # Check cancellation
        if is_cancelled():
            raise asyncio.CancelledError("Scan was cancelled by user")
        
        # =====================================================================
        # Phase 13: V1-Style AI Analysis (RUNS LAST - after all tools complete)
        # This ensures AI analysis includes all tool findings
        # =====================================================================
        ai_analysis_enabled = getattr(config, 'ai_analysis', False)
        if ai_analysis_enabled and results:
            await start_phase(ScanPhase.AI_ANALYSIS, "Running AI analysis (Gemini→Cloud→Local pipeline)...")
            
            try:
                # Load all tool findings for comprehensive AI analysis
                from dashboard.scan_context import load_tools_findings_for_llm
                tools_findings = await load_tools_findings_for_llm(scan_id)
                
                # Run V1-style chunk analysis with tools findings
                ai_report = await run_ai_analysis_on_results(results, scan_id, tools_findings=tools_findings)
                
                if ai_report and not ai_report.get("error"):
                    # Save AI report to database
                    await db.save_ai_analysis_report(scan_id, ai_report)
                    
                    # Build summary message
                    nuclei_count = tools_findings.get("nuclei_findings", {}).get("count", 0)
                    xss_count = tools_findings.get("xss_findings", {}).get("count", 0)
                    api_count = tools_findings.get("api_discoveries", {}).get("count", 0)
                    
                    tool_summary = []
                    if nuclei_count > 0:
                        tool_summary.append(f"{nuclei_count} vulns")
                    if xss_count > 0:
                        tool_summary.append(f"{xss_count} XSS")
                    if api_count > 0:
                        tool_summary.append(f"{api_count} APIs")
                    
                    tools_msg = f" + {', '.join(tool_summary)}" if tool_summary else ""
                    
                    # Broadcast AI analysis complete
                    await manager.broadcast_typed(scan_id, MessageType.AI_SUMMARY, {
                        "cves_analyzed": len(ai_report.get('all_cves', [])),
                        "chunks_processed": ai_report.get('chunks_processed', 0),
                        "tools_analyzed": tool_summary,
                        "provider": ai_report.get('provider', 'unknown')
                    })
                    
                    await manager.broadcast(scan_id, {
                        "type": "log",
                        "message": f"✅ AI analysis complete: {len(ai_report.get('all_cves', []))} CVEs analyzed{tools_msg}"
                    })
                    logger.info(f"Scan {scan_id}: AI analysis saved with {len(ai_report.get('all_cves', []))} CVEs and tools findings")
                    
                    await complete_phase(ScanPhase.AI_ANALYSIS, len(ai_report.get('all_cves', [])))
                else:
                    await manager.broadcast(scan_id, {
                        "type": "log",
                        "message": "⚠️ AI analysis completed but no results generated"
                    })
            except Exception as ai_err:
                logger.error(f"Scan {scan_id}: AI analysis failed: {ai_err}")
                await manager.broadcast(scan_id, {
                    "type": "log",
                    "message": f"⚠️ AI analysis failed: {str(ai_err)[:100]}"
                })
        
        # =====================================================================
        # FINAL: Mark scan as complete
        # =====================================================================
        await start_phase(ScanPhase.COMPLETE, "Finalizing scan results...")
        
        # Final statistics update
        final_stats = manager.get_stats(scan_id)
        if final_stats:
            final_stats.last_updated = datetime.now().isoformat()
            await manager.broadcast_stats(scan_id)
        
        # Update final state
        state.update_scan(scan_id, status="completed", progress=100, results=results)
        await db.update_scan(
            scan_id,
            status="completed",
            progress=100,
            subdomains_count=len(subdomains),
            ips_count=count_actual_ips(results),
            cves_count=total_cves
        )
        
        # Calculate total scan duration
        scan_duration = int((time.time() - phase_timings.get("Initialization", time.time())) * 1000)
        
        # Broadcast completion with comprehensive summary
        await manager.broadcast(scan_id, {
            "type": "complete",
            "status": "completed",
            "progress": 100,
            "message": f"Scan complete: {len(subdomains)} subdomains, {count_actual_ips(results)} IPs, {total_cves} CVEs",
            "summary": {
                "total_subdomains": len(subdomains),
                "total_ips": count_actual_ips(results),
                "total_cves": total_cves,
                "duration_ms": scan_duration,
                "stats": final_stats.to_dict() if final_stats else {}
            }
        })
        
        # Cleanup WebSocket manager data for this scan
        manager.cleanup_scan(scan_id)
        
        logger.info(f"Scan {scan_id} completed in {scan_duration/1000:.1f}s: {len(subdomains)} subdomains, {len(results)} IPs, {total_cves} CVEs")
        
    except asyncio.CancelledError:
        # Scan was cancelled by user
        logger.info(f"Scan {scan_id} was cancelled by user")
        state.update_scan(scan_id, status="cancelled")
        state.clear_cancelled(scan_id)
        await db.update_scan(scan_id, status="cancelled")
        
        # Broadcast cancellation
        await manager.broadcast_typed(scan_id, MessageType.CANCELLED, {
            "message": "Scan was cancelled by user"
        })
        await manager.broadcast(scan_id, {
            "type": "status", 
            "status": "cancelled", 
            "message": "Scan was cancelled by user"
        })
        
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}", exc_info=True)
        state.update_scan(scan_id, status="failed", error=str(e))
        state.clear_cancelled(scan_id)  # Clear cancellation flag if any
        await db.update_scan(scan_id, status="failed", error=str(e))
        await manager.broadcast(scan_id, {"type": "error", "status": "failed", "message": str(e)})

