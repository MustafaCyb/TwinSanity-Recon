from __future__ import annotations
import argparse
import concurrent.futures
import csv
import ipaddress
import json
import logging
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Dict, List, Optional, Set, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from tqdm import tqdm
from dotenv import load_dotenv
import subprocess


# ---------- Configuration ----------
CVE_CACHE_FILENAME = "cve_cache.json"
DEFAULT_UA = "internetdb-fetcher/3.1"
load_dotenv(".env")
SHODAN_API_KEY = os.getenv("SHODAN_API_KEY")
NVD_API_KEY = os.getenv("NVD_API_KEY")
# -----------------------------------

def create_session(retries: int = 4, backoff: float = 0.5, ua: str = DEFAULT_UA,
                   pool_connections: int = 100, pool_maxsize: int = 100) -> requests.Session:
    """Create a requests.Session with a larger connection pool to avoid 'Connection pool is full'."""
    s = requests.Session()
    retry = Retry(
        total=retries,
        backoff_factor=backoff,
        status_forcelist=[429, 500, 502, 503, 504],
        allowed_methods=["HEAD", "GET", "OPTIONS"],
        raise_on_status=False,
    )
    adapter = HTTPAdapter(max_retries=retry, pool_connections=pool_connections, pool_maxsize=pool_maxsize)
    s.mount("https://", adapter)
    s.mount("http://", adapter)
    s.headers.update({"User-Agent": ua})
    return s

def sanitize_filename(name: str, maxlen: int = 80) -> str:
    name = name.rstrip('.')
    name = re.sub(r'[^A-Za-z0-9\-\._]', '_', name)
    return name[:maxlen]

# ---------------- Subdomain discovery ----------------
def crtsh_passive(domain: str, session: Optional[requests.Session] = None, timeout: int = 20) -> Set[str]:
    session = session or create_session()
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subs: Set[str] = set()
    try:
        r = session.get(url, timeout=timeout)
        if r.status_code != 200:
            logging.debug("crt.sh returned %s", r.status_code)
            return subs
        data = r.json()
        for entry in data:
            nv = entry.get("name_value") or entry.get("common_name")
            if not nv:
                continue
            for name in str(nv).split("\n"):
                name = name.strip().lower()
                if not name:
                    continue
                name = name.lstrip("*.")
                if name.endswith(domain) or name == domain:
                    subs.add(name)
    except Exception as e:
        logging.debug("crt.sh passive enumeration failed: %s", e)
    return subs

def brute_force_subdomains(domain: str, wordlist_path: Path, concurrency: int = 50) -> Set[str]:
    subs: Set[str] = set()
    if not wordlist_path.exists():
        logging.error("Wordlist not found: %s", wordlist_path)
        return subs

    def test_name(hostname: str) -> Optional[str]:
        try:
            socket.getaddrinfo(hostname, None)
            return hostname
        except Exception:
            return None

    lines = [l.strip() for l in wordlist_path.read_text(encoding='utf-8', errors='ignore').splitlines() if l.strip()]
    names = [f"{w}.{domain}" for w in lines]
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(test_name, n): n for n in names}
        for fut in concurrent.futures.as_completed(futures):
            try:
                ok = fut.result()
            except Exception:
                ok = None
            if ok:
                subs.add(ok.lower())
    return subs

# ---------------- DNS resolution ----------------
def resolve_host(host: str) -> List[str]:
    ips: List[str] = []
    try:
        for res in socket.getaddrinfo(host, None):
            sockaddr = res[4]
            ip = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                ips.append(str(ip_obj))
            except Exception:
                continue
    except Exception:
        pass
    out: List[str] = []
    seen = set()
    for ip in ips:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out

def resolve_hosts_concurrent(hosts: List[str], concurrency: int = 50) -> Dict[str, List[str]]:
    out: Dict[str, List[str]] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as ex:
        futures = {ex.submit(resolve_host, h): h for h in hosts}
        for fut in concurrent.futures.as_completed(futures):
            h = futures[fut]
            try:
                ips = fut.result()
            except Exception:
                ips = []
            out[h] = ips
    return out

# ---------------- CVE fetching ----------------
def load_cve_cache(path: Path) -> Dict[str, Dict]:
    if path.exists():
        try:
            return json.loads(path.read_text(encoding='utf-8'))
        except Exception:
            logging.debug("Failed to read CVE cache, starting fresh.")
    return {}

def save_cve_cache(path: Path, data: Dict[str, Dict]) -> None:
    try:
        path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding='utf-8')
    except Exception as e:
        logging.debug("Failed to save CVE cache: %s", e)

def fetch_cve_from_circl(session: requests.Session, cve: str, timeout: int = 10, proxies: Optional[Dict] = None) -> Optional[Dict]:
    url = f"https://cve.circl.lu/api/cve/{cve}"
    try:
        r = session.get(url, timeout=timeout, proxies=proxies)
        if r.status_code == 200:
            data = r.json()
            
            # Handle both old and new CIRCL API response formats
            summary = None
            cvss = None
            cvss3 = None
            references = None
            last_modified = None
            
            # Try old format first (direct summary field)
            if "summary" in data:
                summary = data.get("summary")
                cvss = data.get("cvss")
                cvss3 = data.get("cvss3")
                references = data.get("references")
                last_modified = data.get("last-modified")
            
            # Try new CVE 5.1 format with containers
            elif "containers" in data and "cna" in data["containers"]:
                cna = data["containers"]["cna"]
                
                # Extract description/summary from CVE 5.1 format
                descriptions = cna.get("descriptions", [])
                if descriptions:
                    # Find English description
                    for desc in descriptions:
                        if desc.get("lang") == "en":
                            summary = desc.get("value")
                            break
                    # If no English found, take the first one
                    if not summary and descriptions:
                        summary = descriptions[0].get("value")
                
                # If no summary found in CVE 5.1, try the legacy v4 record
                if not summary and "x_legacyV4Record" in cna:
                    legacy = cna["x_legacyV4Record"]
                    desc_data = legacy.get("description", {}).get("description_data", [])
                    if desc_data:
                        # Find English description in legacy format
                        for desc in desc_data:
                            if desc.get("lang") == "eng":
                                summary = desc.get("value")
                                break
                        # If no English found, take the first one
                        if not summary and desc_data:
                            summary = desc_data[0].get("value")
                
                # Extract CVSS scores if available (try multiple locations)
                metrics = cna.get("metrics", [])
                for metric in metrics:
                    if "cvssV3_1" in metric:
                        cvss3 = metric["cvssV3_1"].get("baseScore")
                        cvss = cvss3
                    elif "cvssV3_0" in metric:
                        cvss3 = metric["cvssV3_0"].get("baseScore")
                        cvss = cvss3
                    elif "cvssV2_0" in metric:
                        if not cvss:
                            cvss = metric["cvssV2_0"].get("baseScore")
                
                # Extract references
                refs = cna.get("references", [])
                if refs:
                    references = [ref.get("url") for ref in refs if ref.get("url")]
                
                # Extract dates
                last_modified = cna.get("datePublic")
                if not last_modified:
                    last_modified = data.get("cveMetadata", {}).get("datePublished")
            
            # Also check root level for additional fields
            if not last_modified:
                last_modified = data.get("last-modified") or data.get("published")
            
            if summary:
                return {
                    "id": cve,
                    "summary": summary,
                    "cvss": cvss,
                    "cvss3": cvss3,
                    "references": references,
                    "last_modified": last_modified,
                }
    except Exception as e:
        logging.debug("Failed to fetch CVE %s from CIRCL: %s", cve, e)
    return None

def fetch_cve_from_nvd(session: requests.Session, cve: str, timeout: int = 12, proxies: Optional[Dict] = None) -> Optional[Dict]:
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve}"
    headers = {}
    nvd_key = os.environ.get("NVD_API_KEY")
    if nvd_key:
        headers["apiKey"] = nvd_key
    try:
        r = session.get(url, headers=headers, timeout=timeout, proxies=proxies)
        if r.status_code == 200:
            data = r.json()
            vulnerabilities = data.get("vulnerabilities", [])
            if not vulnerabilities:
                return None
                
            cve_item = vulnerabilities[0].get("cve", {})
            descriptions = cve_item.get("descriptions", [])
            summary = next((desc.get("value") for desc in descriptions if desc.get("lang") == "en"), "")
            
            metrics = cve_item.get("metrics", {})
            cvss_data = {}
            
            # Try to get CVSS v3 first, then v2
            if "cvssMetricV31" in metrics:
                cvss_data = metrics["cvssMetricV31"][0].get("cvssData", {})
            elif "cvssMetricV30" in metrics:
                cvss_data = metrics["cvssMetricV30"][0].get("cvssData", {})
            elif "cvssMetricV2" in metrics:
                cvss_data = metrics["cvssMetricV2"][0].get("cvssData", {})
            
            cvss_score = cvss_data.get("baseScore")
            
            return {
                "id": cve, 
                "summary": summary or None, 
                "cvss": cvss_score,
                "cvss3": cvss_score if cvss_data.get("version", "").startswith("3.") else None,
                "references": [ref.get("url") for ref in cve_item.get("references", [])],
                "last_modified": cve_item.get("lastModified")
            }
    except Exception as e:
        logging.debug("Failed to fetch CVE %s from NVD: %s", cve, e)
    return None

def fetch_cve_from_shodan_cvedb(session: requests.Session, cve: str, timeout: int = 10, proxies: Optional[Dict] = None) -> Optional[Dict]:
    """Fetch CVE details from Shodan CVE database."""
    url = f"https://cvedb.shodan.io/cve/{cve}"
    try:
        r = session.get(url, timeout=timeout, proxies=proxies)
        if r.status_code == 200:
            data = r.json()
            return {
                "id": cve,
                "summary": data.get("summary"),
                "cvss": data.get("cvss"),
                "cvss3": data.get("cvss3") or data.get("cvss_v3"),
                "references": data.get("references"),
                "last_modified": data.get("published") or data.get("modified"),
            }
    except Exception as e:
        logging.debug("Failed to fetch CVE %s from Shodan CVEDB: %s", cve, e)
    return None


# Semaphore will be created once args parsed
cve_global_semaphore: Optional[threading.Semaphore] = None

def fetch_cve_details(session: requests.Session, cve: str, cache: Dict[str, Dict], 
                     polite_sleep: float = 0.05, proxies: Optional[Dict] = None,
                     cve_sources: List[str] = None) -> Dict:
    """Fetch CVE details from specified sources."""
    global cve_global_semaphore
    if cve in cache:
        return cache[cve]
        
    if cve_sources is None:
        cve_sources = ["circl", "nvd"]  # default sources
        
    if cve_global_semaphore:
        acquired = cve_global_semaphore.acquire(timeout=10)
        if not acquired:
            out = {"id": cve, "summary": None, "cvss": None, "note": "cve-semaphore-timeout"}
            cache[cve] = out
            return out
            
    try:
        # Try sources in specified order
        for source in cve_sources:
            res = None
            if source.lower() == "circl":
                res = fetch_cve_from_circl(session, cve, proxies=proxies)
            elif source.lower() == "nvd":
                res = fetch_cve_from_nvd(session, cve, proxies=proxies)
            elif source.lower() == "shodan" or source.lower() == "shodancvedb":
                res = fetch_cve_from_shodan_cvedb(session, cve, proxies=proxies)
                
            if res and res.get("summary"):
                cache[cve] = res
                time.sleep(polite_sleep)
                return res
            
        # Nothing found from any source
        out = {"id": cve, "summary": None, "cvss": None, "cvss3": None, "references": None, "last_modified": None}
        cache[cve] = out
        time.sleep(polite_sleep)
        return out
    finally:
        if cve_global_semaphore:
            cve_global_semaphore.release()


# ---------------- internetdb / shodan ----------------
def fetch_internetdb(session: requests.Session, ip: str, timeout: int = 15, proxies: Optional[Dict] = None) -> Dict:
    url = f"https://internetdb.shodan.io/{ip}"
    try:
        r = session.get(url, timeout=timeout, proxies=proxies)
        if r.status_code == 200:
            return {"source": "internetdb", "ok": True, "data": r.json()}
        elif r.status_code == 404:
            return {"source": "internetdb", "ok": False, "status": 404}
        else:
            return {"source": "internetdb", "ok": False, "status": r.status_code, "text": r.text[:200]}
    except Exception as e:
        return {"source": "internetdb", "ok": False, "error": str(e)}

def fetch_shodan_api(session: requests.Session, ip: str, api_key: str, timeout: int = 15, proxies: Optional[Dict] = None) -> Dict:
    url = f"https://api.shodan.io/shodan/host/{ip}?key={api_key}"
    try:
        r = session.get(url, timeout=timeout, proxies=proxies)
        if r.status_code == 200:
            return {"source": "shodan_api", "ok": True, "data": r.json()}
        else:
            return {"source": "shodan_api", "ok": False, "status": r.status_code, "text": r.text[:300]}
    except Exception as e:
        return {"source": "shodan_api", "ok": False, "error": str(e)}

# ---------------- Proxies ----------------
def load_proxies(path: Path) -> List[str]:
    if not path.exists():
        logging.error("Proxies file not found: %s", path)
        return []
    lines = [l.strip() for l in path.read_text(encoding='utf-8', errors='ignore').splitlines() if l.strip()]
    return lines

def build_proxies_dict(proxy_url: str) -> Dict[str, str]:
    return {"http": proxy_url, "https": proxy_url}

# ---------------- Main ----------------
def main():
    global cve_global_semaphore
    parser = argparse.ArgumentParser(description="Discover subdomains, resolve IPs, query internetdb/shodan and save results.")
    parser.add_argument("--domain", "-d", help="target domain (e.g. google.com)")
    parser.add_argument("--input", "-i", help="optional input file with ip,hostname lines (comma/tab/space separated)")
    parser.add_argument("--output", "-o", default="results", help="output directory")
    parser.add_argument("--report-name", default="shodan_analysis_report.html", help="Name for the final HTML report file") # <-- ADD THIS LINE
    parser.add_argument("--concurrency", "-c", type=int, default=20, help="concurrency for network tasks (DNS + IP querying)")
    parser.add_argument("--timeout", type=int, default=15, help="per-request timeout")
    parser.add_argument("--delay", type=float, default=0.0, help="delay between each fetch (per-worker)")
    parser.add_argument("--bruteforce", action="store_true", help="enable brute-force subdomain discovery using --wordlist")
    parser.add_argument("--wordlist","-w" ,type=str, help="wordlist file for brute forcing")
    parser.add_argument("--use-shodan", action="store_true", help="call official Shodan API if key provided via SHODAN_API_KEY .env")
    parser.add_argument("--proxies-file","-P", type=str, help="optional file with proxy URLs (one per line), e.g. http://127.0.0.1:8080")
    parser.add_argument("--proxy-rotate","-PR", action="store_true", help="rotate proxies from --proxies-file for each request")
    parser.add_argument("--save-host-files", action="store_true", help="also save per-host JSON files (hostnames)")
    parser.add_argument("--max-cve-workers-global","-MCWGB", type=int, default=12, help="max concurrent CVE fetches global (throttle)")
    parser.add_argument("--max-cve-workers-per-ip","-MCWIP", type=int, default=6, help="max concurrent CVE fetches per-IP (internal pool)")
    parser.add_argument("--cve-sources","-scve", type=str, default="all", help="CVE sources to use (comma-separated): circl, nvd, shodan, all. Default: all")
    parser.add_argument("--run-agent", action="store_true", help="Run agent.py against results_all.json after scanning")
    parser.add_argument("--report-only", action="store_true", help="Generate an HTML report from existing results without running the LLM agent.")

    args = parser.parse_args()

    outdir = Path(args.output)
    outdir.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s: %(message)s")

    # create session AFTER knowing args so we can size the pool appropriately
    pool_size = max(20, args.concurrency * 2 + args.max_cve_workers_global)
    session = create_session(pool_connections=pool_size, pool_maxsize=pool_size)

    # load proxies if any
    proxies_list = []
    if args.proxies_file:
        proxies_list = load_proxies(Path(args.proxies_file))
        logging.info("Loaded %d proxies", len(proxies_list))

    # input mapping (ip -> hostnames)
    input_ip_map: Dict[str, List[str]] = {}
    if args.input:
        if not Path(args.input).exists():
            logging.error("Input file not found: %s", args.input)
            sys.exit(1)
        with open(args.input, encoding='utf-8', errors='ignore') as f:
            for raw in f:
                line = raw.strip()
                if not line:
                    continue
                tokens = [t.strip() for t in re.split(r'[\t, ]+', line) if t.strip()]
                found_ip = None
                for tok in tokens:
                    try:
                        ipaddress.ip_address(tok)
                        found_ip = tok
                        break
                    except Exception:
                        continue
                hosts = [t for t in tokens if not (found_ip and t == found_ip)]
                if found_ip:
                    ip_map = input_ip_map.setdefault(found_ip, [])
                    for h in hosts:
                        if h not in ip_map:
                            ip_map.append(h)

    # passive discovery
    discovered_subs: Set[str] = set()
    if args.domain:
        logging.info("Passive enumeration for domain: %s", args.domain)
        discovered_subs.update(crtsh_passive(args.domain, session))
        logging.info("crt.sh discovered %d names", len(discovered_subs))
        if args.bruteforce:
            if not args.wordlist:
                logging.error("--bruteforce requires --wordlist")
                sys.exit(1)
            wlpath = Path(args.wordlist)
            logging.info("Starting brute-force using %s", wlpath)
            bf = brute_force_subdomains(args.domain, wlpath, concurrency=args.concurrency)
            logging.info("Brute force found %d names", len(bf))
            discovered_subs.update(bf)
        discovered_subs.add(args.domain)

    # combine hosts
    all_hosts: Set[str] = set()
    for hosts in input_ip_map.values():
        for h in hosts:
            all_hosts.add(h.lower())
    all_hosts.update(discovered_subs)

    if not all_hosts and not input_ip_map:
        logging.error("No hosts or IPs to process. Provide --domain or --input")
        sys.exit(1)

    # resolve hosts
    hosts_list = sorted(all_hosts)
    logging.info("Resolving %d hosts (concurrency=%d)", len(hosts_list), args.concurrency)
    resolved = resolve_hosts_concurrent(hosts_list, concurrency=args.concurrency)

    # build ip->hosts map
    ip_map: Dict[str, List[str]] = {}
    for h, ips in resolved.items():
        for ip in ips:
            ip_map.setdefault(ip, [])
            if h not in ip_map[ip]:
                ip_map[ip].append(h)

    # include input-file IPs
    for ip, hosts in input_ip_map.items():
        ip_map.setdefault(ip, [])
        for h in hosts:
            if h not in ip_map[ip]:
                ip_map[ip].append(h)

    ips = sorted(ip_map.keys())
    logging.info("Total unique IPs to query: %d", len(ips))

    shodan_key = os.environ.get("SHODAN_API_KEY")
    if args.use_shodan and not shodan_key:
        logging.warning("--use-shodan set but no API key provided (SHODAN_API_KEY). Will skip official API.")
        args.use_shodan = False

    # prepare CVE cache and global semaphore
    cache_path = outdir / CVE_CACHE_FILENAME
    cve_cache = load_cve_cache(cache_path)
    cve_global_semaphore = threading.Semaphore(args.max_cve_workers_global)

    results: Dict[str, Dict] = {}

    # worker: each ip_index is (idx, ip)
    def worker(ip_index: Tuple[int, str]) -> Tuple[str, Dict]:
        idx, ip = ip_index
        out: Dict = {"ip": ip, "hosts": ip_map.get(ip, [])}

        # choose proxy if provided
        proxies = None
        if proxies_list:
            if args.proxy_rotate:
                p = proxies_list[idx % len(proxies_list)]
            else:
                p = proxies_list[0]
            proxies = build_proxies_dict(p)

        # internetdb
        out["internetdb"] = fetch_internetdb(session, ip, timeout=args.timeout, proxies=proxies)
        if args.delay:
            time.sleep(args.delay)

        # shodan api
        if args.use_shodan and shodan_key:
            out["shodan_api"] = fetch_shodan_api(session, ip, shodan_key, timeout=args.timeout, proxies=proxies)
            if args.delay:
                time.sleep(args.delay)

        # CVE explanations
        cve_details: List[Dict] = []
        try:
            idb = out.get("internetdb") or {}
            if idb.get("ok"):
                vulns = idb.get("data", {}).get("vulns") or []
                if isinstance(vulns, dict):
                    vulns = list(vulns.keys())
                if isinstance(vulns, list) and vulns:
                    # Parse CVE sources
                    cve_sources = []
                    if args.cve_sources.lower() == "all":
                        cve_sources = ["circl", "nvd", "shodan"]
                    else:
                        cve_sources = [s.strip().lower() for s in args.cve_sources.split(",")]
                    
                    # Define max_workers for CVE fetching
                    max_workers = min(args.max_cve_workers_per_ip, 8)
                    
                    logging.debug(f"Fetching CVE details for {len(vulns)} vulnerabilities on {ip} using sources: {cve_sources}")
                    
                    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as cex:
                        future_map = {cex.submit(fetch_cve_details, session, v, cve_cache, 0.1, proxies, cve_sources): v for v in vulns}
                        for fut in concurrent.futures.as_completed(future_map):
                            v = future_map[fut]
                            try:
                                detail = fut.result()
                                if detail.get("summary"):
                                    logging.debug(f"Successfully fetched CVE {v}: {detail.get('summary')[:50]}...")
                                else:
                                    logging.debug(f"No summary found for CVE {v}")
                            except Exception as e:
                                logging.debug("Error fetching CVE %s: %s", v, e)
                                detail = {"id": v, "summary": None, "cvss": None, "cvss3": None, "references": None, "last_modified": None}
                            cve_details.append(detail)
        except Exception as e:
            logging.debug("Error fetching CVE details for %s: %s", ip, e)
        out["cve_details"] = cve_details

        return ip, out


    # submit tasks
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.concurrency) as ex:
        futures = {ex.submit(worker, (i, ip)): ip for i, ip in enumerate(ips)}
        for fut in tqdm(concurrent.futures.as_completed(futures), total=len(futures), desc="Querying IPs"):
            ip = futures[fut]
            try:
                _ip, out = fut.result()
            except Exception as e:
                out = {"ip": ip, "error": str(e), "hosts": ip_map.get(ip, [])}
            results[ip] = out
            
            # Save only one file per IP (not both IP and host files)
            hosts = out.get("hosts") or []
            filename = f"{ip}.json"
            
            # If we have hosts and want to save host files, use hostname in filename
            if hosts and args.save_host_files:
                fn = sanitize_filename(hosts[0])
                filename = f"{ip}__{fn}.json"
            
            filepath = outdir / filename
            try:
                filepath.write_text(json.dumps(out, indent=2, ensure_ascii=False), encoding='utf-8')
            except Exception as e:
                logging.debug("Failed to write %s: %s", filepath, e)

    # combined
    combined_file = outdir / "results_all.json"
    try:
        combined_file.write_text(json.dumps(results, indent=2, ensure_ascii=False), encoding='utf-8')
    except Exception:
        logging.debug("Failed to write combined results")

    # CSV
    csv_path = outdir / "summary.csv"
    try:
        with open(csv_path, "w", newline='', encoding='utf-8') as csvf:
            writer = csv.writer(csvf)
            writer.writerow(["ip", "hosts", "internetdb_ok", "internetdb_ports", "internetdb_vulns_count", "top_vulns", "shodan_ok", "shodan_ports_count", "cve_details_count"])
            for ip, data in results.items():
                hosts = data.get("hosts") or []
                idb = data.get("internetdb") or {}
                idb_ok = idb.get("ok", False)
                idb_ports = ""
                idb_vulns = ""
                top_vulns = ""
                if idb_ok:
                    d = idb.get("data", {}) or {}
                    ports = d.get("ports") or []
                    idb_ports = ",".join(str(p) for p in ports[:8])
                    vulns = d.get("vulns") or []
                    if isinstance(vulns, dict):
                        vulns = list(vulns.keys())
                    idb_vulns = str(len(vulns)) if isinstance(vulns, list) else ""
                    if vulns:
                        top_vulns = ",".join(vulns[:3])
                shd = data.get("shodan_api") or {}
                shd_ok = shd.get("ok", False)
                shd_ports_count = ""
                if shd_ok:
                    sp = shd.get("data", {}).get("ports") or []
                    shd_ports_count = str(len(sp))
                
                # Count CVE details with actual descriptions
                cve_details = data.get("cve_details") or []
                cve_with_details = sum(1 for cve in cve_details if cve.get("summary"))
                
                writer.writerow([ip, "|".join(hosts), idb_ok, idb_ports, idb_vulns, top_vulns, shd_ok, shd_ports_count, cve_with_details])
    except Exception:
        logging.debug("Failed to write CSV summary")

    # save cve cache
    try:
        save_cve_cache(cache_path, cve_cache)
    except Exception:
        logging.debug("Failed to save CVE cache")


    if args.run_agent:
        try:
            import subprocess, sys
            agent_script = Path(__file__).parent / "agent.py"
            if agent_script.exists():
                report_dir = outdir / "shodan_report"
                report_dir.mkdir(parents=True, exist_ok=True)
                report_path = report_dir / args.report_name

                cmd = [sys.executable, str(agent_script), "--json", str(combined_file), "--output", str(report_path)]
                logging.info("Launching LLM agent: %s", " ".join(cmd))
                # We use check=False because the agent script handles its own errors
                subprocess.run(cmd, check=False)
            else:
                logging.error("agent.py not found next to Twin.py; cannot run agent.")
        except Exception as e:
            logging.error("Failed to launch agent.py: %s", e)

    elif args.report_only:
        from shodan_report_generator import generate_html_report
        logging.info("Report-only mode activated. Skipping LLM agent.")
        if not combined_file.exists():
            logging.error(f"Cannot generate report: results file not found at {combined_file}")
            sys.exit(1)

        try:
            # Read the raw scan data
            raw_data = json.loads(combined_file.read_text(encoding='utf-8'))

            # --- Extract all CVEs from the raw data ---
            all_discovered_cves = {}
            for ip, data in raw_data.items():
                for cve_detail in data.get("cve_details", []):
                    cve_id = cve_detail.get("id")
                    if not cve_id or not cve_detail.get("summary"):
                        continue
                    if cve_id not in all_discovered_cves:
                        all_discovered_cves[cve_id] = {
                            "id": cve_id,
                            "summary": cve_detail.get("summary"),
                            "cvss": cve_detail.get("cvss") or cve_detail.get("cvss3"),
                            "affected_ips": set()
                        }
                    all_discovered_cves[cve_id]["affected_ips"].add(ip)
            
            final_cve_list = list(all_discovered_cves.values())
            for cve in final_cve_list:
                cve["affected_ips"] = sorted(list(cve["affected_ips"]))

            # --- Build the data structure for the report generator ---
            # This mimics the structure from agent.py but without LLM results
            aggregated_data = {
                "report_generated_at": time.strftime("%Y-%m-%d %H:%M:%S UTC"),
                "source_file": str(combined_file),
                "total_ips_analyzed": len(raw_data),
                "chunks_processed": 0, # No chunks processed by LLM
                "llm_analysis_results": [], # Empty list indicates no LLM analysis
                "all_discovered_cves": final_cve_list
            }
            
            report_dir = outdir / "shodan_report"
            report_dir.mkdir(parents=True, exist_ok=True)
            report_path = report_dir / args.report_name

            logging.info(f"Generating raw data report at: {report_path}")
            ok, msg = generate_html_report(aggregated_data, output_file=str(report_path))
            if ok:
                logging.info("HTML report generated successfully.")
            else:
                logging.error(f"Failed to generate report: {msg}")

        except Exception as e:
            logging.error(f"An error occurred during report generation: {e}", exc_info=True)


    logging.info("Done. Results saved to: %s", outdir.resolve())

if __name__ == "__main__":
    main()