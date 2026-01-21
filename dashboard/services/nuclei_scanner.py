"""
TwinSanity Recon V2 - Nuclei Scanner Service
Runs Nuclei vulnerability scanner against targets.
"""
import asyncio
import json
import logging
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import List, Dict, Optional
from datetime import datetime

logger = logging.getLogger("NucleiScanner")

# Default Nuclei templates path
NUCLEI_TEMPLATES_PATH = Path.home() / "nuclei-templates"


def check_nuclei_installed() -> bool:
    """Check if Nuclei is installed and available."""
    return shutil.which("nuclei") is not None


def get_nuclei_version() -> Optional[str]:
    """Get installed Nuclei version."""
    try:
        result = subprocess.run(
            ["nuclei", "-version"],
            capture_output=True,
            text=True,
            timeout=10
        )
        # Parse version from output
        match = re.search(r'v?(\d+\.\d+\.\d+)', result.stdout + result.stderr)
        if match:
            return match.group(1)
    except Exception:
        pass
    return None


async def run_nuclei_scan(
    targets: List[str],
    templates: List[str] = None,
    severity: str = "critical,high",
    rate_limit: int = 150,
    concurrency: int = 25,
    timeout: int = 300,
    output_json: bool = True
) -> List[Dict]:
    """
    Run Nuclei scanner against targets.
    
    Args:
        targets: List of target URLs/hosts
        templates: Template categories to use (e.g., ["cves", "exposed-panels"])
        severity: Severity filter (e.g., "critical,high,medium")
        rate_limit: Requests per second
        concurrency: Number of concurrent templates
        timeout: Overall timeout in seconds
        output_json: Return JSON output
    
    Returns:
        List of findings as dicts
    """
    if not check_nuclei_installed():
        logger.error("Nuclei is not installed or not in PATH")
        return []
    
    if not targets:
        return []
    
    # Default templates
    if templates is None:
        templates = ["cves", "exposed-panels", "misconfigurations"]
    
    # Security: Validate templates against allowed list to prevent path traversal
    ALLOWED_TEMPLATES = {
        "cves", "exposed-panels", "misconfigurations", "exposures", 
        "takeovers", "technologies", "default-logins", "file", 
        "vulnerabilities", "network", "dns", "ssl", "headless"
    }
    
    validated_templates = []
    for tmpl in templates:
        # Remove any path components and validate
        clean_tmpl = tmpl.strip().lower()
        # Block path traversal attempts
        if '..' in clean_tmpl or '/' in clean_tmpl or '\\' in clean_tmpl:
            logger.warning(f"Blocked potentially malicious template path: {tmpl}")
            continue
        if clean_tmpl in ALLOWED_TEMPLATES:
            validated_templates.append(clean_tmpl)
        else:
            logger.warning(f"Template '{tmpl}' not in allowed list, skipping")
    
    if not validated_templates:
        validated_templates = ["cves"]  # Default fallback
    
    findings = []
    
    # Create temporary targets file
    import tempfile
    with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
        for target in targets:
            f.write(f"{target}\n")
        targets_file = f.name
    
    try:
        # Build Nuclei command
        cmd = [
            "nuclei",
            "-l", targets_file,
            "-severity", severity,
            "-rate-limit", str(rate_limit),
            "-concurrency", str(concurrency),
            "-silent",
            "-jsonl",  # JSON lines output
        ]
        
        # Add validated template filters
        for tmpl in validated_templates:
            cmd.extend(["-t", tmpl])
        
        logger.info(f"Running Nuclei scan on {len(targets)} targets with templates: {templates}")
        
        # Run Nuclei
        process = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )
        
        try:
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
        except asyncio.TimeoutError:
            process.kill()
            logger.warning("Nuclei scan timed out")
            return findings
        
        # Parse JSON lines output
        if stdout:
            for line in stdout.decode().splitlines():
                try:
                    finding = json.loads(line)
                    findings.append({
                        "template_id": finding.get("template-id", finding.get("templateID", "")),
                        "name": finding.get("info", {}).get("name", finding.get("name", "")),
                        "severity": finding.get("info", {}).get("severity", finding.get("severity", "")),
                        "host": finding.get("host", ""),
                        "matched_at": finding.get("matched-at", finding.get("matched", "")),
                        "extracted_results": finding.get("extracted-results", []),
                        "curl_command": finding.get("curl-command", ""),
                        "timestamp": finding.get("timestamp", datetime.now().isoformat()),
                    })
                except json.JSONDecodeError:
                    continue
        
        logger.info(f"Nuclei scan completed: {len(findings)} findings")
        
        if stderr:
            stderr_text = stderr.decode()
            if "error" in stderr_text.lower():
                logger.warning(f"Nuclei stderr: {stderr_text[:500]}")
    
    finally:
        # Cleanup temp file
        try:
            os.unlink(targets_file)
        except:
            pass
    
    return findings


async def save_nuclei_findings(
    scan_id: str,
    findings: List[Dict]
) -> int:
    """Save Nuclei findings to database."""
    import aiosqlite
    from dashboard.database import get_db
    
    db = await get_db()
    
    count = 0
    async with aiosqlite.connect(db.db_path) as conn:
        for f in findings:
            await conn.execute(
                """INSERT INTO nuclei_findings 
                   (scan_id, template_id, name, severity, host, matched_at, extracted_results, curl_command, created_at)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    scan_id,
                    f.get("template_id"),
                    f.get("name"),
                    f.get("severity"),
                    f.get("host"),
                    f.get("matched_at"),
                    json.dumps(f.get("extracted_results", [])),
                    f.get("curl_command"),
                    datetime.now().isoformat()
                )
            )
            count += 1
        await conn.commit()
    
    logger.info(f"Saved {count} Nuclei findings for scan {scan_id}")
    return count


async def get_nuclei_findings(
    scan_id: str,
    severity: str = None
) -> List[Dict]:
    """Get Nuclei findings for a scan."""
    import aiosqlite
    from dashboard.database import get_db
    
    db = await get_db()
    
    query = "SELECT * FROM nuclei_findings WHERE scan_id = ?"
    params = [scan_id]
    
    if severity:
        query += " AND severity = ?"
        params.append(severity)
    
    query += " ORDER BY CASE severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 WHEN 'low' THEN 4 ELSE 5 END"
    
    async with aiosqlite.connect(db.db_path) as conn:
        conn.row_factory = aiosqlite.Row
        async with conn.execute(query, params) as cursor:
            rows = await cursor.fetchall()
            results = []
            for row in rows:
                r = dict(row)
                if r.get("extracted_results"):
                    try:
                        r["extracted_results"] = json.loads(r["extracted_results"])
                    except:
                        r["extracted_results"] = []
                results.append(r)
            return results


# Python-native vulnerability checks (when Nuclei not available)
# These are simplified checks that don't require external tools

async def check_common_vulnerabilities(
    session,
    url: str
) -> List[Dict]:
    """
    Run basic vulnerability checks without Nuclei.
    This is a fallback for when Nuclei is not installed.
    Uses STRICT validation to avoid false positives.
    """
    import aiohttp
    
    findings = []
    
    # Common paths to check with strict validation rules
    checks = [
        {
            "path": "/.git/config",
            "name": "Git Config Exposure",
            "severity": "high",
            "match": "[core]",
            "must_contain": ["repositoryformatversion", "[remote"],
            "max_size": 10000,  # Git config should be small
        },
        {
            "path": "/.env",
            "name": "Environment File Exposure",
            "severity": "high",
            "match": "=",
            "must_contain": ["DB_", "API_", "SECRET", "PASSWORD", "KEY="],  # Env vars
            "must_not_contain": ["<!DOCTYPE", "<html", "<head>"],  # Not HTML
            "max_size": 50000,
        },
        {
            "path": "/wp-config.php.bak",
            "name": "WordPress Config Backup",
            "severity": "critical",
            "match": "DB_NAME",
            "must_contain": ["DB_PASSWORD", "define("],
            "max_size": 50000,
        },
        {
            "path": "/server-status",
            "name": "Apache Server Status",
            "severity": "medium",
            "match": "Apache Server Status",
            "must_contain": ["Server uptime", "requests/sec"],
            "max_size": 500000,
        },
        {
            "path": "/phpinfo.php",
            "name": "PHP Info Exposure",
            "severity": "medium",
            "match": "PHP Version",
            "must_contain": ["php.ini", "Configuration"],
            "max_size": 500000,
        },
        {
            "path": "/.well-known/security.txt",
            "name": "Security.txt",
            "severity": "info",
            "match": "Contact:",
            "must_not_contain": ["<!DOCTYPE", "<html"],
            "max_size": 10000,
        },
        {
            "path": "/robots.txt",
            "name": "Robots.txt",
            "severity": "info",
            "match": "User-agent",
            "must_not_contain": ["<!DOCTYPE", "<html"],
            "max_size": 50000,
        },
        {
            "path": "/.htaccess",
            "name": "HTAccess Exposure",
            "severity": "medium",
            "match": "RewriteEngine",
            "must_not_contain": ["<!DOCTYPE", "<html"],
            "max_size": 20000,
        },
        {
            "path": "/backup.sql",
            "name": "SQL Backup Exposure",
            "severity": "critical",
            "match": "CREATE TABLE",
            "must_contain": ["INSERT INTO"],
            "max_size": None,  # Can be large
        },
    ]
    
    base_url = url.rstrip('/')
    
    for check in checks:
        try:
            test_url = f"{base_url}{check['path']}"
            async with session.get(test_url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as resp:
                if resp.status == 200:
                    # Check content type - should not be HTML for most checks
                    content_type = resp.headers.get('Content-Type', '').lower()
                    
                    # Skip if it's an HTML error page
                    if 'text/html' in content_type and check['path'] not in ['/server-status', '/phpinfo.php']:
                        continue
                    
                    body = await resp.text()
                    body_lower = body.lower()
                    
                    # Size check
                    if check.get('max_size') and len(body) > check['max_size']:
                        continue
                    
                    # Must contain primary match
                    if check["match"].lower() not in body_lower:
                        continue
                    
                    # Must contain additional patterns (any one)
                    if check.get('must_contain'):
                        found_any = any(p.lower() in body_lower for p in check['must_contain'])
                        if not found_any:
                            continue
                    
                    # Must NOT contain patterns (none)
                    if check.get('must_not_contain'):
                        found_bad = any(p.lower() in body_lower for p in check['must_not_contain'])
                        if found_bad:
                            continue
                    
                    # Passed all checks - this is a valid finding
                    findings.append({
                        "template_id": f"python-check-{check['path'].replace('/', '-')}",
                        "name": check["name"],
                        "severity": check["severity"],
                        "host": base_url,
                        "matched_at": test_url,
                        "extracted_results": [body[:500]],  # Include preview
                        "curl_command": f"curl -s '{test_url}'",
                        "timestamp": datetime.now().isoformat(),
                        "verified": True  # Mark as verified
                    })
        except:
            continue
    
    return findings


async def run_python_vuln_checks(
    targets: List[str],
    concurrency: int = 20
) -> List[Dict]:
    """
    Run Python-native vulnerability checks (fallback when Nuclei not available).
    """
    import aiohttp
    
    all_findings = []
    semaphore = asyncio.Semaphore(concurrency)
    
    async def check_target(session, url):
        async with semaphore:
            return await check_common_vulnerabilities(session, url)
    
    connector = aiohttp.TCPConnector(limit=concurrency, ssl=False)
    headers = {"User-Agent": "Mozilla/5.0 TwinSanity-Recon/2.0"}
    
    async with aiohttp.ClientSession(connector=connector, headers=headers) as session:
        tasks = [check_target(session, url) for url in targets]
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        for result in results:
            if isinstance(result, list):
                all_findings.extend(result)
    
    logger.info(f"Python vulnerability checks completed: {len(all_findings)} findings")
    return all_findings
