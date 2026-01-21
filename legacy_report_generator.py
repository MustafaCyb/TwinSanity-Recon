import html
from pathlib import Path
from typing import Dict, Any, Tuple, List, Optional

def _escape(s: Any) -> str:
    """Safely HTML-escapes a value."""
    return html.escape(str(s)) if s is not None else ""

def _get_severity_badge(severity: Optional[str]) -> str:
    """Returns a colored HTML badge based on severity."""
    s = (severity or "low").lower()
    return f"<span class='badge badge-{s}'>{_escape(s.title())}</span>"

def _get_cvss_color_class(score: Optional[float]) -> str:
    """Returns a CSS class for CVSS score colors."""
    if score is None:
        return "text-muted"
    try:
        score = float(score)
    except (ValueError, TypeError):
        return "text-muted"
        
    if score >= 9.0:
        return "text-critical"
    if score >= 7.0:
        return "text-high"
    if score >= 4.0:
        return "text-medium"
    return "text-low"

def generate_html_report(aggregated_data: Dict[str, Any], output_file: str = "report.html") -> Tuple[bool, str]:
    """Generates the main HTML report."""
    try:
        # --- Data Extraction ---
        llm_results = aggregated_data.get("llm_analysis_results", [])
        is_llm_run = bool(llm_results) # Check if LLM analysis was performed
        
        summary_points = []
        high_risk_assets = []
        recommended_actions = []

        if is_llm_run:
            for res in llm_results:
                analysis = res.get("analysis", {})
                if analysis.get("summary"): summary_points.append(analysis["summary"])
                high_risk_assets.extend(analysis.get("high_risk_assets", []))
                recommended_actions.extend(analysis.get("recommended_actions", []))

        # --- Comprehensive CVE List (available in both modes) ---
        all_cves = aggregated_data.get("all_discovered_cves", [])
        host_details = aggregated_data.get("hosts", [])
        
        # --- Stats with Severity Breakdown ---
        total_ips = aggregated_data.get('total_ips_analyzed', 0)
        total_cves_found = len(all_cves)
        
        # Compute severity counts from CVSS scores
        critical_count = sum(1 for c in all_cves if (c.get('cvss') or 0) >= 9.0)
        high_count = sum(1 for c in all_cves if 7.0 <= (c.get('cvss') or 0) < 9.0)
        medium_count = sum(1 for c in all_cves if 4.0 <= (c.get('cvss') or 0) < 7.0)
        low_count = sum(1 for c in all_cves if (c.get('cvss') or 0) < 4.0)
        
        # --- Conditional HTML blocks for LLM data ---
        llm_summary_html = ""
        llm_assets_html = ""
        llm_actions_html = ""
        report_notice_html = ""

        if is_llm_run:
            llm_summary_html = f"""
            <div class='card'><h2>LLM Executive Summary</h2><ul>{''.join(f"<li>{_escape(p)}</li>" for p in summary_points)}</ul></div>
            """
            llm_assets_html = f"""
            <div class='card'><h2>LLM Highlighted: High-Risk Assets</h2>
                <table><thead><tr><th>Severity</th><th>IP Address</th><th>Hostname</th><th>Reason</th></tr></thead><tbody>
                {''.join(f"<tr><td>{_get_severity_badge(a.get('severity'))}</td><td>{_escape(a.get('ip'))}</td><td>{_escape(a.get('hostname'))}</td><td>{_escape(a.get('reason'))}</td></tr>" for a in high_risk_assets) or "<tr><td colspan='4'>No high-risk assets highlighted by the LLM.</td></tr>"}
                </tbody></table>
            </div>
            """
            llm_actions_html = f"""
            <div class='card'><h2>LLM Recommended Actions</h2>
                <table><thead><tr><th>Priority</th><th>Action</th><th>Justification</th></tr></thead><tbody>
                {''.join(f"<tr><td>{_get_severity_badge(a.get('priority'))}</td><td>{_escape(a.get('action'))}</td><td>{_escape(a.get('justification'))}</td></tr>" for a in recommended_actions) or "<tr><td colspan='3'>No specific actions recommended by the LLM.</td></tr>"}
                </tbody></table>
            </div>
            """
        else:
            report_notice_html = "<div class='card notice'><p><strong>Raw Data Report:</strong> This report displays the complete vulnerability data from the scan. The LLM analysis was not run.</p></div>"

        # --- Main HTML Template with Severity Stats ---
        html_template = f"""
<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <title>Twinsainty Security Analysis Report</title>
    <style>
        :root {{
            --bg-color: #1a1a1d; --card-color: #2a2a2f; --text-color: #f0f0f0; 
            --muted-text: #9a9a9a; --accent-color: #4da8da; --border-color: #444;
            --critical: #c3073f; --high: #ff5722; --medium: #ffc107; --low: #009688;
            --notice-bg: rgba(77, 168, 218, 0.1); --notice-border: var(--accent-color);
        }}
        body {{ background-color: var(--bg-color); color: var(--text-color); font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 2rem; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: auto; }}
        .header {{ border-bottom: 2px solid var(--accent-color); padding-bottom: 1rem; margin-bottom: 2rem; }}
        h1, h2, h3 {{ color: var(--accent-color); margin-top: 0; }}
        h1 {{ font-size: 2.5rem; }}
        .card {{ background-color: var(--card-color); border-radius: 8px; padding: 1.5rem; margin-bottom: 2rem; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
        .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1.5rem; }}
        .stat-box {{ text-align: center; padding: 1rem; border-radius: 8px; background: rgba(255,255,255,0.03); }}
        .stat-number {{ font-size: 2rem; font-weight: bold; margin-bottom: 0.5rem; }}
        .stat-number.critical {{ color: var(--critical); }}
        .stat-number.high {{ color: var(--high); }}
        .stat-number.medium {{ color: var(--medium); }}
        .stat-number.low {{ color: var(--low); }}
        .stat-label {{ color: var(--muted-text); font-size: 0.85rem; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 1rem; }}
        th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border-color); }}
        th {{ color: var(--muted-text); font-weight: 600; cursor: pointer; user-select: none; position: relative; }}
        th.sortable::after {{ content: ' \\2195'; opacity: 0.4; }}
        th.sort-asc::after {{ content: ' \\25B2'; opacity: 1; }}
        th.sort-desc::after {{ content: ' \\25BC'; opacity: 1; }}
        tr:hover {{ background-color: rgba(255, 255, 255, 0.05); }}
        .text-muted {{ color: var(--muted-text); }}
        .text-critical {{ color: var(--critical); }} .text-high {{ color: var(--high); }}
        .text-medium {{ color: var(--medium); }} .text-low {{ color: var(--low); }}
        .ip-list {{ font-family: 'Courier New', monospace; font-size: 0.9em; word-break: break-all; }}
        .badge {{ display: inline-block; padding: 0.25em 0.6em; font-size: 0.75em; font-weight: bold; line-height: 1; text-align: center; white-space: nowrap; vertical-align: baseline; border-radius: 0.25rem; }}
        .badge-critical {{ background-color: var(--critical); color: white; }} .badge-high {{ background-color: var(--high); color: white; }}
        .badge-medium {{ background-color: var(--medium); color: #333; }} .badge-low {{ background-color: var(--low); color: white; }}
        .search-box {{ width: 100%; box-sizing: border-box; background-color: #333; color: var(--text-color); border: 1px solid var(--border-color); border-radius: 4px; padding: 0.75rem; font-size: 1rem; margin-bottom: 1rem; }}
        .notice {{ background-color: var(--notice-bg); border-left: 4px solid var(--notice-border); }}
        .footer {{ text-align: center; color: var(--muted-text); margin-top: 3rem; font-size: 0.9em; }}
    </style>
</head>
<body>
<div class='container'>
    <div class='header'>
        <h1>Twinsanity Security Analysis Report</h1>
        <p>Generated on: {_escape(aggregated_data.get('report_generated_at', 'N/A'))} | Source: {_escape(aggregated_data.get('source_file', 'N/A'))}</p>
    </div>

    {report_notice_html}

    <div class='card grid'>
        <div class='stat-box'><div class='stat-number'>{total_ips}</div><div class='stat-label'>IPs Analyzed</div></div>
        <div class='stat-box'><div class='stat-number'>{total_cves_found}</div><div class='stat-label'>Total CVEs</div></div>
        <div class='stat-box'><div class='stat-number critical'>{critical_count}</div><div class='stat-label'>Critical</div></div>
        <div class='stat-box'><div class='stat-number high'>{high_count}</div><div class='stat-label'>High</div></div>
        <div class='stat-box'><div class='stat-number medium'>{medium_count}</div><div class='stat-label'>Medium</div></div>
        <div class='stat-box'><div class='stat-number low'>{low_count}</div><div class='stat-label'>Low</div></div>
    </div>

    {llm_summary_html}
    {llm_assets_html}

    <div class='card'>
        <h2>Comprehensive Vulnerability Listing ({total_cves_found} found)</h2>
        <p>This is a complete list of all vulnerabilities found across all scanned IPs. Use the search box to filter and click headers to sort.</p>
        <input type="text" id="cveSearch" onkeyup="searchCves()" placeholder="Search for CVE, summary, IP..." class="search-box">
        <table id="cveTable">
            <thead><tr>
                <th class="sortable" onclick="sortTable(0)">CVE ID</th>
                <th class="sortable" onclick="sortTable(1, true)">CVSS</th>
                <th class="sortable" onclick="sortTable(2, true)"># Hosts</th>
                <th onclick="sortTable(3)">Summary</th>
                <th onclick="sortTable(4)">Affected IPs</th>
            </tr></thead>
            <tbody>
            {''.join(
                f"""<tr>
                    <td><strong>{_escape(cve.get('id'))}</strong></td>
                    <td class='{_get_cvss_color_class(cve.get('cvss'))}'>{_escape(cve.get('cvss')) or 'N/A'}</td>
                    <td>{len(cve.get('affected_ips', []))}</td>
                    <td>{_escape(cve.get('summary'))}</td>
                    <td class='ip-list'>{', '.join(_escape(ip) for ip in cve.get('affected_ips', []))}</td>
                </tr>""" for cve in sorted(all_cves, key=lambda x: (float(x.get('cvss') or 0.0)), reverse=True)
            ) or "<tr><td colspan='5'>No CVEs with details were found during the scan.</td></tr>"}
            </tbody>
        </table>
    </div>

    {llm_actions_html}

    <div class='card'>
        <h2>Per-Host CVEs</h2>
        <p>Breakdown of vulnerabilities by host/subdomain.</p>
        <table>
            <thead><tr><th>Host</th><th>IP</th><th>Ports</th><th>CVEs</th></tr></thead>
            <tbody>
            {''.join(
                f"<tr><td>{_escape(', '.join(h.get('hosts', [])) or 'N/A')}</td>"
                f"<td>{_escape(h.get('ip'))}</td>"
                f"<td>{', '.join(map(str, h.get('ports', []))) or '—'}</td>"
                f"<td>{', '.join(_escape(c.get('id') or c.get('cve_id') or 'CVE-?') for c in h.get('cves', [])) or '—'}</td></tr>"
                for h in host_details
            ) or "<tr><td colspan='4'>No host-level CVE data.</td></tr>"}
            </tbody>
        </table>
    </div>

    <div class='footer'><p>Report generated by the Twinsanity Security Analysis Agent.</p></div>
</div>

<script>
function searchCves() {{
    let input = document.getElementById('cveSearch').value.toUpperCase();
    let table = document.getElementById('cveTable');
    let tr = table.getElementsByTagName('tr');
    for (let i = 1; i < tr.length; i++) {{ // Start from 1 to skip header
        tr[i].style.display = tr[i].textContent.toUpperCase().indexOf(input) > -1 ? "" : "none";
    }}
}}

function sortTable(columnIndex, isNumeric = false) {{
    let table = document.getElementById('cveTable');
    let tbody = table.tBodies[0];
    let rows = Array.from(tbody.rows);
    let header = table.tHead.rows[0].cells[columnIndex];
    let isAsc = header.classList.contains('sort-desc') || !header.classList.contains('sort-asc');

    rows.sort((a, b) => {{
        let valA = a.cells[columnIndex].textContent.trim();
        let valB = b.cells[columnIndex].textContent.trim();
        if (isNumeric) {{
            valA = parseFloat(valA.replace('N/A', '-1')) || -1;
            valB = parseFloat(valB.replace('N/A', '-1')) || -1;
        }}
        let comparator = valA > valB ? 1 : (valA < valB ? -1 : 0);
        return isAsc ? comparator : -comparator;
    }});
    
    for (let th of table.tHead.rows[0].cells) {{
        th.classList.remove('sort-asc', 'sort-desc');
    }}
    header.classList.add(isAsc ? 'sort-asc' : 'sort-desc');

    rows.forEach(row => tbody.appendChild(row));
}}
</script>
</body>
</html>
        """
        Path(output_file).write_text(html_template, encoding="utf-8")
        return True, f"Report successfully written to {output_file}"

    except Exception as e:
        return False, f"Failed to generate HTML report: {e}"