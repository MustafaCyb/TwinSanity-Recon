"""
TwinSanity Recon V2 - Report Generator
======================================
Generates professional HTML and PDF security reports from scan results.
Features a modern dark cybersecurity theme with professional styling.
Supports wkhtmltopdf for high-quality PDF generation.
"""

import html
import json
import logging
import re
import subprocess
from datetime import datetime
from pathlib import Path
from typing import Dict, Optional, Any

logger = logging.getLogger(__name__)

# Reports directory
REPORTS_DIR = Path(__file__).parent.parent / "reports"
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# wkhtmltopdf path (Windows)
WKHTMLTOPDF_PATH = Path(__file__).parent.parent / "Windows_PDF_Generator" / "wkhtmltopdf.exe"


def _escape(s: Any) -> str:
    """Safely HTML-escapes a value."""
    return html.escape(str(s)) if s is not None else ""


def _get_severity_badge(severity: Optional[str]) -> str:
    """Returns a modern styled HTML badge based on severity."""
    s = (severity or "low").lower()
    colors = {
        "critical": ("linear-gradient(135deg, #ff0844 0%, #ffb199 100%)", "#ff0844"),
        "high": ("linear-gradient(135deg, #f5576c 0%, #f093fb 100%)", "#f5576c"), 
        "medium": ("linear-gradient(135deg, #fa8231 0%, #ffb142 100%)", "#fa8231"),
        "low": ("linear-gradient(135deg, #26de81 0%, #20bf6b 100%)", "#26de81"),
        "unknown": ("linear-gradient(135deg, #4b6584 0%, #778ca3 100%)", "#778ca3")
    }
    gradient, solid = colors.get(s, colors["unknown"])
    return f"""<span class='severity-badge severity-{s}' style='
        display: inline-block;
        padding: 4px 12px;
        border-radius: 20px;
        font-size: 0.7em;
        font-weight: 700;
        letter-spacing: 0.5px;
        color: white;
        background: {gradient};
        box-shadow: 0 2px 8px {solid}40;
        text-transform: uppercase;
    '>{_escape(s)}</span>"""


def _get_severity_badge_simple(severity: Optional[str]) -> str:
    """Returns a simple styled badge for PDF compatibility."""
    s = (severity or "low").lower()
    colors = {
        "critical": "#ff0844",
        "high": "#f5576c", 
        "medium": "#fa8231",
        "low": "#26de81",
        "unknown": "#778ca3"
    }
    color = colors.get(s, colors["unknown"])
    return f"<span style='display:inline-block;padding:3px 10px;border-radius:4px;font-size:0.75em;font-weight:bold;color:white;background:{color};'>{_escape(s.upper())}</span>"


def _get_cvss_color(score: Optional[float]) -> str:
    """Returns a color for CVSS score."""
    if score is None:
        return "#778ca3"
    try:
        score = float(score)
    except (ValueError, TypeError):
        return "#778ca3"
    
    if score >= 9.0:
        return "#ff0844"
    if score >= 7.0:
        return "#f5576c"
    if score >= 4.0:
        return "#fa8231"
    return "#26de81"


def _get_cvss_gauge(score: Optional[float]) -> str:
    """Returns a visual CVSS gauge."""
    if score is None:
        return "<span class='cvss-na'>N/A</span>"
    try:
        score = float(score)
    except (ValueError, TypeError):
        return "<span class='cvss-na'>N/A</span>"
    
    color = _get_cvss_color(score)
    percentage = (score / 10) * 100
    return f"""<div class='cvss-gauge'>
        <div class='cvss-value' style='color: {color};'>{score:.1f}</div>
        <div class='cvss-bar-bg'>
            <div class='cvss-bar-fill' style='width: {percentage}%; background: {color};'></div>
        </div>
    </div>"""


def _pdf_safe_text(text: str) -> str:
    """Replace emojis and special Unicode characters with PDF-compatible alternatives."""
    replacements = {
        '🛡️': '[SHIELD]',
        '🛡': '[SHIELD]',
        '⚠️': '[!]',
        '⚠': '[!]',
        '✅': '[OK]',
        '✓': '[OK]',
        '❌': '[X]',
        '✗': '[X]',
        '🔒': '[LOCK]',
        '🔓': '[UNLOCK]',
        '→': '->',
        '←': '<-',
        '●': '*',
        '○': 'o',
        '★': '*',
        '☆': '*',
        '▶': '>',
        '◀': '<',
        '◆': '*',
        '◇': '*',
        '►': '>',
        '◄': '<',
        '🔴': '[!]',
        '🟡': '[~]',
        '🟢': '[OK]',
        '📊': '[CHART]',
        '📈': '[UP]',
        '📉': '[DOWN]',
        '🔍': '[?]',
        '💡': '[TIP]',
        '📋': '[LIST]',
        '🔧': '[TOOL]',
        '⚡': '[!]',
        '🚨': '[!]',
        '📁': '[FILE]',
        '🌐': '[WEB]',
        '💻': '[PC]',
        '🖥️': '[PC]',
        '🖥': '[PC]',
    }
    for emoji, replacement in replacements.items():
        text = text.replace(emoji, replacement)
    return text


class ReportGenerator:
    """Generates professional security assessment reports with dark cybersecurity theme"""
    
    def __init__(self):
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        self.wkhtmltopdf_available = WKHTMLTOPDF_PATH.exists()
        if self.wkhtmltopdf_available:
            logger.info(f"✅ wkhtmltopdf found at: {WKHTMLTOPDF_PATH}")
        else:
            logger.warning(f"⚠️ wkhtmltopdf not found at: {WKHTMLTOPDF_PATH}")
    
    def _get_favicon_base64(self) -> str:
        """Get favicon as base64 encoded string"""
        import base64
        favicon_path = Path(__file__).parent.parent / "favicon.png"
        try:
            if favicon_path.exists():
                with open(favicon_path, 'rb') as f:
                    return base64.b64encode(f.read()).decode('utf-8')
        except Exception as e:
            logger.debug(f"Could not load favicon: {e}")
        # Return empty string if favicon not found
        return ""
    
    def generate_html_report(
        self, 
        scan_results: Dict, 
        scan_id: str, 
        domain: str, 
        ai_analysis: Optional[str] = None,
        tools_findings: Optional[Dict] = None
    ) -> str:
        """
        Generate HTML report and return the file path.
        """
        # Analyze the results
        data = self._analyze_scan_results(scan_results)
        
        # Add tools findings to data
        data['tools_findings'] = tools_findings or {}
        
        # Build HTML content
        html_content = self._build_html_report(data, scan_id, domain, ai_analysis)
        
        # Create clean filename
        safe_domain = re.sub(r'[^\w\-.]', '_', domain)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"TwinSanity_Report_{safe_domain}_{timestamp}.html"
        
        # Write file
        filepath = REPORTS_DIR / filename
        filepath.write_text(html_content, encoding='utf-8')
        
        logger.info(f"Generated HTML report: {filepath}")
        return str(filepath)
    
    def generate_pdf_report(
        self, 
        scan_results: Dict, 
        scan_id: str, 
        domain: str, 
        ai_analysis: Optional[str] = None,
        tools_findings: Optional[Dict] = None
    ) -> Optional[str]:
        """Generate PDF report using wkhtmltopdf for best quality."""
        # First generate HTML optimized for PDF
        data = self._analyze_scan_results(scan_results)
        
        # Add tools findings to data
        data['tools_findings'] = tools_findings or {}
        
        html_content = self._build_pdf_optimized_report(data, scan_id, domain, ai_analysis)
        
        # Replace emojis/special characters with PDF-compatible text
        html_content = _pdf_safe_text(html_content)
                # Create clean filename
        safe_domain = re.sub(r'[^\w\-.]', '_', domain)
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_filename = f"TwinSanity_Report_{safe_domain}_{timestamp}_print.html"
        pdf_filename = f"TwinSanity_Report_{safe_domain}_{timestamp}.pdf"
        
        # Write HTML file
        html_path = REPORTS_DIR / html_filename
        html_path.write_text(html_content, encoding='utf-8')
        pdf_path = str(REPORTS_DIR / pdf_filename)
        
        # Try wkhtmltopdf first (best quality)
        if self.wkhtmltopdf_available:
            try:
                cmd = [
                    str(WKHTMLTOPDF_PATH),
                    '--enable-local-file-access',
                    '--page-size', 'A4',
                    '--orientation', 'Portrait',
                    '--margin-top', '8mm',
                    '--margin-bottom', '12mm',
                    '--margin-left', '8mm',
                    '--margin-right', '8mm',
                    '--encoding', 'UTF-8',
                    '--no-stop-slow-scripts',
                    '--javascript-delay', '100',
                    '--footer-center', 'Page [page] of [topage]',
                    '--footer-font-name', 'Arial',
                    '--footer-font-size', '8',
                    '--footer-spacing', '5',
                    '--dpi', '150',
                    '--image-quality', '100',
                    '--disable-smart-shrinking',
                    str(html_path),
                    pdf_path
                ]
                
                result = subprocess.run(
                    cmd, 
                    capture_output=True, 
                    text=True, 
                    timeout=120
                )
                
                if result.returncode == 0 and Path(pdf_path).exists():
                    logger.info(f"✅ Generated PDF report with wkhtmltopdf: {pdf_path}")
                    # Clean up temp HTML
                    try:
                        html_path.unlink()
                    except:
                        pass
                    return pdf_path
                else:
                    logger.warning(f"wkhtmltopdf returned code {result.returncode}: {result.stderr}")
            except subprocess.TimeoutExpired:
                logger.error("wkhtmltopdf timed out")
            except Exception as e:
                logger.error(f"wkhtmltopdf failed: {e}")
        
        # Fallback to xhtml2pdf
        try:
            from xhtml2pdf import pisa
            
            with open(pdf_path, 'wb') as pdf_file:
                pisa_status = pisa.CreatePDF(html_content, dest=pdf_file)
            
            if not pisa_status.err:
                logger.info(f"✅ Generated PDF report with xhtml2pdf: {pdf_path}")
                return pdf_path
        except ImportError:
            logger.warning("xhtml2pdf not installed")
        except Exception as e:
            logger.error(f"xhtml2pdf failed: {e}")
        
        logger.error(f"PDF generation failed. HTML report available at: {html_path}")
        return None
    
    def _build_pdf_optimized_report(
        self, 
        data: Dict, 
        scan_id: str, 
        domain: str, 
        ai_analysis: Optional[str]
    ) -> str:
        """Build a clean, print-optimized HTML report for PDF generation."""
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total_cves = len(data["cves"])
        
        # Calculate risk score
        risk_score = min(100, (
            data['severity_counts']['critical'] * 25 +
            data['severity_counts']['high'] * 15 +
            data['severity_counts']['medium'] * 5 +
            data['severity_counts']['low'] * 1
        ))
        risk_level = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW"
        
        # Build CVE table
        cve_rows = ""
        for cve in data["cves"][:50]:  # Limit for PDF
            affected = ", ".join(cve["affected_ips"][:3])
            if len(cve["affected_ips"]) > 3:
                affected += f" +{len(cve['affected_ips']) - 3}"
            
            severity_class = cve['severity'].lower()
            # Truncate summary at word boundary
            summary = cve['summary']
            if len(summary) > 120:
                summary = summary[:120].rsplit(' ', 1)[0] + '...'
            
            cve_rows += f"""<tr>
                <td class="cve-id">{_escape(cve['id'])}</td>
                <td class="cvss">{cve['cvss'] if cve['cvss'] else 'N/A'}</td>
                <td><span class="severity {severity_class}">{cve['severity'].upper()}</span></td>
                <td class="affected">{len(cve['affected_ips'])}</td>
                <td class="summary">{_escape(summary)}</td>
            </tr>"""
        
        if not cve_rows:
            cve_rows = "<tr><td colspan='5' class='no-data'>No vulnerabilities detected</td></tr>"
        
        # Build host table
        host_rows = ""
        for host in data["hosts"][:30]:  # Limit for PDF
            hostnames = ", ".join(host["hosts"][:2]) or "—"
            if len(host["hosts"]) > 2:
                hostnames += f" +{len(host['hosts']) - 2}"
            ports = ", ".join(str(p) for p in host["ports"][:6]) or "—"
            if len(host["ports"]) > 6:
                ports += f" +{len(host['ports']) - 6}"
            
            host_rows += f"""<tr>
                <td>{_escape(host['ip'])}</td>
                <td>{_escape(hostnames)}</td>
                <td class="ports">{_escape(ports)}</td>
                <td class="cve-count">{len(host['cves'])}</td>
            </tr>"""
        
        if not host_rows:
            host_rows = "<tr><td colspan='4' class='no-data'>No hosts analyzed</td></tr>"
        
        # Build AI section
        ai_section = self._build_ai_section_for_pdf(ai_analysis, data)
        
        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>TwinSanity Security Report - {_escape(domain)}</title>
    <style>
        /* PDF-Optimized Styles - Modern wkhtmltopdf compatible design */
        @page {{
            size: A4;
            margin: 12mm 12mm 18mm 12mm;
        }}
        
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        body {{
            font-family: 'Segoe UI', Arial, Helvetica, sans-serif;
            font-size: 9pt;
            line-height: 1.5;
            color: #1a1a2e;
            background: #fff;
        }}
        
        .container {{
            padding: 0;
            width: 100%;
        }}
        
        /* Header - Modern dark design with gradient feel */
        .report-header {{
            background: linear-gradient(135deg, #0a0e14 0%, #1a1f2e 100%);
            color: white;
            padding: 25px 30px;
            margin-bottom: 0;
            position: relative;
        }}
        
        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: linear-gradient(90deg, #00d4ff, #a855f7, #00d4ff);
        }}
        
        .header-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .header-table td {{
            vertical-align: middle;
            padding: 0;
            border: none;
        }}
        
        .logo {{
            width: 48px;
            height: 48px;
            background: linear-gradient(135deg, #00d4ff, #a855f7);
            border-radius: 10px;
            text-align: center;
            line-height: 48px;
            font-size: 24px;
            display: inline-block;
            margin-right: 15px;
            vertical-align: middle;
        }}
        
        .report-title {{
            font-size: 22pt;
            font-weight: 800;
            margin: 0;
            color: #00d4ff;
            letter-spacing: -0.5px;
        }}
        
        .report-subtitle {{
            font-size: 10pt;
            color: #9ba8b5;
            margin-top: 4px;
        }}
        
        .risk-badge {{
            text-align: center;
            padding: 15px 25px;
            background: linear-gradient(135deg, rgba(255,255,255,0.05), rgba(255,255,255,0.02));
            border-radius: 12px;
            border: 2px solid {'#ef4444' if risk_score >= 75 else '#f97316' if risk_score >= 50 else '#eab308' if risk_score >= 25 else '#22c55e'};
        }}
        
        .risk-score {{
            font-size: 32pt;
            font-weight: 800;
            color: {'#ef4444' if risk_score >= 75 else '#f97316' if risk_score >= 50 else '#eab308' if risk_score >= 25 else '#22c55e'};
            line-height: 1;
        }}
        
        .risk-label {{
            font-size: 8pt;
            text-transform: uppercase;
            letter-spacing: 1.5px;
            color: #9ba8b5;
            margin-top: 6px;
        }}
        
        .meta-row {{
            margin-top: 18px;
            color: #9ba8b5;
            font-size: 9pt;
        }}
        
        .meta-item {{
            display: inline-block;
            margin-right: 30px;
            background: rgba(255,255,255,0.05);
            padding: 6px 12px;
            border-radius: 6px;
        }}
        
        .meta-item strong {{
            color: #00d4ff;
        }}
        
        /* Stats Bar - Enhanced with visual hierarchy */
        .stats-bar {{
            background: linear-gradient(180deg, #f8fafc 0%, #f1f5f9 100%);
            padding: 18px 20px;
            border-bottom: 3px solid #0a0e14;
        }}
        
        .stats-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .stats-table td {{
            text-align: center;
            padding: 8px 10px;
            border: none;
        }}
        
        .stat-number {{
            font-size: 22pt;
            font-weight: 800;
            color: #0a0e14;
            display: block;
            line-height: 1.1;
        }}
        
        .stat-number.critical {{ color: #ef4444; }}
        .stat-number.high {{ color: #f97316; }}
        .stat-number.medium {{ color: #ca8a04; }}
        .stat-number.low {{ color: #22c55e; }}
        
        .stat-label {{
            font-size: 7pt;
            color: #64748b;
            text-transform: uppercase;
            letter-spacing: 0.8px;
            font-weight: 600;
        }}
        
        /* Content Area */
        .content {{
            padding: 20px 25px;
        }}
        
        /* Sections - Enhanced cards */
        .section {{
            margin-bottom: 22px;
            border-radius: 8px;
            overflow: hidden;
            border: 1px solid #e2e8f0;
        }}
        
        .section-header {{
            background: linear-gradient(135deg, #0a0e14 0%, #1a1f2e 100%);
            color: white;
            padding: 12px 16px;
            font-size: 11pt;
            font-weight: 700;
            margin-bottom: 0;
        }}
        
        .section-badge {{
            background: rgba(0, 212, 255, 0.2);
            color: #00d4ff;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 8pt;
            float: right;
            font-weight: 700;
        }}
        
        /* Tables - Modern clean design */
        table {{
            width: 100%;
            border-collapse: collapse;
            font-size: 8pt;
            margin: 0;
            table-layout: fixed;
        }}
        
        th {{
            background: linear-gradient(180deg, #f1f5f9 0%, #e2e8f0 100%);
            color: #334155;
            padding: 10px 8px;
            text-align: left;
            font-weight: 700;
            font-size: 7pt;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border: 1px solid #cbd5e1;
        }}
        
        td {{
            padding: 8px;
            border: 1px solid #e2e8f0;
            vertical-align: top;
            word-wrap: break-word;
            overflow: hidden;
        }}
        
        tr:nth-child(even) {{
            background: #f8fafc;
        }}
        
        tr:hover {{
            background: #f1f5f9;
        }}
        
        .cve-id {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-weight: 700;
            color: #0066cc;
            font-size: 7.5pt;
            background: #e0f2fe;
            padding: 2px 6px;
            border-radius: 4px;
        }}
        
        .cvss {{
            font-weight: 800;
            text-align: center;
            font-size: 9pt;
        }}
        
        .severity {{
            font-weight: 700;
            text-align: center;
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 7pt;
            display: inline-block;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        .severity.critical {{
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
        }}
        
        .severity.high {{
            background: linear-gradient(135deg, #f97316, #ea580c);
            color: white;
        }}
        
        .severity.medium {{
            background: linear-gradient(135deg, #eab308, #ca8a04);
            color: white;
        }}
        
        .severity.low {{
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color: white;
        }}
        
        /* Executive Summary - Premium card design */
        .exec-summary {{
            padding: 18px;
            background: linear-gradient(135deg, #f0f9ff 0%, #f8fafc 100%);
            border-left: 5px solid #0066cc;
            margin-bottom: 18px;
            border-radius: 0 8px 8px 0;
        }}
        
        .exec-summary p {{
            margin: 8px 0;
            font-size: 9pt;
            color: #334155;
        }}
        
        .summary-box {{
            padding: 12px;
            background: white;
            border: 1px solid #e2e8f0;
            border-radius: 8px;
            box-shadow: 0 1px 3px rgba(0,0,0,0.05);
        }}
        
        .summary-box strong {{
            color: #0a0e14;
            font-size: 9pt;
        }}
        
        .summary-box ul {{
            font-size: 8pt;
            line-height: 1.6;
            color: #475569;
        }}
        
        .summary-box li {{
            margin: 5px 0;
        }}
        
        .risk-indicator {{
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 8pt;
            letter-spacing: 0.5px;
        }}
        
        .risk-indicator.risk-critical {{
            background: linear-gradient(135deg, #ef4444, #dc2626);
            color: white;
        }}
        
        .risk-indicator.risk-high {{
            background: linear-gradient(135deg, #f97316, #ea580c);
            color: white;
        }}
        
        .risk-indicator.risk-medium {{
            background: linear-gradient(135deg, #eab308, #ca8a04);
            color: white;
        }}
        
        .risk-indicator.risk-low {{
            background: linear-gradient(135deg, #22c55e, #16a34a);
            color: white;
        }}
        
        .affected {{
            text-align: center;
            font-weight: 700;
            color: #0a0e14;
        }}
        
        .summary {{
            color: #475569;
            font-size: 7.5pt;
            line-height: 1.4;
        }}
        
        .ports {{
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 7pt;
            color: #16a34a;
            background: #f0fdf4;
            padding: 2px 4px;
            border-radius: 3px;
        }}
        
        .cve-count {{
            text-align: center;
            font-weight: 700;
        }}
        
        .no-data {{
            text-align: center;
            padding: 20px;
            color: #16a34a;
            font-style: italic;
            background: #f0fdf4;
        }}
        
        /* AI Section - Distinctive styling */
        .ai-section {{
            background: linear-gradient(135deg, #f5f3ff 0%, #faf5ff 100%);
            border: 1px solid #a855f7;
            border-radius: 8px;
            margin-bottom: 22px;
            overflow: hidden;
        }}
        
        .ai-section .section-header {{
            background: linear-gradient(135deg, #7c3aed 0%, #a855f7 100%);
        }}
        
        .ai-section .section-badge {{
            background: rgba(255, 255, 255, 0.2);
            color: white;
        }}
        
        .ai-content {{
            padding: 16px 18px;
        }}
        
        .ai-content h4 {{
            color: #7c3aed;
            font-size: 10pt;
            margin: 14px 0 8px 0;
            padding-bottom: 6px;
            border-bottom: 1px solid #ddd6fe;
            font-weight: 700;
        }}
        
        .ai-content h4:first-child {{
            margin-top: 0;
        }}
        
        .ai-content p {{
            margin-bottom: 10px;
            color: #374151;
            font-size: 8.5pt;
            line-height: 1.5;
        }}
        
        .ai-content ul {{
            margin: 0 0 10px 20px;
            color: #374151;
            font-size: 8pt;
        }}
        
        .ai-content li {{
            margin-bottom: 5px;
        }}
        
        .ai-content table th {{
            background: linear-gradient(180deg, #ede9fe 0%, #ddd6fe 100%);
            color: #5b21b6;
        }}
        
        /* Footer - Clean professional design */
        .report-footer {{
            background: linear-gradient(135deg, #0a0e14 0%, #1a1f2e 100%);
            color: white;
            padding: 18px 30px;
            text-align: center;
            font-size: 8pt;
            margin-top: 25px;
            border-radius: 8px 8px 0 0;
        }}
        
        .report-footer strong {{
            color: #00d4ff;
            font-size: 10pt;
        }}
        
        .footer-disclaimer {{
            color: #9ba8b5;
            margin-top: 8px;
            padding: 6px 12px;
            background: rgba(239, 68, 68, 0.1);
            border-radius: 4px;
            display: inline-block;
        }}
        
        /* Page break handling */
        .page-break {{
            page-break-before: always;
        }}
        
        /* Prevent orphaned headers */
        .section-header {{
            page-break-after: avoid;
        }}
        
        /* Keep table headers with content */
        thead {{
            display: table-header-group;
        }}
        
        tr {{
            page-break-inside: avoid;
        }}
        
        /* Severity colors for CVSS */
        .cvss-critical {{ color: #ef4444; }}
        .cvss-high {{ color: #f97316; }}
        .cvss-medium {{ color: #ca8a04; }}
        .cvss-low {{ color: #22c55e; }}
    </style>
</head>
<body>
    <div class="container">
        <!-- Header using table layout for PDF compatibility -->
        <div class="report-header">
            <table class="header-table">
                <tr>
                    <td style="width: 70%;">
                        <span class="logo">🛡️</span>
                        <span style="vertical-align: middle;">
                            <span class="report-title">TwinSanity Security Report</span><br>
                            <span class="report-subtitle">Automated Vulnerability Assessment</span>
                        </span>
                    </td>
                    <td style="width: 30%; text-align: right;">
                        <div class="risk-badge">
                            <div class="risk-score">{risk_score}</div>
                            <div class="risk-label">Risk Score • {risk_level}</div>
                        </div>
                    </td>
                </tr>
            </table>
            <div class="meta-row">
                <span class="meta-item"><strong>Target:</strong> {_escape(domain)}</span>
                <span class="meta-item"><strong>Scan ID:</strong> {_escape(scan_id[:8])}</span>
                <span class="meta-item"><strong>Generated:</strong> {timestamp}</span>
            </div>
        </div>
        
        <!-- Stats Bar using table layout -->
        <div class="stats-bar">
            <table class="stats-table">
                <tr>
                    <td>
                        <span class="stat-number">{data['total_ips']}</span>
                        <span class="stat-label">IPs Scanned</span>
                    </td>
                    <td>
                        <span class="stat-number">{data['total_subdomains']}</span>
                        <span class="stat-label">Subdomains</span>
                    </td>
                    <td>
                        <span class="stat-number">{total_cves}</span>
                        <span class="stat-label">Unique CVEs</span>
                    </td>
                    <td>
                        <span class="stat-number critical">{data['severity_counts']['critical']}</span>
                        <span class="stat-label">Critical</span>
                    </td>
                    <td>
                        <span class="stat-number high">{data['severity_counts']['high']}</span>
                        <span class="stat-label">High</span>
                    </td>
                    <td>
                        <span class="stat-number medium">{data['severity_counts']['medium']}</span>
                        <span class="stat-label">Medium</span>
                    </td>
                    <td>
                        <span class="stat-number low">{data['severity_counts']['low']}</span>
                        <span class="stat-label">Low</span>
                    </td>
                </tr>
            </table>
        </div>
        
        <!-- Content -->
        <div class="content">
            <!-- Executive Summary -->
            <div class="section">
                <div class="section-header">
                    📋 Executive Summary
                </div>
                <div class="exec-summary">
                    <p><strong>Assessment Target:</strong> {_escape(domain)}</p>
                    <p><strong>Total Vulnerabilities:</strong> {total_cves} unique CVEs identified across {data['total_ips']} IP addresses and {data['total_subdomains']} subdomains</p>
                    <p><strong>Risk Assessment:</strong> <span class="risk-indicator risk-{risk_level.lower()}">{risk_level} RISK</span> (Score: {risk_score}/100)</p>
                    
                    <table style="margin-top: 10px; width: 100%; border-collapse: collapse;">
                        <tr>
                            <td style="width: 50%; vertical-align: top; padding-right: 10px;">
                                <div class="summary-box">
                                    <strong>Key Findings:</strong>
                                    <ul style="margin: 5px 0 0 15px; padding: 0;">
                                        {f'<li style="color:#dc3545;">🔴 {data["severity_counts"]["critical"]} Critical vulnerabilities require immediate attention</li>' if data['severity_counts']['critical'] > 0 else ''}
                                        {f'<li style="color:#fd7e14;">🟠 {data["severity_counts"]["high"]} High-severity vulnerabilities identified</li>' if data['severity_counts']['high'] > 0 else ''}
                                        {f'<li>🌐 {data["attack_surface"]["exposed_hosts"]} hosts with exposed services</li>' if data["attack_surface"]["exposed_hosts"] > 0 else ''}
                                        {f'<li>⚠️ {len(data["attack_surface"]["unique_services"])} different service types exposed</li>' if len(data["attack_surface"]["unique_services"]) > 5 else ''}
                                        {'<li style="color:#28a745;">✅ No vulnerabilities detected - system appears secure</li>' if total_cves == 0 else ''}
                                    </ul>
                                </div>
                            </td>
                            <td style="width: 50%; vertical-align: top; padding-left: 10px;">
                                <div class="summary-box">
                                    <strong>Priority Actions:</strong>
                                    <ul style="margin: 5px 0 0 15px; padding: 0;">
                                        {f'<li>Immediately patch all {data["severity_counts"]["critical"]} Critical vulnerabilities</li>' if data['severity_counts']['critical'] > 0 else ''}
                                        {f'<li>Remediate {data["severity_counts"]["high"]} High-severity issues within 7 days</li>' if data['severity_counts']['high'] > 5 else ''}
                                        {f'<li>Review and close unnecessary ports ({data["attack_surface"]["total_open_ports"]} currently open)</li>' if data["attack_surface"]["total_open_ports"] > 50 else ''}
                                        <li>Update all software to latest secure versions</li>
                                        <li>Continue regular security monitoring</li>
                                    </ul>
                                </div>
                            </td>
                        </tr>
                    </table>
                </div>
            </div>
            
            {ai_section}
            
            <!-- CVE Listing -->
            <div class="section">
                <div class="section-header">
                    🔓 Vulnerability Listing
                    <span class="section-badge">{total_cves} CVEs</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th style="width: 18%;">CVE ID</th>
                            <th style="width: 8%;">CVSS</th>
                            <th style="width: 10%;">Severity</th>
                            <th style="width: 8%;">Hosts</th>
                            <th style="width: 56%;">Description</th>
                        </tr>
                    </thead>
                    <tbody>
                        {cve_rows}
                    </tbody>
                </table>
                {'<p style="text-align:center;color:#666;font-size:7pt;margin-top:8px;"><em>Showing top 50 CVEs. Full data available in HTML report.</em></p>' if total_cves > 50 else ''}
            </div>
            
            <!-- Host Analysis -->
            <div class="section">
                <div class="section-header">
                    🖥️ Host Analysis
                    <span class="section-badge">{data['total_ips']} Hosts</span>
                </div>
                <table>
                    <thead>
                        <tr>
                            <th style="width: 18%;">IP Address</th>
                            <th style="width: 32%;">Hostnames</th>
                            <th style="width: 35%;">Open Ports</th>
                            <th style="width: 15%;">CVE Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {host_rows}
                    </tbody>
                </table>
            </div>
            
            <!-- Technology & Services Analysis -->
            {self._build_technology_section_pdf(data)}
            
            <!-- Tools Findings Section -->
            {self._build_tools_findings_section_pdf(data.get('tools_findings', {}))}
        </div>
        
        <!-- Footer -->
        <div class="report-footer">
            <div><strong>TwinSanity Recon V2</strong> • Automated Security Assessment Platform</div>
            <div class="footer-disclaimer">⚠️ Confidential - Authorized Personnel Only</div>
        </div>
    </div>
</body>
</html>"""

    def _build_tools_findings_section_pdf(self, tools_findings: Dict) -> str:
        """Build tools findings section for PDF report (Nuclei, XSS, API Discovery)."""
        if not tools_findings:
            return ""
        
        nuclei = tools_findings.get('nuclei_findings', {})
        xss = tools_findings.get('xss_findings', {})
        api = tools_findings.get('api_discoveries', {})
        alive = tools_findings.get('alive_hosts', {})
        urls = tools_findings.get('harvested_urls', {})
        
        # Check if there are any findings (including harvested URLs)
        total_findings = (nuclei.get('count', 0) + xss.get('count', 0) + 
                         api.get('count', 0) + alive.get('count', 0) + urls.get('count', 0))
        
        if total_findings == 0:
            return ""
        
        sections = []
        
        # Nuclei Findings
        if nuclei.get('count', 0) > 0:
            nuclei_rows = ""
            for item in nuclei.get('items', [])[:20]:
                severity = item.get('severity', 'unknown').lower()
                sev_color = {'critical': '#ff0844', 'high': '#f5576c', 'medium': '#fa8231', 'low': '#26de81'}.get(severity, '#778ca3')
                nuclei_rows += f"""<tr>
                    <td style="padding:4px 6px;border:1px solid #333;"><span style="color:{sev_color};font-weight:bold;">{_escape(severity.upper())}</span></td>
                    <td style="padding:4px 6px;border:1px solid #333;">{_escape(item.get('name', 'Unknown'))}</td>
                    <td style="padding:4px 6px;border:1px solid #333;font-size:7pt;">{_escape(item.get('host', 'N/A'))}</td>
                </tr>"""
            
            by_sev = nuclei.get('by_severity', {})
            sev_summary = ", ".join([f"{k}: {v}" for k, v in by_sev.items()])
            
            sections.append(f"""
            <div class="section" style="page-break-inside: avoid;">
                <div class="section-header">
                    🎯 Nuclei Vulnerability Scan
                    <span class="section-badge">{nuclei.get('count', 0)} Findings</span>
                </div>
                <p style="font-size:8pt;color:#999;margin:5px 0;">Severity Breakdown: {sev_summary or 'N/A'}</p>
                <table style="width:100%;border-collapse:collapse;font-size:8pt;">
                    <thead>
                        <tr style="background:#1a2029;">
                            <th style="padding:5px;border:1px solid #333;width:15%;">Severity</th>
                            <th style="padding:5px;border:1px solid #333;width:45%;">Vulnerability</th>
                            <th style="padding:5px;border:1px solid #333;width:40%;">Affected Host</th>
                        </tr>
                    </thead>
                    <tbody>{nuclei_rows}</tbody>
                </table>
            </div>""")
        
        # XSS Findings
        if xss.get('count', 0) > 0:
            xss_rows = ""
            for item in xss.get('items', [])[:10]:
                xss_rows += f"""<tr>
                    <td style="padding:4px 6px;border:1px solid #333;color:#f5576c;font-weight:bold;">XSS</td>
                    <td style="padding:4px 6px;border:1px solid #333;">{_escape(item.get('parameter', 'N/A'))}</td>
                    <td style="padding:4px 6px;border:1px solid #333;font-size:7pt;">{_escape(item.get('url', 'N/A')[:60])}</td>
                </tr>"""
            
            sections.append(f"""
            <div class="section" style="page-break-inside: avoid;">
                <div class="section-header">
                    ⚡ XSS Vulnerabilities
                    <span class="section-badge">{xss.get('count', 0)} Found</span>
                </div>
                <table style="width:100%;border-collapse:collapse;font-size:8pt;">
                    <thead>
                        <tr style="background:#1a2029;">
                            <th style="padding:5px;border:1px solid #333;width:15%;">Type</th>
                            <th style="padding:5px;border:1px solid #333;width:25%;">Parameter</th>
                            <th style="padding:5px;border:1px solid #333;width:60%;">URL</th>
                        </tr>
                    </thead>
                    <tbody>{xss_rows}</tbody>
                </table>
            </div>""")
        
        # API Discoveries
        if api.get('count', 0) > 0:
            api_rows = ""
            for item in api.get('items', [])[:15]:
                api_rows += f"""<tr>
                    <td style="padding:4px 6px;border:1px solid #333;">{_escape(item.get('api_type', 'Unknown'))}</td>
                    <td style="padding:4px 6px;border:1px solid #333;">{_escape(item.get('path', 'N/A'))}</td>
                    <td style="padding:4px 6px;border:1px solid #333;">{item.get('status_code', 'N/A')}</td>
                </tr>"""
            
            sections.append(f"""
            <div class="section" style="page-break-inside: avoid;">
                <div class="section-header">
                    🔌 API Endpoints Discovered
                    <span class="section-badge">{api.get('count', 0)} Endpoints</span>
                </div>
                <table style="width:100%;border-collapse:collapse;font-size:8pt;">
                    <thead>
                        <tr style="background:#1a2029;">
                            <th style="padding:5px;border:1px solid #333;width:20%;">Type</th>
                            <th style="padding:5px;border:1px solid #333;width:60%;">Path</th>
                            <th style="padding:5px;border:1px solid #333;width:20%;">Status</th>
                        </tr>
                    </thead>
                    <tbody>{api_rows}</tbody>
                </table>
            </div>""")
        
        # Harvested URLs Section - SHOW ALL URLs with expandable view
        if urls.get('count', 0) > 0:
            url_rows = ""
            all_urls = urls.get('sample', [])  # Now contains ALL URLs
            
            # Build ALL URL rows (no limit)
            for url in all_urls:
                url_str = url if isinstance(url, str) else str(url)
                # Truncate long URLs for display but keep full URL in title
                display_url = url_str[:100] + '...' if len(url_str) > 100 else url_str
                has_params = '?' in url_str
                param_marker = '✓' if has_params else '-'
                url_rows += f'''<tr>
                    <td style="padding:4px 6px;border:1px solid #333;font-size:7pt;word-break:break-all;" title="{_escape(url_str)}">{_escape(display_url)}</td>
                    <td style="padding:4px 6px;border:1px solid #333;text-align:center;">{param_marker}</td>
                </tr>'''
            
            url_count = urls.get('count', 0)
            params_count = urls.get('with_params', 0)
            url_section = f'''
            <div class="section" style="page-break-inside: avoid;">
                <div class="section-header">
                    🔗 Harvested URLs (Wayback/CommonCrawl) - Full List
                    <span class="section-badge">{url_count} URLs ({params_count} with params)</span>
                </div>
                <p style="font-size:8pt;color:#999;margin:5px 0;">URLs with parameters are valuable for security testing (XSS, SQLi, etc.). <strong>Showing all {len(all_urls)} URLs.</strong></p>
                <table style="width:100%;border-collapse:collapse;font-size:8pt;">
                    <thead>
                        <tr style="background:#1a2029;">
                            <th style="padding:5px;border:1px solid #333;width:85%;">URL</th>
                            <th style="padding:5px;border:1px solid #333;width:15%;">Has Params</th>
                        </tr>
                    </thead>
                    <tbody>{url_rows}</tbody>
                </table>
            </div>'''
            sections.append(url_section)
        
        # Summary Stats
        summary = f"""
        <div class="section" style="page-break-inside: avoid;">
            <div class="section-header">
                🔧 Security Tools Summary
            </div>
            <table style="width:100%;border-collapse:collapse;font-size:8pt;">
                <tr>
                    <td style="padding:8px;border:1px solid #333;width:50%;"><strong>Alive Hosts Probed:</strong></td>
                    <td style="padding:8px;border:1px solid #333;">{alive.get('count', 0)}</td>
                </tr>
                <tr style="background:#1a2029;">
                    <td style="padding:8px;border:1px solid #333;"><strong>Nuclei Vulnerabilities:</strong></td>
                    <td style="padding:8px;border:1px solid #333;">{nuclei.get('count', 0)}</td>
                </tr>
                <tr>
                    <td style="padding:8px;border:1px solid #333;"><strong>XSS Issues:</strong></td>
                    <td style="padding:8px;border:1px solid #333;">{xss.get('count', 0)}</td>
                </tr>
                <tr style="background:#1a2029;">
                    <td style="padding:8px;border:1px solid #333;"><strong>API Endpoints:</strong></td>
                    <td style="padding:8px;border:1px solid #333;">{api.get('count', 0)}</td>
                </tr>
                <tr>
                    <td style="padding:8px;border:1px solid #333;"><strong>Harvested URLs:</strong></td>
                    <td style="padding:8px;border:1px solid #333;">{urls.get('count', 0)} ({urls.get('with_params', 0)} with params)</td>
                </tr>
            </table>
        </div>"""
        
        return summary + "\n".join(sections)

    def _build_ai_section_for_pdf(self, ai_analysis: Optional[str], data: Dict) -> str:
        """Build AI analysis section optimized for PDF output."""
        if not ai_analysis:
            # No AI analysis - show top CVEs from scan data instead
            if data["cves"]:
                top_vulns = data["cves"][:5]
                vulns_html = "<ul>"
                for cve in top_vulns:
                    vulns_html += f"<li><strong>{_escape(cve['id'])}</strong> (CVSS: {cve['cvss'] or 'N/A'}) - {_escape(cve['summary'][:100])}...</li>"
                vulns_html += "</ul>"
                return f"""
                <div class="ai-section">
                    <div class="section-header">
                        <span>📊 Key Findings Summary</span>
                    </div>
                    <div class="ai-content">
                        <h4>Top Vulnerabilities Detected</h4>
                        {vulns_html}
                        <p><em>Enable AI Analysis for detailed security recommendations.</em></p>
                    </div>
                </div>"""
            return ""
        
        # Parse AI analysis
        ai_data = None
        if isinstance(ai_analysis, str):
            try:
                ai_data = json.loads(ai_analysis)
            except:
                # Plain text analysis
                return f"""
                <div class="ai-section">
                    <div class="section-header">
                        <span>🤖 AI Security Analysis</span>
                    </div>
                    <div class="ai-content">
                        <p>{_escape(ai_analysis)}</p>
                    </div>
                </div>"""
        elif isinstance(ai_analysis, dict):
            ai_data = ai_analysis
        
        if not ai_data:
            return ""
        
        # Extract data from chunks
        chunks = ai_data.get('llm_analysis_results', [])
        all_summaries = []
        all_high_risk = []
        all_key_vulns = []
        all_actions = []
        
        for chunk in chunks:
            analysis = chunk.get('analysis', {})
            if analysis.get('summary') and analysis['summary'] != 'No summary provided.':
                all_summaries.append(analysis['summary'])
            
            # High risk assets
            for asset in analysis.get('high_risk_assets', []):
                if asset.get('ip') and asset.get('ip') != 'N/A':
                    all_high_risk.append(asset)
            
            # Key vulnerabilities - validate data
            for vuln in analysis.get('key_vulnerabilities', []):
                cve_id = vuln.get('cve_id', '')
                if cve_id and cve_id != 'Unknown' and cve_id.startswith('CVE-'):
                    all_key_vulns.append(vuln)
            
            # Actions
            for action in analysis.get('recommended_actions', []):
                if action.get('action') and action.get('action') != 'N/A':
                    all_actions.append(action)
        
        # Build sections
        content_parts = []
        
        # Executive Summary
        if all_summaries:
            summary_text = " ".join(all_summaries[:3])
            if len(summary_text) > 500:
                summary_text = summary_text[:500] + "..."
            content_parts.append(f"<h4>📋 Executive Summary</h4><p>{_escape(summary_text)}</p>")
        
        # High Risk Assets
        if all_high_risk:
            assets_html = "<table><thead><tr><th>IP</th><th>Hostname</th><th>Severity</th><th>Reason</th></tr></thead><tbody>"
            for asset in all_high_risk[:8]:
                sev = asset.get('severity', 'high').lower()
                assets_html += f"""<tr>
                    <td>{_escape(asset.get('ip', 'N/A'))}</td>
                    <td>{_escape(asset.get('hostname', 'N/A'))}</td>
                    <td class="severity {sev}">{sev.upper()}</td>
                    <td>{_escape(str(asset.get('reason', 'N/A'))[:80])}</td>
                </tr>"""
            assets_html += "</tbody></table>"
            if len(all_high_risk) > 8:
                assets_html += f"<p><em>+{len(all_high_risk) - 8} more high-risk assets</em></p>"
            content_parts.append(f"<h4>🎯 High Risk Assets</h4>{assets_html}")
        
        # Key Vulnerabilities - Use AI data OR fallback to scan CVEs
        if all_key_vulns:
            vulns_html = "<ul>"
            for vuln in all_key_vulns[:10]:
                cve_id = vuln.get('cve_id', 'Unknown')
                cvss = vuln.get('cvss', 'N/A')
                why = vuln.get('why_critical', vuln.get('impact', ''))
                if why and why != 'No description':
                    vulns_html += f"<li><strong>{_escape(cve_id)}</strong> (CVSS: {cvss}): {_escape(str(why)[:100])}</li>"
                else:
                    vulns_html += f"<li><strong>{_escape(cve_id)}</strong> (CVSS: {cvss})</li>"
            vulns_html += "</ul>"
            content_parts.append(f"<h4>🔓 Key Vulnerabilities</h4>{vulns_html}")
        elif data["cves"]:
            # Fallback to actual CVE data from scan
            vulns_html = "<ul>"
            for cve in data["cves"][:10]:
                vulns_html += f"<li><strong>{_escape(cve['id'])}</strong> (CVSS: {cve['cvss'] or 'N/A'}): {_escape(cve['summary'][:100])}</li>"
            vulns_html += "</ul>"
            content_parts.append(f"<h4>🔓 Key Vulnerabilities</h4>{vulns_html}")
        
        # Recommended Actions
        if all_actions:
            actions_html = "<table><thead><tr><th>Priority</th><th>Action</th><th>Justification</th></tr></thead><tbody>"
            for action in all_actions[:8]:
                prio = action.get('priority', 'medium').lower()
                actions_html += f"""<tr>
                    <td class="severity {prio}">{prio.upper()}</td>
                    <td>{_escape(str(action.get('action', 'N/A'))[:60])}</td>
                    <td>{_escape(str(action.get('justification', 'N/A'))[:80])}</td>
                </tr>"""
            actions_html += "</tbody></table>"
            content_parts.append(f"<h4>✅ Recommended Actions</h4>{actions_html}")
        
        # Tools Analysis (AI opinion on recon tools findings)
        tools_analysis = ai_data.get('tools_analysis', {})
        if tools_analysis and tools_analysis.get('executive_summary'):
            tools_parts = []
            
            # Executive summary for tools
            tools_parts.append(f"<p><strong>{_escape(tools_analysis.get('executive_summary', ''))}</strong></p>")
            
            # Nuclei analysis
            nuclei_analysis = tools_analysis.get('nuclei_analysis', {})
            if nuclei_analysis.get('key_findings'):
                tools_parts.append("<h5>🔍 Nuclei Vulnerability Findings</h5>")
                tools_parts.append(f"<p>Risk Assessment: <strong>{nuclei_analysis.get('risk_assessment', 'Unknown').upper()}</strong></p>")
                nuclei_html = "<ul>"
                for finding in nuclei_analysis.get('key_findings', [])[:5]:
                    nuclei_html += f"<li>{_escape(str(finding))}</li>"
                nuclei_html += "</ul>"
                tools_parts.append(nuclei_html)
                if nuclei_analysis.get('attack_scenarios'):
                    tools_parts.append("<p><em>Attack Scenarios:</em></p><ul>")
                    for scenario in nuclei_analysis.get('attack_scenarios', [])[:3]:
                        tools_parts.append(f"<li>{_escape(str(scenario))}</li>")
                    tools_parts.append("</ul>")
            
            # XSS analysis
            xss_analysis = tools_analysis.get('xss_analysis', {})
            if xss_analysis.get('risk_assessment') and xss_analysis.get('risk_assessment') != 'none':
                tools_parts.append("<h5>⚠️ XSS Vulnerabilities Assessment</h5>")
                tools_parts.append(f"<p>Risk Level: <strong>{xss_analysis.get('risk_assessment', 'Unknown').upper()}</strong></p>")
                tools_parts.append(f"<p>Exploitability: {_escape(str(xss_analysis.get('exploitability', 'N/A')))}</p>")
                tools_parts.append(f"<p>Impact: {_escape(str(xss_analysis.get('impact', 'N/A')))}</p>")
            
            # API analysis
            api_analysis = tools_analysis.get('api_analysis', {})
            if api_analysis.get('sensitive_endpoints'):
                tools_parts.append("<h5>🔌 API Exposure Analysis</h5>")
                tools_parts.append(f"<p>Exposure Level: <strong>{api_analysis.get('exposure_level', 'Unknown').upper()}</strong></p>")
                api_html = "<ul>"
                for endpoint in api_analysis.get('sensitive_endpoints', [])[:5]:
                    api_html += f"<li>{_escape(str(endpoint))}</li>"
                api_html += "</ul>"
                tools_parts.append(api_html)
            
            # Overall opinion
            if tools_analysis.get('overall_opinion'):
                tools_parts.append("<h5>🎯 Expert Opinion</h5>")
                tools_parts.append(f"<p><em>{_escape(tools_analysis.get('overall_opinion', ''))}</em></p>")
            
            if tools_parts:
                content_parts.append(f"<h4>🔧 Reconnaissance Tools Analysis</h4>{''.join(tools_parts)}")
        
        if not content_parts:
            return ""
        
        return f"""
        <div class="ai-section">
            <div class="section-header">
                <span>🤖 AI Security Analysis</span>
            </div>
            <div class="ai-content">
                {''.join(content_parts)}
            </div>
        </div>"""
    
    def _build_executive_summary(self, data: Dict, domain: str, risk_score: int, risk_level: str) -> str:
        """Build executive summary section with key findings"""
        total_cves = len(data["cves"])
        critical_count = data['severity_counts']['critical']
        high_count = data['severity_counts']['high']
        
        # Key findings
        findings = []
        if critical_count > 0:
            findings.append(f"🔴 <strong>{critical_count} Critical vulnerabilities</strong> require immediate attention")
        if high_count > 0:
            findings.append(f"🟠 <strong>{high_count} High-severity vulnerabilities</strong> identified")
        if data["attack_surface"]["exposed_hosts"] > 0:
            findings.append(f"🌐 <strong>{data['attack_surface']['exposed_hosts']} hosts</strong> with exposed services")
        if len(data["attack_surface"]["unique_services"]) > 5:
            findings.append(f"⚠️ Large attack surface: <strong>{len(data['attack_surface']['unique_services'])} different services</strong> exposed")
        if total_cves == 0:
            findings.append(f"✅ <strong>No vulnerabilities detected</strong> - system appears secure")
        
        # Recommendations
        recommendations = []
        if critical_count > 0:
            recommendations.append("Immediately patch or mitigate all Critical-severity vulnerabilities")
        if high_count > 5:
            recommendations.append("Prioritize remediation of High-severity issues within 7 days")
        if data["attack_surface"]["total_open_ports"] > 50:
            recommendations.append("Review and close unnecessary open ports to reduce attack surface")
        if len(data["technologies"]) > 0:
            recommendations.append("Update all detected software to latest secure versions")
        if not recommendations:
            recommendations.append("Continue regular security monitoring and vulnerability scanning")
        
        findings_html = "<ul class='exec-findings'>" + "".join(f"<li>{f}</li>" for f in findings[:5]) + "</ul>"
        recommendations_html = "<ul class='exec-recommendations'>" + "".join(f"<li>{r}</li>" for r in recommendations[:5]) + "</ul>"
        
        return f"""
        <section class="executive-summary">
            <h2 class="section-title">📋 Executive Summary</h2>
            <div class="exec-grid">
                <div class="exec-card">
                    <h3>🎯 Assessment Overview</h3>
                    <p>Security assessment of <strong>{_escape(domain)}</strong> identified <strong>{total_cves} unique vulnerabilities</strong> across <strong>{data['total_ips']} IP addresses</strong> and <strong>{data['total_subdomains']} subdomains</strong>.</p>
                    <div class="risk-summary">
                        <span class="risk-badge risk-{risk_level.lower()}">{risk_level} RISK</span>
                        <span class="risk-score-num">Score: {risk_score}/100</span>
                    </div>
                </div>
                <div class="exec-card">
                    <h3>🔍 Key Findings</h3>
                    {findings_html}
                </div>
                <div class="exec-card">
                    <h3>💡 Priority Recommendations</h3>
                    {recommendations_html}
                </div>
            </div>
        </section>"""
    
    def _build_technology_section(self, data: Dict) -> str:
        """Build technology stack and port analysis section"""
        if not data["technologies"] and not data["ports_analysis"]:
            return ""
        
        # Top technologies
        tech_items = ""
        if data["technologies"]:
            sorted_tech = sorted(data["technologies"].items(), key=lambda x: x[1], reverse=True)[:10]
            for tech, count in sorted_tech:
                tech_items += f"<div class='tech-item'><span class='tech-name'>{_escape(tech)}</span><span class='tech-count'>{count} hosts</span></div>"
        else:
            tech_items = "<div class='no-data'>No technology information detected</div>"
        
        # Top ports
        port_items = ""
        if data["ports_analysis"]:
            sorted_ports = sorted(data["ports_analysis"].items(), key=lambda x: x[1], reverse=True)[:15]
            for port, count in sorted_ports:
                # Map common ports to services
                service_names = {
                    80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP",
                    3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 
                    6379: "Redis", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"
                }
                service = service_names.get(port, "Unknown")
                risk_class = "high-risk" if port in [21, 23, 3389, 445] else "medium-risk" if port in [3306, 5432, 27017, 6379] else "low-risk"
                port_items += f"<div class='port-item {risk_class}'><span class='port-number'>{port}</span><span class='port-service'>{service}</span><span class='port-count'>{count} hosts</span></div>"
        else:
            port_items = "<div class='no-data'>No open ports detected</div>"
        
        return f"""
        <section class="tech-section">
            <h2 class="section-title">🔧 Technology Stack & Services</h2>
            <div class="tech-grid">
                <div class="tech-panel">
                    <h3>📦 Detected Technologies</h3>
                    <div class="tech-list">{tech_items}</div>
                </div>
                <div class="tech-panel">
                    <h3>🔌 Open Ports & Services</h3>
                    <div class="port-list">{port_items}</div>
                </div>
            </div>
        </section>"""
    
    def _build_risk_matrix(self, data: Dict) -> str:
        """Build risk matrix visualization with severity distribution chart"""
        # Categorize CVEs by severity and affected hosts
        matrix_data = {
            "critical_widespread": [],  # Critical CVEs affecting 3+ hosts
            "critical_isolated": [],     # Critical CVEs affecting 1-2 hosts
            "high_widespread": [],
            "high_isolated": [],
            "medium_widespread": [],
            "medium_isolated": []
        }
        
        for cve in data["cves"]:
            severity = cve["severity"]
            affected_count = len(cve["affected_ips"])
            category = "widespread" if affected_count >= 3 else "isolated"
            
            key = f"{severity}_{category}"
            if key in matrix_data:
                matrix_data[key].append(cve)
        
        # Build matrix cells
        cells_html = ""
        matrix_structure = [
            ("critical_widespread", "Critical", "Widespread", "top-left"),
            ("high_widespread", "High", "Widespread", "top-right"),
            ("critical_isolated", "Critical", "Isolated", "bottom-left"),
            ("high_isolated", "High", "Isolated", "bottom-right"),
        ]
        
        for key, sev, spread, position in matrix_structure:
            count = len(matrix_data[key])
            cell_class = f"risk-cell {position} sev-{sev.lower()}"
            cells_html += f"""
            <div class='{cell_class}'>
                <div class='cell-label'>{sev} / {spread}</div>
                <div class='cell-count'>{count}</div>
                <div class='cell-sublabel'>vulnerabilities</div>
            </div>"""
        
        # Build severity distribution bar chart
        total = sum(data["severity_counts"].values())
        if total > 0:
            crit_pct = (data["severity_counts"]["critical"] / total) * 100
            high_pct = (data["severity_counts"]["high"] / total) * 100
            med_pct = (data["severity_counts"]["medium"] / total) * 100
            low_pct = (data["severity_counts"]["low"] / total) * 100
        else:
            crit_pct = high_pct = med_pct = low_pct = 0
        
        distribution_chart = f"""
        <div class="severity-distribution">
            <h3 class="dist-title">🎯 Severity Distribution</h3>
            <div class="dist-container">
                <div class="dist-bar-wrapper">
                    <div class="dist-bar" style="--bar-width: {crit_pct}%;">
                        <div class="dist-bar-fill critical" style="width: {crit_pct}%;"></div>
                    </div>
                    <div class="dist-label">
                        <span class="dist-name">Critical</span>
                        <span class="dist-value critical">{data["severity_counts"]["critical"]} ({crit_pct:.1f}%)</span>
                    </div>
                </div>
                <div class="dist-bar-wrapper">
                    <div class="dist-bar" style="--bar-width: {high_pct}%;">
                        <div class="dist-bar-fill high" style="width: {high_pct}%;"></div>
                    </div>
                    <div class="dist-label">
                        <span class="dist-name">High</span>
                        <span class="dist-value high">{data["severity_counts"]["high"]} ({high_pct:.1f}%)</span>
                    </div>
                </div>
                <div class="dist-bar-wrapper">
                    <div class="dist-bar" style="--bar-width: {med_pct}%;">
                        <div class="dist-bar-fill medium" style="width: {med_pct}%;"></div>
                    </div>
                    <div class="dist-label">
                        <span class="dist-name">Medium</span>
                        <span class="dist-value medium">{data["severity_counts"]["medium"]} ({med_pct:.1f}%)</span>
                    </div>
                </div>
                <div class="dist-bar-wrapper">
                    <div class="dist-bar" style="--bar-width: {low_pct}%;">
                        <div class="dist-bar-fill low" style="width: {low_pct}%;"></div>
                    </div>
                    <div class="dist-label">
                        <span class="dist-name">Low</span>
                        <span class="dist-value low">{data["severity_counts"]["low"]} ({low_pct:.1f}%)</span>
                    </div>
                </div>
            </div>
        </div>
        <style>
        .severity-distribution {{
            margin-top: 40px;
            padding: 28px;
            background: rgba(0, 0, 0, 0.2);
            border-radius: 16px;
            border: 1px solid var(--border-color);
        }}
        .dist-title {{
            color: var(--accent-cyan);
            font-size: 1.1rem;
            margin-bottom: 24px;
            font-weight: 700;
        }}
        .dist-container {{
            display: flex;
            flex-direction: column;
            gap: 16px;
        }}
        .dist-bar-wrapper {{
            display: flex;
            flex-direction: column;
            gap: 8px;
        }}
        .dist-bar {{
            height: 32px;
            background: var(--bg-tertiary);
            border-radius: 8px;
            overflow: hidden;
            position: relative;
        }}
        .dist-bar-fill {{
            height: 100%;
            border-radius: 8px;
            transition: width 1s ease-out;
            position: relative;
        }}
        .dist-bar-fill.critical {{
            background: linear-gradient(90deg, var(--critical), #f97316);
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.4);
        }}
        .dist-bar-fill.high {{
            background: linear-gradient(90deg, var(--high), #fb923c);
            box-shadow: 0 0 20px rgba(249, 115, 22, 0.3);
        }}
        .dist-bar-fill.medium {{
            background: linear-gradient(90deg, var(--medium), #fcd34d);
            box-shadow: 0 0 20px rgba(234, 179, 8, 0.3);
        }}
        .dist-bar-fill.low {{
            background: linear-gradient(90deg, var(--low), #4ade80);
            box-shadow: 0 0 20px rgba(34, 197, 94, 0.3);
        }}
        .dist-label {{
            display: flex;
            justify-content: space-between;
            align-items: center;
        }}
        .dist-name {{
            color: var(--text-secondary);
            font-size: 0.9rem;
            font-weight: 500;
        }}
        .dist-value {{
            font-weight: 700;
            font-size: 0.95rem;
        }}
        .dist-value.critical {{ color: var(--critical); }}
        .dist-value.high {{ color: var(--high); }}
        .dist-value.medium {{ color: var(--medium); }}
        .dist-value.low {{ color: var(--low); }}
        </style>
        """
        
        return f"""
        <section class="risk-matrix-section">
            <h2 class="section-title">📊 Risk Matrix</h2>
            <p class="section-desc">Vulnerability distribution by severity and impact scope</p>
            <div class="risk-matrix">
                <div class="matrix-label-y">Impact Severity</div>
                <div class="matrix-label-x">Exposure Scope</div>
                <div class="matrix-grid">{cells_html}</div>
            </div>
            {distribution_chart}
        </section>"""
    
    def _build_remediation_priority(self, data: Dict) -> str:
        """Build remediation priority table"""
        # Categorize CVEs by priority
        immediate = []  # Critical + High with exploits or widespread
        urgent = []     # Critical isolated or High widespread
        important = []  # High isolated or Medium widespread
        monitor = []    # Medium/Low isolated
        
        for cve in data["cves"]:
            severity = cve["severity"]
            affected_count = len(cve["affected_ips"])
            has_exploit = cve.get("exploit_available", False)
            
            if severity == "critical" and (has_exploit or affected_count >= 3):
                immediate.append(cve)
            elif severity == "critical" or (severity == "high" and affected_count >= 3):
                urgent.append(cve)
            elif severity == "high" or (severity == "medium" and affected_count >= 3):
                important.append(cve)
            else:
                monitor.append(cve)
        
        def build_priority_section(cves_list, priority_name, priority_color, time_frame):
            if not cves_list:
                return f"<tr><td colspan='5' class='no-data'>No vulnerabilities in this category</td></tr>"
            
            rows = ""
            for cve in cves_list[:5]:  # Show top 5 per category
                exploit_icon = "⚡" if cve.get("exploit_available") else ""
                rows += f"""
                <tr>
                    <td><span class='priority-badge' style='background:{priority_color};'>{priority_name}</span></td>
                    <td><code>{_escape(cve['id'])}</code> {exploit_icon}</td>
                    <td>{_get_severity_badge(cve['severity'])}</td>
                    <td>{len(cve['affected_ips'])} hosts</td>
                    <td>{time_frame}</td>
                </tr>"""
            
            if len(cves_list) > 5:
                rows += f"<tr><td colspan='5' class='more-items'>+ {len(cves_list) - 5} more items</td></tr>"
            
            return rows
        
        immediate_rows = build_priority_section(immediate, "IMMEDIATE", "#dc3545", "< 24 hours")
        urgent_rows = build_priority_section(urgent, "URGENT", "#fd7e14", "< 7 days")
        important_rows = build_priority_section(important, "IMPORTANT", "#ffc107", "< 30 days")
        monitor_rows = build_priority_section(monitor, "MONITOR", "#28a745", "Next cycle")
        
        return f"""
        <section class="remediation-section">
            <h2 class="section-title">🎯 Remediation Priority Matrix</h2>
            <p class="section-desc">Prioritized action plan based on risk assessment</p>
            <div class="priority-table-wrapper">
                <table class="data-table">
                    <thead>
                        <tr>
                            <th style="width: 12%;">Priority</th>
                            <th style="width: 18%;">CVE ID</th>
                            <th style="width: 12%;">Severity</th>
                            <th style="width: 12%;">Impact</th>
                            <th style="width: 14%;">Timeline</th>
                        </tr>
                    </thead>
                    <tbody>
                        {immediate_rows}
                        {urgent_rows}
                        {important_rows}
                        {monitor_rows}
                    </tbody>
                </table>
            </div>
            <div class="priority-legend">
                <div class="legend-item"><span class="legend-dot" style="background:#dc3545;"></span> <strong>IMMEDIATE:</strong> Critical vulnerabilities requiring immediate action</div>
                <div class="legend-item"><span class="legend-dot" style="background:#fd7e14;"></span> <strong>URGENT:</strong> High-impact vulnerabilities, remediate within a week</div>
                <div class="legend-item"><span class="legend-dot" style="background:#ffc107;"></span> <strong>IMPORTANT:</strong> Medium-high risks, address within 30 days</div>
                <div class="legend-item"><span class="legend-dot" style="background:#28a745;"></span> <strong>MONITOR:</strong> Lower priority, address in next security cycle</div>
            </div>
        </section>"""
    
    def _build_technology_section_pdf(self, data: Dict) -> str:
        """Build technology and port analysis for PDF"""  
        if not data["technologies"] and not data["ports_analysis"]:
            return ""
        
        tech_rows = ""
        if data["technologies"]:
            sorted_tech = sorted(data["technologies"].items(), key=lambda x: x[1], reverse=True)[:15]
            for tech, count in sorted_tech:
                tech_rows += f"<tr><td>{_escape(tech)}</td><td style='text-align:center;'>{count}</td></tr>"
        else:
            tech_rows = "<tr><td colspan='2' style='text-align:center; color:#999;'>No technology data</td></tr>"
        
        port_rows = ""
        if data["ports_analysis"]:
            sorted_ports = sorted(data["ports_analysis"].items(), key=lambda x: x[1], reverse=True)[:15]
            for port, count in sorted_ports:
                service_names = {80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP", 25: "SMTP", 3306: "MySQL", 5432: "PostgreSQL", 27017: "MongoDB", 6379: "Redis", 3389: "RDP", 8080: "HTTP-Alt", 8443: "HTTPS-Alt"}
                service = service_names.get(port, "Unknown")
                risk_color = "#dc3545" if port in [21, 23, 3389, 445] else "#fd7e14" if port in [3306, 5432, 27017, 6379] else "#28a745"
                port_rows += f"<tr><td style='border-left:3px solid {risk_color};'><strong>{port}</strong></td><td>{service}</td><td style='text-align:center;'>{count}</td></tr>"
        else:
            port_rows = "<tr><td colspan='3' style='text-align:center; color:#999;'>No open ports</td></tr>"
        
        return f"""
        <div class="section">
            <div class="section-header">🔧 Technology Stack & Services</div>
            <table style="width:100%; margin-bottom:15px;">
                <tr>
                    <td style="width:48%; vertical-align:top; padding-right:10px;">
                        <table style="width:100%;">
                            <thead><tr><th>Technology/Tag</th><th>Hosts</th></tr></thead>
                            <tbody>{tech_rows}</tbody>
                        </table>
                    </td>
                    <td style="width:4%;"></td>
                    <td style="width:48%; vertical-align:top; padding-left:10px;">
                        <table style="width:100%;">
                            <thead><tr><th>Port</th><th>Service</th><th>Hosts</th></tr></thead>
                            <tbody>{port_rows}</tbody>
                        </table>
                    </td>
                </tr>
            </table>
        </div>
        """
    
    def _analyze_scan_results(self, scan_results: Dict) -> Dict:
        """Parse and analyze scan results for report generation"""
        
        data = {
            "total_ips": 0,
            "total_subdomains": 0,
            "total_cves": 0,
            "severity_counts": {"critical": 0, "high": 0, "medium": 0, "low": 0},
            "cves": [],
            "hosts": [],
            "technologies": {},  # NEW: Track detected technologies
            "ports_analysis": {},  # NEW: Port frequency and services
            "attack_surface": {  # NEW: Attack surface metrics
                "total_open_ports": 0,
                "unique_services": set(),
                "exposed_hosts": 0,
                "dns_records": 0
            }
        }
        
        # Try to load CVE cache for CVSS score lookups
        cve_cache = {}
        try:
            cache_path = Path(__file__).parent.parent / "results" / "cve_cache.json"
            if cache_path.exists():
                import json
                with open(cache_path, 'r', encoding='utf-8') as f:
                    cve_cache = json.load(f)
                logger.debug(f"Loaded {len(cve_cache)} CVEs from cache for CVSS lookup")
        except Exception as e:
            logger.debug(f"Could not load CVE cache: {e}")
        
        # Extract results - handle nested format
        results = scan_results.get("results", scan_results)
        if isinstance(results, dict) and "results" in results:
            results = results["results"]
        
        # Metadata keys to exclude (same as dashboard for consistency)
        metadata_keys = {"timestamp", "domain", "result_file", "findings_summary", "_metadata"}
        
        seen_cves = {}  # CVE ID -> {cve_data, affected_ips}
        all_subdomains = set()  # Track unique subdomains across all IPs
        
        for ip, ip_data in results.items():
            if not isinstance(ip_data, dict):
                continue
            # Skip metadata keys
            if ip in metadata_keys:
                continue
            
            data["total_ips"] += 1
            
            # Get subdomains
            subs = ip_data.get("subdomains", []) or ip_data.get("hosts", [])
            if isinstance(subs, list):
                # Add to unique subdomain set instead of counting per-IP
                all_subdomains.update(s for s in subs if s)
            
            # Get ports from internetdb
            ports = []
            technologies = []
            idb = ip_data.get("internetdb", {})
            if isinstance(idb, dict):
                idb_data = idb.get("data", idb)
                ports = idb_data.get("ports", [])
                # Track technologies/tags
                tags = idb_data.get("tags", [])
                if tags:
                    technologies.extend(tags)
                    for tag in tags:
                        data["technologies"][tag] = data["technologies"].get(tag, 0) + 1
                # Track service names for attack surface
                for port in ports:
                    data["ports_analysis"][port] = data["ports_analysis"].get(port, 0) + 1
                    data["attack_surface"]["total_open_ports"] += 1
                    # Common service mapping
                    service_map = {
                        80: "HTTP", 443: "HTTPS", 22: "SSH", 21: "FTP",
                        25: "SMTP", 3306: "MySQL", 5432: "PostgreSQL",
                        27017: "MongoDB", 6379: "Redis", 3389: "RDP"
                    }
                    if port in service_map:
                        data["attack_surface"]["unique_services"].add(service_map[port])
            
            if ports:
                data["attack_surface"]["exposed_hosts"] += 1
            if subs:
                data["attack_surface"]["dns_records"] += len(subs)
            
            # Get CVEs
            cves = ip_data.get("cve_details", []) or ip_data.get("cves", [])
            host_cve_ids = []
            
            # Also get vulns from internetdb if cve_details is missing CVSS
            idb_vulns = {}
            idb = ip_data.get("internetdb", {})
            if isinstance(idb, dict):
                idb_data = idb.get("data", idb)
                for v in idb_data.get("vulns", []):
                    if isinstance(v, str):
                        idb_vulns[v] = {"id": v, "cvss": None, "summary": "Detected by InternetDB"}
                    elif isinstance(v, dict):
                        vid = v.get("id") or v.get("cve_id", "")
                        idb_vulns[vid] = v
            
            # If no cve_details, use internetdb vulns
            if not cves and idb_vulns:
                cves = list(idb_vulns.values())
            
            if isinstance(cves, list):
                for cve in cves:
                    cve_id = cve.get("id") or cve.get("cve_id") or "Unknown"
                    
                    # Get CVSS score - try multiple field names
                    score = (
                        cve.get("cvss") or 
                        cve.get("cvss3") or 
                        cve.get("cvss_score") or
                        cve.get("cvss_v3") or
                        cve.get("cvss_v2") or
                        cve.get("score") or 
                        cve.get("base_score") or
                        # Check if cached in idb_vulns
                        idb_vulns.get(cve_id, {}).get("cvss") or
                        # Check CVE cache file as last resort
                        cve_cache.get(cve_id, {}).get("cvss") or
                        cve_cache.get(cve_id, {}).get("cvss3") or
                        0
                    )
                    try:
                        score = float(score) if score else 0
                    except:
                        score = 0
                    
                    # Determine severity based on CVSS
                    if score >= 9.0:
                        severity = "critical"
                    elif score >= 7.0:
                        severity = "high"
                    elif score >= 4.0:
                        severity = "medium"
                    else:
                        severity = "low"
                    
                    # Count total CVE occurrences (for reference)
                    data["total_cves"] += 1
                    host_cve_ids.append(cve_id)
                    
                    # Track unique CVEs with affected IPs
                    # Only count severity for NEW unique CVEs
                    if cve_id not in seen_cves:
                        # Extract additional metadata from cache
                        published_date = ""
                        cvss_vector = ""
                        exploit_available = False
                        
                        if cve_id in cve_cache:
                            cached = cve_cache[cve_id]
                            published_date = cached.get("published", cached.get("publishedDate", ""))
                            cvss_vector = cached.get("cvss_vector", cached.get("vectorString", ""))
                            # Check for exploit indicators
                            exploit_available = bool(
                                cached.get("exploit_available") or 
                                cached.get("exploitabilityScore", 0) > 8.5 or
                                cached.get("references", [])
                            )
                        
                        seen_cves[cve_id] = {
                            "id": cve_id,
                            "cvss": score,
                            "severity": severity,
                            "summary": cve.get("summary") or cve.get("description") or "No description available",
                            "affected_ips": [],
                            "published": published_date,
                            "cvss_vector": cvss_vector,
                            "exploit_available": exploit_available
                        }
                        # Count severity only for unique CVEs
                        data["severity_counts"][severity] += 1
                    seen_cves[cve_id]["affected_ips"].append(ip)
            
            # Add host entry
            data["hosts"].append({
                "ip": ip,
                "hosts": subs if isinstance(subs, list) else [],
                "ports": ports if isinstance(ports, list) else [],
                "cves": host_cve_ids,
                "technologies": technologies  # NEW: Track tech per host
            })
        
        # Set total unique subdomains (same counting method as dashboard)
        data["total_subdomains"] = len(all_subdomains)
        
        # Convert CVEs to sorted list
        data["cves"] = sorted(seen_cves.values(), key=lambda x: x["cvss"], reverse=True)
        
        # Convert unique_services set to list for JSON serialization
        data["attack_surface"]["unique_services"] = list(data["attack_surface"]["unique_services"])
        
        return data
    
    def _build_html_report(
        self, 
        data: Dict, 
        scan_id: str, 
        domain: str, 
        ai_analysis: Optional[str],
        for_pdf: bool = False
    ) -> str:
        """Build the complete HTML report with professional dark cybersecurity theme."""
        
        total_cves = len(data["cves"])
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        # Calculate risk score (0-100)
        risk_score = min(100, (
            data['severity_counts']['critical'] * 25 +
            data['severity_counts']['high'] * 15 +
            data['severity_counts']['medium'] * 5 +
            data['severity_counts']['low'] * 1
        ))
        
        risk_level = "CRITICAL" if risk_score >= 75 else "HIGH" if risk_score >= 50 else "MEDIUM" if risk_score >= 25 else "LOW"
        risk_color = "#ff0844" if risk_score >= 75 else "#f5576c" if risk_score >= 50 else "#fa8231" if risk_score >= 25 else "#26de81"
        
        # Build CVE table rows
        cve_rows = ""
        for i, cve in enumerate(data["cves"]):
            # Escape IPs first, then add HTML span
            affected_ips = _escape(", ".join(cve["affected_ips"][:3]))
            if len(cve["affected_ips"]) > 3:
                affected_ips += f" <span class='more'>+{len(cve['affected_ips']) - 3}</span>"
            
            # Build tooltip with additional info
            tooltip_parts = []
            if cve.get("published"):
                tooltip_parts.append(f"Published: {cve['published'][:10]}")
            if cve.get("cvss_vector"):
                tooltip_parts.append(f"CVSS Vector: {cve['cvss_vector']}")
            if cve.get("exploit_available"):
                tooltip_parts.append("⚠️ Exploit may be available")
            tooltip = " • ".join(tooltip_parts) if tooltip_parts else "No additional metadata"
            
            # Add exploit indicator
            exploit_badge = " <span class='exploit-badge' title='Exploit may be publicly available'>⚡ EXPLOIT</span>" if cve.get("exploit_available") else ""
            
            row_class = "row-alt" if i % 2 == 0 else ""
            cve_rows += f"""
            <tr class='{row_class}' title='{_escape(tooltip)}'>
                <td class='cve-id'><code>{_escape(cve['id'])}</code>{exploit_badge}</td>
                <td class='cvss-cell'>{_get_cvss_gauge(cve['cvss'])}</td>
                <td class='count-cell'>{len(cve['affected_ips'])}</td>
                <td>{_get_severity_badge(cve['severity'])}</td>
                <td class='summary-cell'>{_escape(cve['summary'][:200])}{'...' if len(cve['summary']) > 200 else ''}</td>
                <td class='ip-cell'><code>{affected_ips}</code></td>
            </tr>"""
        
        if not cve_rows:
            cve_rows = "<tr><td colspan='6' class='no-data'>✓ No CVEs found - Attack surface appears clean</td></tr>"
        
        # Build host table rows
        host_rows = ""
        for i, host in enumerate(data["hosts"]):
            # Escape base content first, then add HTML spans
            hostnames = _escape(", ".join(host["hosts"][:2]) or "—")
            if len(host["hosts"]) > 2:
                hostnames += f" <span class='more'>+{len(host['hosts']) - 2}</span>"
            
            # Show all ports (no limit)
            ports = _escape(", ".join(str(p) for p in host["ports"]) or "—")
            
            cve_count = len(host["cves"])
            cve_badge = f"<span class='cve-count {'has-cves' if cve_count > 0 else 'no-cves'}'>{cve_count}</span>"
            
            row_class = "row-alt" if i % 2 == 0 else ""
            host_rows += f"""
            <tr class='{row_class}'>
                <td class='hostname-cell'>{hostnames}</td>
                <td class='ip-cell'><code>{_escape(host['ip'])}</code></td>
                <td class='ports-cell'><code>{ports}</code></td>
                <td class='cve-count-cell'>{cve_badge}</td>
            </tr>"""
        
        if not host_rows:
            host_rows = "<tr><td colspan='4' class='no-data'>No host data available</td></tr>"
        
        # AI Analysis section (pass scan data for fallback when AI data is incomplete)
        ai_section = self._build_ai_section(ai_analysis, data)
        
        # Professional Dark Theme HTML Template
        html_template = f"""<!DOCTYPE html>
<html lang='en'>
<head>
    <meta charset='UTF-8'>
    <meta name='viewport' content='width=device-width, initial-scale=1.0'>
    <link rel='icon' type='image/png' href='data:image/png;base64,{self._get_favicon_base64()}'>
    <title>TwinSanity Security Report - {_escape(domain)}</title>
    <style>
        /* ===== CSS VARIABLES - Modern Cybersecurity Theme ===== */
        :root {{
            --bg-primary: #0a0e14;
            --bg-secondary: #121820;
            --bg-tertiary: #1a2029;
            --bg-card: #161d26;
            --bg-glass: rgba(18, 24, 32, 0.85);
            --text-primary: #e6edf3;
            --text-secondary: #9ba8b5;
            --text-muted: #6a7788;
            --accent-cyan: #00d4ff;
            --accent-purple: #a855f7;
            --accent-green: #22c55e;
            --accent-orange: #f97316;
            --accent-pink: #ec4899;
            --border-color: #2d3640;
            --border-highlight: #00d4ff;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22c55e;
            --info: #3b82f6;
            --glow-cyan: rgba(0, 212, 255, 0.2);
            --glow-purple: rgba(168, 85, 247, 0.2);
            --glow-green: rgba(34, 197, 94, 0.15);
            --gradient-primary: linear-gradient(135deg, #00d4ff 0%, #a855f7 100%);
            --gradient-danger: linear-gradient(135deg, #ef4444 0%, #f97316 100%);
            --glass-border: rgba(255, 255, 255, 0.08);
            --shadow-lg: 0 25px 50px -12px rgba(0, 0, 0, 0.5);
            --shadow-glow: 0 0 40px rgba(0, 212, 255, 0.15);
        }}
        
        /* ===== RESET & BASE ===== */
        *, *::before, *::after {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        
        html {{
            scroll-behavior: smooth;
        }}
        
        body {{
            font-family: 'Inter', 'Segoe UI', -apple-system, BlinkMacSystemFont, 'Roboto', sans-serif;
            background: var(--bg-primary);
            color: var(--text-primary);
            line-height: 1.7;
            min-height: 100vh;
            font-size: 15px;
            -webkit-font-smoothing: antialiased;
            -moz-osx-font-smoothing: grayscale;
        }}
        
        /* ===== ANIMATED BACKGROUND - Cyber Grid ===== */
        .bg-grid {{
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: 
                radial-gradient(ellipse at top, rgba(0, 212, 255, 0.08) 0%, transparent 60%),
                radial-gradient(ellipse at bottom right, rgba(168, 85, 247, 0.06) 0%, transparent 50%),
                linear-gradient(rgba(0, 212, 255, 0.02) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 212, 255, 0.02) 1px, transparent 1px);
            background-size: 100% 100%, 100% 100%, 60px 60px, 60px 60px;
            pointer-events: none;
            z-index: 0;
            animation: gridPulse 8s ease-in-out infinite;
        }}
        
        @keyframes gridPulse {{
            0%, 100% {{ opacity: 0.6; }}
            50% {{ opacity: 1; }}
        }}
        
        /* Floating particles effect */
        .bg-grid::before {{
            content: '';
            position: absolute;
            top: 20%;
            left: 10%;
            width: 300px;
            height: 300px;
            background: radial-gradient(circle, var(--glow-cyan) 0%, transparent 70%);
            border-radius: 50%;
            filter: blur(60px);
            animation: floatParticle 15s ease-in-out infinite;
        }}
        
        .bg-grid::after {{
            content: '';
            position: absolute;
            bottom: 20%;
            right: 10%;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, var(--glow-purple) 0%, transparent 70%);
            border-radius: 50%;
            filter: blur(80px);
            animation: floatParticle 20s ease-in-out infinite reverse;
        }}
        
        @keyframes floatParticle {{
            0%, 100% {{ transform: translate(0, 0) scale(1); }}
            33% {{ transform: translate(30px, -30px) scale(1.1); }}
            66% {{ transform: translate(-20px, 20px) scale(0.9); }}
        }}
        
        /* ===== CONTAINER ===== */
        .container {{
            position: relative;
            max-width: 1440px;
            margin: 0 auto;
            padding: 50px 40px;
            z-index: 1;
        }}
        
        /* ===== HEADER - Glassmorphism Design ===== */
        .report-header {{
            background: var(--bg-glass);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--glass-border);
            border-radius: 24px;
            padding: 48px;
            margin-bottom: 36px;
            position: relative;
            overflow: hidden;
            box-shadow: var(--shadow-lg), var(--shadow-glow);
        }}
        
        .report-header::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--gradient-primary);
            border-radius: 24px 24px 0 0;
        }}
        
        /* Subtle corner accent */
        .report-header::after {{
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 200px;
            height: 200px;
            background: radial-gradient(circle at top right, var(--glow-cyan) 0%, transparent 60%);
            pointer-events: none;
        }}
        
        .header-content {{
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            flex-wrap: wrap;
            gap: 36px;
            position: relative;
            z-index: 1;
        }}
        
        .header-left {{
            flex: 1;
            min-width: 320px;
        }}
        
        .logo-title {{
            display: flex;
            align-items: center;
            gap: 20px;
            margin-bottom: 28px;
        }}
        
        .logo-icon {{
            width: 64px;
            height: 64px;
            background: var(--gradient-primary);
            border-radius: 16px;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
            box-shadow: 0 8px 32px var(--glow-cyan);
            position: relative;
        }}
        
        .logo-icon::after {{
            content: '';
            position: absolute;
            inset: -2px;
            border-radius: 18px;
            background: var(--gradient-primary);
            z-index: -1;
            opacity: 0.4;
            filter: blur(10px);
        }}
        
        .report-title {{
            font-size: 2.25rem;
            font-weight: 800;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            letter-spacing: -0.02em;
        }}
        
        .report-subtitle {{
            color: var(--text-secondary);
            font-size: 1rem;
            margin-top: 6px;
            font-weight: 500;
        }}
        
        .meta-info {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-top: 28px;
        }}
        
        .meta-item {{
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 14px;
            padding: 16px 20px;
            transition: all 0.3s ease;
        }}
        
        .meta-item:hover {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 20px var(--glow-cyan);
        }}
        
        .meta-label {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            margin-bottom: 6px;
            font-weight: 600;
        }}
        
        .meta-value {{
            font-size: 1.05rem;
            color: var(--text-primary);
            font-weight: 600;
        }}
        
        .meta-value code {{
            background: var(--bg-tertiary);
            padding: 4px 10px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
            font-size: 0.9em;
            color: var(--accent-cyan);
            border: 1px solid var(--border-color);
        }}
        
        /* ===== RISK SCORE WIDGET - Enhanced Design ===== */
        .header-right {{
            display: flex;
            flex-direction: column;
            align-items: center;
            min-width: 220px;
        }}
        
        .risk-gauge {{
            position: relative;
            width: 180px;
            height: 180px;
        }}
        
        .risk-circle {{
            transform: rotate(-90deg);
            width: 180px;
            height: 180px;
            filter: drop-shadow(0 0 15px {risk_color}60);
        }}
        
        .risk-circle-bg {{
            fill: none;
            stroke: var(--bg-tertiary);
            stroke-width: 10;
        }}
        
        .risk-circle-fill {{
            fill: none;
            stroke: {risk_color};
            stroke-width: 10;
            stroke-linecap: round;
            stroke-dasharray: {risk_score * 3.14}, 314;
            filter: drop-shadow(0 0 12px {risk_color}80);
            transition: stroke-dasharray 1s ease-out;
        }}
        
        .risk-score-text {{
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            text-align: center;
        }}
        
        .risk-number {{
            font-size: 3rem;
            font-weight: 800;
            color: {risk_color};
            text-shadow: 0 0 30px {risk_color}60;
            letter-spacing: -0.02em;
        }}
        
        .risk-label {{
            font-size: 0.7rem;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 2px;
            font-weight: 600;
        }}
        
        .risk-level {{
            margin-top: 16px;
            padding: 8px 24px;
            background: {risk_color}15;
            color: {risk_color};
            border: 2px solid {risk_color}50;
            border-radius: 30px;
            font-weight: 700;
            font-size: 0.85rem;
            letter-spacing: 2px;
            box-shadow: 0 4px 20px {risk_color}30;
        }}
        
        /* ===== STATS CARDS - Modern Glass Design ===== */
        .stats-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(160px, 1fr));
            gap: 20px;
            margin-bottom: 36px;
        }}
        
        .stat-card {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 16px;
            padding: 28px 20px;
            text-align: center;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}
        
        .stat-card::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 4px;
            background: var(--accent-cyan);
            transform: scaleX(0);
            transform-origin: left;
            transition: transform 0.4s ease;
        }}
        
        .stat-card:hover {{
            transform: translateY(-8px);
            border-color: var(--accent-cyan);
            box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4), 0 0 30px var(--glow-cyan);
        }}
        
        .stat-card:hover::before {{
            transform: scaleX(1);
        }}
        
        .stat-card.critical::before {{ background: var(--critical); }}
        .stat-card.high::before {{ background: var(--high); }}
        .stat-card.medium::before {{ background: var(--medium); }}
        .stat-card.low::before {{ background: var(--low); }}
        
        .stat-card.critical:hover {{ border-color: var(--critical); box-shadow: 0 20px 40px rgba(239, 68, 68, 0.2); }}
        .stat-card.high:hover {{ border-color: var(--high); box-shadow: 0 20px 40px rgba(249, 115, 22, 0.2); }}
        .stat-card.medium:hover {{ border-color: var(--medium); box-shadow: 0 20px 40px rgba(234, 179, 8, 0.2); }}
        .stat-card.low:hover {{ border-color: var(--low); box-shadow: 0 20px 40px rgba(34, 197, 94, 0.2); }}
        
        .stat-number {{
            font-size: 2.75rem;
            font-weight: 800;
            color: var(--text-primary);
            line-height: 1;
            margin-bottom: 10px;
            letter-spacing: -0.02em;
        }}
        
        .stat-card.critical .stat-number {{ color: var(--critical); text-shadow: 0 0 30px var(--critical); }}
        .stat-card.high .stat-number {{ color: var(--high); text-shadow: 0 0 30px var(--high); }}
        .stat-card.medium .stat-number {{ color: var(--medium); text-shadow: 0 0 30px var(--medium); }}
        .stat-card.low .stat-number {{ color: var(--low); text-shadow: 0 0 30px var(--low); }}
        
        .stat-label {{
            font-size: 0.75rem;
            color: var(--text-secondary);
            text-transform: uppercase;
            letter-spacing: 1.5px;
            font-weight: 600;
        }}
        
        .stat-icon {{
            font-size: 1.75rem;
            margin-bottom: 12px;
            opacity: 0.9;
            filter: drop-shadow(0 4px 8px rgba(0,0,0,0.3));
        }}
        
        /* ===== SECTIONS - Glass Cards ===== */
        .section {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            margin-bottom: 28px;
            overflow: hidden;
            box-shadow: var(--shadow-lg);
            transition: all 0.3s ease;
        }}
        
        .section:hover {{
            border-color: var(--border-color);
            box-shadow: var(--shadow-lg), 0 0 40px rgba(0, 212, 255, 0.08);
        }}
        
        .section-header {{
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, rgba(26, 32, 41, 0.9) 100%);
            padding: 22px 28px;
            border-bottom: 1px solid var(--border-color);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }}
        
        .section-title {{
            font-size: 1.25rem;
            font-weight: 700;
            color: var(--text-primary);
            display: flex;
            align-items: center;
            gap: 14px;
            letter-spacing: -0.01em;
        }}
        
        .section-icon {{
            font-size: 1.5rem;
            filter: drop-shadow(0 2px 4px rgba(0,0,0,0.3));
        }}
        
        .section-badge {{
            background: linear-gradient(135deg, var(--accent-cyan)20, var(--accent-purple)20);
            color: var(--accent-cyan);
            padding: 6px 16px;
            border-radius: 30px;
            font-size: 0.8rem;
            font-weight: 700;
            border: 1px solid var(--accent-cyan)30;
            letter-spacing: 0.5px;
        }}
        
        .section-content {{
            padding: 0;
        }}
        
        /* ===== TABLE CONTROLS - Enhanced Search ===== */
        .table-controls {{
            display: flex;
            flex-wrap: wrap;
            gap: 18px;
            align-items: center;
            padding: 20px 24px;
            background: rgba(0, 0, 0, 0.2);
            border-bottom: 1px solid var(--border-color);
        }}
        
        .search-box {{
            flex: 1;
            min-width: 280px;
            position: relative;
        }}
        
        .search-box::before {{
            content: '🔍';
            position: absolute;
            left: 16px;
            top: 50%;
            transform: translateY(-50%);
            font-size: 0.9rem;
            opacity: 0.5;
            pointer-events: none;
        }}
        
        .search-box input {{
            width: 100%;
            padding: 14px 20px 14px 44px;
            background: var(--bg-primary);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            color: var(--text-primary);
            font-size: 0.95rem;
            outline: none;
            transition: all 0.3s ease;
            font-family: inherit;
        }}
        
        .search-box input:focus {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 4px var(--glow-cyan), 0 0 20px var(--glow-cyan);
        }}
        
        .search-box input::placeholder {{
            color: var(--text-muted);
        }}
        
        .filter-box select {{
            padding: 14px 20px;
            background: var(--bg-primary);
            border: 2px solid var(--border-color);
            border-radius: 12px;
            color: var(--text-primary);
            font-size: 0.95rem;
            cursor: pointer;
            outline: none;
            min-width: 170px;
            font-family: inherit;
            transition: all 0.3s ease;
            appearance: none;
            background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='12' height='12' viewBox='0 0 12 12'%3E%3Cpath fill='%239ba8b5' d='M6 8L1 3h10z'/%3E%3C/svg%3E");
            background-repeat: no-repeat;
            background-position: right 14px center;
            padding-right: 40px;
        }}
        
        .filter-box select:focus {{
            border-color: var(--accent-cyan);
            box-shadow: 0 0 0 4px var(--glow-cyan);
        }}
        
        .filter-box select:hover {{
            border-color: var(--accent-cyan);
        }}
        
        .results-count {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin-left: auto;
            font-weight: 500;
            padding: 8px 16px;
            background: var(--bg-tertiary);
            border-radius: 8px;
        }}
        
        /* ===== TABLES - Modern Data Grid ===== */
        .data-table {{
            width: 100%;
            border-collapse: collapse;
        }}
        
        .data-table thead {{
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, rgba(26, 32, 41, 0.95) 100%);
            position: sticky;
            top: 0;
            z-index: 10;
        }}
        
        .data-table th {{
            padding: 16px 18px;
            text-align: left;
            font-size: 0.7rem;
            font-weight: 700;
            color: var(--text-muted);
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 2px solid var(--border-color);
        }}
        
        .data-table th.sortable {{
            cursor: pointer;
            user-select: none;
            position: relative;
            transition: all 0.2s ease;
        }}
        
        .data-table th.sortable:hover {{
            color: var(--accent-cyan);
            background: rgba(0, 212, 255, 0.05);
        }}
        
        .data-table th.sortable::after {{
            content: ' ↕';
            opacity: 0.3;
            font-size: 0.7rem;
            margin-left: 6px;
            transition: opacity 0.2s ease;
        }}
        
        .data-table th.sortable:hover::after {{
            opacity: 0.7;
        }}
        
        .data-table th.sort-asc::after {{
            content: ' ▲';
            opacity: 1;
            color: var(--accent-cyan);
        }}
        
        .data-table th.sort-desc::after {{
            content: ' ▼';
            opacity: 1;
            color: var(--accent-cyan);
        }}
        
        .data-table td {{
            padding: 16px 18px;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
            color: var(--text-primary);
            vertical-align: middle;
            transition: background 0.2s ease;
        }}
        
        .data-table tr:last-child td {{
            border-bottom: none;
        }}
        
        .data-table tr.row-alt {{
            background: rgba(0, 0, 0, 0.15);
        }}
        
        .data-table tr:hover td {{
            background: rgba(0, 212, 255, 0.05);
        }}
        
        /* Table cell styles - Enhanced */
        .cve-id code {{
            color: var(--accent-cyan);
            font-weight: 700;
            background: rgba(0, 212, 255, 0.1);
            padding: 6px 12px;
            border-radius: 8px;
            font-family: 'JetBrains Mono', 'Fira Code', monospace;
            font-size: 0.85rem;
            border: 1px solid rgba(0, 212, 255, 0.2);
            transition: all 0.2s ease;
        }}
        
        .cve-id code:hover {{
            background: rgba(0, 212, 255, 0.15);
            border-color: var(--accent-cyan);
        }}
        
        .cvss-cell {{
            min-width: 110px;
        }}
        
        .cvss-gauge {{
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .cvss-value {{
            font-weight: 800;
            font-size: 1.15rem;
            min-width: 38px;
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .cvss-bar-bg {{
            flex: 1;
            height: 8px;
            background: var(--bg-tertiary);
            border-radius: 4px;
            overflow: hidden;
            min-width: 60px;
            box-shadow: inset 0 2px 4px rgba(0,0,0,0.3);
        }}
        
        .cvss-bar-fill {{
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s ease;
            box-shadow: 0 0 10px currentColor;
        }}
        
        .cvss-na {{
            color: var(--text-muted);
            font-style: italic;
            font-size: 0.85rem;
        }}
        
        .count-cell {{
            text-align: center;
            font-weight: 700;
            font-size: 1rem;
        }}
        
        .summary-cell {{
            max-width: 320px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            line-height: 1.6;
        }}
        
        .ip-cell code {{
            font-size: 0.8rem;
            color: var(--accent-purple);
            background: rgba(168, 85, 247, 0.1);
            padding: 4px 8px;
            border-radius: 6px;
            font-family: 'JetBrains Mono', monospace;
            border: 1px solid rgba(168, 85, 247, 0.2);
        }}
        
        .ports-cell code {{
            color: var(--accent-green);
            background: rgba(34, 197, 94, 0.1);
            padding: 2px 6px;
            border-radius: 4px;
            font-family: 'JetBrains Mono', monospace;
        }}
        
        .more {{
            color: var(--text-muted);
            font-size: 0.75rem;
            font-style: italic;
            margin-left: 4px;
        }}
        
        .no-data {{
            text-align: center;
            color: var(--accent-green);
            padding: 50px 24px !important;
            font-size: 1.05rem;
            background: rgba(34, 197, 94, 0.05);
        }}
        
        .cve-count {{
            display: inline-flex;
            align-items: center;
            justify-content: center;
            min-width: 42px;
            padding: 6px 14px;
            border-radius: 24px;
            font-weight: 700;
            font-size: 0.9rem;
        }}
        
        .cve-count.has-cves {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.15), rgba(249, 115, 22, 0.15));
            color: var(--critical);
            border: 1px solid rgba(239, 68, 68, 0.3);
            box-shadow: 0 0 15px rgba(239, 68, 68, 0.2);
        }}
        
        .cve-count.no-cves {{
            background: rgba(34, 197, 94, 0.1);
            color: var(--low);
            border: 1px solid rgba(34, 197, 94, 0.3);
        }}
        
        /* ===== AI ANALYSIS SECTION - Futuristic Design ===== */
        .ai-section {{
            background: linear-gradient(135deg, rgba(18, 24, 32, 0.9) 0%, rgba(30, 20, 50, 0.9) 100%);
            backdrop-filter: blur(15px);
            -webkit-backdrop-filter: blur(15px);
            border: 1px solid rgba(168, 85, 247, 0.3);
            border-radius: 20px;
            margin-bottom: 28px;
            overflow: hidden;
            position: relative;
            box-shadow: 0 20px 50px rgba(168, 85, 247, 0.1), inset 0 1px 0 rgba(255,255,255,0.05);
        }}
        
        .ai-section::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            height: 100%;
            background: 
                radial-gradient(ellipse at top left, rgba(168, 85, 247, 0.1) 0%, transparent 50%),
                radial-gradient(ellipse at bottom right, rgba(0, 212, 255, 0.08) 0%, transparent 50%);
            pointer-events: none;
        }}
        
        .ai-section .section-header {{
            background: linear-gradient(135deg, rgba(168, 85, 247, 0.15) 0%, rgba(0, 212, 255, 0.1) 100%);
            border-bottom: 1px solid rgba(168, 85, 247, 0.2);
            position: relative;
        }}
        
        .ai-section .section-title {{
            color: var(--accent-purple);
        }}
        
        .ai-section .section-badge {{
            background: linear-gradient(135deg, var(--accent-purple)30, var(--accent-cyan)30);
            border: 1px solid var(--accent-purple)50;
        }}
        
        .ai-content {{
            padding: 28px;
            position: relative;
            z-index: 1;
        }}
        
        .ai-content h3 {{
            color: var(--accent-cyan);
            font-size: 1.15rem;
            margin: 24px 0 14px 0;
            padding-bottom: 10px;
            border-bottom: 1px solid var(--border-color);
            font-weight: 700;
            display: flex;
            align-items: center;
            gap: 10px;
        }}
        
        .ai-content h3:first-child {{
            margin-top: 0;
        }}
        
        .ai-content p {{
            color: var(--text-secondary);
            margin-bottom: 14px;
            line-height: 1.8;
            font-size: 0.95rem;
        }}
        
        .ai-content ul {{
            margin-left: 22px;
            color: var(--text-secondary);
        }}
        
        .ai-content li {{
            margin-bottom: 10px;
            line-height: 1.7;
        }}
        
        .ai-content li strong {{
            color: var(--text-primary);
        }}
        
        .ai-content table {{
            width: 100%;
            margin: 18px 0;
            border-collapse: collapse;
            border-radius: 12px;
            overflow: hidden;
        }}
        
        .ai-content table th {{
            background: rgba(168, 85, 247, 0.15);
            color: var(--accent-purple);
            padding: 14px;
            text-align: left;
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            border-bottom: 1px solid var(--border-color);
        }}
        
        .ai-content table td {{
            padding: 14px;
            border-bottom: 1px solid var(--border-color);
            color: var(--text-primary);
            font-size: 0.9rem;
        }}
        
        .ai-content table tr:hover td {{
            background: rgba(168, 85, 247, 0.05);
        }}
        
        /* ===== CVE EXPLOIT BADGE - Animated Warning ===== */
        .exploit-badge {{
            display: inline-flex;
            align-items: center;
            gap: 4px;
            margin-left: 10px;
            padding: 4px 10px;
            background: linear-gradient(135deg, #ff6b35, #f7931e);
            color: white;
            font-size: 0.6rem;
            font-weight: 800;
            border-radius: 6px;
            letter-spacing: 0.8px;
            box-shadow: 0 4px 15px rgba(255, 107, 53, 0.4);
            animation: pulseExploit 2s ease-in-out infinite;
            text-transform: uppercase;
        }}
        
        @keyframes pulseExploit {{
            0%, 100% {{ 
                opacity: 1; 
                transform: scale(1);
                box-shadow: 0 4px 15px rgba(255, 107, 53, 0.4);
            }}
            50% {{ 
                opacity: 0.9; 
                transform: scale(1.05);
                box-shadow: 0 4px 25px rgba(255, 107, 53, 0.6);
            }}
        }}
        
        /* ===== EXECUTIVE SUMMARY - Premium Card ===== */
        .executive-summary {{
            background: linear-gradient(135deg, var(--bg-glass) 0%, rgba(0, 30, 50, 0.7) 100%);
            backdrop-filter: blur(20px);
            -webkit-backdrop-filter: blur(20px);
            border: 1px solid var(--border-highlight);
            border-radius: 24px;
            padding: 40px;
            margin-bottom: 36px;
            box-shadow: 0 25px 50px rgba(0, 212, 255, 0.1), inset 0 1px 0 rgba(255,255,255,0.05);
            position: relative;
            overflow: hidden;
        }}
        
        .executive-summary::before {{
            content: '';
            position: absolute;
            top: 0;
            right: 0;
            width: 400px;
            height: 400px;
            background: radial-gradient(circle, var(--glow-cyan) 0%, transparent 60%);
            opacity: 0.3;
            pointer-events: none;
        }}
        
        .executive-summary .section-title {{
            color: var(--accent-cyan);
            font-size: 1.9rem;
            margin-bottom: 28px;
            padding-bottom: 16px;
            border-bottom: 2px solid var(--border-highlight);
            font-weight: 800;
            letter-spacing: -0.02em;
            position: relative;
        }}
        
        .exec-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
            gap: 24px;
            position: relative;
            z-index: 1;
        }}
        
        .exec-card {{
            background: rgba(0, 0, 0, 0.3);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 24px;
            transition: all 0.3s ease;
        }}
        
        .exec-card:hover {{
            border-color: var(--accent-cyan);
            box-shadow: 0 10px 30px rgba(0, 212, 255, 0.1);
            transform: translateY(-4px);
        }}
        
        .exec-card h3 {{
            color: var(--accent-purple);
            font-size: 1.15rem;
            margin-bottom: 16px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
        }}
        
        .exec-card p {{
            color: var(--text-secondary);
            line-height: 1.8;
            margin-bottom: 18px;
            font-size: 0.95rem;
        }}
        
        .risk-summary {{
            display: flex;
            align-items: center;
            gap: 18px;
            margin-top: 16px;
        }}
        
        .risk-badge {{
            padding: 8px 20px;
            border-radius: 30px;
            font-weight: 800;
            font-size: 0.8rem;
            letter-spacing: 1px;
        }}
        
        .risk-badge.risk-critical {{
            background: linear-gradient(135deg, rgba(239, 68, 68, 0.2), rgba(249, 115, 22, 0.2));
            color: var(--critical);
            border: 2px solid var(--critical);
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.3);
        }}
        
        .risk-badge.risk-high {{
            background: rgba(249, 115, 22, 0.15);
            color: var(--high);
            border: 2px solid var(--high);
            box-shadow: 0 0 20px rgba(249, 115, 22, 0.2);
        }}
        
        .risk-badge.risk-medium {{
            background: rgba(234, 179, 8, 0.15);
            color: var(--medium);
            border: 2px solid var(--medium);
        }}
        
        .risk-badge.risk-low {{
            background: rgba(34, 197, 94, 0.15);
            color: var(--low);
            border: 2px solid var(--low);
        }}
        
        .risk-score-num {{
            color: var(--text-primary);
            font-weight: 700;
            font-size: 1rem;
        }}
        
        .exec-findings, .exec-recommendations {{
            list-style: none;
            margin: 0;
            padding: 0;
        }}
        
        .exec-findings li, .exec-recommendations li {{
            padding: 12px 0;
            color: var(--text-secondary);
            line-height: 1.7;
            border-bottom: 1px solid var(--border-color);
            font-size: 0.9rem;
        }}
        
        .exec-findings li:last-child, .exec-recommendations li:last-child {{
            border-bottom: none;
        }}
        
        /* ===== RISK MATRIX - Visual Chart Design ===== */
        .risk-matrix-section {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 36px;
            box-shadow: var(--shadow-lg);
        }}
        
        .risk-matrix-section .section-title {{
            color: var(--accent-cyan);
            font-size: 1.9rem;
            margin-bottom: 10px;
            font-weight: 800;
            letter-spacing: -0.02em;
        }}
        
        .section-desc {{
            color: var(--text-muted);
            margin-bottom: 32px;
            font-size: 1rem;
            max-width: 600px;
        }}
        
        .risk-matrix {{
            position: relative;
            max-width: 650px;
            margin: 40px auto;
        }}
        
        .matrix-label-y, .matrix-label-x {{
            position: absolute;
            color: var(--text-muted);
            font-size: 0.8rem;
            font-weight: 700;
            text-transform: uppercase;
            letter-spacing: 2px;
        }}
        
        .matrix-label-y {{
            left: -110px;
            top: 50%;
            transform: translateY(-50%) rotate(-90deg);
        }}
        
        .matrix-label-x {{
            bottom: -45px;
            left: 50%;
            transform: translateX(-50%);
        }}
        
        .matrix-grid {{
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 16px;
        }}
        
        .risk-cell {{
            background: linear-gradient(145deg, var(--bg-tertiary), rgba(0,0,0,0.2));
            border: 2px solid var(--border-color);
            border-radius: 16px;
            padding: 36px 24px;
            text-align: center;
            transition: all 0.4s cubic-bezier(0.4, 0, 0.2, 1);
            position: relative;
            overflow: hidden;
        }}
        
        .risk-cell::before {{
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: radial-gradient(circle at center, currentColor 0%, transparent 70%);
            opacity: 0;
            transition: opacity 0.3s ease;
        }}
        
        .risk-cell:hover {{
            transform: translateY(-6px) scale(1.02);
            box-shadow: 0 20px 40px rgba(0,0,0,0.4);
        }}
        
        .risk-cell:hover::before {{
            opacity: 0.05;
        }}
        
        .risk-cell.sev-critical {{
            border-color: var(--critical);
            background: linear-gradient(145deg, rgba(239, 68, 68, 0.1), var(--bg-tertiary));
            color: var(--critical);
        }}
        
        .risk-cell.sev-critical:hover {{
            box-shadow: 0 20px 50px rgba(239, 68, 68, 0.25);
        }}
        
        .risk-cell.sev-high {{
            border-color: var(--high);
            background: linear-gradient(145deg, rgba(249, 115, 22, 0.1), var(--bg-tertiary));
            color: var(--high);
        }}
        
        .risk-cell.sev-high:hover {{
            box-shadow: 0 20px 50px rgba(249, 115, 22, 0.25);
        }}
        
        .cell-label {{
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 10px;
            font-weight: 600;
        }}
        
        .cell-count {{
            color: inherit;
            font-size: 3rem;
            font-weight: 800;
            margin: 10px 0;
            text-shadow: 0 0 30px currentColor;
        }}
        
        .cell-sublabel {{
            color: var(--text-muted);
            font-size: 0.75rem;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }}
        
        /* ===== TECHNOLOGY SECTION - Modern Grid ===== */
        .tech-section {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 36px;
            box-shadow: var(--shadow-lg);
        }}
        
        .tech-section .section-title {{
            color: var(--accent-cyan);
            font-size: 1.9rem;
            margin-bottom: 28px;
            font-weight: 800;
            letter-spacing: -0.02em;
        }}
        
        .tech-grid {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(380px, 1fr));
            gap: 28px;
        }}
        
        .tech-panel {{
            background: rgba(0, 0, 0, 0.25);
            border: 1px solid var(--border-color);
            border-radius: 16px;
            padding: 28px;
            transition: all 0.3s ease;
        }}
        
        .tech-panel:hover {{
            border-color: var(--accent-purple);
            box-shadow: 0 10px 30px rgba(168, 85, 247, 0.1);
        }}
        
        .tech-panel h3 {{
            color: var(--accent-purple);
            font-size: 1.15rem;
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            font-weight: 700;
        }}
        
        .tech-list, .port-list {{
            display: flex;
            flex-direction: column;
            gap: 12px;
        }}
        
        .tech-item, .port-item {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 14px 18px;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--border-color);
            border-radius: 12px;
            transition: all 0.3s ease;
        }}
        
        .tech-item:hover, .port-item:hover {{
            background: rgba(0, 212, 255, 0.05);
            border-color: var(--accent-cyan);
            transform: translateX(4px);
        }}
        
        .tech-name {{
            color: var(--text-primary);
            font-weight: 600;
            font-size: 0.95rem;
        }}
        
        .tech-count, .port-count {{
            color: var(--text-muted);
            font-size: 0.85rem;
            background: var(--bg-tertiary);
            padding: 4px 12px;
            border-radius: 20px;
            font-weight: 600;
        }}
        
        .port-number {{
            color: var(--accent-cyan);
            font-weight: 800;
            font-family: 'JetBrains Mono', monospace;
            font-size: 1rem;
        }}
        
        .port-service {{
            color: var(--text-primary);
            flex: 1;
            margin: 0 18px;
            font-weight: 500;
        }}
        
        .port-item.high-risk {{
            border-left: 4px solid var(--critical);
            background: rgba(239, 68, 68, 0.05);
        }}
        
        .port-item.high-risk:hover {{
            border-color: var(--critical);
            background: rgba(239, 68, 68, 0.1);
        }}
        
        .port-item.medium-risk {{
            border-left: 4px solid var(--medium);
            background: rgba(234, 179, 8, 0.03);
        }}
        
        .port-item.low-risk {{
            border-left: 4px solid var(--low);
        }}
        
        /* ===== REMEDIATION PRIORITY - Action Cards ===== */
        .remediation-section {{
            background: var(--bg-glass);
            backdrop-filter: blur(10px);
            -webkit-backdrop-filter: blur(10px);
            border: 1px solid var(--glass-border);
            border-radius: 20px;
            padding: 40px;
            margin-bottom: 36px;
            box-shadow: var(--shadow-lg);
        }}
        
        .remediation-section .section-title {{
            color: var(--accent-cyan);
            font-size: 1.9rem;
            margin-bottom: 10px;
            font-weight: 800;
            letter-spacing: -0.02em;
        }}
        
        .priority-table-wrapper {{
            margin: 24px 0;
            border-radius: 16px;
            overflow: hidden;
            border: 1px solid var(--border-color);
        }}
        
        .priority-badge {{
            display: inline-flex;
            align-items: center;
            padding: 6px 14px;
            color: white;
            font-weight: 800;
            font-size: 0.7rem;
            border-radius: 6px;
            letter-spacing: 1px;
            text-transform: uppercase;
            box-shadow: 0 2px 8px rgba(0,0,0,0.2);
        }}
        
        .priority-legend {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
            gap: 14px;
            margin-top: 24px;
            padding: 24px;
            background: rgba(0, 0, 0, 0.2);
            border: 1px solid var(--border-color);
            border-radius: 12px;
        }}
        
        .legend-item {{
            display: flex;
            align-items: center;
            gap: 12px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            line-height: 1.5;
        }}
        
        .legend-dot {{
            width: 14px;
            height: 14px;
            border-radius: 50%;
            flex-shrink: 0;
            box-shadow: 0 0 10px currentColor;
        }}
        
        .more-items {{
            text-align: center;
            color: var(--text-muted);
            font-style: italic;
            padding: 14px;
            font-size: 0.9rem;
        }}
        
        /* ===== FOOTER - Minimalist Design ===== */
        .report-footer {{
            text-align: center;
            padding: 40px 30px;
            margin-top: 30px;
            border-top: 1px solid var(--border-color);
            background: linear-gradient(180deg, transparent 0%, rgba(0, 0, 0, 0.2) 100%);
        }}
        
        .footer-logo {{
            font-size: 1.4rem;
            font-weight: 800;
            background: var(--gradient-primary);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            background-clip: text;
            margin-bottom: 10px;
            letter-spacing: -0.01em;
        }}
        
        .footer-text {{
            color: var(--text-muted);
            font-size: 0.9rem;
            margin: 4px 0;
        }}
        
        .footer-disclaimer {{
            margin-top: 24px;
            padding: 16px 28px;
            background: rgba(239, 68, 68, 0.08);
            border: 1px solid rgba(239, 68, 68, 0.2);
            border-radius: 12px;
            color: var(--text-secondary);
            font-size: 0.85rem;
            display: inline-block;
            max-width: 600px;
        }}
        
        /* ===== PRINT STYLES - Optimized for PDF/Print ===== */
        @media print {{
            * {{
                -webkit-print-color-adjust: exact !important;
                print-color-adjust: exact !important;
            }}
            
            body {{
                background: white;
                color: #1a1a2e;
                font-size: 10pt;
            }}
            
            .bg-grid {{
                display: none !important;
            }}
            
            .container {{
                padding: 20px;
                max-width: 100%;
            }}
            
            .report-header {{
                background: #1a1a2e !important;
                color: white !important;
                border-radius: 8px;
                box-shadow: none;
                page-break-inside: avoid;
            }}
            
            .section,
            .stat-card,
            .ai-section,
            .executive-summary,
            .risk-matrix-section,
            .tech-section,
            .remediation-section {{
                background: white !important;
                border: 1px solid #ddd;
                box-shadow: none;
                backdrop-filter: none;
                page-break-inside: avoid;
            }}
            
            .data-table {{
                font-size: 9pt;
            }}
            
            .data-table th {{
                background: #f5f5f5 !important;
                color: #333 !important;
            }}
            
            .data-table td {{
                color: #333 !important;
                padding: 8px 10px;
            }}
            
            .section-title,
            .report-title {{
                -webkit-text-fill-color: #1a1a2e !important;
                color: #1a1a2e !important;
            }}
            
            .footer-logo {{
                -webkit-text-fill-color: #1a1a2e !important;
            }}
            
            .stat-number {{
                text-shadow: none !important;
            }}
            
            /* Hide interactive elements */
            .table-controls {{
                display: none !important;
            }}
            
            /* Force page breaks */
            .section {{
                page-break-inside: avoid;
            }}
            
            h2 {{
                page-break-after: avoid;
            }}
        }}
        
        /* ===== RESPONSIVE - Mobile/Tablet Optimization ===== */
        @media (max-width: 1024px) {{
            .container {{
                padding: 30px 20px;
            }}
            
            .report-header {{
                padding: 32px;
            }}
            
            .tech-grid {{
                grid-template-columns: 1fr;
            }}
            
            .exec-grid {{
                grid-template-columns: 1fr;
            }}
        }}
        
        @media (max-width: 768px) {{
            .container {{
                padding: 20px 15px;
            }}
            
            .report-header {{
                padding: 24px;
                border-radius: 16px;
            }}
            
            .header-content {{
                flex-direction: column;
                gap: 24px;
            }}
            
            .header-right {{
                align-items: center;
                width: 100%;
            }}
            
            .stats-grid {{
                grid-template-columns: repeat(2, 1fr);
                gap: 12px;
            }}
            
            .stat-card {{
                padding: 20px 16px;
            }}
            
            .stat-number {{
                font-size: 2rem;
            }}
            
            .data-table {{
                font-size: 0.8rem;
            }}
            
            .data-table th,
            .data-table td {{
                padding: 10px 8px;
            }}
            
            .section-header {{
                padding: 16px 20px;
            }}
            
            .section-title {{
                font-size: 1.1rem;
            }}
            
            .risk-matrix {{
                margin: 20px 0;
            }}
            
            .matrix-label-y,
            .matrix-label-x {{
                display: none;
            }}
            
            .meta-info {{
                grid-template-columns: 1fr;
            }}
            
            .priority-legend {{
                grid-template-columns: 1fr;
            }}
        }}
        
        @media (max-width: 480px) {{
            .stats-grid {{
                grid-template-columns: 1fr;
            }}
            
            .logo-title {{
                flex-direction: column;
                text-align: center;
                gap: 12px;
            }}
            
            .report-title {{
                font-size: 1.5rem;
            }}
        }}
    </style>
</head>
<body>
    <div class='bg-grid'></div>
    
    <div class='container'>
        <!-- HEADER -->
        <header class='report-header'>
            <div class='header-content'>
                <div class='header-left'>
                    <div class='logo-title'>
                        <div class='logo-icon'>🛡️</div>
                        <div>
                            <h1 class='report-title'>TwinSanity Security Report</h1>
                            <p class='report-subtitle'>Automated Vulnerability Assessment</p>
                        </div>
                    </div>
                    
                    <div class='meta-info'>
                        <div class='meta-item'>
                            <div class='meta-label'>Target Domain</div>
                            <div class='meta-value'><code>{_escape(domain)}</code></div>
                        </div>
                        <div class='meta-item'>
                            <div class='meta-label'>Scan ID</div>
                            <div class='meta-value'><code>{_escape(scan_id[:8])}</code></div>
                        </div>
                        <div class='meta-item'>
                            <div class='meta-label'>Generated</div>
                            <div class='meta-value'>{timestamp}</div>
                        </div>
                        <div class='meta-item'>
                            <div class='meta-label'>IPs Analyzed</div>
                            <div class='meta-value'>{data['total_ips']}</div>
                        </div>
                    </div>
                </div>
                
                <div class='header-right'>
                    <div class='risk-gauge'>
                        <svg class='risk-circle' viewBox='0 0 100 100'>
                            <circle class='risk-circle-bg' cx='50' cy='50' r='40'/>
                            <circle class='risk-circle-fill' cx='50' cy='50' r='40'/>
                        </svg>
                        <div class='risk-score-text'>
                            <div class='risk-number'>{risk_score}</div>
                            <div class='risk-label'>Risk Score</div>
                        </div>
                    </div>
                    <div class='risk-level'>{risk_level}</div>
                </div>
            </div>
        </header>
        
        <!-- STATS GRID -->
        <div class='stats-grid'>
            <div class='stat-card'>
                <div class='stat-icon'>🌐</div>
                <div class='stat-number'>{data['total_ips']}</div>
                <div class='stat-label'>IPs Scanned</div>
            </div>
            <div class='stat-card'>
                <div class='stat-icon'>🔗</div>
                <div class='stat-number'>{data['total_subdomains']}</div>
                <div class='stat-label'>Subdomains</div>
            </div>
            <div class='stat-card'>
                <div class='stat-icon'>⚠️</div>
                <div class='stat-number'>{total_cves}</div>
                <div class='stat-label'>Unique CVEs</div>
            </div>
            <div class='stat-card critical'>
                <div class='stat-icon'>🔴</div>
                <div class='stat-number'>{data['severity_counts']['critical']}</div>
                <div class='stat-label'>Critical</div>
            </div>
            <div class='stat-card high'>
                <div class='stat-icon'>🟠</div>
                <div class='stat-number'>{data['severity_counts']['high']}</div>
                <div class='stat-label'>High</div>
            </div>
            <div class='stat-card medium'>
                <div class='stat-icon'>🟡</div>
                <div class='stat-number'>{data['severity_counts']['medium']}</div>
                <div class='stat-label'>Medium</div>
            </div>
            <div class='stat-card low'>
                <div class='stat-icon'>🟢</div>
                <div class='stat-number'>{data['severity_counts']['low']}</div>
                <div class='stat-label'>Low</div>
            </div>
        </div>
        
        {self._build_executive_summary(data, domain, risk_score, risk_level)}
        
        {self._build_risk_matrix(data)}
        
        {self._build_remediation_priority(data)}
        
        {self._build_technology_section(data)}
        
        {ai_section}
        
        <!-- CVE LISTING -->
        <section class='section'>
            <div class='section-header'>
                <h2 class='section-title'>
                    <span class='section-icon'>🔓</span>
                    Vulnerability Listing
                </h2>
                <span class='section-badge'>{total_cves} CVEs</span>
            </div>
            <div class='section-content'>
                <!-- Search and Filter Controls -->
                <div class='table-controls'>
                    <div class='search-box'>
                        <input type='text' id='cveSearch' placeholder='🔍 Search CVE ID, description, IP...' onkeyup='filterCVEs()'>
                    </div>
                    <div class='filter-box'>
                        <select id='severityFilter' onchange='filterCVEs()'>
                            <option value='all'>All Severities</option>
                            <option value='critical'>Critical</option>
                            <option value='high'>High</option>
                            <option value='medium'>Medium</option>
                            <option value='low'>Low</option>
                        </select>
                    </div>
                    <div class='results-count' id='resultsCount'>{total_cves} vulnerabilities</div>
                </div>
                <table class='data-table' id='cveTable'>
                    <thead>
                        <tr>
                            <th style='width: 14%;' class='sortable' onclick='sortTable(0)'>CVE ID</th>
                            <th style='width: 12%;' class='sortable' onclick='sortTable(1, true)'>CVSS</th>
                            <th style='width: 8%;' class='sortable' onclick='sortTable(2, true)'>Hosts</th>
                            <th style='width: 12%;' class='sortable' onclick='sortTable(3)'>Severity</th>
                            <th style='width: 32%;'>Summary</th>
                            <th style='width: 22%;'>Affected IPs</th>
                        </tr>
                    </thead>
                    <tbody>
                        {cve_rows}
                    </tbody>
                </table>
            </div>
        </section>
        
        <!-- HOST BREAKDOWN -->
        <section class='section'>
            <div class='section-header'>
                <h2 class='section-title'>
                    <span class='section-icon'>🖥️</span>
                    Host Analysis
                </h2>
                <span class='section-badge'>{data['total_ips']} Hosts</span>
            </div>
            <div class='section-content'>
                <table class='data-table'>
                    <thead>
                        <tr>
                            <th style='width: 30%;'>Hostnames</th>
                            <th style='width: 20%;'>IP Address</th>
                            <th style='width: 30%;'>Open Ports</th>
                            <th style='width: 20%;'>CVE Count</th>
                        </tr>
                    </thead>
                    <tbody>
                        {host_rows}
                    </tbody>
                </table>
            </div>
        </section>
        
        <!-- TOOLS FINDINGS -->
        {self._build_tools_findings_section_html(data.get('tools_findings', {}))}
        
        <!-- FOOTER -->
        <footer class='report-footer'>
            <div class='footer-logo'>TwinSanity Recon V2</div>
            <p class='footer-text'>Automated Security Assessment Platform</p>
            <p class='footer-text'>Report generated on {timestamp}</p>
            <div class='footer-disclaimer'>
                ⚠️ This report is confidential and intended for authorized personnel only.
                The findings should be validated before remediation.
            </div>
        </footer>
    </div>
    
    <!-- Search, Filter, and Sort JavaScript -->
    <script>
    function filterCVEs() {{
        const searchTerm = document.getElementById('cveSearch').value.toLowerCase();
        const severityFilter = document.getElementById('severityFilter').value.toLowerCase();
        const table = document.getElementById('cveTable');
        const tbody = table.tBodies[0];
        const rows = tbody.getElementsByTagName('tr');
        let visibleCount = 0;
        
        for (let row of rows) {{
            const text = row.textContent.toLowerCase();
            const severityCell = row.cells[3]?.textContent.toLowerCase() || '';
            
            const matchesSearch = searchTerm === '' || text.includes(searchTerm);
            const matchesSeverity = severityFilter === 'all' || severityCell.includes(severityFilter);
            
            if (matchesSearch && matchesSeverity) {{
                row.style.display = '';
                visibleCount++;
            }} else {{
                row.style.display = 'none';
            }}
        }}
        
        document.getElementById('resultsCount').textContent = visibleCount + ' vulnerabilities';
    }}
    
    let sortDirection = {{}};
    function sortTable(columnIndex, isNumeric = false) {{
        const table = document.getElementById('cveTable');
        const tbody = table.tBodies[0];
        const rows = Array.from(tbody.rows);
        const header = table.tHead.rows[0].cells[columnIndex];
        
        // Toggle sort direction
        sortDirection[columnIndex] = !sortDirection[columnIndex];
        const ascending = sortDirection[columnIndex];
        
        rows.sort((a, b) => {{
            let valA = a.cells[columnIndex]?.textContent.trim() || '';
            let valB = b.cells[columnIndex]?.textContent.trim() || '';
            
            if (isNumeric) {{
                valA = parseFloat(valA.replace(/[^0-9.-]/g, '')) || 0;
                valB = parseFloat(valB.replace(/[^0-9.-]/g, '')) || 0;
            }} else {{
                valA = valA.toLowerCase();
                valB = valB.toLowerCase();
            }}
            
            if (valA < valB) return ascending ? -1 : 1;
            if (valA > valB) return ascending ? 1 : -1;
            return 0;
        }});
        
        // Update header indicators
        const headers = table.tHead.querySelectorAll('th.sortable');
        headers.forEach(h => h.classList.remove('sort-asc', 'sort-desc'));
        header.classList.add(ascending ? 'sort-asc' : 'sort-desc');
        
        // Reorder rows
        rows.forEach(row => tbody.appendChild(row));
    }}
    </script>
</body>
</html>"""
        
        return html_template
    
    def _build_ai_section(self, ai_analysis: Optional[str], scan_data: Dict = None) -> str:
        """Build the AI analysis section HTML with proper data validation."""
        if not ai_analysis:
            # No AI analysis available - show key findings from scan data
            if scan_data and scan_data.get("cves"):
                top_cves = scan_data["cves"][:5]
                vulns_html = ""
                for cve in top_cves:
                    severity_badge = _get_severity_badge(cve['severity'])
                    vulns_html += f"""
                    <div class='finding-item'>
                        <div class='finding-header'>
                            <code class='cve-id'>{_escape(cve['id'])}</code>
                            {severity_badge}
                            <span class='cvss-score' style='color: {_get_cvss_color(cve["cvss"])}'>CVSS: {cve['cvss'] or 'N/A'}</span>
                        </div>
                        <p class='finding-desc'>{_escape(cve['summary'][:200])}{'...' if len(cve['summary']) > 200 else ''}</p>
                        <p class='finding-affected'>Affects: {len(cve['affected_ips'])} host(s)</p>
                    </div>"""
                
                return f"""
                <section class='ai-section findings-section'>
                    <div class='section-header'>
                        <h2 class='section-title'>
                            <span class='section-icon'>📊</span>
                            Key Security Findings
                        </h2>
                        <span class='section-badge'>Auto-generated</span>
                    </div>
                    <div class='ai-content'>
                        <p class='findings-intro'>Top vulnerabilities discovered during the scan. Enable AI Analysis for detailed recommendations.</p>
                        <div class='findings-list'>
                            {vulns_html}
                        </div>
                    </div>
                </section>
                <style>
                .findings-section .finding-item {{
                    background: var(--bg-tertiary);
                    border-radius: 8px;
                    padding: 15px;
                    margin-bottom: 12px;
                    border-left: 3px solid var(--accent-cyan);
                }}
                .findings-section .finding-header {{
                    display: flex;
                    align-items: center;
                    gap: 12px;
                    margin-bottom: 8px;
                    flex-wrap: wrap;
                }}
                .findings-section .cve-id {{
                    color: var(--accent-cyan);
                    font-weight: 600;
                    background: var(--bg-primary);
                    padding: 4px 10px;
                    border-radius: 4px;
                }}
                .findings-section .cvss-score {{
                    font-weight: 700;
                }}
                .findings-section .finding-desc {{
                    color: var(--text-secondary);
                    font-size: 0.9rem;
                    line-height: 1.5;
                    margin-bottom: 8px;
                }}
                .findings-section .finding-affected {{
                    color: var(--text-muted);
                    font-size: 0.8rem;
                }}
                .findings-intro {{
                    color: var(--text-secondary);
                    margin-bottom: 20px;
                    padding: 10px 15px;
                    background: var(--bg-tertiary);
                    border-radius: 8px;
                    border-left: 3px solid var(--accent-purple);
                }}
                </style>"""
            return ""
        
        # Parse AI analysis if it's a JSON string
        ai_data = None
        if isinstance(ai_analysis, str):
            try:
                ai_data = json.loads(ai_analysis)
            except:
                # If it's not JSON, treat as plain text
                ai_text = html.escape(ai_analysis).replace("\n\n", "</p><p>").replace("\n", "<br>")
                return f"""
                <section class='ai-section'>
                    <div class='section-header'>
                        <h2 class='section-title'>
                            <span class='section-icon'>🤖</span>
                            AI Security Analysis
                        </h2>
                    </div>
                    <div class='ai-content'>
                        <p>{ai_text}</p>
                    </div>
                </section>"""
        elif isinstance(ai_analysis, dict):
            ai_data = ai_analysis
        
        if not ai_data:
            return ""
        
        # Format structured AI analysis
        chunks = ai_data.get('llm_analysis_results', [])
        
        all_summaries = []
        all_high_risk = []
        all_key_vulns = []
        all_actions = []
        
        for chunk in chunks:
            analysis = chunk.get('analysis', {})
            if analysis.get('summary') and analysis['summary'] != 'No summary provided.':
                all_summaries.append(analysis['summary'])
            
            # Filter out invalid high risk assets
            for asset in analysis.get('high_risk_assets', []):
                if asset.get('ip') and asset.get('ip') != 'N/A':
                    all_high_risk.append(asset)
            
            # Filter out invalid vulnerabilities (must have valid CVE ID)
            for vuln in analysis.get('key_vulnerabilities', []):
                cve_id = vuln.get('cve_id', '')
                # Only include if it looks like a real CVE ID
                if cve_id and cve_id != 'Unknown' and (cve_id.startswith('CVE-') or cve_id.startswith('cve-')):
                    all_key_vulns.append(vuln)
            
            # Filter out invalid actions
            for action in analysis.get('recommended_actions', []):
                if action.get('action') and action.get('action') != 'N/A':
                    all_actions.append(action)
        
        # Build sections
        summary_html = ""
        if all_summaries:
            summary_html = "<h3>📋 Executive Summary</h3>"
            # Combine summaries into cohesive paragraphs
            combined_summary = " ".join(all_summaries)
            if len(combined_summary) > 1000:
                combined_summary = combined_summary[:1000] + "..."
            summary_html += f"<p>{_escape(combined_summary)}</p>"
        
        high_risk_html = ""
        if all_high_risk:
            high_risk_html = """<h3>🎯 High Risk Assets</h3>
            <table>
                <thead>
                    <tr>
                        <th style="width: 18%;">IP Address</th>
                        <th style="width: 22%;">Hostname</th>
                        <th style="width: 12%;">Severity</th>
                        <th style="width: 48%;">Risk Reason</th>
                    </tr>
                </thead>
                <tbody>"""
            for asset in all_high_risk[:12]:
                severity_badge = _get_severity_badge_simple(asset.get('severity', 'high'))
                reason = asset.get('reason', 'N/A')
                if isinstance(reason, list):
                    reason = ", ".join(str(r) for r in reason)
                reason = str(reason)[:150]
                high_risk_html += f"""
                <tr>
                    <td><code>{_escape(asset.get('ip', 'N/A'))}</code></td>
                    <td>{_escape(asset.get('hostname', 'N/A'))}</td>
                    <td>{severity_badge}</td>
                    <td>{_escape(reason)}</td>
                </tr>"""
            high_risk_html += "</tbody></table>"
            if len(all_high_risk) > 12:
                high_risk_html += f"<p class='more-items'><em>... and {len(all_high_risk) - 12} more high-risk assets</em></p>"
        
        key_vulns_html = ""
        if all_key_vulns:
            key_vulns_html = """<h3>🔓 Key Vulnerabilities (AI Identified)</h3>
            <div class='vulns-grid'>"""
            for vuln in all_key_vulns[:15]:
                cve_id = vuln.get('cve_id', 'Unknown')
                cvss = vuln.get('cvss', 'N/A')
                why = vuln.get('why_critical', vuln.get('impact', ''))
                if not why or why == 'No description':
                    why = 'Critical vulnerability requiring immediate attention'
                why = str(why)[:150]
                cvss_color = _get_cvss_color(float(cvss) if cvss and cvss != 'N/A' else None)
                key_vulns_html += f"""
                <div class='vuln-card'>
                    <div class='vuln-header'>
                        <code class='vuln-id'>{_escape(cve_id)}</code>
                        <span class='vuln-cvss' style='color: {cvss_color}'>CVSS: {cvss}</span>
                    </div>
                    <p class='vuln-why'>{_escape(why)}</p>
                </div>"""
            key_vulns_html += "</div>"
            if len(all_key_vulns) > 15:
                key_vulns_html += f"<p class='more-items'><em>... and {len(all_key_vulns) - 15} more vulnerabilities identified</em></p>"
        elif scan_data and scan_data.get("cves"):
            # Fallback: Use actual CVE data from scan results
            key_vulns_html = """<h3>🔓 Top Vulnerabilities (From Scan Data)</h3>
            <div class='vulns-grid'>"""
            for cve in scan_data["cves"][:10]:
                cvss_color = _get_cvss_color(cve['cvss'])
                key_vulns_html += f"""
                <div class='vuln-card'>
                    <div class='vuln-header'>
                        <code class='vuln-id'>{_escape(cve['id'])}</code>
                        <span class='vuln-cvss' style='color: {cvss_color}'>CVSS: {cve['cvss'] or 'N/A'}</span>
                    </div>
                    <p class='vuln-why'>{_escape(cve['summary'][:150])}</p>
                </div>"""
            key_vulns_html += "</div>"
        
        actions_html = ""
        if all_actions:
            actions_html = """<h3>✅ Recommended Remediation Actions</h3>
            <table>
                <thead>
                    <tr>
                        <th style="width: 12%;">Priority</th>
                        <th style="width: 38%;">Action Required</th>
                        <th style="width: 50%;">Justification</th>
                    </tr>
                </thead>
                <tbody>"""
            for action in all_actions[:12]:
                priority_badge = _get_severity_badge_simple(action.get('priority', 'medium'))
                action_text = str(action.get('action', 'N/A'))[:100]
                justification = str(action.get('justification', 'N/A'))[:150]
                actions_html += f"""
                <tr>
                    <td>{priority_badge}</td>
                    <td>{_escape(action_text)}</td>
                    <td>{_escape(justification)}</td>
                </tr>"""
            actions_html += "</tbody></table>"
            if len(all_actions) > 12:
                actions_html += f"<p class='more-items'><em>... and {len(all_actions) - 12} more recommended actions</em></p>"
        
        # Build Tools Analysis Section (AI opinion on recon tools findings)
        tools_analysis_html = ""
        tools_analysis = ai_data.get('tools_analysis', {})
        if tools_analysis and tools_analysis.get('executive_summary'):
            tools_analysis_html = "<h3>🔧 Reconnaissance Tools Analysis</h3>"
            
            # Executive summary
            tools_analysis_html += f"<div class='tools-analysis-summary'><p><strong>{_escape(tools_analysis.get('executive_summary', ''))}</strong></p></div>"
            
            # Nuclei analysis
            nuclei_analysis = tools_analysis.get('nuclei_analysis', {})
            if nuclei_analysis.get('key_findings'):
                risk_class = nuclei_analysis.get('risk_assessment', 'medium').lower()
                tools_analysis_html += f"""
                <div class='tools-analysis-section'>
                    <h4>🔍 Nuclei Vulnerability Findings</h4>
                    <div class='risk-indicator {risk_class}'>Risk: {nuclei_analysis.get('risk_assessment', 'Unknown').upper()}</div>
                    <ul>"""
                for finding in nuclei_analysis.get('key_findings', [])[:5]:
                    tools_analysis_html += f"<li>{_escape(str(finding))}</li>"
                tools_analysis_html += "</ul>"
                
                if nuclei_analysis.get('attack_scenarios'):
                    tools_analysis_html += "<p class='subsection-title'>Potential Attack Scenarios:</p><ul>"
                    for scenario in nuclei_analysis.get('attack_scenarios', [])[:3]:
                        tools_analysis_html += f"<li class='attack-scenario'>{_escape(str(scenario))}</li>"
                    tools_analysis_html += "</ul>"
                
                if nuclei_analysis.get('recommendations'):
                    tools_analysis_html += "<p class='subsection-title'>Recommendations:</p><ul>"
                    for rec in nuclei_analysis.get('recommendations', [])[:3]:
                        tools_analysis_html += f"<li class='recommendation'>{_escape(str(rec))}</li>"
                    tools_analysis_html += "</ul>"
                tools_analysis_html += "</div>"
            
            # XSS analysis
            xss_analysis = tools_analysis.get('xss_analysis', {})
            if xss_analysis.get('risk_assessment') and xss_analysis.get('risk_assessment') not in ['none', 'N/A']:
                risk_class = xss_analysis.get('risk_assessment', 'medium').lower()
                tools_analysis_html += f"""
                <div class='tools-analysis-section'>
                    <h4>⚠️ XSS Vulnerabilities Assessment</h4>
                    <div class='risk-indicator {risk_class}'>Risk: {xss_analysis.get('risk_assessment', 'Unknown').upper()}</div>
                    <table class='xss-analysis-table'>
                        <tr><td><strong>Exploitability:</strong></td><td>{_escape(str(xss_analysis.get('exploitability', 'N/A')))}</td></tr>
                        <tr><td><strong>Potential Impact:</strong></td><td>{_escape(str(xss_analysis.get('impact', 'N/A')))}</td></tr>
                    </table>"""
                if xss_analysis.get('recommendations'):
                    tools_analysis_html += "<p class='subsection-title'>Remediation:</p><ul>"
                    for rec in xss_analysis.get('recommendations', [])[:3]:
                        tools_analysis_html += f"<li>{_escape(str(rec))}</li>"
                    tools_analysis_html += "</ul>"
                tools_analysis_html += "</div>"
            
            # API analysis
            api_analysis = tools_analysis.get('api_analysis', {})
            if api_analysis.get('sensitive_endpoints') or api_analysis.get('attack_vectors'):
                exposure_class = api_analysis.get('exposure_level', 'medium').lower()
                tools_analysis_html += f"""
                <div class='tools-analysis-section'>
                    <h4>🔌 API Exposure Analysis</h4>
                    <div class='risk-indicator {exposure_class}'>Exposure: {api_analysis.get('exposure_level', 'Unknown').upper()}</div>"""
                
                if api_analysis.get('sensitive_endpoints'):
                    tools_analysis_html += "<p class='subsection-title'>Sensitive Endpoints:</p><ul>"
                    for endpoint in api_analysis.get('sensitive_endpoints', [])[:5]:
                        tools_analysis_html += f"<li><code>{_escape(str(endpoint))}</code></li>"
                    tools_analysis_html += "</ul>"
                
                if api_analysis.get('attack_vectors'):
                    tools_analysis_html += "<p class='subsection-title'>Attack Vectors:</p><ul>"
                    for vector in api_analysis.get('attack_vectors', [])[:3]:
                        tools_analysis_html += f"<li>{_escape(str(vector))}</li>"
                    tools_analysis_html += "</ul>"
                tools_analysis_html += "</div>"
            
            # URL analysis
            url_analysis = tools_analysis.get('url_analysis', {})
            if url_analysis.get('priority_targets') or url_analysis.get('interesting_patterns'):
                tools_analysis_html += f"""
                <div class='tools-analysis-section'>
                    <h4>🔗 URL Attack Surface</h4>
                    <p>{_escape(str(url_analysis.get('attack_surface', '')))}</p>"""
                
                if url_analysis.get('interesting_patterns'):
                    tools_analysis_html += "<p class='subsection-title'>Interesting Patterns:</p><ul>"
                    for pattern in url_analysis.get('interesting_patterns', [])[:5]:
                        tools_analysis_html += f"<li>{_escape(str(pattern))}</li>"
                    tools_analysis_html += "</ul>"
                
                if url_analysis.get('priority_targets'):
                    tools_analysis_html += "<p class='subsection-title'>Priority Targets:</p><ul>"
                    for target in url_analysis.get('priority_targets', [])[:5]:
                        tools_analysis_html += f"<li><code>{_escape(str(target))}</code></li>"
                    tools_analysis_html += "</ul>"
                tools_analysis_html += "</div>"
            
            # Overall opinion
            if tools_analysis.get('overall_opinion'):
                tools_analysis_html += f"""
                <div class='tools-analysis-opinion'>
                    <h4>🎯 Expert Opinion</h4>
                    <blockquote>{_escape(tools_analysis.get('overall_opinion', ''))}</blockquote>
                </div>"""
        
        # Additional styles for the AI section
        extra_styles = """
        <style>
        .ai-content .vulns-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 12px;
            margin: 15px 0;
        }
        .ai-content .vuln-card {
            background: var(--bg-tertiary);
            border-radius: 8px;
            padding: 12px 15px;
            border-left: 3px solid var(--accent-cyan);
        }
        .ai-content .vuln-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 8px;
        }
        .ai-content .vuln-id {
            color: var(--accent-cyan);
            font-weight: 600;
            background: var(--bg-primary);
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 0.85rem;
        }
        .ai-content .vuln-cvss {
            font-weight: 700;
            font-size: 0.9rem;
        }
        .ai-content .vuln-why {
            color: var(--text-secondary);
            font-size: 0.85rem;
            line-height: 1.4;
            margin: 0;
        }
        .ai-content .more-items {
            color: var(--text-muted);
            font-size: 0.85rem;
            margin-top: 10px;
        }
        /* Tools Analysis Styles */
        .tools-analysis-summary {
            background: var(--bg-tertiary);
            padding: 15px;
            border-radius: 8px;
            border-left: 4px solid var(--accent-purple);
            margin-bottom: 20px;
        }
        .tools-analysis-section {
            background: var(--bg-tertiary);
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 15px;
        }
        .tools-analysis-section h4 {
            color: var(--accent-cyan);
            margin-bottom: 10px;
        }
        .risk-indicator {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 0.8rem;
            font-weight: 600;
            margin-bottom: 10px;
        }
        .risk-indicator.critical { background: rgba(255, 107, 129, 0.2); color: var(--danger); }
        .risk-indicator.high { background: rgba(255, 165, 2, 0.2); color: var(--warning); }
        .risk-indicator.medium { background: rgba(255, 204, 0, 0.2); color: #ffcc00; }
        .risk-indicator.low { background: rgba(0, 255, 127, 0.2); color: var(--success); }
        .risk-indicator.none, .risk-indicator.minimal { background: rgba(100, 255, 218, 0.1); color: var(--accent-cyan); }
        .subsection-title {
            color: var(--text-secondary);
            font-weight: 600;
            margin-top: 12px;
            margin-bottom: 8px;
        }
        .attack-scenario { color: var(--warning); }
        .recommendation { color: var(--success); }
        .xss-analysis-table {
            margin: 10px 0;
            font-size: 0.9rem;
        }
        .xss-analysis-table td {
            padding: 5px 10px;
        }
        .tools-analysis-opinion {
            background: linear-gradient(135deg, var(--bg-tertiary) 0%, var(--bg-secondary) 100%);
            padding: 20px;
            border-radius: 8px;
            margin-top: 20px;
            border: 1px solid var(--accent-purple);
        }
        .tools-analysis-opinion h4 {
            color: var(--accent-purple);
            margin-bottom: 12px;
        }
        .tools-analysis-opinion blockquote {
            margin: 0;
            padding: 0 15px;
            border-left: 3px solid var(--accent-cyan);
            font-style: italic;
            color: var(--text-secondary);
        }
        </style>
        """
        
        return f"""
        <section class='ai-section'>
            <div class='section-header'>
                <h2 class='section-title'>
                    <span class='section-icon'>🤖</span>
                    AI Security Analysis
                </h2>
                <span class='section-badge'>Powered by AI</span>
            </div>
            <div class='ai-content'>
                {summary_html}
                {high_risk_html}
                {key_vulns_html}
                {actions_html}
                {tools_analysis_html}
            </div>
        </section>
        {extra_styles}"""

    def _build_tools_findings_section_html(self, tools_findings: Dict) -> str:
        """Build tools findings section for HTML report (Nuclei, XSS, API Discovery)."""
        if not tools_findings:
            return ""
        
        nuclei = tools_findings.get('nuclei_findings', {})
        xss = tools_findings.get('xss_findings', {})
        api = tools_findings.get('api_discoveries', {})
        alive = tools_findings.get('alive_hosts', {})
        urls = tools_findings.get('harvested_urls', {})
        
        total_findings = (nuclei.get('count', 0) + xss.get('count', 0) + 
                         api.get('count', 0))
        
        # Show section if ANY tool has findings (not just nuclei/xss/api)
        if total_findings == 0 and alive.get('count', 0) == 0 and urls.get('count', 0) == 0:
            return ""
        
        sections = []
        
        # Summary Stats Card
        summary_html = f"""
        <section class='section tools-findings-section'>
            <div class='section-header'>
                <h2 class='section-title'>
                    <span class='section-icon'>🔧</span>
                    Security Tools Results
                </h2>
                <span class='section-badge'>{total_findings} Findings</span>
            </div>
            <div class='section-content'>
                <div class='tools-summary-grid'>
                    <div class='tools-stat-card'>
                        <div class='tools-stat-icon'>🎯</div>
                        <div class='tools-stat-value'>{nuclei.get('count', 0)}</div>
                        <div class='tools-stat-label'>Nuclei Findings</div>
                    </div>
                    <div class='tools-stat-card'>
                        <div class='tools-stat-icon'>⚡</div>
                        <div class='tools-stat-value'>{xss.get('count', 0)}</div>
                        <div class='tools-stat-label'>XSS Vulnerabilities</div>
                    </div>
                    <div class='tools-stat-card'>
                        <div class='tools-stat-icon'>🔌</div>
                        <div class='tools-stat-value'>{api.get('count', 0)}</div>
                        <div class='tools-stat-label'>API Endpoints</div>
                    </div>
                    <div class='tools-stat-card'>
                        <div class='tools-stat-icon'>🌐</div>
                        <div class='tools-stat-value'>{alive.get('count', 0)}</div>
                        <div class='tools-stat-label'>Alive Hosts</div>
                    </div>
                    <div class='tools-stat-card'>
                        <div class='tools-stat-icon'>🔗</div>
                        <div class='tools-stat-value'>{urls.get('count', 0)}</div>
                        <div class='tools-stat-label'>Harvested URLs</div>
                    </div>
                </div>
            </div>
        </section>"""
        sections.append(summary_html)
        
        # Nuclei Findings
        if nuclei.get('count', 0) > 0:
            nuclei_rows = ""
            for item in nuclei.get('items', [])[:30]:
                severity = item.get('severity', 'unknown').lower()
                nuclei_rows += f"""<tr>
                    <td>{_get_severity_badge(severity)}</td>
                    <td>{_escape(item.get('name', 'Unknown'))}</td>
                    <td><code>{_escape(item.get('host', 'N/A'))}</code></td>
                </tr>"""
            
            by_sev = nuclei.get('by_severity', {})
            sev_badges = " ".join([f"<span class='sev-count sev-{k}'>{k}: {v}</span>" for k, v in by_sev.items()])
            
            sections.append(f"""
            <section class='section'>
                <div class='section-header'>
                    <h2 class='section-title'>
                        <span class='section-icon'>🎯</span>
                        Nuclei Vulnerability Scan
                    </h2>
                    <span class='section-badge'>{nuclei.get('count', 0)} Findings</span>
                </div>
                <div class='section-content'>
                    <div class='severity-summary'>{sev_badges}</div>
                    <table class='data-table'>
                        <thead>
                            <tr>
                                <th style='width: 15%;'>Severity</th>
                                <th style='width: 50%;'>Vulnerability</th>
                                <th style='width: 35%;'>Affected Host</th>
                            </tr>
                        </thead>
                        <tbody>{nuclei_rows}</tbody>
                    </table>
                </div>
            </section>""")
        
        # XSS Findings
        if xss.get('count', 0) > 0:
            xss_rows = ""
            for item in xss.get('items', [])[:15]:
                xss_rows += f"""<tr>
                    <td><span class='xss-badge'>XSS</span></td>
                    <td><code>{_escape(item.get('parameter', 'N/A'))}</code></td>
                    <td class='url-cell'>{_escape(item.get('url', 'N/A')[:80])}</td>
                </tr>"""
            
            sections.append(f"""
            <section class='section'>
                <div class='section-header'>
                    <h2 class='section-title'>
                        <span class='section-icon'>⚡</span>
                        XSS Vulnerabilities
                    </h2>
                    <span class='section-badge xss-badge'>{xss.get('count', 0)} Found</span>
                </div>
                <div class='section-content'>
                    <table class='data-table'>
                        <thead>
                            <tr>
                                <th style='width: 15%;'>Type</th>
                                <th style='width: 25%;'>Parameter</th>
                                <th style='width: 60%;'>URL</th>
                            </tr>
                        </thead>
                        <tbody>{xss_rows}</tbody>
                    </table>
                </div>
            </section>""")
        
        # API Discoveries
        if api.get('count', 0) > 0:
            api_rows = ""
            for item in api.get('items', [])[:20]:
                api_rows += f"""<tr>
                    <td><span class='api-type-badge'>{_escape(item.get('api_type', 'Unknown'))}</span></td>
                    <td><code>{_escape(item.get('path', 'N/A'))}</code></td>
                    <td>{item.get('status_code', 'N/A')}</td>
                </tr>"""
            
            sections.append(f"""
            <section class='section'>
                <div class='section-header'>
                    <h2 class='section-title'>
                        <span class='section-icon'>🔌</span>
                        API Endpoints Discovered
                    </h2>
                    <span class='section-badge'>{api.get('count', 0)} Endpoints</span>
                </div>
                <div class='section-content'>
                    <table class='data-table'>
                        <thead>
                            <tr>
                                <th style='width: 20%;'>Type</th>
                                <th style='width: 60%;'>Path</th>
                                <th style='width: 20%;'>Status</th>
                            </tr>
                        </thead>
                        <tbody>{api_rows}</tbody>
                    </table>
                </div>
            </section>""")
        
        # Harvested URLs Section with expandable toggle
        if urls.get('count', 0) > 0:
            sample_urls = urls.get('sample', [])
            total_url_count = urls.get('count', 0)
            preview_count = min(15, len(sample_urls))  # Show 15 in preview
            
            # Build preview rows (first 15)
            preview_rows = ""
            for url in sample_urls[:preview_count]:
                url_str = url if isinstance(url, str) else str(url)
                display_url = url_str[:100] + '...' if len(url_str) > 100 else url_str
                has_params = '?' in url_str
                preview_rows += f"""<tr>
                    <td class='url-cell'><code>{_escape(display_url)}</code></td>
                    <td style='text-align: center;'>{('<span class="param-badge">✓ Params</span>' if has_params else '<span class="no-param">-</span>')}</td>
                </tr>"""
            
            # Build all rows for expandable section
            all_rows = ""
            for url in sample_urls:
                url_str = url if isinstance(url, str) else str(url)
                display_url = url_str[:120] + '...' if len(url_str) > 120 else url_str
                has_params = '?' in url_str
                all_rows += f"""<tr>
                    <td class='url-cell'><code>{_escape(display_url)}</code></td>
                    <td style='text-align: center;'>{('<span class="param-badge">✓ Params</span>' if has_params else '<span class="no-param">-</span>')}</td>
                </tr>"""
            
            expand_button = ""
            expandable_section = ""
            if len(sample_urls) > preview_count:
                expand_button = f"""
                <button class='url-expand-toggle' onclick='toggleUrlList(this)'>
                    <svg class='expand-icon' width='16' height='16' viewBox='0 0 24 24' fill='none' stroke='currentColor' stroke-width='2'>
                        <polyline points='6 9 12 15 18 9'></polyline>
                    </svg>
                    Show All {len(sample_urls)} URLs
                </button>"""
                expandable_section = f"""
                <div class='url-full-list' style='display: none;'>
                    <table class='data-table'>
                        <thead>
                            <tr>
                                <th style='width: 85%;'>URL</th>
                                <th style='width: 15%;'>Has Params</th>
                            </tr>
                        </thead>
                        <tbody>{all_rows}</tbody>
                    </table>
                </div>"""
            
            sections.append(f"""
            <section class='section'>
                <div class='section-header'>
                    <h2 class='section-title'>
                        <span class='section-icon'>🔗</span>
                        Harvested URLs (Wayback/CommonCrawl)
                    </h2>
                    <span class='section-badge'>{total_url_count} URLs</span>
                </div>
                <div class='section-content'>
                    <p class='section-info'>URLs with parameters are valuable for security testing (XSS, SQLi, IDOR, etc.). Found {urls.get('with_params', 0)} URLs with parameters.</p>
                    <div class='url-preview-list'>
                        <table class='data-table'>
                            <thead>
                                <tr>
                                    <th style='width: 85%;'>URL</th>
                                    <th style='width: 15%;'>Has Params</th>
                                </tr>
                            </thead>
                            <tbody>{preview_rows}</tbody>
                        </table>
                    </div>
                    {expand_button}
                    {expandable_section}
                    {f"<p class='section-note'>Showing sample of {len(sample_urls)} URLs from {total_url_count} total harvested</p>" if total_url_count > len(sample_urls) else ''}
                </div>
            </section>
            <script>
            function toggleUrlList(btn) {{
                const section = btn.parentElement;
                const preview = section.querySelector('.url-preview-list');
                const fullList = section.querySelector('.url-full-list');
                const icon = btn.querySelector('.expand-icon');
                
                if (fullList.style.display === 'none') {{
                    preview.style.display = 'none';
                    fullList.style.display = 'block';
                    btn.innerHTML = '<svg class="expand-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="18 15 12 9 6 15"></polyline></svg> Show Less';
                }} else {{
                    preview.style.display = 'block';
                    fullList.style.display = 'none';
                    btn.innerHTML = '<svg class="expand-icon" width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="6 9 12 15 18 9"></polyline></svg> Show All {len(sample_urls)} URLs';
                }}
            }}
            </script>""")
        
        # Add CSS styles for tools sections
        styles = """
        <style>
        .tools-findings-section .tools-summary-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
            gap: 15px;
            margin-bottom: 20px;
        }
        .tools-stat-card {
            background: var(--bg-tertiary);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
            border: 1px solid rgba(0, 212, 255, 0.1);
            transition: all 0.3s ease;
        }
        .tools-stat-card:hover {
            border-color: var(--accent-cyan);
            transform: translateY(-3px);
        }
        .tools-stat-icon {
            font-size: 2rem;
            margin-bottom: 10px;
        }
        .tools-stat-value {
            font-size: 2rem;
            font-weight: 700;
            color: var(--accent-cyan);
        }
        .tools-stat-label {
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-top: 5px;
        }
        .severity-summary {
            display: flex;
            gap: 10px;
            margin-bottom: 15px;
            flex-wrap: wrap;
        }
        .sev-count {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.8rem;
            font-weight: 600;
        }
        .sev-critical { background: rgba(255, 8, 68, 0.2); color: #ff0844; }
        .sev-high { background: rgba(245, 87, 108, 0.2); color: #f5576c; }
        .sev-medium { background: rgba(250, 130, 49, 0.2); color: #fa8231; }
        .sev-low { background: rgba(38, 222, 129, 0.2); color: #26de81; }
        .sev-unknown { background: rgba(75, 101, 132, 0.2); color: #778ca3; }
        .xss-badge {
            background: linear-gradient(135deg, #f5576c 0%, #f093fb 100%);
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.75rem;
        }
        .api-type-badge {
            background: var(--bg-primary);
            color: var(--accent-cyan);
            padding: 3px 10px;
            border-radius: 4px;
            font-size: 0.8rem;
        }
        .url-cell {
            font-size: 0.85rem;
            word-break: break-all;
        }
        .param-badge {
            background: linear-gradient(135deg, #26de81 0%, #20bf6b 100%);
            color: white;
            padding: 3px 10px;
            border-radius: 4px;
            font-weight: 600;
            font-size: 0.75rem;
        }
        .no-param {
            color: var(--text-muted);
        }
        .section-info {
            color: var(--text-secondary);
            font-size: 0.9rem;
            margin-bottom: 15px;
            padding: 10px;
            background: rgba(0, 212, 255, 0.05);
            border-radius: 8px;
            border-left: 3px solid var(--accent-cyan);
        }
        .section-note {
            color: var(--text-muted);
            font-size: 0.8rem;
            margin-top: 10px;
            font-style: italic;
        }
        .url-expand-toggle {
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            width: 100%;
            padding: 12px 20px;
            margin-top: 15px;
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.1) 0%, rgba(138, 43, 226, 0.1) 100%);
            border: 1px solid rgba(0, 212, 255, 0.3);
            border-radius: 8px;
            color: var(--accent-cyan);
            font-weight: 600;
            font-size: 0.9rem;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        .url-expand-toggle:hover {
            background: linear-gradient(135deg, rgba(0, 212, 255, 0.2) 0%, rgba(138, 43, 226, 0.2) 100%);
            border-color: var(--accent-cyan);
            box-shadow: 0 0 15px rgba(0, 212, 255, 0.3);
        }
        .url-expand-toggle .expand-icon {
            transition: transform 0.3s ease;
        }
        .url-full-list {
            margin-top: 15px;
            max-height: 600px;
            overflow-y: auto;
            border: 1px solid rgba(0, 212, 255, 0.2);
            border-radius: 8px;
        }
        .url-full-list::-webkit-scrollbar {
            width: 8px;
        }
        .url-full-list::-webkit-scrollbar-track {
            background: var(--bg-primary);
            border-radius: 4px;
        }
        .url-full-list::-webkit-scrollbar-thumb {
            background: var(--accent-cyan);
            border-radius: 4px;
        }
        </style>"""
        
        return styles + "\n".join(sections)



# Global instance
_report_generator = None

def get_report_generator() -> ReportGenerator:
    """Get or create the global report generator instance"""
    global _report_generator
    if _report_generator is None:
        _report_generator = ReportGenerator()
    return _report_generator
