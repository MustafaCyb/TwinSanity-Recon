"""
TwinSanity Recon V2 - Reports Router  
Report generation and download endpoints.
"""
from datetime import datetime
from pathlib import Path
from fastapi import APIRouter, HTTPException, Request, Depends

from fastapi.responses import FileResponse

from dashboard.config import PROJECT_ROOT, logger
from dashboard.middleware.auth import require_auth

router = APIRouter(prefix="/api/report", tags=["Reports"])
REPORTS_DIR = PROJECT_ROOT / "reports"


async def verify_scan_access(scan_id: str, request: Request):
    """Verify user has access to a scan. Returns the scan if authorized."""
    from dashboard.database import get_db
    
    db = await get_db()
    scan = await db.get_scan_by_id(scan_id)
    
    if not scan:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    user_id = getattr(request.state, 'user_id', None)
    is_super_admin = getattr(request.state, 'is_primary_admin', False)
    
    # Super admin can access all scans
    if is_super_admin:
        return scan
    
    # Check ownership or public visibility
    scan_owner = scan.get('user_id')
    visibility = scan.get('visibility', 'private')
    
    if scan_owner != user_id and visibility != 'public':
        raise HTTPException(status_code=403, detail="Access denied to this scan")
    
    return scan


@router.post("/generate/{scan_id}")
async def generate_report(scan_id: str, request: Request, _=Depends(require_auth)):
    """Generate an HTML report for a scan"""
    from dashboard.report_generator import get_report_generator
    from dashboard.scan_context import load_scan_results_for_llm
    from dashboard.state import state
    
    # Verify scan access
    await verify_scan_access(scan_id, request)
    
    body = await request.json() if request.headers.get("content-type") == "application/json" else {}
    format_type = body.get("format", "html")
    include_ai = body.get("include_ai_analysis", True)
    include_tools = body.get("include_tool_findings", True)  # New option for tool findings
    
    scan_data = await load_scan_results_for_llm(scan_id)
    if not scan_data:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan_results = scan_data.get("results", {})
    tools_findings = scan_data.get("tools_findings", {}) if include_tools else {}
    
    domain = "unknown"
    scan = state.get_scan(scan_id)
    if scan:
        domain = scan.get("config", {}).get("domain", "unknown")
    else:
        try:
            from dashboard.database import get_db
            db = await get_db()
            db_scan = await db.get_scan_by_id(scan_id)
            if db_scan:
                domain = db_scan.get("domain", "unknown")
        except:
            pass
    
    ai_analysis = None
    if include_ai:
        try:
            from dashboard.database import get_db
            db = await get_db()
            analyses = await db.get_ai_analysis(scan_id)
            if analyses:
                ai_analysis = analyses[-1].get("content", "")
                logger.info(f"[Report] Found existing AI analysis for scan {scan_id}")
            else:
                logger.info(f"[Report] No AI analysis found for scan {scan_id}")
        except Exception as e:
            logger.warning(f"[Report] Failed to fetch AI analysis: {e}")
    
    rg = get_report_generator()
    
    if format_type == "pdf":
        pdf_path = rg.generate_pdf_report(scan_results, scan_id, domain, ai_analysis, tools_findings)
        if pdf_path:
            filename = Path(pdf_path).name
            return FileResponse(
                pdf_path,
                media_type="application/pdf",
                filename=filename,
                headers={"Content-Disposition": f'attachment; filename="{filename}"'}
            )
        logger.warning("PDF generation failed, returning HTML instead")
    
    html_path = rg.generate_html_report(scan_results, scan_id, domain, ai_analysis, tools_findings)
    filename = Path(html_path).name
    return FileResponse(
        html_path,
        media_type="text/html",
        filename=filename,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'}
    )


@router.get("/download/{scan_id}")
async def download_report(scan_id: str, request: Request, format: str = "html", _=Depends(require_auth)):
    """Download a previously generated report"""
    # Validate scan_id format (should be alphanumeric)
    import re
    if not re.match(r'^[a-zA-Z0-9_-]+$', scan_id):
        raise HTTPException(status_code=400, detail="Invalid scan ID format")
    
    # Security: Check user has access to this scan
    await verify_scan_access(scan_id, request)
    
    REPORTS_DIR.mkdir(exist_ok=True)
    
    # Use only first 8 chars and ensure no glob special characters
    safe_scan_id = scan_id[:8].replace('*', '').replace('?', '').replace('[', '').replace(']', '')
    pattern = f"TwinSanity_Report_*_{safe_scan_id}*"
    html_files = list(REPORTS_DIR.glob(f"{pattern}.html"))
    pdf_files = list(REPORTS_DIR.glob(f"{pattern}.pdf"))
    
    if format == "pdf" and pdf_files:
        return FileResponse(
            str(pdf_files[0]),
            media_type="application/pdf",
            filename=pdf_files[0].name
        )
    elif html_files:
        return FileResponse(
            str(html_files[0]),
            media_type="text/html",
            filename=html_files[0].name
        )
    
    raise HTTPException(status_code=404, detail="Report not found. Generate it first.")


@router.get("/list")
async def list_reports(request: Request, _=Depends(require_auth)):
    """List all generated reports - only shows user's own reports unless super admin"""
    from dashboard.database import get_db
    
    REPORTS_DIR.mkdir(exist_ok=True)
    
    user_id = getattr(request.state, 'user_id', None)
    is_super_admin = getattr(request.state, 'is_primary_admin', False)
    
    db = await get_db()
    
    reports = []
    for f in REPORTS_DIR.glob("TwinSanity_Report_*.html"):
        # Extract scan_id from filename (format: TwinSanity_Report_domain_scanid_date.html)
        parts = f.stem.split('_')
        if len(parts) >= 4:
            scan_id = parts[3]  # Extract scan_id
            
            # Check if user has access to this scan
            try:
                scan = await db.get_scan_by_id(scan_id)
                if scan:
                    scan_owner = scan.get('user_id')
                    visibility = scan.get('visibility', 'private')
                    
                    # Only include if super admin, owner, or public
                    if not is_super_admin and scan_owner != user_id and visibility != 'public':
                        continue
            except:
                # If we can't verify, skip for non-super-admins
                if not is_super_admin:
                    continue
        
        stat = f.stat()
        reports.append({
            "filename": f.name,
            "path": str(f),
            "size": stat.st_size,
            "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
            "has_pdf": (f.with_suffix('.pdf')).exists()
        })
    
    return {"reports": sorted(reports, key=lambda x: x["created"], reverse=True)}
