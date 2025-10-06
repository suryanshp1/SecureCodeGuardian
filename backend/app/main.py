from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from jinja2 import Environment, FileSystemLoader
import pdfkit
from datetime import datetime
from .models import CodeSnippet, RepoScanRequest, ReportRequest
from .agents import SecurityAgent
from .db import results
from .celery_app import celery
from celery.result import AsyncResult

app = FastAPI()
agent = SecurityAgent()
env = Environment(loader=FileSystemLoader("app/templates"))

@app.post("/scan/snippet/", response_model=dict)
def scan_snippet(snippet: CodeSnippet):
    return agent.scan_code(snippet)

@app.post("/scan/repo", response_model=dict)
def scan_repo(req: RepoScanRequest):
    return agent.scan_repo(req)


@app.get("/scan/status/{scan_id}", response_model=dict)
def scan_status(scan_id: str):
    """Return the stored scan document and, if available, the celery task state."""
    doc = results.find_one({"_id": scan_id})
    if not doc:
        raise HTTPException(404, "Scan not found")

    status = {"db_doc": doc}
    task_id = doc.get("task_id")
    if task_id:
        try:
            res = AsyncResult(task_id, app=celery)
            status["task_state"] = res.state
            status["task_result"] = res.result if res.ready() else None
        except Exception as e:
            status["task_state_error"] = str(e)

    return status

@app.post("/report/", response_model=None, response_class=FileResponse)
def report(req: ReportRequest):
    doc = results.find_one({"_id": req.scan_id})
    if not doc:
        raise HTTPException(404, "Scan not found")

    # Render template to HTML
    # Build a template-friendly context named `result`.
    # For snippet scans, the stored doc is already similar to ScanResult.
    # For repo scans, we need to aggregate findings into a vulnerabilities list.
    result = {
        'report_generated_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')
    }
    if doc.get("type") == "repo":
        # Aggregate pattern_findings and ai_findings across files
        vulns = []
        for item in doc.get("findings", []):
            file_path = item.get("file")
            for pf in item.get("pattern_findings", []):
                vulns.append({
                    "id": f"PATTERN_{pf.get('rule', 'unknown')}",
                    "description": f"Pattern finding in {file_path} at line {pf.get('line')}: {pf.get('snippet')}",
                    "severity": "medium",
                    "mitigation": "Review the code and apply appropriate sanitization / safe APIs"
                })
            for av in item.get("ai_findings", []):
                # ai_findings may already contain id/description/severity/mitigation
                if isinstance(av, dict):
                    vulns.append({
                        "id": av.get("id", "AI_UNKNOWN"),
                        "description": av.get("description", "No description"),
                        "severity": av.get("severity", "medium"),
                        "mitigation": av.get("mitigation", "No mitigation provided")
                    })
        result["target"] = doc.get("repo")
        result["vulnerabilities"] = vulns
        result["mitigated_code"] = None
    else:
        # Assume snippet-like document
        result["target"] = doc.get("target", "snippet")
        # Some snippet responses are stored directly as ScanResult dicts
        result["vulnerabilities"] = doc.get("vulnerabilities", [])
        result["mitigated_code"] = doc.get("mitigated_code")

    template = env.get_template("report.html")
    html = template.render(result=result)

    # Create PDF from HTML
    pdf_path = f"/tmp/report_{req.scan_id}.pdf"
    try:
        pdfkit.from_string(html, pdf_path)
    except (OSError, FileNotFoundError) as e:
        # Common failure: wkhtmltopdf not installed or not found in PATH
        raise HTTPException(status_code=500, detail=(
            "PDF generation failed: wkhtmltopdf executable not found or not runnable. "
            "Ensure wkhtmltopdf is installed in the container or host and visible to the process. "
            "See README for Dockerfile changes or install instructions. Error: " + str(e)
        ))
    except Exception as e:
        raise HTTPException(status_code=500, detail=(
            "PDF generation failed with an unexpected error: " + str(e)
        ))

    # Save PDF path and generation timestamp in MongoDB
    results.update_one({"_id": req.scan_id}, {"$set": {"report_pdf_path": pdf_path, "report_generated_at": datetime.utcnow().isoformat()}})

    # Also generate JSON report file for API consumers (kept for backward compatibility)
    report_file_path = agent.generate_report(req.scan_id)

    # Return the PDF file
    return FileResponse(pdf_path, filename="report.pdf", media_type="application/pdf")
