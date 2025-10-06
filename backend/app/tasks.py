from datetime import datetime
import tempfile
import subprocess
import shutil
import os
import json
from .db import results
from .celery_app import celery


@celery.task(bind=True)
def scan_repository(self, scan_id: str = None, git_url: str = None, local_path: str = None):
    """Celery task to scan a git repository"""
    temp_dir = None
    try:
        # Clone repository if git_url is provided
        if git_url:
            temp_dir = tempfile.mkdtemp()
            clone_command = f"git clone {git_url} {temp_dir}"
            process = subprocess.run(clone_command, shell=True, capture_output=True, text=True)
            if process.returncode != 0:
                raise Exception(f"Failed to clone repository: {process.stderr}")
            scan_path = temp_dir
        elif local_path and os.path.exists(local_path):
            scan_path = local_path
        else:
            results.update_one(
                {"_id": scan_id},
                {"$set": {"status": "failed", "error": "No valid repository path provided"}}
            )
            return

        # Import here to avoid circular imports
        from .agents import SecurityAgent
        agent = SecurityAgent()

        # Perform the scan
        collected = []
        for root, _, files in os.walk(scan_path):
            for fn in files:
                if fn.endswith((".py", ".js", ".php")):
                    fp = os.path.join(root, fn)
                    try:
                        with open(fp, "r", encoding="utf-8") as fh:
                            content = fh.read()
                            # Get pattern-based findings
                            pattern_findings = agent._scan_code_text(content)
                            # Get AI-based analysis
                            ai_findings = agent._analyze_vulnerabilities(content, fp.split(".")[-1])
                            try:
                                ai_vulns = json.loads(ai_findings)
                            except:
                                ai_vulns = []
                            
                            if pattern_findings or (isinstance(ai_vulns, list) and ai_vulns):
                                collected.append({
                                    "file": os.path.relpath(fp, scan_path),
                                    "pattern_findings": pattern_findings,
                                    "ai_findings": ai_vulns if isinstance(ai_vulns, list) else []
                                })
                    except Exception as e:
                        print(f"Error processing {fp}: {str(e)}")
                        continue

        # Update with results
        summary = {
            "total_files_scanned": sum(1 for _ in os.walk(scan_path) for f in _[2] if f.endswith((".py", ".js", ".php"))),
            "total_files_with_findings": len(collected),
            "total_findings": sum(len(f["pattern_findings"]) + len(f["ai_findings"]) for f in collected)
        }
        results.update_one(
            {"_id": scan_id},
            {"$set": {
                "findings": collected,
                "summary": summary,
                "status": "completed",
                "completed_at": datetime.utcnow().isoformat()
            }}
        )

    except Exception as e:
        error_msg = str(e)
        results.update_one(
            {"_id": scan_id},
            {"$set": {"status": "failed", "error": error_msg}}
        )

    finally:
        # Clean up temporary directory if it was created
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir, ignore_errors=True)