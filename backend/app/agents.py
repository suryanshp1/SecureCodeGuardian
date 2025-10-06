from agno.agent import Agent
from agno.models.openai import OpenAIChat
from agno.tools import tool
from .models import CodeSnippet, RepoScanRequest, ScanResult, Vulnerability
from datetime import datetime
import os
import json
import uuid
import re
import tempfile
import shutil
from typing import List, Dict, Any
import subprocess

from .db import results

class SecurityAgent:
    def __init__(self):
        # Agent is used internally to run prompts — no tools needed for direct calls
        self.agent = Agent(
            name="SecurityAnalyzer",
            model=OpenAIChat(id="gpt-4o"),
            instructions=[
                "You are a senior application security engineer.",
                "Analyze code for OWASP Top 10 vulnerabilities.",
                "Return findings in strict JSON when requested.",
                "Provide only code when asked to fix it."
            ],
            markdown=False,
        )

        # future: init scanners, rules, threadpool, etc.
        self.patterns = {
            "eval_exec": re.compile(r"\b(eval|exec)\s*\("),
            "os_system": re.compile(r"\b(os\.system|subprocess\.Popen|subprocess\.call)\b"),
            "pickle_loads": re.compile(r"\b(pickle\.loads|pickle\.load)\b"),
            "hardcoded_secret": re.compile(r"(API_KEY|SECRET|PASSWORD)\s*[:=]\s*['\"].{4,}['\"]"),
            "unsafe_input": re.compile(r"\binput\s*\("),
        }

    def _analyze_vulnerabilities(self, code: str, language: str) -> str:
        """Internal method: returns raw JSON string of vulnerabilities"""
        prompt = f"""
        Analyze the following {language} code for security vulnerabilities.
        Return a JSON array. Each object must have:
        - "id": e.g., "SQL_INJECTION_01"
        - "description"
        - "severity": "high", "medium", or "low"
        - "mitigation"

        Code:
        {code}

        Respond ONLY with valid JSON. No markdown, no extra text.
        """
        response = self.agent.run(prompt)
        return response.content

    def _generate_secure_code(self, code: str, language: str) -> str:
        """Internal method: returns fixed code as string"""
        prompt = f"""
        Rewrite the following {language} code to fix all security vulnerabilities.
        Return ONLY the fixed code. No explanations.

        Original code:
        {code}
        """
        response = self.agent.run(prompt)
        return self._extract_code_block(response.content)

    def _scan_code_text(self, code: str) -> List[Dict[str, Any]]:
        findings = []
        for i, line in enumerate(code.splitlines(), start=1):
            for name, pattern in self.patterns.items():
                if pattern.search(line):
                    findings.append({
                        "rule": name,
                        "line": i,
                        "snippet": line.strip()
                    })
        return findings

    def scan_code(self, snippet: CodeSnippet) -> ScanResult:
        # Step 1: Get vulnerabilities
        vuln_response = self._analyze_vulnerabilities(snippet.code, snippet.language)
        try:
            vuln_response = self._extract_code_block(vuln_response)
            vulns_data = json.loads(vuln_response)
            if not isinstance(vulns_data, list):
                vulns_data = []
        except json.JSONDecodeError as e:
            print(f"JSON decode error: {e}")
            print(f"Raw response: {vuln_response}")
            vulns_data = []

        vulnerabilities = [
            Vulnerability(
                id=v.get("id", "UNKNOWN"),
                description=v.get("description", "No description"),
                severity=v.get("severity", "medium"),
                mitigation=v.get("mitigation", "No mitigation provided")
            )
            for v in vulns_data
        ]

        # Step 2: Generate mitigated code
        mitigated_code = self._generate_secure_code(snippet.code, snippet.language)

        return ScanResult(
            target="snippet",
            vulnerabilities=vulnerabilities,
            mitigated_code=mitigated_code
        ).model_dump()

    def scan_repo(self, req: RepoScanRequest) -> Dict[str, Any]:
        """
        Support scan of a repository. Creates a scan record and delegates to a Celery task.
        Returns immediately with a scan_id that can be used to check status.
        """
        scan_id = uuid.uuid4().hex
        git_url = getattr(req, "git_url", None)
        local_path = getattr(req, "path", None)
        
        doc = {
            "_id": scan_id,
            "type": "repo",
            "repo": git_url or local_path,
            "findings": [],
            "summary": {},
            "status": "queued",
            "created_at": datetime.utcnow().isoformat()
        }
        # Insert record and queue task
        results.insert_one(doc)
        
        # Import here to avoid circular imports
        from .tasks import scan_repository
        # Call task with all parameters as keyword arguments
        task = scan_repository.delay(
            scan_id=scan_id,
            git_url=git_url,
            local_path=local_path
        )
        
        # Update doc with task id for tracking
        results.update_one(
            {"_id": scan_id}, 
            {"$set": {"task_id": task.id}}
        )
        
        return {
            "scan_id": scan_id,
            "status": "queued",
            "message": "Repository scan has been queued"
        }

    def generate_report(self, scan_id: str) -> str:
        """
        Generate a JSON report file from the MongoDB doc and update the document with the report path.
        Returns the path to the generated JSON file.
        """
        doc = results.find_one({"_id": scan_id})
        if not doc:
            raise ValueError("Scan not found")

        report_dir = "/tmp"
        os.makedirs(report_dir, exist_ok=True)
        report_path = os.path.join(report_dir, f"report_{scan_id}.json")
        # Ensure we don't include Mongo-specific objects; doc already uses primitive _id (string)
        with open(report_path, "w", encoding="utf-8") as fh:
            json.dump(doc, fh, default=str, indent=2)

        results.update_one({"_id": scan_id}, {"$set": {"report_path": report_path, "report_generated_at": datetime.utcnow().isoformat()}})
        return report_path

    def _extract_code_block(self, text: str) -> str:
        # Remove markdown code fences
        match = re.search(r"```(?:\w+)?\n?(.*?)```", text, re.DOTALL)
        if match:
            return match.group(1).strip()
        return text.strip()