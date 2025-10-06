from pydantic import BaseModel, Field
from typing import List, Dict

class CodeSnippet(BaseModel):
    language: str = Field(..., example="python")
    code: str

class RepoScanRequest(BaseModel):
    git_url: str

class Vulnerability(BaseModel):
    id: str
    description: str
    severity: str
    mitigation: str

class ScanResult(BaseModel):
    target: str
    vulnerabilities: List[Vulnerability]
    mitigated_code: str = None

class ReportRequest(BaseModel):
    scan_id: str