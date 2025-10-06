# SecureCodeGuardian

SecureCodeGuardian is an MVP **code review agent** built with FastAPI, Agno AgentOS, Pydantic, MongoDB, Docker, Docker Compose, Streamlit, and Jinja2 PDF reporting. It scans code snippets or entire repositories for vulnerabilities, suggests mitigations, and generates vulnerability-free code. Results and metrics are stored in MongoDB and visualized via a Streamlit dashboard.

## Features

- **Snippet Scan**: Submit a code snippet and receive vulnerabilities + mitigated code.
- **Repo Scan**: Scan a Git repository URL, produce vulnerability report and fixes for each file.
- **PDF Reporting**: Generate a comprehensive PDF report using Jinja2 templates.
- **Metrics Dashboard**: Real-time dashboard for total scans and vulnerability distribution.
- **AgentOS Integration**: Uses Agno’s pre-built FastAPI and control plane for monitoring.

## Architecture

- **FastAPI** backend (`/backend`) – API endpoints, agent core logic, PDF generation.
- **Streamlit** dashboard (`/dashboard`) – Metrics visualization.
- **MongoDB** – Stores scan results and metrics.
- **Agno AgentOS** – Orchestrates analysis & remediation tasks.
- **Docker & Docker Compose** – Containerized services for easy deployment.

### Architecture diagram (Mermaid)

Below is a mermaid diagram that illustrates the main components and data flow of the application. If your Markdown renderer supports Mermaid (GitHub/GitLab or VS Code with the Mermaid plugin), the diagram will render inline.

```mermaid
flowchart LR
  subgraph DockerCompose[Docker Compose]
    direction TB
    API[FastAPI (backend)]
    Worker[Celery Worker]
    Redis[Redis (Broker)]
    Mongo[MongoDB]
    Dashboard[Streamlit Dashboard]
  end

  User[User / Client]
  Git[Git Repository]
  PDFGen[PDFKit / Jinja2]

  User -->|POST /scan/snippet| API
  User -->|POST /scan/repo| API
  API -->|enqueue task (task_id)| Worker
  API -->|read/write| Mongo
  Worker -->|use broker| Redis
  Worker -->|store results| Mongo
  API -->|GET /scan/status| Mongo
  API -->|POST /report| Mongo
  API -->|generate HTML & call| PDFGen
  PDFGen -->|write file path| Mongo
  API -->|serve PDF| User
  Dashboard -->|read metrics| Mongo
  API -->|clone repo| Git

  classDef infra fill:#f9f,stroke:#333,stroke-width:1px;
  class API,Worker,Redis,Mongo,Dashboard infra
```

This diagram shows the primary interactions:

- Clients submit snippet or repo scan requests to the FastAPI backend.
- For repo scans, the backend enqueues a Celery task (Redis as broker). A Celery worker performs the scan, writes findings to MongoDB, and optionally updates task progress.
- The FastAPI `report` endpoint renders a Jinja2 template to HTML and uses PDFKit to produce a PDF file; the PDF path and timestamp are stored in MongoDB and the PDF is returned to the client.
- The Streamlit dashboard reads metrics directly from MongoDB to visualize totals and distributions.

# CodeGuardian API Testing

## API Endpoints Testing
Use insomnia/postman/curl to test

### 1. Scan Code Snippet
```bash
curl -X POST http://localhost:8000/scan/snippet \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"admin123\"\nprint(f\"Password is {password}\")",
    "language": "python"
  }'
```

### 2. Scan Git Repository
```bash
curl -X POST http://localhost:8000/scan/repo \
  -H "Content-Type: application/json" \
  -d '{
    "git_url": "https://github.com/username/repository"
  }'
```

### 3. Generate Security Report
```bash
curl -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{
    "scan_id": "your-scan-id-here"
  }' \
  --output report.pdf
```

### 4. Full curl examples (expanded)

Below are copy-paste-ready examples showing request and response handling for each endpoint. Replace values like <scan_id> and <git_url> as appropriate.

- Scan a code snippet (returns JSON):

```bash
curl -sS -X POST http://localhost:8000/scan/snippet \
  -H "Content-Type: application/json" \
  -d '{
    "code": "password = \"admin123\"\nprint(f\"Password is {password}\")",
    "language": "python"
  }'
```

Sample output (truncated):

```json
{
  "target": "snippet",
  "vulnerabilities": [ ... ],
  "mitigated_code": "..."
}
```

- Start a repository scan (async) — returns a MongoDB document with a generated `scan_id`:

```bash
curl -sS -X POST http://localhost:8000/scan/repo \
  -H "Content-Type: application/json" \
  -d '{ "git_url": "https://github.com/username/repository" }'
```

Example response (contains `scan_id` you'll use to poll status and request reports):

```json
{
  "_id": "<scan_id>",
  "git_url": "https://github.com/username/repository",
  "status": "QUEUED",
  "task_id": "<celery-task-id>",
  "created_at": "2025-10-05T12:34:56.789Z"
}
```

- Poll scan status using the returned `scan_id`:

```bash
curl -sS http://localhost:8000/scan/status/<scan_id>
```

Sample response (includes DB document and optional Celery task state):

```json
{
  "db_doc": { /* full MongoDB document for the scan (findings, summary, status, task_id) */ },
  "task_state": "STARTED",
  "task_result": null
}
```

- Generate/download the PDF report for a finished scan:

```bash
curl -sS -X POST http://localhost:8000/report \
  -H "Content-Type: application/json" \
  -d '{ "scan_id": "<scan_id>" }' \
  --output report.pdf
```

Notes:
- If the API is not on localhost or uses a different port (e.g., when running behind a reverse proxy or Docker), update the host/port accordingly.
- The `/scan/repo` endpoint is asynchronous: expect a DB document with a `task_id` that corresponds to a Celery worker job. Poll `/scan/status/<scan_id>` to follow progress.
- The `report` endpoint returns a PDF file and also writes the PDF path into the MongoDB document under `report_pdf_path`.

Important: PDF generation dependency

- This project uses `pdfkit` which requires the `wkhtmltopdf` binary to generate PDFs. If you see errors like "No wkhtmltopdf executable found" in the backend logs, make sure the backend image has `wkhtmltopdf` installed.

To rebuild the backend image with wkhtmltopdf (Docker Compose):

```bash
docker compose up -d --build backend
```

If not using Docker, install `wkhtmltopdf` on the host (macOS/Linux) or ensure the binary path is provided to `pdfkit.configuration`.

Notes about architectures and wkhtmltopdf

- Some base images / Debian repositories do not provide `wkhtmltopdf` packages for all CPU architectures (for example, arm64 builds often lack a wkhtmltopdf package). If your Docker build fails with "Package 'wkhtmltopdf' has no installation candidate", you are likely building on an unsupported architecture.

Options to get wkhtmltopdf working:

1. Build an amd64 image (runs on amd64 or via emulation):

```bash
# Build and run backend for amd64 using buildx (requires Docker buildx enabled)
docker buildx build --platform linux/amd64 -t codeguardian-backend:amd64 backend/ --load
docker run --rm -p 8000:8000 codeguardian-backend:amd64
```

2. Use a custom image that already bundles wkhtmltopdf.

3. Mount the host wkhtmltopdf binary into the container (not recommended for production but useful for development).

4. Replace pdfkit/wkhtmltopdf with a headless Chromium-based PDF renderer (Playwright/Chromium) — requires code changes but is multi-arch friendly.

## Sample Responses

### Snippet Scan Response
```json
{
  "target": "snippet",
  "vulnerabilities": [
    {
      "id": "SEC001",
      "description": "Hardcoded password in source code",
      "severity": "HIGH",
      "location": "line 1",
      "recommendation": "Use environment variables or secure vault for sensitive data"
    }
  ],
  "mitigated_code": "import os\npassword = os.getenv('PASSWORD')\nprint(f\"Password is {'*' * len(password)}\")"
}
```

### Repository Scan Response
```json
{
  "target": "https://github.com/username/repository",
  "vulnerabilities": [
    {
      "id": "SEC002",
      "description": "SQL Injection vulnerability",
      "severity": "CRITICAL",
      "location": "src/database.py:23",
      "recommendation": "Use parameterized queries"
    }
  ],
  "mitigated_code": {
    "src/database.py": "... secure version of the code ..."
  }
}
```

## Notes
- Replace `localhost:8000` with your actual API server address
- The `scan_id` in the report generation request should be obtained from a previous scan response
- Reports are generated as PDF files
- All endpoints expect and return JSON data (except report endpoint which returns a PDF file)

## Status Endpoint (new)

You can check the status of a repository scan using the `scan_id` returned by the `/scan/repo` endpoint.

Endpoint:

GET /scan/status/{scan_id}

Example:

```bash
curl http://localhost:8000/scan/status/<scan_id>
```

Response (example):

```json
{
  "db_doc": { /* full MongoDB document for the scan */ },
  "task_state": "STARTED",
  "task_result": null
}
```

Notes:
- `db_doc` contains the stored scan document (findings, summary, status, task_id).
- If the `db_doc` contains `task_id`, the `task_state` will reflect the Celery task state (PENDING, STARTED, SUCCESS, FAILURE, etc.).

## Running the full stack (with Celery + Redis)

The project uses Docker Compose to run the API, MongoDB, Redis and a Celery worker. To start everything:

```bash
docker compose up -d --build
```

Watch Celery worker logs:

```bash
docker compose logs -f celery_worker
```

Trigger a repo scan and poll status:

```bash
# Start a scan
curl -X POST http://localhost:8000/scan/repo -H 'Content-Type: application/json' -d '{"git_url":"https://github.com/username/repo"}'

# Poll status
curl http://localhost:8000/scan/status/<scan_id>
```

If you want progress recorded into the MongoDB document during scanning (clone started, per-file errors, etc.) or a simplified status payload, I can add that next.
