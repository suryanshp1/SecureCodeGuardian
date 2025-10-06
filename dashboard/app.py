import streamlit as st
from pymongo import MongoClient
import pandas as pd
import os, json, requests
from datetime import datetime

# API configuration
API_URL = os.getenv("API_URL", "http://backend:8000")

def call_api(endpoint: str, method: str = "GET", json_data: dict = None) -> dict:
    """Helper to call backend API endpoints with error handling."""
    try:
        url = f"{API_URL}{endpoint}"
        if method == "GET":
            response = requests.get(url)
        else:
            response = requests.post(url, json=json_data)
        
        response.raise_for_status()
        return response.json() if response.headers.get("content-type", "").startswith("application/json") else {}
    except requests.RequestException as e:
        st.error(f"API error: {str(e)}")
        return None

def download_report(scan_id: str):
    """Download PDF report for a scan."""
    try:
        response = requests.post(
            f"{API_URL}/report/",
            json={"scan_id": scan_id},
            stream=True
        )
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        st.error(f"Failed to download report: {str(e)}")
        return None

# Use the same MONGO_URI and database/collection as backend
MONGO_URI = os.getenv("MONGO_URI", "mongodb://mongo:27017")
client = MongoClient(MONGO_URI)
db = client.get_database("codeguardian")
results = db.get_collection("results")

st.title("SecureCodeGuardian Metrics")

# ---- Controls / Sidebar ----
st.sidebar.title("Controls")

# Scan Controls
with st.sidebar.expander("New Code Snippet Scan", expanded=True):
    code = st.text_area("Code to scan", height=150)
    language = st.selectbox("Language", ["python", "javascript", "java", "php"])
    if st.button("Scan Snippet"):
        if code:
            with st.spinner("Scanning code..."):
                result = call_api("/scan/snippet/", "POST", {"code": code, "language": language})
                if result:
                    st.success("Scan completed!")
                    # Show results in main area
                    with st.expander("Scan Results", expanded=True):
                        if "vulnerabilities" in result:
                            st.write("Found vulnerabilities:", len(result["vulnerabilities"]))
                            for v in result["vulnerabilities"]:
                                st.warning(f"**{v.get('id')} ({v.get('severity', 'UNKNOWN')})**\n\n"
                                         f"{v.get('description')}\n\n"
                                         f"*Mitigation: {v.get('mitigation', 'N/A')}*")
                        if "mitigated_code" in result:
                            st.subheader("Mitigated Code")
                            st.code(result["mitigated_code"], language=language)
        else:
            st.warning("Please enter some code to scan")

with st.sidebar.expander("New Repository Scan"):
    repo_url = st.text_input("Git Repository URL")
    scan_id_input = st.text_input("Or check existing scan ID")
    
    col1, col2 = st.columns(2)
    with col1:
        if st.button("Scan Repository"):
            if repo_url:
                with st.spinner("Starting repository scan..."):
                    result = call_api("/scan/repo", "POST", {"git_url": repo_url})
                    if result:
                        scan_id = result.get("scan_id")
                        st.success(f"Scan queued! ID: {scan_id}")
                        st.info("The scan will run in the background. Use the filters below to track its status.")
            else:
                st.warning("Please enter a repository URL")
    
    with col2:
        if st.button("Check Status") and scan_id_input:
            with st.spinner("Checking status..."):
                status = call_api(f"/scan/status/{scan_id_input}")
                if status:
                    st.json(status)
                    if status.get("task_state") == "SUCCESS":
                        if st.button("Generate Report"):
                            pdf_content = download_report(scan_id_input)
                            if pdf_content:
                                st.download_button(
                                    "Download PDF",
                                    pdf_content,
                                    file_name=f"report_{scan_id_input}.pdf",
                                    mime="application/pdf"
                                )

st.sidebar.header("Filters")
refresh = st.sidebar.button("Refresh data")
status_filter = st.sidebar.multiselect("Status", options=["queued", "completed", "failed", "unknown"], default=["completed", "queued", "failed", "unknown"])
severity_filter = st.sidebar.multiselect("Severity", options=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"], default=["CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN"])

# Fetch data (allow refresh button to re-run)
docs = list(results.find())

# Apply status filter
filtered_docs = [d for d in docs if d.get("status", "unknown") in status_filter]

# Totals
st.metric("Total Scans (filtered)", len(filtered_docs))

# Status breakdown
status_counts = {}
for d in filtered_docs:
    s = d.get("status", "unknown")
    status_counts[s] = status_counts.get(s, 0) + 1
if status_counts:
    st.subheader("Scan Statuses")
    st.write(status_counts)

# Build normalized vulnerability list with metadata (scan_id, file, date)
vuln_rows = []
scan_dates = []
for d in filtered_docs:
    scan_id = d.get("_id")
    created = d.get("created_at")
    scan_dates.append(created)

    # snippet-style
    for v in d.get("vulnerabilities", []):
        sev = (v.get("severity") or "UNKNOWN").upper()
        if sev in severity_filter:
            vuln_rows.append({
                "scan_id": scan_id,
                "file": d.get("target", "snippet"),
                "id": v.get("id"),
                "severity": sev,
                "description": v.get("description")
            })

    # repo-style
    for item in d.get("findings", []):
        file_path = item.get("file")
        for pf in item.get("pattern_findings", []):
            sev = "MEDIUM"
            if sev in severity_filter:
                vuln_rows.append({
                    "scan_id": scan_id,
                    "file": file_path,
                    "id": f"PATTERN_{pf.get('rule', 'unknown')}",
                    "severity": sev,
                    "description": pf.get('snippet')
                })
        for av in item.get("ai_findings", []):
            if isinstance(av, dict):
                sev = (av.get("severity") or "UNKNOWN").upper()
                if sev in severity_filter:
                    vuln_rows.append({
                        "scan_id": scan_id,
                        "file": file_path,
                        "id": av.get('id'),
                        "severity": sev,
                        "description": av.get('description')
                    })

df = pd.DataFrame(vuln_rows)

# Vulnerability severity distribution
if not df.empty:
    st.subheader("Vulnerability Severity Distribution")
    st.bar_chart(df["severity"].value_counts())
else:
    st.info("No vulnerabilities match the current filters.")

# Scans per day (time series)
if scan_dates:
    dates = pd.to_datetime([d for d in scan_dates if d is not None])
    if not dates.empty:
        counts_by_day = dates.normalize().value_counts().sort_index()
        st.subheader("Scans per Day")
        st.line_chart(counts_by_day)

# Detailed findings table grouped by file
st.subheader("Detailed Findings")
if df.empty:
    st.write("No findings to display")
else:
    # Allow CSV download
    csv = df.to_csv(index=False)
    st.download_button("Download CSV", csv, file_name="findings.csv", mime="text/csv")

    # Group by file and show expanders
    for file, group in df.groupby("file"):
        with st.expander(f"{file} — {len(group)} findings"):
            findings_table = group[["scan_id", "id", "severity", "description"]]
            st.table(findings_table)
            
            # Add report download button for each unique scan
            scan_ids = group["scan_id"].unique()
            for sid in scan_ids:
                if st.button(f"Download Report (Scan {sid})", key=f"report_{sid}"):
                    with st.spinner("Generating report..."):
                        pdf_content = download_report(sid)
                        if pdf_content:
                            st.download_button(
                                "Download PDF",
                                pdf_content,
                                file_name=f"report_{sid}.pdf",
                                mime="application/pdf",
                                key=f"dl_{sid}"
                            )
