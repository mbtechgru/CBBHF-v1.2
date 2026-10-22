# CBBHF v1.1 Operations

## Scope and authorization
1. Read program policy and record authorization summary and HTTPS policy URL.
2. Enter explicit in-scope hostnames and wildcard entries (wildcards exclude apex).
3. Activate the engagement only during the permitted testing window.
4. Confirm the program permits third-party passive reconnaissance sources before starting Subfinder or Amass.
5. Use only synthetic, non-sensitive evidence and submit reports through the program's approved channel.

## Background discovery
The Jobs panel starts passive reconnaissance and returns immediately. Status changes from running to completed, failed, or cancelled. The dashboard refreshes the job list every four seconds. A stop requests cancellation of running jobs and blocks new jobs. External tools can take a moment to exit; if the service is killed unexpectedly, inspect process state separately.

## Evidence
Upload text, markdown, JSON, PNG, JPG, or PDF (max 5 MiB). Uploaded files are stored outside the web root. Evidence links force attachment downloads. Files are not scanned for malware; do not open untrusted evidence without appropriate isolation.

## API quick reference
- `GET /api/engagements/{id}/jobs` — recent jobs
- `POST /api/engagements/{id}/jobs` — JSON `{ "tool": "subfinder", "confirm_authorized": true }`
- `POST /api/engagements/{id}/jobs/{job_id}/cancel` — request cancellation
- `GET /api/engagements/{id}/graph` — stored asset/finding graph
- `POST /api/engagements/{id}/evidence` — multipart file upload
- `GET /api/engagements/{id}/evidence` — list evidence metadata
- `GET /api/engagements/{id}/evidence/{evidence_id}` — download evidence

## Security and limitations
Local-only web server without authentication; do not publish it or proxy it onto a network. Use encrypted storage and keep evidence directories private. The original synchronous `/recon` endpoint is retained for backwards compatibility and cannot be cancelled by the new Jobs panel. The graph visualizes known records only; it does not identify real network topology. No active vulnerability scanning is implemented. Only one Uvicorn worker is supported for reliable in-memory job control.
