# CBBHF v1.0 — Cyber Bug Bounty Hunting Framework

A **local-only** Kali Linux bug bounty workflow console: engagement tracking, explicit scope allowlists, passive subdomain discovery, findings, audit log, printable HTML reporting, and a clean light-themed UI.

## Requirements
- Kali Linux with Python 3.11–3.13, python3-venv and pip
- Optional: `subfinder` or `amass` in PATH for passive discovery
- Do **not** expose the local web service to the internet; it has no login/authentication layer.

## Install
```bash
sudo apt update
sudo apt install -y python3 python3-venv python3-pip
unzip cbbhf-v1.0-kali.zip
cd cbbhf
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
python -m pytest -q
./run.sh
```
Open http://127.0.0.1:8765 in your Kali browser.

## Use
1. Read program rules, obtain authorization, and record policy URL and written authorization summary.
2. Enter exact DNS names and/or explicit wildcard entries in scope. Wildcard `*.example.org` **does not** include the apex `example.org`.
3. Engagements begin STOPPED. Activate only while the authorization remains valid.
4. Add in-scope assets manually. If the program permits passive subdomain discovery, optionally run Subfinder or Amass.
5. Record findings with sanitized evidence. Export the printable report using the report button and browser Print > Save as PDF.
6. Use Emergency Stop to prevent starting further recon. The stop does **not** terminate an already running command in v1.0; wait for its 90-second timeout or terminate the server process. No active probes are supported.

## Safety boundaries
- Only DNS hostnames, not IP ranges, ports, URLs, or arbitrary shell commands.
- Passive recon requires one explicit apex domain and optional matching wildcard; every returned hostname is rechecked against the allowlist.
- No mass scanning, brute force, payload exploitation, automated vulnerability scans, credential collection, or HTTP probing.
- Tool invocation uses fixed argv lists (`shell=False`), 90-second timeout, and output cap of 5000 lines.
- No automated report submission or target interaction beyond the selected passive tool's behavior. Check each tool's upstream behavior and program restrictions before use.
- Local dashboard has **no authentication**. It binds only to loopback. Treat SQLite data as sensitive; protect your VM and disk.
- Avoid storing secrets, personal data, session cookies, or unauthorized customer records in findings.

## Tool installation
Use Kali's package manager or the tools' official release instructions. `command -v subfinder` and `command -v amass` verify availability. No third-party tool is bundled.

## Interactive demo
Open `docs/demo.html` directly in a browser (no server or install needed) for a guided, fully simulated walkthrough: scope allowlist, gated passive recon, emergency stop, scanner import triage, evidence vault, and the printable report. It uses example data only and makes no network requests to targets.

## API
Interactive API reference: http://127.0.0.1:8765/api/docs

## Database
Default `./cbbhf.sqlite3`, override with `CBBHF_DB=/secure/path/file.sqlite3`.

## Limitations
v1.0 is a functional local MVP, not an enterprise scanner. It does not include login, role management, scheduling, cancellation of in-flight jobs, a PDF engine, CVSS calculator, or active Nuclei/ZAP integrations. See `docs/ROADMAP.md`.

## v1.1 upgrade: background jobs, graph, evidence
The dashboard now starts passive discovery through `/api/engagements/{id}/jobs`, displays progress, and supports cancellation. Emergency Stop also requests termination of in-flight jobs. Cancellation is best effort (SIGTERM) and may take time; no new discovered assets are committed for cancelled jobs. Job states persist in SQLite. On unexpected application shutdown, running jobs may remain marked `running` in SQLite until manually reconciled; do not assume they are active. One background job per engagement is supported per process. Avoid multiple Uvicorn workers.

The attack-surface SVG uses stored assets and findings and performs **no network traffic**. It shows the first 120 nodes and may need scrolling for large inventories. Evidence uploads accept only TXT, MD, JSON, PNG, JPG, or PDF, maximum 5 MiB, and store files under `private_evidence/` with restrictive permissions. Files are downloaded as attachments; SHA-256 checksums are recorded. File type checks are basic signature/extension checks, not antivirus or content sanitization. **Do not upload secrets or personal data.**

**Important:** The local web service has no authentication. Keep it on 127.0.0.1 and use a dedicated, encrypted Kali VM. The legacy synchronous `/recon` endpoint remains for compatibility but does not support cancellation; use `/jobs` instead. v1.1 is not production multi-user software.

For upgrades from v1.0, stop the old process, back up `cbbhf.sqlite3`, then replace the application files and run `./run.sh`. New tables are created automatically. Install updated dependencies with `python -m pip install -r requirements.txt`.

## v1.2 — Offline scanner integration and validation

The dashboard now imports **Nuclei JSONL**, **OWASP ZAP JSON**, and **normalized Burp JSON** exports. It rejects out-of-scope hostnames and creates **Draft** findings only. An analyst must manually validate each observation; the dashboard provides a **Validate** action with a review note. **No active scanner execution is added in v1.2.** See `docs/V1_2_INTEGRATIONS.md` for schemas, limitations, and the review workflow. Example exports are under `examples/`.
