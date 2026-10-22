# CBBHF v1.2 — Scanner export integrations

## Safety model

CBBHF v1.2 **does not execute** Nuclei, ZAP, or Burp against targets. It imports previously generated scanner exports offline. Obtain authorization, check the program's automated-testing policy, and run any external tool separately in accordance with those rules. An imported result is always **Draft**, not a confirmed vulnerability. The import rejects observations whose hostnames do not match the engagement's DNS allowlist. This does not independently verify authorization.

## Nuclei

Export Nuclei JSONL (one JSON object per line) using your approved workflow. Choose **Nuclei JSONL** in the dashboard. CBBHF reads `matched-at` (or `host`), `info.name`, `info.severity`, `info.description`, and `template-id`.

## OWASP ZAP

Export the traditional ZAP JSON report with a top-level `site` list containing `alerts` lists. Choose **OWASP ZAP JSON report**. CBBHF uses the first `instances[].uri` as the affected URL when present, otherwise the site's `@name`.

## Burp Suite

Burp's native XML export is not accepted. Use a Burp extension or offline conversion that produces a JSON object with an `issues` list, or a JSON array. Each issue needs `name`, `severity`, and `url` (or `host`), with optional `description`. See `examples/burp-normalized.json`. Do not paste secrets, cookies, or live tokens into exported data.

## Review workflow

1. Create an engagement with the exact permitted DNS hosts and optional wildcard entries.
2. Review the source program's rules and obtain authorization.
3. Import an export file up to 2 MiB and 500 observations.
4. Check rejected entries and verify that accepted observations are relevant.
5. Reproduce each finding with authorized test accounts and minimal impact.
6. Use **Validate** to record a manual analyst note; only then mark it validated.
7. Open the printable HTML report and submit findings through the program's required channel.

## Limitations

The dashboard is a single-user localhost-only tool with no authentication. Do not expose port 8765 beyond the Kali VM. Exports can contain sensitive information; store and delete them according to program requirements. v1.2 does not deduplicate findings, parse native Burp XML, sanitize HTML in descriptions imported from ZAP (report output is HTML-escaped), or automatically score CVSS. Large import requests are bounded by application checks, but a reverse proxy is recommended for stricter request-size enforcement. A scanner's risk label is not proof of exploitability.
