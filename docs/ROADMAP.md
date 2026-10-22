# Development roadmap
- v1.1: engagement authorization expiry, explicit program policy version, asynchronous jobs and cancellation, stronger tool timeout enforcement.
- v1.2: scope-aware opt-in HTTP checks, Nuclei/ZAP integrations with rate limits and manual approval.
- v1.3: interactive attack surface graph, evidence attachments, timeline, export/import.
- v1.4: CVSS scoring, PDF export, structured HackerOne/Bugcrowd templates.
- v1.5: local authentication, role controls, encryption-at-rest, AI-assisted duplicate triage.

# Scope model
Scope accepts DNS hostnames and `*.domain` wildcards. Subdomains do not implicitly include their parent. CBBHF does not attempt to prove ownership of submitted scope entries. The operator is responsible for verifying current program authorization.
