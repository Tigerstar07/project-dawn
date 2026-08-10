# Project Dawn Model And Scanner Architecture

## Core Principle

The local model should not be trusted as the vulnerability scanner. Smaller open-source models are useful as planners, explainers, prioritizers, and report writers. Deterministic modules and specialist tools should collect evidence.

## Pipeline

1. Scope Gate
   - Requires explicit authorization.
   - Normalizes the target.
   - Blocks active probes unless the target is localhost, loopback, or private RFC1918 space.

2. Evidence Collection
   - Fetches the entry page.
   - Crawls a bounded number of same-origin links.
   - Fetches bounded JavaScript assets.
   - Checks a bounded sensitive-path list for serious exposure.
   - Runs selected passive modules.
   - Optionally runs active lab probes on local/private lab targets only.

3. Evidence Files
   - Writes `passive-scan`, `findings`, and `report` artifacts.
   - The files are the model memory.
   - Future model calls read these files instead of depending on one long context window.

4. Local Model Pass
   - Reads the evidence files.
   - Produces a concise brief, fix priorities, and operator answer.
   - Must not invent vulnerabilities that are not in evidence.

5. Critic Pass
   - The next iteration should add a second model pass that checks whether each claim has evidence.
   - Claims without evidence should be moved to "needs manual validation."

## Why This Works Better

An LLM is weak at reliable vulnerability discovery from scratch. It is stronger when given structured observations:

- URL inventory
- Input and redirect parameters
- Form fields
- Response headers
- Cookie flags
- Exposed files and debug endpoints
- JavaScript endpoints and secret-like patterns
- Scanner output from ZAP or Nuclei when those adapters are added

## Current Modules

- Transport checks
- Header checks
- Cookie checks
- Form checks
- Mixed-content checks
- Injection surface mapping
- Client-secret scanning
- Stack exposure checks
- Client asset/API route extraction
- Dangerous exposure path checks
- Active lab probes for local/private targets

## Active Lab Boundary

Active lab mode is intentionally restricted. It may send non-destructive probes to localhost or private lab hosts to validate reflection, SQL/error signals, and open redirect behavior. It does not run against public internet targets, does not brute force, does not bypass authentication, and does not extract data.

## Future Tool Adapters

Use external security tools as evidence providers:

- OWASP ZAP Baseline for spider plus passive scanning.
- Nuclei for template-based vulnerability checks.
- OSV or similar vulnerability databases for package/dependency risk.

The model should ingest their JSON/Markdown output and turn it into prioritized remediation guidance.

## References

- OWASP Web Security Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- OWASP Top 10 Injection: https://owasp.org/Top10/2021/A03_2021-Injection/
- ZAP Baseline Scan: https://www.zaproxy.org/docs/docker/baseline-scan/
- ProjectDiscovery Nuclei Templates: https://docs.projectdiscovery.io/templates/introduction
