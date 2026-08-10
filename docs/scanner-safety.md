# Scanner Safety Policy

Project Dawn is intended for defensive use on systems you own or are explicitly authorized to assess.

## Current Safety Defaults

- Authorization checkbox is required.
- Scanner is passive-only.
- One bounded GET request is used for page inspection.
- Response body reads are capped.
- Cookie values are redacted in findings.
- Secret-like values are redacted in findings.
- Injection checks map risky inputs and parameters without sending payloads.
- Active lab probes are blocked unless the target is localhost, loopback, or private RFC1918 space.
- Findings are evidence-based and remediation-focused.

## Do Not Add Without Extra Controls

- Login brute force
- Credential stuffing
- Exploit payload delivery
- SQL injection payload fuzzing
- Cross-site scripting payload fuzzing
- SSRF probing against internal networks
- Directory brute forcing
- Denial-of-service tests
- Vulnerability exploitation or post-exploitation logic

## Requirements For Future Active Modules

Any active module should require:

- Written authorization record
- Target allowlist
- Rate limit
- Maximum request count
- Clear module description
- Dry-run mode
- Audit log
- Stop button
- Legal scope text in generated reports

## Validation Targets

Use local or intentionally vulnerable apps for validation:

- OWASP Juice Shop
- DVWA
- WebGoat
- Local test pages created for one finding type at a time

## Current SQL Injection Coverage

Project Dawn can identify SQLi-relevant surfaces such as query parameters, search fields, ID parameters, filter/sort inputs, and forms that should be validated by an authorized reviewer. Baseline mode does not send SQL payloads. Active lab mode can send bounded non-destructive probes only to localhost/private targets; it does not attempt bypasses, enumerate data, or prove exploitability against public live websites.

## Active Lab Mode

Active lab mode can send non-destructive validation probes to local/private lab targets for reflection, SQL/error-disclosure signals, and open redirect behavior. It is designed for intentionally vulnerable apps, owned staging systems, and private test environments. It is blocked for public internet targets.
