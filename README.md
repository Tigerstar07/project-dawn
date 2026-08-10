# Project Dawn

Project Dawn is a local-first AI workspace and consent-gated passive web security scanner. It combines deterministic evidence collection with a locally hosted Ollama model that summarizes findings without inventing them.

The scanner is intended only for websites you own or are authorized to assess. It does not run exploit payloads against public targets.

## Highlights

- File-backed AI workspaces that preserve context between model calls.
- A long-running local agent with checkpoints, compressed memory and a JSONL journal.
- Ollama integration with streaming output and configurable local models.
- Passive checks for HTTPS, headers, cookies, forms, mixed content and exposed metadata.
- Static client-side analysis for dangerous sinks, source maps, API routes and possible secret exposure.
- Markdown reports with observed evidence and remediation priorities.
- Guarded shell and project-edit capabilities that are disabled by default.
- Local/private-target gating for the small set of active lab checks.

## Run locally

```bash
npm ci
ollama pull dolphin3:8b-llama3.1-q4_K_M
npm run dev
```

Open `http://localhost:4177`.

You can choose a different installed Ollama model in the UI or configure `OLLAMA_BASE_URL` for another local endpoint.

## Long-running agent

The CLI runner keeps a durable workspace and can continue across many model calls:

```bash
npm run agent:long -- --goal "Review the scanner architecture and propose improvements" --iterations 25
```

Project source edits require the explicit `--allow-project-edits` flag. Shell access requires `--allow-shell`. Environment files, Git metadata, dependencies and generated data remain outside the writable scope.

## Scanner coverage

- Transport security and common security headers
- Cookie and form-security signals
- Mixed-content and source-map exposure
- Client-delivered API routes and sensitive comments
- DOM XSS sinks and unguarded `postMessage` handlers
- Hardcoded credential patterns in delivered JavaScript
- Common accidental exposures such as `.env`, `.git/config`, database dumps, Swagger and GraphQL endpoints

The local model only summarizes deterministic findings. It is instructed to stay within the observed evidence.

## Architecture

```text
server/
  agents/       Ollama client and file-backed workspace loop
  scanner/      Passive checks and scan orchestration
  reports/      Markdown report generation
  utils/        Shared HTTP and file helpers
src/            React interface
docs/           Architecture and safety notes
data/           Local generated workspaces and reports
```

## Build

```bash
npm ci
npm run build
```

## Responsible use

Use Project Dawn only on systems you own or have written authorization to test. The repository is an educational defensive engineering prototype, not a replacement for a professional security assessment.

