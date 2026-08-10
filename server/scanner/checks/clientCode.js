// Deep, passive static analysis of client-delivered JavaScript.
// We only read code the browser already downloads. We never execute it and
// never send payloads anywhere. The goal is high-signal, low-false-positive
// detection of genuinely risky code patterns so a human can verify them.

const TAINT_SOURCES = /location\.(?:href|search|hash|pathname)|document\.(?:URL|documentURI|referrer|cookie)|window\.name|location\b|\.hash\b/;

// Dangerous sinks. eval / Function constructor are risky on their own.
const HARD_SINKS = [
  { id: "eval", label: "eval()", pattern: /\beval\s*\(/, severity: "medium" },
  { id: "function_ctor", label: "new Function(...)", pattern: /\bnew\s+Function\s*\(/, severity: "medium" },
  { id: "settimeout_string", label: "setTimeout/setInterval with string", pattern: /\bset(?:Timeout|Interval)\s*\(\s*["'`]/, severity: "low" }
];

// These are only flagged when a tainted source also appears in the same file,
// because innerHTML/document.write are extremely common in benign framework code.
const TAINTED_SINKS = [
  { id: "innerhtml", label: ".innerHTML assignment", pattern: /\.innerHTML\s*=/ },
  { id: "outerhtml", label: ".outerHTML assignment", pattern: /\.outerHTML\s*=/ },
  { id: "document_write", label: "document.write()", pattern: /document\.write(?:ln)?\s*\(/ },
  { id: "insert_adjacent", label: "insertAdjacentHTML()", pattern: /\.insertAdjacentHTML\s*\(/ },
  { id: "react_dangerous", label: "dangerouslySetInnerHTML", pattern: /dangerouslySetInnerHTML/ }
];

// High-confidence hardcoded credential formats. Publishable/public keys are
// intentionally excluded to avoid noise.
const TOKEN_PATTERNS = [
  { name: "Google API key", pattern: /\bAIza[0-9A-Za-z_\-]{35}\b/g, severity: "high" },
  { name: "AWS access key id", pattern: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high" },
  { name: "Stripe live secret key", pattern: /\bsk_live_[0-9A-Za-z]{20,}\b/g, severity: "critical" },
  { name: "GitHub token", pattern: /\bgh[pousr]_[0-9A-Za-z]{36,}\b/g, severity: "high" },
  { name: "Slack token", pattern: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, severity: "high" },
  { name: "JSON Web Token", pattern: /\beyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b/g, severity: "medium" },
  { name: "Private key block", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: "high" }
];

export async function analyzeClientCode({ assets, pages, html }) {
  const documents = collectScriptDocuments({ assets, pages, html });
  if (!documents.length) return [];

  const findings = [];
  const sinkHits = new Map(); // id -> { label, severity, examples:Set }
  const taintedHits = new Map();
  const postMessageHits = [];
  const tokenHits = new Map(); // name -> { severity, examples:Set }

  for (const doc of documents) {
    const text = doc.text;
    const hasTaint = TAINT_SOURCES.test(text);

    for (const sink of HARD_SINKS) {
      if (sink.pattern.test(text)) {
        addHit(sinkHits, sink.id, sink, snippet(text, sink.pattern, doc.label));
      }
    }

    if (hasTaint) {
      for (const sink of TAINTED_SINKS) {
        if (sink.pattern.test(text)) {
          addHit(taintedHits, sink.id, { ...sink, severity: "medium" }, snippet(text, sink.pattern, doc.label));
        }
      }
    }

    // window message handlers without an origin check are a common XSS / data-leak path.
    if (/addEventListener\s*\(\s*["']message["']/.test(text) && !/\.origin\b/.test(text)) {
      postMessageHits.push(snippet(text, /addEventListener\s*\(\s*["']message["']/, doc.label));
    }

    for (const token of TOKEN_PATTERNS) {
      for (const match of text.matchAll(token.pattern)) {
        addHit(tokenHits, token.name, { id: token.name, severity: token.severity }, `${doc.label}: ${redact(match[0])}`);
      }
    }
  }

  for (const [id, hit] of sinkHits) {
    findings.push({
      id: `client_code.sink_${id}`,
      title: `Dangerous JS sink: ${hit.label}`,
      severity: hit.severity,
      evidence: [...hit.examples].slice(0, 4).join(" / "),
      remediation: "Avoid dynamic code execution. Replace eval/Function with safe parsing, and never build executable code from untrusted input."
    });
  }

  for (const [id, hit] of taintedHits) {
    findings.push({
      id: `client_code.dom_xss_${id}`,
      title: `Possible DOM XSS: ${hit.label} with a URL/DOM data source present`,
      severity: "medium",
      evidence: [...hit.examples].slice(0, 4).join(" / "),
      remediation: "Sanitize/encode before writing to the DOM, prefer textContent or framework-safe rendering, and treat location/referrer/window.name as untrusted."
    });
  }

  if (postMessageHits.length) {
    findings.push({
      id: "client_code.postmessage_no_origin",
      title: "window message handler without an origin check",
      severity: "medium",
      evidence: postMessageHits.slice(0, 4).join(" / "),
      remediation: "Validate event.origin (and ideally event.source) inside every postMessage handler before trusting the data."
    });
  }

  for (const [name, hit] of tokenHits) {
    findings.push({
      id: `client_code.token_${slug(name)}`,
      title: `Hardcoded credential in client JS: ${name}`,
      severity: hit.severity,
      evidence: [...hit.examples].slice(0, 4).join(" / "),
      remediation: "Remove secrets from client-delivered JavaScript, rotate the exposed credential immediately, and load privileged values only server-side."
    });
  }

  return findings;
}

function collectScriptDocuments({ assets, pages, html }) {
  const documents = [];
  for (const asset of assets || []) {
    if (asset.html) documents.push({ label: shortLabel(asset.finalUrl?.pathname || asset.url), text: asset.html });
  }
  // Inline <script> blocks from the entry page and crawled pages.
  const htmlDocs = [{ label: "entry page", text: html || "" }, ...(pages || []).map((p) => ({ label: shortLabel(p.finalUrl?.pathname || p.url), text: p.html || "" }))];
  for (const doc of htmlDocs) {
    for (const match of (doc.text || "").matchAll(/<script\b(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi)) {
      const code = match[1].trim();
      if (code.length > 20) documents.push({ label: `${doc.label} (inline)`, text: code });
    }
  }
  return documents.filter((doc) => doc.text);
}

function addHit(map, key, meta, example) {
  const entry = map.get(key) || { label: meta.label, severity: meta.severity, examples: new Set() };
  if (entry.examples.size < 8) entry.examples.add(example);
  map.set(key, entry);
}

function snippet(text, pattern, label) {
  const match = text.match(pattern);
  if (!match) return label;
  const index = match.index ?? 0;
  const start = Math.max(0, index - 30);
  const fragment = text.slice(start, index + 70).replace(/\s+/g, " ").trim();
  return `${label}: …${redact(fragment)}…`;
}

function redact(value) {
  return String(value || "").replace(
    /\b(AIza[0-9A-Za-z_\-]{6}|AKIA[0-9A-Z]{4}|sk_live_[0-9A-Za-z]{4}|gh[pousr]_[0-9A-Za-z]{4}|eyJ[A-Za-z0-9_\-]{4})[0-9A-Za-z_\-.]+/g,
    "$1…[redacted]"
  );
}

function shortLabel(value) {
  const text = String(value || "asset");
  return text.length > 60 ? `…${text.slice(-57)}` : text;
}

function slug(value) {
  return String(value || "token").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
}
