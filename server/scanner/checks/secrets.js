const SECRET_PATTERNS = [
  { name: "AWS access key", pattern: /\bAKIA[0-9A-Z]{16}\b/g, severity: "high" },
  { name: "OpenAI-like API key", pattern: /\bsk-[A-Za-z0-9_-]{20,}\b/g, severity: "high" },
  { name: "Private key block", pattern: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, severity: "high" },
  { name: "Generic access token", pattern: /\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|secret)\s*[:=]\s*["'][^"']{12,}["']/gi, severity: "medium" }
];

export async function analyzeSecrets({ html, pages, assets }) {
  const documents = [
    { label: "entry page", text: html || "" },
    ...(pages || []).map((page) => ({ label: page.finalUrl?.pathname || page.url, text: page.html || "" })),
    ...(assets || []).map((asset) => ({ label: asset.finalUrl?.pathname || asset.url, text: asset.html || "" }))
  ].filter((item) => item.text);

  if (!documents.length) return [];

  const findings = [];
  for (const secret of SECRET_PATTERNS) {
    const matches = [];
    for (const document of documents) {
      for (const match of document.text.matchAll(secret.pattern)) {
        matches.push(`${document.label}: ${redact(match[0])}`);
        if (matches.length >= 5) break;
      }
      if (matches.length >= 5) break;
    }
    if (!matches.length) continue;

    findings.push({
      id: `secrets.${slug(secret.name)}`,
      title: `${secret.name} exposed in client response`,
      severity: secret.severity,
      evidence: matches.join(" / "),
      remediation: "Remove secrets from client-delivered content, rotate exposed credentials, and serve sensitive values only from trusted server-side components."
    });
  }

  const comments = [];
  for (const document of documents) {
    for (const match of document.text.matchAll(/<!--([\s\S]*?)-->/g)) {
      const comment = match[1].trim();
      if (/(password|secret|token|todo|fixme|admin|debug)/i.test(comment)) {
        comments.push(`${document.label}: ${truncate(comment)}`);
      }
      if (comments.length >= 5) break;
    }
    if (comments.length >= 5) break;
  }

  if (comments.length) {
    findings.push({
      id: "secrets.sensitive_comments",
      title: "Sensitive-looking HTML comments",
      severity: "low",
      evidence: comments.join(" / "),
      remediation: "Remove operational comments from production HTML and move internal notes to private issue tracking."
    });
  }

  return findings;
}

function slug(value) {
  return String(value).toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
}

function redact(value) {
  const text = String(value || "");
  if (text.length <= 10) return "[redacted]";
  return `${text.slice(0, 5)}...[redacted]...${text.slice(-4)}`;
}

function truncate(value) {
  const text = String(value || "").replace(/\s+/g, " ");
  return text.length > 120 ? `${text.slice(0, 120)}...` : text;
}
