function hasHeader(headers, name) {
  return Boolean(headers[name.toLowerCase()]);
}

function headerValue(headers, name) {
  return headers[name.toLowerCase()] || "";
}

export async function analyzeHeaders({ finalUrl, headers }) {
  const findings = [];
  const isHttps = finalUrl.protocol === "https:";
  const csp = headerValue(headers, "content-security-policy");

  if (isHttps && !hasHeader(headers, "strict-transport-security")) {
    findings.push({
      id: "headers.missing_hsts",
      title: "Missing Strict-Transport-Security",
      severity: "medium",
      evidence: "No Strict-Transport-Security response header was observed.",
      remediation: "Add HSTS after validating HTTPS across all subdomains that will be covered."
    });
  }

  if (!csp) {
    findings.push({
      id: "headers.missing_csp",
      title: "Missing Content-Security-Policy",
      severity: "medium",
      evidence: "No Content-Security-Policy response header was observed.",
      remediation: "Add a Content Security Policy that restricts scripts, frames, objects, and trusted origins."
    });
  }

  if (!hasHeader(headers, "x-content-type-options")) {
    findings.push({
      id: "headers.missing_nosniff",
      title: "Missing X-Content-Type-Options",
      severity: "low",
      evidence: "No X-Content-Type-Options header was observed.",
      remediation: "Set X-Content-Type-Options: nosniff."
    });
  }

  const hasFrameGuard = hasHeader(headers, "x-frame-options") || /frame-ancestors/i.test(csp);
  if (!hasFrameGuard) {
    findings.push({
      id: "headers.missing_frame_guard",
      title: "Missing clickjacking protection",
      severity: "medium",
      evidence: "No X-Frame-Options header or CSP frame-ancestors directive was observed.",
      remediation: "Use CSP frame-ancestors or X-Frame-Options to restrict framing."
    });
  }

  if (!hasHeader(headers, "referrer-policy")) {
    findings.push({
      id: "headers.missing_referrer_policy",
      title: "Missing Referrer-Policy",
      severity: "low",
      evidence: "No Referrer-Policy header was observed.",
      remediation: "Set a Referrer-Policy such as strict-origin-when-cross-origin."
    });
  }

  if (!hasHeader(headers, "permissions-policy")) {
    findings.push({
      id: "headers.missing_permissions_policy",
      title: "Missing Permissions-Policy",
      severity: "low",
      evidence: "No Permissions-Policy header was observed.",
      remediation: "Set a Permissions-Policy that disables browser features the site does not need."
    });
  }

  const allowOrigin = headerValue(headers, "access-control-allow-origin");
  const allowCredentials = headerValue(headers, "access-control-allow-credentials");
  if (allowOrigin === "*" && /true/i.test(allowCredentials)) {
    findings.push({
      id: "headers.cors_wildcard_credentials",
      title: "Potentially unsafe CORS credential policy",
      severity: "high",
      evidence: "Access-Control-Allow-Origin is * and Access-Control-Allow-Credentials is true.",
      remediation: "Avoid wildcard origins with credentials. Use an explicit allowlist for trusted origins."
    });
  } else if (allowOrigin === "*") {
    findings.push({
      id: "headers.cors_wildcard",
      title: "Wildcard CORS origin",
      severity: "info",
      evidence: "Access-Control-Allow-Origin is *.",
      remediation: "Confirm that public cross-origin access is intentional."
    });
  }

  return findings;
}
