const ENDPOINT_PATTERN = /["'`](\/(?:api|graphql|auth|admin|v\d+|internal|private|upload|download|user|account)[^"'`\s<>{}]*)["'`]/gi;
const ABSOLUTE_URL_PATTERN = /\bhttps?:\/\/[^\s"'`<>{}]+/gi;

export async function analyzeClientAssets({ assets }) {
  if (!assets?.length) return [];

  const endpoints = new Set();
  const externalHosts = new Set();
  const sourceMaps = new Set();

  for (const asset of assets) {
    const text = asset.html || "";
    for (const match of text.matchAll(ENDPOINT_PATTERN)) {
      endpoints.add(match[1]);
    }
    for (const match of text.matchAll(ABSOLUTE_URL_PATTERN)) {
      try {
        const url = new URL(match[0].replace(/[);,\]]+$/g, ""));
        externalHosts.add(url.origin);
      } catch {
        // Ignore malformed URL-like strings.
      }
    }
    for (const match of text.matchAll(/sourceMappingURL=([^\s*]+)/gi)) {
      sourceMaps.add(match[1]);
    }
  }

  const findings = [];
  if (endpoints.size) {
    findings.push({
      id: "client_assets.api_routes",
      title: "Client bundle exposes API routes",
      severity: "medium",
      evidence: [...endpoints].slice(0, 14).join(" / "),
      remediation: "Review exposed routes for authorization checks, object-level access control, rate limits, and server-side validation."
    });
  }

  if (externalHosts.size) {
    findings.push({
      id: "client_assets.external_hosts",
      title: "Client bundle references external hosts",
      severity: "low",
      evidence: [...externalHosts].slice(0, 10).join(" / "),
      remediation: "Verify that external dependencies are expected, trusted, and covered by CSP and vendor risk review."
    });
  }

  if (sourceMaps.size) {
    findings.push({
      id: "client_assets.source_maps",
      title: "Client bundle references source maps",
      severity: "medium",
      evidence: [...sourceMaps].slice(0, 8).join(" / "),
      remediation: "Avoid public production source maps unless access is intentionally restricted and secrets are never embedded."
    });
  }

  return findings;
}
