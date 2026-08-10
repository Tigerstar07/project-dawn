function headerValue(headers, name) {
  return headers[name.toLowerCase()] || "";
}

export async function analyzeStackExposure({ headers, html }) {
  const findings = [];
  const exposedHeaders = [
    ["server", headerValue(headers, "server")],
    ["x-powered-by", headerValue(headers, "x-powered-by")],
    ["x-aspnet-version", headerValue(headers, "x-aspnet-version")],
    ["x-generator", headerValue(headers, "x-generator")]
  ].filter(([, value]) => Boolean(value));

  if (exposedHeaders.length) {
    findings.push({
      id: "stack.exposed_headers",
      title: "Technology/version headers exposed",
      severity: "low",
      evidence: exposedHeaders.map(([name, value]) => `${name}: ${value}`).join(" / "),
      remediation: "Reduce unnecessary framework and version disclosure in production response headers."
    });
  }

  if (!html) return findings;

  const generator = html.match(/<meta\b[^>]*(?:name=["']generator["'][^>]*content=["']([^"']+)|content=["']([^"']+)["'][^>]*name=["']generator["'])/i);
  if (generator) {
    findings.push({
      id: "stack.generator_meta",
      title: "Generator metadata exposed",
      severity: "info",
      evidence: `generator: ${generator[1] || generator[2]}`,
      remediation: "Remove generator metadata if it reveals unnecessary product or version details."
    });
  }

  const sourceMaps = [...html.matchAll(/\b(?:src|href)\s*=\s*["']([^"']+\.map)["']/gi)]
    .map((match) => match[1])
    .slice(0, 8);
  if (sourceMaps.length) {
    findings.push({
      id: "stack.source_maps",
      title: "Source map references exposed",
      severity: "medium",
      evidence: sourceMaps.join(" / "),
      remediation: "Avoid publishing production source maps unless access is intentionally restricted."
    });
  }

  if (/<title>\s*Index of\s*\//i.test(html) || /<h1>\s*Index of\s*\//i.test(html)) {
    findings.push({
      id: "stack.directory_listing",
      title: "Directory listing page detected",
      severity: "medium",
      evidence: "The page resembles a generated directory index.",
      remediation: "Disable directory listing on production web servers unless public indexing is intentional."
    });
  }

  return findings;
}
