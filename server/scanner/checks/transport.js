export async function analyzeTransport({ targetUrl, finalUrl }) {
  const findings = [];

  if (finalUrl.protocol !== "https:") {
    findings.push({
      id: "transport.no_https",
      title: "Target is not using HTTPS",
      severity: "high",
      evidence: `Final URL is ${finalUrl.href}`,
      remediation: "Serve the site over HTTPS and redirect all HTTP traffic to HTTPS."
    });
  }

  if (targetUrl.protocol === "http:" && finalUrl.protocol === "https:") {
    findings.push({
      id: "transport.http_redirect",
      title: "HTTP redirects to HTTPS",
      severity: "info",
      evidence: `${targetUrl.href} redirected to ${finalUrl.href}`,
      remediation: "Keep the redirect, and pair it with HSTS after confirming HTTPS is stable."
    });
  }

  return findings;
}
