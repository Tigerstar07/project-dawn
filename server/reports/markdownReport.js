const SEVERITY_ORDER = ["critical", "high", "medium", "low", "info"];

export function createMarkdownReport(scan) {
  const bySeverity = new Map(SEVERITY_ORDER.map((severity) => [severity, []]));
  for (const finding of scan.findings) {
    const bucket = bySeverity.get(finding.severity) || bySeverity.get("info");
    bucket.push(finding);
  }

  const lines = [
    `# Project Dawn Passive Scan Report`,
    "",
    `- Target: ${scan.target}`,
    `- Final URL: ${scan.finalUrl}`,
    `- Scan ID: ${scan.scanId}`,
    `- Started: ${scan.startedAt}`,
    `- Duration: ${scan.durationMs} ms`,
    `- Profile: ${scan.scanProfile || "baseline"}`,
    `- Passive only: ${scan.passiveOnly ? "yes" : "no"}`,
    `- Modules: ${scan.modules.join(", ")}`,
    scan.discovery ? `- Discovery: ${scan.discovery.crawledPages} page(s), ${scan.discovery.fetchedAssets} asset(s), ${scan.discovery.checkedExposurePaths} exposure path(s)` : "",
    "",
    "## Summary",
    "",
    ...SEVERITY_ORDER.map((severity) => `- ${capitalize(severity)}: ${bySeverity.get(severity).length}`),
    "",
    "## Findings",
    ""
  ];

  if (scan.findings.length === 0) {
    lines.push("No findings were identified by the enabled passive checks.", "");
    return lines.join("\n");
  }

  for (const severity of SEVERITY_ORDER) {
    const findings = bySeverity.get(severity);
    if (!findings.length) continue;
    lines.push(`### ${capitalize(severity)}`, "");

    findings.forEach((finding, index) => {
      lines.push(`#### ${index + 1}. ${finding.title}`);
      lines.push("");
      lines.push(`- ID: ${finding.id}`);
      lines.push(`- Module: ${finding.module || "core"}`);
      if (finding.tier) lines.push(`- Risk tier: ${finding.tier}`);
      if (finding.impact) lines.push(`- Impact: ${finding.impact}`);
      lines.push(`- Evidence: ${normalizeEvidence(finding.evidence)}`);
      lines.push(`- Remediation: ${finding.remediation}`);
      lines.push("");
    });
  }

  lines.push("## Scope Note", "");
  lines.push("This report is based on bounded authorized checks. Active lab probes, when enabled, are restricted to localhost/private lab targets and do not attempt brute force, authentication bypass, destructive actions, or data extraction.");
  lines.push("");

  return lines.join("\n");
}

function capitalize(value) {
  return `${value[0].toUpperCase()}${value.slice(1)}`;
}

function normalizeEvidence(value) {
  return String(value || "Not provided").replace(/\n/g, " / ");
}
