export async function analyzeMixedContent({ finalUrl, html }) {
  if (finalUrl.protocol !== "https:" || !html) return [];

  const matches = [...html.matchAll(/\b(?:src|href|action)\s*=\s*["'](http:\/\/[^"']+)["']/gi)]
    .map((match) => match[1])
    .slice(0, 10);

  if (matches.length === 0) return [];

  return [
    {
      id: "mixed_content.http_assets",
      title: "HTTPS page references HTTP resources",
      severity: "medium",
      evidence: matches.join("\n"),
      remediation: "Load scripts, images, forms, and styles over HTTPS to avoid mixed-content exposure."
    }
  ];
}
