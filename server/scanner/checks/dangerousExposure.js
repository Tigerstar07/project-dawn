const SIGNALS = [
  { id: "env", pattern: /(?:APP_KEY|DB_PASSWORD|DATABASE_URL|SECRET_KEY|AWS_SECRET|PRIVATE_KEY)\s*=/i, severity: "critical" },
  { id: "git_config", pattern: /\[core\][\s\S]{0,300}(?:repositoryformatversion|filemode|bare)\s*=/i, severity: "critical" },
  { id: "sql_dump", pattern: /(?:CREATE TABLE|INSERT INTO|DROP TABLE)\s+[`"'\[]?[a-z0-9_]+/i, severity: "critical" },
  { id: "spring_actuator", pattern: /(?:propertySources|activeProfiles|systemEnvironment|management\.endpoints)/i, severity: "critical" },
  { id: "openapi", pattern: /"(?:openapi|swagger)"\s*:\s*"[0-9.]+"/i, severity: "medium" },
  { id: "server_status", pattern: /Apache Server Status|Scoreboard|Server uptime/i, severity: "medium" },
  { id: "graphql", pattern: /(?:GraphQL|Cannot query field|Must provide query string)/i, severity: "medium" }
];

export async function analyzeDangerousExposure({ exposures }) {
  if (!exposures?.length) return [];

  const findings = [];
  for (const exposure of exposures) {
    if (!isInterestingStatus(exposure.status)) continue;
    const body = exposure.html || "";
    const matchedSignal = SIGNALS.find((signal) => signal.pattern.test(body));
    const severity = matchedSignal?.severity || exposure.expectedSeverity || "low";

    if (matchedSignal || likelySensitiveByPath(exposure)) {
      findings.push({
        id: `dangerous_exposure.${matchedSignal?.id || slug(exposure.label)}`,
        title: `${exposure.label} appears publicly reachable`,
        severity,
        evidence: `${exposure.finalUrl?.href || exposure.url} returned HTTP ${exposure.status}${body ? ` with signal: ${redact(body)}` : ""}`,
        remediation: "Remove this resource from public access, rotate any exposed credentials, and add deployment checks that block sensitive files and debug endpoints."
      });
    }
  }

  return findings;
}

function isInterestingStatus(status) {
  return status >= 200 && status < 400;
}

function likelySensitiveByPath(exposure) {
  const url = String(exposure.finalUrl?.href || exposure.url || "");
  const contentType = String(exposure.contentType || "").toLowerCase();
  const body = String(exposure.html || "");
  const looksLikeHtmlFallback = contentType.includes("text/html") || /^\s*<!doctype html|^\s*<html[\s>]/i.test(body);
  if (looksLikeHtmlFallback) return false;
  return /\.(?:env|sql|bak|zip)$/i.test(url) || /\/\.git\/(?:config|HEAD)$/i.test(url);
}

function slug(value) {
  return String(value || "exposure").toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "");
}

function redact(value) {
  const compact = String(value || "").replace(/\s+/g, " ").slice(0, 180);
  return compact.replace(/([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS)[A-Z0-9_]*=)[^&\s"']+/gi, "$1[redacted]");
}
