const SQL_ERROR_PATTERNS = [
  /sql syntax/i,
  /mysql_fetch/i,
  /mysqli_/i,
  /postgresql/i,
  /pg_query/i,
  /sqlite(?:3)?::/i,
  /ora-\d{5}/i,
  /odbc/i,
  /jdbc/i,
  /unclosed quotation mark/i,
  /quoted string not properly terminated/i
];

const REDIRECT_PARAM_NAMES = ["redirect", "return", "returnurl", "next", "url", "continue", "dest", "destination"];
const INPUT_PARAM_NAMES = ["id", "q", "query", "search", "user", "uid", "account", "filter", "sort", "order", "page", "category"];

export async function analyzeActiveLab({ finalUrl, pages, activeFetch, addEvent }) {
  if (!activeFetch) return [];

  const findings = [];
  const candidates = collectCandidateUrls(finalUrl, pages).slice(0, 6);
  let probeCount = 0;

  for (const candidate of candidates) {
    const params = [...candidate.searchParams.keys()];
    const inputParams = params.filter((name) => isInputParam(name));
    const redirectParams = params.filter((name) => isRedirectParam(name));

    for (const param of inputParams.slice(0, 2)) {
      const marker = `PDWN_REFLECT_${Math.random().toString(16).slice(2, 8)}`;
      const reflected = cloneWithParam(candidate, param, marker);
      const reflectionResult = await activeFetch(reflected);
      probeCount += 1;

      if (reflectionResult.text.includes(marker)) {
        findings.push({
          id: "active.reflected_input",
          title: "Active lab probe found reflected input",
          severity: "high",
          evidence: `${reflected.pathname} reflects parameter ${param}`,
          remediation: "Treat this route as XSS-relevant until verified. Encode output by context, validate input, and add automated regression tests."
        });
      }

      const sqlProbe = cloneWithParam(candidate, param, `${marker}'`);
      const sqlResult = await activeFetch(sqlProbe);
      probeCount += 1;

      if (sqlResult.status >= 500 || SQL_ERROR_PATTERNS.some((pattern) => pattern.test(sqlResult.text))) {
        findings.push({
          id: "active.sql_error_signal",
          title: "Active lab probe triggered SQL/error disclosure signal",
          severity: "critical",
          evidence: `${sqlProbe.pathname} parameter ${param} returned HTTP ${sqlResult.status} or database-like error text`,
          remediation: "Review this route immediately. Use parameterized queries, strict input typing, generic error responses, and server-side tests for injection cases."
        });
      }

      if (probeCount >= 10) break;
    }

    for (const param of redirectParams.slice(0, 1)) {
      const redirectProbe = cloneWithParam(candidate, param, "https://project-dawn.invalid/");
      const redirectResult = await activeFetch(redirectProbe, { redirect: "manual" });
      probeCount += 1;
      const location = redirectResult.headers.location || "";

      if (location.includes("project-dawn.invalid")) {
        findings.push({
          id: "active.open_redirect_signal",
          title: "Active lab probe found open redirect behavior",
          severity: "high",
          evidence: `${redirectProbe.pathname} accepted external redirect value in ${param}`,
          remediation: "Allowlist redirect destinations and use server-side route identifiers instead of arbitrary URLs."
        });
      }

      if (probeCount >= 10) break;
    }

    if (probeCount >= 10) break;
  }

  addEvent?.("active-lab", `Sent ${probeCount} non-destructive active lab probe(s)`, "complete");
  return findings;
}

function collectCandidateUrls(finalUrl, pages = []) {
  const urls = [finalUrl];
  for (const page of pages) {
    if (page.finalUrl?.search) urls.push(page.finalUrl);
    const html = page.html || "";
    const matches = [...html.matchAll(/\bhref\s*=\s*["']([^"']+\?[^"']+)["']/gi)];
    for (const match of matches) {
      try {
        const url = new URL(match[1], finalUrl.href);
        if (url.origin === finalUrl.origin) urls.push(url);
      } catch {
        // Ignore malformed links.
      }
    }
  }

  const seen = new Set();
  return urls.filter((url) => {
    const key = url.href;
    if (!url.search || seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function cloneWithParam(url, param, value) {
  const cloned = new URL(url.href);
  cloned.searchParams.set(param, value);
  return cloned;
}

function isInputParam(name) {
  const normalized = String(name || "").toLowerCase();
  return INPUT_PARAM_NAMES.some((candidate) => normalized === candidate || normalized.includes(candidate));
}

function isRedirectParam(name) {
  const normalized = String(name || "").toLowerCase();
  return REDIRECT_PARAM_NAMES.some((candidate) => normalized === candidate || normalized.includes(candidate));
}
