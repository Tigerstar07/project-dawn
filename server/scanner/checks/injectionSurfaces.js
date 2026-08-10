const RISKY_PARAM_NAMES = [
  "id",
  "user",
  "uid",
  "account",
  "search",
  "q",
  "query",
  "filter",
  "sort",
  "order",
  "page",
  "category",
  "redirect",
  "return",
  "next",
  "url",
  "file",
  "path"
];

function getAttr(tag, name) {
  const match = tag.match(new RegExp(`${name}\\s*=\\s*["']?([^"'\\s>]+)`, "i"));
  return match?.[1] || "";
}

function unique(values) {
  return [...new Set(values.filter(Boolean))];
}

function isRiskyName(name) {
  const normalized = String(name || "").toLowerCase();
  return RISKY_PARAM_NAMES.some((risk) => normalized === risk || normalized.includes(risk));
}

function resolveUrl(value, baseUrl) {
  try {
    return new URL(value, baseUrl.href);
  } catch {
    return null;
  }
}

export async function analyzeInjectionSurfaces({ finalUrl, html, pages }) {
  const findings = [];
  const urlRiskParams = unique([...finalUrl.searchParams.keys()].filter(isRiskyName));

  if (urlRiskParams.length) {
    findings.push({
      id: "injection.url_parameters",
      title: "URL has injection-relevant parameters",
      severity: "medium",
      evidence: `${finalUrl.href} uses: ${urlRiskParams.join(", ")}`,
      remediation: "Validate and type-check these inputs server-side, use parameterized database queries, and encode output by context."
    });
  }

  const pageSet = pages?.length ? pages : [{ finalUrl, html }];
  const combinedHtml = pageSet.map((page) => page.html || "").join("\n");
  if (!combinedHtml) return findings;

  const forms = combinedHtml.match(/<form\b[\s\S]*?<\/form>/gi) || [];
  const formSignals = [];
  forms.slice(0, 30).forEach((form, index) => {
    const openTag = form.match(/<form\b[^>]*>/i)?.[0] || "";
    const method = (getAttr(openTag, "method") || "get").toUpperCase();
    const action = resolveUrl(getAttr(openTag, "action") || finalUrl.href, finalUrl);
    const inputs = [...form.matchAll(/<(?:input|textarea|select)\b[^>]*>/gi)]
      .map((match) => getAttr(match[0], "name") || getAttr(match[0], "id"))
      .filter(isRiskyName);

    if (inputs.length) {
      formSignals.push(`form ${index + 1} ${method} ${action?.pathname || "/"} fields: ${unique(inputs).join(", ")}`);
    }
  });

  if (formSignals.length) {
    findings.push({
      id: "injection.form_fields",
      title: "Forms expose injection-relevant fields",
      severity: "medium",
      evidence: formSignals.slice(0, 8).join(" / "),
      remediation: "Treat these fields as untrusted input. Use allowlisted validation, parameterized queries, CSRF protection for state changes, and context-aware output encoding."
    });
  }

  const linkSignals = [];
  const links = [...combinedHtml.matchAll(/\bhref\s*=\s*["']([^"']+\?[^"']+)["']/gi)]
    .map((match) => resolveUrl(match[1], finalUrl))
    .filter((url) => url && url.origin === finalUrl.origin)
    .slice(0, 80);

  for (const link of links) {
    const risky = unique([...link.searchParams.keys()].filter(isRiskyName));
    if (risky.length) linkSignals.push(`${link.pathname}: ${risky.join(", ")}`);
  }

  if (linkSignals.length) {
    findings.push({
      id: "injection.parameterized_links",
      title: "Parameterized same-origin links found",
      severity: "low",
      evidence: unique(linkSignals).slice(0, 10).join(" / "),
      remediation: "Review these routes for server-side validation, authorization checks, parameterized queries, and consistent output encoding."
    });
  }

  const redirectSignals = [];
  for (const link of links) {
    const risky = unique([...link.searchParams.keys()].filter((name) => /^(redirect|return|returnurl|next|url|continue|dest|destination)$/i.test(name)));
    if (risky.length) redirectSignals.push(`${link.pathname}: ${risky.join(", ")}`);
  }

  if (redirectSignals.length) {
    findings.push({
      id: "injection.redirect_parameters",
      title: "Redirect-like parameters found",
      severity: "medium",
      evidence: unique(redirectSignals).slice(0, 10).join(" / "),
      remediation: "Validate redirect destinations with a strict allowlist and avoid accepting arbitrary URL values."
    });
  }

  return findings;
}
