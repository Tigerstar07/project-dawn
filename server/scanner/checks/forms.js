function getAttr(tag, name) {
  const match = tag.match(new RegExp(`${name}\\s*=\\s*["']?([^"'\\s>]+)`, "i"));
  return match?.[1] || "";
}

function resolveAction(action, finalUrl) {
  try {
    return new URL(action || finalUrl.href, finalUrl.href);
  } catch {
    return finalUrl;
  }
}

export async function analyzeForms({ finalUrl, html }) {
  const findings = [];
  if (!html) return findings;

  const forms = html.match(/<form\b[\s\S]*?<\/form>/gi) || [];
  forms.slice(0, 25).forEach((form, index) => {
    const openTag = form.match(/<form\b[^>]*>/i)?.[0] || "";
    const method = (getAttr(openTag, "method") || "get").toLowerCase();
    const action = resolveAction(getAttr(openTag, "action"), finalUrl);
    const hasPassword = /<input\b[^>]*type\s*=\s*["']?password/i.test(form);
    const hasCsrfLikeToken = /<input\b[^>]*(name|id)\s*=\s*["'][^"']*(csrf|xsrf|token|authenticity)[^"']*["']/i.test(form);

    if (hasPassword && action.protocol !== "https:") {
      findings.push({
        id: "forms.password_over_http",
        title: "Password form can submit over HTTP",
        severity: "high",
        evidence: `Form ${index + 1} action resolves to ${action.href}`,
        remediation: "Submit credential forms only over HTTPS."
      });
    }

    if (method === "post" && !hasCsrfLikeToken) {
      findings.push({
        id: "forms.no_csrf_token",
        title: "POST form has no obvious CSRF token",
        severity: "medium",
        evidence: `Form ${index + 1} method is POST and no CSRF-like hidden token name was found.`,
        remediation: "Use server-validated anti-CSRF tokens for state-changing forms."
      });
    }

    if (finalUrl.protocol === "https:" && action.protocol === "http:") {
      findings.push({
        id: "forms.downgrade_action",
        title: "HTTPS page contains HTTP form action",
        severity: "medium",
        evidence: `Form ${index + 1} action resolves to ${action.href}`,
        remediation: "Keep form actions on HTTPS origins."
      });
    }
  });

  return findings;
}
