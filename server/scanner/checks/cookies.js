import { getSetCookieHeaders } from "../../utils/http.js";

function cookieName(cookie) {
  return String(cookie || "").split("=")[0]?.trim() || "cookie";
}

function isSensitiveName(name) {
  return /(session|auth|token|jwt|sid|account|login)/i.test(name);
}

export async function analyzeCookies({ finalUrl, rawHeaders }) {
  const cookies = getSetCookieHeaders(rawHeaders);
  const findings = [];
  const isHttps = finalUrl.protocol === "https:";

  for (const cookie of cookies) {
    const name = cookieName(cookie);
    const sensitive = isSensitiveName(name);
    const hasSecure = /;\s*secure\b/i.test(cookie);
    const hasHttpOnly = /;\s*httponly\b/i.test(cookie);
    const sameSite = cookie.match(/;\s*samesite=([^;]+)/i)?.[1]?.toLowerCase();

    if (isHttps && !hasSecure) {
      findings.push({
        id: "cookies.missing_secure",
        title: `${name} cookie is missing Secure`,
        severity: sensitive ? "medium" : "low",
        evidence: redactCookie(cookie),
        remediation: "Set the Secure attribute on cookies that should only travel over HTTPS."
      });
    }

    if (!hasHttpOnly && sensitive) {
      findings.push({
        id: "cookies.missing_httponly",
        title: `${name} cookie is missing HttpOnly`,
        severity: "medium",
        evidence: redactCookie(cookie),
        remediation: "Set HttpOnly on session or authentication cookies to reduce script access risk."
      });
    }

    if (!sameSite) {
      findings.push({
        id: "cookies.missing_samesite",
        title: `${name} cookie is missing SameSite`,
        severity: sensitive ? "medium" : "low",
        evidence: redactCookie(cookie),
        remediation: "Set SameSite=Lax or SameSite=Strict unless cross-site cookie behavior is required."
      });
    }

    if (sameSite === "none" && !hasSecure) {
      findings.push({
        id: "cookies.samesite_none_without_secure",
        title: `${name} uses SameSite=None without Secure`,
        severity: "medium",
        evidence: redactCookie(cookie),
        remediation: "Cookies with SameSite=None should also use Secure."
      });
    }
  }

  return findings;
}

function redactCookie(cookie) {
  return String(cookie || "").replace(/^([^=]+)=([^;]*)/, (_match, name) => `${name}=[redacted]`);
}
