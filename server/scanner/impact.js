// Adds a real-world risk tier + plain-English attack-scenario to each finding,
// so the output reads like a pentest report instead of a flat header checklist.
//
// Tiers, highest first:
//   breach: finding it often means access is already possible (exposed
//                 secrets/source, leaked credentials). Closest thing a *passive*
//                 scan can say to "this is a breach."
//   exploitable: a concrete vulnerability class an attacker could weaponize
//                 (XSS sink, injection surface, unsafe CORS).
//   hardening: a missing protection. Real, but low standalone risk; it
//                 widens the blast radius of other bugs.
//   info: disclosure / fingerprinting that helps an attacker plan.

const RULES = [
  {
    match: /^dangerous_exposure\./,
    tier: "breach",
    impact: "Sensitive resource is publicly reachable. An attacker who requests this URL can often read secrets, source, or data directly, frequently a straight path to account or server compromise."
  },
  {
    match: /^secrets\./,
    tier: "breach",
    impact: "A credential/secret is exposed in client-delivered content. It can be copied and used as-is to access the linked account, API, or infrastructure."
  },
  {
    match: /^client_code\.token_/,
    tier: "breach",
    impact: "A live credential is hardcoded in shipped JavaScript. Anyone can lift it from the browser and authenticate to the linked service."
  },
  {
    match: /^client_code\.(dom_xss|sink)/,
    tier: "exploitable",
    impact: "This code can run attacker-controlled input as script in a victim's browser (DOM XSS), leading to session theft or account takeover. Confirm by tracing the data source on an authorized target."
  },
  {
    match: /^client_code\.postmessage_no_origin/,
    tier: "exploitable",
    impact: "A message handler trusts data without checking the sender's origin. A malicious page can feed it data, enabling data theft or DOM XSS."
  },
  {
    match: /^headers\.cors_wildcard_credentials/,
    tier: "exploitable",
    impact: "Wildcard CORS combined with credentials lets any website read this site's authenticated responses, direct exposure of logged-in user data."
  },
  {
    match: /^injection\./,
    tier: "exploitable",
    impact: "These inputs reach server-side logic. If they aren't validated/parameterized they are the usual entry point for SQL injection or XSS. Needs authorized active testing to confirm exploitability."
  },
  {
    match: /^cookies\.missing_(secure|httponly|samesite)/,
    tier: "exploitable",
    impact: "Weak session-cookie protection. Combined with any XSS or network access, it makes session hijacking, CSRF, or cookie theft realistic. High-value fix."
  },
  {
    match: /^headers\.missing_csp/,
    tier: "hardening",
    impact: "No Content-Security-Policy. Not a vuln alone, but if an XSS bug exists there is nothing to contain it. Strong mitigation to add."
  },
  {
    match: /^stack\./,
    tier: "info",
    impact: "Software/version disclosure. Helps an attacker fingerprint the stack and look up known CVEs for the exact version."
  },
  {
    match: /^transport\./,
    tier: "hardening",
    impact: "Transport-security gap. Without HTTPS/HSTS, traffic and cookies can be read or modified by anyone on the network path."
  },
  {
    match: /^headers\./,
    tier: "hardening",
    impact: "Defense-in-depth response header. Low standalone risk; its absence makes other attacks easier or more impactful."
  }
];

const DEFAULT = {
  tier: "info",
  impact: "Informational signal for an authorized reviewer to confirm in context."
};

const TIER_RANK = { breach: 4, exploitable: 3, hardening: 2, info: 1 };

export function annotateFindings(findings) {
  return (findings || []).map((finding) => {
    const rule = RULES.find((entry) => entry.match.test(finding.id || "")) || DEFAULT;
    return {
      ...finding,
      tier: finding.tier || rule.tier,
      impact: finding.impact || rule.impact
    };
  });
}

export function tierRank(tier) {
  return TIER_RANK[tier] || 0;
}
