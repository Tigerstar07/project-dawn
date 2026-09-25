// Version & CVE intelligence, fully passive.
// The server already discloses its software versions (Server, X-Powered-By,
// generator meta). We look those exact versions up against the authoritative
// end-of-life database (endoflife.date) to tell whether the software is
// out-of-date or unsupported, the strongest "known-CVE risk" signal you can
// get without sending a single payload. Each finding links to the official NVD
// CVE search for that exact product + version.

const PRODUCTS = {
  apache: { eol: "apache", label: "Apache HTTP Server", cve: "Apache HTTP Server" },
  nginx: { eol: "nginx", label: "nginx", cve: "nginx" },
  openssl: { eol: "openssl", label: "OpenSSL", cve: "OpenSSL" },
  php: { eol: "php", label: "PHP", cve: "PHP" },
  wordpress: { eol: "wordpress", label: "WordPress", cve: "WordPress" },
  nodejs: { eol: "nodejs", label: "Node.js", cve: "Node.js" }
};

const NAME_TO_KEY = {
  apache: "apache",
  httpd: "apache",
  nginx: "nginx",
  openssl: "openssl",
  php: "php",
  wordpress: "wordpress",
  node: "nodejs",
  "node.js": "nodejs",
  nodejs: "nodejs"
};

export async function analyzeVersionIntel({ headers = {}, html = "" }) {
  const detected = detectVersions(headers, html);
  if (!detected.length) return [];
  const findings = await Promise.all(detected.map((item) => assess(item)));
  return findings.filter(Boolean);
}

function detectVersions(headers, html) {
  const out = [];
  const seen = new Set();
  const add = (name, version, source) => {
    const key = NAME_TO_KEY[String(name).toLowerCase()];
    if (!key || !version) return;
    const id = `${key}@${version}`;
    if (seen.has(id)) return;
    seen.add(id);
    out.push({ key, version, source });
  };

  const banners = [
    [headers["server"], "Server header"],
    [headers["x-powered-by"], "X-Powered-By header"]
  ];
  for (const [value, source] of banners) {
    for (const match of String(value || "").matchAll(/([A-Za-z][A-Za-z0-9_.+-]*)\/(\d+\.\d+(?:\.\d+)?)/g)) {
      add(match[1], match[2], source);
    }
  }

  const generator = String(html || "").match(/<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']/i);
  const wp = generator?.[1].match(/WordPress\s+(\d+\.\d+(?:\.\d+)?)/i);
  if (wp) add("wordpress", wp[1], "generator meta");

  return out;
}

async function assess({ key, version, source }) {
  const cfg = PRODUCTS[key];
  const nvdLink = `https://nvd.nist.gov/vuln/search/results?form_type=Basic&query=${encodeURIComponent(`${cfg.cve} ${version}`)}`;
  const evidenceBase = `${source}: ${cfg.label}/${version}`;

  let cycle = null;
  try {
    const response = await fetch(`https://endoflife.date/api/${cfg.eol}.json`, {
      headers: { accept: "application/json" },
      signal: AbortSignal.timeout(8000)
    });
    if (response.ok) cycle = matchCycle(await response.json(), version);
  } catch {
    // endoflife.date unreachable, fall through to the "verify manually" finding.
  }

  if (!cycle) {
    return {
      id: `version_intel.${key}`,
      title: `${cfg.label} ${version} disclosed, verify patch level`,
      severity: "info",
      tier: "info",
      impact: `${cfg.label} ${version} is exposed. Could not auto-check it against the version database; confirm it is fully patched.`,
      evidence: evidenceBase,
      remediation: `Check known CVEs for this exact version: ${nvdLink}`
    };
  }

  const latest = cycle.latest || "";
  const isEol = cycle.eol === true || (typeof cycle.eol === "string" && new Date(cycle.eol) < new Date());
  const outdated = latest && compareVersions(version, latest) < 0;

  if (isEol) {
    return {
      id: `version_intel.${key}_eol`,
      title: `${cfg.label} ${version} is end-of-life, no security patches`,
      severity: "high",
      tier: "exploitable",
      impact: `${cfg.label} ${version} (cycle ${cycle.cycle}) no longer receives security updates, so any new CVE stays permanently unpatched. EOL software is a primary attacker target.`,
      evidence: `${evidenceBase}. Cycle ${cycle.cycle} reached EOL${typeof cycle.eol === "string" ? ` on ${cycle.eol}` : ""}. Latest known: ${latest || "n/a"}.`,
      remediation: `Upgrade to a supported release. Review applicable CVEs: ${nvdLink}`
    };
  }

  if (outdated) {
    return {
      id: `version_intel.${key}_outdated`,
      title: `${cfg.label} ${version} is behind the latest patch (${latest})`,
      severity: "medium",
      tier: "hardening",
      impact: `${cfg.label} ${version} is missing security fixes shipped in ${latest}. CVEs patched upstream may still apply to this host.`,
      evidence: `${evidenceBase}. Latest in cycle ${cycle.cycle}: ${latest}.`,
      remediation: `Update to ${latest} or newer. Review CVEs fixed since your version: ${nvdLink}`
    };
  }

  return {
    id: `version_intel.${key}_current`,
    title: `${cfg.label} ${version} is on the latest patch`,
    severity: "info",
    tier: "info",
    impact: `${cfg.label} ${version} appears current for its release cycle, good. Disclosing the exact version still helps attackers fingerprint the stack.`,
    evidence: `${evidenceBase}. Latest in cycle ${cycle.cycle}: ${latest}.`,
    remediation: `No patch action needed. Optionally suppress the version banner. CVE history: ${nvdLink}`
  };
}

function matchCycle(cycles, version) {
  if (!Array.isArray(cycles)) return null;
  let best = null;
  for (const cycle of cycles) {
    const cy = String(cycle.cycle);
    if (version === cy || version.startsWith(`${cy}.`)) {
      if (!best || cy.length > String(best.cycle).length) best = cycle;
    }
  }
  if (best) return best;
  const major = version.split(".")[0];
  return cycles.find((cycle) => String(cycle.cycle) === major) || null;
}

function compareVersions(a, b) {
  const pa = String(a).split(".").map(Number);
  const pb = String(b).split(".").map(Number);
  for (let i = 0; i < Math.max(pa.length, pb.length); i += 1) {
    const x = pa[i] || 0;
    const y = pb[i] || 0;
    if (x !== y) return x < y ? -1 : 1;
  }
  return 0;
}
