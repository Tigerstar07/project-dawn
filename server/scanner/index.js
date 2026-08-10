import path from "node:path";
import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";
import { normalizeUrl, readLimitedText, headerObject } from "../utils/http.js";
import { ensureDir } from "../utils/files.js";
import { analyzeCookies } from "./checks/cookies.js";
import { analyzeForms } from "./checks/forms.js";
import { analyzeHeaders } from "./checks/headers.js";
import { analyzeInjectionSurfaces } from "./checks/injectionSurfaces.js";
import { analyzeMixedContent } from "./checks/mixedContent.js";
import { analyzeSecrets } from "./checks/secrets.js";
import { analyzeStackExposure } from "./checks/stackExposure.js";
import { analyzeClientAssets } from "./checks/clientAssets.js";
import { analyzeClientCode } from "./checks/clientCode.js";
import { analyzeDangerousExposure } from "./checks/dangerousExposure.js";
import { analyzeActiveLab } from "./checks/activeLab.js";
import { analyzeTransport } from "./checks/transport.js";
import { analyzeVersionIntel } from "./checks/versionIntel.js";
import { createMarkdownReport } from "../reports/markdownReport.js";
import { annotateFindings, tierRank } from "../impact.js";

const CHECKS = {
  transport: analyzeTransport,
  headers: analyzeHeaders,
  cookies: analyzeCookies,
  forms: analyzeForms,
  mixedContent: analyzeMixedContent,
  injectionSurfaces: analyzeInjectionSurfaces,
  secrets: analyzeSecrets,
  stackExposure: analyzeStackExposure,
  versionIntel: analyzeVersionIntel,
  clientAssets: analyzeClientAssets,
  clientCode: analyzeClientCode,
  dangerousExposure: analyzeDangerousExposure,
  activeLab: analyzeActiveLab
};

// Checks that depend on crawled pages / fetched JS assets.
const NEEDS_DISCOVERY = ["injectionSurfaces", "clientAssets", "clientCode", "secrets"];

const SENSITIVE_PATHS = [
  { path: "/.env", label: ".env file", severity: "critical" },
  { path: "/.git/config", label: "Git config", severity: "critical" },
  { path: "/.git/HEAD", label: "Git HEAD", severity: "high" },
  { path: "/config.php.bak", label: "PHP config backup", severity: "high" },
  { path: "/wp-config.php.bak", label: "WordPress config backup", severity: "high" },
  { path: "/backup.zip", label: "Backup archive", severity: "high" },
  { path: "/db.sql", label: "Database dump", severity: "critical" },
  { path: "/dump.sql", label: "Database dump", severity: "critical" },
  { path: "/server-status", label: "Apache server-status", severity: "medium" },
  { path: "/actuator/env", label: "Spring actuator env", severity: "critical" },
  { path: "/actuator/health", label: "Spring actuator health", severity: "medium" },
  { path: "/swagger.json", label: "Swagger JSON", severity: "medium" },
  { path: "/openapi.json", label: "OpenAPI JSON", severity: "medium" },
  { path: "/api-docs", label: "API docs", severity: "medium" },
  { path: "/graphql", label: "GraphQL endpoint", severity: "medium" },
  { path: "/robots.txt", label: "Robots file", severity: "info" },
  { path: "/sitemap.xml", label: "Sitemap", severity: "info" }
];

function selectedChecks(modules) {
  if (!modules || !Array.isArray(modules) || modules.length === 0) return Object.entries(CHECKS);
  const requested = new Set(modules);
  return Object.entries(CHECKS).filter(([name]) => requested.has(name));
}

function requestedModules(modules) {
  return new Set((modules && Array.isArray(modules) ? modules : Object.keys(CHECKS)));
}

export async function runPassiveScan({ rootDir, url, consent, modules, scanProfile, onEvent }) {
  if (consent !== true) {
    throw new Error("Explicit authorization is required before scanning a website.");
  }

  const emit = (phase, message, status) => pushEvent(events, phase, message, status, onEvent);
  const startedAt = new Date();
  const targetUrl = normalizeUrl(url);
  const scanId = `scan-${randomUUID().slice(0, 8)}`;
  const userAgent = "ProjectDawnPassiveScanner/0.1 (+defensive authorized assessment)";
  const findings = [];
  const events = [];
  const requested = requestedModules(modules);
  const activeLabRequested = scanProfile === "activeLab" && requested.has("activeLab");
  const pages = [];
  const assets = [];
  const exposures = [];
  const discovery = {
    crawledPages: 0,
    fetchedAssets: 0,
    checkedExposurePaths: 0,
    discoveredLinks: 0,
    discoveredScripts: 0
  };
  let response;
  let html = "";
  let finalUrl = targetUrl;
  let responseHeaders = {};
  let status = 0;

  emit("scope", "Authorization accepted and target normalized", "complete");

  try {
    emit("fetch", `Fetching ${targetUrl.href}`, "running");
    const initial = await fetchTextResource(targetUrl, userAgent, "entry");
    response = initial.response;
    finalUrl = initial.finalUrl;
    status = initial.status;
    responseHeaders = initial.headers;
    html = initial.html;
    pages.push(initial);
    emit("fetch", `Fetched entry page with HTTP ${status}`, "complete");
  } catch (error) {
    findings.push({
      id: "request.failed",
      title: "Request failed",
      severity: "medium",
      evidence: error.message,
      remediation: "Confirm the URL, network path, DNS, firewall policy, and whether the target allows passive assessment traffic."
    });
    emit("fetch", `Request failed: ${error.message}`, "error");
  }

  if (html && NEEDS_DISCOVERY.some((name) => requested.has(name))) {
    emit("crawl", "Discovering same-origin pages and client assets", "running");
    const discovered = discoverFromHtml(html, finalUrl);
    discovery.discoveredLinks = discovered.links.length;
    discovery.discoveredScripts = discovered.scripts.length;

    const pageTargets = discovered.links.slice(0, 8);
    for (const pageUrl of pageTargets) {
      try {
        const page = await fetchTextResource(pageUrl, userAgent, "crawl", 180_000);
        if (page.html) pages.push(page);
      } catch (error) {
        emit("crawl", `Skipped ${pageUrl.href}: ${error.message}`, "warning");
      }
    }
    discovery.crawledPages = pages.length;

    const scriptTargets = discovered.scripts.slice(0, 12);
    for (const scriptUrl of scriptTargets) {
      try {
        const asset = await fetchTextResource(scriptUrl, userAgent, "script", 260_000);
        if (asset.html || /javascript|text\/plain/i.test(asset.contentType)) assets.push(asset);
      } catch (error) {
        emit("assets", `Skipped ${scriptUrl.href}: ${error.message}`, "warning");
      }
    }
    discovery.fetchedAssets = assets.length;
    emit("crawl", `Mapped ${pages.length} page(s) and ${assets.length} script asset(s)`, "complete");
  }

  if (requested.has("dangerousExposure")) {
    emit("exposure", "Checking bounded sensitive exposure paths", "running");
    const exposureTargets = buildExposureTargets(finalUrl).slice(0, 18);
    for (const target of exposureTargets) {
      try {
        const resource = await fetchTextResource(target.url, userAgent, "exposure", 160_000);
        exposures.push({ ...resource, label: target.label, expectedSeverity: target.severity });
      } catch (error) {
        exposures.push({
          url: target.url.href,
          finalUrl: target.url,
          status: 0,
          headers: {},
          html: "",
          contentType: "",
          purpose: "exposure",
          label: target.label,
          expectedSeverity: target.severity,
          error: error.message
        });
      }
    }
    discovery.checkedExposurePaths = exposures.length;
    emit("exposure", `Checked ${exposures.length} sensitive path(s)`, "complete");
  }

  const context = {
    targetUrl,
    finalUrl,
    status,
    headers: responseHeaders,
    rawHeaders: pages[0]?.rawHeaders || response?.headers,
    html,
    pages,
    assets,
    exposures,
    discovery,
    activeFetch: activeLabRequested && isActiveLabAllowed(finalUrl)
      ? (probeUrl, options = {}) => fetchProbe(probeUrl, userAgent, options)
      : null,
    addEvent: (phase, message, status) => emit(phase, message, status)
  };

  if (activeLabRequested && !isActiveLabAllowed(finalUrl)) {
    findings.push({
      id: "active_lab.blocked_public_target",
      module: "activeLab",
      title: "Active lab mode blocked for non-lab target",
      severity: "info",
      evidence: `${finalUrl.hostname} is not localhost, loopback, or private RFC1918 space.`,
      remediation: "Run active verification only against localhost, private lab hosts, or an intentionally vulnerable owned target."
    });
    emit("active-lab", "Blocked active probes because the target is not a lab/private host", "warning");
  }

  for (const [name, check] of selectedChecks(modules)) {
    try {
      emit("analyze", `Running ${name}`, "running");
      const checkFindings = await check(context);
      findings.push(...checkFindings.map((finding) => ({ ...finding, module: name })));
      emit("analyze", `${name} produced ${checkFindings.length} finding(s)`, "complete");
    } catch (error) {
      findings.push({
        id: `${name}.error`,
        module: name,
        title: `Check failed: ${name}`,
        severity: "info",
        evidence: error.message,
        remediation: "Review the check implementation or retry with the module disabled."
      });
      emit("analyze", `${name} failed: ${error.message}`, "error");
    }
  }

  const endedAt = new Date();
  const normalizedFindings = annotateFindings(dedupeFindings(findings));
  const result = {
    scanId,
    target: targetUrl.href,
    finalUrl: finalUrl.href,
    startedAt: startedAt.toISOString(),
    endedAt: endedAt.toISOString(),
    durationMs: endedAt.getTime() - startedAt.getTime(),
    passiveOnly: !activeLabRequested,
    scanProfile: scanProfile || "baseline",
    modules: selectedChecks(modules).map(([name]) => name),
    status,
    discovery,
    events,
    findings: normalizedFindings.sort(
      (a, b) => tierRank(b.tier) - tierRank(a.tier) || severityRank(b.severity) - severityRank(a.severity)
    )
  };

  emit("report", "Writing Markdown report", "running");
  const report = createMarkdownReport(result);
  const reportsDir = await ensureDir(path.join(rootDir, "data", "reports"));
  const reportPath = path.join(reportsDir, `${scanId}.md`);
  await writeFile(reportPath, report, "utf8");
  emit("report", `Report saved to ${path.basename(reportPath)}`, "complete");

  return {
    ...result,
    report,
    reportPath
  };
}

function severityRank(severity) {
  return { critical: 5, high: 4, medium: 3, low: 2, info: 1 }[severity] || 0;
}

function dedupeFindings(findings) {
  const seen = new Set();
  const result = [];
  for (const finding of findings) {
    const key = [
      finding.id,
      finding.module,
      finding.severity,
      String(finding.evidence || "").slice(0, 240)
    ].join("|");
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(finding);
  }
  return result;
}

function pushEvent(events, phase, message, status, onEvent) {
  const event = {
    at: new Date().toISOString(),
    phase,
    message,
    status
  };
  events.push(event);
  if (typeof onEvent === "function") {
    try {
      onEvent(event);
    } catch {
      // Streaming consumer errors must never break the scan.
    }
  }
}

async function fetchTextResource(url, userAgent, purpose, maxBytes = 350_000) {
  const response = await fetch(url.href, {
    method: "GET",
    redirect: "follow",
    headers: {
      "user-agent": userAgent,
      accept: "text/html,application/xhtml+xml,application/xml,text/plain,application/javascript,application/json,*/*;q=0.8"
    },
    signal: AbortSignal.timeout(12_000)
  });

  const contentType = response.headers.get("content-type") || "";
  const finalUrl = new URL(response.url || url.href);
  const text = await readLimitedText(response, maxBytes);

  return {
    response,
    url: url.href,
    finalUrl,
    status: response.status,
    headers: headerObject(response.headers),
    rawHeaders: response.headers,
    html: text,
    contentType,
    purpose
  };
}

async function fetchProbe(url, userAgent, options = {}) {
  await wait(150);
  const response = await fetch(url.href, {
    method: "GET",
    redirect: options.redirect || "follow",
    headers: {
      "user-agent": `${userAgent} active-lab`,
      accept: "text/html,application/xhtml+xml,application/json,text/plain,*/*;q=0.8"
    },
    signal: AbortSignal.timeout(10_000)
  });
  const text = await readLimitedText(response, 180_000);
  return {
    url: url.href,
    status: response.status,
    headers: headerObject(response.headers),
    text
  };
}

function wait(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function isActiveLabAllowed(url) {
  const hostname = url.hostname.toLowerCase();
  if (hostname === "localhost" || hostname === "::1") return true;
  if (/^127\./.test(hostname)) return true;
  if (/^10\./.test(hostname)) return true;
  if (/^192\.168\./.test(hostname)) return true;
  const private172 = hostname.match(/^172\.(\d{1,2})\./);
  if (private172) {
    const second = Number(private172[1]);
    if (second >= 16 && second <= 31) return true;
  }
  return false;
}

function discoverFromHtml(html, baseUrl) {
  const links = uniqueUrls(
    [...html.matchAll(/\bhref\s*=\s*["']([^"']+)["']/gi)]
      .map((match) => toSameOriginUrl(match[1], baseUrl))
      .filter((url) => url && ["http:", "https:"].includes(url.protocol))
      .filter((url) => !/\.(?:png|jpe?g|gif|svg|webp|ico|woff2?|ttf|css|pdf|zip)$/i.test(url.pathname))
  );

  const scripts = uniqueUrls(
    [...html.matchAll(/<script\b[^>]*\bsrc\s*=\s*["']([^"']+)["'][^>]*>/gi)]
      .map((match) => toSameOriginUrl(match[1], baseUrl))
      .filter((url) => url && /\.(?:js|mjs)(?:$|\?)/i.test(`${url.pathname}${url.search}`))
  );

  return { links, scripts };
}

function toSameOriginUrl(value, baseUrl) {
  try {
    const url = new URL(value, baseUrl.href);
    if (url.origin !== baseUrl.origin) return null;
    url.hash = "";
    return url;
  } catch {
    return null;
  }
}

function uniqueUrls(urls) {
  const seen = new Set();
  const result = [];
  for (const url of urls) {
    const key = url.href;
    if (seen.has(key)) continue;
    seen.add(key);
    result.push(url);
  }
  return result;
}

function buildExposureTargets(baseUrl) {
  return SENSITIVE_PATHS.map((item) => ({
    ...item,
    url: new URL(item.path, baseUrl.origin)
  }));
}
