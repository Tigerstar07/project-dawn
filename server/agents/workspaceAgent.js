import path from "node:path";
import { randomUUID } from "node:crypto";
import { chatWithOllama } from "./ollamaClient.js";
import { ensureDir, readMarkdownFiles, safeSegment, truncateText, writeMarkdown } from "../utils/files.js";
import { runPassiveScan } from "../scanner/index.js";

const DEFAULT_MODEL = "dolphin3:8b-llama3.1-q4_K_M";
const NOTE_TYPES = ["plan", "facts", "risks", "answer", "next-steps"];
const SCAN_NOTE_TYPES = ["dawn-brief", "fix-priorities", "operator-answer"];

function workspacePath(rootDir, sessionId) {
  return path.join(rootDir, "data", "workspaces", safeSegment(sessionId, "session"));
}

function parseModelJson(text) {
  const trimmed = String(text || "").trim();
  const fenced = trimmed.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1] : trimmed;
  const start = candidate.indexOf("{");
  const end = candidate.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;

  try {
    return JSON.parse(candidate.slice(start, end + 1));
  } catch {
    return null;
  }
}

function padIndex(index) {
  return String(index).padStart(2, "0");
}

function trimUrl(value) {
  return String(value || "").replace(/[),.;\]]+$/g, "");
}

function extractTargetUrl(question) {
  const text = String(question || "");
  const explicit = text.match(/\bhttps?:\/\/[^\s<>"']+/i);
  if (explicit) return trimUrl(explicit[0]);

  const domain = text.match(/\b(?:[a-z0-9-]+\.)+[a-z]{2,}(?:\/[^\s<>"']*)?/i);
  return domain ? trimUrl(domain[0]) : "";
}

function renderScanSummary(scan) {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const finding of scan.findings || []) {
    counts[finding.severity] = (counts[finding.severity] || 0) + 1;
  }

  return [
    "# Passive Scan Completed",
    "",
    `- Scan ID: ${scan.scanId}`,
    `- Target: ${scan.target}`,
    `- Final URL: ${scan.finalUrl}`,
    `- HTTP status: ${scan.status}`,
    `- Duration: ${scan.durationMs} ms`,
    `- Modules: ${scan.modules.join(", ")}`,
    scan.discovery ? `- Discovery: ${scan.discovery.crawledPages} page(s), ${scan.discovery.fetchedAssets} asset(s), ${scan.discovery.checkedExposurePaths} exposure path(s)` : "",
    "",
    "## Severity Counts",
    "",
    `- Critical: ${counts.critical}`,
    `- High: ${counts.high}`,
    `- Medium: ${counts.medium}`,
    `- Low: ${counts.low}`,
    `- Info: ${counts.info}`,
    "",
    "## Boundary",
    "",
    "This was an authorized review. Active lab probes, when enabled, are restricted to localhost/private lab targets and do not attempt brute force, destructive actions, authentication bypass, or data extraction."
  ].join("\n");
}

function renderFindings(scan) {
  if (!scan.findings?.length) {
    return [
      "# Findings",
      "",
      "No findings were identified by the enabled passive checks."
    ].join("\n");
  }

  const lines = ["# Findings", ""];
  scan.findings.forEach((finding, index) => {
    lines.push(`## ${index + 1}. ${finding.title}`);
    lines.push("");
    lines.push(`- Severity: ${finding.severity}`);
    lines.push(`- Module: ${finding.module || "core"}`);
    lines.push(`- ID: ${finding.id}`);
    lines.push(`- Evidence: ${String(finding.evidence || "Not provided").replace(/\n/g, " / ")}`);
    lines.push(`- Remediation: ${finding.remediation}`);
    lines.push("");
  });
  return lines.join("\n");
}

function fallbackNote({ question, index, noteType, error }) {
  const type = NOTE_TYPES[Math.min(index, NOTE_TYPES.length - 1)];
  const safeType = noteType || type;
  const title = safeType === "answer" ? "Draft Answer" : `${safeType[0].toUpperCase()}${safeType.slice(1)} Notes`;
  const body =
    safeType === "plan"
      ? [
          `# ${title}`,
          "",
          "The local model did not respond, so Project Dawn created a fallback workspace note.",
          "",
          "## Working Goal",
          question,
          "",
          "## Next Move",
          "Start Ollama, pull the configured model, then retry this question."
        ].join("\n")
      : [
          `# ${title}`,
          "",
          "The previous model call was unavailable.",
          "",
          `Error: ${error || "unknown model error"}`
        ].join("\n");

  return { fileName: `${padIndex(index)}-${safeType}.md`, content: body };
}

async function writeStep({ dir, question, model, index, noteType, scan, emit }) {
  const previous = await readMarkdownFiles(dir);
  const notes = previous
    .map((file) => `--- ${file.name} ---\n${file.content}`)
    .join("\n\n");

  const system = [
    "You are Project Dawn's local workspace agent.",
    "Create concise, user-visible working notes as markdown files.",
    "Do not write hidden chain-of-thought. Write useful artifacts: plan, facts, assumptions, risks, checks, and a final answer.",
    "CRITICAL: When passive scan results are provided, you may ONLY discuss findings that appear verbatim in those results. Never invent vulnerabilities, severities, CVEs, or attack paths that are not in the evidence. If the evidence does not support a claim, say so explicitly.",
    "Do not provide breach instructions, exploit payloads, brute-force steps, or unauthorized access guidance.",
    "Focus on defensive findings, severity, evidence, and remediation. Reference findings by their ID from the scan.",
    "Prefer concrete next actions, explicit uncertainty, and short sections.",
    "Return only valid JSON with keys: fileName, title, content, nextFocus."
  ].join(" ");

  const selectedNoteType = noteType || NOTE_TYPES[Math.min(index - 1, NOTE_TYPES.length - 1)];
  const scanContext = scan
    ? [
        "Actual passive scan result:",
        truncateText(scan.report || renderFindings(scan), 12000)
      ].join("\n")
    : "No passive scan was run for this workspace pass.";

  const user = [
    `Question: ${question}`,
    "",
    `Create the next ${selectedNoteType} note.`,
    "The note should help future model calls continue from files instead of relying on one long context.",
    "",
    scanContext,
    "",
    "Existing workspace notes:",
    truncateText(notes, 9000),
    "",
    "JSON shape:",
    `{"fileName":"${padIndex(index)}-${selectedNoteType}.md","title":"Short title","content":"# Markdown note...","nextFocus":"One-sentence next focus"}`
  ].join("\n");

  try {
    emit?.("model", `Asking ${model} for the ${selectedNoteType} note`, "running");
    const raw = await chatWithOllama({
      model,
      messages: [
        { role: "system", content: system },
        { role: "user", content: user }
      ]
    });
    const parsed = parseModelJson(raw);
    const content = parsed?.content || raw;
    const fileName = parsed?.fileName || `${padIndex(index)}-${selectedNoteType}.md`;
    await writeMarkdown(dir, fileName, content);
    emit?.("model", `Wrote ${fileName}`, "complete");
  } catch (error) {
    const note = fallbackNote({ question, index, noteType: selectedNoteType, error: error.message });
    await writeMarkdown(dir, note.fileName, note.content);
    emit?.("model", `Model unavailable for ${selectedNoteType} note — wrote fallback`, "warning");
  }
}

export async function runWorkspaceAgent({ rootDir, question, model, sessionId, steps, actionMode, targetUrl, consent, modules, scanProfile, onEvent }) {
  const cleanQuestion = String(question || "").trim();
  if (!cleanQuestion) throw new Error("A question is required.");

  const events = [];
  const emit = (phase, message, status) => {
    const event = { at: new Date().toISOString(), phase, message, status };
    events.push(event);
    if (typeof onEvent === "function") {
      try {
        onEvent(event);
      } catch {
        // Streaming consumer errors must never break the run.
      }
    }
  };

  const cleanSessionId = safeSegment(sessionId || `dawn-${randomUUID().slice(0, 8)}`);
  const dir = await ensureDir(workspacePath(rootDir, cleanSessionId));
  const stepCount = Math.max(1, Math.min(Number(steps || 3), 5));
  const mode = String(actionMode || "assess");
  const extractedTarget = String(targetUrl || "").trim() || extractTargetUrl(cleanQuestion);
  const shouldScan = mode === "assess" && Boolean(extractedTarget);

  if (shouldScan && consent !== true) {
    throw new Error("Authorized scope is required before Project Dawn can run an assessment.");
  }

  emit("workspace", `Workspace ${cleanSessionId} ready`, "complete");

  await writeMarkdown(
    dir,
    "00-question.md",
    [
      "# User Question",
      "",
      cleanQuestion,
      "",
      "## Workspace Contract",
      "Project Dawn stores concise working artifacts here so later calls can continue from files.",
      "",
      "## Requested Mode",
      mode,
      "",
      "## Target",
      extractedTarget || "No target URL supplied."
    ].join("\n")
  );

  let scan = null;
  let nextIndex = 1;

  if (shouldScan) {
    emit("scan", `Starting passive scan of ${extractedTarget}`, "running");
    scan = await runPassiveScan({
      rootDir,
      url: extractedTarget,
      consent: true,
      modules,
      scanProfile,
      onEvent // stream the scanner's own phase events live
    });
    emit("scan", `Scan complete — ${scan.findings.length} finding(s)`, "complete");

    await writeMarkdown(dir, `${padIndex(nextIndex)}-passive-scan.md`, renderScanSummary(scan));
    nextIndex += 1;
    await writeMarkdown(dir, `${padIndex(nextIndex)}-findings.md`, renderFindings(scan));
    nextIndex += 1;
    await writeMarkdown(dir, `${padIndex(nextIndex)}-report.md`, scan.report);
    nextIndex += 1;
  }

  const noteTypes = scan ? SCAN_NOTE_TYPES : NOTE_TYPES;
  const boundedSteps = Math.min(stepCount, noteTypes.length);
  for (let offset = 0; offset < boundedSteps; offset += 1) {
    await writeStep({
      dir,
      question: cleanQuestion,
      model,
      index: nextIndex + offset,
      noteType: noteTypes[offset],
      scan,
      emit
    });
  }

  emit("done", "Workspace run finished", "complete");
  const files = await readMarkdownFiles(dir);
  return {
    sessionId: cleanSessionId,
    model: model || DEFAULT_MODEL,
    files,
    scan,
    actions: [
      shouldScan ? `Passive scan completed for ${scan?.finalUrl || extractedTarget}` : "Workspace notes generated",
      ...events.slice(-5).map((event) => `${event.phase}: ${event.message}`),
      `${files.length} workspace files available`
    ],
    events: [...(scan?.events || []), ...events].sort((a, b) => a.at.localeCompare(b.at))
  };
}

export async function listWorkspaceFiles(rootDir, sessionId) {
  const cleanSessionId = safeSegment(sessionId);
  const dir = workspacePath(rootDir, cleanSessionId);
  return {
    sessionId: cleanSessionId,
    files: await readMarkdownFiles(dir)
  };
}
