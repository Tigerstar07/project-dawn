#!/usr/bin/env node
import { mkdir, readFile, readdir, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";

const DEFAULT_MODEL = "dolphin3:8b-llama3.1-q4_K_M";
const DEFAULT_OLLAMA = "http://127.0.0.1:11434";

const args = parseArgs(process.argv.slice(2));
const goal = args.goal || args.g;
if (!goal) {
  console.error('Missing --goal "..."');
  process.exit(1);
}

// ---- Configuration (all overridable via flags / env) --------------------
const root = path.resolve(
  args.workspace || args.w || path.join("data", "agent-runs", safeSegment(goal).slice(0, 40))
);
const model = args.model || DEFAULT_MODEL;
const iterations = Math.max(1, Number(args.iterations || args.n || 25));
const ollamaBaseUrl = (args.ollama || process.env.OLLAMA_BASE_URL || DEFAULT_OLLAMA).replace(/\/$/, "");
const allowShell = Boolean(args["allow-shell"]);
const allowWeb = args.web !== "false";
const stream = args.stream !== "false";

// Performance / reliability knobs.
const numCtx = Number(args["num-ctx"] || 8192);
const numPredict = Number(args["num-predict"] || 4096); // bounds runaway generations
const temperature = Number(args.temperature ?? 0.2);
const keepAlive = String(args["keep-alive"] || "30m"); // keep model resident between calls
const idleTimeoutMs = Number(args["idle-timeout"] || 120) * 1000; // abort if NO tokens for this long
const maxTimeoutMs = Number(args["max-timeout"] || 900) * 1000; // hard ceiling per call
const retries = Math.max(1, Number(args.retries || 3));
const compressEvery = Math.max(0, Number(args["compress-every"] || 5)); // 0 disables
const MAX_CONTEXT_CHARS = Number(args["max-context"] || 20_000);
const MAX_TOOL_OUTPUT = 18_000;
const webTimeoutMs = Number(args["web-timeout"] || 20) * 1000;

// Real code editing: read is always allowed inside the project; writes need the flag.
const allowProjectEdits = Boolean(args["allow-project-edits"]);
const projectRoot = args["project-root"]
  ? path.resolve(args["project-root"])
  : path.resolve(process.cwd());

await mkdir(root, { recursive: true });
await mkdir(path.join(root, "files"), { recursive: true });

const statePath = path.join(root, "state.json");
const memoryPath = path.join(root, "memory.md");
const journalPath = path.join(root, "journal.ndjson");
const goalPath = path.join(root, "goal.md");

await writeIfMissing(goalPath, `# Goal\n\n${goal}\n`);
await writeIfMissing(memoryPath, "# Durable Memory\n\nNo memory compressed yet.\n");

let state = await readJson(statePath, {
  goal,
  model,
  iteration: 0,
  status: "running",
  lastObservation: "Starting run.",
  filesWritten: [],
  tokensGenerated: 0
});
state.tokensGenerated = state.tokensGenerated || 0;

const c = makeColors();
let stopping = false;
process.on("SIGINT", () => {
  stopping = true;
  console.log(c.dim("\n\nStop requested, finishing current step and saving state..."));
});

banner();

try {
  await warmUpModel();
} catch (err) {
  console.error(c.red(`\nCould not reach the model. ${describeError(err)}`));
  console.error(c.dim(`Is Ollama running at ${ollamaBaseUrl} and is "${model}" pulled?`));
  console.error(c.dim('Check with: ollama list   |   start with: ollama serve'));
  process.exit(1);
}

const runStart = Date.now();

for (let i = state.iteration; i < iterations && !stopping; i += 1) {
  state.iteration = i + 1;
  await writeJson(statePath, state);

  const label = `[${state.iteration}/${iterations}]`;
  try {
    const context = await buildContext({ root, goal, state });

    const decision = await askModelForDecision({ goal, context, label });
    await appendJournal(journalPath, {
      at: new Date().toISOString(),
      iteration: state.iteration,
      type: "decision",
      decision
    });
    printDecision(label, decision);

    const observation = await executeDecision(decision);
    state.lastObservation = observation.summary;
    if (observation.file) state.filesWritten.push(observation.file);
    printObservation(label, observation);

    await appendJournal(journalPath, {
      at: new Date().toISOString(),
      iteration: state.iteration,
      type: "observation",
      observation: { summary: observation.summary, file: observation.file }
    });

    if (decision.action === "finish" || decision.done === true) {
      console.log(c.green(`\n${label} model reported the goal complete.`));
      break;
    }

    if (compressEvery && state.iteration % compressEvery === 0) {
      await compressMemory({ label });
    }
  } catch (err) {
    // A single failed step must never kill a long run.
    const message = describeError(err);
    console.log(c.red(`${label} step failed: ${message}`));
    state.lastObservation = `Step failed: ${message}`;
    await appendJournal(journalPath, {
      at: new Date().toISOString(),
      iteration: state.iteration,
      type: "error",
      error: message
    });
  }

  await writeJson(statePath, state);
}

state.status = stopping ? "stopped" : "complete";
await writeJson(statePath, state);

const mins = ((Date.now() - runStart) / 60000).toFixed(1);
console.log(c.green(`\nDone (${state.status}) in ${mins} min.`));
console.log(`  Files written: ${state.filesWritten.length}`);
console.log(`  Tokens generated: ${state.tokensGenerated}`);
console.log(`  Workspace: ${root}`);

// ===========================================================================
// Model interaction
// ===========================================================================

async function warmUpModel() {
  const spin = startSpinner("loading model (first call can take a while)");
  try {
    await chatOllama({
      messages: [{ role: "user", content: "Reply with the single word: ready" }],
      numPredict: 8,
      onToken: () => spin.set("warming up"),
      // generous timeouts: cold model load from disk can be slow
      idleMs: Math.max(idleTimeoutMs, 180_000),
      maxMs: Math.max(maxTimeoutMs, 300_000)
    });
  } finally {
    spin.stop();
  }
  console.log(c.green("Model ready.\n"));
}

async function askModelForDecision({ goal, context, label }) {
  const system = [
    "You are Project Dawn's long-running local coding and research agent.",
    "You persist work through files and a journal, so you can run for many iterations.",
    "Return ONLY a single JSON object. No prose, no markdown fences.",
    "Allowed actions: write_note, write_file, edit_file, read_file, list_dir, web_search, fetch_url, shell, finish.",
    "Files default to your run workspace. To change the project's real source code, set \"scope\":\"project\" and use a path relative to the project root (e.g. scripts/foo.js).",
    "Prefer concrete progress: read code, then edit_file or write_file. Use web_search/fetch_url only when external information is needed.",
    "Web access is PASSIVE only (search + GET fetch). Never attempt attacks, exploits, payloads, fuzzing, brute force, or scanning of systems you do not own or are not explicitly authorized to test. For security work, assess only authorized targets and report findings defensively.",
    "Use shell only for local build/test/list commands, never destructive operations.",
    "Keep each action small and verifiable. Call finish when the goal is met."
  ].join(" ");

  const user = [
    `Goal:\n${goal}`,
    "",
    "Current durable context:",
    context,
    "",
    "Reply with one JSON object of this shape (omit fields you do not use):",
    JSON.stringify({
      action: "write_file",
      reason: "why this step is next",
      scope: "workspace | project",
      path: "files/example.md",
      content: "content for write_file / write_note",
      find: "text to locate for edit_file",
      replace: "replacement text for edit_file",
      query: "search query for web_search",
      url: "https://example.com for fetch_url",
      command: "npm test for shell",
      done: false
    })
  ].join("\n");

  const spin = startSpinner(`${label} thinking`);
  let result;
  try {
    result = await chatOllama({
      messages: [
        { role: "system", content: system },
        { role: "user", content: trim(user, MAX_CONTEXT_CHARS) }
      ],
      json: true,
      onToken: (_t, full) => spin.set(`${full.length} chars`)
    });
  } finally {
    spin.stop();
  }
  recordStats(result.stats);
  printStats(label, result.stats);

  return (
    parseJsonObject(result.content) || {
      action: "write_note",
      reason: "Model returned non-JSON output; saving raw text.",
      path: `files/iteration-${Date.now()}.md`,
      content: result.content
    }
  );
}

async function compressMemory({ label }) {
  const memory = await readText(memoryPath);
  const journal = await readTail(journalPath, 8_000); // smaller window = much faster
  const prompt = [
    "Update Project Dawn's durable memory for a long-running local agent.",
    "Keep only: facts, decisions, useful discoveries, file locations, unresolved tasks, next steps.",
    "Be concise. No hidden reasoning, no chit-chat.",
    "",
    `Goal:\n${goal}`,
    "",
    `Existing memory:\n${memory}`,
    "",
    `Recent journal:\n${journal}`
  ].join("\n");

  const spin = startSpinner(`${label} compressing memory`);
  try {
    const { content, stats } = await chatOllama({
      messages: [{ role: "user", content: trim(prompt, MAX_CONTEXT_CHARS) }],
      numPredict: 1200,
      onToken: (_t, full) => spin.set(`${full.length} chars`)
    });
    recordStats(stats);
    if (content.trim()) await writeFile(memoryPath, trim(content, 40_000), "utf8");
    spin.stop(c.dim(`${label} memory updated.`));
  } catch (err) {
    spin.stop(c.yellow(`${label} memory compression skipped: ${describeError(err)}`));
  }
}

/**
 * Streaming Ollama chat with retries.
 * The key fix: instead of one fixed deadline, we use an IDLE timeout that
 * resets on every received token, plus a hard ceiling. A model that is slow
 * but still producing output will never be killed.
 */
async function chatOllama(opts) {
  let lastError;
  for (let attempt = 1; attempt <= retries; attempt += 1) {
    try {
      return await chatOllamaOnce(opts);
    } catch (err) {
      lastError = err;
      if (attempt < retries) {
        const wait = 1500 * attempt;
        console.log(
          c.yellow(`  model call failed (attempt ${attempt}/${retries}): ${describeError(err)}, retrying in ${wait / 1000}s`)
        );
        await sleep(wait);
      }
    }
  }
  throw lastError;
}

async function chatOllamaOnce({ messages, json = false, numPredict: np, onToken, idleMs, maxMs }) {
  const controller = new AbortController();
  const idle = idleMs ?? idleTimeoutMs;
  const max = maxMs ?? maxTimeoutMs;
  let idleTimer;
  const resetIdle = () => {
    clearTimeout(idleTimer);
    idleTimer = setTimeout(() => controller.abort(new Error(`no output for ${idle / 1000}s`)), idle);
  };
  const maxTimer = setTimeout(() => controller.abort(new Error(`exceeded ${max / 1000}s ceiling`)), max);
  resetIdle();

  let content = "";
  let stats = {};
  try {
    const response = await fetch(`${ollamaBaseUrl}/api/chat`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({
        model,
        messages,
        stream,
        format: json ? "json" : undefined,
        keep_alive: keepAlive,
        options: {
          temperature,
          num_ctx: numCtx,
          num_predict: np ?? numPredict
        }
      }),
      signal: controller.signal
    });

    if (!response.ok) {
      const text = await response.text().catch(() => "");
      throw new Error(`Ollama ${response.status}: ${text || response.statusText}`);
    }

    if (!stream) {
      const data = await response.json();
      content = data.message?.content || "";
      onToken?.(content, content);
      stats = pickStats(data);
      return { content, stats };
    }

    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) break;
      resetIdle();
      buffer += decoder.decode(value, { stream: true });
      let nl;
      while ((nl = buffer.indexOf("\n")) !== -1) {
        const line = buffer.slice(0, nl).trim();
        buffer = buffer.slice(nl + 1);
        if (!line) continue;
        let obj;
        try {
          obj = JSON.parse(line);
        } catch {
          continue;
        }
        if (obj.error) throw new Error(`Ollama error: ${obj.error}`);
        const piece = obj.message?.content;
        if (piece) {
          content += piece;
          onToken?.(piece, content);
        }
        if (obj.done) stats = pickStats(obj);
      }
    }
    return { content, stats };
  } finally {
    clearTimeout(idleTimer);
    clearTimeout(maxTimer);
  }
}

function pickStats(obj) {
  return {
    evalCount: obj.eval_count || 0,
    evalDuration: obj.eval_duration || 0,
    promptEvalCount: obj.prompt_eval_count || 0
  };
}

function recordStats(stats) {
  if (stats?.evalCount) state.tokensGenerated += stats.evalCount;
}

function printStats(label, stats) {
  if (!stats?.evalCount || !stats?.evalDuration) return;
  const tps = stats.evalCount / (stats.evalDuration / 1e9);
  console.log(c.dim(`${label} ${stats.evalCount} tokens @ ${tps.toFixed(1)} tok/s`));
}

// ===========================================================================
// Actions
// ===========================================================================

async function executeDecision(decision) {
  const action = decision.action || "write_note";
  const scope = decision.scope === "project" ? "project" : "workspace";

  if (action === "finish") {
    return { summary: decision.reason || "Model marked the goal complete." };
  }

  if (action === "write_note" || action === "write_file") {
    const rel = String(decision.path || `files/iteration-${Date.now()}.md`);
    const target = resolveScoped(scope, rel, { forWrite: true });
    await mkdir(path.dirname(target), { recursive: true });
    await writeFile(target, String(decision.content ?? decision.reason ?? ""), "utf8");
    return { summary: `Wrote ${scope}:${rel}`, file: scope === "workspace" ? safeRelativePath(rel) : undefined };
  }

  if (action === "edit_file") {
    const rel = String(decision.path || "");
    if (!rel) return { summary: "edit_file requires a path." };
    const target = resolveScoped(scope, rel, { forWrite: true });
    const before = await readFile(target, "utf8").catch(() => null);
    if (before === null) return { summary: `Cannot edit ${scope}:${rel}, file not found.` };
    if (typeof decision.find === "string" && decision.find.length) {
      const occurrences = before.split(decision.find).length - 1;
      if (occurrences === 0) {
        return { summary: `edit_file: "find" text not present in ${scope}:${rel}; no change.` };
      }
      const after = before.split(decision.find).join(String(decision.replace ?? ""));
      await writeFile(target, after, "utf8");
      return { summary: `Edited ${scope}:${rel} (${occurrences} replacement${occurrences === 1 ? "" : "s"})` };
    }
    if (typeof decision.content === "string") {
      await writeFile(target, decision.content, "utf8");
      return { summary: `Overwrote ${scope}:${rel}` };
    }
    return { summary: "edit_file needs either find/replace or content." };
  }

  if (action === "read_file") {
    const rel = String(decision.path || "");
    const target = resolveScoped(scope, rel, { forWrite: false });
    const content = await readFile(target, "utf8");
    return { summary: `Read ${scope}:${rel} (${content.length} chars)`, output: trim(content, MAX_TOOL_OUTPUT) };
  }

  if (action === "list_dir") {
    const rel = String(decision.path || ".");
    const base = scope === "project" ? projectRoot : root;
    resolveScoped(scope, rel, { forWrite: false }); // validates path safety
    const files = await listFiles(path.join(base, rel === "." ? "" : rel));
    return { summary: `Listed ${scope}:${rel} (${files.length} entries)`, output: files.join("\n") };
  }

  if (action === "web_search") {
    if (!allowWeb) return { summary: "Web search skipped (web disabled)." };
    const query = decision.query || decision.reason || goal;
    const results = await webSearch(query);
    const file = `files/search-${Date.now()}.md`;
    await writeFile(path.join(root, file), renderSearchResults(query, results), "utf8");
    return { summary: `Searched "${query}", ${results.length} results → ${file}`, file };
  }

  if (action === "fetch_url") {
    if (!allowWeb) return { summary: "Fetch skipped (web disabled)." };
    const result = await fetchUrlText(decision.url);
    const file = `files/fetch-${Date.now()}.md`;
    await writeFile(path.join(root, file), result, "utf8");
    return { summary: `Fetched ${decision.url} → ${file}`, file };
  }

  if (action === "shell") {
    if (!allowShell) {
      return { summary: "Shell skipped. Rerun with --allow-shell to enable local build/test commands." };
    }
    const result = await runShell(decision.command || "");
    const file = `files/shell-${Date.now()}.txt`;
    await writeFile(path.join(root, file), result, "utf8");
    return { summary: `Ran shell command → ${file}`, file };
  }

  return { summary: `Unknown action "${action}"; no operation performed.` };
}

// ===========================================================================
// Web (passive only)
// ===========================================================================

async function webSearch(query) {
  try {
    if (process.env.SEARXNG_URL) return await searchSearxng(query);
    if (process.env.BRAVE_SEARCH_API_KEY) return await searchBrave(query);
    return await searchDuckDuckGo(query);
  } catch (err) {
    // Non-fatal: surface the problem as a result instead of crashing the run.
    return [{ title: "Web search failed", url: "", snippet: describeError(err) }];
  }
}

async function searchSearxng(query) {
  const base = process.env.SEARXNG_URL.replace(/\/$/, "");
  const url = `${base}/search?q=${encodeURIComponent(query)}&format=json`;
  const response = await fetch(url, { signal: AbortSignal.timeout(webTimeoutMs) });
  if (!response.ok) throw new Error(`SearXNG returned ${response.status}`);
  const data = await response.json();
  return (data.results || []).slice(0, 8).map((r) => ({
    title: r.title,
    url: r.url,
    snippet: r.content || r.snippet || ""
  }));
}

async function searchBrave(query) {
  const url = `https://api.search.brave.com/res/v1/web/search?q=${encodeURIComponent(query)}&count=8`;
  const response = await fetch(url, {
    headers: { "x-subscription-token": process.env.BRAVE_SEARCH_API_KEY, accept: "application/json" },
    signal: AbortSignal.timeout(webTimeoutMs)
  });
  if (!response.ok) throw new Error(`Brave Search returned ${response.status}`);
  const data = await response.json();
  return (data.web?.results || []).slice(0, 8).map((r) => ({
    title: r.title,
    url: r.url,
    snippet: r.description || ""
  }));
}

// No-API-key default so web search works out of the box.
async function searchDuckDuckGo(query) {
  const url = `https://html.duckduckgo.com/html/?q=${encodeURIComponent(query)}`;
  const response = await fetch(url, {
    headers: {
      "user-agent":
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36",
      accept: "text/html"
    },
    signal: AbortSignal.timeout(webTimeoutMs)
  });
  if (!response.ok) throw new Error(`DuckDuckGo returned ${response.status}`);
  const html = await response.text();
  const results = parseDuckDuckGoHtml(html).slice(0, 8);
  if (!results.length) {
    return [{ title: "No results parsed", url: "", snippet: "DuckDuckGo returned no parseable results for this query." }];
  }
  return results;
}

function parseDuckDuckGoHtml(html) {
  const results = [];
  const snippets = [];
  const snippetRe = /class="result__snippet"[^>]*>([\s\S]*?)<\/a>/g;
  let m;
  while ((m = snippetRe.exec(html))) snippets.push(stripTags(m[1]));
  const linkRe = /class="result__a"[^>]+href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/g;
  let i = 0;
  while ((m = linkRe.exec(html))) {
    results.push({ title: stripTags(m[2]), url: decodeDdgUrl(m[1]), snippet: snippets[i] || "" });
    i += 1;
  }
  return results;
}

function decodeDdgUrl(href) {
  try {
    const full = href.startsWith("//") ? `https:${href}` : href;
    const parsed = new URL(full, "https://duckduckgo.com");
    return parsed.searchParams.get("uddg") || full;
  } catch {
    return href;
  }
}

async function fetchUrlText(url) {
  const parsed = new URL(String(url || ""));
  if (!["http:", "https:"].includes(parsed.protocol)) throw new Error("Only http(s) URLs can be fetched.");
  const response = await fetch(parsed.href, {
    headers: { "user-agent": "ProjectDawnLongRun/0.2 (+passive-fetch)" },
    signal: AbortSignal.timeout(Math.max(webTimeoutMs, 25_000))
  });
  const contentType = response.headers.get("content-type") || "";
  const raw = await response.text();
  const body = /html/i.test(contentType) ? htmlToText(raw) : raw;
  return trim(`# ${parsed.href}\n\nHTTP ${response.status} (${contentType})\n\n${body}`, MAX_TOOL_OUTPUT);
}

function htmlToText(html) {
  return String(html || "")
    .replace(/<script[\s\S]*?<\/script>/gi, " ")
    .replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<\/(p|div|li|tr|h[1-6])>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
    .replace(/[ \t]+/g, " ")
    .replace(/\n[ \t]+/g, "\n")
    .replace(/\n{3,}/g, "\n\n")
    .trim();
}

async function runShell(command) {
  const text = String(command || "").trim();
  if (!text) return "No command provided.";
  if (/[;&|`]|Remove-Item|rm\s+-|del\s+|format\s+|shutdown|reg\s+delete|Invoke-WebRequest|curl\s|wget\s/i.test(text)) {
    return `Blocked unsafe shell command: ${text}`;
  }
  return new Promise((resolve) => {
    const child = spawn("powershell.exe", ["-NoProfile", "-Command", text], { cwd: root, windowsHide: true });
    let output = "";
    const timer = setTimeout(() => child.kill(), 120_000);
    child.stdout.on("data", (chunk) => (output += chunk.toString()));
    child.stderr.on("data", (chunk) => (output += chunk.toString()));
    child.on("close", (code) => {
      clearTimeout(timer);
      resolve(trim(`exit ${code}\n${output}`, MAX_TOOL_OUTPUT));
    });
    child.on("error", (err) => {
      clearTimeout(timer);
      resolve(`Failed to run command: ${describeError(err)}`);
    });
  });
}

// ===========================================================================
// Context + filesystem helpers
// ===========================================================================

async function buildContext({ root, goal, state }) {
  const memory = await readText(memoryPath);
  const files = await listFiles(root);
  const journal = await readTail(journalPath, 12_000);
  return trim(
    [
      "# Goal",
      goal,
      "",
      "# State",
      JSON.stringify({ iteration: state.iteration, lastObservation: state.lastObservation, filesWritten: state.filesWritten.slice(-20) }, null, 2),
      "",
      "# Memory",
      memory,
      "",
      "# Workspace Files",
      files.map((f) => `- ${f}`).join("\n"),
      "",
      "# Recent Journal",
      journal
    ].join("\n"),
    MAX_CONTEXT_CHARS
  );
}

function resolveScoped(scope, relPath, { forWrite }) {
  const rel = String(relPath || "").replace(/\\/g, "/").replace(/^\/+/, "");
  if (scope === "project") {
    if (forWrite && !allowProjectEdits) {
      throw new Error("project edits are disabled; rerun with --allow-project-edits");
    }
    if (isBlockedProjectPath(rel)) throw new Error(`Refusing to access protected path: ${rel}`);
    const abs = path.resolve(projectRoot, rel);
    if (!withinRoot(projectRoot, abs)) throw new Error(`Path escapes project root: ${relPath}`);
    return abs;
  }
  const abs = path.resolve(root, rel);
  if (!withinRoot(root, abs)) throw new Error(`Path escapes workspace: ${relPath}`);
  return abs;
}

function withinRoot(base, abs) {
  const b = path.resolve(base);
  return abs === b || abs.startsWith(b + path.sep);
}

function isBlockedProjectPath(rel) {
  return /(^|\/)\.env/i.test(rel) || /(^|\/)\.git(\/|$)/i.test(rel) || /(^|\/)node_modules(\/|$)/i.test(rel) || /(^|\/)data(\/|$)/i.test(rel);
}

function renderSearchResults(query, results) {
  return [
    "# Web Search",
    "",
    `Query: ${query || ""}`,
    "",
    ...results.map((r, index) =>
      [`## ${index + 1}. ${r.title || "Untitled"}`, r.url || "", "", r.snippet || ""].join("\n")
    )
  ].join("\n");
}

async function listFiles(dir, prefix = "") {
  const entries = await readdir(path.join(dir, prefix), { withFileTypes: true }).catch(() => []);
  const files = [];
  for (const entry of entries) {
    const relative = path.join(prefix, entry.name);
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    if (entry.isDirectory()) files.push(...(await listFiles(dir, relative)));
    else files.push(relative);
  }
  return files.slice(0, 200);
}

async function readTail(file, maxChars) {
  const content = await readText(file);
  return content.length > maxChars ? content.slice(-maxChars) : content;
}

async function readText(file) {
  return readFile(file, "utf8").catch(() => "");
}

async function writeIfMissing(file, content) {
  try {
    await stat(file);
  } catch {
    await mkdir(path.dirname(file), { recursive: true });
    await writeFile(file, content, "utf8");
  }
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch {
    return fallback;
  }
}

async function writeJson(file, value) {
  await writeFile(file, `${JSON.stringify(value, null, 2)}\n`, "utf8");
}

async function appendJournal(file, value) {
  const existing = await readText(file);
  await writeFile(file, `${existing}${JSON.stringify(value)}\n`, "utf8");
}

// ===========================================================================
// Parsing + small utilities
// ===========================================================================

function parseJsonObject(text) {
  const value = String(text || "").trim();
  const start = value.indexOf("{");
  const end = value.lastIndexOf("}");
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(value.slice(start, end + 1));
  } catch {
    return null;
  }
}

function safeRelativePath(value) {
  const relative = String(value || "").replace(/\\/g, "/").replace(/^\/+/, "");
  const normalized = path.normalize(relative);
  if (normalized.startsWith("..") || path.isAbsolute(normalized)) {
    throw new Error(`Unsafe path outside workspace: ${value}`);
  }
  return normalized;
}

function safeSegment(value) {
  return String(value || "run").toLowerCase().replace(/[^a-z0-9._-]+/g, "-").replace(/^-+|-+$/g, "") || "run";
}

function stripTags(html) {
  return String(html || "")
    .replace(/<[^>]*>/g, "")
    .replace(/&amp;/g, "&")
    .replace(/&lt;/g, "<")
    .replace(/&gt;/g, ">")
    .replace(/&quot;/g, '"')
    .replace(/&#x27;/g, "'")
    .replace(/&#39;/g, "'")
    .replace(/&nbsp;/g, " ")
    .replace(/\s+/g, " ")
    .trim();
}

function trim(value, max) {
  const text = String(value || "");
  return text.length > max ? `${text.slice(0, max)}\n\n[truncated ${text.length - max} chars]` : text;
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function describeError(err) {
  if (err?.name === "AbortError") return err.cause?.message || "request aborted (timeout)";
  if (err?.cause?.code === "ECONNREFUSED") return "connection refused (is Ollama running?)";
  return err?.message || String(err);
}

function parseArgs(argv) {
  const parsed = {};
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index];
    if (!arg.startsWith("--")) continue;
    const key = arg.slice(2);
    const next = argv[index + 1];
    if (!next || next.startsWith("--")) {
      parsed[key] = true;
    } else {
      parsed[key] = next;
      index += 1;
    }
  }
  return parsed;
}

function webProviderName() {
  if (process.env.SEARXNG_URL) return "SearXNG";
  if (process.env.BRAVE_SEARCH_API_KEY) return "Brave Search";
  return "DuckDuckGo (no key)";
}

// ===========================================================================
// Terminal UI
// ===========================================================================

function makeColors() {
  const on = process.stdout.isTTY && !process.env.NO_COLOR;
  const wrap = (code) => (text) => (on ? `\x1b[${code}m${text}\x1b[0m` : String(text));
  return { dim: wrap(2), red: wrap(31), green: wrap(32), yellow: wrap(33), cyan: wrap(36), bold: wrap(1) };
}

function banner() {
  console.log(c.bold("Project Dawn: long run"));
  console.log(`  Workspace:    ${root}`);
  console.log(`  Model:        ${model}  (ctx ${numCtx}, keep-alive ${keepAlive})`);
  console.log(`  Iterations:   ${iterations}`);
  console.log(`  Web:          ${allowWeb ? `enabled, ${webProviderName()}` : "disabled"}`);
  console.log(`  Shell:        ${allowShell ? "enabled" : "disabled"}`);
  console.log(`  Project edits:${allowProjectEdits ? ` enabled → ${projectRoot}` : " disabled (read-only)"}`);
  console.log(`  Timeouts:     idle ${idleTimeoutMs / 1000}s, ceiling ${maxTimeoutMs / 1000}s, retries ${retries}`);
  console.log("");
}

function printDecision(label, decision) {
  const detail =
    decision.query ? ` "${decision.query}"` :
    decision.url ? ` ${decision.url}` :
    decision.path ? ` ${decision.scope === "project" ? "project:" : ""}${decision.path}` :
    decision.command ? ` ${decision.command}` : "";
  console.log(`${label} ${c.cyan("action")} ${c.bold(decision.action || "write_note")}${detail}`);
  if (decision.reason) console.log(c.dim(`        ${decision.reason}`));
}

function printObservation(label, observation) {
  console.log(`${label} ${c.green("✓")} ${observation.summary}`);
}

function startSpinner(label) {
  if (!process.stdout.isTTY) {
    process.stdout.write(`${label}...\n`);
    return { set() {}, stop(msg) { if (msg) console.log(msg); } };
  }
  const frames = ["|", "/", "-", "\\"];
  const start = Date.now();
  let i = 0;
  let extra = "";
  const id = setInterval(() => {
    const secs = ((Date.now() - start) / 1000).toFixed(1);
    process.stdout.write(`\r  ${frames[i++ % frames.length]} ${label}  ${secs}s  ${extra}        `);
  }, 90);
  return {
    set(text) {
      extra = text;
    },
    stop(finalMsg) {
      clearInterval(id);
      process.stdout.write("\r" + " ".repeat(Math.min(process.stdout.columns || 80, 100)) + "\r");
      if (finalMsg) console.log(finalMsg);
    }
  };
}
