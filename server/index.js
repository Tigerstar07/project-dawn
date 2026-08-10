import express from "express";
import cors from "cors";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { mkdir } from "node:fs/promises";
import { runWorkspaceAgent, listWorkspaceFiles } from "./agents/workspaceAgent.js";
import { runPassiveScan } from "./scanner/index.js";
import { recommendModels, describeDevice } from "./agents/modelAdvisor.js";

const OLLAMA_BASE = () => process.env.OLLAMA_BASE_URL || "http://127.0.0.1:11434";

async function fetchOllamaModels() {
  const response = await fetch(`${OLLAMA_BASE()}/api/tags`, { signal: AbortSignal.timeout(2500) });
  if (!response.ok) throw new Error(`Ollama returned ${response.status}`);
  const data = await response.json();
  return data.models || [];
}

// Streams newline-delimited JSON: many {type:"event"} lines, then one
// {type:"result"} or {type:"error"}. The client reads it progressively so
// progress is real, not simulated.
async function streamRun(res, runner) {
  res.setHeader("Content-Type", "application/x-ndjson");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders?.();
  const write = (obj) => res.write(`${JSON.stringify(obj)}\n`);
  try {
    const result = await runner((event) => write({ type: "event", event }));
    write({ type: "result", result });
  } catch (error) {
    write({ type: "error", error: error.message });
  } finally {
    res.end();
  }
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const rootDir = path.resolve(__dirname, "..");
const isProd = process.argv.includes("--prod");
const port = Number(process.env.PORT || 4177);

const app = express();
app.use(cors());
app.use(express.json({ limit: "1mb" }));

await mkdir(path.join(rootDir, "data", "workspaces"), { recursive: true });
await mkdir(path.join(rootDir, "data", "reports"), { recursive: true });

app.get("/api/health", async (_req, res) => {
  let ollama = { ok: false, models: [], error: null };
  let recommendation = null;

  try {
    const rawModels = await fetchOllamaModels();
    recommendation = recommendModels(rawModels);
    ollama = {
      ok: true,
      models: rawModels.map((model) => model.name),
      modelDetails: recommendation.models,
      recommended: recommendation.recommended,
      error: null
    };
  } catch (error) {
    ollama.error = error.message;
    recommendation = { device: describeDevice(), recommended: "", reason: error.message, models: [] };
  }

  res.json({
    app: "Project Dawn",
    ok: true,
    ollama,
    recommendation,
    dataDir: path.join(rootDir, "data")
  });
});

app.get("/api/models", async (_req, res) => {
  try {
    const rawModels = await fetchOllamaModels();
    res.json(recommendModels(rawModels));
  } catch (error) {
    res.status(502).json({ device: describeDevice(), recommended: "", reason: error.message, models: [], error: error.message });
  }
});

app.post("/api/ai/ask", async (req, res) => {
  try {
    const result = await runWorkspaceAgent({
      rootDir,
      question: req.body.question,
      model: req.body.model,
      sessionId: req.body.sessionId,
      steps: req.body.steps,
      actionMode: req.body.actionMode,
      targetUrl: req.body.targetUrl,
      consent: req.body.consent,
      modules: req.body.modules,
      scanProfile: req.body.scanProfile
    });
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/ai/ask/stream", async (req, res) => {
  await streamRun(res, (onEvent) =>
    runWorkspaceAgent({
      rootDir,
      question: req.body.question,
      model: req.body.model,
      sessionId: req.body.sessionId,
      steps: req.body.steps,
      actionMode: req.body.actionMode,
      targetUrl: req.body.targetUrl,
      consent: req.body.consent,
      modules: req.body.modules,
      scanProfile: req.body.scanProfile,
      onEvent
    })
  );
});

app.get("/api/workspaces/:sessionId/files", async (req, res) => {
  try {
    const result = await listWorkspaceFiles(rootDir, req.params.sessionId);
    res.json(result);
  } catch (error) {
    res.status(404).json({ error: error.message });
  }
});

app.post("/api/scans", async (req, res) => {
  try {
    const result = await runPassiveScan({
      rootDir,
      url: req.body.url,
      consent: req.body.consent,
      modules: req.body.modules,
      scanProfile: req.body.scanProfile
    });
    res.json(result);
  } catch (error) {
    res.status(400).json({ error: error.message });
  }
});

app.post("/api/scans/stream", async (req, res) => {
  await streamRun(res, (onEvent) =>
    runPassiveScan({
      rootDir,
      url: req.body.url,
      consent: req.body.consent,
      modules: req.body.modules,
      scanProfile: req.body.scanProfile,
      onEvent
    })
  );
});

if (isProd) {
  app.use(express.static(path.join(rootDir, "dist")));
  app.get("*", (_req, res) => {
    res.sendFile(path.join(rootDir, "dist", "index.html"));
  });
} else {
  const { createServer: createViteServer } = await import("vite");
  const vite = await createViteServer({
    root: rootDir,
    server: { middlewareMode: true },
    appType: "spa"
  });
  app.use(vite.middlewares);
}

app.listen(port, () => {
  console.log(`Project Dawn is running at http://localhost:${port}`);
});
