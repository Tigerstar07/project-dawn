import { useEffect, useMemo, useRef, useState } from "react";
import {
  Activity,
  AlertTriangle,
  Brain,
  CheckCircle2,
  Download,
  FileText,
  Globe2,
  Loader2,
  Play,
  RefreshCw,
  ShieldCheck,
  Sliders,
  Sun
} from "lucide-react";

const DEFAULT_MODEL = "dolphin3:8b-llama3.1-q4_K_M";
const DEFAULT_QUESTION = "Run an authorized passive security assessment and tell me what matters most, in plain language.";

const SCAN_MODULES = [
  { id: "transport", label: "Transport (HTTPS)" },
  { id: "headers", label: "Security headers" },
  { id: "cookies", label: "Cookies" },
  { id: "forms", label: "Forms" },
  { id: "mixedContent", label: "Mixed content" },
  { id: "injectionSurfaces", label: "Injection surfaces" },
  { id: "secrets", label: "Exposed secrets" },
  { id: "stackExposure", label: "Tech/version leaks" },
  { id: "versionIntel", label: "Version & CVE intel" },
  { id: "clientAssets", label: "Client assets" },
  { id: "clientCode", label: "Deep JS analysis" },
  { id: "dangerousExposure", label: "Sensitive files" },
  { id: "activeLab", label: "Active lab probes" }
];

const ALL_MODULES = SCAN_MODULES.map((module) => module.id);
const EVIDENCE_FILES = /(?:passive-scan|findings|report)\.md$/i;
const NOTE_PRIORITY = ["operator-answer", "fix-priorities", "dawn-brief", "answer", "risks", "facts", "plan"];
const TIER_LABELS = { breach: "likely breach", exploitable: "exploitable", hardening: "hardening", info: "info" };

function isPublicTarget(rawUrl) {
  try {
    const host = new URL(/^https?:\/\//i.test(rawUrl) ? rawUrl : `https://${rawUrl}`).hostname.toLowerCase();
    if (host === "localhost" || host === "::1" || /^127\./.test(host)) return false;
    if (/^10\./.test(host) || /^192\.168\./.test(host)) return false;
    const m = host.match(/^172\.(\d{1,2})\./);
    if (m && Number(m[1]) >= 16 && Number(m[1]) <= 31) return false;
    return true;
  } catch {
    return true;
  }
}

// Reads the streaming NDJSON run endpoint; falls back to the one-shot endpoint
// if streaming isn't available (e.g. server not restarted after an update).
async function streamRequest(path, body, onEvent) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(body)
    });
  } catch (error) {
    throw new Error(`Cannot reach the Dawn server, is it running? (${error.message})`);
  }

  const contentType = response.headers.get("content-type") || "";
  if (response.status === 404 || !response.body || !contentType.includes("ndjson")) {
    return fallbackRequest(path.replace(/\/stream$/, ""), body, onEvent);
  }

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  let result = null;
  for (;;) {
    const { value, done } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    let nl;
    while ((nl = buffer.indexOf("\n")) !== -1) {
      const line = buffer.slice(0, nl).trim();
      buffer = buffer.slice(nl + 1);
      if (!line) continue;
      let message;
      try {
        message = JSON.parse(line);
      } catch {
        continue;
      }
      if (message.type === "event") onEvent?.(message.event);
      else if (message.type === "result") result = message.result;
      else if (message.type === "error") throw new Error(message.error);
    }
  }
  if (!result) throw new Error("The run ended without returning a result.");
  return result;
}

async function fallbackRequest(path, body, onEvent) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body)
  });
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error((data && data.error) || `Request failed (${response.status})`);
  if (!data) throw new Error("The server returned an unreadable response.");
  for (const event of data.events || []) onEvent?.(event);
  return data;
}

function App() {
  const [health, setHealth] = useState(null);
  const [healthError, setHealthError] = useState("");
  const [recommendation, setRecommendation] = useState(null);

  const [url, setUrl] = useState("");
  const [consent, setConsent] = useState(false);
  const [useAi, setUseAi] = useState(true);

  const [model, setModel] = useState(DEFAULT_MODEL);
  const [modelTouched, setModelTouched] = useState(false);
  const [passes, setPasses] = useState(3);
  const [modules, setModules] = useState(ALL_MODULES);
  const [activeLab, setActiveLab] = useState(false);
  const [question, setQuestion] = useState(DEFAULT_QUESTION);
  const [session, setSession] = useState("");

  const [running, setRunning] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState(null);
  const [notes, setNotes] = useState([]);
  const [selectedNote, setSelectedNote] = useState("");
  const [runEvents, setRunEvents] = useState([]);

  useEffect(() => {
    refreshHealth();
  }, []);

  const severityCounts = useSeverityCounts(result);
  const selectedNoteContent = useMemo(
    () => notes.find((note) => note.name === selectedNote)?.content || "",
    [notes, selectedNote]
  );

  async function refreshHealth() {
    setHealthError("");
    try {
      const response = await fetch("/api/health");
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Health check failed");
      setHealth(data);
      setRecommendation(data.recommendation || null);
      const installed = data.ollama?.models || [];
      if (!modelTouched) {
        const recommended = data.recommendation?.recommended;
        if (recommended && installed.includes(recommended)) setModel(recommended);
        else if (installed.includes(DEFAULT_MODEL)) setModel(DEFAULT_MODEL);
      }
    } catch (err) {
      setHealthError(err.message);
    }
  }

  function chooseModel(name) {
    setModelTouched(true);
    setModel(name);
  }

  function toggleModule(id) {
    setModules((current) => (current.includes(id) ? current.filter((m) => m !== id) : [...current, id]));
  }

  async function run(event) {
    event.preventDefault();
    if (!url.trim()) {
      setError("Enter the address of a website first.");
      return;
    }
    if (!consent) {
      setError("Tick the box to confirm you are authorized to test this site.");
      return;
    }

    setRunning(true);
    setError("");
    setResult(null);
    setNotes([]);
    setRunEvents([]);
    const scanProfile = activeLab ? "activeLab" : "baseline";
    const onEvent = (ev) => setRunEvents((current) => [...current, ev]);

    try {
      if (useAi) {
        const data = await streamRequest(
          "/api/ai/ask/stream",
          {
            question: question || DEFAULT_QUESTION,
            model,
            sessionId: session,
            steps: Number(passes),
            actionMode: "assess",
            targetUrl: url,
            consent,
            modules,
            scanProfile
          },
          onEvent
        );
        setSession(data.sessionId || "");
        setResult(data.scan || null);
        const aiNotes = (data.files || []).filter(
          (file) => !EVIDENCE_FILES.test(file.name) && file.name !== "00-question.md"
        );
        setNotes(aiNotes);
        setSelectedNote(pickDefaultNote(aiNotes));
      } else {
        const data = await streamRequest("/api/scans/stream", { url, consent, modules, scanProfile }, onEvent);
        setResult(data);
        setNotes([]);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setRunning(false);
    }
  }

  function downloadReport() {
    if (!result?.report) return;
    const blob = new Blob([result.report], { type: "text/markdown" });
    const href = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = href;
    anchor.download = `${result.scanId}.md`;
    anchor.click();
    URL.revokeObjectURL(href);
  }

  const ollamaOk = health?.ollama?.ok;
  const targetIsPublic = isPublicTarget(url);

  return (
    <div className="dawn-app single">
      <aside className="dawn-rail">
        <div className="brand-stack">
          <div className="brand-mark">
            <Sun size={23} />
          </div>
          <div>
            <h1>Project Dawn</h1>
            <p>Local security check</p>
          </div>
        </div>

        <div className="rail-block">
          <StatusPill ok={ollamaOk} label={ollamaOk ? "Ollama online" : "Ollama offline"} />
          <button className="icon-button" type="button" onClick={refreshHealth} title="Refresh status">
            <RefreshCw size={18} />
          </button>
        </div>

        <div className="rail-help">
          <h4>How it works</h4>
          <ol>
            <li>Paste a website address you own or are allowed to test.</li>
            <li>Press <strong>Run</strong>. Dawn checks the site safely (it only looks, it never attacks).</li>
            <li>Read the <strong>summary</strong> for what to fix first. Each point links back to the raw evidence.</li>
          </ol>
        </div>

        {healthError ? <InlineAlert tone="warning" message={healthError} /> : null}
      </aside>

      <div className="dawn-stage">
        <header className="dawn-header simple">
          <h2>Check a website for security issues</h2>
          <p className="view-hint">
            Dawn reads what a site already serves and lists what to fix first. It never attacks, brute-forces or
            exploits anything, so only point it at sites you own or have permission to test.
          </p>
        </header>

        <main className="scan-layout">
          <form className="panel command-panel" onSubmit={run}>
            <label className="field">
              <span className="field-label"><Globe2 size={15} /> Website address</span>
              <input value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://example.com" />
            </label>

            <label className="big-check">
              <input type="checkbox" checked={consent} onChange={(e) => setConsent(e.target.checked)} />
              <span>
                <strong>I'm authorized to test this site.</strong>
                <small>It's mine, or I have written permission (or it's an in-scope bug-bounty target).</small>
              </span>
            </label>

            <label className="big-check">
              <input type="checkbox" checked={useAi} onChange={(e) => setUseAi(e.target.checked)} />
              <span>
                <strong>Summarise with a local model</strong>
                <small>{useAi ? `Using ${model}` : "Off: show raw findings only"}</small>
              </span>
            </label>

            {error ? <InlineAlert tone="danger" message={error} /> : null}

            <button className="primary-button big" type="submit" disabled={running}>
              {running ? <Loader2 className="spin" size={18} /> : <Play size={18} />}
              {running ? "Running…" : useAi ? "Run scan" : "Run scan"}
            </button>

            <details className="advanced">
              <summary>
                <Sliders size={15} /> Advanced options
              </summary>
              <div className="advanced-body">
                <ModelPicker
                  model={model}
                  setModel={chooseModel}
                  modelDetails={health?.ollama?.modelDetails || []}
                  recommendation={recommendation}
                  disabled={!useAi}
                />

                {useAi ? (
                  <label className="field">
                    <span className="field-label">AI thoroughness ({passes} pass{passes > 1 ? "es" : ""})</span>
                    <input type="range" min="1" max="5" value={passes} onChange={(e) => setPasses(e.target.value)} />
                    <span className="field-hint">More passes = a more detailed brief, but slower.</span>
                  </label>
                ) : null}

                <label className="big-check small">
                  <input
                    type="checkbox"
                    checked={activeLab}
                    onChange={(e) => setActiveLab(e.target.checked)}
                    disabled={targetIsPublic}
                  />
                  <span>
                    <strong>Send active lab probes</strong>
                    <small>
                      {targetIsPublic
                        ? "Disabled: only allowed on localhost / your own private lab, not public sites."
                        : "Harmless test requests for a local/private lab target."}
                    </small>
                  </span>
                </label>

                <div className="field">
                  <span className="field-label">Checks to run</span>
                  <span className="field-hint">All on by default. Turn off what you don't need.</span>
                  <ModulePicker modules={modules} toggleModule={toggleModule} />
                </div>

                {useAi ? (
                  <label className="field">
                    <span className="field-label">What do you want to know? (optional)</span>
                    <textarea value={question} onChange={(e) => setQuestion(e.target.value)} rows={3} />
                  </label>
                ) : null}
              </div>
            </details>
          </form>

          <section className="results-column">
            <div className="panel result-summary">
              <div className="panel-title">
                <Activity size={18} />
                <h3>{running ? "Live progress" : result ? "Summary" : "Results"}</h3>
                {result?.report ? (
                  <button className="icon-button push-right" type="button" onClick={downloadReport} title="Download report">
                    <Download size={18} />
                  </button>
                ) : null}
              </div>

              {running || (runEvents.length > 0 && !result) ? (
                <LiveLog events={runEvents} loading={running} emptyText="Press Run to start." />
              ) : null}

              {result ? (
                <>
                  <p className="evidence-note">
                    <ShieldCheck size={13} /> {result.findings.length} finding(s) on{" "}
                    <strong>{result.finalUrl || result.target}</strong>, each one is observed evidence, not an AI guess.
                  </p>
                  <div className="summary-grid">
                    <SeverityBox label="Critical" value={severityCounts.critical} tone="critical" />
                    <SeverityBox label="High" value={severityCounts.high} tone="high" />
                    <SeverityBox label="Medium" value={severityCounts.medium} tone="medium" />
                    <SeverityBox label="Low" value={severityCounts.low} tone="low" />
                    <SeverityBox label="Info" value={severityCounts.info} tone="info" />
                  </div>
                </>
              ) : running ? null : (
                <EmptyState icon={<AlertTriangle size={22} />} text="No results yet. Run a scan." />
              )}
            </div>

            {useAi && notes.length ? (
              <section className="panel ai-brief">
                <div className="panel-title">
                  <Brain size={18} />
                  <h3>Summary</h3>
                  <span className="tag ai push-right">Written by the local model. Check it against the evidence below.</span>
                </div>
                {notes.length > 1 ? (
                  <div className="note-tabs">
                    {notes.map((note) => (
                      <button
                        key={note.name}
                        type="button"
                        className={selectedNote === note.name ? "active" : ""}
                        onClick={() => setSelectedNote(note.name)}
                      >
                        {prettyNoteName(note.name)}
                      </button>
                    ))}
                  </div>
                ) : null}
                <pre className="markdown-preview">{selectedNoteContent || "The model did not return a summary."}</pre>
              </section>
            ) : null}

            {result?.findings?.length ? (
              <section className="panel finding-panel">
                <div className="panel-title">
                  <ShieldCheck size={18} />
                  <h3>Evidence ({result.findings.length})</h3>
                </div>
                <div className="finding-list">
                  {result.findings.map((finding, index) => (
                    <article className="finding" key={`${finding.id}-${index}`}>
                      <div className="finding-heading">
                        {finding.tier ? <span className={`tier ${finding.tier}`}>{TIER_LABELS[finding.tier] || finding.tier}</span> : null}
                        <span className={`severity ${finding.severity}`}>{finding.severity}</span>
                        <h4>{finding.title}</h4>
                      </div>
                      <p className="finding-meta">{finding.id} / {finding.module}</p>
                      {finding.impact ? <p className="impact">{finding.impact}</p> : null}
                      <p className="evidence-text">{finding.evidence}</p>
                      <p className="remediation">{finding.remediation}</p>
                    </article>
                  ))}
                </div>
              </section>
            ) : null}
          </section>
        </main>
      </div>
    </div>
  );
}

function pickDefaultNote(notes) {
  for (const key of NOTE_PRIORITY) {
    const match = notes.find((note) => note.name.includes(key));
    if (match) return match.name;
  }
  return notes[notes.length - 1]?.name || "";
}

function prettyNoteName(name) {
  return name
    .replace(/^\d+-/, "")
    .replace(/\.md$/, "")
    .replace(/-/g, " ")
    .replace(/\b\w/g, (c) => c.toUpperCase());
}

function ModelPicker({ model, setModel, modelDetails, recommendation, disabled }) {
  const details = modelDetails?.length ? modelDetails : null;
  const known = details?.some((entry) => entry.name === model);

  return (
    <div className="model-block">
      <span className="field-label"><Brain size={14} /> AI model</span>
      <select
        value={known ? model : "__custom"}
        disabled={disabled}
        onChange={(event) => {
          if (event.target.value !== "__custom") setModel(event.target.value);
        }}
      >
        {details ? (
          details.map((entry) => (
            <option key={entry.name} value={entry.name}>
              {entry.recommended ? "★ " : ""}
              {entry.name} · {entry.paramLabel} · {entry.sizeLabel}
              {entry.fits ? "" : " · heavy"}
            </option>
          ))
        ) : (
          <option value={model}>{model}</option>
        )}
        {details && !known ? <option value="__custom">{model} (custom)</option> : null}
      </select>
      {recommendation?.recommended ? (
        <div className="model-reco">
          <p className="reco-head">
            <Brain size={13} /> Recommended: <strong>{recommendation.recommended}</strong>
          </p>
          <p className="reco-reason">{recommendation.reason}</p>
          {model !== recommendation.recommended ? (
            <button type="button" className="link-button" onClick={() => setModel(recommendation.recommended)}>
              Use recommended
            </button>
          ) : (
            <span className="reco-active">
              <CheckCircle2 size={13} /> in use
            </span>
          )}
        </div>
      ) : null}
    </div>
  );
}

function ModulePicker({ modules, toggleModule }) {
  return (
    <div className="module-picker" aria-label="Scan checks">
      {SCAN_MODULES.map((module) => (
        <button
          key={module.id}
          type="button"
          className={modules.includes(module.id) ? "module active" : "module"}
          onClick={() => toggleModule(module.id)}
        >
          <CheckCircle2 size={15} />
          {module.label}
        </button>
      ))}
    </div>
  );
}

function LiveLog({ events, loading, emptyText }) {
  const endRef = useRef(null);
  useEffect(() => {
    endRef.current?.scrollIntoView({ block: "nearest" });
  }, [events]);

  if (!events?.length) {
    return <div className="live-log empty">{loading ? "Starting…" : emptyText}</div>;
  }

  return (
    <div className="live-log">
      {events.map((event, index) => (
        <div className={`log-row ${event.status || ""}`} key={`${event.at}-${index}`}>
          <span className="log-dot" />
          <span className="log-phase">{event.phase}</span>
          <span className="log-msg">{event.message}</span>
        </div>
      ))}
      <div ref={endRef} />
    </div>
  );
}

function StatusPill({ ok, label }) {
  return (
    <span className={ok ? "status-pill ok" : "status-pill muted"}>
      <span />
      {label}
    </span>
  );
}

function SeverityBox({ label, value, tone }) {
  return (
    <div className={`severity-box ${tone}`}>
      <strong>{value}</strong>
      <span>{label}</span>
    </div>
  );
}

function EmptyState({ icon, text }) {
  return (
    <div className="empty-state">
      {icon}
      <span>{text}</span>
    </div>
  );
}

function InlineAlert({ tone, message }) {
  return <div className={`inline-alert ${tone}`}>{message}</div>;
}

function useSeverityCounts(scan) {
  return useMemo(() => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const finding of scan?.findings || []) {
      counts[finding.severity] = (counts[finding.severity] || 0) + 1;
    }
    return counts;
  }, [scan]);
}

export default App;
