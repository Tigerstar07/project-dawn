import os from "node:os";

// Picks the most capable locally-installed Ollama model that runs comfortably
// in this machine's memory. "More capable" = more parameters, which tends to
// find deeper / subtler issues, at the cost of speed.

const FAMILY_PREFERENCE = ["qwen2", "qwen2.5", "llama", "gemma3", "phi2"];

export function describeDevice() {
  const totalGB = os.totalmem() / 1e9;
  const freeGB = os.freemem() / 1e9;
  return {
    platform: os.platform(),
    arch: os.arch(),
    cpus: os.cpus()?.length || 0,
    totalMemGB: round(totalGB),
    freeMemGB: round(freeGB)
  };
}

// Estimate the memory a model needs: GGUF file footprint + runtime/KV-cache
// overhead. Rough but good enough to keep recommendations safe.
function estimateNeedGB(sizeBytes) {
  const fileGB = (sizeBytes || 0) / 1e9;
  return fileGB * 1.15 + 1.3;
}

function parseParams(parameterSize) {
  const match = String(parameterSize || "").match(/([\d.]+)\s*([BMK])/i);
  if (!match) return 0;
  const value = Number(match[1]);
  const unit = match[2].toUpperCase();
  if (unit === "B") return value; // billions
  if (unit === "M") return value / 1000;
  return value / 1e6;
}

function familyRank(family) {
  const index = FAMILY_PREFERENCE.indexOf(String(family || "").toLowerCase());
  return index === -1 ? FAMILY_PREFERENCE.length : index;
}

export function recommendModels(rawModels) {
  const device = describeDevice();
  const totalGB = device.totalMemGB || 0;

  const models = (rawModels || []).map((model) => {
    const sizeBytes = model.size || 0;
    const params = parseParams(model.details?.parameter_size);
    const needGB = estimateNeedGB(sizeBytes);
    const fits = totalGB === 0 ? true : needGB <= totalGB * 0.85;
    const comfortable = totalGB === 0 ? true : needGB <= totalGB * 0.6;
    return {
      name: model.name,
      sizeBytes,
      sizeLabel: formatBytes(sizeBytes),
      params,
      paramLabel: model.details?.parameter_size || (params ? `${params}B` : "?"),
      quant: model.details?.quantization_level || "",
      family: model.details?.family || "",
      needGB: round(needGB),
      fits,
      comfortable
    };
  });

  // Candidate pool: comfortable first; fall back to anything that fits; then all.
  const comfortable = models.filter((m) => m.comfortable);
  const fitting = models.filter((m) => m.fits);
  const pool = comfortable.length ? comfortable : fitting.length ? fitting : models;

  // Most capable: largest params, then smaller footprint (more headroom),
  // then preferred family.
  const ranked = [...pool].sort((a, b) => {
    if (b.params !== a.params) return b.params - a.params;
    if (a.sizeBytes !== b.sizeBytes) return a.sizeBytes - b.sizeBytes;
    return familyRank(a.family) - familyRank(b.family);
  });

  const recommended = ranked[0]?.name || models[0]?.name || "";
  const rec = models.find((m) => m.name === recommended);

  let reason;
  if (!models.length) {
    reason = "No local models found. Pull one with: ollama pull qwen2.5:7b-instruct";
  } else if (rec && !rec.fits) {
    reason = `All installed models are large for ${totalGB}GB RAM. "${recommended}" is the smallest available — expect slow responses.`;
  } else if (rec) {
    reason = `Most capable model (${rec.paramLabel}, ${rec.sizeLabel}) that runs ${rec.comfortable ? "comfortably" : "within"} ${totalGB}GB RAM. Bigger models find deeper issues.`;
  } else {
    reason = "Recommendation unavailable.";
  }

  return {
    device,
    recommended,
    reason,
    models: models.map((m) => ({ ...m, recommended: m.name === recommended }))
  };
}

function round(value) {
  return Math.round((value || 0) * 10) / 10;
}

function formatBytes(bytes) {
  if (!bytes) return "?";
  const gb = bytes / 1e9;
  if (gb >= 1) return `${round(gb)} GB`;
  return `${Math.round(bytes / 1e6)} MB`;
}
