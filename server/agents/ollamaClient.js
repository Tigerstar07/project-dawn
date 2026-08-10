const DEFAULT_BASE_URL = "http://127.0.0.1:11434";

export async function chatWithOllama({ model, messages, temperature = 0.2 }) {
  const selectedModel = String(model || "dolphin3:8b-llama3.1-q4_K_M").trim();
  const baseUrl = process.env.OLLAMA_BASE_URL || DEFAULT_BASE_URL;

  const response = await fetch(`${baseUrl}/api/chat`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      model: selectedModel,
      messages,
      stream: false,
      options: {
        temperature,
        num_ctx: 4096
      }
    }),
    signal: AbortSignal.timeout(120_000)
  });

  if (!response.ok) {
    const errorText = await response.text().catch(() => "");
    throw new Error(`Ollama returned ${response.status}: ${errorText || response.statusText}`);
  }

  const data = await response.json();
  return data.message?.content || "";
}
