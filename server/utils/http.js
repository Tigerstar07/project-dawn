export function normalizeUrl(rawUrl) {
  const value = String(rawUrl || "").trim();
  if (!value) throw new Error("A URL is required.");

  const withProtocol = /^https?:\/\//i.test(value) ? value : `https://${value}`;
  const parsed = new URL(withProtocol);

  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error("Only http:// and https:// URLs are supported.");
  }

  return parsed;
}

export async function readLimitedText(response, maxBytes = 350_000) {
  if (!response.body) return "";

  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;

  while (received < maxBytes) {
    const { value, done } = await reader.read();
    if (done) break;
    const remaining = maxBytes - received;
    const chunk = value.length > remaining ? value.slice(0, remaining) : value;
    chunks.push(chunk);
    received += chunk.length;
    if (value.length > remaining) break;
  }

  try {
    await reader.cancel();
  } catch {
    // The stream can already be closed.
  }

  return new TextDecoder("utf-8", { fatal: false }).decode(Buffer.concat(chunks));
}

export function headerObject(headers) {
  const result = {};
  for (const [key, value] of headers.entries()) {
    result[key.toLowerCase()] = value;
  }
  return result;
}

export function getSetCookieHeaders(headers) {
  if (typeof headers.getSetCookie === "function") return headers.getSetCookie();

  const combined = headers.get("set-cookie");
  if (!combined) return [];
  return combined.split(/,(?=\s*[^;,=\s]+=[^;,]+)/g).map((cookie) => cookie.trim());
}
