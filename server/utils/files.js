import { mkdir, readFile, readdir, writeFile } from "node:fs/promises";
import path from "node:path";

export function safeSegment(value, fallback = "session") {
  return String(value || fallback)
    .trim()
    .replace(/[^a-zA-Z0-9._-]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 80) || fallback;
}

export async function ensureDir(dir) {
  await mkdir(dir, { recursive: true });
  return dir;
}

export async function writeMarkdown(dir, fileName, content) {
  await ensureDir(dir);
  const target = path.join(dir, safeSegment(fileName, "note.md"));
  await writeFile(target, content.trimEnd() + "\n", "utf8");
  return target;
}

export async function readMarkdownFiles(dir) {
  const entries = await readdir(dir, { withFileTypes: true }).catch(() => []);
  const files = entries
    .filter((entry) => entry.isFile() && entry.name.endsWith(".md"))
    .map((entry) => entry.name)
    .sort();

  const contents = [];
  for (const file of files) {
    const content = await readFile(path.join(dir, file), "utf8");
    contents.push({ name: file, content });
  }
  return contents;
}

export function truncateText(value, maxChars) {
  const text = String(value || "");
  if (text.length <= maxChars) return text;
  return `${text.slice(0, maxChars)}\n\n[truncated ${text.length - maxChars} chars]`;
}
