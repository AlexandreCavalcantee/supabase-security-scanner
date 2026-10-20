import { findSecrets, redact } from "./secrets.js";
import type { Finding } from "./types.js";

const MAX_FILES = 60;
const MAX_BYTES = 8 * 1024 * 1024;

type Fetcher = (url: string) => Promise<Response>;

async function fetchText(fetcher: Fetcher, url: string): Promise<string | null> {
  try {
    const res = await fetcher(url);
    if (!res.ok) return null;
    const length = Number(res.headers.get("content-length") ?? 0);
    if (length > MAX_BYTES) return null;
    const text = await res.text();
    return text.length > MAX_BYTES ? text.slice(0, MAX_BYTES) : text;
  } catch {
    return null;
  }
}

/** Script URLs referenced by a page: <script src>, modulepreload links and JS imports. */
export function extractScriptUrls(html: string, base: string): string[] {
  const urls = new Set<string>();
  const add = (raw: string) => {
    try {
      const url = new URL(raw, base);
      if (url.protocol === "http:" || url.protocol === "https:") urls.add(url.href);
    } catch {
      /* ignore malformed */
    }
  };
  for (const m of html.matchAll(/<script\b[^>]*\bsrc=["']([^"']+)["']/gi)) add(m[1]!);
  for (const m of html.matchAll(/<link\b[^>]*\brel=["'](?:modulepreload|preload)["'][^>]*\bhref=["']([^"']+\.m?js[^"']*)["']/gi)) {
    add(m[1]!);
  }
  return [...urls];
}

const importsOf = (js: string, base: string) =>
  [...js.matchAll(/(?:import|from)\s*\(?\s*["'](\.{0,2}\/[^"']+\.m?js)["']/g)].map((m) => new URL(m[1]!, base).href);

/**
 * Downloads a deployed page and the JavaScript it loads (same origin only) and
 * looks for credentials that should never be shipped to a browser.
 */
export async function scanBundle(pageUrl: string, fetcher: Fetcher = fetch): Promise<Finding[]> {
  const origin = new URL(pageUrl).origin;
  const html = await fetchText(fetcher, pageUrl);
  if (html === null) throw new Error(`could not download ${pageUrl}`);

  const queue = extractScriptUrls(html, pageUrl).filter((u) => new URL(u).origin === origin);
  const seen = new Set<string>();
  const sources: { url: string; text: string }[] = [{ url: pageUrl, text: html }];

  while (queue.length && seen.size < MAX_FILES) {
    const url = queue.shift()!;
    if (seen.has(url)) continue;
    seen.add(url);
    const js = await fetchText(fetcher, url);
    if (js === null) continue;
    sources.push({ url, text: js });
    for (const dep of importsOf(js, url)) if (new URL(dep).origin === origin && !seen.has(dep)) queue.push(dep);
  }

  const findings: Finding[] = [];
  for (const { url, text } of sources) {
    for (const s of findSecrets(text)) {
      findings.push({
        ruleId: "SS101",
        severity: s.severity,
        message: `${s.kind} found in ${url}: ${redact(s.value)}${s.detail ? ` (${s.detail})` : ""}. Rotate it now — anyone who loaded the page has it.`,
      });
    }
  }
  return findings;
}

export const bundleRule = {
  id: "SS101",
  name: "secret-in-frontend-bundle",
  title: "Secret shipped to the browser",
  description:
    "A key that bypasses security (Supabase service_role/secret key, payment or cloud credentials) was found in JavaScript served to every visitor.",
  remediation:
    "Rotate the key immediately, move the code that needs it to the server (Edge Function / API route) and keep only the publishable/anon key in the front end.",
  docs: "https://supabase.com/docs/guides/api/api-keys",
};
