import type { Severity } from "./types.js";

export type SecretMatch = { kind: string; severity: Severity; value: string; detail?: string };

type Pattern = { kind: string; severity: Severity; re: RegExp };

// Keys that must never reach a browser. The public anon/publishable key is
// expected in front-end code and is deliberately not reported.
const PATTERNS: Pattern[] = [
  { kind: "Supabase secret key", severity: "critical", re: /\bsb_secret_[A-Za-z0-9_-]{20,}/g },
  { kind: "Stripe live secret key", severity: "critical", re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}/g },
  { kind: "AWS access key id", severity: "high", re: /\b(?:AKIA|ASIA)[A-Z0-9]{16}\b/g },
  { kind: "GitHub token", severity: "high", re: /\b(?:ghp|gho|ghs|ghu|github_pat)_[A-Za-z0-9_]{30,}/g },
  { kind: "OpenAI API key", severity: "high", re: /\bsk-(?:proj-)?[A-Za-z0-9_-]{32,}/g },
  { kind: "Anthropic API key", severity: "high", re: /\bsk-ant-[A-Za-z0-9_-]{32,}/g },
  { kind: "Google API key", severity: "medium", re: /\bAIza[0-9A-Za-z_-]{35}\b/g },
  { kind: "Private key", severity: "critical", re: /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/g },
];

const JWT_RE = /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g;

export function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    return JSON.parse(Buffer.from(part, "base64url").toString("utf8"));
  } catch {
    return null;
  }
}

/** Keep enough to recognize the key, never enough to use it. */
export const redact = (value: string) => (value.length <= 12 ? "****" : `${value.slice(0, 10)}…${value.slice(-4)}`);

export function findSecrets(text: string): SecretMatch[] {
  const found = new Map<string, SecretMatch>();

  for (const p of PATTERNS) {
    for (const m of text.matchAll(p.re)) found.set(m[0], { kind: p.kind, severity: p.severity, value: m[0] });
  }

  for (const m of text.matchAll(JWT_RE)) {
    const payload = decodeJwtPayload(m[0]);
    // Supabase's legacy keys are JWTs; only the service role bypasses RLS.
    if (payload?.role === "service_role") {
      found.set(m[0], {
        kind: "Supabase service_role key",
        severity: "critical",
        value: m[0],
        detail: typeof payload.ref === "string" ? `project ${payload.ref}` : undefined,
      });
    }
  }

  return [...found.values()];
}
