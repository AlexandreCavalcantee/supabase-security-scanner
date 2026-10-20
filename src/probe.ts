import type { Finding } from "./types.js";

type Fetcher = (url: string, init?: RequestInit) => Promise<Response>;

/**
 * Black-box check of a live project with the PUBLIC key only: asks the Data API
 * which tables it exposes and tries to read one row from each. Read-only — it
 * never writes, and it only touches the project you point it at.
 */
export async function probeAnonAccess(
  projectUrl: string,
  anonKey: string,
  { schema = "public", fetcher = fetch as Fetcher } = {},
): Promise<Finding[]> {
  const base = projectUrl.replace(/\/+$/, "") + "/rest/v1/";
  const headers: Record<string, string> = {
    apikey: anonKey,
    "Accept-Profile": schema,
  };
  // Legacy anon keys are JWTs and also go in Authorization; new publishable keys don't.
  if (anonKey.startsWith("eyJ")) headers.Authorization = `Bearer ${anonKey}`;

  const spec = await fetcher(base, { headers: { ...headers, Accept: "application/openapi+json" } });
  if (!spec.ok) throw new Error(`could not read the API schema (${spec.status} ${spec.statusText})`);
  const openapi = (await spec.json()) as { paths?: Record<string, unknown> };
  const tables = Object.keys(openapi.paths ?? {})
    .filter((p) => p !== "/" && !p.startsWith("/rpc/"))
    .map((p) => p.slice(1));

  const findings: Finding[] = [];
  for (const table of tables) {
    const res = await fetcher(`${base}${encodeURIComponent(table)}?select=*&limit=1`, {
      headers: { ...headers, Prefer: "count=exact" },
    });
    if (!res.ok) continue;
    const rows = (await res.json()) as unknown[];
    if (!Array.isArray(rows) || rows.length === 0) continue;
    const total = res.headers.get("content-range")?.split("/")[1];
    findings.push({
      ruleId: "SS201",
      severity: "high",
      message: `Anyone with the public key can read ${schema}.${table}${total && total !== "*" ? ` (${total} rows)` : ""}. Confirm this data is meant to be public.`,
      object: { kind: "table", schema, name: table },
    });
  }
  return findings;
}

export const probeRule = {
  id: "SS201",
  name: "anon-can-read",
  title: "Table readable with the public key",
  description:
    "A live request using only the public anon/publishable key returned rows. Everything the key can read is effectively public.",
  remediation: "Enable RLS and restrict the select policy, or revoke select from anon if the table isn't public data.",
};
