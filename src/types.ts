export const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
export type Severity = (typeof SEVERITIES)[number];

/** Lower rank = more severe. */
export const severityRank = (s: Severity) => SEVERITIES.indexOf(s);
export const atLeast = (s: Severity, threshold: Severity) => severityRank(s) <= severityRank(threshold);

export type RuleMeta = {
  id: string;
  name: string;
  title: string;
  /** Why it matters, in one or two sentences. */
  description: string;
  remediation: string;
  docs?: string;
};

/** What the finding points at, so it can be mapped back to a migration line. */
export type DbObject =
  | { kind: "table" | "view" | "function" | "policy" | "extension" | "bucket"; schema?: string; name: string; table?: string };

export type Finding = {
  ruleId: string;
  severity: Severity;
  message: string;
  object?: DbObject;
  /** Filled in by the migration locator, or set directly by file-based scanners. */
  location?: { file: string; line: number };
};

export const objectLabel = (o: DbObject) => {
  const qualified = o.schema ? `${o.schema}.${o.name}` : o.name;
  return o.kind === "policy" && o.table ? `policy "${o.name}" on ${o.schema}.${o.table}` : `${o.kind} ${qualified}`;
};
