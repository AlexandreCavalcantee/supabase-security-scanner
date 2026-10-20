import { databaseRules } from "./rules/database.js";
import { bundleRule } from "./scan-bundle.js";
import { probeRule } from "./probe.js";
import { objectLabel, severityRank, SEVERITIES, type Finding, type RuleMeta, type Severity } from "./types.js";

export const ALL_RULES: RuleMeta[] = [...databaseRules, bundleRule, probeRule];
const ruleById = new Map(ALL_RULES.map((r) => [r.id, r]));

const sortFindings = (findings: Finding[]) =>
  [...findings].sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || a.ruleId.localeCompare(b.ruleId));

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (code: string) => (s: string) => (useColor ? `\x1b[${code}m${s}\x1b[0m` : s);
const bold = paint("1");
const dim = paint("2");
const SEVERITY_STYLE: Record<Severity, (s: string) => string> = {
  critical: paint("1;97;41"),
  high: paint("1;31"),
  medium: paint("33"),
  low: paint("36"),
  info: paint("2"),
};

export function formatText(findings: Finding[], target: string): string {
  const out: string[] = [];
  out.push(bold(`supabase-security-scanner`) + dim(` · ${target}`), "");

  if (!findings.length) {
    out.push(paint("32")("✔ No issues found."));
    return out.join("\n");
  }

  for (const f of sortFindings(findings)) {
    const rule = ruleById.get(f.ruleId);
    const tag = SEVERITY_STYLE[f.severity](` ${f.severity.toUpperCase()} `.padEnd(10));
    out.push(`${tag} ${bold(f.ruleId)} ${rule?.title ?? ""}`);
    out.push(`           ${f.message}`);
    if (f.location) out.push(dim(`           at ${f.location.file}:${f.location.line}`));
    else if (f.object) out.push(dim(`           ${objectLabel(f.object)}`));
    if (rule) out.push(dim(`           fix: ${rule.remediation}`));
    out.push("");
  }

  const counts = SEVERITIES.map((s) => [s, findings.filter((f) => f.severity === s).length] as const).filter(([, n]) => n);
  out.push(bold(`${findings.length} finding${findings.length === 1 ? "" : "s"}: `) + counts.map(([s, n]) => SEVERITY_STYLE[s](`${n} ${s}`)).join(", "));
  return out.join("\n");
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

export const formatJson = (findings: Finding[]) =>
  JSON.stringify(
    sortFindings(findings).map((f) => ({ ...f, title: ruleById.get(f.ruleId)?.title })),
    null,
    2,
  );

// ---------------------------------------------------------------------------
// SARIF 2.1.0 — consumed by GitHub code scanning (Security tab + PR annotations).
// ---------------------------------------------------------------------------

const SARIF_LEVEL: Record<Severity, "error" | "warning" | "note"> = {
  critical: "error",
  high: "error",
  medium: "warning",
  low: "note",
  info: "note",
};
// GitHub orders alerts by this numeric score.
const SECURITY_SEVERITY: Record<Severity, string> = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", info: "0.0" };

export function formatSarif(findings: Finding[], { fallbackFile }: { fallbackFile: string }): string {
  const used = [...new Set(findings.map((f) => f.ruleId))];
  const rules = ALL_RULES.filter((r) => used.includes(r.id));

  return JSON.stringify(
    {
      $schema: "https://json.schemastore.org/sarif-2.1.0.json",
      version: "2.1.0",
      runs: [
        {
          tool: {
            driver: {
              name: "supabase-security-scanner",
              informationUri: "https://github.com/AlexandreCavalcantee/supabase-security-scanner",
              version: "0.1.0",
              rules: rules.map((r) => ({
                id: r.id,
                name: r.name,
                shortDescription: { text: r.title },
                fullDescription: { text: r.description },
                help: { text: r.remediation, markdown: `**Fix:** ${r.remediation}${r.docs ? `\n\n[Docs](${r.docs})` : ""}` },
                ...(r.docs ? { helpUri: r.docs } : {}),
                properties: { tags: ["security", "supabase"] },
              })),
            },
          },
          results: sortFindings(findings).map((f) => ({
            ruleId: f.ruleId,
            ruleIndex: rules.findIndex((r) => r.id === f.ruleId),
            level: SARIF_LEVEL[f.severity],
            message: { text: f.message },
            // Code scanning requires a location; objects we couldn't map point at the migrations folder's first file.
            locations: [
              {
                physicalLocation: {
                  artifactLocation: { uri: f.location?.file ?? fallbackFile },
                  region: { startLine: f.location?.line ?? 1 },
                },
                ...(f.object ? { logicalLocations: [{ fullyQualifiedName: objectLabel(f.object) }] } : {}),
              },
            ],
            partialFingerprints: { objectHash: `${f.ruleId}:${f.object ? objectLabel(f.object) : f.message}` },
            properties: { "security-severity": SECURITY_SEVERITY[f.severity] },
          })),
        },
      ],
    },
    null,
    2,
  );
}
