#!/usr/bin/env node
import { readdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { parseArgs } from "node:util";
import { locateFindings } from "./locate.js";
import { probeAnonAccess } from "./probe.js";
import { ALL_RULES, formatJson, formatSarif, formatText } from "./reporters.js";
import { scanBundle } from "./scan-bundle.js";
import { DEFAULT_SCHEMAS, scanDatabase } from "./scan-db.js";
import { atLeast, SEVERITIES, type Finding, type Severity } from "./types.js";

const HELP = `supabase-scan — find security misconfigurations in Supabase projects

Usage
  supabase-scan db     --db-url <postgres url> [--schemas public,api] [--migrations supabase/migrations]
  supabase-scan bundle --url <https://your-app.com>
  supabase-scan probe  --url <https://<ref>.supabase.co> --anon-key <public key> [--schemas public]
  supabase-scan rules

Options
  --format <text|json|sarif>   output format (default: text)
  --output <file>              write the report to a file instead of stdout
  --fail-on <severity>         exit 1 if any finding is at least this severe (default: high; "none" to never fail)
  --min-severity <severity>    hide findings below this severity (default: info)

Environment
  SUPABASE_DB_URL, SUPABASE_URL, SUPABASE_ANON_KEY can replace the matching flags.

Severities: ${SEVERITIES.join(", ")}`;

function fail(message: string): never {
  console.error(`error: ${message}\n\nRun "supabase-scan --help" for usage.`);
  process.exit(2);
}

const isSeverity = (s: string): s is Severity => (SEVERITIES as readonly string[]).includes(s);

async function main() {
  const { values, positionals } = parseArgs({
    allowPositionals: true,
    options: {
      "db-url": { type: "string" },
      url: { type: "string" },
      "anon-key": { type: "string" },
      schemas: { type: "string" },
      migrations: { type: "string", default: "supabase/migrations" },
      format: { type: "string", default: "text" },
      output: { type: "string" },
      "fail-on": { type: "string", default: "high" },
      "min-severity": { type: "string", default: "info" },
      help: { type: "boolean", short: "h" },
    },
  });

  const command = positionals[0];
  if (values.help || !command) {
    console.log(HELP);
    return;
  }

  const format = values.format!;
  if (!["text", "json", "sarif"].includes(format)) fail(`unknown format "${format}"`);
  const failOn = values["fail-on"]!;
  if (failOn !== "none" && !isSeverity(failOn)) fail(`unknown severity "${failOn}"`);
  const minSeverity = values["min-severity"]!;
  if (!isSeverity(minSeverity)) fail(`unknown severity "${minSeverity}"`);
  const schemas = values.schemas?.split(",").map((s) => s.trim()).filter(Boolean);

  let findings: Finding[];
  let target: string;

  switch (command) {
    case "rules":
      for (const r of ALL_RULES) console.log(`${r.id}  ${r.name.padEnd(30)} ${r.title}`);
      return;

    case "db": {
      const dbUrl = values["db-url"] ?? process.env.SUPABASE_DB_URL;
      if (!dbUrl) fail("--db-url (or SUPABASE_DB_URL) is required");
      target = `database (${(schemas ?? DEFAULT_SCHEMAS).join(", ")})`;
      findings = locateFindings(await scanDatabase({ connectionString: dbUrl, schemas }), values.migrations!);
      break;
    }

    case "bundle": {
      const url = values.url;
      if (!url) fail("--url is required");
      target = url;
      findings = await scanBundle(url);
      break;
    }

    case "probe": {
      const url = values.url ?? process.env.SUPABASE_URL;
      const key = values["anon-key"] ?? process.env.SUPABASE_ANON_KEY;
      if (!url || !key) fail("--url and --anon-key (or SUPABASE_URL / SUPABASE_ANON_KEY) are required");
      target = url;
      findings = [];
      for (const schema of schemas ?? DEFAULT_SCHEMAS) findings.push(...(await probeAnonAccess(url, key, { schema })));
      break;
    }

    default:
      fail(`unknown command "${command}"`);
  }

  findings = findings.filter((f) => atLeast(f.severity, minSeverity));

  const fallbackFile = (() => {
    try {
      const first = readdirSync(values.migrations!).filter((f) => f.endsWith(".sql")).sort()[0];
      return first ? join(values.migrations!, first) : "README.md";
    } catch {
      return "README.md";
    }
  })();

  const report =
    format === "json" ? formatJson(findings) : format === "sarif" ? formatSarif(findings, { fallbackFile }) : formatText(findings, target);

  if (values.output) {
    writeFileSync(values.output, report + "\n");
    if (format !== "text") console.log(formatText(findings, target));
  } else {
    console.log(report);
  }

  if (failOn !== "none" && findings.some((f) => atLeast(f.severity, failOn as Severity))) process.exitCode = 1;
}

main().catch((e: unknown) => {
  console.error(`error: ${e instanceof Error ? e.message : String(e)}`);
  process.exit(2);
});
