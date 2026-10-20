import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";
import type { DbObject, Finding } from "./types.js";

type SqlFile = { path: string; lines: string[] };

function loadSql(dir: string): SqlFile[] {
  let entries: string[];
  try {
    entries = readdirSync(dir).sort();
  } catch {
    return [];
  }
  return entries
    .map((f) => join(dir, f))
    .filter((p) => p.endsWith(".sql") && statSync(p).isFile())
    .map((path) => ({ path, lines: readFileSync(path, "utf8").split("\n") }));
}

const esc = (s: string) => s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
const ident = (name: string) => `"?${esc(name)}"?`;
const qualified = (schema: string | undefined, name: string) =>
  schema ? `(?:${ident(schema)}\\s*\\.\\s*)?${ident(name)}` : ident(name);

/** The statement that introduced (or last changed) an object, per finding kind. */
function patternFor(o: DbObject): RegExp[] {
  const q = qualified(o.schema, o.name);
  switch (o.kind) {
    case "table":
      return [new RegExp(`create\\s+table\\s+(?:if\\s+not\\s+exists\\s+)?${q}\\b`, "i")];
    case "view":
      return [new RegExp(`create\\s+(?:or\\s+replace\\s+)?(?:materialized\\s+)?view\\s+${q}\\b`, "i")];
    case "function":
      return [new RegExp(`create\\s+(?:or\\s+replace\\s+)?function\\s+${q}\\s*\\(`, "i")];
    case "policy":
      return [new RegExp(`create\\s+policy\\s+"?${esc(o.name)}"?`, "i")];
    case "extension":
      return [new RegExp(`create\\s+extension\\s+(?:if\\s+not\\s+exists\\s+)?"?${esc(o.name)}"?`, "i")];
    case "bucket":
      return [new RegExp(`['"]${esc(o.name)}['"]`, "i")];
  }
}

/**
 * Points each database finding at the migration line that created the object,
 * so CI annotations land on the SQL that needs fixing. The latest migration
 * wins, since that's the definition currently in effect.
 */
export function locateFindings(findings: Finding[], migrationsDir: string, cwd = process.cwd()): Finding[] {
  const files = loadSql(migrationsDir);
  if (!files.length) return findings;

  return findings.map((f) => {
    if (f.location || !f.object) return f;
    const patterns = patternFor(f.object);
    for (const file of [...files].reverse()) {
      const line = file.lines.findIndex((l) => patterns.some((p) => p.test(l)));
      if (line >= 0) return { ...f, location: { file: relative(cwd, file.path), line: line + 1 } };
    }
    return f;
  });
}
