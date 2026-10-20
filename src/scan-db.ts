import pg from "pg";
import { databaseRules, type DatabaseRule, type Queryable } from "./rules/database.js";
import type { Finding } from "./types.js";

export type DbScanOptions = {
  connectionString: string;
  schemas?: string[];
  rules?: DatabaseRule[];
};

export const DEFAULT_SCHEMAS = ["public"];

export async function scanDatabase({ connectionString, schemas = DEFAULT_SCHEMAS, rules = databaseRules }: DbScanOptions) {
  const client = new pg.Client({ connectionString, application_name: "supabase-security-scanner" });
  await client.connect();
  try {
    // Read-only by construction: the scanner never needs to write.
    await client.query("set session characteristics as transaction read only");
    const db = client as unknown as Queryable;
    const findings: Finding[] = [];
    for (const rule of rules) findings.push(...(await rule.run({ db, schemas })));
    return findings;
  } finally {
    await client.end();
  }
}
