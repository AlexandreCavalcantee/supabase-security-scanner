// Runs against the fixtures in fixtures/supabase (see README → Development).
import { describe, expect, it } from "vitest";
import { scanDatabase } from "../src/scan-db.js";

const dbUrl = process.env.SCANNER_TEST_DB_URL;

describe.skipIf(!dbUrl)("database rules against the fixtures", () => {
  it("catches every planted mistake in the vuln schema", async () => {
    const findings = await scanDatabase({ connectionString: dbUrl!, schemas: ["vuln", "public"] });
    const summary = findings.map((f) => `${f.ruleId} ${f.severity} ${f.object?.name}`).sort();
    expect(summary).toEqual(
      [
        "SS001 critical customers",
        "SS002 info audit_log",
        "SS003 high anyone can read invoices",
        "SS004 high admins only",
        "SS005 high promote_to_admin",
        "SS006 high promote_to_admin",
        "SS007 high all_invoices",
        "SS008 high invoices",
        "SS009 low citext",
      ].sort(),
    );
  });

  it("reports nothing for the secure schema", async () => {
    const findings = await scanDatabase({ connectionString: dbUrl!, schemas: ["secure"] });
    expect(findings.filter((f) => f.object?.schema === "secure")).toEqual([]);
  });

  it("never writes: the session is read-only", async () => {
    // A rule that tries to write must fail instead of changing the database.
    const writer = {
      id: "TEST",
      name: "writer",
      title: "",
      description: "",
      remediation: "",
      run: async ({ db }: { db: { query: (sql: string) => Promise<unknown> } }) => {
        await db.query("create table public.should_not_exist (id int)");
        return [];
      },
    };
    await expect(scanDatabase({ connectionString: dbUrl!, rules: [writer] })).rejects.toThrow(/read-only/);
  });
});
