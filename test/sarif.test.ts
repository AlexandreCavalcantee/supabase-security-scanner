import { describe, expect, it } from "vitest";
import { formatSarif } from "../src/reporters.js";

describe("formatSarif", () => {
  it("produces SARIF that GitHub code scanning accepts", () => {
    const sarif = JSON.parse(
      formatSarif(
        [
          { ruleId: "SS001", severity: "critical", message: "rls off", object: { kind: "table", schema: "public", name: "t" }, location: { file: "supabase/migrations/1.sql", line: 7 } },
          { ruleId: "SS008", severity: "medium", message: "public bucket", object: { kind: "bucket", name: "avatars" } },
        ],
        { fallbackFile: "supabase/migrations/1.sql" },
      ),
    );
    const run = sarif.runs[0];
    expect(sarif.version).toBe("2.1.0");
    expect(run.tool.driver.rules.map((r: { id: string }) => r.id)).toEqual(["SS001", "SS008"]);
    expect(run.results[0]).toMatchObject({
      ruleId: "SS001",
      level: "error",
      properties: { "security-severity": "9.5" },
      locations: [{ physicalLocation: { artifactLocation: { uri: "supabase/migrations/1.sql" }, region: { startLine: 7 } } }],
    });
    // Every result needs a location for code scanning, even when the object couldn't be mapped.
    expect(run.results[1].locations[0].physicalLocation.region.startLine).toBe(1);
    expect(run.results[1].ruleIndex).toBe(1);
  });
});
