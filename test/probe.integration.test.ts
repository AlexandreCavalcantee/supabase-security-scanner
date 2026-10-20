import { describe, expect, it } from "vitest";
import { probeAnonAccess } from "../src/probe.js";

const url = process.env.SCANNER_TEST_API_URL;
const keys = [process.env.SCANNER_TEST_ANON_KEY, process.env.SCANNER_TEST_PUBLISHABLE_KEY].filter(Boolean) as string[];

describe.skipIf(!url || keys.length === 0)("live probe against the fixtures", () => {
  it.each(keys)("reads exactly the leaky tables with the public key %#", async (key) => {
    const leaks = await probeAnonAccess(url!, key, { schema: "vuln" });
    expect(leaks.map((f) => f.object?.name).sort()).toEqual(["all_invoices", "customers", "invoices"]);
  });

  it("finds nothing readable in the secure schema", async () => {
    expect(await probeAnonAccess(url!, keys[0]!, { schema: "secure" })).toEqual([]);
  });
});
