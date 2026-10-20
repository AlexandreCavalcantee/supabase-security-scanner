import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { locateFindings } from "../src/locate.js";
import type { Finding } from "../src/types.js";

const dir = mkdtempSync(join(tmpdir(), "scan-"));
writeFileSync(join(dir, "001_init.sql"), "-- init\ncreate table public.orders (id int);\ncreate policy \"open\" on public.orders using (true);\n");
writeFileSync(join(dir, "002_fix.sql"), "\n\ncreate or replace function public.pay(p int) returns void language sql as $$ select 1 $$;\n");

const finding = (object: Finding["object"]): Finding => ({ ruleId: "SS000", severity: "high", message: "", object });

describe("locateFindings", () => {
  it("points tables, policies and functions at the statement that created them", () => {
    const [table, policy, fn] = locateFindings(
      [
        finding({ kind: "table", schema: "public", name: "orders" }),
        finding({ kind: "policy", schema: "public", name: "open", table: "orders" }),
        finding({ kind: "function", schema: "public", name: "pay" }),
      ],
      dir,
      dir,
    );
    expect(table!.location).toEqual({ file: "001_init.sql", line: 2 });
    expect(policy!.location).toEqual({ file: "001_init.sql", line: 3 });
    expect(fn!.location).toEqual({ file: "002_fix.sql", line: 3 });
  });

  it("leaves findings it can't map untouched", () => {
    const [f] = locateFindings([finding({ kind: "table", schema: "public", name: "nope" })], dir, dir);
    expect(f!.location).toBeUndefined();
  });
});
