import { describe, expect, it } from "vitest";
import { extractScriptUrls, scanBundle } from "../src/scan-bundle.js";
import { fakeFetch, fakeJwt } from "./helpers.js";

const serviceKey = fakeJwt({ role: "service_role", ref: "prodref" });
const anonKey = fakeJwt({ role: "anon", ref: "prodref" });

describe("scanBundle", () => {
  it("finds a service key in a lazily imported chunk, but not the anon key", async () => {
    const findings = await scanBundle(
      "https://app.test/",
      fakeFetch({
        "https://app.test/": `<html><script type="module" src="/assets/index.js"></script></html>`,
        "https://app.test/assets/index.js": `const anon="${anonKey}"; import("./admin.js")`,
        "https://app.test/assets/admin.js": `export const admin = createClient(u, "${serviceKey}")`,
      }),
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]).toMatchObject({ ruleId: "SS101", severity: "critical" });
    expect(findings[0]!.message).toContain("https://app.test/assets/admin.js");
    expect(findings[0]!.message).not.toContain(serviceKey);
  });

  it("does not download scripts from other origins", async () => {
    const findings = await scanBundle(
      "https://app.test/",
      fakeFetch({
        "https://app.test/": `<script src="https://cdn.other.test/lib.js"></script>`,
        "https://cdn.other.test/lib.js": `"${serviceKey}"`,
      }),
    );
    expect(findings).toEqual([]);
  });

  it("fails clearly when the page can't be downloaded", async () => {
    await expect(scanBundle("https://app.test/missing", fakeFetch({}))).rejects.toThrow("could not download");
  });
});

describe("extractScriptUrls", () => {
  it("resolves script tags and modulepreload links against the page", () => {
    const html = `<script src="/a.js"></script><link rel="modulepreload" href="b.js"><script>inline()</script>`;
    expect(extractScriptUrls(html, "https://x.test/app/")).toEqual(["https://x.test/a.js", "https://x.test/app/b.js"]);
  });
});
