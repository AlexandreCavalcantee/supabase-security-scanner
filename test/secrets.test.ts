import { describe, expect, it } from "vitest";
import { decodeJwtPayload, findSecrets, redact } from "../src/secrets.js";
import { fakeJwt } from "./helpers.js";

// Built at runtime so no key-shaped literal lives in the repo (GitHub push protection).
const SECRET = ["sb", "secret", "N7UND0UgjKTVK-Uodkm0Hg_xSvEMPvz"].join("_");
const PUBLISHABLE = ["sb", "publishable", "ACJWlzQHlZjBrEguHvfOxg_3BJgxAaH"].join("_");

describe("findSecrets", () => {
  it("flags a legacy service_role JWT as critical", () => {
    const key = fakeJwt({ iss: "supabase", ref: "abcd1234", role: "service_role" });
    const [match] = findSecrets(`createClient(url, "${key}")`);
    expect(match).toMatchObject({ kind: "Supabase service_role key", severity: "critical", detail: "project abcd1234" });
  });

  it("does not flag the public anon key, which is meant to be in the browser", () => {
    const key = fakeJwt({ iss: "supabase", role: "anon" });
    expect(findSecrets(`const anon = "${key}"`)).toEqual([]);
    expect(findSecrets(`const key = "${PUBLISHABLE}"`)).toEqual([]);
  });

  it("flags new-style Supabase secret keys and other common credentials", () => {
    const kinds = findSecrets(
      [
        SECRET,
        "sk_live_" + "a".repeat(24),
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_" + "b".repeat(36),
        "-----BEGIN PRIVATE KEY-----",
      ].join("\n"),
    ).map((m) => m.kind);
    expect(kinds).toEqual(
      expect.arrayContaining(["Supabase secret key", "Stripe live secret key", "AWS access key id", "GitHub token", "Private key"]),
    );
  });

  it("reports each distinct secret once", () => {
    const key = SECRET;
    expect(findSecrets(`${key} ${key} ${key}`)).toHaveLength(1);
  });

  it("ignores text that only looks like a JWT", () => {
    expect(decodeJwtPayload("eyJnot.eyJvalid!.x")).toBeNull();
  });
});

describe("redact", () => {
  it("never prints the full key", () => {
    const key = SECRET;
    const shown = redact(key);
    expect(shown).not.toContain(key);
    expect(shown.replace("…", "").length).toBeLessThan(16);
  });
});
