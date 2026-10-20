// A JWT-shaped token with the given payload. Signature is junk: the scanner only reads the payload.
export const fakeJwt = (payload: Record<string, unknown>) =>
  [{ alg: "HS256", typ: "JWT" }, payload].map((p) => Buffer.from(JSON.stringify(p)).toString("base64url")).join(".") +
  ".c2lnbmF0dXJlLW5vdC1jaGVja2Vk";

/** fetch() stand-in serving a fixed map of URLs. */
export const fakeFetch = (pages: Record<string, string>) => async (url: string) =>
  url in pages ? new Response(pages[url], { status: 200 }) : new Response("not found", { status: 404 });
