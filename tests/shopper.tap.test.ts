import { generateKeyPairSync } from "node:crypto";
import { describe, expect, it } from "vitest";
import { createTapKeyDirectory, createTapSigner, createTapVerifier, signatureBase, serializeSignatureParams, TapError } from "../shopper/tap.js";

const T = 1_800_000_000;
const req = { authority: "shop.example.test", path: "/checkout/abc/confirm" };
function rig() {
  const agent = createTapSigner(generateKeyPairSync("ed25519").privateKey);
  const keys = createTapKeyDirectory([agent.jwk]);
  return { agent, keys, merchant: createTapVerifier(keys) };
}
const reason = (fn: () => unknown) => { try { fn(); return "ok"; } catch (e) { return e instanceof TapError ? e.reason : String(e); } };

describe("Visa TAP message signatures (RFC 9421)", () => {
  it("builds the RFC 9421 base string with the spec's required params", () => {
    const params = serializeSignatureParams(["@authority", "@path"], { created: 1735689600, expires: 1735693200, keyid: "k1", alg: "ed25519", nonce: "n1", tag: "agent-browser-auth" });
    expect(signatureBase({ authority: "Example.com", path: "/example-product" }, ["@authority", "@path"], params)).toBe(
      `"@authority": example.com\n"@path": /example-product\n"@signature-params": ("@authority" "@path");created=1735689600;expires=1735693200;keyid="k1";alg="ed25519";nonce="n1";tag="agent-browser-auth"`);
  });

  it("emits sig2 Signature-Input/Signature headers that the merchant verifies", () => {
    const { agent, merchant } = rig();
    const signed = agent.signRequest({ ...req, tag: "agent-payer-auth", nowSeconds: T });
    expect(signed.headers["signature-input"]).toMatch(/^sig2=\("@authority" "@path"\);created=\d+;expires=\d+;keyid="[A-Za-z0-9_-]{43}";alg="ed25519";nonce="[^"]+";tag="agent-payer-auth"$/);
    expect(signed.headers.signature).toMatch(/^sig2=:[A-Za-z0-9+/=]+:$/);
    const v = merchant.verifyRequest({ ...req, headers: signed.headers, nowSeconds: T + 1, requireTag: "agent-payer-auth" });
    expect(v).toMatchObject({ keyId: agent.keyId, tag: "agent-payer-auth", nonce: signed.nonce });
  });

  it("blocks each case the spec says to block", () => {
    const { agent, merchant } = rig();
    const sign = (o: Partial<Parameters<typeof agent.signRequest>[0]> = {}) => agent.signRequest({ ...req, tag: "agent-payer-auth", nowSeconds: T, ...o }).headers;
    expect(reason(() => merchant.verifyRequest({ ...req, headers: {}, nowSeconds: T + 1 }))).toBe("not_signed");
    expect(reason(() => merchant.verifyRequest({ ...req, headers: sign({ nowSeconds: T + 100 }), nowSeconds: T }))).toBe("created_in_future");
    expect(reason(() => merchant.verifyRequest({ ...req, headers: sign({ ttlSeconds: 60 }), nowSeconds: T + 61 }))).toBe("expired");
    expect(reason(() => merchant.verifyRequest({ ...req, headers: sign({ ttlSeconds: 481 }), nowSeconds: T + 1 }))).toBe("window_too_long");
    expect(reason(() => merchant.verifyRequest({ ...req, path: "/checkout/other/confirm", headers: sign(), nowSeconds: T + 1 }))).toBe("bad_signature");
    expect(reason(() => merchant.verifyRequest({ ...req, authority: "evil.example.test", headers: sign(), nowSeconds: T + 1 }))).toBe("bad_signature");
    expect(reason(() => merchant.verifyRequest({ ...req, headers: sign({ tag: "agent-browser-auth" }), nowSeconds: T + 1, requireTag: "agent-payer-auth" }))).toBe("wrong_tag");
    const h = sign({ nonce: "fixed-nonce" });
    expect(reason(() => merchant.verifyRequest({ ...req, headers: { ...h, "signature-input": h["signature-input"]!.replace(/;tag="[^"]+"/, "") }, nowSeconds: T + 1 }))).toBe("bad_tag");
    expect(reason(() => merchant.verifyRequest({ ...req, headers: { ...h, "signature-input": h["signature-input"]!.replace(/;nonce="[^"]+"/, "") }, nowSeconds: T + 1 }))).toBe("missing_field");
    expect(reason(() => merchant.verifyRequest({ ...req, headers: h, nowSeconds: T + 1 }))).toBe("ok");
    expect(reason(() => merchant.verifyRequest({ ...req, headers: h, nowSeconds: T + 2 }))).toBe("nonce_replayed");
  });

  it("rejects an agent key that is not in the trusted key directory", () => {
    const { merchant } = rig();
    const rogue = createTapSigner(generateKeyPairSync("ed25519").privateKey);
    expect(reason(() => merchant.verifyRequest({ ...req, headers: rogue.signRequest({ ...req, tag: "agent-payer-auth", nowSeconds: T }).headers, nowSeconds: T + 1 }))).toBe("unknown_key");
  });

  it("verifies the agentic payment container: same key, same nonce, untampered", () => {
    const { agent, merchant } = rig();
    const signed = agent.signRequest({ ...req, tag: "agent-payer-auth", nowSeconds: T });
    const v = merchant.verifyRequest({ ...req, headers: signed.headers, nowSeconds: T + 1 });
    const container = agent.signContainer(signed.nonce, { checkoutId: "abc", tpaMandateHash: "f".repeat(64), amountBaseUnits: "3780", currency: "USD" });
    expect(reason(() => merchant.verifyContainer(container, v))).toBe("ok");
    expect(reason(() => merchant.verifyContainer({ ...container, amountBaseUnits: "9999" }, v))).toBe("container_bad_signature");
    expect(reason(() => merchant.verifyContainer(agent.signContainer("other", { checkoutId: "abc" }), v))).toBe("container_nonce_mismatch");
    const { signature: _s, ...unsigned } = container;
    expect(reason(() => merchant.verifyContainer(unsigned, v))).toBe("container_missing_field");
  });
});
