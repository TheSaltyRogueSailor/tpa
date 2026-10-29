import { generateKeyPairSync, randomBytes } from "node:crypto";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { spawnSync } from "node:child_process";
import { describe, expect, it } from "vitest";
import { createTpaAuthority } from "../src/config.js";
import type { TpaCheckoutInput } from "../src/domain.js";
import { createTpaService } from "../src/service.js";
import { createTpaMandateSigner } from "../src/signing.js";
import { createMemoryTpaPersistence } from "../scripts/demo/memory-store.js";
import { syntheticAuthenticator } from "./support/authenticator.js";

/** Synthetic local crypto and memory persistence only. No demo, RPC or payment execution. */
async function fixture() {
  const origin = "https://tpa-review.example.test";
  const rpID = "tpa-review.example.test";
  const owner = { principalId: 1, sessionHash: "a".repeat(64), owner: true as const };
  const context = { owner, headers: { origin } };
  let clock = Date.now();
  const memory = createMemoryTpaPersistence({ ownerIds: [owner.principalId] });
  const signer = createTpaMandateSigner({ activeKeyId: "synthetic-review", privateKey: generateKeyPairSync("ed25519").privateKey });
  const input = { store: memory.store, evidence: memory.evidence, signer, authority: createTpaAuthority({ enabled: true, origin, rpID }), now: () => clock };
  const service = createTpaService(input);
  const device = syntheticAuthenticator(origin, rpID);
  const registration = await service.registrationOptions(context, { label: "Synthetic test credential", consent: true });
  await service.registrationVerify(context, { ceremonyId: registration.ceremonyId, response: device.register(registration.options.challenge) });
  const checkout: TpaCheckoutInput = {
    currency: "USD", recipient: "user:42", merchant: { id: "review-store", name: "Synthetic review store" },
    items: [{ sku: "MUG-01", qty: 2, unitPriceBaseUnits: "750" }, { sku: "TEE-02", qty: 1, unitPriceBaseUnits: "1500" }],
    shipping: { method: "standard", costBaseUnits: "500" }, taxBaseUnits: "280", totalBaseUnits: "3780",
  };
  async function pending() { return service.createIntent(context, { ...checkout, consent: true }); }
  async function approved() {
    const intent = await pending();
    const prompt = await service.authenticationOptions(context, { intentId: intent.id, consent: true });
    await service.authorize(context, { intentId: intent.id, ceremonyId: prompt.ceremonyId, response: device.assert(prompt.options.challenge), consent: true });
    return intent;
  }
  return { context, service, memory, input, device, checkout, pending, approved, advance: (ms: number) => { clock += ms; } };
}

describe("core-only synthetic regression and demo compatibility", () => {
  it("allows exact approval once and records approval plus replay refusal", async () => {
    const f = await fixture();
    const intent = await f.approved();
    await expect(f.service.consume(f.context, { intentId: intent.id, consent: true, checkout: f.checkout })).resolves.toMatchObject({ consumed: true, checkoutMatched: true });
    await expect(f.service.consume(f.context, { intentId: intent.id, consent: true, checkout: f.checkout })).rejects.toMatchObject({ code: "intent" });
    const audit = await f.service.auditLog(f.context, { intentId: intent.id });
    expect(audit).toEqual(expect.arrayContaining([
      expect.objectContaining({ action: "authorized", outcome: "approved" }),
      expect.objectContaining({ action: "consumed", outcome: "approved" }),
      expect.objectContaining({ action: "consume", outcome: "refused", reasonCode: "intent" }),
    ]));
  });

  it("preserves the red-team generic-prompt attack using explicit synthetic storage corruption", async () => {
    const f = await fixture();
    const intent = await f.pending();
    const prompt = await f.service.authenticationOptions(f.context, { intentId: intent.id, consent: true });
    const genericChallenge = randomBytes(32).toString("base64url");
    f.memory.tamper.ceremonies.get(prompt.ceremonyId)!.challenge = genericChallenge;
    f.memory.tamper.bindings.delete(prompt.ceremonyId);
    await expect(f.service.authorize(f.context, { intentId: intent.id, ceremonyId: prompt.ceremonyId, response: f.device.assert(genericChallenge), consent: true })).rejects.toMatchObject({ code: "challenge_unbound" });
    expect(f.memory.tamper.intents.get(intent.id)!.state).toBe("pending");
    expect(await f.service.auditLog(f.context, { intentId: intent.id })).toEqual(expect.arrayContaining([
      expect.objectContaining({ action: "authorize", outcome: "refused", reasonCode: "challenge_unbound" }),
    ]));
  });

  it("rejects raw v3 unbound-ceremony creation before a ceremony is persisted", async () => {
    const f = await fixture();
    const intent = await f.pending();
    const ceremonyId = "c".repeat(64);
    await expect(f.memory.store.startAuthorization({ userId: 1, sessionHash: f.context.owner.sessionHash, origin: f.context.headers.origin, ceremonyId, intentId: intent.id, challenge: randomBytes(32).toString("base64url") })).rejects.toMatchObject({ kind: "integrity" });
    expect(f.memory.tamper.ceremonies.has(ceremonyId)).toBe(false);
  });

  it.each([
    ["one-cent price", (cart: TpaCheckoutInput): TpaCheckoutInput => ({ ...cart, items: [cart.items[0]!, { ...cart.items[1]!, unitPriceBaseUnits: String(BigInt(cart.items[1]!.unitPriceBaseUnits) + 1n) }], totalBaseUnits: String(BigInt(cart.totalBaseUnits) + 1n) })],
    ["swapped item", (cart: TpaCheckoutInput): TpaCheckoutInput => ({ ...cart, items: [cart.items[0]!, { ...cart.items[1]!, sku: "OTHER-ITEM" }] })],
    ["express shipping", (cart: TpaCheckoutInput): TpaCheckoutInput => ({ ...cart, shipping: { ...cart.shipping, method: "express" } })],
    ["wrong merchant", (cart: TpaCheckoutInput): TpaCheckoutInput => ({ ...cart, merchant: { id: "wrong-store", name: "Other synthetic store" } })],
  ] as const)("refuses %s without consuming the valid approval", async (_name, change) => {
    const f = await fixture();
    const intent = await f.approved();
    await expect(f.service.consume(f.context, { intentId: intent.id, consent: true, checkout: change(f.checkout) })).rejects.toMatchObject({ code: "terms_changed" });
    expect(f.memory.tamper.intents.get(intent.id)!.state).toBe("authorized");
  });

  it("refuses an expired signed approval", async () => {
    const f = await fixture();
    const intent = await f.approved();
    f.advance(301_000);
    await expect(f.service.consume(f.context, { intentId: intent.id, consent: true, checkout: f.checkout })).rejects.toMatchObject({ code: "intent" });
    expect(f.memory.tamper.intents.get(intent.id)!.state).toBe("authorized");
  });

  it("rolls memory consumption back if mandatory completion audit fails", async () => {
    const f = await fixture();
    const intent = await f.approved();
    const broken = createTpaService({ ...f.input, evidence: { ...f.memory.evidence, audit: async event => {
      if (event.action === "consumed") throw new Error("Synthetic audit failure");
      return f.memory.evidence.audit(event);
    } } });
    await expect(broken.consume(f.context, { intentId: intent.id, consent: true, checkout: f.checkout })).rejects.toMatchObject({ code: "unavailable" });
    expect(f.memory.tamper.intents.get(intent.id)!.state).toBe("authorized");
    const audit = await broken.auditLog(f.context, { intentId: intent.id });
    expect(audit.filter(event => event.outcome === "attempt")).toHaveLength(0);
    expect(audit).toEqual(expect.arrayContaining([expect.objectContaining({ action: "consume", outcome: "refused" })]));
  });
});

describe("standalone source refresh safety", () => {
  it("refuses to overwrite hardened store code with an older source", () => {
    const temp = mkdtempSync(join(tmpdir(), "tpa-refresh-test-"));
    try {
      mkdirSync(join(temp, "scripts"));
      mkdirSync(join(temp, "src"));
      const script = join(temp, "scripts", "sync-lifecycle-store.mjs");
      writeFileSync(script, readFileSync(new URL("../scripts/sync-lifecycle-store.mjs", import.meta.url), "utf8"));
      const output = join(temp, "src", "store.ts");
      const preserved = "// TpaIntentLifecycleHook: protected standalone output\n";
      writeFileSync(output, preserved);
      const upstream = join(temp, "upstream.ts");
      writeFileSync(upstream, "// old source without standalone hardening\n");
      const result = spawnSync(process.execPath, [script, upstream], { encoding: "utf8", env: { PATH: process.env.PATH ?? "", HOME: process.env.HOME ?? "", METAL_LIVE: "0" } });
      expect(result.status).not.toBe(0);
      expect(result.stderr).toContain("Refusing to erase standalone lifecycle hardening");
      expect(readFileSync(output, "utf8")).toBe(preserved);
    } finally { rmSync(temp, { recursive: true, force: true }); }
  });
});
