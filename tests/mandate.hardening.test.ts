/**
 * Hardened checkout mandate suite (version 3.0).
 *
 * REAL service + REAL MySQL/MariaDB store + REAL WebAuthn ES256 verification + REAL Ed25519
 * mandate signatures. The Ed25519 keys are generated in memory per test run (dev/test only)
 * and are never written to disk or committed.
 *
 * Opt-in: set TPA_TEST_DATABASE_URL to a disposable schema. The suite DROPS and recreates
 * every tpa_* table there. Without the variable the suite is skipped.
 */
import { createHash, generateKeyPairSync, randomBytes, verify as verifySignature } from "node:crypto";
import { drizzle } from "drizzle-orm/mysql2";
import mysql from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createTpaAuthority } from "../src/config.js";
import { canonicalTpaMandate, type TpaCheckoutInput } from "../src/domain.js";
import { createTpaEvidenceStore, TpaEvidenceError } from "../src/evidence.js";
import { createMinimalOwnerAdapter } from "../src/host/minimal-owner.js";
import { tpaSchema } from "../src/schema.js";
import { createTpaService, type TpaService } from "../src/service.js";
import { createTpaMandateSigner, type TpaMandateSigner } from "../src/signing.js";
import { createTpaStore } from "../src/store.js";
import { syntheticAuthenticator, type SyntheticAuthenticator } from "./support/authenticator.js";
import { resetTpaSchema } from "./support/schema.js";

const DATABASE_URL = process.env.TPA_TEST_DATABASE_URL;
const ORIGIN = "https://tpa.example.test";
const RP_ID = "tpa.example.test";
const T0 = 1_800_000_000_000;
const sha256hex = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const owner = { principalId: 1, sessionHash: "a".repeat(64), owner: true as const };
const ctx = { owner, headers: { origin: ORIGIN } };

/** $37.80 checkout: 2 x $7.50 mug + 1 x $15.00 tee = $30.00, + $5.00 standard shipping + $2.80 tax. */
const CHECKOUT: TpaCheckoutInput = {
  currency: "USD",
  recipient: "user:42",
  merchant: { id: "acme-store", name: "Acme Store" },
  items: [{ sku: "TEE-02", qty: 1, unitPriceBaseUnits: "1500" }, { sku: "MUG-01", qty: 2, unitPriceBaseUnits: "750" }],
  shipping: { method: "standard", costBaseUnits: "500" },
  taxBaseUnits: "280",
  totalBaseUnits: "3780",
};
const ORDER = { ...CHECKOUT, consent: true as const };

const devKey = () => generateKeyPairSync("ed25519").privateKey;
const KEY_A = devKey();
const KEY_B = devKey();

let pool: mysql.Pool;
let clock = T0;
let signer: TpaMandateSigner;
let service: TpaService;
let device: SyntheticAuthenticator;

function db() { return drizzle(pool, { schema: tpaSchema, mode: "default" }); }
function adapter() { const database = db(); return createMinimalOwnerAdapter(async () => database as never); }
function buildService(options: { signer?: TpaMandateSigner; legacyTransferMandates?: boolean; withEvidence?: boolean } = {}) {
  const host = adapter();
  return createTpaService({
    store: createTpaStore(host), authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now: () => clock,
    signer: options.signer, evidence: options.withEvidence === false ? undefined : createTpaEvidenceStore(host), legacyTransferMandates: options.legacyTransferMandates,
  });
}

function buildServiceWithEvidenceFailure(fail: (event: { action?: string; operation: string }) => boolean) {
  const host = adapter();
  const real = createTpaEvidenceStore(host);
  const evidence = {
    ...real,
    saveSignature: async (input: Parameters<typeof real.saveSignature>[0]) => {
      if (fail({ operation: "saveSignature" })) throw new TpaEvidenceError("unavailable");
      return real.saveSignature(input);
    },
    saveChallengeBinding: async (input: Parameters<typeof real.saveChallengeBinding>[0]) => {
      if (fail({ operation: "saveChallengeBinding" })) throw new TpaEvidenceError("unavailable");
      return real.saveChallengeBinding(input);
    },
    audit: async (input: Parameters<typeof real.audit>[0]) => {
      if (fail({ operation: "audit", action: input.action })) throw new TpaEvidenceError("unavailable");
      return real.audit(input);
    },
  };
  return createTpaService({
    store: createTpaStore(host), authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now: () => clock, signer, evidence,
  });
}

/** Advances only from the selected real evidence callback, after a store lock exists when `transaction` is present. */
function buildServiceWithExpiryAdvance(advance: (event: { action?: string; operation: string; transaction?: unknown }) => boolean) {
  const host = adapter();
  const real = createTpaEvidenceStore(host);
  const tick = (event: { action?: string; operation: string; transaction?: unknown }) => { if (advance(event)) clock += 300_000; };
  const evidence = {
    ...real,
    getSignatures: async (input: Parameters<typeof real.getSignatures>[0]) => {
      const result = await real.getSignatures(input);
      tick({ operation: "getSignatures", transaction: input.transaction });
      return result;
    },
    audit: async (input: Parameters<typeof real.audit>[0]) => {
      await real.audit(input);
      tick({ operation: "audit", action: input.action, transaction: input.transaction });
    },
  };
  return createTpaService({
    store: createTpaStore(host), authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now: () => clock, signer, evidence,
  });
}

async function row(table: string, key: string, id: string) {
  const [rows] = await pool.query(`SELECT * FROM ${table} WHERE ${key} = ?`, [id]);
  return (rows as any[])[0];
}
const intentRow = (id: string) => row("tpa_intents", "id", id);
async function auditRows() {
  const [rows] = await pool.query("SELECT * FROM tpa_audit_events ORDER BY id");
  return rows as any[];
}

async function humanAuthorizes(intentId: string, svc = service) {
  const started = await svc.authenticationOptions(ctx, { intentId, consent: true });
  const response = device.assert(started.options.challenge);
  return { started, response, result: () => svc.authorize(ctx, { intentId, ceremonyId: started.ceremonyId, response, consent: true }) };
}
async function authorizedIntent(order = ORDER, svc = service) {
  const intent = await svc.createIntent(ctx, order);
  await (await humanAuthorizes(intent.id, svc)).result();
  return intent;
}
const refused = (code: string, reason?: string) => expect.objectContaining({ name: "TpaServiceError", code, ...(reason ? { reason } : {}) });
const consume = (intentId: string, checkout: unknown = CHECKOUT, svc = service) => svc.consume(ctx, { intentId, consent: true, checkout: checkout as TpaCheckoutInput });

describe.skipIf(!DATABASE_URL)("Hardened checkout mandate: signed, passkey-bound, exact match at use (real MySQL + WebAuthn + Ed25519)", () => {
  beforeAll(async () => { pool = mysql.createPool({ uri: DATABASE_URL!, connectionLimit: 8 }); });
  afterAll(async () => { await pool?.end(); });
  beforeEach(async () => {
    await resetTpaSchema(pool);
    clock = T0;
    signer = createTpaMandateSigner({ activeKeyId: "test-key-a", privateKey: KEY_A });
    service = buildService({ signer });
    device = syntheticAuthenticator(ORIGIN, RP_ID);
    const reg = await service.registrationOptions(ctx, { label: "Raul phone", consent: true });
    await service.registrationVerify(ctx, { ceremonyId: reg.ceremonyId, response: device.register(reg.options.challenge) });
  });

  it("HAPPY PATH: signed checkout mandate, passkey bound to it, exact checkout consumed once, all audited", async () => {
    const intent: any = await service.createIntent(ctx, ORDER);
    expect(intent.mandate).toMatchObject({
      version: "3.0", action: "checkout-authorization", merchant: { id: "acme-store", name: "Acme Store" },
      items: [{ sku: "MUG-01", qty: 2, unitPriceBaseUnits: "750" }, { sku: "TEE-02", qty: 1, unitPriceBaseUnits: "1500" }],
      shipping: { method: "standard", costBaseUnits: "500" }, subtotalBaseUnits: "3000", taxBaseUnits: "280", amountBaseUnits: "3780", feeBaseUnits: "0",
    });
    const canonical = canonicalTpaMandate(intent.mandate);
    expect(intent.mandateHash).toBe(sha256hex(canonical));
    // Independent verification of the server signature with only the published public key.
    expect(intent.serverSignature).toMatchObject({ keyId: "test-key-a", algorithm: "Ed25519", valid: true });
    const publicKey = signer.publicKeys()["test-key-a"]!;
    expect(verifySignature(null, Buffer.from(`TPA-MANDATE-SIG/1\ntest-key-a\n${canonical}`), { key: Buffer.from(publicKey, "base64"), format: "der", type: "spki" }, Buffer.from(intent.serverSignature.signature, "base64url"))).toBe(true);

    clock += 1_000;
    const { started, result } = await humanAuthorizes(intent.id);
    // Independent recomputation: challenge = base64url(SHA-256(mandateHash bytes || bindingNonce bytes)).
    const expected = createHash("sha256").update(Buffer.concat([Buffer.from(intent.mandateHash, "hex"), Buffer.from(started.challengeBinding!.bindingNonce, "base64url")])).digest("base64url");
    expect(started.options.challenge).toBe(expected);
    expect((await result()).intent.state).toBe("authorized");

    clock += 1_000;
    // Same cart presented in a different line order is the same canonical checkout.
    const used = await consume(intent.id, { ...CHECKOUT, items: [...CHECKOUT.items].reverse() });
    expect(used.intent).toMatchObject({ state: "consumed", mandateHash: intent.mandateHash });
    await expect(consume(intent.id)).rejects.toEqual(refused("intent"));

    const audit = await auditRows();
    expect(audit.filter(a => a.intentId === intent.id).map(a => [a.action, a.outcome, a.reasonCode])).toEqual([
      ["intent_created", "approved", "ok"], ["authorized", "approved", "ok"], ["consume", "attempt", "pending"], ["consumed", "approved", "ok"],
      // The failed lifecycle transaction rolls its attempted-use audit back;
      // the separately best-effort refusal record truthfully remains.
      ["consume", "refused", "intent"],
    ]);
    expect(audit.find(a => a.action === "consumed")).toMatchObject({ userId: 1, mandateHash: intent.mandateHash, keyId: "test-key-a", atMs: T0 + 2_000 });
    const status: any = await service.status(ctx);
    expect(status.intents.find((i: any) => i.id === intent.id).serverSignature).toMatchObject({ keyId: "test-key-a", valid: true });
  });

  describe("exact match at use time: terms_changed, never unavailable", () => {
    const cases: Array<[string, TpaCheckoutInput, string]> = [
      ["item added", { ...CHECKOUT, items: [...CHECKOUT.items, { sku: "SOCK-03", qty: 1, unitPriceBaseUnits: "400" }], totalBaseUnits: "4180" }, "items_mismatch"],
      ["item swapped (same price, different SKU)", { ...CHECKOUT, items: [{ sku: "TEE-99", qty: 1, unitPriceBaseUnits: "1500" }, CHECKOUT.items[1]!] }, "items_mismatch"],
      ["item quantity changed", { ...CHECKOUT, items: [CHECKOUT.items[0]!, { sku: "MUG-01", qty: 3, unitPriceBaseUnits: "750" }], totalBaseUnits: "4530" }, "items_mismatch"],
      ["item removed", { ...CHECKOUT, items: [CHECKOUT.items[0]!], totalBaseUnits: "2280" }, "items_mismatch"],
      ["unit price changed by one cent", { ...CHECKOUT, items: [CHECKOUT.items[0]!, { sku: "MUG-01", qty: 2, unitPriceBaseUnits: "751" }], totalBaseUnits: "3782" }, "items_mismatch"],
      ["shipping method changed (same cost)", { ...CHECKOUT, shipping: { method: "overnight", costBaseUnits: "500" } }, "shipping_mismatch"],
      ["shipping cost changed", { ...CHECKOUT, shipping: { method: "standard", costBaseUnits: "900" }, totalBaseUnits: "4180" }, "shipping_mismatch"],
      ["tax changed (total adjusted)", { ...CHECKOUT, taxBaseUnits: "300", totalBaseUnits: "3800" }, "tax_mismatch"],
      ["currency changed with a total-consistent checkout", { ...CHECKOUT, currency: "DOGE", totalBaseUnits: "3780" }, "currency_mismatch"],
      ["total bumped without any component change", { ...CHECKOUT, totalBaseUnits: "3781" }, "checkout_total_inconsistent"],
      ["total lowered without any component change", { ...CHECKOUT, totalBaseUnits: "3779" }, "checkout_total_inconsistent"],
      ["wrong merchant id", { ...CHECKOUT, merchant: { id: "evil-store", name: "Acme Store" } }, "merchant_mismatch"],
      ["wrong merchant name", { ...CHECKOUT, merchant: { id: "acme-store", name: "Acme Store Ltd" } }, "merchant_mismatch"],
      ["different payee account", { ...CHECKOUT, recipient: "user:666" }, "recipient_mismatch"],
      ["duplicate SKU line", { ...CHECKOUT, items: [...CHECKOUT.items, { sku: "MUG-01", qty: 0 + 1, unitPriceBaseUnits: "0" }] }, "checkout_duplicate_sku"],
      ["float amount", { ...CHECKOUT, totalBaseUnits: "37.80" }, "checkout_invalid"],
    ];
    for (const [name, checkout, reason] of cases) {
      it(`${name} at consume is refused as terms_changed/${reason} and audited`, async () => {
        const intent = await authorizedIntent();
        await expect(consume(intent.id, checkout)).rejects.toEqual(refused("terms_changed", reason));
        expect((await intentRow(intent.id)).state).toBe("authorized");
        expect((await auditRows()).at(-1)).toMatchObject({ intentId: intent.id, action: "consume", outcome: "refused", reasonCode: `terms_changed:${reason}`, userId: 1 });
        // The exact checkout still works afterwards: a refused attempt does not burn the authorization.
        expect((await consume(intent.id)).intent.state).toBe("consumed");
      });
    }
    it("consume of a checkout mandate without presenting the checkout is refused (checkout_required)", async () => {
      const intent = await authorizedIntent();
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("terms_changed", "checkout_required"));
    });
  });

  describe("server signature", () => {
    it("bad server signature (one byte flipped in storage) is refused at read, authorization and consume", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const stored = await row("tpa_mandate_signatures", "intentId", intent.id);
      const flipped = (stored.signature[0] === "A" ? "B" : "A") + stored.signature.slice(1);
      await pool.query("UPDATE tpa_mandate_signatures SET signature = ? WHERE intentId = ?", [flipped, intent.id]);
      const status: any = await service.status(ctx);
      expect(status.intents.find((i: any) => i.id === intent.id).serverSignature.valid).toBe(false);
      await expect(service.authenticationOptions(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("mandate_signature_invalid", "bad_signature"));
    });
    it("signature tampered after authorization is refused at consume", async () => {
      const intent = await authorizedIntent();
      const stored = await row("tpa_mandate_signatures", "intentId", intent.id);
      await pool.query("UPDATE tpa_mandate_signatures SET signature = ? WHERE intentId = ?", [(stored.signature[5] === "A" ? "B" : "A").padStart(6, stored.signature.slice(0, 5)) + stored.signature.slice(6), intent.id]);
      await expect(consume(intent.id)).rejects.toEqual(refused("mandate_signature_invalid", "bad_signature"));
      expect((await intentRow(intent.id)).state).toBe("authorized");
    });
    it("missing signature row is refused", async () => {
      const intent = await authorizedIntent();
      await pool.query("DELETE FROM tpa_mandate_signatures WHERE intentId = ?", [intent.id]);
      await expect(consume(intent.id)).rejects.toEqual(refused("mandate_signature_invalid", "missing"));
    });
    it("wrong server key id (unknown kid) is refused", async () => {
      const intent = await authorizedIntent();
      await pool.query("UPDATE tpa_mandate_signatures SET keyId = ? WHERE intentId = ?", ["attacker-kid", intent.id]);
      await expect(consume(intent.id)).rejects.toEqual(refused("mandate_signature_invalid", "unknown_key"));
    });
    it("a different key published under the same key id does not verify", async () => {
      const intent = await authorizedIntent();
      const impostor = buildService({ signer: createTpaMandateSigner({ activeKeyId: "test-key-a", privateKey: KEY_B }) });
      await expect(consume(intent.id, CHECKOUT, impostor)).rejects.toEqual(refused("mandate_signature_invalid", "bad_signature"));
    });
    it("a mandate signed by an attacker's own key is refused (unknown key id)", async () => {
      const intent = await authorizedIntent();
      const attacker = createTpaMandateSigner({ activeKeyId: "attacker-kid", privateKey: KEY_B });
      const forged = attacker.sign(canonicalTpaMandate(intent.mandate));
      await pool.query("UPDATE tpa_mandate_signatures SET keyId = ?, signature = ? WHERE intentId = ?", [forged.keyId, forged.signature, intent.id]);
      await expect(consume(intent.id)).rejects.toEqual(refused("mandate_signature_invalid", "unknown_key"));
    });
    it("key rotation: a retired key in the verify set still verifies; once removed it is refused", async () => {
      const intent = await authorizedIntent();
      const rotated = createTpaMandateSigner({ activeKeyId: "test-key-b", privateKey: KEY_B, verificationKeys: { "test-key-a": signer.publicKeys()["test-key-a"]! } });
      const after = buildService({ signer: rotated });
      const fresh: any = await after.createIntent(ctx, { ...ORDER, taxBaseUnits: "281", totalBaseUnits: "3781" });
      expect(fresh.serverSignature.keyId).toBe("test-key-b");
      expect((await consume(intent.id, CHECKOUT, after)).intent.state).toBe("consumed");
      const second = await authorizedIntent(ORDER, service);
      const removed = buildService({ signer: createTpaMandateSigner({ activeKeyId: "test-key-b", privateKey: KEY_B }) });
      await expect(consume(second.id, CHECKOUT, removed)).rejects.toEqual(refused("mandate_signature_invalid", "unknown_key"));
    });
    it("consistent database rewrite (new terms + recomputed hash) is refused by the signature", async () => {
      const intent = await authorizedIntent();
      const rewritten = { ...intent.mandate, recipient: "user:666" };
      const hash = sha256hex(canonicalTpaMandate(rewritten as any));
      await pool.query("UPDATE tpa_intents SET mandateJson = ?, mandateHash = ? WHERE id = ?", [JSON.stringify(rewritten), hash, intent.id]);
      await expect(consume(intent.id, { ...CHECKOUT, recipient: "user:666" })).rejects.toEqual(refused("mandate_signature_invalid", "hash_mismatch"));
      await pool.query("UPDATE tpa_mandate_signatures SET mandateHash = ? WHERE intentId = ?", [hash, intent.id]);
      await expect(consume(intent.id, { ...CHECKOUT, recipient: "user:666" })).rejects.toEqual(refused("mandate_signature_invalid", "bad_signature"));
      expect((await intentRow(intent.id)).state).toBe("authorized");
    });
    it("mandate edited without its hash is an integrity refusal, not unavailable", async () => {
      const intent = await authorizedIntent();
      await pool.query("UPDATE tpa_intents SET mandateJson = ? WHERE id = ?", [JSON.stringify({ ...intent.mandate, taxBaseUnits: "0" }), intent.id]);
      await expect(consume(intent.id)).rejects.toEqual(refused("integrity"));
    });
    it("no signer configured: checkout mandates are neither issued nor honored", async () => {
      const intent = await authorizedIntent();
      const unsigned = buildService({});
      await expect(unsigned.createIntent(ctx, ORDER)).rejects.toEqual(refused("unavailable", "signer_not_configured"));
      await expect(consume(intent.id, CHECKOUT, unsigned)).rejects.toEqual(refused("mandate_signature_invalid", "signer_not_configured"));
    });
  });

  describe("passkey challenge bound to the mandate", () => {
    it("tampered binding nonce: the challenge no longer derives from the mandate and is refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const { started, result } = await humanAuthorizes(intent.id);
      await pool.query("UPDATE tpa_challenge_bindings SET bindingNonce = ? WHERE ceremonyId = ?", [randomBytes(32).toString("base64url"), started.ceremonyId]);
      await expect(result()).rejects.toEqual(refused("challenge_unbound"));
      expect((await intentRow(intent.id)).state).toBe("pending");
    });
    it("a raw v3 ceremony with no evidence hook fails closed before it is created", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const store = createTpaStore(adapter());
      const ceremonyId = "7".repeat(64);
      const challenge = randomBytes(32).toString("base64url");
      await expect(store.startAuthorization({ userId: 1, sessionHash: owner.sessionHash, origin: ORIGIN, ceremonyId, challenge, intentId: intent.id, now: clock })).rejects.toEqual(expect.objectContaining({ kind: "integrity" }));
      expect(await row("tpa_ceremonies", "id", ceremonyId)).toBeUndefined();
      expect((await intentRow(intent.id)).state).toBe("pending");
    });
    it("a binding row pointed at another mandate's hash is refused", async () => {
      const a = await service.createIntent(ctx, ORDER);
      const b = await service.createIntent(ctx, { ...ORDER, taxBaseUnits: "281", totalBaseUnits: "3781" });
      const { started, result } = await humanAuthorizes(a.id);
      await pool.query("UPDATE tpa_challenge_bindings SET mandateHash = ? WHERE ceremonyId = ?", [b.mandateHash, started.ceremonyId]);
      await expect(result()).rejects.toEqual(refused("challenge_unbound"));
    });
    it("deleted binding is refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const { started, result } = await humanAuthorizes(intent.id);
      await pool.query("DELETE FROM tpa_challenge_bindings WHERE ceremonyId = ?", [started.ceremonyId]);
      await expect(result()).rejects.toEqual(refused("challenge_unbound"));
    });
  });

  describe("creation rules", () => {
    it("default service refuses the legacy amount-only transfer shape", async () => {
      await expect(service.createIntent(ctx, { currency: "USD", amountBaseUnits: "2000", recipient: "user:42", consent: true } as any)).rejects.toEqual(refused("invalid", "checkout_required"));
    });
    it("legacy mode with a signer still works and signs the 2.0 mandate", async () => {
      const legacy = buildService({ signer, legacyTransferMandates: true });
      const intent: any = await legacy.createIntent(ctx, { currency: "USD", amountBaseUnits: "2000", recipient: "user:42", consent: true } as any);
      expect(intent.serverSignature).toMatchObject({ keyId: "test-key-a", valid: true });
      await (await humanAuthorizes(intent.id, legacy)).result();
      expect((await legacy.consume(ctx, { intentId: intent.id, consent: true })).intent.state).toBe("consumed");
    });
    it("inconsistent totals, duplicate SKUs, floats and numeric amounts are rejected before anything is stored", async () => {
      await expect(service.createIntent(ctx, { ...ORDER, totalBaseUnits: "3781" })).rejects.toEqual(refused("invalid", "checkout_total_inconsistent"));
      await expect(service.createIntent(ctx, { ...ORDER, items: [...ORDER.items, { sku: "MUG-01", qty: 1, unitPriceBaseUnits: "0" }] })).rejects.toEqual(refused("invalid", "checkout_duplicate_sku"));
      await expect(service.createIntent(ctx, { ...ORDER, taxBaseUnits: "2.80" })).rejects.toEqual(refused("invalid"));
      await expect(service.createIntent(ctx, { ...ORDER, totalBaseUnits: 3780 } as any)).rejects.toEqual(refused("invalid"));
      await expect(service.createIntent(ctx, { ...ORDER, items: [{ sku: "MUG-01", qty: 1.5, unitPriceBaseUnits: "750" }] } as any)).rejects.toEqual(refused("invalid"));
      const [rows] = await pool.query("SELECT (SELECT COUNT(*) FROM tpa_intents) AS i, (SELECT COUNT(*) FROM tpa_mandate_signatures) AS s");
      expect((rows as any[])[0]).toMatchObject({ i: 0, s: 0 });
    });
    it("signature or creation-audit failure rolls the intent back without an orphan", async () => {
      const signatureFailure = buildServiceWithEvidenceFailure(event => event.operation === "saveSignature");
      await expect(signatureFailure.createIntent(ctx, ORDER)).rejects.toEqual(refused("unavailable"));
      let [rows] = await pool.query("SELECT COUNT(*) AS n FROM tpa_intents");
      expect(Number((rows as any[])[0].n)).toBe(0);

      const auditFailure = buildServiceWithEvidenceFailure(event => event.operation === "audit" && event.action === "intent_created");
      await expect(auditFailure.createIntent(ctx, ORDER)).rejects.toEqual(refused("unavailable"));
      [rows] = await pool.query("SELECT COUNT(*) AS n FROM tpa_intents");
      expect(Number((rows as any[])[0].n)).toBe(0);
    });
    it("raw v3 create, finalize, and consume calls without lifecycle hooks fail closed", async () => {
      const issued = await service.createIntent(ctx, ORDER);
      const store = createTpaStore(adapter());
      await expect(store.createIntent({ userId: 1, sessionHash: owner.sessionHash, origin: ORIGIN, id: "f".repeat(64), mandate: issued.mandate, now: clock })).rejects.toEqual(expect.objectContaining({ kind: "integrity" }));
      await expect(store.finalizeAuthorization({ userId: 1, sessionHash: owner.sessionHash, origin: ORIGIN, intentId: issued.id, credentialId: device.id, newCounter: 1, now: clock })).rejects.toEqual(expect.objectContaining({ kind: "integrity" }));
      await (await humanAuthorizes(issued.id)).result();
      await expect(store.consumeIntent({ userId: 1, sessionHash: owner.sessionHash, origin: ORIGIN, intentId: issued.id, now: clock })).rejects.toEqual(expect.objectContaining({ kind: "integrity" }));
      expect((await intentRow(issued.id)).state).toBe("authorized");
    });
  });

  describe("transactional evidence and direct intent reads", () => {
    it("refuses expiry advanced by the creation audit callback and leaves no signed intent orphan", async () => {
      const signed = buildServiceWithExpiryAdvance(event => event.operation === "audit" && event.action === "intent_created" && !!event.transaction);
      await expect(signed.createIntent(ctx, ORDER)).rejects.toEqual(refused("intent"));
      const [rows] = await pool.query("SELECT (SELECT COUNT(*) FROM tpa_intents) AS intents, (SELECT COUNT(*) FROM tpa_mandate_signatures) AS signatures, (SELECT COUNT(*) FROM tpa_audit_events WHERE action = 'intent_created') AS audits");
      expect((rows as any[])[0]).toMatchObject({ intents: 0, signatures: 0, audits: 0 });
    });
    it("refuses expiry advanced by a locked challenge evidence read and leaves no ceremony or binding orphan", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const signed = buildServiceWithExpiryAdvance(event => event.operation === "getSignatures" && !!event.transaction);
      await expect(signed.authenticationOptions(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
      const [rows] = await pool.query("SELECT (SELECT COUNT(*) FROM tpa_ceremonies WHERE intentId = ?) AS ceremonies, (SELECT COUNT(*) FROM tpa_challenge_bindings WHERE intentId = ?) AS bindings", [intent.id, intent.id]);
      expect((rows as any[])[0]).toMatchObject({ ceremonies: 0, bindings: 0 });
      expect((await intentRow(intent.id)).state).toBe("pending");
    });
    it("refuses expiry advanced by a locked authorization evidence read, rolls back state and counter, and burns the ceremony", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const started = await service.authenticationOptions(ctx, { intentId: intent.id, consent: true });
      const signed = buildServiceWithExpiryAdvance(event => event.operation === "getSignatures" && !!event.transaction);
      await expect(signed.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: device.assert(started.options.challenge), consent: true })).rejects.toEqual(refused("intent"));
      expect((await intentRow(intent.id)).state).toBe("pending");
      expect(Number((await row("tpa_credentials", "credentialId", device.id)).counter)).toBe(0);
      expect((await row("tpa_ceremonies", "id", started.ceremonyId)).consumedAtMs).not.toBeNull();
    });
    it("refuses expiry advanced by the authorization audit callback after the state transition and rolls it back", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const started = await service.authenticationOptions(ctx, { intentId: intent.id, consent: true });
      const signed = buildServiceWithExpiryAdvance(event => event.operation === "audit" && event.action === "authorized" && !!event.transaction);
      await expect(signed.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: device.assert(started.options.challenge), consent: true })).rejects.toEqual(refused("intent"));
      expect((await intentRow(intent.id)).state).toBe("pending");
      expect(Number((await row("tpa_credentials", "credentialId", device.id)).counter)).toBe(0);
      expect((await auditRows()).filter(event => event.intentId === intent.id && event.action === "authorized")).toHaveLength(0);
    });
    it("refuses expiry advanced by a locked consume evidence read and leaves the mandate authorized", async () => {
      const intent = await authorizedIntent();
      const signed = buildServiceWithExpiryAdvance(event => event.operation === "getSignatures" && !!event.transaction);
      await expect(consume(intent.id, CHECKOUT, signed)).rejects.toEqual(refused("intent"));
      expect((await intentRow(intent.id)).state).toBe("authorized");
      expect((await auditRows()).filter(event => event.intentId === intent.id && event.action === "consume" && event.outcome === "attempt")).toHaveLength(0);
    });
    it("refuses expiry advanced by the completion audit callback after consume and rolls it back", async () => {
      const intent = await authorizedIntent();
      const signed = buildServiceWithExpiryAdvance(event => event.operation === "audit" && event.action === "consumed" && !!event.transaction);
      await expect(consume(intent.id, CHECKOUT, signed)).rejects.toEqual(refused("intent"));
      expect((await intentRow(intent.id)).state).toBe("authorized");
      expect((await auditRows()).filter(event => event.intentId === intent.id && event.action === "consume" && event.outcome === "attempt")).toHaveLength(0);
      expect((await auditRows()).filter(event => event.intentId === intent.id && event.action === "consumed")).toHaveLength(0);
    });
    it("binding failure rolls its authorization ceremony back with no orphan", async () => {
      const signed = buildServiceWithEvidenceFailure(event => event.operation === "saveChallengeBinding");
      const intent = await signed.createIntent(ctx, ORDER);
      const [before] = await pool.query("SELECT COUNT(*) AS n FROM tpa_ceremonies");
      await expect(signed.authenticationOptions(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("unavailable"));
      const [after] = await pool.query("SELECT COUNT(*) AS n FROM tpa_ceremonies");
      expect(Number((after as any[])[0].n)).toBe(Number((before as any[])[0].n));
    });
    it("authorization audit failure rolls back the counter and state but burns the verified ceremony", async () => {
      const signed = buildServiceWithEvidenceFailure(event => event.operation === "audit" && event.action === "authorized");
      const intent = await signed.createIntent(ctx, ORDER);
      const started = await signed.authenticationOptions(ctx, { intentId: intent.id, consent: true });
      await expect(signed.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: device.assert(started.options.challenge), consent: true })).rejects.toEqual(refused("unavailable"));
      expect((await intentRow(intent.id)).state).toBe("pending");
      expect(Number((await row("tpa_credentials", "credentialId", device.id)).counter)).toBe(0);
      expect((await row("tpa_ceremonies", "id", started.ceremonyId)).consumedAtMs).not.toBeNull();
    });
    it("consume completion-audit failure leaves the mandate authorized", async () => {
      const signed = buildServiceWithEvidenceFailure(event => event.operation === "audit" && event.action === "consumed");
      const intent = await authorizedIntent(ORDER, signed);
      await expect(consume(intent.id, CHECKOUT, signed)).rejects.toEqual(refused("unavailable"));
      expect((await intentRow(intent.id)).state).toBe("authorized");
      expect((await auditRows()).filter(event => event.intentId === intent.id && event.outcome === "attempt")).toHaveLength(0);
    });
    it("registration approval-audit failure rolls back credential persistence and the ceremony completion claim", async () => {
      const signed = buildServiceWithEvidenceFailure(event => event.operation === "audit" && event.action === "credential_registered");
      const replacement = syntheticAuthenticator(ORIGIN, RP_ID);
      const started = await signed.registrationOptions(ctx, { label: "Backup phone", consent: true });
      await expect(signed.registrationVerify(ctx, { ceremonyId: started.ceremonyId, response: replacement.register(started.options.challenge) })).rejects.toEqual(refused("unavailable"));
      expect(await row("tpa_credentials", "credentialId", replacement.id)).toBeUndefined();
      expect(await row("tpa_ceremonies", "registeredCredentialIdHash", sha256hex(replacement.id))).toBeUndefined();
      const ceremony = await row("tpa_ceremonies", "id", started.ceremonyId);
      expect(ceremony).toMatchObject({ consumedAtMs: expect.anything(), completedAtMs: null, registeredCredentialIdHash: null });
    });
    it("revocation remains available when best-effort audit storage is unavailable", async () => {
      const signed = buildServiceWithEvidenceFailure(event => event.operation === "audit" && (event.action === "revoked" || event.action === "credential_revoked"));
      const intent = await service.createIntent(ctx, ORDER);
      await expect(signed.revoke(ctx, { intentId: intent.id, consent: true })).resolves.toMatchObject({ revoked: true });
      expect((await intentRow(intent.id)).state).toBe("revoked");
      const credential = await row("tpa_credentials", "credentialId", device.id);
      await expect(signed.revokeCredential(ctx, { credentialIdHash: credential.credentialIdHash, consent: true })).resolves.toMatchObject({ revoked: true });
      expect((await row("tpa_credentials", "credentialId", device.id)).revokedAtMs).not.toBeNull();
    });
    it("unsigned v2 uses the direct bound read beyond the status page and remains compatible", async () => {
      const legacy = buildService({ legacyTransferMandates: true, withEvidence: false });
      const stale = await legacy.createIntent(ctx, { currency: "USD", amountBaseUnits: "2000", recipient: "user:42", consent: true });
      for (let amount = 2001; amount <= 2030; amount += 1) {
        clock += 1;
        await legacy.createIntent(ctx, { currency: "USD", amountBaseUnits: String(amount), recipient: "user:42", consent: true });
      }
      const status = await legacy.status(ctx);
      expect(status.intents).toHaveLength(30);
      expect(status.intents.some(intent => intent.id === stale.id)).toBe(false);
      const started = await legacy.authenticationOptions(ctx, { intentId: stale.id, consent: true });
      expect((await legacy.authorize(ctx, { intentId: stale.id, ceremonyId: started.ceremonyId, response: device.assert(started.options.challenge), consent: true })).intent.state).toBe("authorized");
      expect((await legacy.consume(ctx, { intentId: stale.id, consent: true })).intent.state).toBe("consumed");
    });
    it("mutating signature evidence immediately before the real transition cannot authorize or consume", async () => {
      const pending = await service.createIntent(ctx, ORDER);
      const baseAuthorize = createTpaStore(adapter());
      const mutatingAuthorize = createTpaService({
        store: { ...baseAuthorize, finalizeAuthorization: async input => {
          await pool.query("UPDATE tpa_mandate_signatures SET signature = CONCAT(CASE WHEN LEFT(signature, 1) = 'A' THEN 'B' ELSE 'A' END, SUBSTRING(signature, 2)) WHERE intentId = ?", [input.intentId]);
          return baseAuthorize.finalizeAuthorization(input);
        } }, authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), signer, evidence: createTpaEvidenceStore(adapter()), now: () => clock,
      });
      const started = await mutatingAuthorize.authenticationOptions(ctx, { intentId: pending.id, consent: true });
      await expect(mutatingAuthorize.authorize(ctx, { intentId: pending.id, ceremonyId: started.ceremonyId, response: device.assert(started.options.challenge), consent: true })).rejects.toEqual(refused("mandate_signature_invalid", "bad_signature"));
      expect((await intentRow(pending.id)).state).toBe("pending");

      const authorized = await authorizedIntent({ ...ORDER, taxBaseUnits: "281", totalBaseUnits: "3781" });
      const baseConsume = createTpaStore(adapter());
      const mutatingConsume = createTpaService({
        store: { ...baseConsume, consumeIntent: async input => {
          await pool.query("UPDATE tpa_mandate_signatures SET mandateHash = ? WHERE intentId = ?", ["f".repeat(64), input.intentId]);
          return baseConsume.consumeIntent(input);
        } }, authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), signer, evidence: createTpaEvidenceStore(adapter()), now: () => clock,
      });
      await expect(mutatingConsume.consume(ctx, { intentId: authorized.id, consent: true, checkout: { ...CHECKOUT, taxBaseUnits: "281", totalBaseUnits: "3781" } })).rejects.toEqual(refused("mandate_signature_invalid", "hash_mismatch"));
      expect((await intentRow(authorized.id)).state).toBe("authorized");
    });
  });

  describe("signed v3 lifecycle refusals and concurrency", () => {
    it("never lets v3 fall back to legacy mode when signer or evidence is absent", async () => {
      const noEvidence = buildService({ signer, legacyTransferMandates: true, withEvidence: false });
      const noSigner = buildService({ legacyTransferMandates: true });
      const pending = await service.createIntent(ctx, ORDER);
      await expect(noEvidence.authenticationOptions(ctx, { intentId: pending.id, consent: true })).rejects.toEqual(refused("mandate_signature_invalid", "evidence_not_configured"));
      await expect(noSigner.authenticationOptions(ctx, { intentId: pending.id, consent: true })).rejects.toEqual(refused("mandate_signature_invalid", "signer_not_configured"));

      const evidenceCeremony = await service.authenticationOptions(ctx, { intentId: pending.id, consent: true });
      await expect(noEvidence.authorize(ctx, { intentId: pending.id, ceremonyId: evidenceCeremony.ceremonyId, response: device.assert(evidenceCeremony.options.challenge), consent: true })).rejects.toEqual(refused("mandate_signature_invalid", "evidence_not_configured"));
      expect((await intentRow(pending.id)).state).toBe("pending");

      const pendingWithoutSigner = await service.createIntent(ctx, { ...ORDER, taxBaseUnits: "281", totalBaseUnits: "3781" });
      const signerCeremony = await service.authenticationOptions(ctx, { intentId: pendingWithoutSigner.id, consent: true });
      await expect(noSigner.authorize(ctx, { intentId: pendingWithoutSigner.id, ceremonyId: signerCeremony.ceremonyId, response: device.assert(signerCeremony.options.challenge), consent: true })).rejects.toEqual(refused("mandate_signature_invalid", "signer_not_configured"));
      expect((await intentRow(pendingWithoutSigner.id)).state).toBe("pending");

      const authorized = await authorizedIntent({ ...ORDER, taxBaseUnits: "282", totalBaseUnits: "3782" });
      await expect(noEvidence.consume(ctx, { intentId: authorized.id, consent: true })).rejects.toEqual(refused("mandate_signature_invalid", "evidence_not_configured"));
      await expect(noSigner.consume(ctx, { intentId: authorized.id, consent: true })).rejects.toEqual(refused("mandate_signature_invalid", "signer_not_configured"));
      expect((await intentRow(authorized.id)).state).toBe("authorized");
    });
    it("legacy v2 remains compatible with no signer or no evidence without using a status listing", async () => {
      const variants = [
        buildService({ legacyTransferMandates: true }),
        buildService({ signer, legacyTransferMandates: true, withEvidence: false }),
      ];
      for (const [index, legacy] of variants.entries()) {
        const intent = await legacy.createIntent(ctx, { currency: "USD", amountBaseUnits: String(2_000 + index), recipient: "user:42", consent: true });
        const started = await legacy.authenticationOptions(ctx, { intentId: intent.id, consent: true });
        await expect(legacy.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: device.assert(started.options.challenge), consent: true })).resolves.toMatchObject({ accepted: true });
        await expect(legacy.consume(ctx, { intentId: intent.id, consent: true })).resolves.toMatchObject({ consumed: true });
      }
    });
    it("requires explicit consent at every v3 permission boundary", async () => {
      await expect(service.createIntent(ctx, { ...ORDER, consent: false } as any)).rejects.toEqual(refused("invalid"));
      const intent = await service.createIntent(ctx, ORDER);
      await expect(service.authenticationOptions(ctx, { intentId: intent.id, consent: false } as any)).rejects.toEqual(refused("invalid"));
      const started = await service.authenticationOptions(ctx, { intentId: intent.id, consent: true });
      const response = device.assert(started.options.challenge);
      await expect(service.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response, consent: false } as any)).rejects.toEqual(refused("invalid"));
      await expect(service.consume(ctx, { intentId: intent.id, consent: false, checkout: CHECKOUT } as any)).rejects.toEqual(refused("invalid"));
      await expect(service.revoke(ctx, { intentId: intent.id, consent: false } as any)).rejects.toEqual(refused("invalid"));
    });
    it("refuses signed v3 expiry, pending and absent mandates without changing state", async () => {
      const expired = await service.createIntent(ctx, ORDER);
      clock += 300_000;
      await expect(service.authenticationOptions(ctx, { intentId: expired.id, consent: true })).rejects.toEqual(refused("intent"));
      expect((await intentRow(expired.id)).state).toBe("pending");

      clock = T0;
      const pending = await service.createIntent(ctx, { ...ORDER, taxBaseUnits: "281", totalBaseUnits: "3781" });
      await expect(consume(pending.id)).rejects.toEqual(refused("intent"));
      await expect(service.consume(ctx, { intentId: "9".repeat(64), consent: true, checkout: CHECKOUT })).rejects.toEqual(refused("intent"));
      expect((await intentRow(pending.id)).state).toBe("pending");
    });
    it("burns a signed v3 ceremony after a bad assertion and leaves the mandate pending", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const started = await service.authenticationOptions(ctx, { intentId: intent.id, consent: true });
      await expect(service.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: device.assert(started.options.challenge, { corruptSignature: true }), consent: true })).rejects.toEqual(refused("ceremony"));
      expect((await intentRow(intent.id)).state).toBe("pending");
      await expect(service.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: device.assert(started.options.challenge), consent: true })).rejects.toEqual(refused("ceremony"));
    });
    it("revocation blocks signed v3 authorization and consumption", async () => {
      const pending = await service.createIntent(ctx, ORDER);
      await service.revoke(ctx, { intentId: pending.id, consent: true });
      await expect(service.authenticationOptions(ctx, { intentId: pending.id, consent: true })).rejects.toEqual(refused("intent"));

      const authorized = await authorizedIntent({ ...ORDER, taxBaseUnits: "281", totalBaseUnits: "3781" });
      await service.revoke(ctx, { intentId: authorized.id, consent: true });
      await expect(consume(authorized.id, { ...CHECKOUT, taxBaseUnits: "281", totalBaseUnits: "3781" })).rejects.toEqual(refused("intent"));
    });
    it("permits exactly one concurrent signed v3 consume and refuses replay", async () => {
      const intent = await authorizedIntent();
      const outcomes = await Promise.allSettled(Array.from({ length: 5 }, () => consume(intent.id)));
      expect(outcomes.filter(outcome => outcome.status === "fulfilled")).toHaveLength(1);
      await expect(consume(intent.id)).rejects.toEqual(refused("intent"));
      await expect(service.authenticationOptions(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
    });
  });

  describe("audit log", () => {
    it("records refusals with reason code and timestamp, including unauthenticated callers, and holds no secrets", async () => {
      const intent = await authorizedIntent();
      clock += 5_000;
      await expect(consume(intent.id, { ...CHECKOUT, merchant: { id: "evil-store", name: "Acme Store" } })).rejects.toEqual(refused("terms_changed"));
      await pool.query("UPDATE tpa_mandate_signatures SET keyId = 'attacker-kid' WHERE intentId = ?", [intent.id]);
      await expect(consume(intent.id)).rejects.toEqual(refused("mandate_signature_invalid"));
      await expect(service.consume({ owner: undefined, headers: { origin: ORIGIN } } as any, { intentId: intent.id, consent: true, checkout: CHECKOUT })).rejects.toEqual(refused("unauthenticated"));
      const refusals = (await auditRows()).filter(a => a.outcome === "refused");
      expect(refusals.map(a => [a.action, a.reasonCode, a.userId == null ? null : Number(a.userId), Number(a.atMs)])).toEqual([
        ["consume", "terms_changed:merchant_mismatch", 1, T0 + 5_000],
        ["consume", "mandate_signature_invalid:unknown_key", 1, T0 + 5_000],
        ["consume", "unauthenticated", null, T0 + 5_000],
      ]);
      // No secrets: no session hash, passkey challenge, binding nonce, signature or key material in any audit row.
      const [secrets] = await pool.query("SELECT (SELECT GROUP_CONCAT(signature) FROM tpa_mandate_signatures) AS sig, (SELECT GROUP_CONCAT(challenge) FROM tpa_challenge_bindings) AS ch, (SELECT GROUP_CONCAT(bindingNonce) FROM tpa_challenge_bindings) AS nonce");
      const dump = JSON.stringify(await auditRows());
      const s = (secrets as any[])[0];
      for (const value of [owner.sessionHash, ...String(s.sig).split(","), ...String(s.ch).split(","), ...String(s.nonce).split(",")]) expect(dump).not.toContain(value);
      expect(Object.keys((await auditRows())[0]).sort()).toEqual(["action", "atMs", "id", "intentId", "keyId", "mandateHash", "outcome", "reasonCode", "userId"]);
      // The owner-scoped reader shows only this owner's rows (the unauthenticated attempt has no owner).
      const viaService = await service.auditLog(ctx, { intentId: intent.id });
      expect(viaService[0]).toMatchObject({ outcome: "refused", reasonCode: "mandate_signature_invalid:unknown_key" });
    });
    it("records refused passkey binding attempts and refused creation", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const { started, result } = await humanAuthorizes(intent.id);
      await pool.query("DELETE FROM tpa_challenge_bindings WHERE ceremonyId = ?", [started.ceremonyId]);
      await expect(result()).rejects.toEqual(refused("challenge_unbound"));
      await expect(service.createIntent(ctx, { ...ORDER, totalBaseUnits: "1" })).rejects.toEqual(refused("invalid"));
      const refusals = (await auditRows()).filter(a => a.outcome === "refused").map(a => [a.action, a.reasonCode, a.intentId]);
      expect(refusals).toEqual([["authorize", "challenge_unbound", intent.id], ["create_intent", "invalid:checkout_total_inconsistent", null]]);
    });
  });
});
