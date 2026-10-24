/**
 * Proof of Permission (mandate) refusal suite.
 *
 * Runs the REAL service + REAL MySQL store + REAL WebAuthn ES256 verification
 * against a disposable MySQL/MariaDB schema. A synthetic in-process P-256
 * authenticator stands in for the human's passkey. Nothing here moves money.
 *
 * This file pins the legacy 2.0 transfer mandate (legacyTransferMandates: true, no signer)
 * to prove backward compatibility. The hardened checkout mandate is covered by
 * tests/mandate.hardening.test.ts.
 *
 * Opt-in: set TPA_TEST_DATABASE_URL (e.g. mysql://user:pass@127.0.0.1:3306/tpa_test).
 * The suite DROPS and recreates the four tpa_* tables in that schema; never point it
 * at a shared or production database. Without the variable the suite is skipped.
 */
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { drizzle } from "drizzle-orm/mysql2";
import mysql from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { createTpaAuthority } from "../src/config.js";
import { canonicalTpaMandate, tpaMandateSchema, tpaTransferInput, type TpaMandate } from "../src/domain.js";
import { createMinimalOwnerAdapter } from "../src/host/minimal-owner.js";
import { assertFreshTpaReview } from "../src/review.js";
import { tpaSchema } from "../src/schema.js";
import { createTpaService, type TpaService } from "../src/service.js";
import { createTpaStore } from "../src/store.js";
import { syntheticAuthenticator } from "./support/authenticator.js";
import { resetTpaSchema } from "./support/schema.js";

const DATABASE_URL = process.env.TPA_TEST_DATABASE_URL;
const ORIGIN = "https://tpa.example.test";
const RP_ID = "tpa.example.test";
const T0 = 1_800_000_000_000;
const b64 = (value: Uint8Array | string) => Buffer.from(value).toString("base64url");
const sha256hex = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");
const owner = { principalId: 1, sessionHash: "a".repeat(64), owner: true as const };
const ctx = { owner, headers: { origin: ORIGIN } };
const ORDER = { currency: "USD" as const, amountBaseUnits: "2000", recipient: "user:42", consent: true as const }; // $20.00 to merchant account user:42

const authenticator = () => syntheticAuthenticator(ORIGIN, RP_ID);

let pool: mysql.Pool;
let clock = T0;
let service: TpaService;
let device: ReturnType<typeof authenticator>;
let credentialIdHash: string;

async function freshSchema() {
  await resetTpaSchema(pool);
}

async function intentRow(id: string) {
  const [rows] = await pool.query("SELECT * FROM tpa_intents WHERE id = ?", [id]);
  return (rows as any[])[0];
}

/** Human approves the exact pending intent with their passkey. */
async function humanAuthorizes(intentId: string, opts: Parameters<ReturnType<typeof authenticator>["assert"]>[1] = {}) {
  const started = await service.authenticationOptions(ctx, { intentId, consent: true });
  const response = device.assert(started.options.challenge, opts);
  return { started, response, result: () => service.authorize(ctx, { intentId, ceremonyId: started.ceremonyId, response, consent: true }) };
}

async function authorizedIntent(order = ORDER) {
  const intent = await service.createIntent(ctx, order);
  const { result } = await humanAuthorizes(intent.id);
  await result();
  return intent;
}

const refused = (code?: string) => (code ? expect.objectContaining({ name: "TpaServiceError", code }) : expect.objectContaining({ name: "TpaServiceError" }));

describe.skipIf(!DATABASE_URL)("Proof of Permission: signed mandate must match exactly (real MySQL + real WebAuthn)", () => {
  beforeAll(async () => { pool = mysql.createPool({ uri: DATABASE_URL!, connectionLimit: 8 }); });
  afterAll(async () => { await pool?.end(); });
  beforeEach(async () => {
    await freshSchema();
    clock = T0;
    const db = drizzle(pool, { schema: tpaSchema, mode: "default" });
    const store = createTpaStore(createMinimalOwnerAdapter(async () => db as never));
    service = createTpaService({ store, authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now: () => clock, legacyTransferMandates: true });
    device = authenticator();
    const reg = await service.registrationOptions(ctx, { label: "Raul phone", consent: true });
    const saved = await service.registrationVerify(ctx, { ceremonyId: reg.ceremonyId, response: device.register(reg.options.challenge) });
    credentialIdHash = saved.credential.credentialIdHash;
  });

  it("HAPPY PATH: exact mandate is authorized by the human, consumed exactly once, and recorded", async () => {
    const intent = await service.createIntent(ctx, ORDER);
    expect(intent.mandate).toMatchObject({ amountBaseUnits: "2000", recipient: "user:42", currency: "USD", feeBaseUnits: "0", scope: "single_use", issuerUserId: 1 });
    expect(intent.mandateHash).toBe(sha256hex(canonicalTpaMandate(intent.mandate)));
    clock += 1_000;
    const { result } = await humanAuthorizes(intent.id);
    expect((await result()).intent.state).toBe("authorized");
    clock += 1_000;
    const first = await service.consume(ctx, { intentId: intent.id, consent: true });
    expect(first.intent).toMatchObject({ state: "consumed", mandateHash: intent.mandateHash, authorizedCredentialIdHash: credentialIdHash, authorizedAtMs: T0 + 1_000, consumedAtMs: T0 + 2_000 });
    await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
    // "Logged": the only record the library keeps is the intent row itself (see report: no separate audit log).
    const row = await intentRow(intent.id);
    expect(row).toMatchObject({ state: "consumed", mandateHash: intent.mandateHash, authorizedCredentialIdHash: credentialIdHash });
    expect(Number(row.consumedAtMs)).toBe(T0 + 2_000);
    const status = await service.status(ctx);
    expect(status.intents.find(i => i.id === intent.id)?.state).toBe("consumed");
  });

  it("HAPPY PATH under contention: 5 concurrent consumes of one authorization, exactly one wins", async () => {
    const intent = await authorizedIntent();
    const outcomes = await Promise.allSettled(Array.from({ length: 5 }, () => service.consume(ctx, { intentId: intent.id, consent: true })));
    expect(outcomes.filter(o => o.status === "fulfilled")).toHaveLength(1);
  });

  describe("amount changed by one cent", () => {
    it("stored mandate edited from $20.00 to $20.01 (hash left as signed-off) is refused at consume", async () => {
      const intent = await authorizedIntent();
      const tampered = { ...intent.mandate, amountBaseUnits: "2001" };
      await pool.query("UPDATE tpa_intents SET mandateJson = ? WHERE id = ?", [JSON.stringify(tampered), intent.id]);
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused());
      expect((await intentRow(intent.id)).state).toBe("authorized");
    });
    it("a fresh $20.01 intent cannot ride on the human's $20.00 authorization", async () => {
      const approved = await authorizedIntent();
      const bumped = await service.createIntent(ctx, { ...ORDER, amountBaseUnits: "2001" });
      expect(bumped.mandateHash).not.toBe(approved.mandateHash);
      await expect(service.consume(ctx, { intentId: bumped.id, consent: true })).rejects.toEqual(refused());
    });
    it("a passkey ceremony opened for $20.00 cannot authorize a $20.01 intent", async () => {
      const a = await service.createIntent(ctx, ORDER);
      const b = await service.createIntent(ctx, { ...ORDER, amountBaseUnits: "2001" });
      const { started, response } = await humanAuthorizes(a.id);
      await expect(service.authorize(ctx, { intentId: b.id, ceremonyId: started.ceremonyId, response, consent: true })).rejects.toEqual(refused("ceremony"));
      expect((await intentRow(b.id)).state).toBe("pending");
    });
    it("client review guard refuses when the server copy differs by one cent", () => {
      const m = tpaMandateSchema.parse({ type: "TPA-mandate", version: "2.0", action: "transfer-authorization-pilot", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot", amountBaseUnits: "2000", recipient: "user:42", feeBaseUnits: "0", nonce: "e".repeat(64), issuedAt: 1000, expires: 1300, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2" });
      const reviewed = { id: "x", mandate: m, mandateHash: sha256hex(canonicalTpaMandate(m)), state: "pending", expiresAtMs: 1_300_000 };
      const m2 = { ...m, amountBaseUnits: "2001" };
      expect(() => assertFreshTpaReview(reviewed, { ...reviewed, mandate: m2 }, "authorize", 1_000_000)).toThrow(/changed/i);
    });
  });

  describe("item added or swapped / shipping or other terms changed", () => {
    it("mandate and transfer input are strict: an extra items[] or shipping field is rejected, fee is pinned to 0", () => {
      expect(tpaTransferInput.safeParse({ ...ORDER, items: [{ sku: "A", qty: 1 }] }).success).toBe(false);
      expect(tpaTransferInput.safeParse({ ...ORDER, shipping: "overnight" }).success).toBe(false);
      const m = { type: "TPA-mandate", version: "2.0", action: "transfer-authorization-pilot", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot", amountBaseUnits: "2000", recipient: "user:42", feeBaseUnits: "0", nonce: "e".repeat(64), issuedAt: 1000, expires: 1300, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2" };
      expect(tpaMandateSchema.safeParse(m).success).toBe(true);
      expect(tpaMandateSchema.safeParse({ ...m, items: ["B"] }).success).toBe(false);
      expect(tpaMandateSchema.safeParse({ ...m, feeBaseUnits: "500" }).success).toBe(false);
    });
    it("service refuses an intent request carrying items/shipping (strict input)", async () => {
      await expect(service.createIntent(ctx, { ...ORDER, items: ["swap"] } as any)).rejects.toThrow();
      const [rows] = await pool.query("SELECT COUNT(*) AS n FROM tpa_intents"); expect(Number((rows as any[])[0].n)).toBe(0);
    });
    it("stored mandate with a fee (term) injected after authorization is refused at consume", async () => {
      const intent = await authorizedIntent();
      await pool.query("UPDATE tpa_intents SET mandateJson = ? WHERE id = ?", [JSON.stringify({ ...intent.mandate, feeBaseUnits: "1" }), intent.id]);
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused());
    });
  });

  describe("different merchant (recipient)", () => {
    it("stored recipient swapped after authorization is refused at consume", async () => {
      const intent = await authorizedIntent();
      await pool.query("UPDATE tpa_intents SET mandateJson = ? WHERE id = ?", [JSON.stringify({ ...intent.mandate, recipient: "user:666" }), intent.id]);
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused());
    });
    it("a new intent to a different merchant needs its own human authorization", async () => {
      await authorizedIntent();
      const other = await service.createIntent(ctx, { ...ORDER, recipient: "user:666" });
      await expect(service.consume(ctx, { intentId: other.id, consent: true })).rejects.toEqual(refused());
    });
  });

  describe("expired mandate", () => {
    it("authorization after the 300 s absolute expiry is refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      clock += 300_000;
      await expect(service.authenticationOptions(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
    });
    it("ceremony started in time but finished after mandate expiry is refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      clock += 299_000;
      const { result } = await humanAuthorizes(intent.id);
      clock += 1_000;
      await expect(result()).rejects.toEqual(refused());
      expect((await intentRow(intent.id)).state).toBe("pending");
    });
    it("consume of an authorized mandate after expiry is refused", async () => {
      const intent = await authorizedIntent();
      clock += 300_000;
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
      expect((await intentRow(intent.id)).state).toBe("authorized");
    });
  });

  describe("replay / reuse after a successful use", () => {
    it("second consume, re-authorization, and replay of the same passkey assertion are all refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const { started, response, result } = await humanAuthorizes(intent.id);
      await result();
      await service.consume(ctx, { intentId: intent.id, consent: true });
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
      await expect(service.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response, consent: true })).rejects.toEqual(refused("ceremony"));
      await expect(service.authenticationOptions(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
    });
    it("identical order re-submitted later is a NEW mandate (new nonce/hash) and is not pre-authorized", async () => {
      const first = await authorizedIntent();
      await service.consume(ctx, { intentId: first.id, consent: true });
      const again = await service.createIntent(ctx, ORDER);
      expect(again.mandate.nonce).not.toBe(first.mandate.nonce);
      await expect(service.consume(ctx, { intentId: again.id, consent: true })).rejects.toEqual(refused());
    });
  });

  describe("tampered field so verification fails", () => {
    it("corrupted passkey signature is refused and burns the ceremony", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const { result, started } = await humanAuthorizes(intent.id, { corruptSignature: true });
      await expect(result()).rejects.toThrow();
      expect((await intentRow(intent.id)).state).toBe("pending");
      const good = device.assert(started.options.challenge);
      await expect(service.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: good, consent: true })).rejects.toEqual(refused("ceremony"));
    });
    it("clientDataJSON altered after signing is refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const { result } = await humanAuthorizes(intent.id, { tamperClientData: true });
      await expect(result()).rejects.toThrow();
      expect((await intentRow(intent.id)).state).toBe("pending");
    });
    it("stored mandateHash rewritten to match nothing is refused (integrity)", async () => {
      const intent = await authorizedIntent();
      await pool.query("UPDATE tpa_intents SET mandateHash = ? WHERE id = ?", ["f".repeat(64), intent.id]);
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused());
    });
  });

  it("signature from the wrong key (attacker key, same credential id) is refused", async () => {
    const intent = await service.createIntent(ctx, ORDER);
    const attacker = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
    const { result } = await humanAuthorizes(intent.id, { signWith: attacker.privateKey });
    await expect(result()).rejects.toThrow();
    expect((await intentRow(intent.id)).state).toBe("pending");
  });

  it("an unregistered authenticator is refused", async () => {
    const intent = await service.createIntent(ctx, ORDER);
    const started = await service.authenticationOptions(ctx, { intentId: intent.id, consent: true });
    const stranger = authenticator();
    await expect(service.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: stranger.assert(started.options.challenge), consent: true })).rejects.toEqual(refused("credential"));
  });

  describe("missing mandate (rogue agent)", () => {
    it("consume with no such mandate is refused", async () => {
      await expect(service.consume(ctx, { intentId: "9".repeat(64), consent: true })).rejects.toEqual(refused("intent"));
    });
    it("consume of a pending mandate the human never approved is refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused());
      expect((await intentRow(intent.id)).state).toBe("pending");
    });
    it("BUG: a rogue consume of a never-approved or revoked-pending mandate should be an intent refusal, not a 503 outage", async () => {
      // Refused either way (fail closed), but today it surfaces as code "unavailable" (HTTP 503) because
      // store.ts consumeIntent throws "integrity" for a null authorizedCredentialIdHash before checking state.
      const pending = await service.createIntent(ctx, ORDER);
      await expect(service.consume(ctx, { intentId: pending.id, consent: true })).rejects.toEqual(refused("intent"));
      const revoked = await service.createIntent(ctx, { ...ORDER, amountBaseUnits: "1999" });
      await service.revoke(ctx, { intentId: revoked.id, consent: true });
      await expect(service.consume(ctx, { intentId: revoked.id, consent: true })).rejects.toEqual(refused("intent"));
    });
    it("authorize without a server-issued ceremony is refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      await expect(service.authorize(ctx, { intentId: intent.id, ceremonyId: "8".repeat(64), response: device.assert(b64(randomBytes(32))), consent: true })).rejects.toEqual(refused("ceremony"));
    });
    it("no host session, or a different session, cannot consume", async () => {
      const intent = await authorizedIntent();
      await expect(service.consume({ owner: undefined, headers: { origin: ORIGIN } }, { intentId: intent.id, consent: true })).rejects.toEqual(refused("unauthenticated"));
      await expect(service.consume({ owner: { ...owner, sessionHash: "b".repeat(64) }, headers: { origin: ORIGIN } }, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
      expect((await intentRow(intent.id)).state).toBe("authorized");
    });
  });

  describe("revoked mandate", () => {
    it("revoked while pending: cannot be authorized or consumed", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      await service.revoke(ctx, { intentId: intent.id, consent: true });
      await expect(service.authenticationOptions(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused());
    });
    it("revoked after authorization: consume is refused", async () => {
      const intent = await authorizedIntent();
      await service.revoke(ctx, { intentId: intent.id, consent: true });
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
    });
    it("revoked mid-ceremony: finishing the passkey step is refused", async () => {
      const intent = await service.createIntent(ctx, ORDER);
      const { result } = await humanAuthorizes(intent.id);
      await service.revoke(ctx, { intentId: intent.id, consent: true });
      await expect(result()).rejects.toEqual(refused("intent"));
    });
    it("passkey credential revoked after authorization: consume is refused", async () => {
      const intent = await authorizedIntent();
      await service.revokeCredential(ctx, { credentialIdHash, consent: true });
      await expect(service.consume(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("credential"));
    });
    it("a consumed mandate cannot be revoked (no rewriting history)", async () => {
      const intent = await authorizedIntent();
      await service.consume(ctx, { intentId: intent.id, consent: true });
      await expect(service.revoke(ctx, { intentId: intent.id, consent: true })).rejects.toEqual(refused("intent"));
    });
  });

  describe("nonce reuse", () => {
    it("server refuses a second mandate that reuses an existing nonce (different amount)", async () => {
      const ids = ["1".repeat(64), "2".repeat(64), "1".repeat(64), "3".repeat(64)]; // service draws nonce then intent id: [nonce, id, reused nonce, id]
      let n = 0;
      const db = drizzle(pool, { schema: tpaSchema, mode: "default" });
      const svc = createTpaService({ store: createTpaStore(createMinimalOwnerAdapter(async () => db as never)), authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now: () => clock, randomId: () => ids[n++]!, legacyTransferMandates: true });
      await svc.createIntent(ctx, ORDER);
      await expect(svc.createIntent(ctx, { ...ORDER, amountBaseUnits: "2001" })).rejects.toEqual(refused("intent"));
      const [rows] = await pool.query("SELECT COUNT(*) AS n FROM tpa_intents"); expect(Number((rows as any[])[0].n)).toBe(1);
    });
    it("store refuses the identical mandate twice (per-owner hash uniqueness)", async () => {
      const db = drizzle(pool, { schema: tpaSchema, mode: "default" });
      const store = createTpaStore(createMinimalOwnerAdapter(async () => db as never));
      const issuedAt = Math.floor(T0 / 1000);
      const m: TpaMandate = { type: "TPA-mandate", version: "2.0", action: "transfer-authorization-pilot", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot", amountBaseUnits: "2000", recipient: "user:42", feeBaseUnits: "0", nonce: "c".repeat(64), issuedAt, expires: issuedAt + 300, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2" };
      await store.createIntent({ userId: 1, sessionHash: owner.sessionHash, origin: ORIGIN, id: "4".repeat(64), mandate: m, now: T0 });
      await expect(store.createIntent({ userId: 1, sessionHash: owner.sessionHash, origin: ORIGIN, id: "5".repeat(64), mandate: m, now: T0 })).rejects.toMatchObject({ kind: "intent" });
    });
  });
});
