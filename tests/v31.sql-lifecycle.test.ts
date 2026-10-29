/**
 * v3.1 real-SQL lifecycle with a mock rail. Opt-in: TPA_TEST_DATABASE_URL must point at a DISPOSABLE schema; the
 * suite drops and recreates the tpa_* tables and tpa_payment_dispatches (0002 then 0003) before every test.
 * The first three cases are adopted from Michael's independent 1461e69 review (tests/v31.review-sql.test.ts), with
 * only this header changed; the fourth adds the post-markSent freshness guard on the real SQL dispatch store.
 * Synthetic Ed25519 key generated in memory, synthetic passkey, mock Metal client: no provider, chain or network.
 */
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { drizzle } from "drizzle-orm/mysql2";
import mysql from "mysql2/promise";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { createTpaAuthority } from "../src/config.js";
import { createTpaDispatchStore } from "../src/dispatch.js";
import { createTpaEvidenceStore } from "../src/evidence.js";
import { createMinimalOwnerAdapter } from "../src/host/minimal-owner.js";
import { tpaSchema } from "../src/schema.js";
import { createTpaService } from "../src/service.js";
import { createTpaMandateSigner } from "../src/signing.js";
import { createTpaStore } from "../src/store.js";
import { combineTargetResolvers, createDispatchLedger, createMetalTargetResolver, createMetalUsdzAdapter, createMockMetalClient } from "../shopper/payments.js";
import { syntheticAuthenticator } from "./support/authenticator.js";
import { PAYEE, PAYER, ONE_DOLLAR_USDZ, reviewCheckout } from "./support/dispatch.js";
import { resetTpaSchema } from "./support/schema.js";

const URL = process.env.TPA_TEST_DATABASE_URL;
const ORIGIN = "https://tpa.example.test", RP_ID = "tpa.example.test";
const clock = 1_800_000_000_000;
const ctx = { owner: { principalId: 1, sessionHash: "a".repeat(64), owner: true as const }, headers: { origin: ORIGIN } };
const checkout = reviewCheckout();
let pool: mysql.Pool;
let failConsumedAudit = false;

async function fixture() {
  const host = createMinimalOwnerAdapter(async () => drizzle(pool, { schema: tpaSchema, mode: "default" }) as never);
  const originalEvidence = createTpaEvidenceStore(host);
  const evidence = { ...originalEvidence, audit: async (event: Parameters<typeof originalEvidence.audit>[0]) => {
    if (failConsumedAudit && event.action === "consumed") throw new Error("synthetic audit outage");
    return originalEvidence.audit(event);
  } };
  const service = createTpaService({
    store: createTpaStore(host), evidence,
    authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now: () => clock,
    signer: createTpaMandateSigner({ activeKeyId: "independent-sql-review", privateKey: generateKeyPairSync("ed25519").privateKey }),
    quotes: { resolve: async ({ ownerUserId, merchantId, quoteId }) => ownerUserId === 1 && merchantId === checkout.merchant.id && quoteId === "q-independent-sql"
      ? { ownerUserId, merchantId, quoteId, checkout: structuredClone(checkout), expiresAtMs: clock + 900_000 } : null },
    targets: combineTargetResolvers(createMetalTargetResolver({ [checkout.merchant.id]: PAYEE })),
  });
  const phone = syntheticAuthenticator(ORIGIN, RP_ID);
  const registration = await service.registrationOptions(ctx, { label: "Synthetic test authenticator", consent: true });
  await service.registrationVerify(ctx, { ceremonyId: registration.ceremonyId, response: phone.register(registration.options.challenge) });
  const intent = await service.createIntent(ctx, { merchantId: checkout.merchant.id, quoteId: "q-independent-sql", rail: "metal-usdz", consent: true });
  const auth = await service.authenticationOptions(ctx, { intentId: intent.id, consent: true });
  await service.authorize(ctx, { intentId: intent.id, ceremonyId: auth.ceremonyId, response: phone.assert(auth.options.challenge), consent: true });
  const consume = (actual = checkout) => service.consume(ctx, { intentId: intent.id, checkout: actual, quoteId: "q-independent-sql", consent: true });
  return { service, host, intent, consume };
}

describe.skipIf(!URL)("v3.1 real-SQL lifecycle plus mock rail", () => {
  beforeAll(async () => { pool = mysql.createPool({ uri: URL!, connectionLimit: 8 }); });
  afterAll(async () => { await pool?.end(); });
  beforeEach(async () => {
    failConsumedAudit = false;
    await resetTpaSchema(pool);
    await pool.query("DROP TABLE IF EXISTS tpa_payment_dispatches");
    for (const name of ["0002_tpa_payment_dispatches.sql", "0003_tpa_checkout_binding.sql"]) {
      const ddl = readFileSync(`migrations/${name}`, "utf8").replace(/^--.*$/gm, "");
      for (const statement of ddl.split(";").map(s => s.trim()).filter(Boolean)) await pool.query(statement);
    }
  });

  it("actual v3.1 signature/passkey/consume is one-use under SQL locks, then exact mock dispatch is durable and one-use", async () => {
    const { service, host, intent, consume } = await fixture();
    expect(intent.mandate.version).toBe("3.1");
    expect("serverSignature" in intent && intent.serverSignature.valid).toBe(true);
    const uses = await Promise.allSettled([consume(), consume()]);
    expect(uses.filter(s => s.status === "fulfilled")).toHaveLength(1);
    expect(uses.filter(s => s.status === "rejected")).toHaveLength(1);
    const store = createTpaDispatchStore(host);
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const transfer = vi.spyOn(client, "transfer");
    const ledger = createDispatchLedger({ store, lookupIntent: id => service.readSignedIntent(ctx, { intentId: id }), now: () => clock });
    const rail = createMetalUsdzAdapter(client, PAYER, ledger);
    const request = { receipt: { consumed: true as const, intentId: intent.id, mandateHash: intent.mandateHash }, checkoutId: "q-independent-sql", checkout };
    const results = await Promise.all([rail.pay(request), rail.pay(structuredClone(request)), rail.pay(structuredClone(request))]);
    expect(new Set(results.map(r => r.reference)).size).toBe(1);
    expect(transfer).toHaveBeenCalledTimes(1);
    expect(await client.balanceOf(PAYEE)).toBe(ONE_DOLLAR_USDZ);
    expect(await store.get(intent.id)).toMatchObject({ status: "succeeded", mandateHash: intent.mandateHash, checkoutFingerprint: (intent.mandate as { checkoutFingerprint: string }).checkoutFingerprint });
    const audit = await service.auditLog(ctx, { intentId: intent.id });
    expect(audit.filter(e => e.action === "consumed" && e.outcome === "approved")).toHaveLength(1);
    expect(audit.some(e => e.action === "authorized" && e.outcome === "approved")).toBe(true);
  });

  it("same-total item substitution refuses at the locked SQL consume boundary without burning the authorized intent", async () => {
    const { service, intent, consume } = await fixture();
    const changed = { ...checkout, items: [{ ...checkout.items[0]!, sku: "SWAPPED-SKU" }] };
    await expect(consume(changed)).rejects.toMatchObject({ code: "terms_changed", reason: "items_mismatch" });
    expect((await service.readSignedIntent(ctx, { intentId: intent.id }))?.state).toBe("authorized");
    await expect(consume()).resolves.toMatchObject({ consumed: true });
    const audit = await service.auditLog(ctx, { intentId: intent.id });
    expect(audit.some(e => e.outcome === "refused" && e.reasonCode === "terms_changed:items_mismatch")).toBe(true);
  });

  it("v3.1 consume and success audit roll back together on an actual SQL transaction", async () => {
    const { service, intent, consume } = await fixture();
    failConsumedAudit = true;
    await expect(consume()).rejects.toMatchObject({ code: "unavailable" });
    expect((await service.readSignedIntent(ctx, { intentId: intent.id }))?.state).toBe("authorized");
    const before = await service.auditLog(ctx, { intentId: intent.id });
    expect(before.some(e => e.action === "consumed" && e.outcome === "approved")).toBe(false);
    failConsumedAudit = false;
    await expect(consume()).resolves.toMatchObject({ consumed: true });
  });

  it("expiry crossing the SQL markSent write: the row stays sent in MySQL, nothing is sent, a retry stays read-only", async () => {
    const { service, host, intent, consume } = await fixture();
    await consume();
    const inner = createTpaDispatchStore(host);
    let at = clock;
    const expires = (intent.mandate as { expires: number }).expires;
    const store = { ...inner, markSent: async (id: string, hash: string, when: number) => { const ok = await inner.markSent(id, hash, when); at = (expires + 1) * 1000; return ok; } };
    const client = createMockMetalClient({ [PAYER]: 10n * ONE_DOLLAR_USDZ });
    const lookupIntent = (id: string) => service.readSignedIntent(ctx, { intentId: id });
    const request = { receipt: { consumed: true as const, intentId: intent.id, mandateHash: intent.mandateHash }, checkoutId: "q-independent-sql", checkout };
    await expect(createMetalUsdzAdapter(client, PAYER, createDispatchLedger({ store, lookupIntent, now: () => at })).pay(request)).rejects.toMatchObject({ reason: "approval_expired" });
    expect(await inner.get(intent.id)).toMatchObject({ status: "sent", txHash: client.signatures[0] });
    expect(await client.balanceOf(PAYEE)).toBe(0n);
    const restarted = createDispatchLedger({ store: createTpaDispatchStore(host), lookupIntent, now: () => clock });
    await expect(createMetalUsdzAdapter(client, PAYER, restarted).pay(structuredClone(request))).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(client.signatures).toHaveLength(1);
    expect(await client.balanceOf(PAYEE)).toBe(0n);
  });
});
