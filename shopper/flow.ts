/**
 * TPA Shopper end to end: intent -> TAP-signed browsing -> cart -> TPA mandate (Ed25519) ->
 * owner passkey approval -> TAP-signed checkout -> TPA exact-match consume -> payment rail -> order.
 * Uses the REAL TPA service (src/service.ts) with the demo in-memory store, and a synthetic passkey.
 */
import { createPrivateKey, generateKeyPairSync, type KeyObject } from "node:crypto";
import { existsSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { dirname } from "node:path";
import { createTpaAuthority } from "../src/config.js";
import type { TpaCheckoutInput } from "../src/domain.js";
import { createTpaService, TpaServiceError } from "../src/service.js";
import { createTpaMandateSigner, tpaMandateSignerFromEnv } from "../src/signing.js";
import { syntheticAuthenticator } from "../tests/support/authenticator.js";
import { createMemoryTpaPersistence } from "../scripts/demo/memory-store.js";
import { planCart, type Plan, type ShoppingIntent } from "./agent.js";
import { DEMO_MERCHANT, DEMO_MERCHANT_METAL_ADDRESS, type Product } from "./catalog.js";
import { startDemoMerchant, type MerchantAttack, type Quote } from "./merchant.js";
import { createMetalUsdzAdapter, createMockAiriAdapter, PaymentRefused, type PaymentAdapter, type PaymentResult } from "./payments.js";
import { selectMetalClient } from "./metal.js";
import { createTapKeyDirectory, createTapSigner, createTapVerifier, type TapTag } from "./tap.js";

export const SHOPPER_PAYER_METAL_ADDRESS = "0x000000000000000000000000000000000000a11c";
const ORIGIN = "https://tpa-shopper.example.test";
const RP_ID = "tpa-shopper.example.test";

/** Agent TAP key: loaded from a local, gitignored PEM (created on first run), or ephemeral in tests. */
export function loadOrCreateAgentKey(path: string | undefined): KeyObject {
  if (!path) return generateKeyPairSync("ed25519").privateKey;
  if (existsSync(path)) return createPrivateKey(readFileSync(path, "utf8"));
  const { privateKey } = generateKeyPairSync("ed25519");
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, privateKey.export({ format: "pem", type: "pkcs8" }), { mode: 0o600 });
  return privateKey;
}

export type ShopEvent = { actor: "agent" | "merchant" | "tpa" | "owner" | "rail" | "attacker"; step: string; ok: boolean; detail: string };
export type ShopOutcome = {
  outcome: "PAID" | "BLOCKED"; blockedBy?: "tpa" | "tap" | "budget" | "rail"; reason?: string;
  plan?: Plan; quote?: Quote; intentId?: string; mandateHash?: string; payment?: PaymentResult; orderNumber?: string; events: ShopEvent[];
};
export type ShopOptions = ShoppingIntent & { rail?: "airwallex" | "metal"; merchantAttack?: MerchantAttack; ownerApproves?: boolean };

/**
 * metal: "auto" (default) uses the real alta-testnet client only when METAL_LIVE=1 and credentials are present,
 * otherwise the mock; "mock" always uses the mock (tests).
 */
export async function createShopperRig(options: { agentKeyPath?: string; metal?: "auto" | "mock"; env?: NodeJS.ProcessEnv } = {}) {
  const owner = { principalId: 1, sessionHash: "a".repeat(64), owner: true as const };
  const ctx = { owner, headers: { origin: ORIGIN } };
  const now = () => Date.now();
  const nowSeconds = () => Math.floor(now() / 1000);
  const memory = createMemoryTpaPersistence({ ownerIds: [owner.principalId] });
  const signer = tpaMandateSignerFromEnv() ?? createTpaMandateSigner({ activeKeyId: "tpa-shopper-demo", privateKey: generateKeyPairSync("ed25519").privateKey });
  const service = createTpaService({ store: memory.store, evidence: memory.evidence, signer, authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now });
  const phone = syntheticAuthenticator(ORIGIN, RP_ID);
  const reg = await service.registrationOptions(ctx, { label: "Owner's phone", consent: true });
  await service.registrationVerify(ctx, { ceremonyId: reg.ceremonyId, response: phone.register(reg.options.challenge) });

  // Visa TAP: the agent's key is published in a (local stand-in for the) scheme key directory.
  const agentTap = createTapSigner(loadOrCreateAgentKey(options.agentKeyPath));
  const keyDirectory = createTapKeyDirectory([agentTap.jwk]);
  const merchant = await startDemoMerchant({ verifier: createTapVerifier(keyDirectory), nowSeconds });
  const env = options.env ?? process.env;
  const metalSelection = selectMetalClient({ env: options.metal === "mock" ? {} : env, mockPayer: SHOPPER_PAYER_METAL_ADDRESS, mockBalance: 500n * 10n ** 18n });
  const metal = metalSelection.client;
  const merchantMetalAddress = (metalSelection.live && env.METAL_MERCHANT_ADDRESS) || DEMO_MERCHANT_METAL_ADDRESS;
  const rails: Record<"airwallex" | "metal", PaymentAdapter> = {
    airwallex: createMockAiriAdapter(),
    // TPA checks (Proof of Person via passkey, Presence via TAP, Permission via mandate consume) all run before rail.pay().
    metal: createMetalUsdzAdapter(metal, metalSelection.payer, { [DEMO_MERCHANT.id]: merchantMetalAddress }),
  };

  /** Every agent -> merchant request is TAP-signed; checkout calls also carry a signed payment container. */
  async function tapRequest(method: "GET" | "POST", path: string, tag: TapTag, body?: Record<string, unknown>, container?: Record<string, unknown>) {
    const signed = agentTap.signRequest({ authority: merchant.authority, path, tag, nowSeconds: nowSeconds() });
    const payload = container ? { ...body, agenticPaymentContainer: agentTap.signContainer(signed.nonce, container) } : body;
    const res = await fetch(`${merchant.baseUrl}${path}`, { method, headers: { ...signed.headers, ...(payload ? { "content-type": "application/json" } : {}) }, body: payload ? JSON.stringify(payload) : undefined });
    return { status: res.status, json: await res.json() as Record<string, unknown>, headers: signed.headers, body: payload };
  }

  async function shop(opts: ShopOptions): Promise<ShopOutcome> {
    const events: ShopEvent[] = [];
    const log = (e: ShopEvent) => { events.push(e); };
    const blocked = (blockedBy: ShopOutcome["blockedBy"], reason: string, extra: Partial<ShopOutcome> = {}): ShopOutcome => ({ outcome: "BLOCKED", blockedBy, reason, events, ...extra });

    const browse = await tapRequest("GET", "/products", "agent-browser-auth");
    log({ actor: "merchant", step: "TAP verify browse (agent-browser-auth)", ok: browse.status === 200, detail: `GET /products -> ${browse.status}, keyid ${agentTap.keyId.slice(0, 12)}...` });
    if (browse.status !== 200) return blocked("tap", String(browse.json.reason));
    const plan = planCart(opts, browse.json.products as Product[]);
    log({ actor: "agent", step: "plan cart", ok: plan.lines.length > 0, detail: `${plan.lines.map(l => l.sku).join(", ")} (est. $${(plan.estimatedTotalCents / 100).toFixed(2)} of $${(opts.budgetCents / 100).toFixed(2)} budget)` });
    if (!plan.lines.length) return blocked("budget", "nothing_fits_budget", { plan });

    const quoted = await tapRequest("POST", "/checkout/quote", "agent-browser-auth", { lines: plan.lines.map(l => ({ sku: l.sku, qty: l.qty })), shipping: opts.shipping ?? "standard" });
    if (quoted.status !== 200) return blocked("tap", String(quoted.json.reason ?? quoted.json.error), { plan });
    const quote = quoted.json as unknown as Quote;
    log({ actor: "merchant", step: "quote", ok: true, detail: `${quote.checkoutId}: total $${(Number(quote.totalBaseUnits) / 100).toFixed(2)} incl. shipping $${(Number(quote.shipping.costBaseUnits) / 100).toFixed(2)} + tax $${(Number(quote.taxBaseUnits) / 100).toFixed(2)}` });
    if (Number(quote.totalBaseUnits) > opts.budgetCents) { log({ actor: "agent", step: "budget guard", ok: false, detail: "quote exceeds budget, not asking for approval" }); return blocked("budget", "over_budget", { plan, quote }); }

    const { checkoutId, ...cart } = quote;
    const intent = await service.createIntent(ctx, { ...cart, consent: true });
    log({ actor: "tpa", step: "mandate 3.0 created + Ed25519 signed", ok: true, detail: `mandate ${intent.mandateHash.slice(0, 16)}... binds merchant, ${cart.items.length} items, shipping, tax, total` });

    if (opts.ownerApproves !== false) {
      const started = await service.authenticationOptions(ctx, { intentId: intent.id, consent: true });
      await service.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: phone.assert(started.options.challenge), consent: true });
      log({ actor: "owner", step: "passkey approval", ok: true, detail: "owner approved the exact mandate (challenge bound to mandate hash)" });
    } else {
      log({ actor: "agent", step: "skip approval", ok: false, detail: "agent tries to pay without the owner's passkey approval" });
    }

    const container = { checkoutId, tpaMandateHash: intent.mandateHash, amountBaseUnits: cart.totalBaseUnits, currency: cart.currency };
    const confirmed = await tapRequest("POST", `/checkout/${checkoutId}/confirm`, "agent-payer-auth", {}, container);
    log({ actor: "merchant", step: "TAP verify checkout (agent-payer-auth + payment container)", ok: confirmed.status === 200, detail: `POST /checkout/${checkoutId}/confirm -> ${confirmed.status}` });
    if (confirmed.status !== 200) return blocked("tap", String(confirmed.json.reason ?? confirmed.json.error), { plan, quote });
    const paymentRequest = confirmed.json.paymentRequest as TpaCheckoutInput;

    let consumed;
    try { consumed = await service.consume(ctx, { intentId: intent.id, consent: true, checkout: paymentRequest }); }
    catch (error) {
      const code = error instanceof TpaServiceError ? (error.reason ? `${error.code}:${error.reason}` : error.code) : String(error);
      log({ actor: "tpa", step: "exact-match check at consume", ok: false, detail: `BLOCKED ${code}; no money moved` });
      return blocked("tpa", code, { plan, quote, intentId: intent.id, mandateHash: intent.mandateHash });
    }
    log({ actor: "tpa", step: "exact-match check at consume", ok: true, detail: "merchant payment request matches the approved mandate; mandate consumed (single use)" });

    const rail = rails[opts.rail ?? "airwallex"];
    let payment: PaymentResult;
    try {
      payment = await rail.pay({ receipt: { consumed: consumed.consumed, intentId: intent.id, mandateHash: intent.mandateHash }, merchant: cart.merchant, currency: "USD", amountBaseUnits: cart.totalBaseUnits, checkoutId });
    } catch (error) {
      return blocked("rail", error instanceof PaymentRefused ? error.reason : String(error), { plan, quote, intentId: intent.id });
    }
    log({ actor: "rail", step: `pay via ${rail.rail} (${rail.mode})`, ok: true, detail: `reference ${payment.reference.slice(0, 26)}` });

    const done = await tapRequest("POST", `/checkout/${checkoutId}/complete`, "agent-payer-auth", {}, { checkoutId, paymentReference: payment.reference, rail: rail.rail });
    log({ actor: "merchant", step: "order confirmed", ok: done.status === 200, detail: `order ${String(done.json.orderNumber)}` });
    return { outcome: "PAID", events, plan, quote, intentId: intent.id, mandateHash: intent.mandateHash, payment, orderNumber: String(done.json.orderNumber) };
  }

  /** An attacker who captured a valid agent-payer-auth request replays it verbatim to the merchant. */
  async function replayCapturedCheckout() {
    const shopped = await tapRequest("POST", "/checkout/quote", "agent-browser-auth", { lines: [{ sku: "FILTER-100", qty: 1 }] });
    const quote = shopped.json as unknown as Quote;
    const first = await tapRequest("POST", `/checkout/${quote.checkoutId}/confirm`, "agent-payer-auth", {}, { checkoutId: quote.checkoutId, tpaMandateHash: "0".repeat(64), amountBaseUnits: quote.totalBaseUnits, currency: "USD" });
    const replay = await fetch(`${merchant.baseUrl}/checkout/${quote.checkoutId}/confirm`, { method: "POST", headers: { ...first.headers, "content-type": "application/json" }, body: JSON.stringify(first.body) });
    const unsigned = await fetch(`${merchant.baseUrl}/checkout/${quote.checkoutId}/confirm`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    return { firstStatus: first.status, replay: { status: replay.status, ...(await replay.json() as { reason?: string }) }, unsigned: { status: unsigned.status, ...(await unsigned.json() as { reason?: string }) } };
  }

  return { shop, replayCapturedCheckout, service, ctx, merchant, rails, metal, metalSelection: { live: metalSelection.live, payer: metalSelection.payer, reason: metalSelection.reason }, agentTap, auditLog: (intentId?: string) => service.auditLog(ctx, { intentId, limit: 50 }), close: () => merchant.close() };
}
export type ShopperRig = Awaited<ReturnType<typeof createShopperRig>>;
