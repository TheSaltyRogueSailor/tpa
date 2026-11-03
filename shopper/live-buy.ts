/**
 * One REAL Airi purchase, end to end, for a merchant in config/airi-live.json (pnpm airi:buy -- --merchant <id>):
 *
 *   caps (per-buy cap, run total cap over the journal, no repeat buy) -> TPA v3.1 bound mandate for the exact
 *   checkout (item, tax, total, merchant, Airi target) -> TPA owner approval -> exact-match consume ->
 *   createAiriCliAdapter: whoami, payment method listed, mandate create (owner approves with the Airi passkey),
 *   get-credential --file (0600 temp file) -> MANUAL CHECKOUT HANDOFF (shopper/handoff.ts: a separate operator /
 *   GUI agent fills the merchant form and signals the order id) -> file deleted -> mandate result.
 *
 * The dispatch ledger is the locked file journal artifacts/airi-dispatch-journal.json (one mandate per TPA intent,
 * restart-safe). A one-line summary per run (no card data) is appended to artifacts/airi-buy-log.jsonl.
 *
 * Standalone-pilot limit, stated plainly: the TPA service here uses the in-memory demo persistence and the synthetic
 * passkey (as in pnpm demo:shopper). The human approval that gates real money is the Airi passkey on the mandate.
 */
import { generateKeyPairSync } from "node:crypto";
import { appendFileSync, existsSync, mkdirSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { z } from "zod";
import { createTpaAuthority } from "../src/config.js";
import type { TpaCheckoutInput } from "../src/domain.js";
import { createTpaService, TpaServiceError, type TpaQuoteResolver } from "../src/service.js";
import { createTpaMandateSigner, tpaMandateSignerFromEnv } from "../src/signing.js";
import { syntheticAuthenticator } from "../tests/support/authenticator.js";
import { createMemoryTpaPersistence } from "../scripts/demo/memory-store.js";
import type { AiriClient } from "./airi.js";
import {
  PaymentRefused, combineTargetResolvers, createAiriCliAdapter, createAiriMerchantResolver, createDispatchLedger, createFileDispatchStore,
  type AiriApprovalNotice, type AiriCheckoutSubmitter, type PaymentResult,
} from "./payments.js";

const cents = z.number().int().nonnegative().max(100_000);
const merchantSchema = z.object({
  name: z.string().min(1).max(120).regex(/^[^\u0000-\u001f\u007f-]/),
  url: z.string().regex(/^https:\/\/[^\s]+$/),
  checkoutUrl: z.string().regex(/^https:\/\/[^\s]+$/),
  country: z.string().regex(/^[A-Z]{2}$/),
  recipient: z.string().regex(/^user:[1-9][0-9]{0,9}$/),
  item: z.object({ sku: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,63}$/), name: z.string().min(1).max(120), priceCents: cents.min(1) }).strict(),
  expectedTaxCents: cents,
  capCents: cents.min(1),
  notes: z.string().max(500).optional(),
}).strict();
export const airiLiveConfigSchema = z.object({
  $comment: z.string().optional(),
  version: z.literal(1),
  source: z.string().min(1).max(64),
  paymentMethodId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/),
  paymentMethodLabel: z.string().max(64).optional(),
  runTotalCapCents: cents.min(1),
  handoffTimeoutMinutes: z.number().positive().max(120),
  approvalTimeoutSeconds: z.number().int().positive().max(900),
  merchants: z.record(z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$/), merchantSchema),
}).strict();
export type AiriLiveFileConfig = z.infer<typeof airiLiveConfigSchema>;
export type AiriLiveMerchant = z.infer<typeof merchantSchema>;

/** Load and validate config/airi-live.json (or AIRI_LIVE_CONFIG). AIRI_PAYMENT_METHOD_ID overrides the payment method. */
export function loadAiriLiveConfig(env: NodeJS.ProcessEnv = process.env, path = env.AIRI_LIVE_CONFIG ?? "config/airi-live.json"): AiriLiveFileConfig {
  let raw: unknown;
  try { raw = JSON.parse(readFileSync(resolve(path), "utf8")); } catch { throw new PaymentRefused("airi_misconfigured", `Airi live config ${path} is missing or not JSON.`); }
  const parsed = airiLiveConfigSchema.safeParse(raw);
  if (!parsed.success) throw new PaymentRefused("airi_misconfigured", `Airi live config ${path} is invalid: ${parsed.error.issues.map(i => i.path.join(".")).join(", ")}.`);
  const config = parsed.data;
  if (env.AIRI_PAYMENT_METHOD_ID) {
    if (!/^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/.test(env.AIRI_PAYMENT_METHOD_ID)) throw new PaymentRefused("airi_misconfigured", "AIRI_PAYMENT_METHOD_ID is not a valid id.");
    config.paymentMethodId = env.AIRI_PAYMENT_METHOD_ID;
  }
  return config;
}

/** Sum of Airi dispatches already reserved, sent or settled in the journal (conservative: a cancelled mandate still counts). */
export function journalSpend(journalPath: string): { totalCents: number; rows: { merchantId: string; status: string; amountCents: number; reference?: string }[] } {
  if (!existsSync(journalPath)) return { totalCents: 0, rows: [] };
  let rows: unknown;
  try { rows = JSON.parse(readFileSync(journalPath, "utf8")); } catch { throw new PaymentRefused("dispatch_store_unavailable", "Dispatch journal is unreadable; refusing to check the run cap."); }
  if (!Array.isArray(rows)) throw new PaymentRefused("dispatch_store_unavailable", "Dispatch journal is malformed; refusing to check the run cap.");
  const out = rows.flatMap(r => (r && r.rail === "airwallex-airi" ? [{ merchantId: String(r.merchantId), status: String(r.status), amountCents: Number(r.amountBaseUnits), ...(r.txHash ? { reference: String(r.txHash) } : {}) }] : []));
  return { totalCents: out.reduce((t, r) => t + r.amountCents, 0), rows: out };
}

export type AiriBuyPlan = {
  merchantId: string; merchant: AiriLiveMerchant; priceCents: number; taxCents: number; totalCents: number; capCents: number;
  spentCents: number; runTotalCapCents: number; paymentMethodId: string; checkout: TpaCheckoutInput;
};
const usd = (c: number) => `$${(c / 100).toFixed(2)}`;
/** All cap checks, before anything else (no airi-cli call, no TPA intent). Throws PaymentRefused on any breach. */
export function planAiriBuy(config: AiriLiveFileConfig, merchantId: string, journalPath: string, over: { priceCents?: number; taxCents?: number; allowRepeat?: boolean } = {}): AiriBuyPlan {
  const merchant = Object.prototype.hasOwnProperty.call(config.merchants, merchantId) ? config.merchants[merchantId] : undefined;
  if (!merchant) throw new PaymentRefused("airi_merchant_not_allowed", `Merchant "${merchantId}" is not in the Airi allowlist (${Object.keys(config.merchants).join(", ")}).`);
  const priceCents = over.priceCents ?? merchant.item.priceCents;
  const taxCents = over.taxCents ?? merchant.expectedTaxCents;
  if (!Number.isInteger(priceCents) || priceCents < merchant.item.priceCents) throw new PaymentRefused("airi_price_invalid", `Price must be a whole number of cents and at least ${usd(merchant.item.priceCents)}.`);
  if (!Number.isInteger(taxCents) || taxCents < 0) throw new PaymentRefused("airi_price_invalid", "Tax must be a whole, non-negative number of cents.");
  const totalCents = priceCents + taxCents;
  if (totalCents > merchant.capCents) throw new PaymentRefused("airi_buy_cap", `${usd(totalCents)} exceeds the ${merchantId} per-buy cap of ${usd(merchant.capCents)}.`);
  const spent = journalSpend(journalPath);
  if (spent.totalCents + totalCents > config.runTotalCapCents) throw new PaymentRefused("airi_run_cap", `${usd(spent.totalCents)} already dispatched + ${usd(totalCents)} exceeds the run total cap of ${usd(config.runTotalCapCents)}.`);
  if (!over.allowRepeat && spent.rows.some(r => r.merchantId === merchantId && (r.status === "succeeded" || r.status === "sent" || r.status === "reserved"))) {
    throw new PaymentRefused("airi_repeat_buy", `The journal already has an Airi dispatch for ${merchantId}; refusing a second buy (pass --allow-repeat only if the first was cancelled and confirmed unpaid).`);
  }
  const checkout: TpaCheckoutInput = {
    currency: "USD", recipient: merchant.recipient, merchant: { id: merchantId, name: merchant.name },
    items: [{ sku: merchant.item.sku, qty: 1, unitPriceBaseUnits: String(priceCents) }], shipping: { method: "digital", costBaseUnits: "0" },
    taxBaseUnits: String(taxCents), totalBaseUnits: String(totalCents),
  };
  return { merchantId, merchant, priceCents, taxCents, totalCents, capCents: merchant.capCents, spentCents: spent.totalCents, runTotalCapCents: config.runTotalCapCents, paymentMethodId: config.paymentMethodId, checkout };
}

export type AiriBuyOutcome = { status: "PAID" | "REFUSED"; reason?: string; message?: string; plan: AiriBuyPlan; intentId?: string; mandateHash?: string; payment?: PaymentResult };
const ORIGIN = "https://tpa-shopper.example.test";
const RP_ID = "tpa-shopper.example.test";

/** Run one buy. The submitter is the manual handoff in production; tests inject the fake airi-cli client and a scripted signal. */
export async function runAiriBuy(options: {
  config: AiriLiveFileConfig; merchantId: string; client: AiriClient; submitCheckout: AiriCheckoutSubmitter;
  journalPath?: string; logPath?: string; priceCents?: number; taxCents?: number; allowRepeat?: boolean;
  print?: (line: string) => void; onApprovalRequested?: (notice: AiriApprovalNotice) => void | Promise<void>; now?: () => number;
}): Promise<AiriBuyOutcome> {
  const journalPath = options.journalPath ?? "artifacts/airi-dispatch-journal.json";
  const logPath = options.logPath ?? "artifacts/airi-buy-log.jsonl";
  const print = options.print ?? (line => process.stdout.write(`${line}\n`));
  const now = options.now ?? Date.now;
  const plan = planAiriBuy(options.config, options.merchantId, journalPath, options);
  const log = (entry: Record<string, unknown>) => {
    mkdirSync(dirname(resolve(logPath)), { recursive: true });
    appendFileSync(logPath, `${JSON.stringify({ at: new Date(now()).toISOString(), merchantId: plan.merchantId, totalCents: plan.totalCents, ...entry })}\n`, { mode: 0o600 });
  };
  print(`Airi buy: ${plan.merchant.name} [${plan.merchantId}] ${plan.merchant.item.name} ${usd(plan.priceCents)} + tax ${usd(plan.taxCents)} = ${usd(plan.totalCents)} (cap ${usd(plan.capCents)}; run ${usd(plan.spentCents)} of ${usd(plan.runTotalCapCents)} used)`);

  const owner = { principalId: 1, sessionHash: "b".repeat(64), owner: true as const };
  const ctx = { owner, headers: { origin: ORIGIN } };
  const memory = createMemoryTpaPersistence({ ownerIds: [owner.principalId] });
  const signer = tpaMandateSignerFromEnv() ?? createTpaMandateSigner({ activeKeyId: "tpa-airi-live", privateKey: generateKeyPairSync("ed25519").privateKey });
  const quoteId = `q_${plan.merchantId}_${now().toString(36)}`;
  const quotes: TpaQuoteResolver = {
    async resolve({ merchantId, quoteId: id }) {
      return merchantId === plan.merchantId && id === quoteId ? { merchantId, quoteId, ownerUserId: owner.principalId, checkout: structuredClone(plan.checkout), expiresAtMs: now() + 15 * 60_000 } : null;
    },
  };
  const directory = { [plan.merchantId]: { url: plan.merchant.url, country: plan.merchant.country } };
  const service = createTpaService({ store: memory.store, evidence: memory.evidence, signer, authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now,
    quotes, targets: combineTargetResolvers(createAiriMerchantResolver(directory)) });
  const phone = syntheticAuthenticator(ORIGIN, RP_ID);
  const reg = await service.registrationOptions(ctx, { label: "Owner (synthetic, standalone pilot)", consent: true });
  await service.registrationVerify(ctx, { ceremonyId: reg.ceremonyId, response: phone.register(reg.options.challenge) });

  let intentId: string | undefined; let mandateHash: string | undefined;
  try {
    const intent = await service.createIntent(ctx, { merchantId: plan.merchantId, quoteId, rail: "airwallex-airi", checkout: structuredClone(plan.checkout), consent: true });
    intentId = intent.id; mandateHash = intent.mandateHash;
    print(`  TPA mandate 3.1 ${intent.mandateHash.slice(0, 16)}... binds ${plan.merchantId}, ${plan.merchant.item.sku}, tax, total ${usd(plan.totalCents)}, payee awx-airi-merchant:${plan.merchantId}`);
    const started = await service.authenticationOptions(ctx, { intentId: intent.id, consent: true });
    await service.authorize(ctx, { intentId: intent.id, ceremonyId: started.ceremonyId, response: phone.assert(started.options.challenge), consent: true });
    const consumed = await service.consume(ctx, { intentId: intent.id, consent: true, checkout: structuredClone(plan.checkout), quoteId });
    const ledger = createDispatchLedger({ store: createFileDispatchStore(journalPath), lookupIntent: id => service.readSignedIntent(ctx, { intentId: id }), now });
    const adapter = createAiriCliAdapter(ledger, {
      client: options.client, paymentMethodId: plan.paymentMethodId, source: options.config.source, merchants: directory,
      submitCheckout: options.submitCheckout, approvalTimeoutSeconds: options.config.approvalTimeoutSeconds,
      itemName: sku => (sku === plan.merchant.item.sku ? plan.merchant.item.name : undefined),
      onApprovalRequested: options.onApprovalRequested ?? (n => {
        print(`  Airi mandate ${n.mandateId} created for ${n.merchant} ${n.currency} ${n.amount} on ${n.card}.`);
        print(`  OWNER: approve it with your passkey${n.passkeyUrl ? ` at ${n.passkeyUrl}` : " in the Airi app"} (waiting up to ${options.config.approvalTimeoutSeconds}s).`);
      }),
    });
    const payment = await adapter.pay({ receipt: { consumed: consumed.consumed, intentId: consumed.intent.id, mandateHash: consumed.intent.mandateHash }, checkoutId: quoteId, checkout: structuredClone(plan.checkout) });
    log({ status: "PAID", intentId, mandateId: payment.reference, merchantOrderId: payment.detail.merchantOrderId, card: payment.detail.oneTimeCard ?? payment.detail.card, airiResultReported: payment.detail.airiResultReported });
    print(`  PAID: Airi mandate ${payment.reference}, merchant order ${payment.detail.merchantOrderId ?? "?"}, result reported to Airi: ${payment.detail.airiResultReported}`);
    return { status: "PAID", plan, intentId, mandateHash, payment };
  } catch (error) {
    const reason = error instanceof PaymentRefused ? error.reason : error instanceof TpaServiceError ? `tpa_${error.code}` : "error";
    const message = error instanceof Error ? error.message : String(error);
    log({ status: "REFUSED", reason, intentId });
    print(`  REFUSED (${reason}): ${message}`);
    return { status: "REFUSED", reason, message, plan, ...(intentId ? { intentId } : {}), ...(mandateHash ? { mandateHash } : {}) };
  }
}
