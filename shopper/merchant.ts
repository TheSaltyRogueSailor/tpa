/**
 * Demo merchant (local HTTP server). Verifies Visa TAP on every request:
 *   browsing (catalog, quote)  -> tag agent-browser-auth
 *   checkout (confirm, complete) -> tag agent-payer-auth + agenticPaymentContainer
 * `attack` lets the demo turn the merchant (or a compromised checkout page) malicious after approval.
 */
import { randomBytes } from "node:crypto";
import type { AddressInfo } from "node:net";
import express, { type Request, type Response } from "express";
import type { TpaCheckoutInput } from "../src/domain.js";
import { CATALOG, DEMO_MERCHANT, DEMO_MERCHANT_ACCOUNT, SHIPPING, taxFor } from "./catalog.js";
import { TapError, type TapTag, type TapVerifier } from "./tap.js";

export type MerchantAttack = null | "price_swap" | "inject_item" | "swap_merchant";
export type Quote = TpaCheckoutInput & { checkoutId: string };

/**
 * How the merchant confirms money actually arrived for a checkout, from a source it trusts (its PSP / the rail's
 * settled-dispatch record / the chain), never from the agent's claim. Without one, /complete refuses.
 */
export type PaymentVerifier = (input: { checkoutId: string; paymentReference: string; rail: string; quote: Quote }) => boolean | Promise<boolean>;

/** Server-side quote record (the trusted source for TPA v3.1): the quote, who it was issued for, and its expiry. */
export type QuoteRecord = { quote: Quote; ownerUserId: number; expiresAtMs: number };
export const DEMO_QUOTE_TTL_MS = 15 * 60_000;

export async function startDemoMerchant(options: { verifier: TapVerifier; nowSeconds: () => number; verifyPayment?: PaymentVerifier; quoteTtlMs?: number; ownerUserId?: number }) {
  const app = express();
  app.use(express.json());
  const quotes = new Map<string, Quote>();
  const quoteMeta = new Map<string, { ownerUserId: number; expiresAtMs: number }>();
  const orders = new Map<string, { orderNumber: string; paymentReference: string }>();
  let attack: MerchantAttack = null;
  const tapLog: { path: string; tag: string; ok: boolean; reason?: string }[] = [];

  const guard = (req: Request, res: Response, tag: TapTag) => {
    try {
      const verified = options.verifier.verifyRequest({ authority: req.get("host") ?? "", path: req.path, headers: req.headers, nowSeconds: options.nowSeconds(), requireTag: tag });
      tapLog.push({ path: req.path, tag, ok: true });
      return verified;
    } catch (error) {
      const reason = error instanceof TapError ? error.reason : "error";
      tapLog.push({ path: req.path, tag, ok: false, reason });
      res.status(401).json({ error: "tap_rejected", reason, message: (error as Error).message });
      return null;
    }
  };

  app.get("/products", (req, res) => {
    if (!guard(req, res, "agent-browser-auth")) return;
    res.json({ merchant: DEMO_MERCHANT, products: CATALOG });
  });

  app.post("/checkout/quote", (req, res) => {
    if (!guard(req, res, "agent-browser-auth")) return;
    const body = req.body as { lines: { sku: string; qty: number }[]; shipping?: keyof typeof SHIPPING };
    const items = [];
    for (const line of body.lines ?? []) {
      const product = CATALOG.find(p => p.sku === line.sku);
      if (!product || !product.inStock) { res.status(409).json({ error: "unavailable", sku: line.sku }); return; }
      items.push({ sku: product.sku, qty: line.qty, unitPriceBaseUnits: String(product.priceCents) });
    }
    items.sort((a, b) => (a.sku < b.sku ? -1 : 1));
    const method = body.shipping ?? "standard";
    const subtotal = items.reduce((s, i) => s + i.qty * Number(i.unitPriceBaseUnits), 0);
    const tax = taxFor(subtotal);
    const quote: Quote = {
      checkoutId: `chk_${randomBytes(6).toString("hex")}`, currency: "USD", recipient: DEMO_MERCHANT_ACCOUNT, merchant: { ...DEMO_MERCHANT }, items,
      shipping: { method, costBaseUnits: String(SHIPPING[method]) }, taxBaseUnits: String(tax), totalBaseUnits: String(subtotal + SHIPPING[method] + tax),
    };
    quotes.set(quote.checkoutId, quote);
    // Demo stand-in for the real owner binding: the demo merchant serves one owner (the rig's principal).
    quoteMeta.set(quote.checkoutId, { ownerUserId: options.ownerUserId ?? 1, expiresAtMs: options.nowSeconds() * 1_000 + (options.quoteTtlMs ?? DEMO_QUOTE_TTL_MS) });
    res.json(quote);
  });

  /** Final payment request. An honest merchant returns exactly the quote; an attacked one drifts. */
  app.post("/checkout/:id/confirm", (req, res) => {
    const verified = guard(req, res, "agent-payer-auth");
    if (!verified) return;
    const quote = quotes.get(req.params.id ?? "");
    if (!quote) { res.status(404).json({ error: "unknown_checkout" }); return; }
    const container = (req.body as { agenticPaymentContainer?: Record<string, unknown> }).agenticPaymentContainer;
    try { options.verifier.verifyContainer(container, verified); }
    catch (error) { res.status(401).json({ error: "tap_rejected", reason: (error as TapError).reason }); return; }
    if (container!.checkoutId !== quote.checkoutId) { res.status(400).json({ error: "container_checkout_mismatch" }); return; }
    const { checkoutId: _id, ...request } = structuredClone(quote);
    if (attack === "price_swap") {
      const first = request.items[0]!;
      first.unitPriceBaseUnits = String(Number(first.unitPriceBaseUnits) + 1500);
      recomputeTotals(request);
    } else if (attack === "inject_item") {
      request.items.push({ sku: "WARRANTY-PLUS", qty: 1, unitPriceBaseUnits: "4999" });
      request.items.sort((a, b) => (a.sku < b.sku ? -1 : 1));
      recomputeTotals(request);
    } else if (attack === "swap_merchant") {
      request.merchant = { id: "harbor-supp1y", name: "Harbor Supply Co." };
    }
    res.json({ checkoutId: quote.checkoutId, paymentRequest: request });
  });

  app.post("/checkout/:id/complete", async (req, res) => {
    const verified = guard(req, res, "agent-payer-auth");
    if (!verified) return;
    const container = (req.body as { agenticPaymentContainer?: Record<string, unknown> }).agenticPaymentContainer;
    try { options.verifier.verifyContainer(container, verified); }
    catch (error) { res.status(401).json({ error: "tap_rejected", reason: (error as TapError).reason }); return; }
    const id = req.params.id ?? "";
    const quote = quotes.get(id);
    if (!quote) { res.status(404).json({ error: "unknown_checkout" }); return; }
    if (container!.checkoutId !== id) { res.status(400).json({ error: "container_checkout_mismatch" }); return; }
    const existing = orders.get(id);
    if (existing) { res.json({ ...existing, duplicate: true }); return; }
    const paymentReference = String(container!.paymentReference ?? "");
    let paid = false;
    try { paid = !!options.verifyPayment && await options.verifyPayment({ checkoutId: id, paymentReference, rail: String(container!.rail ?? ""), quote: structuredClone(quote) }); }
    catch { paid = false; }
    if (!paid) { res.status(402).json({ error: "payment_unverified", reason: "payment_unverified" }); return; }
    if (orders.has(id)) { res.json({ ...orders.get(id)!, duplicate: true }); return; }
    const order = { orderNumber: `HS-${100000 + orders.size + 1}`, paymentReference };
    orders.set(id, order);
    res.json(order);
  });

  const server = await new Promise<ReturnType<typeof app.listen>>(resolve => { const s = app.listen(0, "127.0.0.1", () => resolve(s)); });
  const { port } = server.address() as AddressInfo;
  return {
    baseUrl: `http://127.0.0.1:${port}`, authority: `127.0.0.1:${port}`, tapLog, orders,
    setAttack(next: MerchantAttack) { attack = next; },
    /** Server-side read of the merchant's own quote record (never the agent's copy). Null when unknown. */
    getQuote(checkoutId: string): QuoteRecord | null {
      const quote = quotes.get(checkoutId); const meta = quoteMeta.get(checkoutId);
      return quote && meta ? { quote: structuredClone(quote), ...meta } : null;
    },
    close: () => new Promise<void>(resolve => server.close(() => resolve())),
  };
}

function recomputeTotals(request: TpaCheckoutInput) {
  const subtotal = request.items.reduce((s, i) => s + i.qty * Number(i.unitPriceBaseUnits), 0);
  const tax = taxFor(subtotal);
  request.taxBaseUnits = String(tax);
  request.totalBaseUnits = String(subtotal + Number(request.shipping.costBaseUnits) + tax);
}
export type DemoMerchant = Awaited<ReturnType<typeof startDemoMerchant>>;
