/**
 * The shopping agent's planner. Deterministic on purpose (hackathon guide: keep amounts, limits and
 * validation in code; let a model read text and propose). An LLM can replace `scoreProducts` to rank
 * products from free text, but the budget arithmetic below stays in code.
 */
import { SHIPPING, taxFor, type Product } from "./catalog.js";

export type ShoppingIntent = { text: string; budgetCents: number; shipping?: keyof typeof SHIPPING };
export type PlannedLine = { sku: string; qty: number; name: string; priceCents: number };
export type Plan = { lines: PlannedLine[]; estimatedTotalCents: number; reasoning: string[] };

const words = (text: string) => new Set(text.toLowerCase().match(/[a-z]+/g) ?? []);

export function scoreProducts(intent: ShoppingIntent, catalog: Product[]) {
  const want = words(intent.text);
  return catalog
    .filter(p => p.inStock && !p.tags.includes("warranty"))
    .map(p => ({ p, score: p.tags.filter(t => want.has(t) || want.has(`${t}s`)).length }))
    .filter(x => x.score > 0)
    .sort((a, b) => b.score - a.score || a.p.priceCents - b.p.priceCents);
}

/** Greedy pick by relevance, never exceeding the budget once shipping and tax are included. */
export function planCart(intent: ShoppingIntent, catalog: Product[]): Plan {
  const shipping = SHIPPING[intent.shipping ?? "standard"];
  const lines: PlannedLine[] = [];
  const reasoning: string[] = [];
  let subtotal = 0;
  for (const { p, score } of scoreProducts(intent, catalog)) {
    const next = subtotal + p.priceCents;
    if (next + shipping + taxFor(next) > intent.budgetCents) { reasoning.push(`skip ${p.sku}: would exceed budget`); continue; }
    subtotal = next;
    lines.push({ sku: p.sku, qty: 1, name: p.name, priceCents: p.priceCents });
    reasoning.push(`add ${p.sku} (relevance ${score})`);
  }
  for (const p of catalog.filter(p => !p.inStock)) reasoning.push(`skip ${p.sku}: out of stock`);
  return { lines, estimatedTotalCents: lines.length ? subtotal + shipping + taxFor(subtotal) : 0, reasoning };
}
