/**
 * One REAL Airi purchase with a manual checkout handoff (shopper/live-buy.ts, shopper/handoff.ts).
 *
 *   pnpm airi:buy -- --merchant gumroad-kyle                # plan only: caps + checkout, no airi-cli call
 *   AIRI_LIVE=1 pnpm airi:buy -- --merchant gumroad-kyle    # live: creates ONE Airi mandate (owner passkey), hands off
 *
 * Flags: --merchant <id> (required), --price-cents <n> (pay-what-you-want, >= configured), --tax-cents <n>,
 * --handoff-timeout-min <n>, --allow-repeat, --no-stdin. Never runs `airi-cli auth login`; never prints card data.
 */
import { createAiriCliRunner, createAiriClient } from "../shopper/airi.js";
import { createManualCheckoutHandoff } from "../shopper/handoff.js";
import { loadAiriLiveConfig, planAiriBuy, runAiriBuy } from "../shopper/live-buy.js";
import { PaymentRefused } from "../shopper/payments.js";

function args(argv: string[]) {
  const out: Record<string, string | true> = {};
  for (let i = 0; i < argv.length; i += 1) {
    const a = argv[i]!;
    if (a === "--") continue;
    if (!a.startsWith("--")) throw new PaymentRefused("usage", `Unexpected argument ${a}.`);
    const key = a.slice(2);
    if (["allow-repeat", "no-stdin", "plan"].includes(key)) out[key] = true;
    else { const v = argv[i + 1]; if (v === undefined || v.startsWith("--")) throw new PaymentRefused("usage", `--${key} needs a value.`); out[key] = v; i += 1; }
  }
  return out;
}
const int = (v: string | true | undefined, name: string) => {
  if (v === undefined) return undefined;
  if (typeof v !== "string" || !/^\d+$/.test(v)) throw new PaymentRefused("usage", `--${name} must be a whole number.`);
  return Number(v);
};

async function main() {
  const a = args(process.argv.slice(2));
  const merchantId = typeof a.merchant === "string" ? a.merchant : "";
  const config = loadAiriLiveConfig();
  if (!merchantId) throw new PaymentRefused("usage", `--merchant is required (${Object.keys(config.merchants).join(", ")}).`);
  const over = { priceCents: int(a["price-cents"], "price-cents"), taxCents: int(a["tax-cents"], "tax-cents"), allowRepeat: a["allow-repeat"] === true };
  const journalPath = "artifacts/airi-dispatch-journal.json";
  const plan = planAiriBuy(config, merchantId, journalPath, over);
  if (process.env.AIRI_LIVE !== "1" || a.plan === true) {
    console.log(`PLAN ONLY (set AIRI_LIVE=1 to buy): ${plan.merchant.name} [${merchantId}] ${plan.merchant.item.name}`);
    console.log(`  price ${(plan.priceCents / 100).toFixed(2)} + tax ${(plan.taxCents / 100).toFixed(2)} = USD ${(plan.totalCents / 100).toFixed(2)}; per-buy cap ${(plan.capCents / 100).toFixed(2)}; run ${(plan.spentCents / 100).toFixed(2)} of ${(plan.runTotalCapCents / 100).toFixed(2)} used`);
    console.log(`  merchant url ${plan.merchant.url} (${plan.merchant.country}); checkout ${plan.merchant.checkoutUrl}; payment method ${plan.paymentMethodId}${config.paymentMethodLabel ? ` (${config.paymentMethodLabel})` : ""}`);
    return;
  }
  const client = createAiriClient(createAiriCliRunner());
  const timeoutMin = int(a["handoff-timeout-min"], "handoff-timeout-min") ?? config.handoffTimeoutMinutes;
  const useStdin = a["no-stdin"] !== true && process.stdin.isTTY === true;
  const handoff = createManualCheckoutHandoff({ timeoutMs: timeoutMin * 60_000, checkoutUrlFor: id => config.merchants[id]?.checkoutUrl, ...(useStdin ? { stdin: process.stdin } : {}) });
  try {
    const result = await runAiriBuy({ config, merchantId, client, submitCheckout: handoff, journalPath, ...over });
    if (result.status !== "PAID") process.exitCode = 1;
  } finally { if (useStdin) process.stdin.pause(); }
}
main().catch(error => { console.error(error instanceof PaymentRefused ? `REFUSED (${error.reason}): ${error.message}` : error instanceof Error ? `${error.name}: ${error.message}` : "airi:buy failed"); process.exitCode = 1; });
