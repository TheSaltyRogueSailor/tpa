/**
 * TPA Shopper demo: an AI shopping agent buys within a budget, protected by TPA, signed with Visa TAP,
 * paid through Airwallex (mock Airi) or Metal (mock USDZ). Then three attacks get blocked.
 * Local only: a localhost merchant, in-memory TPA store, no real payment, no network beyond 127.0.0.1.
 *
 *   pnpm demo:shopper            # full run
 *   pnpm demo:shopper -- --slow  # paced output for screen recording
 */
import { createShopperRig, type ShopEvent, type ShopOutcome } from "../shopper/flow.js";

const useColor = process.env.FORCE_COLOR ? process.env.FORCE_COLOR !== "0" : !process.env.NO_COLOR;
const paint = (code: string) => (t: string) => (useColor ? `\x1b[${code}m${t}\x1b[0m` : t);
const green = paint("1;32"), red = paint("1;31"), dim = paint("2"), bold = paint("1"), cyan = paint("1;36"), yellow = paint("33");
const slow = process.argv.includes("--slow");
const pause = (ms: number) => (slow ? new Promise(r => setTimeout(r, ms)) : Promise.resolve());
const say = (line = "") => { console.log(line); };
const ACTOR: Record<ShopEvent["actor"], string> = { agent: "AGENT   ", merchant: "MERCHANT", tpa: "TPA     ", owner: "OWNER   ", rail: "RAIL    ", attacker: "ATTACKER" };

async function printEvents(events: ShopEvent[]) {
  for (const e of events) { say(`  ${dim(ACTOR[e.actor])} ${e.ok ? green("ok ") : red("NO ")} ${bold(e.step)}  ${dim(e.detail)}`); await pause(450); }
}
const MEANING: Record<string, string> = {
  "tpa:terms_changed:items_mismatch": "items or prices differ from what the owner approved",
  "tpa:terms_changed:merchant_mismatch": "a different merchant than the one the owner approved",
  "tpa:intent": "no valid owner approval: never approved, already used, expired or revoked",
};
const results: { name: string; outcome: string; reason: string; pass: boolean }[] = [];
async function scenario(name: string, expected: "PAID" | "BLOCKED", run: () => Promise<ShopOutcome>) {
  say(cyan(`== ${name} ==`));
  const r = await run();
  await printEvents(r.events);
  const badge = r.outcome === "PAID" ? green(" PAID ") : red(" BLOCKED ");
  const why = r.outcome === "PAID" ? `order ${r.orderNumber}, ${r.payment?.rail} ref ${r.payment?.reference.slice(0, 24)}...` : `${r.blockedBy}: ${r.reason}`;
  say(`  ${badge} ${why}${r.outcome === "BLOCKED" && MEANING[`${r.blockedBy}:${r.reason}`] ? dim(` (${MEANING[`${r.blockedBy}:${r.reason}`]})`) : ""}`);
  say();
  results.push({ name, outcome: r.outcome, reason: r.outcome === "PAID" ? "ok" : `${r.blockedBy}:${r.reason}`, pass: r.outcome === expected });
  await pause(900);
  return r;
}

async function main() {
  const rig = await createShopperRig({ agentKeyPath: process.env.TPA_SHOPPER_AGENT_KEY ?? ".shopper-keys/tap-agent-ed25519.pem" });
  const intent = { text: "Coffee brewing setup for the office: beans, filters, mugs", budgetCents: 12_000 };
  try {
    say(cyan("=================================================================="));
    say(cyan("  TPA Shopper") + dim("  Triple Protection Authentication for agentic checkout"));
    say(cyan("=================================================================="));
    say(`  Shopper intent: ${bold(`"${intent.text}"`)}, budget ${bold("$120.00")}`);
    say(dim(`  Agent TAP keyid (RFC 7638 thumbprint): ${rig.agentTap.keyId}`));
    say(dim(`  Merchant: Harbor Supply Co. at ${rig.merchant.baseUrl} (local demo, verifies Visa TAP on every request)`));
    say();
    const sample = rig.agentTap.signRequest({ authority: rig.merchant.authority, path: "/checkout/example/confirm", tag: "agent-payer-auth", nowSeconds: Math.floor(Date.now() / 1000) });
    say(dim("  Example TAP checkout headers the agent sends:"));
    say(dim(`    Signature-Input: ${sample.headers["signature-input"]!.slice(0, 150)}...`));
    say(dim(`    Signature: ${sample.headers.signature!.slice(0, 60)}...`));
    say();
    await pause(1500);

    const happy = await scenario("1. Happy path: agent buys, owner approves, paid via Airwallex (mock Airi)", "PAID", () => rig.shop(intent));
    if (happy.quote) say(dim(`  Approved cart: ${happy.quote.items.map(i => `${i.qty} x ${i.sku} @ $${(Number(i.unitPriceBaseUnits) / 100).toFixed(2)}`).join(", ")}\n`));
    await scenario("2. Same cart paid in USDZ on Metal (mock testnet, chain 63825)", "PAID", () => rig.shop({ ...intent, rail: "metal" }));

    rig.merchant.setAttack("price_swap");
    await scenario("Attack A: merchant raises a price after the owner approved", "BLOCKED", () => rig.shop(intent));
    rig.merchant.setAttack("inject_item");
    const injected = await scenario("Attack B: checkout page injects an extra $49.99 protection plan", "BLOCKED", () => rig.shop(intent));
    rig.merchant.setAttack("swap_merchant");
    await scenario("Attack C: lookalike merchant id (harbor-supp1y) at payment time", "BLOCKED", () => rig.shop(intent));
    rig.merchant.setAttack(null);
    await scenario("Attack D: agent tries to spend without the owner's passkey approval", "BLOCKED", () => rig.shop({ ...intent, ownerApproves: false }));

    say(cyan("== Attack E: replayed or unsigned agent traffic at the merchant (Visa TAP) =="));
    const replay = await rig.replayCapturedCheckout();
    say(`  ${dim(ACTOR.attacker)} ${replay.replay.status === 401 ? green("ok ") : red("NO ")} ${bold("replay a captured agent-payer-auth request")}  ${dim(`-> ${replay.replay.status} ${replay.replay.reason}`)}`);
    say(`  ${dim(ACTOR.attacker)} ${replay.unsigned.status === 401 ? green("ok ") : red("NO ")} ${bold("unsigned bot hits checkout")}  ${dim(`-> ${replay.unsigned.status} ${replay.unsigned.reason}`)}`);
    results.push({ name: "Attack E: TAP replay / unsigned", outcome: "BLOCKED", reason: `tap:${replay.replay.reason},${replay.unsigned.reason}`, pass: replay.replay.reason === "nonce_replayed" && replay.unsigned.reason === "not_signed" });
    say();

    say(cyan("== Audit log for Attack B (owner-scoped, no secrets) =="));
    for (const a of (await rig.auditLog(injected.intentId)).reverse()) say(dim(`  #${a.id} ${a.action.padEnd(22)} ${a.outcome.padEnd(9)} ${a.reasonCode}`));
    say();

    say(cyan("== Summary =="));
    for (const r of results) say(`  ${r.pass ? green("PASS") : red("FAIL")}  ${r.outcome === "PAID" ? green("PAID   ") : red("BLOCKED")}  ${r.name}  ${dim(r.reason)}`);
    say();
    say(yellow("  Mocked pending credentials: Airwallex Airi CLI (Kit 09 allowlist), Metal testnet RPC + USDZ key."));
    say(dim("  Real: TPA mandate 3.0 + Ed25519 signature, WebAuthn ES256 verification, exact-match consume, audit log, Visa TAP RFC 9421 signing/verification."));
    if (results.some(r => !r.pass)) process.exitCode = 1;
  } finally {
    await rig.close();
  }
}
main().catch(error => { console.error(error); process.exitCode = 1; });
