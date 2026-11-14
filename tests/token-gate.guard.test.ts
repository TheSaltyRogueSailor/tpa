// TPA token gate unit tests: rug-like, honeypot-like, bundled and healthy fixtures (offline).
// Ported from the TSRS TPA gate tests (artifacts/api-server/test/tpa-guard.test.ts), node:test to Vitest.
import { test } from "vitest";
import assert from "node:assert/strict";
import { evaluateTpa, CreatorRegistry, holderBalances, holderSnapshot, prewatchTpa } from "../mcp/token-gate/guard.js";
import { tokenGateConfig } from "../mcp/token-gate/thresholds.js";
import { healthy, rugLike, honeypotLike, bundled, SAFE_MINT, Curve, wallet } from "./fixtures/token-gate.js";

const cfg = tokenGateConfig();
const noHistory = { launchesLastHour: 1, priorDumps: 0, priorTokens: 0 };

test("healthy token -> VERIFIED, all analysis fields filled", () => {
  const { curve, creator } = healthy();
  const v = evaluateTpa({ mint: curve.mint, creator, trades: curve.trades, mintInfo: SAFE_MINT, creatorHistory: noHistory }, cfg);
  assert.equal(v.verdict, "VERIFIED", JSON.stringify(v.reasons));
  assert.equal(v.pass, true);
  assert.deepEqual(v.reasons, []);
  assert.equal(v.trapFilter, "PASS");
  assert.ok(v.score >= 90);
  assert.ok(v.insiderConcentration >= 0 && v.insiderConcentration < 0.25);
  assert.ok(v.walletConcentration > 0 && v.walletConcentration < 10);
  assert.equal(v.creatorSellPercent, 0);
});

test("rug-like (creator holds ~18% and sells) -> BLOCKED on holders + creator layers", () => {
  const { curve, creator } = rugLike();
  const v = evaluateTpa({ mint: curve.mint, creator, trades: curve.trades, mintInfo: SAFE_MINT, creatorHistory: noHistory }, cfg);
  assert.equal(v.verdict, "BLOCKED");
  assert.ok(v.reasons.some(r => r.startsWith("creator_holds_")), v.reasons.join());
  assert.ok(v.reasons.some(r => r.startsWith("creator_selling_")), v.reasons.join());
  assert.ok(v.layers.holders.length > 0 && v.layers.creator.length > 0);
  assert.ok(v.creatorSellPercent >= 39 && v.creatorSellPercent <= 41);
});

test("honeypot-like (freeze authority, nobody sold) -> BLOCKED on contract layer, trap FAIL", () => {
  const { curve, creator, mint } = honeypotLike();
  const v = evaluateTpa({ mint: curve.mint, creator, trades: curve.trades, mintInfo: mint, creatorHistory: noHistory }, cfg);
  assert.equal(v.verdict, "BLOCKED");
  assert.ok(v.reasons.includes("freeze_authority_active(honeypot_risk)"));
  assert.equal(v.trapFilter, "FAIL");
  assert.ok(v.warnings.some(w => w.startsWith("sell_unverified")));
});

test("observed-sell requirement turns sell_unverified into a hard block", () => {
  const { curve, creator } = honeypotLike();
  const v = evaluateTpa({ mint: curve.mint, creator, trades: curve.trades, mintInfo: SAFE_MINT, creatorHistory: noHistory }, { ...cfg, requireObservedSell: true });
  assert.equal(v.pass, false);
  assert.ok(v.reasons.some(r => r.startsWith("sell_unverified")));
});

test("bundled launch (5 snipers in the creation slot) -> BLOCKED", () => {
  const { curve, creator } = bundled();
  const v = evaluateTpa({ mint: curve.mint, creator, trades: curve.trades, mintInfo: SAFE_MINT, creatorHistory: noHistory }, cfg);
  assert.equal(v.pass, false);
  assert.ok(v.reasons.some(r => r.startsWith("bundled_launch_5_wallets")), v.reasons.join());
  assert.ok(v.warnings.some(w => w.startsWith("same_slot_cluster_")));
});

test("contract layer: unknown mint info fails closed; mint authority, Token-2022 hooks, transfer fee block", () => {
  const { curve, creator } = healthy();
  const base = { mint: curve.mint, creator, trades: curve.trades, creatorHistory: noHistory };
  assert.ok(evaluateTpa({ ...base, mintInfo: null }, cfg).reasons.includes("mint_info_unavailable"));
  assert.ok(evaluateTpa({ ...base, mintInfo: { ...SAFE_MINT, mintAuthority: "X" } }, cfg).reasons.includes("mint_authority_active"));
  assert.ok(evaluateTpa({ ...base, mintInfo: { ...SAFE_MINT, program: "token-2022", extensions: ["transferHook"] } }, cfg).reasons.includes("token2022_transferHook"));
  assert.ok(evaluateTpa({ ...base, mintInfo: { ...SAFE_MINT, program: "token-2022", extensions: ["metadataPointer", "tokenMetadata"] } }, cfg).pass);
  assert.ok(evaluateTpa({ ...base, mintInfo: { ...SAFE_MINT, transferFeeBps: 300 } }, cfg).reasons.includes("transfer_fee_300bps"));
});

test("creator history: serial launcher and prior dumps block; RugCheck rugged/danger block, unavailable warns", () => {
  const { curve, creator } = healthy();
  const base = { mint: curve.mint, creator, trades: curve.trades, mintInfo: SAFE_MINT };
  assert.ok(evaluateTpa({ ...base, creatorHistory: { launchesLastHour: 5, priorDumps: 0, priorTokens: 4 } }, cfg).reasons.some(r => r.startsWith("serial_launcher_5")));
  assert.ok(evaluateTpa({ ...base, creatorHistory: { launchesLastHour: 1, priorDumps: 1, priorTokens: 1 } }, cfg).reasons.some(r => r.startsWith("creator_dumped_before")));
  const rc = { rugged: false, creatorTokens: 0, dangerRisks: [] as string[], warnRisks: [] as string[] };
  assert.ok(evaluateTpa({ ...base, creatorHistory: noHistory, rugcheck: { ...rc, rugged: true } }, cfg).reasons.includes("rugcheck_rugged"));
  assert.ok(evaluateTpa({ ...base, creatorHistory: noHistory, rugcheck: { ...rc, creatorTokens: 40 } }, cfg).reasons.some(r => r.startsWith("rugcheck_creator_tokens")));
  assert.ok(evaluateTpa({ ...base, creatorHistory: noHistory, rugcheck: { ...rc, dangerRisks: ["Freeze Authority still enabled"] } }, cfg).pass === false);
  const unavailable = evaluateTpa({ ...base, creatorHistory: noHistory, rugcheck: null }, cfg);
  assert.equal(unavailable.pass, true);
  assert.ok(unavailable.warnings.includes("rugcheck_unavailable"));
});

test("holderBalances excludes the bonding curve by construction (only trader wallets)", () => {
  const c = new Curve(); const a = wallet("a");
  c.buy(a, 1, 0); c.sell(a, 0.5, 1000);
  const bal = holderBalances(c.trades);
  assert.equal(bal.size, 1);
  assert.ok(Math.abs((bal.get(a) ?? 0) - c.bal.get(a)!) < 1e-6);
});

test("CreatorRegistry: counts launches, flags a dump (>=50% sold), reports it on the next launch", () => {
  const reg = new CreatorRegistry();
  const { curve, creator } = rugLike();
  reg.recordLaunch(creator, curve.mint, curve.t0);
  for (const t of curve.trades) reg.onTrade(t);
  // creator sold 40% - not a dump yet
  assert.equal(reg.history(creator, "next", curve.t0 + 10_000).priorDumps, 0);
  const t = curve.sell(creator, 1, 8000); reg.onTrade(t);
  reg.recordLaunch(creator, "NEXTmint", curve.t0 + 20_000);
  const h = reg.history(creator, "NEXTmint", curve.t0 + 20_000);
  assert.equal(h.priorDumps, 1);
  assert.equal(h.launchesLastHour, 2);
  assert.equal(h.priorTokens, 1);
});

// TPA Shield additions to the ported suite.
test("thresholds match the TSRS main-venue config v1.1.0", () => {
  assert.equal(cfg.maxTopHolderPct, 10);
  assert.equal(cfg.maxTop5Pct, 30);
  assert.equal(cfg.maxCreatorHeldPct, 10);
  assert.equal(cfg.requireObservedSell, false);
  assert.equal(cfg.rugcheck, true);
  assert.equal(cfg.rcMaxCreatorTokens, 5);
});

test("without trades the holder and trade checks are not evaluated and say so", () => {
  const v = evaluateTpa({ mint: "M", mintInfo: SAFE_MINT, creatorHistory: { launchesLastHour: 0, priorDumps: 0, priorTokens: 0 }, rugcheck: undefined }, { ...cfg, requireObservedSell: true });
  assert.equal(v.pass, true, v.reasons.join());
  assert.ok(v.warnings.includes("trade_history_not_provided"));
  assert.ok(!v.warnings.some(w => w.startsWith("few_early_buyers") || w.startsWith("sell_unverified")));
  const frozen = evaluateTpa({ mint: "M", mintInfo: { ...SAFE_MINT, freezeAuthority: "F" }, creatorHistory: { launchesLastHour: 0, priorDumps: 0, priorTokens: 0 } }, cfg);
  assert.ok(frozen.reasons.includes("freeze_authority_active(honeypot_risk)"));
});

test("prewatchTpa flags serial launchers and prior dumps; holderSnapshot keeps the creator row", () => {
  assert.equal(prewatchTpa({ launchesLastHour: 3, priorDumps: 1, priorTokens: 2 }, cfg).reasons.length, 2);
  assert.equal(prewatchTpa({ launchesLastHour: 1, priorDumps: 0, priorTokens: 0 }, cfg).reasons.length, 0);
  const { curve, creator } = rugLike();
  const rows = holderSnapshot(curve.trades, creator, 1e9, 3);
  assert.ok(rows.some(row => row.creator));
});
