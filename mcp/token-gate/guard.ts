/**
 * TPA token gate: Solana / pump.fun token safety checks (rug-pull and honeypot risk).
 *
 * Ported from the TSRS TPA gate (artifacts/api-server/src/lib/tpa-guard.ts: evaluateTpa, prewatchTpa,
 * holderBalances, holderSnapshot, CreatorRegistry, fetchMintInfo, fetchRugcheck). Only the safety gate
 * was brought over. TPA Shield changes, all marked below:
 *   - thresholds come from ./thresholds.ts (no environment reads or overrides);
 *   - `trades` is optional: without pump.fun trade history the holder and trade checks are not
 *     evaluated and the result carries a "trade_history_not_provided" warning instead of a silent pass;
 *   - the collectors use plain fetch (JSON-RPC getAccountInfo and the free RugCheck report API) with
 *     short timeouts, no SDK, no keys, no caches and no paper-feed mocks.
 *
 * Three layers, all must pass:
 *   1. CONTRACT: mint and freeze authority revoked, no dangerous Token-2022 extensions, no transfer fee,
 *      curve not complete, sellability evidence.
 *   2. HOLDERS: top holder and top 5 concentration (bonding curve excluded), creator-held share,
 *      same-slot bundles at launch, insider share, one-wallet volume, early-buyer count.
 *   3. CREATOR: creator selling, serial launches, prior dumps, RugCheck rugged flag and creator token count.
 *
 * Read-only: no signing, no transactions, no wallet keys.
 */
import { tokenGateConfig } from "./thresholds.js";

/** pump.fun bonding-curve token supply (UI units). */
export const PUMP_TOTAL_SUPPLY = 1_000_000_000;

/** One pump.fun trade (shape of the TSRS PumpTrade record). */
export interface PumpTrade {
  sig: string;
  slot: number;
  mint: string;
  user: string;
  isBuy: boolean;
  /** SOL moved by the trade (UI units) */
  sol: number;
  /** tokens moved by the trade (UI units) */
  tokens: number;
  /** chain block time (unix seconds) */
  ts: number;
  /** post-trade virtual reserves (UI units) */
  vSol: number;
  vTok: number;
  /** post-trade real token reserves (UI units); 0 means curve complete / migrated */
  realTok: number;
  /** receive time (ms), used for all time windows */
  t: number;
  /** spot price after this trade, SOL per token */
  price: number;
}

/** One hard block reason with its rule id (the threshold key when there is one), observed value and limit. */
export interface ReasonDetail { rule: string; text: string; observed: unknown; limit: unknown }

export interface TpaConfig {
  maxTopHolderPct: number;
  maxTop5Pct: number;
  maxCreatorHeldPct: number;
  bundleSlots: number;
  minBundleWallets: number;
  maxBundlePct: number;
  maxInsiderPct: number;
  maxCreatorSoldPct: number;
  maxCreatorLaunchesPerHour: number;
  maxCreatorPriorDumps: number;
  earlyWindowS: number;
  minEarlyBuyers: number;
  maxSingleBuyerVolPct: number;
  sameSlotCluster: number;
  requireObservedSell: boolean;
  rcMaxCreatorTokens: number;
  rugcheck: boolean;
  singleBuyerBelowBuyers: number;
  dumpSoldFraction: number;
  dumpWindowS: number;
}

export function prewatchTpa(h: CreatorHistory, cfg: TpaConfig): { reasons: string[]; details: ReasonDetail[] } {
  const details: ReasonDetail[] = [];
  if (h.launchesLastHour > cfg.maxCreatorLaunchesPerHour)
    details.push({ rule: "TPA_MAX_CREATOR_LAUNCHES_PER_HOUR", text: `serial_launcher_${h.launchesLastHour}_in_1h`, observed: h.launchesLastHour, limit: cfg.maxCreatorLaunchesPerHour });
  if (h.priorDumps > cfg.maxCreatorPriorDumps)
    details.push({ rule: "TPA_MAX_CREATOR_PRIOR_DUMPS", text: `creator_dumped_before_x${h.priorDumps}`, observed: h.priorDumps, limit: cfg.maxCreatorPriorDumps });
  return { reasons: details.map(d => d.text), details };
}

export interface MintInfo {
  program: "spl-token" | "token-2022" | "unknown";
  mintAuthority: string | null;
  freezeAuthority: string | null;
  extensions: string[];
  transferFeeBps: number;
  supply: number; // UI units
}

export interface CreatorHistory { launchesLastHour: number; priorDumps: number; priorTokens: number }
export interface RugcheckInfo { rugged: boolean; creatorTokens: number; dangerRisks: string[]; warnRisks: string[] }

export interface TpaInput {
  mint: string;
  creator?: string;
  /** pump.fun trades since launch. When omitted, the holder and trade checks are not evaluated (TPA Shield change). */
  trades?: PumpTrade[];
  mintInfo: MintInfo | null;
  creatorHistory: CreatorHistory;
  rugcheck?: RugcheckInfo | null;
}

export interface TpaMetrics {
  topHolderPct: number; top5Pct: number; creatorHeldPct: number; creatorSoldPct: number;
  launchSlotBuyers: number; bundlePct: number; insiderPct: number; earlyBuyers: number;
  uniqueBuyers: number; nonCreatorSells: number; singleBuyerVolPct: number; maxSameSlotBuyers: number;
  curveComplete: boolean;
}

export interface TpaVerdict {
  verdict: "VERIFIED" | "BLOCKED";
  pass: boolean;
  score: number;
  reasons: string[];
  /** same order as `reasons`: rule id + observed value + limit for each hard reason */
  reasonDetails: ReasonDetail[];
  warnings: string[];
  layers: { contract: string[]; holders: string[]; creator: string[] };
  metrics: TpaMetrics;
  // fills TradeSignal's previously-unused optional fields
  trapFilter: "PASS" | "FAIL" | "WARN";
  insiderConcentration: number; // fraction 0..1
  creatorSellPercent: number;   // %
  walletConcentration: number;  // % (top holder)
}

const DANGEROUS_EXTENSIONS = new Set([
  "transferHook", "permanentDelegate", "nonTransferable", "defaultAccountState", "pausable", "confidentialTransferMint",
]);

/** Reconstruct holder balances (UI tokens) from trades. Bonding curve is not a trader → excluded. */
export function holderBalances(trades: PumpTrade[]): Map<string, number> {
  const bal = new Map<string, number>();
  for (const t of trades) bal.set(t.user, (bal.get(t.user) ?? 0) + (t.isBuy ? t.tokens : -t.tokens));
  return bal;
}

/** Holder snapshot for the audit trail: top N balances (bonding curve excluded) + the creator. */
export function holderSnapshot(trades: PumpTrade[], creator: string | undefined, supply = PUMP_TOTAL_SUPPLY, top = 20): { owner: string; tokens: number; pct: number; creator: boolean }[] {
  const rows = [...holderBalances(trades).entries()].filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  const pick = rows.slice(0, top);
  if (creator && !pick.some(([o]) => o === creator)) { const c = rows.find(([o]) => o === creator); if (c) pick.push(c); }
  return pick.map(([owner, tokens]) => ({ owner, tokens, pct: (tokens / supply) * 100, creator: owner === creator }));
}

export function evaluateTpa(input: TpaInput, cfg: TpaConfig): TpaVerdict {
  const { creator, mintInfo, creatorHistory, rugcheck } = input;
  const tradesKnown = Array.isArray(input.trades);
  const trades = input.trades ?? [];
  const supply = mintInfo?.supply && mintInfo.supply > 0 ? mintInfo.supply : PUMP_TOTAL_SUPPLY;
  const pct = (x: number) => (x / supply) * 100;
  const contract: string[] = [], holders: string[] = [], creatorL: string[] = [], warnings: string[] = [];
  const det = new Map<string, ReasonDetail>();
  const add = (layer: string[], text: string, rule: string, observed: unknown, limit: unknown) => { layer.push(text); det.set(text, { rule, text, observed, limit }); };

  // ── Layer 1: CONTRACT ────────────────────────────────────────────────
  if (!mintInfo) add(contract, "mint_info_unavailable", "MINT_INFO_AVAILABLE", null, "mint account readable (fails closed)");
  else {
    if (mintInfo.mintAuthority) add(contract, "mint_authority_active", "MINT_AUTHORITY_REVOKED", mintInfo.mintAuthority, null);
    if (mintInfo.freezeAuthority) add(contract, "freeze_authority_active(honeypot_risk)", "FREEZE_AUTHORITY_REVOKED", mintInfo.freezeAuthority, null);
    for (const e of mintInfo.extensions) if (DANGEROUS_EXTENSIONS.has(e)) add(contract, `token2022_${e}`, "TOKEN2022_NO_DANGEROUS_EXTENSIONS", e, "none");
    if (mintInfo.transferFeeBps > 0) add(contract, `transfer_fee_${mintInfo.transferFeeBps}bps`, "TRANSFER_FEE_BPS", mintInfo.transferFeeBps, 0);
  }
  const last = trades[trades.length - 1];
  const curveComplete = !!last && last.realTok <= 0;
  if (tradesKnown && curveComplete) add(contract, "curve_complete(migrated)", "CURVE_NOT_COMPLETE", last?.realTok ?? 0, "realTok>0");
  const nonCreatorSells = trades.filter(t => !t.isBuy && t.user !== creator).length;
  if (tradesKnown && nonCreatorSells === 0) {
    if (cfg.requireObservedSell) add(contract, "sell_unverified(no_non_creator_sell_seen)", "TPA_REQUIRE_OBSERVED_SELL", nonCreatorSells, ">=1 non-creator sell");
    else warnings.push("sell_unverified(no_non_creator_sell_seen)");
  }

  // ── Layer 2: HOLDERS ─────────────────────────────────────────────────
  const bal = holderBalances(trades);
  const creatorHeld = creator ? Math.max(0, bal.get(creator) ?? 0) : 0;
  const sorted = [...bal.entries()].filter(([, v]) => v > 0).sort((a, b) => b[1] - a[1]);
  const topHolderPct = sorted.length ? pct(sorted[0]![1]) : 0;
  const top5Pct = pct(sorted.slice(0, 5).reduce((s, [, v]) => s + v, 0));
  const creatorHeldPct = pct(creatorHeld);

  const launchSlot = trades.length ? Math.min(...trades.map(t => t.slot)) : 0;
  const launchBuyers = new Set(trades.filter(t => t.isBuy && t.user !== creator && t.slot <= launchSlot + cfg.bundleSlots).map(t => t.user));
  const bundleHeld = [...launchBuyers].reduce((s, u) => s + Math.max(0, bal.get(u) ?? 0), 0);
  const bundlePct = pct(bundleHeld);
  const insiderPct = pct(bundleHeld + creatorHeld);

  const slotBuyers = new Map<number, Set<string>>();
  for (const t of trades) if (t.isBuy && t.user !== creator) {
    if (!slotBuyers.has(t.slot)) slotBuyers.set(t.slot, new Set());
    slotBuyers.get(t.slot)!.add(t.user);
  }
  const maxSameSlotBuyers = Math.max(0, ...[...slotBuyers.values()].map(s => s.size));

  const t0 = trades.length ? trades[0]!.t : 0;
  const nonCreatorBuys = trades.filter(t => t.isBuy && t.user !== creator);
  const earlyBuyers = new Set(nonCreatorBuys.filter(t => t.t - t0 <= cfg.earlyWindowS * 1000).map(t => t.user)).size;
  const uniqueBuyers = new Set(nonCreatorBuys.map(t => t.user)).size;
  const volByBuyer = new Map<string, number>();
  for (const t of nonCreatorBuys) volByBuyer.set(t.user, (volByBuyer.get(t.user) ?? 0) + t.sol);
  const totalBuyVol = [...volByBuyer.values()].reduce((a, b) => a + b, 0);
  const singleBuyerVolPct = totalBuyVol > 0 ? (Math.max(...volByBuyer.values()) / totalBuyVol) * 100 : 0;

  if (tradesKnown) {
    if (topHolderPct > cfg.maxTopHolderPct) add(holders, `top_holder_${topHolderPct.toFixed(1)}%>${cfg.maxTopHolderPct}%`, "TPA_MAX_TOP_HOLDER_PCT", topHolderPct, cfg.maxTopHolderPct);
    if (top5Pct > cfg.maxTop5Pct) add(holders, `top5_holders_${top5Pct.toFixed(1)}%>${cfg.maxTop5Pct}%`, "TPA_MAX_TOP5_PCT", top5Pct, cfg.maxTop5Pct);
    if (creatorHeldPct > cfg.maxCreatorHeldPct) add(holders, `creator_holds_${creatorHeldPct.toFixed(1)}%>${cfg.maxCreatorHeldPct}%`, "TPA_MAX_CREATOR_HELD_PCT", creatorHeldPct, cfg.maxCreatorHeldPct);
    if (launchBuyers.size >= cfg.minBundleWallets && bundlePct > cfg.maxBundlePct)
      add(holders, `bundled_launch_${launchBuyers.size}_wallets_${bundlePct.toFixed(1)}%`, "TPA_MAX_BUNDLE_PCT", { bundlePct, wallets: launchBuyers.size }, { maxBundlePct: cfg.maxBundlePct, minBundleWallets: cfg.minBundleWallets, bundleSlots: cfg.bundleSlots });
    if (insiderPct > cfg.maxInsiderPct) add(holders, `insider_share_${insiderPct.toFixed(1)}%>${cfg.maxInsiderPct}%`, "TPA_MAX_INSIDER_PCT", insiderPct, cfg.maxInsiderPct);
    if (uniqueBuyers >= 1 && singleBuyerVolPct > cfg.maxSingleBuyerVolPct && uniqueBuyers < cfg.singleBuyerBelowBuyers)
      add(holders, `volume_from_one_wallet_${singleBuyerVolPct.toFixed(0)}%`, "TPA_MAX_SINGLE_BUYER_VOL_PCT", { singleBuyerVolPct, uniqueBuyers }, { maxPct: cfg.maxSingleBuyerVolPct, appliesBelowBuyers: cfg.singleBuyerBelowBuyers });
    if (maxSameSlotBuyers >= cfg.sameSlotCluster) warnings.push(`same_slot_cluster_${maxSameSlotBuyers}_buyers`);
    if (earlyBuyers < cfg.minEarlyBuyers) warnings.push(`few_early_buyers_${earlyBuyers}`);
  } else warnings.push("trade_history_not_provided");

  // ── Layer 3: CREATOR ─────────────────────────────────────────────────
  let creatorBought = 0, creatorSold = 0;
  for (const t of trades) if (creator && t.user === creator) { if (t.isBuy) creatorBought += t.tokens; else creatorSold += t.tokens; }
  const creatorSoldPct = creatorSold > 0 ? (creatorBought > 0 ? Math.min(100, (creatorSold / creatorBought) * 100) : 100) : 0;
  if (tradesKnown && creatorSoldPct > cfg.maxCreatorSoldPct) add(creatorL, `creator_selling_${creatorSoldPct.toFixed(0)}%`, "TPA_MAX_CREATOR_SOLD_PCT", creatorSoldPct, cfg.maxCreatorSoldPct);
  if (!creator) warnings.push("creator_unknown");
  if (creatorHistory.launchesLastHour > cfg.maxCreatorLaunchesPerHour) add(creatorL, `serial_launcher_${creatorHistory.launchesLastHour}_in_1h`, "TPA_MAX_CREATOR_LAUNCHES_PER_HOUR", creatorHistory.launchesLastHour, cfg.maxCreatorLaunchesPerHour);
  if (creatorHistory.priorDumps > cfg.maxCreatorPriorDumps) add(creatorL, `creator_dumped_before_x${creatorHistory.priorDumps}`, "TPA_MAX_CREATOR_PRIOR_DUMPS", creatorHistory.priorDumps, cfg.maxCreatorPriorDumps);
  if (rugcheck) {
    if (rugcheck.rugged) add(creatorL, "rugcheck_rugged", "RUGCHECK_NOT_RUGGED", true, false);
    if (rugcheck.creatorTokens > cfg.rcMaxCreatorTokens) add(creatorL, `rugcheck_creator_tokens_${rugcheck.creatorTokens}`, "TPA_RC_MAX_CREATOR_TOKENS", rugcheck.creatorTokens, cfg.rcMaxCreatorTokens);
    for (const r of rugcheck.dangerRisks) {
      if (/freeze|mint authority|copycat|honeypot/i.test(r)) add(contract, `rugcheck:${r}`, "RUGCHECK_DANGER_RISK", r, "none");
      else warnings.push(`rugcheck:${r}`);
    }
    for (const r of rugcheck.warnRisks) warnings.push(`rugcheck:${r}`);
  } else if (rugcheck === null) warnings.push("rugcheck_unavailable");

  const reasons = [...contract, ...holders, ...creatorL];
  const score = Math.max(0, Math.min(100, 100 - 25 * reasons.length - 5 * warnings.length));
  const pass = reasons.length === 0;
  return {
    verdict: pass ? "VERIFIED" : "BLOCKED",
    pass, score, reasons, reasonDetails: reasons.map(r => det.get(r) ?? { rule: "UNKNOWN", text: r, observed: null, limit: null }), warnings,
    layers: { contract, holders, creator: creatorL },
    metrics: { topHolderPct, top5Pct, creatorHeldPct, creatorSoldPct, launchSlotBuyers: launchBuyers.size, bundlePct, insiderPct, earlyBuyers, uniqueBuyers, nonCreatorSells, singleBuyerVolPct, maxSameSlotBuyers, curveComplete },
    trapFilter: contract.length ? "FAIL" : warnings.some(w => w.startsWith("sell_unverified")) ? "WARN" : "PASS",
    insiderConcentration: insiderPct / 100,
    creatorSellPercent: creatorSoldPct,
    walletConcentration: topHolderPct,
  };
}


// ── Creator registry (in-session history from the live feeds) ──────────────
export class CreatorRegistry {
  constructor(private dump: Pick<TpaConfig, "dumpSoldFraction" | "dumpWindowS"> = tokenGateConfig()) {}
  private launches = new Map<string, number[]>();
  private dumps = new Map<string, number>();
  private tokens = new Map<string, Set<string>>();
  private creatorOf = new Map<string, string>();
  private flow = new Map<string, { bought: number; sold: number; dumped: boolean; t0: number }>();

  recordLaunch(creator: string, mint: string, t = Date.now()): void {
    if (!creator) return;
    this.creatorOf.set(mint, creator);
    const arr = this.launches.get(creator) ?? [];
    arr.push(t);
    this.launches.set(creator, arr.filter(x => t - x < 3_600_000));
    if (!this.tokens.has(creator)) this.tokens.set(creator, new Set());
    this.tokens.get(creator)!.add(mint);
    this.flow.set(mint, { bought: 0, sold: 0, dumped: false, t0: t });
  }

  getCreator(mint: string): string | undefined { return this.creatorOf.get(mint); }

  /** Feed listener: track creator flows; a creator selling ≥ TPA_DUMP_SOLD_FRACTION of their buy within TPA_DUMP_WINDOW_S = dump. */
  onTrade(t: PumpTrade): void {
    const c = this.creatorOf.get(t.mint);
    if (!c || t.user !== c) return;
    const f = this.flow.get(t.mint);
    if (!f) return;
    if (t.isBuy) f.bought += t.tokens; else f.sold += t.tokens;
    if (!f.dumped && f.sold > 0 && f.sold >= this.dump.dumpSoldFraction * Math.max(f.bought, 1e-9) && t.t - f.t0 < this.dump.dumpWindowS * 1000) {
      f.dumped = true;
      this.dumps.set(c, (this.dumps.get(c) ?? 0) + 1);
    }
  }

  history(creator: string | undefined, excludeMint: string, now = Date.now()): CreatorHistory {
    if (!creator) return { launchesLastHour: 0, priorDumps: 0, priorTokens: 0 };
    const launches = (this.launches.get(creator) ?? []).filter(x => now - x < 3_600_000).length;
    let priorDumps = 0;
    for (const m of this.tokens.get(creator) ?? []) if (m !== excludeMint && this.flow.get(m)?.dumped) priorDumps++;
    return { launchesLastHour: launches, priorDumps, priorTokens: Math.max(0, (this.tokens.get(creator)?.size ?? 1) - 1) };
  }

  prune(now = Date.now()): void {
    for (const [m, f] of this.flow) if (now - f.t0 > 3_600_000) { this.flow.delete(m); this.creatorOf.delete(m); }
    for (const [c, arr] of this.launches) {
      const keep = arr.filter(x => now - x < 3_600_000);
      if (keep.length) this.launches.set(c, keep); else { this.launches.delete(c); this.tokens.delete(c); this.dumps.delete(c); }
    }
  }
}

/* ------------------------------ Collectors (I/O) ------------------------------ */
/* TPA Shield rewrite of the TSRS collectors: plain fetch, short timeouts, never throws. */

export type FetchLike = (input: string, init?: { method?: string; headers?: Record<string, string>; body?: string; signal?: AbortSignal }) => Promise<{ ok: boolean; status: number; json(): Promise<unknown> }>;

export const DEFAULT_SOLANA_RPC_URL = "https://api.mainnet-beta.solana.com";
export const RUGCHECK_API = "https://api.rugcheck.xyz/v1/tokens";
const SPL_TOKEN_PROGRAM = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA";
const TOKEN_2022_PROGRAM = "TokenzQdBNbLqP5VEhdkAS6EPFLC1PHnBqCXEpPxuEb";

async function fetchJson(fetchImpl: FetchLike, url: string, init: Parameters<FetchLike>[1], timeoutMs: number): Promise<unknown | null> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    const response = await fetchImpl(url, { ...init, signal: controller.signal });
    if (!response.ok) return null;
    return await response.json();
  } catch {
    return null;
  } finally {
    clearTimeout(timer);
  }
}

/** Parse a jsonParsed getAccountInfo result into MintInfo. Returns null when it is not a token mint. */
export function parseMintAccount(value: any): MintInfo | null {
  if (!value || typeof value !== "object") return null;
  const owner = String(value.owner ?? "");
  const parsed = value.data?.parsed;
  const info = parsed?.info;
  if (!info || (parsed.type !== undefined && parsed.type !== "mint")) return null;
  const exts: any[] = Array.isArray(info.extensions) ? info.extensions : [];
  const tf = exts.find(e => e?.extension === "transferFeeConfig");
  const feeBps = Number(tf?.state?.newerTransferFee?.transferFeeBasisPoints ?? 0) || 0;
  return {
    program: owner === TOKEN_2022_PROGRAM ? "token-2022" : owner === SPL_TOKEN_PROGRAM ? "spl-token" : "unknown",
    mintAuthority: info.mintAuthority ?? null,
    freezeAuthority: info.freezeAuthority ?? null,
    extensions: exts.map(e => String(e?.extension)),
    transferFeeBps: feeBps,
    supply: Number(info.supply ?? 0) / 10 ** Number(info.decimals ?? 6),
  };
}

/** One read-only getAccountInfo on the mint (up to 2 attempts). Returns null when unreadable: the gate then fails closed. */
export async function fetchMintInfo(mint: string, options: { rpcUrl?: string; fetchImpl?: FetchLike; timeoutMs?: number } = {}): Promise<MintInfo | null> {
  const fetchImpl = options.fetchImpl ?? (fetch as unknown as FetchLike);
  const body = JSON.stringify({ jsonrpc: "2.0", id: 1, method: "getAccountInfo", params: [mint, { encoding: "jsonParsed", commitment: "confirmed" }] });
  for (let attempt = 0; attempt < 2; attempt++) {
    const data: any = await fetchJson(fetchImpl, options.rpcUrl ?? DEFAULT_SOLANA_RPC_URL, { method: "POST", headers: { "content-type": "application/json" }, body }, options.timeoutMs ?? 5000);
    if (data && typeof data === "object" && "result" in data) return parseMintAccount(data.result?.value);
  }
  return null;
}

/** Parse a RugCheck report. Holder and liquidity risks are ignored, as in TSRS (holders come from trades). */
export function parseRugcheckReport(d: any): RugcheckInfo | null {
  if (!d || typeof d !== "object") return null;
  const risks: any[] = Array.isArray(d.risks) ? d.risks : [];
  const relevant = risks.filter(r => !/holder|ownership|LP|liquidity/i.test(String(r?.name)));
  return {
    rugged: !!d.rugged,
    creatorTokens: Array.isArray(d.creatorTokens) ? d.creatorTokens.length : 0,
    dangerRisks: relevant.filter(r => r?.level === "danger").map(r => String(r.name)),
    warnRisks: relevant.filter(r => r?.level === "warn").map(r => String(r.name)),
  };
}

/** Free RugCheck report (no key). Returns null when unavailable; never throws. */
export async function fetchRugcheck(mint: string, options: { fetchImpl?: FetchLike; timeoutMs?: number } = {}): Promise<RugcheckInfo | null> {
  const fetchImpl = options.fetchImpl ?? (fetch as unknown as FetchLike);
  const data = await fetchJson(fetchImpl, `${RUGCHECK_API}/${encodeURIComponent(mint)}/report`, { method: "GET", headers: { accept: "application/json" } }, options.timeoutMs ?? 4000);
  return parseRugcheckReport(data);
}
