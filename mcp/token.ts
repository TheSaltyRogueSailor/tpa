/**
 * check_token: TPA Shield wrapper around the token gate ported from the TSRS TPA gate (./token-gate/guard.ts).
 * Reads public data only (one Solana RPC getAccountInfo on the mint, and the free RugCheck report).
 * No keys, no signing, no transactions. RugCheck being down degrades to a "rugcheck_unavailable" warning;
 * an unreadable mint fails closed ("mint_info_unavailable" block), as in the original gate.
 */
import { z } from "zod";
import { PREFLIGHT_NOTE } from "./checks.js";
import {
  DEFAULT_SOLANA_RPC_URL, evaluateTpa, fetchMintInfo, fetchRugcheck,
  type CreatorHistory, type FetchLike, type MintInfo, type PumpTrade, type RugcheckInfo, type TpaVerdict,
} from "./token-gate/guard.js";
import { TOKEN_REASON_TEXT, tokenReasonCode } from "./token-gate/reasons.js";
import { ISSUER_CONTROLLED_STABLECOINS, ISSUER_DOWNGRADABLE_CODES, issuerStablecoin } from "./token-gate/stablecoins.js";
import { TOKEN_GATE_THRESHOLDS, TOKEN_GATE_THRESHOLDS_VERSION, tokenGateConfig } from "./token-gate/thresholds.js";

const BASE58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/** A Solana address is base58 that decodes to exactly 32 bytes. Offline check, no network. */
export function isSolanaAddress(value: string): boolean {
  if (typeof value !== "string" || value.length < 32 || value.length > 44) return false;
  let number = 0n;
  for (const character of value) {
    const position = BASE58.indexOf(character);
    if (position < 0) return false;
    number = number * 58n + BigInt(position);
  }
  let leading = 0;
  while (value[leading] === "1") leading++;
  const bodyBytes = number === 0n ? 0 : Math.ceil(number.toString(16).length / 2);
  return leading + bodyBytes === 32;
}

const tradeSchema = z.object({
  sig: z.string().max(128), slot: z.number().int().nonnegative(), mint: z.string().max(64), user: z.string().max(64), isBuy: z.boolean(),
  sol: z.number().nonnegative(), tokens: z.number().nonnegative(), ts: z.number().nonnegative(), vSol: z.number(), vTok: z.number(),
  realTok: z.number(), t: z.number().nonnegative(), price: z.number(),
}).strict();

export const checkTokenArgs = {
  mint: z.string().min(1).max(64).describe("Solana token mint address (base58)."),
  creator: z.string().max(64).optional().describe("Optional: the creator (deployer) wallet, to check creator holdings and selling."),
  trades: z.array(tradeSchema).max(20_000).optional().describe("Optional: pump.fun trades since launch, oldest first. Without them the holder and trade checks are not evaluated."),
  creatorHistory: z.object({ launchesLastHour: z.number().int().nonnegative(), priorDumps: z.number().int().nonnegative(), priorTokens: z.number().int().nonnegative() }).strict().optional()
    .describe("Optional: what the caller knows about the creator's recent launches and dumps."),
  rugcheck: z.boolean().optional().describe("Call the free RugCheck API (default true)."),
  requireObservedSell: z.boolean().optional().describe("Optional: turn 'no non-creator sell seen' into a block instead of a warning."),
};
export type CheckTokenInput = {
  mint: string; creator?: string; trades?: PumpTrade[]; creatorHistory?: CreatorHistory; rugcheck?: boolean; requireObservedSell?: boolean;
};
export type TokenGateIo = { rpcUrl?: string; fetchImpl?: FetchLike; rpcTimeoutMs?: number; rugcheckTimeoutMs?: number };

export type TokenDecisionReason = { code: string; text: string; detail: string; layer?: "contract" | "holders" | "creator"; observed?: unknown; limit?: unknown };
export type TokenDecision = {
  decision: "pass" | "warn" | "block";
  check: "check_token";
  mint: string;
  reasons: TokenDecisionReason[];
  warnings: TokenDecisionReason[];
  checksRun: string[];
  details?: { score: number; mintInfo: MintInfo | null; rugcheck: RugcheckInfo | null | "skipped"; metrics?: TpaVerdict["metrics"]; thresholdsVersion: string };
  note: string;
};

function describe(text: string): TokenDecisionReason {
  const code = tokenReasonCode(text);
  return { code, text: TOKEN_REASON_TEXT[code] ?? text, detail: text };
}

export async function checkToken(input: CheckTokenInput, io: TokenGateIo = {}): Promise<TokenDecision> {
  const mint = input.mint.trim();
  if (!isSolanaAddress(mint)) {
    return { decision: "block", check: "check_token", mint, reasons: [describe("mint_address_invalid")], warnings: [], checksRun: ["mint address format"], note: PREFLIGHT_NOTE };
  }
  const useRugcheck = input.rugcheck ?? tokenGateConfig().rugcheck;
  const [mintInfo, rugcheck] = await Promise.all([
    fetchMintInfo(mint, { rpcUrl: io.rpcUrl ?? DEFAULT_SOLANA_RPC_URL, fetchImpl: io.fetchImpl, timeoutMs: io.rpcTimeoutMs }),
    useRugcheck ? fetchRugcheck(mint, { fetchImpl: io.fetchImpl, timeoutMs: io.rugcheckTimeoutMs }) : Promise.resolve(undefined),
  ]);
  const config = { ...tokenGateConfig(), ...(input.requireObservedSell !== undefined ? { requireObservedSell: input.requireObservedSell } : {}) };
  const verdict = evaluateTpa({
    mint, creator: input.creator, trades: input.trades, mintInfo,
    creatorHistory: input.creatorHistory ?? { launchesLastHour: 0, priorDumps: 0, priorTokens: 0 },
    rugcheck: useRugcheck ? rugcheck : undefined,
  }, config);
  const layerOf = (text: string) => verdict.layers.contract.includes(text) ? "contract" as const : verdict.layers.holders.includes(text) ? "holders" as const : "creator" as const;
  const reasons = verdict.reasonDetails.map(detail => {
    const described = detail.rule === "RUGCHECK_DANGER_RISK"
      ? { code: "rugcheck_danger", text: TOKEN_REASON_TEXT.rugcheck_danger!, detail: detail.text }
      : describe(detail.text);
    return { ...described, layer: layerOf(detail.text), observed: detail.observed, limit: detail.limit };
  });
  let warnings: TokenDecisionReason[] = verdict.warnings.map(describe);
  if (!useRugcheck) warnings.push(describe("rugcheck_skipped"));
  // Issuer allowance (approved Nov 13, 2026): for an allowlisted regulated stablecoin with the expected token program,
  // mint and freeze authority alone become warnings. Any other block reason keeps the decision at block.
  const stablecoin = issuerStablecoin(mint);
  let blocking = reasons;
  if (stablecoin && mintInfo?.program === stablecoin.program && reasons.length > 0 && reasons.every(entry => ISSUER_DOWNGRADABLE_CODES.has(entry.code))) {
    const allowance: TokenDecisionReason = { code: "issuer_controlled_stablecoin", text: TOKEN_REASON_TEXT.issuer_controlled_stablecoin!, detail: `${stablecoin.symbol} (${stablecoin.issuer}), mint verified from ${stablecoin.source}` };
    warnings = [allowance, ...reasons, ...warnings];
    blocking = [];
  }
  const checksRun = [
    "mint address format",
    "mint authority revoked", "freeze authority revoked (honeypot)", "no dangerous Token-2022 extensions", "no transfer fee",
    ...(input.trades ? ["curve not complete", "sellability (non-creator sell seen)", "top holder and top 5 concentration", "creator holdings", "bundled launch", "insider share", "one-wallet volume", "creator selling"] : []),
    "creator launch and dump history (as provided)",
    ...(useRugcheck ? ["RugCheck report (rugged flag, creator token count, danger risks)"] : []),
  ];
  return {
    decision: blocking.length ? "block" : warnings.length ? "warn" : "pass",
    check: "check_token",
    mint,
    reasons: blocking,
    warnings,
    checksRun,
    details: {
      score: verdict.score, mintInfo, rugcheck: useRugcheck ? (rugcheck ?? null) : "skipped",
      ...(input.trades ? { metrics: verdict.metrics } : {}), thresholdsVersion: TOKEN_GATE_THRESHOLDS_VERSION,
    },
    note: PREFLIGHT_NOTE,
  };
}

export function tokenGatePolicy() {
  return {
    chain: "Solana (SPL Token and Token-2022, pump.fun aware)",
    source: "Ported from the TSRS TPA gate",
    thresholdsVersion: TOKEN_GATE_THRESHOLDS_VERSION,
    thresholds: Object.fromEntries(Object.entries(TOKEN_GATE_THRESHOLDS).map(([key, entry]) => [key, { value: entry.value, unit: entry.unit }])),
    blocks: ["mint_info_unavailable (fails closed)", "mint_authority_active", "freeze_authority_active (honeypot)", "token2022_dangerous_extension", "transfer_fee",
      "with trades: curve_complete, top_holder_concentration, top5_concentration, creator_holds, bundled_launch, insider_share, volume_from_one_wallet, creator_selling",
      "creator history: serial_launcher, creator_dumped_before", "RugCheck: rugcheck_rugged, rugcheck_creator_tokens, freeze / mint authority / copycat / honeypot danger risks"],
    issuerControlledStablecoins: {
      rule: "For these exact mints (and expected token program), mint_authority_active and freeze_authority_active alone return warn with issuer_controlled_stablecoin. Any other block reason still blocks.",
      mints: ISSUER_CONTROLLED_STABLECOINS.map(entry => ({ symbol: entry.symbol, issuer: entry.issuer, mint: entry.mint, program: entry.program, source: entry.source })),
    },
    warns: ["issuer_controlled_stablecoin", "rugcheck_unavailable", "trade_history_not_provided", "sell_unverified", "same_slot_cluster", "few_early_buyers", "creator_unknown", "other RugCheck risks"],
    network: "Reads one public Solana RPC call (default the free public mainnet RPC, override with TPA_SHIELD_SOLANA_RPC_URL) and the free RugCheck API. No keys, short timeouts.",
    holderNote: "Holder concentration is computed from pump.fun trades when the caller provides them. RugCheck holder risks are ignored, as in the original gate.",
  };
}
