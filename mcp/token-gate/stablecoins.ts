/**
 * Issuer-controlled regulated stablecoins on Solana mainnet (approved by Raul, Nov 13, 2026).
 *
 * Their issuers keep mint and freeze authority on purpose (to issue, redeem and meet legal freeze
 * orders). For these exact mints, and only when mint_authority_active and/or freeze_authority_active
 * are the ONLY block reasons, check_token returns "warn" with issuer_controlled_stablecoin instead of
 * "block". Any other block reason (RugCheck danger or rugged, Token-2022 traps, transfer fee, creator
 * or holder checks, unreadable mint) still blocks.
 *
 * Each mint was checked against the issuer's own documentation on Nov 13, 2026:
 *   USDC  Circle  https://developers.circle.com/stablecoins/usdc-contract-addresses
 *   USDT  Tether  https://tether.to/en/supported-protocols/
 *   PYUSD Paxos   https://docs.paxos.com/guides/stablecoin/pyusd/mainnet
 * Cross-checked with the Solana payments docs: https://solana.com/docs/payments/how-payments-work
 * The expected token program is also checked, so a look-alike account cannot use the allowlist.
 */
export type IssuerStablecoin = { symbol: "USDC" | "USDT" | "PYUSD"; issuer: string; mint: string; program: "spl-token" | "token-2022"; source: string };

export const ISSUER_CONTROLLED_STABLECOINS: readonly IssuerStablecoin[] = Object.freeze([
  { symbol: "USDC", issuer: "Circle", mint: "EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v", program: "spl-token", source: "https://developers.circle.com/stablecoins/usdc-contract-addresses" },
  { symbol: "USDT", issuer: "Tether", mint: "Es9vMFrzaCERmJfrF4H2FYD4KCoNkY11McCe8BenwNYB", program: "spl-token", source: "https://tether.to/en/supported-protocols/" },
  { symbol: "PYUSD", issuer: "Paxos (for PayPal)", mint: "2b1kV6DkPAnxd5ixfnxCpjxmKwqjjaYmCZfHsFu24GXo", program: "token-2022", source: "https://docs.paxos.com/guides/stablecoin/pyusd/mainnet" },
]);

/** Block reasons that the issuer allowance may downgrade to warnings. Nothing else. */
export const ISSUER_DOWNGRADABLE_CODES: ReadonlySet<string> = new Set(["mint_authority_active", "freeze_authority_active"]);

export function issuerStablecoin(mint: string): IssuerStablecoin | undefined {
  return ISSUER_CONTROLLED_STABLECOINS.find(entry => entry.mint === mint);
}
