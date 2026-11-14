/** Stable reason codes and plain-language text for the TPA token gate (check_token). */

/** Text for each stable token-gate reason code. The gate's own detail string (with numbers) is kept in `detail`. */
export const TOKEN_REASON_TEXT: Readonly<Record<string, string>> = {
  mint_address_invalid: "Not a valid Solana mint address",
  mint_info_unavailable: "Mint account could not be read or is not a token mint (fails closed)",
  mint_authority_active: "Mint authority is still active: more tokens can be minted at any time (rug-pull risk)",
  freeze_authority_active: "Freeze authority is still active: holders can be frozen and unable to sell (honeypot risk)",
  token2022_dangerous_extension: "Token-2022 extension that can trap or seize funds (transfer hook, permanent delegate, non-transferable, default frozen, pausable or confidential transfers)",
  transfer_fee: "Token charges a transfer fee",
  curve_complete: "pump.fun bonding curve is complete (token migrated)",
  sell_unverified: "No sell by anyone other than the creator has been seen (sellability unproven)",
  top_holder_concentration: "One wallet holds too much of the supply",
  top5_concentration: "The top 5 wallets hold too much of the supply",
  creator_holds: "Creator holds too much of the supply",
  bundled_launch: "Several wallets bought in the launch slot (bundled launch)",
  insider_share: "Creator plus launch-slot buyers hold too much of the supply",
  volume_from_one_wallet: "Most buy volume comes from one wallet",
  same_slot_cluster: "Many buyers in one slot (possible coordinated buying)",
  few_early_buyers: "Few early buyers",
  creator_selling: "Creator is selling",
  creator_unknown: "Creator wallet not provided, so creator checks were limited",
  serial_launcher: "Creator launched too many tokens in the last hour",
  creator_dumped_before: "Creator dumped a previous token",
  rugcheck_rugged: "RugCheck marks this token as rugged",
  rugcheck_creator_tokens: "RugCheck shows the creator launched many tokens",
  rugcheck_danger: "RugCheck reports a danger-level risk",
  rugcheck_warning: "RugCheck reports a risk",
  rugcheck_unavailable: "RugCheck could not be reached, so its checks were skipped",
  rugcheck_skipped: "RugCheck was turned off for this call",
  issuer_controlled_stablecoin: "Regulated stablecoin on the TPA allowlist (USDC, USDT or PYUSD): its issuer keeps these controls on purpose, so they are warnings, not blocks. Circle and Tether can freeze and mint. Paxos can freeze, mint, and move funds from holders (PYUSD permanent delegate).",
  trade_history_not_provided: "No pump.fun trade history was given, so holder concentration, bundles, sells and creator selling were not evaluated",
};

/** Map a gate reason or warning string to a stable code. */
export function tokenReasonCode(text: string): string {
  const rules: Array<[RegExp, string]> = [
    [/^mint_info_unavailable/, "mint_info_unavailable"], [/^mint_authority_active/, "mint_authority_active"],
    [/^freeze_authority_active/, "freeze_authority_active"], [/^token2022_/, "token2022_dangerous_extension"],
    [/^transfer_fee_/, "transfer_fee"], [/^curve_complete/, "curve_complete"], [/^sell_unverified/, "sell_unverified"],
    [/^top_holder_/, "top_holder_concentration"], [/^top5_holders_/, "top5_concentration"], [/^creator_holds_/, "creator_holds"],
    [/^bundled_launch_/, "bundled_launch"], [/^insider_share_/, "insider_share"], [/^volume_from_one_wallet_/, "volume_from_one_wallet"],
    [/^same_slot_cluster_/, "same_slot_cluster"], [/^few_early_buyers_/, "few_early_buyers"], [/^creator_selling_/, "creator_selling"],
    [/^creator_unknown/, "creator_unknown"], [/^serial_launcher_/, "serial_launcher"], [/^creator_dumped_before_/, "creator_dumped_before"],
    [/^rugcheck_rugged/, "rugcheck_rugged"], [/^rugcheck_creator_tokens_/, "rugcheck_creator_tokens"],
    [/^rugcheck_unavailable/, "rugcheck_unavailable"], [/^trade_history_not_provided/, "trade_history_not_provided"],
  ];
  for (const [pattern, code] of rules) if (pattern.test(text)) return code;
  return text.startsWith("rugcheck:") ? "rugcheck_warning" : text;
}
