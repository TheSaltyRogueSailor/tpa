/**
 * TPA token gate thresholds (main venue).
 *
 * Ported from the TSRS TPA gate config (config/tpa-thresholds.json, version 1.1.0, effective 2026-10-29).
 * Only the main-venue thresholds the gate reads are kept. TPA Shield applies no environment
 * overrides: the values below are the policy. Change one only in a commit that bumps the version.
 */
import type { TpaConfig } from "./guard.js";

export const TOKEN_GATE_THRESHOLDS_VERSION = "1.1.0";
export const TOKEN_GATE_THRESHOLDS_EFFECTIVE = "2026-10-29";

export type ThresholdEntry = { field: keyof TpaConfig; value: number | boolean; direction: "higher_is_looser" | "higher_is_tighter" | "true_is_tighter"; unit: string };

export const TOKEN_GATE_THRESHOLDS: Readonly<Record<string, ThresholdEntry>> = {
  "TPA_MAX_TOP_HOLDER_PCT": {
    "field": "maxTopHolderPct",
    "value": 10,
    "direction": "higher_is_looser",
    "unit": "% of supply"
  },
  "TPA_MAX_TOP5_PCT": {
    "field": "maxTop5Pct",
    "value": 30,
    "direction": "higher_is_looser",
    "unit": "% of supply"
  },
  "TPA_MAX_CREATOR_HELD_PCT": {
    "field": "maxCreatorHeldPct",
    "value": 10,
    "direction": "higher_is_looser",
    "unit": "% of supply"
  },
  "TPA_BUNDLE_SLOTS": {
    "field": "bundleSlots",
    "value": 1,
    "direction": "higher_is_tighter",
    "unit": "slots after launch counted as bundle"
  },
  "TPA_MIN_BUNDLE_WALLETS": {
    "field": "minBundleWallets",
    "value": 3,
    "direction": "higher_is_looser",
    "unit": "wallets before a bundle can block"
  },
  "TPA_MAX_BUNDLE_PCT": {
    "field": "maxBundlePct",
    "value": 12,
    "direction": "higher_is_looser",
    "unit": "% of supply"
  },
  "TPA_MAX_INSIDER_PCT": {
    "field": "maxInsiderPct",
    "value": 25,
    "direction": "higher_is_looser",
    "unit": "% of supply"
  },
  "TPA_MAX_CREATOR_SOLD_PCT": {
    "field": "maxCreatorSoldPct",
    "value": 10,
    "direction": "higher_is_looser",
    "unit": "% of creator buys"
  },
  "TPA_MAX_CREATOR_LAUNCHES_PER_HOUR": {
    "field": "maxCreatorLaunchesPerHour",
    "value": 2,
    "direction": "higher_is_looser",
    "unit": "launches / h"
  },
  "TPA_MAX_CREATOR_PRIOR_DUMPS": {
    "field": "maxCreatorPriorDumps",
    "value": 0,
    "direction": "higher_is_looser",
    "unit": "dumps this session"
  },
  "TPA_EARLY_WINDOW_S": {
    "field": "earlyWindowS",
    "value": 10,
    "direction": "higher_is_looser",
    "unit": "s (warning only)"
  },
  "TPA_MIN_EARLY_BUYERS": {
    "field": "minEarlyBuyers",
    "value": 3,
    "direction": "higher_is_tighter",
    "unit": "buyers (warning only)"
  },
  "TPA_MAX_SINGLE_BUYER_VOL_PCT": {
    "field": "maxSingleBuyerVolPct",
    "value": 50,
    "direction": "higher_is_looser",
    "unit": "% of buy volume"
  },
  "TPA_SAME_SLOT_CLUSTER": {
    "field": "sameSlotCluster",
    "value": 4,
    "direction": "higher_is_looser",
    "unit": "buyers in one slot (warning only)"
  },
  "TPA_REQUIRE_OBSERVED_SELL": {
    "field": "requireObservedSell",
    "value": false,
    "direction": "true_is_tighter",
    "unit": "bool"
  },
  "TPA_RC_MAX_CREATOR_TOKENS": {
    "field": "rcMaxCreatorTokens",
    "value": 5,
    "direction": "higher_is_looser",
    "unit": "tokens (RugCheck)"
  },
  "TPA_RUGCHECK": {
    "field": "rugcheck",
    "value": true,
    "direction": "true_is_tighter",
    "unit": "bool (RugCheck enrichment on)"
  },
  "TPA_SINGLE_BUYER_BELOW_BUYERS": {
    "field": "singleBuyerBelowBuyers",
    "value": 10,
    "direction": "higher_is_tighter",
    "unit": "buyers (the one-wallet-volume rule applies while unique buyers < this)"
  },
  "TPA_DUMP_SOLD_FRACTION": {
    "field": "dumpSoldFraction",
    "value": 0.5,
    "direction": "higher_is_looser",
    "unit": "fraction of the creator's bought tokens sold = a dump"
  },
  "TPA_DUMP_WINDOW_S": {
    "field": "dumpWindowS",
    "value": 600,
    "direction": "higher_is_tighter",
    "unit": "s after launch in which a creator sell-off counts as a dump"
  }
};

/** The gate config built from the committed thresholds. */
export function tokenGateConfig(): TpaConfig {
  const config: Record<string, number | boolean> = {};
  for (const entry of Object.values(TOKEN_GATE_THRESHOLDS)) config[entry.field] = entry.value;
  return config as unknown as TpaConfig;
}
