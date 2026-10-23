import { canonicalTpaMandate, type TpaMandate } from "./domain.js";

export type TpaReviewIntent = { id: string; mandate: TpaMandate; mandateHash: string; state: string; expiresAtMs: number };

/** Refuse an action when the user-reviewed evidence differs from the latest server state. */
export function assertFreshTpaReview(reviewed: TpaReviewIntent, latest: TpaReviewIntent | undefined, action: "authorize" | "consume" | "revoke", nowMs: number): TpaReviewIntent {
  if (!latest || latest.id !== reviewed.id || latest.mandateHash !== reviewed.mandateHash || canonicalTpaMandate(latest.mandate) !== canonicalTpaMandate(reviewed.mandate) || latest.expiresAtMs !== reviewed.expiresAtMs || latest.state !== reviewed.state) {
    throw new Error("Request changed. Refresh and review it again.");
  }
  if (action !== "revoke" && latest.expiresAtMs <= nowMs) throw new Error("Request expired. Prepare a new request.");
  if ((action === "authorize" && latest.state !== "pending") || (action === "consume" && latest.state !== "authorized") || (action === "revoke" && !["pending", "authorized"].includes(latest.state))) {
    throw new Error("Request is no longer available for this action.");
  }
  return latest;
}
