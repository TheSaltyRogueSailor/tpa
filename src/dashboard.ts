import { formatBaseUnits } from "./domain.js";

/**
 * Security dashboard view, derived only from records the caller already stored.
 * It never fills a missing source with a sample, a zero that pretends a check ran, or a price.
 */

export const DASHBOARD_FEED_LIMIT = 40;
export const DASHBOARD_PAYMENT_LIMIT = 40;

export type DashboardAuditEvent = {
  id: number;
  intentId: string | null;
  action: string;
  outcome: string;
  reasonCode: string;
  atMs: number;
};

/** Narrow payment facts copied off a stored mandate. No nonce, signature, challenge, or session. */
export type DashboardIntent = {
  id: string;
  merchantName: string | null;
  amountBaseUnits: string | null;
  currency: "USD" | "DOGE" | null;
};

export type DashboardPillarId = "person" | "presence" | "permission";
export type DashboardPillarStat = {
  id: DashboardPillarId;
  label: string;
  /** False when this pillar's results are not in the records that were read. */
  recorded: boolean;
  passed: number | null;
  blocked: number | null;
  /** passed / (passed + blocked), four decimal places. Null when there is no decision. */
  passRate: number | null;
  note: string;
};

export type DashboardSafetyStat = {
  id: "rug_pull" | "honeypot";
  label: string;
  recorded: boolean;
  blocked: number | null;
  note: string;
};

export type DashboardFeedItem = {
  id: number;
  atMs: number;
  atUtc: string;
  action: string;
  outcome: string;
  reasonCode: string;
  pillar: DashboardPillarId | "safety" | "record";
  result: "passed" | "blocked" | "pending" | "info";
  resultLabel: string;
  merchantText: string;
  amountText: string;
  detail: string;
};

export type DashboardPaymentRow = {
  id: number;
  atMs: number;
  atUtc: string;
  amountText: string;
  merchantText: string;
  result: "passed" | "blocked";
  resultLabel: "Passed" | "Blocked";
  reasonCode: string | null;
  reasonText: string | null;
};

export type SecurityDashboard = {
  generatedAtMs: number;
  /** False when the audit log could not be read (evidence store not configured). */
  auditAvailable: boolean;
  checks: { recorded: boolean; passed: number | null; blocked: number | null; note: string };
  pillars: { person: DashboardPillarStat; presence: DashboardPillarStat; permission: DashboardPillarStat };
  safety: { rugPull: DashboardSafetyStat; honeypot: DashboardSafetyStat };
  feed: DashboardFeedItem[];
  feedTruncated: boolean;
  payments: DashboardPaymentRow[];
  paymentsTruncated: boolean;
  auditEvents: number;
  paymentNote: string;
};

const TAP_REASONS = new Set([
  "not_signed", "nonce_replayed", "bad_tag", "wrong_tag", "window_too_long", "unknown_key", "created_in_future",
  "container_missing_field", "container_nonce_mismatch", "container_kid_mismatch", "container_bad_signature",
]);

const REASON_TEXT: Readonly<Record<string, string>> = {
  intent: "Approval already used, missing, expired, or revoked",
  ceremony: "Passkey was not made for this purchase",
  challenge_unbound: "Passkey prompt was not tied to this mandate",
  credential: "No active passkey",
  forbidden: "Owner access was refused",
  unauthenticated: "No owner session",
  unavailable: "Authorization service was unavailable",
  rate: "Request limit reached",
  invalid: "Request was rejected",
  integrity: "Stored evidence failed integrity verification",
  "terms_changed:merchant_mismatch": "Merchant changed after approval",
  "terms_changed:items_mismatch": "Items or prices changed after approval",
  "terms_changed:shipping_mismatch": "Shipping changed after approval",
  "terms_changed:tax_mismatch": "Tax changed after approval",
  "terms_changed:total_mismatch": "Total changed after approval",
  "terms_changed:checkout_total_inconsistent": "Total does not match the approved items, shipping, and tax",
  "terms_changed:recipient_mismatch": "Recipient changed after approval",
  "terms_changed:currency_mismatch": "Currency changed after approval",
  "terms_changed:quote_mismatch": "Quote changed after approval",
  "terms_changed:fingerprint_mismatch": "Checkout fingerprint changed after approval",
  "terms_changed:quote_expired": "Quote or conversion expired",
  "terms_changed:checkout_required": "Checkout was not presented",
  "terms_changed:legacy_mismatch": "Transfer terms changed after approval",
  "mandate_signature_invalid:bad_signature": "Mandate signature does not verify",
  "mandate_signature_invalid:hash_mismatch": "Mandate was altered after signing",
  "mandate_signature_invalid:missing": "Mandate signature is missing",
  "mandate_signature_invalid:unknown_key": "Mandate signature key is unknown",
  "mandate_signature_invalid:evidence_not_configured": "Mandate signature evidence is not configured",
  "mandate_signature_invalid:signer_not_configured": "Mandate signer is not configured",
  not_signed: "Agent request was not signed",
  nonce_replayed: "Agent signature nonce was replayed",
  bad_tag: "Agent signature tag was rejected",
  wrong_tag: "Agent signature tag did not match this request",
  window_too_long: "Agent signature window was too long",
  unknown_key: "Agent signing key is unknown",
  created_in_future: "Agent signature time is in the future",
  container_missing_field: "Payment container is missing a field",
  container_nonce_mismatch: "Payment container nonce does not match",
  container_kid_mismatch: "Payment container key does not match",
  container_bad_signature: "Payment container signature does not verify",
};

const PRESENCE_ABSENT = "Visa TAP presence checks are not written to the TPA audit log.";
const RUG_ABSENT = "No rug-pull check is stored in the audit log.";
const HONEYPOT_ABSENT = "No honeypot check is stored in the audit log.";
const PAYMENT_NOTE = "Merchant and amount are read from mandates still in the owner status window. Older payments say Not in recent intents.";

type Classified = {
  kind: DashboardFeedItem["pillar"];
  result: DashboardFeedItem["result"];
  safety: "rug_pull" | "honeypot" | null;
};

function passRate(passed: number, blocked: number): number | null {
  const total = passed + blocked;
  if (total === 0) return null;
  return Math.round((passed * 10_000) / total) / 10_000;
}

function formatUtc(ms: number): string {
  if (!Number.isSafeInteger(ms) || ms < 0) return "Unknown time";
  return new Date(ms).toISOString().replace("T", " ").replace(/\.\d{3}Z$/, " UTC");
}

export function formatDashboardAmount(amountBaseUnits: string, currency: "USD" | "DOGE"): string {
  const formatted = formatBaseUnits(amountBaseUnits, currency);
  return currency === "USD" ? `$${formatted}` : `${formatted} DOGE`;
}

function describeReason(code: string): string {
  const known = REASON_TEXT[code];
  if (known) return known;
  if (code.startsWith("terms_changed:")) return "Checkout changed after approval";
  if (code.startsWith("mandate_signature_invalid")) return "Mandate signature did not verify";
  if (code.toLowerCase().includes("honeypot")) return "Honeypot check blocked the payment";
  if (/rug[_-]?pull|rugpull/i.test(code)) return "Rug-pull check blocked the payment";
  return code;
}

function safetyOf(action: string, reasonCode: string): "rug_pull" | "honeypot" | null {
  const text = `${action}:${reasonCode}`.toLowerCase();
  if (text.includes("honeypot")) return "honeypot";
  if (text.includes("rug_pull") || text.includes("rugpull") || text.includes("rug-pull")) return "rug_pull";
  return null;
}

function classify(event: DashboardAuditEvent): Classified {
  const safety = safetyOf(event.action, event.reasonCode);
  if (safety) {
    if (event.outcome === "refused") return { kind: "safety", result: "blocked", safety };
    if (event.outcome === "approved") return { kind: "safety", result: "passed", safety };
    return { kind: "safety", result: "pending", safety };
  }
  if (event.action === "authorized" && event.outcome === "approved") return { kind: "person", result: "passed", safety: null };
  if (event.action === "authorize" && event.outcome === "refused") return { kind: "person", result: "blocked", safety: null };
  if (event.action === "authorize") return { kind: "person", result: "pending", safety: null };
  if (event.action === "consumed" && event.outcome === "approved") return { kind: "permission", result: "passed", safety: null };
  if (event.action === "consume" && event.outcome === "refused") return { kind: "permission", result: "blocked", safety: null };
  if (event.action === "consume") return { kind: "permission", result: "pending", safety: null };
  if (event.action === "tap" || event.action === "presence" || TAP_REASONS.has(event.reasonCode)) {
    if (event.outcome === "approved") return { kind: "presence", result: "passed", safety: null };
    if (event.outcome === "refused") return { kind: "presence", result: "blocked", safety: null };
    return { kind: "presence", result: "pending", safety: null };
  }
  return { kind: "record", result: "info", safety: null };
}

function resultLabel(result: DashboardFeedItem["result"]): string {
  if (result === "passed") return "Passed";
  if (result === "blocked") return "Blocked";
  if (result === "pending") return "Pending";
  return "Recorded";
}

function lookupIntent(intents: ReadonlyMap<string, DashboardIntent>, intentId: string | null): DashboardIntent | undefined {
  if (!intentId) return undefined;
  return intents.get(intentId);
}

function merchantText(intent: DashboardIntent | undefined, intentId: string | null): string {
  if (!intentId) return "No intent";
  if (!intent) return "Not in recent intents";
  if (!intent.merchantName) return "Not on mandate";
  return intent.merchantName;
}

function amountText(intent: DashboardIntent | undefined, intentId: string | null): string {
  if (!intentId) return "No intent";
  if (!intent) return "Not in recent intents";
  if (!intent.amountBaseUnits || !intent.currency) return "Not on mandate";
  try { return formatDashboardAmount(intent.amountBaseUnits, intent.currency); }
  catch { return "Unreadable"; }
}

function pillarStat(id: DashboardPillarId, label: string, recorded: boolean, passed: number, blocked: number, absentNote: string, emptyNote: string): DashboardPillarStat {
  if (!recorded) return { id, label, recorded: false, passed: null, blocked: null, passRate: null, note: absentNote };
  const rate = passRate(passed, blocked);
  return { id, label, recorded: true, passed, blocked, passRate: rate, note: rate === null ? emptyNote : `${passed} passed, ${blocked} blocked.` };
}

function safetyStat(id: DashboardSafetyStat["id"], label: string, name: string, seen: boolean, blocked: number, absent: string): DashboardSafetyStat {
  if (!seen) return { id, label, recorded: false, blocked: null, note: absent };
  const attempt = blocked === 1 ? "attempt" : "attempts";
  return { id, label, recorded: true, blocked, note: `${blocked} blocked ${name} ${attempt} in the audit log.` };
}

function isPayment(kind: DashboardFeedItem["pillar"], result: DashboardFeedItem["result"]): boolean {
  if (kind === "permission" && (result === "passed" || result === "blocked")) return true;
  if (result === "blocked" && (kind === "person" || kind === "safety")) return true;
  return false;
}

/**
 * Fold audit rows and intent payment facts into the security dashboard.
 * `auditAvailable` false means the log was not read; counts stay null instead of looking like a clean zero.
 */
export function buildSecurityDashboard(input: {
  audit: readonly DashboardAuditEvent[];
  intents: readonly DashboardIntent[];
  nowMs: number;
  auditAvailable: boolean;
}): SecurityDashboard {
  const intents = new Map(input.intents.map(intent => [intent.id, intent]));
  const events = input.auditAvailable ? [...input.audit] : [];
  let personPassed = 0, personBlocked = 0, presencePassed = 0, presenceBlocked = 0, permissionPassed = 0, permissionBlocked = 0;
  let presenceSeen = false, rugSeen = false, honeypotSeen = false, rugBlocked = 0, honeypotBlocked = 0;
  const classified = events.map(event => {
    const row = classify(event);
    if (row.kind === "person" && row.result === "passed") personPassed += 1;
    if (row.kind === "person" && row.result === "blocked") personBlocked += 1;
    if (row.kind === "presence") {
      presenceSeen = true;
      if (row.result === "passed") presencePassed += 1;
      if (row.result === "blocked") presenceBlocked += 1;
    }
    if (row.kind === "permission" && row.result === "passed") permissionPassed += 1;
    if (row.kind === "permission" && row.result === "blocked") permissionBlocked += 1;
    if (row.safety === "rug_pull") {
      rugSeen = true;
      if (row.result === "blocked") rugBlocked += 1;
    }
    if (row.safety === "honeypot") {
      honeypotSeen = true;
      if (row.result === "blocked") honeypotBlocked += 1;
    }
    return { event, ...row };
  });

  const passed = personPassed + presencePassed + permissionPassed + classified.filter(row => row.kind === "safety" && row.result === "passed").length;
  const blocked = personBlocked + presenceBlocked + permissionBlocked + rugBlocked + honeypotBlocked;
  const checksRecorded = input.auditAvailable;
  const newest = classified.sort((a, b) => (b.event.atMs - a.event.atMs) || (b.event.id - a.event.id));

  const feed: DashboardFeedItem[] = newest.slice(0, DASHBOARD_FEED_LIMIT).map(({ event, kind, result }) => {
    const intent = lookupIntent(intents, event.intentId);
    const blockedDetail = result === "blocked" ? describeReason(event.reasonCode) : result === "pending" ? "Waiting for a decision" : result === "passed" ? "Allowed" : "Recorded";
    return {
      id: event.id, atMs: event.atMs, atUtc: formatUtc(event.atMs), action: event.action, outcome: event.outcome, reasonCode: event.reasonCode,
      pillar: kind, result, resultLabel: resultLabel(result), merchantText: merchantText(intent, event.intentId), amountText: amountText(intent, event.intentId), detail: blockedDetail,
    };
  });

  const paymentRows = newest.filter(row => isPayment(row.kind, row.result));
  const payments: DashboardPaymentRow[] = paymentRows.slice(0, DASHBOARD_PAYMENT_LIMIT).map(({ event, result }) => {
    const intent = lookupIntent(intents, event.intentId);
    const blocked = result === "blocked";
    return {
      id: event.id, atMs: event.atMs, atUtc: formatUtc(event.atMs),
      amountText: amountText(intent, event.intentId), merchantText: merchantText(intent, event.intentId),
      result: blocked ? "blocked" : "passed", resultLabel: blocked ? "Blocked" : "Passed",
      reasonCode: blocked ? event.reasonCode : null, reasonText: blocked ? describeReason(event.reasonCode) : null,
    };
  });

  return {
    generatedAtMs: input.nowMs,
    auditAvailable: input.auditAvailable,
    checks: {
      recorded: checksRecorded,
      passed: checksRecorded ? passed : null,
      blocked: checksRecorded ? blocked : null,
      note: checksRecorded
        ? (passed + blocked === 0
          ? "No decisive checks in the audit log yet."
          : "Passed and blocked count decisive checks stored in the audit log. A pillar stays blank until its own result is stored.")
        : "The audit log is not configured on this host.",
    },
    pillars: {
      person: pillarStat("person", "Person", input.auditAvailable, personPassed, personBlocked, "The audit log is not configured, so passkey decisions cannot be read.", "No passkey approval decisions in the audit log yet."),
      presence: pillarStat("presence", "Presence", presenceSeen, presencePassed, presenceBlocked, PRESENCE_ABSENT, "No presence decisions in the audit log yet."),
      permission: pillarStat("permission", "Permission", input.auditAvailable, permissionPassed, permissionBlocked, "The audit log is not configured, so exact-match decisions cannot be read.", "No exact-match decisions in the audit log yet."),
    },
    safety: {
      rugPull: safetyStat("rug_pull", "Rug pulls blocked", "rug-pull", rugSeen, rugBlocked, RUG_ABSENT),
      honeypot: safetyStat("honeypot", "Honeypots blocked", "honeypot", honeypotSeen, honeypotBlocked, HONEYPOT_ABSENT),
    },
    feed,
    feedTruncated: newest.length > DASHBOARD_FEED_LIMIT,
    payments,
    paymentsTruncated: paymentRows.length > DASHBOARD_PAYMENT_LIMIT,
    auditEvents: events.length,
    paymentNote: PAYMENT_NOTE,
  };
}
