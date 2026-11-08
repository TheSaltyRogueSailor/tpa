import { generateKeyPairSync, randomBytes } from "node:crypto";
import { createTpaAuthority } from "../src/config.js";
import { isCheckoutMandate, type TpaCheckoutInput } from "../src/domain.js";
import { buildSecurityDashboard, type DashboardFeedItem, type DashboardIntent, type DashboardPaymentRow, type SecurityDashboard } from "../src/dashboard.js";
import { TpaServiceError, createTpaService } from "../src/service.js";
import { createTpaMandateSigner } from "../src/signing.js";
import type { TpaIntentPublic } from "../src/store.js";
import { createMemoryTpaPersistence } from "../scripts/demo/memory-store.js";
import { syntheticAuthenticator } from "../tests/support/authenticator.js";
import { PublicDemoError } from "./config.js";

const ORIGIN = "https://tpa.example.test";
const RP_ID = "tpa.example.test";

export const PUBLIC_DEMO_LABEL = "Mock payment rail, real executed security checks.";
export const PUBLIC_DEMO_SCENARIOS = [
  "Passkey approval",
  "Allowed mock payment",
  "Merchant swap blocked",
  "Price change blocked",
  "Replay blocked",
] as const;

export type PublicDemoSource = "startup" | "sandbox";
export type ReplayStep = {
  title: string;
  result: "passed" | "blocked";
  badge: "PASSED" | "BLOCKED";
  reason: string;
  detail: string;
  /** How many real decisive passes this step adds. Taken from the audit summary, not guessed. */
  passedDelta: number;
  blockedDelta: number;
};
export type ReplayPlan = { steps: ReplayStep[]; finish: string };
export type PublicDemoSnapshot = {
  mode: "public-demo";
  rail: "mock";
  label: typeof PUBLIC_DEMO_LABEL;
  livePayments: false;
  source: PublicDemoSource;
  scenarios: readonly string[];
  dashboard: SecurityDashboard;
  replay: ReplayPlan;
};

function joinDetail(parts: Array<string | null | undefined>): string {
  return parts.filter(part => typeof part === "string" && part.length > 0).join(" · ");
}

function blockedStep(title: string, row: DashboardPaymentRow): ReplayStep {
  return {
    title,
    result: "blocked",
    badge: "BLOCKED",
    reason: row.reasonText || row.reasonCode || "Blocked",
    detail: joinDetail([row.merchantText, row.amountText, row.reasonText || row.reasonCode]),
    passedDelta: 0,
    blockedDelta: 1,
  };
}

/** Ordered playback of the five demo checks, using only rows present in this run. */
export function buildReplay(dashboard: SecurityDashboard): ReplayPlan {
  const payments = dashboard.payments;
  const feed = dashboard.feed;
  const steps: ReplayStep[] = [];
  const personPass = feed.find(item => item.action === "authorized" && item.result === "passed");
  const personBlock = feed.find(item => item.action === "authorize" && item.result === "blocked");
  const person = dashboard.pillars.person;
  if (person.recorded && (personPass || personBlock)) {
    const shown: DashboardFeedItem = personPass ?? personBlock!;
    const passed = person.passed ?? 0;
    const blocked = person.blocked ?? 0;
    const ok = passed > 0;
    steps.push({
      title: "Passkey approval",
      result: ok ? "passed" : "blocked",
      badge: ok ? "PASSED" : "BLOCKED",
      reason: ok ? (shown.detail || "Allowed") : (shown.detail || "Blocked"),
      detail: joinDetail([shown.merchantText, shown.amountText, shown.detail]),
      passedDelta: passed,
      blockedDelta: blocked,
    });
  }
  const allowed = payments.find(row => row.result === "passed");
  if (allowed && dashboard.pillars.permission.recorded) {
    steps.push({
      title: "Allowed mock payment",
      result: "passed",
      badge: "PASSED",
      reason: "Allowed",
      detail: joinDetail([allowed.merchantText, allowed.amountText, "Allowed"]),
      passedDelta: dashboard.pillars.permission.passed ?? 0,
      blockedDelta: 0,
    });
  }
  const merchant = payments.find(row => row.reasonCode === "terms_changed:merchant_mismatch");
  const price = payments.find(row => row.reasonCode === "terms_changed:items_mismatch");
  const replay = payments.find(row => row.reasonCode === "intent");
  if (merchant) steps.push(blockedStep("Merchant swap blocked", merchant));
  if (price) steps.push(blockedStep("Price change blocked", price));
  if (replay) steps.push(blockedStep("Replay blocked", replay));
  const passed = dashboard.checks.passed;
  const blocked = dashboard.checks.blocked;
  const finish = passed == null || blocked == null
    ? "Done. Every check ran just now in a sandbox."
    : `Done: ${passed} passed, ${blocked} blocked. Every check ran just now in a sandbox.`;
  return { steps, finish };
}

const checkout: TpaCheckoutInput = {
  currency: "USD",
  recipient: "user:42",
  merchant: { id: "acme-store", name: "Acme Store" },
  items: [
    { sku: "MUG-01", qty: 2, unitPriceBaseUnits: "750" },
    { sku: "TEE-02", qty: 1, unitPriceBaseUnits: "1500" },
  ],
  shipping: { method: "standard", costBaseUnits: "500" },
  taxBaseUnits: "280",
  totalBaseUnits: "3780",
};

function dashboardIntent(intent: TpaIntentPublic): DashboardIntent {
  const mandate = intent.mandate;
  if (isCheckoutMandate(mandate)) return { id: intent.id, merchantName: mandate.merchant.name, amountBaseUnits: mandate.amountBaseUnits, currency: mandate.currency };
  return { id: intent.id, merchantName: null, amountBaseUnits: mandate.amountBaseUnits, currency: mandate.currency };
}

async function mustRefuse(operation: Promise<unknown>, code: string): Promise<void> {
  try {
    await operation;
  } catch (error) {
    if (error instanceof TpaServiceError && error.code === code) return;
    throw new PublicDemoError("seed");
  }
  throw new PublicDemoError("seed");
}

function assertExecuted(view: SecurityDashboard): void {
  const reasons = new Set(view.payments.map(row => row.reasonCode).filter((code): code is string => typeof code === "string"));
  const allowed = view.payments.some(row => row.result === "passed" && row.merchantText === "Acme Store" && row.amountText === "$37.80");
  if (!view.auditAvailable || view.pillars.presence.recorded || view.safety.rugPull.recorded || view.safety.honeypot.recorded) throw new PublicDemoError("seed");
  if ((view.pillars.person.passed ?? 0) < 1 || (view.pillars.permission.passed ?? 0) < 1 || (view.pillars.permission.blocked ?? 0) < 3) throw new PublicDemoError("seed");
  if (!allowed || !reasons.has("terms_changed:merchant_mismatch") || !reasons.has("terms_changed:items_mismatch") || !reasons.has("intent")) throw new PublicDemoError("seed");
}

/**
 * Runs the mock demo against the real TPA service and returns only the sanitized dashboard.
 * The in-memory signer, passkey, and raw audit rows never leave this function.
 */
export async function runPublicDemo(source: PublicDemoSource): Promise<PublicDemoSnapshot> {
  const owner = { principalId: 1, sessionHash: randomBytes(32).toString("hex"), owner: true as const };
  const memory = createMemoryTpaPersistence({ ownerIds: [owner.principalId] });
  const signer = createTpaMandateSigner({ activeKeyId: "tpa-public-demo", privateKey: generateKeyPairSync("ed25519").privateKey });
  const service = createTpaService({
    store: memory.store,
    evidence: memory.evidence,
    signer,
    authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }),
  });
  const context = { owner, headers: { origin: ORIGIN } };
  const device = syntheticAuthenticator(ORIGIN, RP_ID);
  const registration = await service.registrationOptions(context, { label: "Public demo passkey", consent: true });
  await service.registrationVerify(context, { ceremonyId: registration.ceremonyId, response: device.register(registration.options.challenge) });

  async function approved() {
    const intent = await service.createIntent(context, { ...checkout, consent: true });
    const prompt = await service.authenticationOptions(context, { intentId: intent.id, consent: true });
    await service.authorize(context, { intentId: intent.id, ceremonyId: prompt.ceremonyId, response: device.assert(prompt.options.challenge), consent: true });
    return intent;
  }

  const paid = await approved();
  await service.consume(context, { intentId: paid.id, consent: true, checkout });
  const swapped = await approved();
  await mustRefuse(service.consume(context, {
    intentId: swapped.id,
    consent: true,
    checkout: { ...checkout, merchant: { id: "evil-store", name: "Evil Store" } },
  }), "terms_changed");
  const repriced = await approved();
  await mustRefuse(service.consume(context, {
    intentId: repriced.id,
    consent: true,
    checkout: {
      ...checkout,
      items: [checkout.items[0]!, { ...checkout.items[1]!, unitPriceBaseUnits: "1750" }],
      totalBaseUnits: "4030",
    },
  }), "terms_changed");
  await mustRefuse(service.consume(context, { intentId: paid.id, consent: true, checkout }), "intent");

  const audit = await memory.evidence.listAudit({ userId: owner.principalId, limit: 500 });
  const status = await memory.store.tpaStatus({ userId: owner.principalId, sessionHash: owner.sessionHash, origin: ORIGIN });
  const dashboard = buildSecurityDashboard({
    audit,
    intents: status.intents.map(dashboardIntent),
    nowMs: Date.now(),
    auditAvailable: true,
  });
  assertExecuted(dashboard);
  return {
    mode: "public-demo",
    rail: "mock",
    label: PUBLIC_DEMO_LABEL,
    livePayments: false,
    source,
    scenarios: PUBLIC_DEMO_SCENARIOS,
    dashboard,
    replay: buildReplay(dashboard),
  };
}
