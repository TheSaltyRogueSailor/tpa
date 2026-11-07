import { generateKeyPairSync } from "node:crypto";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { readFileSync } from "node:fs";
import express from "express";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createTpaAuthority } from "../src/config.js";
import { DASHBOARD_FEED_LIMIT, buildSecurityDashboard, type DashboardAuditEvent, type DashboardIntent } from "../src/dashboard.js";
import { createTpaExpressRouter } from "../src/http/express.js";
import { createTpaService, type TpaService } from "../src/service.js";
import { createTpaMandateSigner } from "../src/signing.js";
import type { TpaCheckoutInput } from "../src/domain.js";
import { createMemoryTpaPersistence } from "../scripts/demo/memory-store.js";
import { createLocalDashboardApp } from "../scripts/dashboard-server.js";
import { syntheticAuthenticator } from "./support/authenticator.js";

const page = readFileSync(new URL("../examples/security-dashboard.html", import.meta.url), "utf8");
const at = 1_700_000_000_000;

function event(partial: Partial<DashboardAuditEvent> & Pick<DashboardAuditEvent, "id" | "action" | "outcome">): DashboardAuditEvent {
  return { intentId: partial.intentId ?? null, reasonCode: partial.reasonCode ?? "ok", atMs: partial.atMs ?? at, ...partial };
}

describe("security dashboard aggregation", () => {
  it("keeps every unrecorded source blank when the audit log is empty", () => {
    const view = buildSecurityDashboard({ audit: [], intents: [], nowMs: at, auditAvailable: true });
    expect(view.checks).toMatchObject({ recorded: true, passed: 0, blocked: 0 });
    expect(view.pillars.person).toMatchObject({ recorded: true, passed: 0, blocked: 0, passRate: null });
    expect(view.pillars.permission.passRate).toBeNull();
    expect(view.pillars.presence).toMatchObject({ recorded: false, passed: null, blocked: null, passRate: null });
    expect(view.safety.rugPull).toMatchObject({ recorded: false, blocked: null });
    expect(view.safety.honeypot).toMatchObject({ recorded: false, blocked: null });
    expect(view.feed).toEqual([]);
    expect(view.payments).toEqual([]);
    expect(JSON.stringify(view)).not.toMatch(/[\u2013\u2014]/);
  });

  it("does not turn a missing audit log into a clean zero", () => {
    const view = buildSecurityDashboard({ audit: [], intents: [], nowMs: at, auditAvailable: false });
    expect(view.auditAvailable).toBe(false);
    expect(view.checks).toMatchObject({ recorded: false, passed: null, blocked: null });
    expect(view.pillars.person.recorded).toBe(false);
    expect(view.pillars.permission.recorded).toBe(false);
    expect(view.pillars.presence.recorded).toBe(false);
  });

  it("counts person and permission from audit rows and joins merchant and amount", () => {
    const intents: DashboardIntent[] = [
      { id: "a".repeat(64), merchantName: "Acme Store", amountBaseUnits: "3780", currency: "USD" },
      { id: "b".repeat(64), merchantName: null, amountBaseUnits: "100", currency: "DOGE" },
    ];
    const view = buildSecurityDashboard({
      nowMs: at, auditAvailable: true, intents,
      audit: [
        event({ id: 1, intentId: "a".repeat(64), action: "intent_created", outcome: "approved", atMs: at }),
        event({ id: 2, intentId: "a".repeat(64), action: "authorized", outcome: "approved", atMs: at + 1 }),
        event({ id: 3, intentId: "a".repeat(64), action: "consume", outcome: "attempt", reasonCode: "pending", atMs: at + 2 }),
        event({ id: 4, intentId: "a".repeat(64), action: "consumed", outcome: "approved", atMs: at + 3 }),
        event({ id: 5, intentId: "a".repeat(64), action: "consume", outcome: "refused", reasonCode: "terms_changed:merchant_mismatch", atMs: at + 4 }),
        event({ id: 6, intentId: "b".repeat(64), action: "authorize", outcome: "refused", reasonCode: "challenge_unbound", atMs: at + 5 }),
        event({ id: 7, intentId: "c".repeat(64), action: "consumed", outcome: "approved", atMs: at + 6 }),
      ],
    });
    expect(view.pillars.person).toMatchObject({ passed: 1, blocked: 1, passRate: 0.5 });
    expect(view.pillars.permission).toMatchObject({ passed: 2, blocked: 1, passRate: 0.6667 });
    expect(view.checks).toMatchObject({ passed: 3, blocked: 2 });
    expect(view.feed[0]).toMatchObject({ id: 7, merchantText: "Not in recent intents", amountText: "Not in recent intents", result: "passed" });
    expect(view.payments.map(row => [row.id, row.result, row.merchantText, row.amountText, row.reasonText])).toEqual([
      [7, "passed", "Not in recent intents", "Not in recent intents", null],
      [6, "blocked", "Not on mandate", "0.00000100 DOGE", "Passkey prompt was not tied to this mandate"],
      [5, "blocked", "Acme Store", "$37.80", "Merchant changed after approval"],
      [4, "passed", "Acme Store", "$37.80", null],
    ]);
    expect(view.feed.some(row => row.action === "consume" && row.result === "pending")).toBe(true);
    expect(view.payments.some(row => row.id === 3)).toBe(false);
    expect(view.pillars.presence.recorded).toBe(false);
    expect(view.safety.rugPull.recorded).toBe(false);
    expect(view.safety.honeypot.recorded).toBe(false);
  });

  it("counts a stored presence or honeypot result and still leaves the other safety check blank", () => {
    const view = buildSecurityDashboard({
      nowMs: at, auditAvailable: true, intents: [],
      audit: [
        event({ id: 1, action: "tap", outcome: "approved", reasonCode: "ok", atMs: at }),
        event({ id: 2, action: "tap", outcome: "refused", reasonCode: "nonce_replayed", atMs: at + 1 }),
        event({ id: 3, action: "safety", outcome: "refused", reasonCode: "honeypot", atMs: at + 2 }),
      ],
    });
    expect(view.pillars.presence).toMatchObject({ recorded: true, passed: 1, blocked: 1, passRate: 0.5 });
    expect(view.safety.honeypot).toMatchObject({ recorded: true, blocked: 1 });
    expect(view.safety.rugPull).toMatchObject({ recorded: false, blocked: null });
    expect(view.checks.blocked).toBe(2);
    expect(view.payments.filter(row => row.reasonCode === "honeypot")).toHaveLength(1);
    expect(view.payments.some(row => row.reasonCode === "nonce_replayed")).toBe(false);
  });

  it("truncates the feed without dropping the totals", () => {
    const audit = Array.from({ length: DASHBOARD_FEED_LIMIT + 1 }, (_, index) => event({ id: index + 1, action: "authorized", outcome: "approved", atMs: at + index }));
    const view = buildSecurityDashboard({ audit, intents: [], nowMs: at, auditAvailable: true });
    expect(view.feed).toHaveLength(DASHBOARD_FEED_LIMIT);
    expect(view.feedTruncated).toBe(true);
    expect(view.feed[0]?.id).toBe(DASHBOARD_FEED_LIMIT + 1);
    expect(view.pillars.person.passed).toBe(DASHBOARD_FEED_LIMIT + 1);
  });
});

describe("security dashboard page", () => {
  it("polls the audit API, uses the shield and bell, and does not ship sample numbers", () => {
    expect(page).toContain("/tpa-api/dashboard");
    expect(page).toContain('fill="#2ea043"');
    expect(page).toContain('fill="#e5484d"');
    expect(page).toContain("Not recorded");
    expect(page).toContain("No checks yet");
    expect(page).toContain("Reading the audit log.");
    expect(page).not.toMatch(/[\u2013\u2014]/);
    expect(page).not.toMatch(/\$\d/);
    expect(page).not.toMatch(/price chart|trading pair|candlestick|lightweight-charts|chart\.js/i);
    expect(page).toContain("No token prices and no trading.");
  });
});

describe("security dashboard HTTP", () => {
  const origin = "https://tpa.example.test";
  const owner = { principalId: 1, sessionHash: "a".repeat(64), owner: true as const };
  const headers = { origin };
  let server: Server;
  let base: string;
  let current: typeof owner | undefined;
  let memory: ReturnType<typeof createMemoryTpaPersistence>;
  let service: TpaService;
  const checkout: TpaCheckoutInput = {
    currency: "USD", recipient: "user:42", merchant: { id: "acme-store", name: "Acme Store" },
    items: [{ sku: "MUG-01", qty: 2, unitPriceBaseUnits: "750" }, { sku: "TEE-02", qty: 1, unitPriceBaseUnits: "1500" }],
    shipping: { method: "standard", costBaseUnits: "500" }, taxBaseUnits: "280", totalBaseUnits: "3780",
  };

  beforeAll(async () => {
    memory = createMemoryTpaPersistence({ ownerIds: [owner.principalId] });
    const signer = createTpaMandateSigner({ activeKeyId: "dashboard-test", privateKey: generateKeyPairSync("ed25519").privateKey });
    service = createTpaService({ store: memory.store, evidence: memory.evidence, signer, authority: createTpaAuthority({ enabled: true, origin, rpID: "tpa.example.test" }) });
    const device = syntheticAuthenticator(origin, "tpa.example.test");
    const context = { owner, headers };
    const registration = await service.registrationOptions(context, { label: "Dashboard test", consent: true });
    await service.registrationVerify(context, { ceremonyId: registration.ceremonyId, response: device.register(registration.options.challenge) });
    async function approvedIntent() {
      const intent = await service.createIntent(context, { ...checkout, consent: true });
      const prompt = await service.authenticationOptions(context, { intentId: intent.id, consent: true });
      await service.authorize(context, { intentId: intent.id, ceremonyId: prompt.ceremonyId, response: device.assert(prompt.options.challenge), consent: true });
      return intent;
    }
    await service.consume(context, { intentId: (await approvedIntent()).id, consent: true, checkout });
    const swapped = { ...checkout, merchant: { id: "evil-store", name: "Evil Store" } };
    await service.consume(context, { intentId: (await approvedIntent()).id, consent: true, checkout: swapped }).catch(error => {
      if (!error || (error as { code?: string }).code !== "terms_changed") throw error;
    });
    const app = express();
    app.use("/tpa-api", createTpaExpressRouter(service, async () => current));
    server = createServer(app);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}/tpa-api`;
  });
  afterAll(async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); });

  it("requires an owner and does not read the log anonymously", async () => {
    current = undefined;
    const listAudit = vi.spyOn(memory.evidence, "listAudit");
    const response = await fetch(`${base}/dashboard`);
    expect(response.status).toBe(401);
    expect(listAudit).not.toHaveBeenCalled();
    listAudit.mockRestore();
  });

  it("returns the real run: one allowed payment, one merchant change blocked, no invented safety counts", async () => {
    current = owner;
    const response = await fetch(`${base}/dashboard`, { headers: { origin } });
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.auditAvailable).toBe(true);
    expect(body.pillars.person).toMatchObject({ recorded: true, passed: 2, blocked: 0, passRate: 1 });
    expect(body.pillars.permission).toMatchObject({ recorded: true, passed: 1, blocked: 1, passRate: 0.5 });
    expect(body.pillars.presence.recorded).toBe(false);
    expect(body.safety.rugPull.blocked).toBeNull();
    expect(body.safety.honeypot.blocked).toBeNull();
    expect(body.payments[0]).toMatchObject({
      result: "blocked", merchantText: "Acme Store", amountText: "$37.80", reasonCode: "terms_changed:merchant_mismatch", reasonText: "Merchant changed after approval",
    });
    expect(body.payments.some((row: { result: string; amountText: string }) => row.result === "passed" && row.amountText === "$37.80")).toBe(true);
    const dumped = JSON.stringify(body);
    expect(dumped).not.toContain(owner.sessionHash);
    for (const secret of memory.secretValues()) expect(dumped).not.toContain(secret);
    const names = new Set<string>();
    const walk = (value: unknown) => {
      if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === "object") for (const [key, child] of Object.entries(value)) { names.add(key); walk(child); }
    };
    walk(body);
    for (const key of ["nonce", "signature", "sessionHash", "challenge", "publicKey", "mandateJson"]) expect(names.has(key)).toBe(false);
    expect(dumped).not.toMatch(/[\u2013\u2014]/);
  });

  it("rejects a limit that is not an integer from 1 to 500", async () => {
    current = owner;
    expect((await fetch(`${base}/dashboard?limit=0`)).status).toBe(400);
    expect((await fetch(`${base}/dashboard?limit=501`)).status).toBe(400);
    expect((await fetch(`${base}/dashboard?limit=nope`)).status).toBe(400);
  });
});

describe("local dashboard viewer", () => {
  let server: Server;
  let base: string;
  const started = createLocalDashboardApp();

  beforeAll(async () => {
    server = createServer(started.app);
    server.listen(0, "127.0.0.1");
    await once(server, "listening");
    base = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
  });
  afterAll(async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); });

  it("starts from a real empty audit log and then shows a check only after one is stored", async () => {
    const first = await (await fetch(`${base}/tpa-api/dashboard`)).json();
    expect(first.checks).toMatchObject({ recorded: true, passed: 0, blocked: 0 });
    expect(first.safety.honeypot.recorded).toBe(false);
    expect(first.payments).toEqual([]);
    await started.memory.evidence.audit({ userId: started.owner.principalId, intentId: null, action: "safety", outcome: "refused", reasonCode: "honeypot", atMs: at });
    const second = await (await fetch(`${base}/tpa-api/dashboard`)).json();
    expect(second.safety.honeypot).toMatchObject({ recorded: true, blocked: 1 });
    expect(second.safety.rugPull.recorded).toBe(false);
    expect(second.checks.blocked).toBe(1);
    const html = await (await fetch(`${base}/dashboard`)).text();
    expect(html).toContain("TPA Security");
    expect(html).not.toContain(started.owner.sessionHash);
    expect(html).not.toContain("$37.80");
  });
});
