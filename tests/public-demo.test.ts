import { mkdtempSync, readFileSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { buildSecurityDashboard } from "../src/dashboard.js";
import { createPublicDemoApp } from "../public-demo/app.js";
import { PublicDemoError, assertPublicDemoHost, contactLink, loadSiteConfig, operatorMessage, resolveListen } from "../public-demo/config.js";
import { PUBLIC_DEMO_LABEL, type PublicDemoSnapshot } from "../public-demo/run-demo.js";

const page = readFileSync(new URL("../public-demo/public.html", import.meta.url), "utf8");
const cleanDir = mkdtempSync(join(tmpdir(), "tpa-public-demo-"));

function stubSnapshot(source: "startup" | "sandbox"): PublicDemoSnapshot {
  return {
    mode: "public-demo",
    rail: "mock",
    label: PUBLIC_DEMO_LABEL,
    livePayments: false,
    source,
    scenarios: ["Passkey approval"],
    dashboard: buildSecurityDashboard({ audit: [], intents: [], nowMs: source === "startup" ? 10 : 99, auditAvailable: true }),
  };
}

async function listen(app: import("express").Express): Promise<{ base: string; close: () => Promise<void> }> {
  const server: Server = createServer(app);
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("no port");
  return {
    base: `http://127.0.0.1:${address.port}`,
    close: () => new Promise(resolve => { server.closeAllConnections(); server.close(() => resolve()); }),
  };
}

describe("public demo host guard", () => {
  it("refuses live rails and secret env without echoing the value", () => {
    expect(() => assertPublicDemoHost({ METAL_LIVE: "supersecret-value" }, cleanDir)).toThrow(PublicDemoError);
    try { assertPublicDemoHost({ AIRI_LIVE: "1" }, cleanDir); } catch (error) {
      expect(error).toMatchObject({ code: "env" });
      expect(String(error)).not.toContain("1");
      expect(operatorMessage(error)).not.toContain("supersecret-value");
    }
    expect(() => assertPublicDemoHost({ TPA_MANDATE_SIGNING_KEY: "not-a-real-key" }, cleanDir)).toThrow(PublicDemoError);
    expect(() => assertPublicDemoHost({ METAL_LIVE: "0", AIRI_LIVE: "false" }, cleanDir)).not.toThrow();
    expect(resolveListen({ PORT: "10000" })).toEqual({ host: "0.0.0.0", port: 10000 });
    expect(() => resolveListen({ PORT: "nope" })).toThrow(PublicDemoError);
  });

  it("refuses to boot beside an env file and does not read it", async () => {
    const dir = mkdtempSync(join(tmpdir(), "tpa-public-demo-env-"));
    writeFileSync(join(dir, ".env.metal-wallet"), "PAYER=do-not-print-this-wallet");
    await expect(createPublicDemoApp({ env: {}, cwd: dir, runDemo: async () => { throw new Error("should-not-run"); } })).rejects.toMatchObject({ code: "host-file" });
    expect(operatorMessage(new PublicDemoError("host-file"))).not.toContain("do-not-print-this-wallet");
  });
});

describe("public demo site config", () => {
  it("uses the owner pricing and X contact, and hides an empty contact link", () => {
    const config = loadSiteConfig();
    expect(config.pricing.freePilot).toBe("Free pilot");
    expect(config.pricing.paidPlans).toBe("Contact us for pricing");
    expect(contactLink(config)).toEqual({
      label: "DM @Saltymetax on X",
      href: "https://x.com/messages/compose?recipient_id=1957940007609724928",
    });
    expect(contactLink({ ...config, contact: { ...config.contact, href: "" } })).toBeNull();
    expect(config.video.href).toBe("");
  });
});

describe("public demo page", () => {
  it("keeps the brand, the mock-rail label, and the read-only API, with no sample amounts", () => {
    expect(page).toContain("Michael Moving Forward DingDong");
    expect(page).toContain("The only easy day was yesterday!");
    expect(page).toContain("Mock payment rail, real executed security checks.");
    expect(page).toContain("Green shield with a fingerprint and a checkmark, and a red bell");
    expect(page).toContain('fill="#2ea043"');
    expect(page).toContain('fill="#e5484d"');
    expect(page).toContain("/api/public-dashboard");
    expect(page).toContain("/api/public-demo/run");
    expect(page).toContain("Demo video link goes here.");
    expect(page).not.toContain("/tpa-api");
    expect(page).not.toMatch(/[\u2013\u2014]/);
    expect(page).not.toMatch(/\$\d/);
    expect(page).not.toMatch(/live Airwallex|live Metal|METAL_LIVE|price chart/i);
  });
});

describe("public demo HTTP", () => {
  let base: string;
  let close: () => Promise<void>;
  beforeAll(async () => {
    const created = await createPublicDemoApp({ env: {}, cwd: cleanDir });
    const server = await listen(created.app);
    base = server.base;
    close = server.close;
  });
  afterAll(async () => { await close(); });

  it("serves health, the page, and a sanitized startup snapshot from executed checks", async () => {
    const health = await fetch(`${base}/healthz`);
    expect(health.status).toBe(200);
    expect(health.headers.get("x-content-type-options")).toBe("nosniff");
    expect(health.headers.get("x-frame-options")).toBe("DENY");
    expect(await health.json()).toEqual({ ok: true, demo: "public", livePayments: false });
    const html = await fetch(`${base}/dashboard`);
    expect(html.status).toBe(200);
    expect(await html.text()).toContain("Get TPA");
    const site = await (await fetch(`${base}/api/public-site`)).json();
    expect(site.contact.href).toBe("https://x.com/messages/compose?recipient_id=1957940007609724928");
    expect(site.pricing.freePilot).toBe("Free pilot");
    const body = await (await fetch(`${base}/api/public-dashboard`)).json();
    expect(body).toMatchObject({
      mode: "public-demo",
      rail: "mock",
      label: PUBLIC_DEMO_LABEL,
      livePayments: false,
      source: "startup",
    });
    expect(body.dashboard.pillars.person).toMatchObject({ recorded: true, passed: 3, blocked: 0, passRate: 1 });
    expect(body.dashboard.pillars.permission).toMatchObject({ recorded: true, passed: 1, blocked: 3, passRate: 0.25 });
    expect(body.dashboard.pillars.presence.recorded).toBe(false);
    expect(body.dashboard.safety.rugPull).toMatchObject({ recorded: false, blocked: null });
    expect(body.dashboard.safety.honeypot).toMatchObject({ recorded: false, blocked: null });
    expect(body.dashboard.payments.some((row: { result: string; merchantText: string; amountText: string }) => row.result === "passed" && row.merchantText === "Acme Store" && row.amountText === "$37.80")).toBe(true);
    const reasons = body.dashboard.payments.map((row: { reasonCode: string | null }) => row.reasonCode);
    expect(reasons).toEqual(expect.arrayContaining(["terms_changed:merchant_mismatch", "terms_changed:items_mismatch", "intent"]));
    const names = new Set<string>();
    const walk = (value: unknown) => {
      if (Array.isArray(value)) value.forEach(walk);
      else if (value && typeof value === "object") for (const [key, child] of Object.entries(value)) { names.add(key); walk(child); }
    };
    walk(body);
    for (const key of ["nonce", "signature", "sessionHash", "challenge", "publicKey", "privateKey", "mandateHash", "keyId", "userId"]) expect(names.has(key)).toBe(false);
    expect(JSON.stringify(body)).not.toMatch(/[\u2013\u2014]/);
  });

  it("keeps the startup snapshot stable when a visitor runs a sandbox", async () => {
    const before = await (await fetch(`${base}/api/public-dashboard`)).json();
    const run = await fetch(`${base}/api/public-demo/run`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
    expect(run.status).toBe(200);
    const sandbox = await run.json();
    expect(sandbox.source).toBe("sandbox");
    expect(sandbox.dashboard.payments.some((row: { reasonCode: string | null }) => row.reasonCode === "terms_changed:merchant_mismatch")).toBe(true);
    const after = await (await fetch(`${base}/api/public-dashboard`)).json();
    expect(after.dashboard.generatedAtMs).toBe(before.dashboard.generatedAtMs);
    expect(after.source).toBe("startup");
  });

  it("does not expose authorize, consume, registration, or private audit routes", async () => {
    const paths = ["/tpa-api/authorize", "/tpa-api/consume", "/tpa-api/registration/options", "/tpa-api/registration/verify", "/tpa-api/audit", "/tpa-api/dashboard", "/audit", "/authorize", "/consume"];
    for (const path of paths) {
      const response = await fetch(`${base}${path}`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ consent: true, intentId: "a".repeat(64) }) });
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({ error: "Not found." });
    }
    expect((await fetch(`${base}/tpa-api/audit`)).status).toBe(404);
  });
});

describe("public demo limits and errors", () => {
  it("rate limits sandbox runs and does not log a thrown secret", async () => {
    const logs: string[] = [];
    const original = console.error;
    console.error = (message?: unknown) => { logs.push(String(message)); };
    try {
      const created = await createPublicDemoApp({
        env: {},
        cwd: cleanDir,
        rateLimit: { limit: 2, windowMs: 60_000 },
        runDemo: async source => {
          if (source === "sandbox") throw new Error("SUPER_SECRET_material");
          return stubSnapshot(source);
        },
      });
      const server = await listen(created.app);
      try {
        expect((await fetch(`${server.base}/api/public-demo/run`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status).toBe(503);
        expect((await fetch(`${server.base}/api/public-demo/run`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" })).status).toBe(503);
        const limited = await fetch(`${server.base}/api/public-demo/run`, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
        expect(limited.status).toBe(429);
        expect(limited.headers.get("retry-after")).toBeTruthy();
        const huge = await fetch(`${server.base}/api/public-demo/run`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ pad: "x".repeat(2000) }) });
        expect(huge.status).toBe(413);
        const dumped = logs.join("\n") + await limited.text() + await huge.text();
        expect(dumped).not.toContain("SUPER_SECRET_material");
      } finally {
        await server.close();
      }
    } finally {
      console.error = original;
    }
  });
});
