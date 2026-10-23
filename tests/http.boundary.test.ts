import express from "express";
import { createServer, type Server } from "node:http";
import { once } from "node:events";
import { afterAll, beforeAll, describe, expect, it, vi } from "vitest";
import { createTpaAuthority } from "../src/config.js";
import { createTpaService } from "../src/service.js";
import { createTpaExpressRouter } from "../src/http/express.js";
import type { TpaAuthenticatedOwner } from "../src/host/contracts.js";
let server: Server, base: string;
let currentOwner: TpaAuthenticatedOwner | undefined;
const owner = { principalId: 1, sessionHash: "a".repeat(64), owner: true as const };
const store = { tpaStatus: vi.fn(async () => ({ credentials: [], intents: [] })), createIntent: vi.fn() } as any;
beforeAll(async () => {
  const service = createTpaService({ store, authority: createTpaAuthority({ enabled: true, origin: "https://tpa.example.test", rpID: "tpa.example.test" }) });
  const app = express(); app.use("/tpa-api", createTpaExpressRouter(service, async () => currentOwner));
  server = createServer(app); server.listen(0, "127.0.0.1"); await once(server, "listening"); base = `http://127.0.0.1:${(server.address() as { port: number }).port}/tpa-api`;
});
afterAll(async () => { server.closeAllConnections(); await new Promise<void>(resolve => server.close(() => resolve())); });
const payload = { currency: "USD", amountBaseUnits: "2000", recipient: "user:2", consent: true };
describe("standalone bounded HTTP host boundary", () => {
  it("does not accept forged client identity when no host session exists", async () => {
    currentOwner = undefined;
    const response = await fetch(`${base}/intents`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://tpa.example.test", "x-owner": "true" }, body: JSON.stringify({ ...payload, owner }) });
    expect(response.status).toBe(401); expect(store.createIntent).not.toHaveBeenCalled();
  });
  it("denies cross-origin mutation even with a trusted host identity", async () => {
    currentOwner = owner;
    const response = await fetch(`${base}/intents`, { method: "POST", headers: { "Content-Type": "application/json", Origin: "https://evil.example.test" }, body: JSON.stringify(payload) });
    expect(response.status).toBe(403); expect(store.createIntent).not.toHaveBeenCalled();
  });
  it("returns generic malformed-JSON errors without stacks or raw body reflection", async () => {
    const response = await fetch(`${base}/intents`, { method: "POST", headers: { "Content-Type": "application/json" }, body: '{"secret-fixture":' });
    expect(response.status).toBe(400); expect(await response.json()).toEqual({ error: "Invalid TPA request." });
  });
  it("enforces JSON-only mutation and the bounded body ceiling", async () => {
    expect((await fetch(`${base}/intents`, { method: "POST", headers: { "Content-Type": "text/plain" }, body: "test" })).status).toBe(415);
    expect((await fetch(`${base}/intents`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ fixture: "x".repeat(65536) }) })).status).toBe(413);
  });
  it("returns no-store/nosniff policy on status and rejects reflected untrusted origins without exposing records", async () => {
    const response = await fetch(`${base}/status`, { headers: { Origin: "https://evil.example.test" } });
    expect(response.headers.get("cache-control")).toContain("no-store"); expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(await response.json()).toMatchObject({ originMatches: false, credentials: [], intents: [] }); expect(store.tpaStatus).not.toHaveBeenCalled();
  });
});
