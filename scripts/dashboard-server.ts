/**
 * Local viewer for the TPA security dashboard. Loopback only.
 * The audit log starts empty. This process does not invent checks, prices, or sample payments.
 * It authenticates one local owner so the page can read that empty log. Do not expose the port.
 */
import { existsSync, readFileSync } from "node:fs";
import { createServer } from "node:http";
import { dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";
import express from "express";
import { createTpaAuthority } from "../src/config.js";
import { createTpaExpressRouter } from "../src/http/express.js";
import { createTpaService } from "../src/service.js";
import { createMemoryTpaPersistence } from "./demo/memory-store.js";

const LOCAL_ORIGIN = "https://tpa.example.test";

export function createLocalDashboardApp(): { app: express.Express; memory: ReturnType<typeof createMemoryTpaPersistence>; owner: { principalId: number; sessionHash: string; owner: true } } {
  const owner = { principalId: 1, sessionHash: "c".repeat(64), owner: true as const };
  const memory = createMemoryTpaPersistence({ ownerIds: [owner.principalId] });
  const service = createTpaService({
    store: memory.store,
    evidence: memory.evidence,
    authority: createTpaAuthority({ enabled: true, origin: LOCAL_ORIGIN, rpID: "tpa.example.test" }),
  });
  const app = express();
  app.disable("x-powered-by");
  app.use("/tpa-api", createTpaExpressRouter(service, async () => owner));
  app.get(["/", "/dashboard"], (_request, response) => {
    const page = readDashboardPage();
    response.set({ "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer" });
    if (!page) return response.status(404).type("text/plain").send("Security dashboard page is missing.");
    response.type("html").send(page);
  });
  return { app, memory, owner };
}

export function readDashboardPage(): string | undefined {
  const here = dirname(fileURLToPath(import.meta.url));
  const path = [join(here, "../examples/security-dashboard.html"), join(here, "../../examples/security-dashboard.html")].find(candidate => existsSync(candidate));
  return path ? readFileSync(path, "utf8") : undefined;
}

function listen(): void {
  const port = Number(process.env.TPA_DASHBOARD_PORT ?? 4173);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    console.error("TPA_DASHBOARD_PORT must be an integer port.");
    process.exitCode = 1;
    return;
  }
  const { app } = createLocalDashboardApp();
  const server = createServer(app);
  server.on("error", () => {
    console.error(`Could not listen on 127.0.0.1:${port}.`);
    process.exitCode = 1;
  });
  server.listen(port, "127.0.0.1", () => {
    console.log(`TPA security dashboard: http://127.0.0.1:${port}/dashboard`);
    console.log("Audit log starts empty. This viewer does not invent checks.");
  });
}

const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) listen();
