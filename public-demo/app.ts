import { readFileSync } from "node:fs";
import express, { type NextFunction, type Request, type Response } from "express";
import { PublicDemoError, assertPublicDemoHost, contactLink, loadSiteConfig, resolvePublicFile, type SiteConfig } from "./config.js";
import { runPublicDemo, type PublicDemoSnapshot } from "./run-demo.js";

const FORBIDDEN_KEYS = new Set(["nonce", "signature", "sessionHash", "challenge", "publicKey", "privateKey", "mandateHash", "keyId", "credentialId", "bindingNonce", "mandateJson", "userId", "payerKey"]);
const MAX_RESPONSE_CHARS = 200_000;

export type PublicDemoAppOptions = {
  env?: NodeJS.ProcessEnv;
  cwd?: string;
  config?: SiteConfig;
  rateLimit?: { limit: number; windowMs: number };
  runDemo?: (source: "startup" | "sandbox") => Promise<PublicDemoSnapshot>;
};

type Bucket = { hits: number[]; running: boolean };

export function createRateLimiter(options: { limit: number; windowMs: number; maxKeys?: number }) {
  const buckets = new Map<string, Bucket>();
  return {
    tryAcquire(key: string, now = Date.now()): { ok: true } | { ok: false; retryAfterSeconds: number } {
      let bucket = buckets.get(key);
      if (!bucket) {
        if (buckets.size >= (options.maxKeys ?? 2_000)) {
          const oldest = buckets.keys().next().value;
          if (oldest !== undefined) buckets.delete(oldest);
        }
        bucket = { hits: [], running: false };
        buckets.set(key, bucket);
      }
      bucket.hits = bucket.hits.filter(hit => now - hit < options.windowMs);
      if (bucket.running || bucket.hits.length >= options.limit) {
        const oldestHit = bucket.hits[0] ?? now;
        return { ok: false, retryAfterSeconds: Math.max(1, Math.ceil((options.windowMs - (now - oldestHit)) / 1000)) };
      }
      bucket.hits.push(now);
      bucket.running = true;
      return { ok: true };
    },
    release(key: string): void {
      const bucket = buckets.get(key);
      if (bucket) bucket.running = false;
    },
  };
}

function logFailure(error: unknown): void {
  const name = error instanceof Error ? error.name : "Error";
  console.error(`public-demo failure: ${name}`);
}

function sanitize(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(sanitize);
  if (value && typeof value === "object") {
    const out: Record<string, unknown> = {};
    for (const [key, child] of Object.entries(value)) {
      if (FORBIDDEN_KEYS.has(key)) continue;
      out[key] = sanitize(child);
    }
    return out;
  }
  return value;
}

function sendJson(response: Response, status: number, body: unknown): void {
  const encoded = JSON.stringify(sanitize(body));
  if (encoded.length > MAX_RESPONSE_CHARS) {
    response.status(500).json({ error: "The public demo could not finish that request." });
    return;
  }
  response.status(status).type("json").send(encoded);
}

function clientKey(request: Request): string {
  const address = request.ip || request.socket.remoteAddress || "unknown";
  return address.slice(0, 128);
}

export async function createPublicDemoApp(options: PublicDemoAppOptions = {}): Promise<{ app: express.Express }> {
  assertPublicDemoHost(options.env ?? process.env, options.cwd ?? process.cwd());
  const config = options.config ?? loadSiteConfig();
  const runDemo = options.runDemo ?? runPublicDemo;
  let startup: PublicDemoSnapshot;
  try {
    startup = await runDemo("startup");
  } catch (error) {
    logFailure(error);
    if (error instanceof PublicDemoError) throw error;
    throw new PublicDemoError("seed");
  }
  const page = readFileSync(resolvePublicFile("public.html"), "utf8");
  const limiter = createRateLimiter({ limit: options.rateLimit?.limit ?? 6, windowMs: options.rateLimit?.windowMs ?? 600_000 });
  const app = express();
  app.disable("x-powered-by");
  app.set("trust proxy", 1);
  app.use((_request, response, next) => {
    response.set({
      "Cache-Control": "no-store",
      "X-Content-Type-Options": "nosniff",
      "X-Frame-Options": "DENY",
      "Referrer-Policy": "no-referrer",
      "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
      "Content-Security-Policy": "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      "Cross-Origin-Opener-Policy": "same-origin",
      "Cross-Origin-Resource-Policy": "same-origin",
    });
    next();
  });

  app.get("/healthz", (_request, response) => {
    sendJson(response, 200, { ok: true, demo: "public", livePayments: false });
  });
  app.get("/api/public-site", (_request, response) => {
    sendJson(response, 200, { pricing: config.pricing, contact: contactLink(config), video: config.video });
  });
  app.get("/api/public-dashboard", (_request, response) => {
    sendJson(response, 200, startup);
  });
  app.post("/api/public-demo/run", express.json({ limit: 1024, strict: true }), async (request, response) => {
    const length = Number(request.headers["content-length"] ?? 0);
    if (Number.isFinite(length) && length > 1024) {
      sendJson(response, 413, { error: "Request is too large." });
      return;
    }
    const key = clientKey(request);
    const slot = limiter.tryAcquire(key);
    if (!slot.ok) {
      response.set("Retry-After", String(slot.retryAfterSeconds));
      sendJson(response, 429, { error: "Too many demo runs. Wait and try again." });
      return;
    }
    try {
      sendJson(response, 200, await runDemo("sandbox"));
    } catch (error) {
      logFailure(error);
      sendJson(response, 503, { error: "The demo run did not finish. No new checks were published." });
    } finally {
      limiter.release(key);
    }
  });
  app.get(["/", "/dashboard"], (_request, response) => {
    response.type("html").send(page);
  });
  app.use((error: unknown, _request: Request, response: Response, next: NextFunction) => {
    if (response.headersSent) return next(error);
    const type = error && typeof error === "object" && "type" in error ? String((error as { type: unknown }).type) : "";
    if (type === "entity.too.large") {
      sendJson(response, 413, { error: "Request is too large." });
      return;
    }
    logFailure(error);
    sendJson(response, 400, { error: "The public demo could not read that request." });
  });
  app.use((_request, response) => {
    sendJson(response, 404, { error: "Not found." });
  });
  return { app };
}
