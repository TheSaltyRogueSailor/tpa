import { existsSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";
import { z } from "zod";

export class PublicDemoError extends Error {
  constructor(readonly code: "env" | "host-file" | "config" | "seed" | "listen") {
    super(code);
    this.name = "PublicDemoError";
  }
}

const LIVE_OFF = new Set(["", "0", "false", "off", "no"]);
const SECRET_ENV = ["TPA_MANDATE_SIGNING_KEY", "TPA_DATABASE_URL", "TPA_TEST_DATABASE_URL", "TPA_DISPATCH_TEST_DATABASE_URL"] as const;
const HOST_FILES = [".env", ".env.metal", ".env.metal-wallet", ".env.metal-demo"] as const;

const httpsOrEmpty = z.string().max(300).refine(value => {
  if (value === "") return true;
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.username === "" && url.password === "";
  } catch {
    return false;
  }
}, "Contact and video links must be empty or https URLs without a username or password.");

export const siteConfigSchema = z.object({
  pricing: z.object({
    title: z.string().min(1).max(80),
    freePilot: z.string().min(1).max(120),
    paidPlans: z.string().min(1).max(200),
  }).strict(),
  contact: z.object({
    label: z.string().min(1).max(80),
    href: httpsOrEmpty,
  }).strict(),
  video: z.object({
    title: z.string().min(1).max(80),
    href: httpsOrEmpty,
  }).strict(),
}).strict();

export type SiteConfig = z.infer<typeof siteConfigSchema>;

export function liveFlagEnabled(value: string | undefined): boolean {
  if (value === undefined) return false;
  return !LIVE_OFF.has(value.trim().toLowerCase());
}

/** Refuse live rails and refuse to boot next to secret env or gitignored env files. Values are never copied into the error. */
export function assertPublicDemoHost(env: NodeJS.ProcessEnv, cwd: string): void {
  if (liveFlagEnabled(env.METAL_LIVE) || liveFlagEnabled(env.AIRI_LIVE)) throw new PublicDemoError("env");
  if (SECRET_ENV.some(name => typeof env[name] === "string" && env[name]!.trim() !== "")) throw new PublicDemoError("env");
  if (HOST_FILES.some(name => existsSync(join(cwd, name)))) throw new PublicDemoError("host-file");
}

export function operatorMessage(error: unknown): string {
  if (error instanceof PublicDemoError) {
    if (error.code === "env") return "Refusing to start because a live payment flag or a secret environment variable is set. This public demo does not run live rails and does not read secrets.";
    if (error.code === "host-file") return "Refusing to start because a local env file is present. This public demo does not read .env or wallet files.";
    if (error.code === "config") return "Refusing to start because public-demo/site-config.json is missing or invalid.";
    if (error.code === "seed") return "Refusing to start because the demo checks did not finish. No dashboard was published.";
    return "Refusing to start because PORT is not a valid port.";
  }
  return "Refusing to start the public demo.";
}

export function resolveListen(env: NodeJS.ProcessEnv): { host: "0.0.0.0"; port: number } {
  const raw = env.PORT ?? "4173";
  if (!/^[0-9]+$/.test(raw)) throw new PublicDemoError("listen");
  const port = Number(raw);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new PublicDemoError("listen");
  return { host: "0.0.0.0", port };
}

export function resolvePublicFile(fileName: "site-config.json" | "public.html"): string {
  const here = dirname(fileURLToPath(import.meta.url));
  const candidates = [
    join(here, fileName),
    join(here, "../../public-demo", fileName),
    join(process.cwd(), "public-demo", fileName),
  ];
  const found = candidates.find(candidate => existsSync(candidate));
  if (!found) throw new PublicDemoError("config");
  return found;
}

export function loadSiteConfig(path = resolvePublicFile("site-config.json")): SiteConfig {
  let parsed: unknown;
  try {
    parsed = JSON.parse(readFileSync(path, "utf8"));
  } catch {
    throw new PublicDemoError("config");
  }
  const result = siteConfigSchema.safeParse(parsed);
  if (!result.success) throw new PublicDemoError("config");
  return result.data;
}

export function contactLink(config: SiteConfig): { label: string; href: string } | null {
  if (config.contact.href === "") return null;
  return { label: config.contact.label, href: config.contact.href };
}
