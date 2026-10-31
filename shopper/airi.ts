/**
 * Airwallex Airi CLI client (Kit 09). Wraps `airi-cli` (@airwallex/airi-cli 0.1.0-beta.3) as documented by its --help
 * output and its bundled `airi-get-credential` agent skill:
 *
 *   auth whoami -> payment-methods list -> mandate create (pushes a passkey approval to the account owner)
 *   -> mandate get-credential --file <0600 path> (blocks until the owner approves; the one-time card is written to the
 *   file, stdout only shows {"status":"saved","tokenType","tokenExpiration"}) -> merchant checkout -> mandate result.
 *   mandate cancel (status becomes DENIED) when a checkout stops before the merchant is charged; mandate list to read
 *   what already happened (reconcile).
 *
 * Safety rules enforced here, not left to callers:
 *   - The binary is run with execFile (no shell), always with `-o json --no-telemetry`, and only for the subcommands
 *     in AIRI_ALLOWED_COMMANDS. Never `auth login/logout`: signing in is a human step.
 *   - get-credential ALWAYS uses --file; the credential never reaches stdout, this process' memory or any log. The
 *     caller gets only the file path (to hand to the checkout step) and must delete it (createAiriCredentialFile).
 *   - Payment methods are reduced to { id, brand, last4, nickname, expiry? } at parse time; nothing else is kept, and
 *     maskPaymentMethod() is the only form that should ever be logged or stored (brand + last4).
 *   - CLI stdout/stderr is never echoed into errors (it could carry account data); errors carry a reason code only.
 */
import { execFile } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

export class AiriCliError extends Error {
  constructor(readonly reason: AiriErrorReason, message: string) { super(message); this.name = "AiriCliError"; }
}
export type AiriErrorReason =
  | "airi_unauthenticated" | "airi_cli_failed" | "airi_bad_output" | "airi_approval_timeout" | "airi_command_refused" | "airi_invalid_input";

/** Subcommands this app may run. Login/logout are deliberately absent (a human signs in, see README). */
export const AIRI_ALLOWED_COMMANDS = [
  "auth whoami", "payment-methods list", "mandate create", "mandate get-credential", "mandate result", "mandate cancel", "mandate list",
] as const;
export type AiriCommand = (typeof AIRI_ALLOWED_COMMANDS)[number];

/** One CLI invocation. `args` never include the global -o/--no-telemetry flags; the runner adds them. */
export type AiriRunResult = { code: number; stdout: string; stderr: string; timedOut?: boolean };
export type AiriRunner = (command: AiriCommand, args: readonly string[], options?: { timeoutMs?: number }) => Promise<AiriRunResult>;

/**
 * Real runner: execFile on the airi-cli binary (default: `airi-cli` on PATH, or AIRI_CLI_BIN). No shell, no
 * inherited stdin, telemetry off, JSON output forced. The CLI keeps its own session file; this code never reads it.
 */
export function createAiriCliRunner(options: { bin?: string; env?: NodeJS.ProcessEnv } = {}): AiriRunner {
  const env = options.env ?? process.env;
  const bin = options.bin ?? env.AIRI_CLI_BIN ?? "airi-cli";
  return (command, args, run = {}) => new Promise(resolve => {
    if (!(AIRI_ALLOWED_COMMANDS as readonly string[]).includes(command)) {
      resolve({ code: 126, stdout: "", stderr: "command not allowed" });
      return;
    }
    const argv = [...command.split(" "), ...args, "-o", "json", "--no-telemetry"];
    execFile(bin, argv, { env: { ...env, AIRI_TELEMETRY_DISABLED: "1" }, timeout: run.timeoutMs ?? 60_000, maxBuffer: 1024 * 1024, windowsHide: true },
      (error, stdout, stderr) => {
        const e = error as (NodeJS.ErrnoException & { code?: number | string; killed?: boolean; signal?: string }) | null;
        resolve({ code: e ? (typeof e.code === "number" ? e.code : 1) : 0, stdout: String(stdout ?? ""), stderr: String(stderr ?? ""), timedOut: !!e?.killed });
      });
  });
}

/* ------------------------------------ shapes ------------------------------------ */
export type AiriWhoami = { authenticated: boolean; sessionExpires?: string; clientName?: string };
export type AiriPaymentMethod = { id: string; brand: string; last4: string; nickname?: string };
export type AiriMandateItem = { name: string; unitPrice: string; quantity: number };
export type AiriMandateInput = {
  source: string; paymentMethodId: string; merchantName: string; merchantUrl: string; merchantCountry: string;
  /** Major units, e.g. "42.00". */
  totalAmount: string; currency: string; items: readonly AiriMandateItem[]; description: string;
};
export type AiriMandate = { mandateId: string; passkeyUrl?: string; status?: string };
export type AiriCredentialReceipt = { status: "saved"; tokenType?: string; tokenExpiration?: string };
export type AiriTransactionResult = "SUCCEEDED" | "CANCELLED" | "DECLINED";
export type AiriMandateSummary = { mandateId: string; status: string; totalAmount?: string; currency?: string; merchantName?: string; createdAt?: string };
export const AIRI_MANDATE_STATUSES = ["CREATED", "AUTHENTICATED", "READY", "COMPLETED", "FAILED", "DENIED"] as const;

/** Safe display form of a payment method: brand and last 4 digits only. */
export const maskPaymentMethod = (pm: Pick<AiriPaymentMethod, "brand" | "last4">) => `${pm.brand || "card"} ****${pm.last4 || "????"}`;

const isObj = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);
/** Field lookup that accepts the CLI's snake_case and the API's camelCase spellings (both appear in the docs). */
function pick(o: Record<string, unknown>, ...keys: string[]): unknown {
  for (const k of keys) if (o[k] !== undefined && o[k] !== null) return o[k];
  return undefined;
}
const str = (v: unknown) => (typeof v === "string" ? v : typeof v === "number" ? String(v) : undefined);
const ID = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}$/;

/** Reduce one payment method to the four safe fields. Anything that looks like a full card number is discarded. */
export function parsePaymentMethod(raw: unknown): AiriPaymentMethod | null {
  if (!isObj(raw)) return null;
  const card = isObj(raw.card) ? raw.card : {};
  const id = str(pick(raw, "paymentMethodId", "payment_method_id", "id"));
  if (!id || !ID.test(id)) return null;
  const brand = str(pick(raw, "brand", "cardBrand", "card_brand", "scheme")) ?? str(pick(card, "brand", "scheme")) ?? "card";
  let last4 = str(pick(raw, "last4", "last_4", "lastFour", "last_four")) ?? str(pick(card, "last4", "last_4", "lastFour")) ?? "";
  if (!/^\d{4}$/.test(last4)) last4 = "";
  const nickname = str(pick(raw, "nickname", "nickName", "name"));
  return { id, brand: brand.slice(0, 32), last4, ...(nickname ? { nickname: nickname.slice(0, 64) } : {}) };
}

function json(result: AiriRunResult, what: string): unknown {
  try { return JSON.parse(result.stdout); } catch { throw new AiriCliError("airi_bad_output", `airi-cli ${what}: output was not JSON.`); }
}
const AUTH_HINT = /unauthenticated|not (signed|logged) in|token (is )?(expired|revoked)|session (has )?expired|auth login/i;
function check(result: AiriRunResult, what: string) {
  if (result.code === 126) throw new AiriCliError("airi_command_refused", `airi-cli ${what} is not an allowed command.`);
  if (result.code !== 0) {
    if (AUTH_HINT.test(result.stderr) || AUTH_HINT.test(result.stdout)) throw new AiriCliError("airi_unauthenticated", `airi-cli ${what}: the Airi session expired or was revoked; a human must run \`airi-cli auth login\`.`);
    throw new AiriCliError("airi_cli_failed", `airi-cli ${what} failed (exit ${result.code}${result.timedOut ? ", timed out" : ""}).`);
  }
}

/** cents -> "12.49" (Airi takes major units). */
export function centsToMajor(cents: string | bigint): string {
  const v = BigInt(cents);
  if (v < 0n) throw new AiriCliError("airi_invalid_input", "Negative amount.");
  return `${v / 100n}.${(v % 100n).toString().padStart(2, "0")}`;
}
/** Each --item value is name:<product>,unit_price:<price>,quantity:<n>; the CLI parses it with a regex, so refuse anything ambiguous. */
export function formatItem(item: AiriMandateItem): string {
  if (!/^[^\u0000-\u001f\u007f,:]{1,120}$/.test(item.name)) throw new AiriCliError("airi_invalid_input", "Item name must not contain commas, colons or control characters.");
  if (!/^\d+\.\d{2}$/.test(item.unitPrice)) throw new AiriCliError("airi_invalid_input", "Item unit price must be in major units with 2 decimals.");
  if (!Number.isInteger(item.quantity) || item.quantity < 1) throw new AiriCliError("airi_invalid_input", "Item quantity must be a positive integer.");
  return `name:${item.name},unit_price:${item.unitPrice},quantity:${item.quantity}`;
}
const flagSafe = (v: string, field: string) => {
  if (!v || /[\u0000-\u001f\u007f]/.test(v) || v.startsWith("-")) throw new AiriCliError("airi_invalid_input", `Invalid ${field}.`);
  return v;
};

export type AiriClient = ReturnType<typeof createAiriClient>;
export function createAiriClient(run: AiriRunner) {
  return {
    async whoami(): Promise<AiriWhoami> {
      const r = await run("auth whoami", []);
      check(r, "auth whoami");
      const o = json(r, "auth whoami");
      if (!isObj(o)) throw new AiriCliError("airi_bad_output", "airi-cli auth whoami: unexpected output.");
      return { authenticated: o.authenticated === true, sessionExpires: str(o.session_expires), clientName: str(o.client_name) };
    },
    async listPaymentMethods(): Promise<AiriPaymentMethod[]> {
      const r = await run("payment-methods list", []);
      check(r, "payment-methods list");
      const o = json(r, "payment-methods list");
      const list = Array.isArray(o) ? o : isObj(o) ? (pick(o, "items", "paymentMethods", "payment_methods", "data") ?? []) : [];
      if (!Array.isArray(list)) throw new AiriCliError("airi_bad_output", "airi-cli payment-methods list: unexpected output.");
      return list.map(parsePaymentMethod).filter((x): x is AiriPaymentMethod => x !== null);
    },
    /** Creates the mandate. This pushes a passkey approval to the Airi account owner: never call it in tests or dry runs. */
    async createMandate(input: AiriMandateInput): Promise<AiriMandate> {
      if (!input.items.length) throw new AiriCliError("airi_invalid_input", "At least one item is required.");
      if (!/^\d+\.\d{2}$/.test(input.totalAmount)) throw new AiriCliError("airi_invalid_input", "Total must be in major units with 2 decimals.");
      if (!/^[A-Z]{3}$/.test(input.currency)) throw new AiriCliError("airi_invalid_input", "Currency must be a 3-letter code.");
      if (!/^[A-Z]{2}$/.test(input.merchantCountry)) throw new AiriCliError("airi_invalid_input", "Merchant country must be a 2-letter code.");
      if (!/^https:\/\/[^\s]+$/.test(input.merchantUrl)) throw new AiriCliError("airi_invalid_input", "Merchant URL must be https.");
      const args = [
        "--source", flagSafe(input.source, "source"), "--payment-method-id", flagSafe(input.paymentMethodId, "payment method id"),
        "--merchant-name", flagSafe(input.merchantName, "merchant name"), "--merchant-url", input.merchantUrl, "--merchant-country", input.merchantCountry,
        "--total-amount", input.totalAmount, "--currency", input.currency,
        ...input.items.flatMap(i => ["--item", formatItem(i)]), "--description", flagSafe(input.description, "description"),
      ];
      const r = await run("mandate create", args);
      check(r, "mandate create");
      const o = json(r, "mandate create");
      const mandateId = isObj(o) ? str(pick(o, "mandate_id", "mandateId", "id")) : undefined;
      if (!isObj(o) || !mandateId || !ID.test(mandateId)) throw new AiriCliError("airi_bad_output", "airi-cli mandate create: no mandate id in the response.");
      const passkeyUrl = str(pick(o, "passkey_url", "passkeyUrl", "verification_url"));
      const status = str(pick(o, "status"));
      return { mandateId, ...(passkeyUrl ? { passkeyUrl } : {}), ...(status ? { status } : {}) };
    },
    /**
     * Blocks while the owner approves (CLI default: poll 2 s, give up after 300 s). Always writes the credential to
     * `file` (0600, refuses to overwrite or follow a symlink); stdout is only a receipt. A timeout is not a failure
     * per the skill ("the user has not confirmed yet"); it surfaces as airi_approval_timeout.
     */
    async getCredential(input: { mandateId: string; file: string; timeoutSeconds?: number; intervalSeconds?: number }): Promise<AiriCredentialReceipt> {
      const timeout = input.timeoutSeconds ?? 300;
      const args = ["--mandate-id", flagSafe(input.mandateId, "mandate id"), "--file", flagSafe(input.file, "credential file"),
        "--timeout", String(timeout), "--interval", String(input.intervalSeconds ?? 2)];
      const r = await run("mandate get-credential", args, { timeoutMs: (timeout + 30) * 1000 });
      if (r.code !== 0 && (r.timedOut || /timed out after/i.test(r.stderr) || /timed out after/i.test(r.stdout))) {
        throw new AiriCliError("airi_approval_timeout", "The Airi owner has not approved the mandate yet (get-credential timed out); nothing was written.");
      }
      check(r, "mandate get-credential");
      const o = json(r, "mandate get-credential");
      if (!isObj(o) || o.status !== "saved") throw new AiriCliError("airi_bad_output", "airi-cli mandate get-credential: expected a {\"status\":\"saved\"} receipt.");
      // Keep only the documented receipt fields; anything else is dropped unread.
      return { status: "saved", ...(str(o.tokenType) ? { tokenType: str(o.tokenType) } : {}), ...(str(o.tokenExpiration) ? { tokenExpiration: str(o.tokenExpiration) } : {}) };
    },
    async reportResult(input: { mandateId: string; result: AiriTransactionResult; reason?: string }): Promise<void> {
      if (!["SUCCEEDED", "CANCELLED", "DECLINED"].includes(input.result)) throw new AiriCliError("airi_invalid_input", "Result must be SUCCEEDED, CANCELLED or DECLINED.");
      const args = ["--mandate-id", flagSafe(input.mandateId, "mandate id"), "--result", input.result, ...(input.reason ? ["--reason", flagSafe(input.reason.slice(0, 200), "reason")] : [])];
      check(await run("mandate result", args), "mandate result");
    },
    /** Status becomes DENIED; {"status":"ok"} is the confirmation. */
    async cancelMandate(mandateId: string): Promise<void> {
      const r = await run("mandate cancel", ["--mandate-id", flagSafe(mandateId, "mandate id")]);
      check(r, "mandate cancel");
      const o = json(r, "mandate cancel");
      if (!isObj(o) || o.status !== "ok") throw new AiriCliError("airi_bad_output", "airi-cli mandate cancel: no {\"status\":\"ok\"} confirmation.");
    },
    async listMandates(filter: { status?: readonly string[]; size?: number; page?: number; createdFrom?: string } = {}): Promise<{ items: AiriMandateSummary[]; hasMore: boolean }> {
      const args = [...(filter.status ?? []).flatMap(s => ["--status", s]), "--size", String(filter.size ?? 20), "--page", String(filter.page ?? 0),
        ...(filter.createdFrom ? ["--created-from", filter.createdFrom] : [])];
      const r = await run("mandate list", args);
      check(r, "mandate list");
      const o = json(r, "mandate list");
      if (!isObj(o) || !Array.isArray(o.items)) throw new AiriCliError("airi_bad_output", "airi-cli mandate list: unexpected output.");
      const items = o.items.flatMap((m): AiriMandateSummary[] => {
        if (!isObj(m)) return [];
        const mandateId = str(pick(m, "mandateId", "mandate_id", "id"));
        const status = str(pick(m, "status"));
        if (!mandateId || !status) return [];
        const merchant = isObj(m.merchant) ? m.merchant : {};
        return [{ mandateId, status, totalAmount: str(pick(m, "totalAmount", "total_amount", "amount")), currency: str(pick(m, "currency")),
          merchantName: str(pick(m, "merchantName", "merchant_name")) ?? str(pick(merchant, "name")), createdAt: str(pick(m, "createdAt", "created_at")) }];
      });
      return { items, hasMore: o.hasMore === true };
    },
  };
}

/**
 * A private, single-use location for the one-time credential: a fresh 0700 directory; the CLI creates the file
 * itself (0600, no overwrite). `dispose()` removes the directory and the file whatever happened; always call it.
 */
export function createAiriCredentialFile(baseDir: string = tmpdir()) {
  const dir = mkdtempSync(join(baseDir, "airi-cred-"));
  return { path: join(dir, "credential.json"), dispose: () => rmSync(dir, { recursive: true, force: true }) };
}
