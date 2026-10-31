/**
 * Manual checkout handoff for the live Airi rail. The merchant card form is filled by a SEPARATE operator (a human or
 * a GUI browser agent on the box desktop), never by this code: this module drives no browser and never types a card.
 *
 *   1. airi-cli has written the one-time credential to a fresh 0600 file (createAiriCredentialFile).
 *   2. announce(): print ONLY the credential file path and the masked last 4 of the one-time card, and write a
 *      0600 `pending.json` in the handoff dir (mandate id, merchant, checkout URL, amount, file path, masked last 4,
 *      signal file path, deadline). No card number, CVC, expiry or token is ever printed, logged or written.
 *   3. Wait for the checkout-done signal, whichever comes first:
 *        - a marker file `<handoffDir>/<mandateId>.done`, or
 *        - one line on stdin (when `stdin` is given),
 *      carrying `SUCCEEDED <merchant order/receipt id>`, `DECLINED <reason>` or `CANCELLED <reason>` (or the JSON
 *      `{"result":"SUCCEEDED","orderId":"..."}`). SUCCEEDED without an order id is rejected and waiting continues.
 *   4. Return the outcome. The adapter then deletes the credential file and ALWAYS reports `mandate result`.
 *   5. No signal before the deadline: throw AiriHandoffTimeout; the adapter cancels the mandate and deletes the file.
 *
 * The masked last 4 comes from the credential file: the file is parsed, the first card-number-like field is reduced
 * to its last 4 digits inside one function, and every other value is dropped unread and never leaves that function.
 */
import { chmodSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, rmSync, writeSync } from "node:fs";
import { join, resolve } from "node:path";
import type { Readable } from "node:stream";
import type { AiriCheckoutOutcome, AiriCheckoutSubmitter } from "./payments.js";
import type { AiriTransactionResult } from "./airi.js";

export class AiriHandoffTimeout extends Error {
  readonly reason = "airi_handoff_timeout";
  constructor(message: string) { super(message); this.name = "AiriHandoffTimeout"; }
}

const CARD_KEYS = /^(pan|card_?number|cardnumber|number|account_?number|token(ized)?_?pan|network_?token|dpan|token_?number)$/i;
/**
 * Last 4 digits of the one-time card in the credential file, or null. Only the 4 digits leave this function. Looks
 * for the first field named like a card number (pan, card_number, number, tokenized_pan, ...) at any depth whose value
 * is 12-19 digits (spaces/dashes allowed). Never throws with file content in the message.
 */
export function credentialLast4(file: string): string | null {
  let parsed: unknown;
  try { parsed = JSON.parse(readFileSync(file, "utf8")); } catch { return null; }
  const seen = new Set<unknown>();
  const walk = (v: unknown, depth: number): string | null => {
    if (!v || typeof v !== "object" || depth > 4 || seen.has(v)) return null;
    seen.add(v);
    for (const [k, val] of Object.entries(v as Record<string, unknown>)) {
      if (CARD_KEYS.test(k) && (typeof val === "string" || typeof val === "number")) {
        const digits = String(val).replace(/[\s-]/g, "");
        if (/^\d{12,19}$/.test(digits)) return digits.slice(-4);
      }
    }
    for (const val of Object.values(v as Record<string, unknown>)) { const r = walk(val, depth + 1); if (r) return r; }
    return null;
  };
  const last4 = walk(parsed, 0);
  parsed = undefined;
  return last4;
}

export type HandoffSignal = { result: AiriTransactionResult; orderId?: string; reason?: string };
const ORDER_ID = /^[A-Za-z0-9][A-Za-z0-9 _.:#/-]{0,127}$/;
const REASON = /^[^\u0000-\u001f\u007f]{1,200}$/;
/** Parse one signal (marker file body or stdin line). Returns null for anything that is not a complete, valid signal. */
export function parseHandoffSignal(text: string): HandoffSignal | null {
  const t = text.trim();
  if (!t) return null;
  let result: string | undefined; let detail: string | undefined;
  if (t.startsWith("{")) {
    try {
      const o = JSON.parse(t) as Record<string, unknown>;
      result = typeof o.result === "string" ? o.result : undefined;
      const d = o.orderId ?? o.order_id ?? o.receiptId ?? o.reason;
      detail = typeof d === "string" || typeof d === "number" ? String(d) : undefined;
    } catch { return null; }
  } else {
    const m = /^(\S+)\s*(.*)$/s.exec(t.split(/\r?\n/)[0]!);
    result = m?.[1]; detail = m?.[2]?.trim() || undefined;
  }
  result = result?.toUpperCase();
  if (result === "SUCCEEDED") return detail && ORDER_ID.test(detail) ? { result, orderId: detail } : null;
  if (result === "DECLINED" || result === "CANCELLED") return { result, ...(detail && REASON.test(detail) ? { reason: detail } : {}) };
  return null;
}

export type ManualHandoffOptions = {
  /** Where pending.json and the <mandateId>.done marker live (default artifacts/airi-handoff). */
  handoffDir?: string;
  timeoutMs: number;
  /** Optional line-based signal source (process.stdin for the CLI). */
  stdin?: Readable;
  /** Output for the operator. Receives only safe text (paths, masked last 4, ids, amounts). */
  print?: (line: string) => void;
  pollMs?: number;
  /** Fallback label when the credential file has no recognizable card number (e.g. the funding card mask). */
  fallbackCard?: () => string | undefined;
  /** Checkout page to hand the operator (default: the merchant URL bound in the mandate). */
  checkoutUrlFor?: (merchantId: string) => string | undefined;
  now?: () => number;
};
export type ManualHandoff = AiriCheckoutSubmitter & { readonly lastOrderId: () => string | undefined; readonly lastCardLast4: () => string | undefined };

function writePrivate(path: string, body: string) {
  rmSync(path, { force: true });
  const fd = openSync(path, "wx", 0o600);
  try { writeSync(fd, body); } finally { closeSync(fd); }
  chmodSync(path, 0o600);
}

/** The AiriCheckoutSubmitter for manual (operator / GUI agent) checkout. See the module comment for the protocol. */
export function createManualCheckoutHandoff(options: ManualHandoffOptions): ManualHandoff {
  const dir = resolve(options.handoffDir ?? "artifacts/airi-handoff");
  const print = options.print ?? (line => process.stdout.write(`${line}\n`));
  const now = options.now ?? Date.now;
  const pollMs = options.pollMs ?? 500;
  let lastOrderId: string | undefined;
  let lastCardLast4: string | undefined;
  const submit = (async ({ credentialFile, mandateId, merchant, amount, currency }) => {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    chmodSync(credentialFile, 0o600); // owner-only, whatever the CLI did
    const last4 = credentialLast4(credentialFile);
    lastCardLast4 = last4 ?? undefined;
    const masked = last4 ? `****${last4}` : `${options.fallbackCard?.() ?? "card"} (one-time card last 4 not readable; funding card shown)`;
    const signalFile = join(dir, `${mandateId}.done`);
    const checkoutUrl = options.checkoutUrlFor?.(merchant.id) ?? merchant.url;
    const pendingFile = join(dir, "pending.json");
    const deadline = now() + options.timeoutMs;
    rmSync(signalFile, { force: true }); // a stale marker can never complete a new mandate
    writePrivate(pendingFile, JSON.stringify({ mandateId, merchantId: merchant.id, merchantName: merchant.name, checkoutUrl, amount, currency,
      credentialFile, card: masked, signalFile, deadline: new Date(deadline).toISOString(),
      signal: "write 'SUCCEEDED <merchant order/receipt id>' | 'DECLINED <reason>' | 'CANCELLED <reason>' to signalFile" }, null, 2));
    print(`AIRI HANDOFF  mandate ${mandateId}  ${merchant.name}  ${currency} ${amount}`);
    print(`  credential file: ${credentialFile}`);
    print(`  card: ${masked}`);
    print(`  checkout: ${checkoutUrl}`);
    print(`  when done: echo 'SUCCEEDED <order id>' > ${signalFile}   (or DECLINED/CANCELLED <reason>${options.stdin ? ", or type it here" : ""})`);
    print(`  deadline: ${new Date(deadline).toISOString()} (then the mandate is cancelled and the file deleted)`);

    let stdinSignal: HandoffSignal | null = null;
    let buffer = "";
    const onData = (chunk: Buffer | string) => {
      buffer += chunk.toString();
      let i: number;
      while ((i = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, i); buffer = buffer.slice(i + 1);
        const s = parseHandoffSignal(line);
        if (s) { stdinSignal = s; return; }
        if (line.trim()) print("  (ignored: expected 'SUCCEEDED <order id>', 'DECLINED <reason>' or 'CANCELLED <reason>')");
      }
    };
    options.stdin?.on("data", onData);
    let warned = false;
    try {
      for (;;) {
        let signal: HandoffSignal | null = stdinSignal;
        if (!signal && existsSync(signalFile)) {
          let body = "";
          try { body = readFileSync(signalFile, "utf8"); } catch { /* being written; next poll */ }
          signal = parseHandoffSignal(body);
          if (!signal && body.trim() && !warned) { warned = true; print(`  (signal file ${signalFile} is not a valid signal yet; still waiting)`); }
        }
        if (signal) {
          lastOrderId = signal.orderId;
          print(`  signal: ${signal.result}${signal.orderId ? ` order ${signal.orderId}` : ""}`);
          const reason = signal.result === "SUCCEEDED" ? undefined : signal.reason;
          return { result: signal.result, ...(reason ? { reason } : {}), ...(signal.orderId ? { merchantOrderId: signal.orderId } : {}), ...(last4 ? { oneTimeCardLast4: last4 } : {}) } satisfies AiriCheckoutOutcome;
        }
        if (now() >= deadline) throw new AiriHandoffTimeout(`No checkout-done signal for Airi mandate ${mandateId} within ${Math.round(options.timeoutMs / 1000)}s.`);
        await new Promise(r => setTimeout(r, pollMs));
      }
    } finally {
      options.stdin?.off("data", onData);
      rmSync(pendingFile, { force: true });
      rmSync(signalFile, { force: true });
    }
  }) as ManualHandoff;
  Object.defineProperty(submit, "lastOrderId", { value: () => lastOrderId });
  Object.defineProperty(submit, "lastCardLast4", { value: () => lastCardLast4 });
  return submit;
}
