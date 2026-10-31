/**
 * Live Airi buy with the MANUAL CHECKOUT HANDOFF (shopper/handoff.ts + shopper/live-buy.ts) against the fake airi-cli
 * (recorded / documented outputs in tests/fixtures/airi). Offline: no real mandate, credential, browser or payment.
 */
import { chmodSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { PassThrough } from "node:stream";
import { describe, expect, it } from "vitest";
import { createAiriClient, type AiriCommand, type AiriRunner, type AiriRunResult } from "../shopper/airi.js";
import { createManualCheckoutHandoff, credentialLast4, parseHandoffSignal } from "../shopper/handoff.js";
import { journalSpend, loadAiriLiveConfig, planAiriBuy, runAiriBuy, type AiriLiveFileConfig } from "../shopper/live-buy.js";

const FIX = join(import.meta.dirname, "fixtures", "airi");
const ok = (name: string): AiriRunResult => ({ code: 0, stdout: readFileSync(join(FIX, name), "utf8"), stderr: "" });
const SECRET = /0000 0000 0000 4242|0000000000004242|"cvv"|expiry_(month|year)|NETWORK_TOKEN"?\s*:/;

function fakeAiri(over: Partial<Record<AiriCommand, (args: readonly string[]) => AiriRunResult>> = {}) {
  const calls: { command: AiriCommand; args: readonly string[] }[] = [];
  let credentialFile = "";
  const handlers: Record<AiriCommand, (args: readonly string[]) => AiriRunResult> = {
    "auth whoami": () => ok("whoami.json"),
    "payment-methods list": () => ({ code: 0, stdout: JSON.stringify([{ paymentMethodId: "e993fd4b-f272-4bdf-ad26-b65b0ff7bbab", brand: "VISA", last4: "0005", nickname: "Test" }]), stderr: "" }),
    "mandate create": () => ok("mandate-create.json"),
    "mandate get-credential": args => {
      credentialFile = args[args.indexOf("--file") + 1]!;
      writeFileSync(credentialFile, readFileSync(join(FIX, "credential-file-fake.json")), { mode: 0o600, flag: "wx" });
      return ok("get-credential-saved.json");
    },
    "mandate result": () => ok("status-ok.json"),
    "mandate cancel": () => ok("status-ok.json"),
    "mandate list": () => ok("mandate-list-empty.json"),
    ...over,
  };
  const run: AiriRunner = async (command, args) => { calls.push({ command, args: [...args] }); return handlers[command](args); };
  return { calls, commands: () => calls.map(c => c.command), client: createAiriClient(run), credentialFile: () => credentialFile };
}
const config = (): AiriLiveFileConfig => loadAiriLiveConfig({}, join(import.meta.dirname, "..", "config", "airi-live.json"));
function workdir() {
  const dir = mkdtempSync(join(tmpdir(), "airi-buy-"));
  return { dir, journal: join(dir, "airi-dispatch-journal.json"), log: join(dir, "airi-buy-log.jsonl"), handoff: join(dir, "handoff") };
}
/** Plays the GUI agent: waits for pending.json, checks the credential file, then writes the signal. */
async function operator(handoffDir: string, signal: string | null, seen: { file?: string; mode?: number; pending?: Record<string, unknown> }) {
  const pending = join(handoffDir, "pending.json");
  for (let i = 0; i < 200 && !existsSync(pending); i += 1) await new Promise(r => setTimeout(r, 10));
  const p = JSON.parse(readFileSync(pending, "utf8")) as Record<string, unknown>;
  seen.pending = p; seen.file = String(p.credentialFile); seen.mode = statSync(seen.file).mode & 0o777;
  if (signal !== null) writeFileSync(String(p.signalFile), signal);
}

describe("airi live config (config/airi-live.json)", () => {
  it("allowlists exactly the two approved merchants: https, US, per-buy caps $1.10 / $2.75, run cap $5.00, the X Money Visa id", () => {
    const c = config();
    expect(Object.keys(c.merchants).sort()).toEqual(["gumroad-kyle", "itch-limezu"]);
    expect(c.merchants["gumroad-kyle"]).toMatchObject({ url: "https://kyletwebster.gumroad.com/l/ZHvXw", country: "US", capCents: 110, item: { priceCents: 100 } });
    expect(c.merchants["itch-limezu"]).toMatchObject({ url: "https://limezu.itch.io/modernoffice", checkoutUrl: "https://limezu.itch.io/modernoffice/purchase", country: "US", capCents: 275, item: { priceCents: 250 } });
    expect(c.runTotalCapCents).toBe(500);
    expect(c.paymentMethodId).toBe("e993fd4b-f272-4bdf-ad26-b65b0ff7bbab");
    expect(loadAiriLiveConfig({ AIRI_PAYMENT_METHOD_ID: "pm_override" }, join(import.meta.dirname, "..", "config", "airi-live.json")).paymentMethodId).toBe("pm_override");
    expect(() => loadAiriLiveConfig({ AIRI_PAYMENT_METHOD_ID: "--bad" }, join(import.meta.dirname, "..", "config", "airi-live.json"))).toThrow();
  });

  it("caps: per-buy cap, run total cap over the journal, repeat buys and unknown merchants are refused before anything runs", () => {
    const w = workdir();
    expect(planAiriBuy(config(), "gumroad-kyle", w.journal)).toMatchObject({ totalCents: 106, checkout: { totalBaseUnits: "106", taxBaseUnits: "6" } });
    expect(planAiriBuy(config(), "itch-limezu", w.journal)).toMatchObject({ totalCents: 266 });
    expect(() => planAiriBuy(config(), "gumroad-kyle", w.journal, { taxCents: 11 })).toThrow(expect.objectContaining({ reason: "airi_buy_cap" }));
    expect(() => planAiriBuy(config(), "itch-limezu", w.journal, { priceCents: 249 })).toThrow(expect.objectContaining({ reason: "airi_price_invalid" }));
    expect(() => planAiriBuy(config(), "amazon", w.journal)).toThrow(expect.objectContaining({ reason: "airi_merchant_not_allowed" }));
    writeFileSync(w.journal, JSON.stringify([{ rail: "airwallex-airi", merchantId: "other", status: "succeeded", amountBaseUnits: "300" }]));
    expect(journalSpend(w.journal).totalCents).toBe(300);
    expect(() => planAiriBuy(config(), "itch-limezu", w.journal)).toThrow(expect.objectContaining({ reason: "airi_run_cap" }));
    writeFileSync(w.journal, JSON.stringify([{ rail: "airwallex-airi", merchantId: "gumroad-kyle", status: "sent", amountBaseUnits: "106", txHash: "mdt_x" }]));
    expect(() => planAiriBuy(config(), "gumroad-kyle", w.journal)).toThrow(expect.objectContaining({ reason: "airi_repeat_buy" }));
    expect(planAiriBuy(config(), "itch-limezu", w.journal).spentCents).toBe(106);
  });
});

describe("handoff signal and masking", () => {
  it("only the last 4 of the one-time card leave the credential file", () => {
    expect(credentialLast4(join(FIX, "credential-file-fake.json"))).toBe("4242");
    const dir = mkdtempSync(join(tmpdir(), "airi-l4-"));
    writeFileSync(join(dir, "x.json"), JSON.stringify({ cvv: "123456789012", note: "1234567890123" }));
    expect(credentialLast4(join(dir, "x.json"))).toBeNull();
    expect(credentialLast4(join(dir, "missing.json"))).toBeNull();
  });
  it("signals: SUCCEEDED needs an order id; DECLINED / CANCELLED take a reason; JSON form accepted", () => {
    expect(parseHandoffSignal("SUCCEEDED 1234-ABCD\n")).toEqual({ result: "SUCCEEDED", orderId: "1234-ABCD" });
    expect(parseHandoffSignal("succeeded")).toBeNull();
    expect(parseHandoffSignal('{"result":"SUCCEEDED","orderId":"gumroad#99"}')).toEqual({ result: "SUCCEEDED", orderId: "gumroad#99" });
    expect(parseHandoffSignal("DECLINED card declined")).toEqual({ result: "DECLINED", reason: "card declined" });
    expect(parseHandoffSignal("CANCELLED")).toEqual({ result: "CANCELLED" });
    expect(parseHandoffSignal("PAID 1")).toBeNull();
  });
});

describe("pnpm airi:buy (runAiriBuy) with the manual handoff", () => {
  it("success via marker file: prints only path + masked last 4, then deletes the file, reports SUCCEEDED and journals the order id", async () => {
    const w = workdir();
    const fake = fakeAiri();
    const out: string[] = [];
    const handoff = createManualCheckoutHandoff({ handoffDir: w.handoff, timeoutMs: 5_000, pollMs: 10, print: l => out.push(l), checkoutUrlFor: () => "https://kyletwebster.gumroad.com/l/ZHvXw" });
    const seen: Parameters<typeof operator>[2] = {};
    const [result] = await Promise.all([
      runAiriBuy({ config: config(), merchantId: "gumroad-kyle", client: fake.client, submitCheckout: handoff, journalPath: w.journal, logPath: w.log, print: l => out.push(l) }),
      operator(w.handoff, "SUCCEEDED GR-ORDER-123", seen),
    ]);
    expect(result).toMatchObject({ status: "PAID", payment: { mode: "live", reference: "mdt_test_0001", detail: { merchantOrderId: "GR-ORDER-123", oneTimeCard: "****4242", airiResultReported: "true", amount: "1.06" } } });
    expect(fake.commands()).toEqual(["auth whoami", "payment-methods list", "mandate create", "mandate get-credential", "mandate result"]);
    expect(fake.calls.find(c => c.command === "mandate create")!.args).toEqual(expect.arrayContaining(["--payment-method-id", "e993fd4b-f272-4bdf-ad26-b65b0ff7bbab",
      "--merchant-url", "https://kyletwebster.gumroad.com/l/ZHvXw", "--merchant-country", "US", "--total-amount", "1.06", "--item", "name:Kyle's Very Nice Paper Layer,unit_price:1.00,quantity:1", "--item", "name:Tax,unit_price:0.06,quantity:1"]));
    expect(fake.calls.at(-1)).toEqual({ command: "mandate result", args: ["--mandate-id", "mdt_test_0001", "--result", "SUCCEEDED"] });
    expect(seen.mode).toBe(0o600);
    expect(seen.file).toMatch(/\/airi-cred-[^/]+\/credential\.json$/);
    expect(seen.pending).toMatchObject({ mandateId: "mdt_test_0001", card: "****4242", checkoutUrl: "https://kyletwebster.gumroad.com/l/ZHvXw", amount: "1.06" });
    expect(existsSync(seen.file!)).toBe(false);
    expect(existsSync(join(w.handoff, "pending.json"))).toBe(false);
    const text = out.join("\n");
    expect(text).toContain(`credential file: ${seen.file}`);
    expect(text).toContain("card: ****4242");
    const journal = readFileSync(w.journal, "utf8");
    expect(JSON.parse(journal)).toEqual([expect.objectContaining({ merchantId: "gumroad-kyle", status: "succeeded", amountBaseUnits: "106", result: expect.objectContaining({ detail: expect.objectContaining({ merchantOrderId: "GR-ORDER-123" }) }) })]);
    for (const s of [text, journal, readFileSync(w.log, "utf8"), JSON.stringify(seen.pending), JSON.stringify(result)]) expect(s).not.toMatch(SECRET);
    // The run cap and the repeat guard now see this buy.
    await expect(runAiriBuy({ config: config(), merchantId: "gumroad-kyle", client: fake.client, submitCheckout: handoff, journalPath: w.journal, logPath: w.log, print: () => {} })).rejects.toMatchObject({ reason: "airi_repeat_buy" });
  });

  it("success via a stdin line; a credential file the CLI left group-readable is tightened to 0600 before the handoff", async () => {
    const w = workdir();
    const fake = fakeAiri({ "mandate get-credential": args => {
      const f = args[args.indexOf("--file") + 1]!;
      writeFileSync(f, readFileSync(join(FIX, "credential-file-fake.json")), { flag: "wx" }); chmodSync(f, 0o644);
      return ok("get-credential-saved.json");
    } });
    const stdin = new PassThrough();
    const handoff = createManualCheckoutHandoff({ handoffDir: w.handoff, timeoutMs: 5_000, pollMs: 10, stdin, print: () => {} });
    const seen: Parameters<typeof operator>[2] = {};
    const [result] = await Promise.all([
      runAiriBuy({ config: config(), merchantId: "itch-limezu", client: fake.client, submitCheckout: handoff, journalPath: w.journal, logPath: w.log, print: () => {} }),
      operator(w.handoff, null, seen).then(() => { stdin.write("nonsense\n"); stdin.write("SUCCEEDED itch-receipt-77\n"); }),
    ]);
    expect(result).toMatchObject({ status: "PAID", payment: { detail: { merchantOrderId: "itch-receipt-77", amount: "2.66" } } });
    expect(seen.mode).toBe(0o600);
    expect(existsSync(seen.file!)).toBe(false);
  });

  it("timeout: no signal -> mandate cancelled, credential file deleted, no result reported, row stays sent (never re-bought)", async () => {
    const w = workdir();
    const fake = fakeAiri();
    const out: string[] = [];
    const handoff = createManualCheckoutHandoff({ handoffDir: w.handoff, timeoutMs: 150, pollMs: 10, print: l => out.push(l) });
    const seen: Parameters<typeof operator>[2] = {};
    const [result] = await Promise.all([
      runAiriBuy({ config: config(), merchantId: "gumroad-kyle", client: fake.client, submitCheckout: handoff, journalPath: w.journal, logPath: w.log, print: l => out.push(l) }),
      operator(w.handoff, null, seen),
    ]);
    expect(result).toMatchObject({ status: "REFUSED", reason: "airi_handoff_timeout" });
    expect(fake.commands()).toEqual(["auth whoami", "payment-methods list", "mandate create", "mandate get-credential", "mandate cancel"]);
    expect(existsSync(seen.file!)).toBe(false);
    expect(JSON.parse(readFileSync(w.journal, "utf8"))).toEqual([expect.objectContaining({ status: "sent", txHash: "mdt_test_0001" })]);
    expect(out.join("\n")).not.toMatch(SECRET);
  });

  it("DECLINED signal: reported to Airi as DECLINED, nothing settles, file deleted", async () => {
    const w = workdir();
    const fake = fakeAiri();
    const handoff = createManualCheckoutHandoff({ handoffDir: w.handoff, timeoutMs: 5_000, pollMs: 10, print: () => {} });
    const seen: Parameters<typeof operator>[2] = {};
    const [result] = await Promise.all([
      runAiriBuy({ config: config(), merchantId: "gumroad-kyle", client: fake.client, submitCheckout: handoff, journalPath: w.journal, logPath: w.log, print: () => {} }),
      operator(w.handoff, "DECLINED card declined by merchant", seen),
    ]);
    expect(result).toMatchObject({ status: "REFUSED", reason: "airi_declined" });
    expect(fake.calls.at(-1)).toEqual({ command: "mandate result", args: ["--mandate-id", "mdt_test_0001", "--result", "DECLINED", "--reason", "card declined by merchant"] });
    expect(existsSync(seen.file!)).toBe(false);
  });

  it("signed out: refused before any mandate, nothing handed off", async () => {
    const w = workdir();
    const fake = fakeAiri({ "auth whoami": () => ok("whoami-signed-out.json") });
    const handoff = createManualCheckoutHandoff({ handoffDir: w.handoff, timeoutMs: 100, pollMs: 10, print: () => {} });
    const result = await runAiriBuy({ config: config(), merchantId: "gumroad-kyle", client: fake.client, submitCheckout: handoff, journalPath: w.journal, logPath: w.log, print: () => {} });
    expect(result).toMatchObject({ status: "REFUSED", reason: "airi_unauthenticated" });
    expect(fake.commands()).toEqual(["auth whoami"]);
    expect(existsSync(join(w.handoff, "pending.json"))).toBe(false);
  });
});
