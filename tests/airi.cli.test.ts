/**
 * Real Airi CLI rail (createAiriCliAdapter + shopper/airi.ts) against RECORDED / documented airi-cli output
 * (tests/fixtures/airi). Offline: a fake runner stands in for the binary; nothing here creates a real mandate,
 * fetches a real credential or pays anything.
 */
import { chmodSync, existsSync, mkdtempSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import {
  AIRI_ALLOWED_COMMANDS, centsToMajor, createAiriCliRunner, createAiriClient, formatItem, maskPaymentMethod, parsePaymentMethod,
  type AiriCommand, type AiriRunner, type AiriRunResult,
} from "../shopper/airi.js";
import { createShopperRig, selectAiriMode } from "../shopper/flow.js";
import {
  PaymentRefused, airiItemsFor, createAiriCliAdapter, createAiriMerchantResolver, createDispatchLedger, createFileDispatchStore, createMemoryDispatchStore,
  snapshotRequest, type AiriCheckoutSubmitter,
} from "../shopper/payments.js";
import { tpaPaymentTargetSchema } from "../src/binding.js";
import { boundFixture, boundLedger, consumedLookup, reviewCheckout, type Fixture } from "./support/dispatch.js";

const fixture = (name: string) => readFileSync(join(import.meta.dirname, "fixtures", "airi", name), "utf8");
const ok = (name: string): AiriRunResult => ({ code: 0, stdout: fixture(name), stderr: "" });
const MERCHANTS = { "review-merchant": { url: "https://shop.example.test", country: "US" } };
const tempJournal = () => join(mkdtempSync(join(tmpdir(), "airi-journal-")), "dispatch.json");

/** Fake airi-cli: per-command handlers returning recorded output; records every call. get-credential writes a dummy file like the CLI. */
function fakeAiri(over: Partial<Record<AiriCommand, (args: readonly string[]) => AiriRunResult | Promise<AiriRunResult>>> = {}) {
  const calls: { command: AiriCommand; args: readonly string[] }[] = [];
  const handlers: Record<AiriCommand, (args: readonly string[]) => AiriRunResult | Promise<AiriRunResult>> = {
    "auth whoami": () => ok("whoami.json"),
    "payment-methods list": () => ok("payment-methods.json"),
    "mandate create": () => ok("mandate-create.json"),
    "mandate get-credential": args => {
      const file = args[args.indexOf("--file") + 1]!;
      writeFileSync(file, JSON.stringify({ pan: "FAKE-TOKENIZED-PAN", expiry: "12/30", cvv: "000" }), { mode: 0o600, flag: "wx" });
      return ok("get-credential-saved.json");
    },
    "mandate result": () => ok("status-ok.json"),
    "mandate cancel": () => ok("status-ok.json"),
    "mandate list": () => ok("mandate-list-empty.json"),
    ...over,
  };
  const run: AiriRunner = async (command, args) => { calls.push({ command, args: [...args] }); return handlers[command](args); };
  return { run, calls, commands: () => calls.map(c => c.command), client: createAiriClient(run) };
}
const airiFixture = (over: Parameters<typeof boundFixture>[0] = {}): Fixture =>
  boundFixture({ rail: "airwallex-airi", ...over, target: t => ({ ...t, network: "airwallex:airi-card", payee: "awx-airi-merchant:review-merchant" }) });
function liveAdapter(fx: Fixture, fake = fakeAiri(), opts: { submit?: AiriCheckoutSubmitter; journal?: string; now?: () => number } = {}) {
  const seen: { file: string; existed: boolean; mode: number }[] = [];
  const notices: unknown[] = [];
  const submit: AiriCheckoutSubmitter = opts.submit ?? (async ({ credentialFile }) => {
    seen.push({ file: credentialFile, existed: existsSync(credentialFile), mode: statSync(credentialFile).mode & 0o777 });
    return { result: "SUCCEEDED" };
  });
  const journal = opts.journal ?? tempJournal();
  const ledger = createDispatchLedger({ store: createFileDispatchStore(journal), lookupIntent: consumedLookup(fx), ...(opts.now ? { now: opts.now } : {}) });
  const adapter = createAiriCliAdapter(ledger, { client: fake.client, paymentMethodId: "pm_test_0001", source: "TPA Shopper", merchants: MERCHANTS, submitCheckout: submit, onApprovalRequested: n => { notices.push(n); } });
  return { adapter, fake, seen, notices, journal };
}

describe("airi-cli client (recorded output)", () => {
  it("payment methods are reduced to id, brand, last4, nickname; full numbers are never kept", () => {
    const pms = JSON.parse(fixture("payment-methods.json")) as unknown[];
    expect(pms.map(parsePaymentMethod)).toEqual([
      { id: "pm_test_0001", brand: "VISA", last4: "0005", nickname: "Test card" },
      { id: "pm_test_0002", brand: "MASTERCARD", last4: "0013", nickname: "Backup" },
    ]);
    const leaky = parsePaymentMethod({ id: "pm_x", card: { brand: "VISA", last4: "0000111122223333", number: "0000111122223333", cvv: "123" } });
    expect(leaky).toEqual({ id: "pm_x", brand: "VISA", last4: "" });
    expect(JSON.stringify(leaky)).not.toMatch(/0000111122223333|123/);
    expect(maskPaymentMethod({ brand: "VISA", last4: "0005" })).toBe("VISA ****0005");
  });

  it("an empty payment method list (recorded) parses to []", async () => {
    const fake = fakeAiri({ "payment-methods list": () => ok("payment-methods-empty.json") });
    expect(await fake.client.listPaymentMethods()).toEqual([]);
  });

  it("mandate create builds exactly the documented flags; --item is name:..,unit_price:..,quantity:..", async () => {
    const fake = fakeAiri();
    const m = await fake.client.createMandate({ source: "TPA Shopper", paymentMethodId: "pm_test_0001", merchantName: "Review merchant", merchantUrl: "https://shop.example.test",
      merchantCountry: "US", totalAmount: "42.00", currency: "USD", items: [{ name: "Widget", unitPrice: "21.00", quantity: 2 }], description: "Order 1" });
    expect(m).toEqual({ mandateId: "mdt_test_0001", passkeyUrl: "https://app.airi.com/passkey/mdt_test_0001", status: "CREATED" });
    expect(fake.calls[0]).toEqual({ command: "mandate create", args: ["--source", "TPA Shopper", "--payment-method-id", "pm_test_0001", "--merchant-name", "Review merchant",
      "--merchant-url", "https://shop.example.test", "--merchant-country", "US", "--total-amount", "42.00", "--currency", "USD", "--item", "name:Widget,unit_price:21.00,quantity:2", "--description", "Order 1"] });
    expect(() => formatItem({ name: "a,unit_price:0.01", unitPrice: "1.00", quantity: 1 })).toThrow();
    expect(centsToMajor("1249")).toBe("12.49");
    expect(centsToMajor("5")).toBe("0.05");
  });

  it("get-credential always writes to --file and returns only the receipt", async () => {
    const fake = fakeAiri();
    const dir = mkdtempSync(join(tmpdir(), "airi-t-"));
    const receipt = await fake.client.getCredential({ mandateId: "mdt_test_0001", file: join(dir, "c.json") });
    expect(receipt).toEqual({ status: "saved", tokenType: "NETWORK_TOKEN", tokenExpiration: "2026-10-31T01:30:00-04:00" });
    expect(fake.calls[0]!.args).toEqual(expect.arrayContaining(["--mandate-id", "mdt_test_0001", "--file", join(dir, "c.json")]));
    const timedOut = fakeAiri({ "mandate get-credential": () => ({ code: 1, stdout: "", stderr: "Timed out after 300s waiting for credential authorization." }) });
    await expect(timedOut.client.getCredential({ mandateId: "mdt_test_0001", file: join(dir, "d.json") })).rejects.toMatchObject({ reason: "airi_approval_timeout" });
  });

  it("an expired session maps to airi_unauthenticated without echoing CLI output", async () => {
    const fake = fakeAiri({ "payment-methods list": () => ({ code: 1, stdout: "", stderr: "Error: session expired; run airi-cli auth login. token=SECRET" }) });
    const error = await fake.client.listPaymentMethods().then(() => new Error("resolved"), (e: unknown) => e as Error);
    expect(error).toMatchObject({ reason: "airi_unauthenticated" });
    expect(error.message).not.toContain("SECRET");
  });

  it("the real runner forces -o json --no-telemetry, uses no shell, and refuses non-allowlisted commands (login)", async () => {
    const dir = mkdtempSync(join(tmpdir(), "airi-bin-"));
    const bin = join(dir, "fake-airi-cli");
    writeFileSync(bin, `#!/usr/bin/env node\nprocess.stdout.write(JSON.stringify({ argv: process.argv.slice(2), telemetry: process.env.AIRI_TELEMETRY_DISABLED }));\n`);
    chmodSync(bin, 0o755);
    const run = createAiriCliRunner({ bin, env: { PATH: process.env.PATH } });
    const r = await run("mandate list", ["--size", "1; rm -rf /"]);
    expect(JSON.parse(r.stdout)).toEqual({ argv: ["mandate", "list", "--size", "1; rm -rf /", "-o", "json", "--no-telemetry"], telemetry: "1" });
    expect(AIRI_ALLOWED_COMMANDS).not.toContain("auth login" as never);
    expect(await run("auth login" as AiriCommand, [])).toMatchObject({ code: 126 });
  });
});

describe("createAiriCliAdapter: whoami -> payment-methods -> mandate create -> get-credential -> checkout -> result", () => {
  it("happy path: one mandate, credential only as a 0600 file that is deleted, result reported, masked card in the result", async () => {
    const fx = airiFixture({ intentId: "airi-ok", quoteId: "q-ok" });
    const { adapter, fake, seen, notices } = liveAdapter(fx);
    const paid = await adapter.pay(fx.request());
    expect(fake.commands()).toEqual(["auth whoami", "payment-methods list", "mandate create", "mandate get-credential", "mandate result"]);
    expect(paid).toMatchObject({ rail: "airwallex-airi", mode: "live", status: "succeeded", reference: "mdt_test_0001",
      detail: { paymentMandateId: "mdt_test_0001", card: "VISA ****0005", to: "awx-airi-merchant:review-merchant", amountBaseUnits: "100", amount: "1.00", currency: "USD", airiResultReported: "true" } });
    expect(JSON.stringify(paid)).not.toMatch(/FAKE-TOKENIZED-PAN|cvv/i);
    expect(seen).toHaveLength(1);
    expect(seen[0]).toMatchObject({ existed: true, mode: 0o600 });
    expect(existsSync(seen[0]!.file)).toBe(false);
    const create = fake.calls.find(c => c.command === "mandate create")!.args;
    expect(create).toEqual(expect.arrayContaining(["--merchant-name", "Review merchant", "--merchant-url", "https://shop.example.test", "--merchant-country", "US", "--total-amount", "1.00", "--currency", "USD", "--item", "name:REVIEW-1,unit_price:1.00,quantity:1"]));
    expect(fake.calls.find(c => c.command === "mandate result")!.args).toEqual(["--mandate-id", "mdt_test_0001", "--result", "SUCCEEDED"]);
    expect(notices).toEqual([expect.objectContaining({ mandateId: "mdt_test_0001", passkeyUrl: "https://app.airi.com/passkey/mdt_test_0001", amount: "1.00", card: "VISA ****0005" })]);
    // Same intent again: answered from the ledger, no new CLI call, never a second mandate.
    const before = fake.calls.length;
    expect(await adapter.pay(fx.request())).toMatchObject({ reference: "mdt_test_0001" });
    expect(fake.calls.length).toBe(before);
  });

  it("needs a durable ledger: a memory ledger is refused before any CLI call", async () => {
    const fx = airiFixture();
    const fake = fakeAiri();
    const adapter = createAiriCliAdapter(boundLedger([fx], createMemoryDispatchStore()), { client: fake.client, paymentMethodId: "pm_test_0001", source: "TPA Shopper", merchants: MERCHANTS, submitCheckout: async () => ({ result: "SUCCEEDED" }) });
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "ledger_not_durable" });
    expect(fake.calls).toEqual([]);
  });

  it("a mock-fixture target (or a merchant outside the directory) never reaches airi-cli", async () => {
    const mockFx = boundFixture({ rail: "airwallex-airi", intentId: "mockfx" });
    const a = liveAdapter(mockFx);
    await expect(a.adapter.pay(mockFx.request())).rejects.toMatchObject({ reason: "destination_unverified" });
    expect(a.fake.calls).toEqual([]);
    const fx = airiFixture({ intentId: "nodir" });
    const ledger = createDispatchLedger({ store: createFileDispatchStore(tempJournal()), lookupIntent: consumedLookup(fx) });
    const fake = fakeAiri();
    const adapter = createAiriCliAdapter(ledger, { client: fake.client, paymentMethodId: "pm_test_0001", source: "TPA Shopper", merchants: {}, submitCheckout: async () => ({ result: "SUCCEEDED" }) });
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "destination_unverified" });
    expect(fake.calls).toEqual([]);
  });

  it("signed out: refused before any mandate, reservation released", async () => {
    const fx = airiFixture({ intentId: "signed-out" });
    const { adapter, fake } = liveAdapter(fx, fakeAiri({ "auth whoami": () => ok("whoami-signed-out.json") }));
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "airi_unauthenticated" });
    expect(fake.commands()).toEqual(["auth whoami"]);
  });

  it("configured payment method not listed (e.g. no agent-enabled card): refused before any mandate", async () => {
    const fx = airiFixture({ intentId: "no-pm" });
    const { adapter, fake } = liveAdapter(fx, fakeAiri({ "payment-methods list": () => ok("payment-methods-empty.json") }));
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "airi_payment_method_unavailable" });
    expect(fake.commands()).not.toContain("mandate create");
  });

  it("owner never approves: get-credential times out, the mandate is cancelled, and a retry never creates a second mandate", async () => {
    const fx = airiFixture({ intentId: "timeout" });
    const fake = fakeAiri({ "mandate get-credential": () => ({ code: 1, stdout: "", stderr: "Timed out after 300s waiting for credential authorization." }) });
    const { adapter, journal } = liveAdapter(fx, fake);
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "airi_approval_timeout" });
    expect(fake.commands()).toEqual(["auth whoami", "payment-methods list", "mandate create", "mandate get-credential", "mandate cancel"]);
    const retry = liveAdapter(fx, fake, { journal });
    await expect(retry.adapter.pay(fx.request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(fake.commands().filter(c => c === "mandate create")).toHaveLength(1);
    expect(fake.commands().at(-1)).toBe("mandate list");
  });

  it("merchant declines: DECLINED is reported to Airi and nothing settles", async () => {
    const fx = airiFixture({ intentId: "declined" });
    const { adapter, fake } = liveAdapter(fx, fakeAiri(), { submit: async () => ({ result: "DECLINED", reason: "card declined" }) });
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "airi_declined" });
    expect(fake.calls.at(-1)).toEqual({ command: "mandate result", args: ["--mandate-id", "mdt_test_0001", "--result", "DECLINED", "--reason", "card declined"] });
  });

  it("checkout step crashes: outcome unknown, nothing reported or retried, credential file still deleted", async () => {
    const fx = airiFixture({ intentId: "crash" });
    let file = "";
    const { adapter, fake } = liveAdapter(fx, fakeAiri(), { submit: async ({ credentialFile }) => { file = credentialFile; throw new Error("browser died"); } });
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "airi_checkout_unknown" });
    expect(existsSync(file)).toBe(false);
    expect(fake.commands()).not.toContain("mandate result");
  });

  it("after a restart a recorded mandate settles only by reconcile (mandate list COMPLETED), with no new mandate or credential", async () => {
    const fx = airiFixture({ intentId: "restart" });
    const first = liveAdapter(fx, fakeAiri(), { submit: async () => { throw new Error("process killed"); } });
    await expect(first.adapter.pay(fx.request())).rejects.toMatchObject({ reason: "airi_checkout_unknown" });
    const fake = fakeAiri({ "mandate list": () => ok("mandate-list-completed.json") });
    const second = liveAdapter(fx, fake, { journal: first.journal });
    expect(await second.adapter.pay(fx.request())).toMatchObject({ mode: "live", reference: "mdt_test_0001", detail: { reconciled: "true" } });
    expect(fake.commands()).toEqual(["mandate list"]);
    expect(fake.calls[0]!.args).toEqual(expect.arrayContaining(["--status", "COMPLETED"]));
  });

  it("TPA approval expires while the mandate is being created: the mandate is cancelled and no credential is fetched", async () => {
    const issuedAt = Math.floor(Date.now() / 1000);
    const fx = airiFixture({ intentId: "expire", issuedAt });
    let clock = issuedAt * 1000;
    const fake = fakeAiri({ "mandate create": () => { clock = (fx.mandate.expires + 1) * 1000; return ok("mandate-create.json"); } });
    const { adapter } = liveAdapter(fx, fake, { now: () => clock });
    await expect(adapter.pay(fx.request())).rejects.toMatchObject({ reason: "approval_expired" });
    expect(fake.commands()).toEqual(["auth whoami", "payment-methods list", "mandate create", "mandate cancel"]);
  });
});

describe("Airi target, items and mode selection", () => {
  it("the airi-card target binds the merchant as payee; network and payee tags must agree", () => {
    const t = createAiriMerchantResolver(MERCHANTS)({ rail: "airwallex-airi", merchant: { id: "review-merchant" }, recipientRef: "user:7001", currency: "USD", sourceAmountBaseUnits: "100", nowSeconds: 1_900_000_000 })!;
    expect(t).toMatchObject({ network: "airwallex:airi-card", payee: "awx-airi-merchant:review-merchant", railAmount: "100", fee: { capBaseUnits: "0" } });
    expect(tpaPaymentTargetSchema.safeParse(t).success).toBe(true);
    expect(tpaPaymentTargetSchema.safeParse({ ...t, network: "airwallex:mock-fixture" }).success).toBe(false);
    expect(tpaPaymentTargetSchema.safeParse({ ...t, payee: "awx-mock-fixture:x" }).success).toBe(false);
    expect(createAiriMerchantResolver(MERCHANTS)({ rail: "airwallex-airi", merchant: { id: "elsewhere" }, recipientRef: "user:7001", currency: "USD", sourceAmountBaseUnits: "100", nowSeconds: 1 })).toBeNull();
    expect(() => createAiriMerchantResolver({ m: { url: "http://insecure.test", country: "US" } })).toThrow(PaymentRefused);
  });

  it("Airi line items include shipping and tax and add up to the signed total", () => {
    const req = snapshotRequest(boundFixture({ checkout: reviewCheckout({ items: [{ sku: "A-1", qty: 2, unitPriceBaseUnits: "1000" }], shipping: { method: "express", costBaseUnits: "599" }, taxBaseUnits: "165", totalBaseUnits: "2764" }) }).request());
    expect(airiItemsFor(req, sku => (sku === "A-1" ? "Mug, ceramic: blue" : undefined))).toEqual([
      { name: "Mug ceramic blue", unitPrice: "10.00", quantity: 2 }, { name: "Shipping express", unitPrice: "5.99", quantity: 1 }, { name: "Tax", unitPrice: "1.65", quantity: 1 },
    ]);
  });

  it("mock stays the default; AIRI_LIVE=1 without a live config refuses to start (no silent fallback)", async () => {
    expect(selectAiriMode({})).toEqual({ live: false });
    expect(() => selectAiriMode({ AIRI_LIVE: "1" })).toThrow(PaymentRefused);
    await expect(createShopperRig({ metal: "mock", env: { AIRI_LIVE: "1" } })).rejects.toMatchObject({ reason: "airi_misconfigured" });
    const rig = await createShopperRig({ metal: "mock", env: {} });
    try {
      expect(rig.airiSelection.live).toBe(false);
      expect(rig.rails.airwallex.mode).toBe("mock");
    } finally { await rig.close(); }
  });
});
