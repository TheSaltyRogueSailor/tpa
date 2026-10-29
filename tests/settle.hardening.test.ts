/**
 * Review findings on feb6083 (Michael, 2026-10-29): file-journal directory fsync, closed-schema journal rows and
 * results, and the receipt hash check on the first Metal receipt path. Offline only: temp-dir journals and an
 * in-process viem transport (no RPC).
 */
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { custom, encodeAbiParameters, keccak256, toFunctionSelector, toHex, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { afterAll, describe, expect, it, vi } from "vitest";
import { parseDispatchRecord, parseDispatchResult } from "../src/dispatch.js";
import { createMetalTestnetClient } from "../shopper/metal.js";
import { createFileDispatchStore, type DispatchRecord } from "../shopper/payments.js";

const dirs: string[] = [];
const tempJournal = () => { const d = mkdtempSync(join(tmpdir(), "tpa-settle-")); dirs.push(d); return { dir: d, path: join(d, "dispatch.json") }; };
afterAll(() => { for (const d of dirs) rmSync(d, { recursive: true, force: true }); });

const TX = `0x${"ab".repeat(32)}`;
const PAYEE = "0x0000000000000000000000000000000000000002";
const base = (over: Record<string, unknown> = {}) => ({
  intentId: "i".repeat(64), mandateHash: "a".repeat(64), checkoutId: "co-1", rail: "metal-usdz", merchantId: "harbor-supply", currency: "USD",
  amountBaseUnits: "1249", payee: PAYEE, railAmount: "12490000000000000000", status: "reserved", createdAtMs: 1, updatedAtMs: 1, ...over,
});
const result = (over: Record<string, unknown> = {}) => ({ rail: "metal-usdz", mode: "testnet", status: "succeeded", reference: TX, detail: { finalized: "true" }, ...over });

describe("finding 1: the file journal fsyncs the parent directory after the rename", () => {
  it("syncs the directory after every write, and refuses when that sync fails", async () => {
    const fs = await import("node:fs");
    const { path, dir } = tempJournal();
    const store = createFileDispatchStore(path);
    // Spy through the module namespace: payments.ts calls the same node:fs bindings.
    const real = { open: fs.openSync, fsync: fs.fsyncSync, rename: fs.renameSync };
    const events: string[] = [];
    const dirFds = new Set<number>();
    vi.doMock("node:fs", async () => ({
      ...(await vi.importActual<typeof import("node:fs")>("node:fs")),
      openSync: (p: string, flags: unknown, mode?: unknown) => { const fd = (real.open as any)(p, flags, mode); if (p === dir) { dirFds.add(fd); events.push("open-dir"); } return fd; },
      fsyncSync: (fd: number) => { events.push(dirFds.has(fd) ? "fsync-dir" : "fsync-file"); return real.fsync(fd); },
      renameSync: (a: string, b: string) => { events.push("rename"); return real.rename(a, b); },
    }));
    vi.resetModules();
    const fresh = await import("../shopper/payments.js");
    const spied = fresh.createFileDispatchStore(path);
    await spied.reserve(base() as DispatchRecord);
    expect(events).toEqual(["fsync-file", "rename", "open-dir", "fsync-dir"]);

    // A failing directory sync is an uncertain write: refuse rather than report success.
    vi.doMock("node:fs", async () => ({
      ...(await vi.importActual<typeof import("node:fs")>("node:fs")),
      fsyncSync: (fd: number) => { if (fs.fstatSync(fd).isDirectory()) throw Object.assign(new Error("EIO"), { code: "EIO" }); return real.fsync(fd); },
    }));
    vi.resetModules();
    const failing = (await import("../shopper/payments.js")).createFileDispatchStore(path);
    await expect(failing.markSent("i".repeat(64), TX, 2)).rejects.toMatchObject({ reason: "dispatch_store_unavailable" });
    vi.doUnmock("node:fs");
    vi.resetModules();
    expect(await store.get("i".repeat(64))).toMatchObject({ status: "sent" }); // the rename landed; the caller was told it is uncertain
  });
});

describe("finding 2: journal rows and stored results use a closed schema", () => {
  it("accepts well-formed rows in every status", () => {
    expect(parseDispatchRecord(base())).toMatchObject({ status: "reserved" });
    expect(parseDispatchRecord(base({ status: "sent", txHash: TX }))).toMatchObject({ txHash: TX });
    expect(parseDispatchRecord(base({ status: "succeeded", txHash: TX, result: result() }))).toMatchObject({ status: "succeeded" });
    expect(parseDispatchRecord(base({ rail: "airwallex-airi", payee: "harbor-supply", railAmount: "1249", status: "succeeded", result: result({ rail: "airwallex-airi", mode: "mock", reference: "awx_mock_1" }) }))).toMatchObject({ rail: "airwallex-airi" });
  });

  it.each([
    ["an unknown key", base({ extra: "x" })],
    ["an unknown status", base({ status: "paid" })],
    ["an unknown rail", base({ rail: "wire" })],
    ["a non-USD currency", base({ currency: "EUR" })],
    ["a numeric amount", base({ amountBaseUnits: 1249 })],
    ["a zero amount", base({ amountBaseUnits: "0" })],
    ["a short mandate hash", base({ mandateHash: "abc" })],
    ["a non-address Metal payee", base({ payee: "harbor-supply" })],
    ["a string timestamp", base({ createdAtMs: "1" })],
    ["updatedAtMs before createdAtMs", base({ updatedAtMs: 0 })],
    ["a reserved row with a tx hash", base({ txHash: TX })],
    ["a sent row without a tx hash", base({ status: "sent" })],
    ["a sent row with a result", base({ status: "sent", txHash: TX, result: result() })],
    ["a succeeded row without a result", base({ status: "succeeded", txHash: TX })],
    ["a settled Metal row whose reference is not its tx", base({ status: "succeeded", txHash: TX, result: result({ reference: `0x${"cd".repeat(32)}` }) })],
    ["a result for another rail", base({ status: "succeeded", txHash: TX, result: result({ rail: "airwallex-airi" }) })],
    ["a result with an unknown mode", base({ status: "succeeded", txHash: TX, result: result({ mode: "live" }) })],
    ["a result with an unknown key", base({ status: "succeeded", txHash: TX, result: { ...result(), paid: true } })],
    ["a result with a non-string detail", base({ status: "succeeded", txHash: TX, result: result({ detail: { finalized: true } }) })],
    ["a row that is an array", [base()]],
  ])("refuses %s", (_name, row) => {
    expect(() => parseDispatchRecord(row)).toThrow(/invalid dispatch record/);
  });

  it("refuses a result with status other than succeeded", () => {
    expect(() => parseDispatchResult(result({ status: "pending" }))).toThrow(/invalid dispatch record/);
  });

  it("a journal holding a malformed or duplicate row refuses every operation, never guesses", async () => {
    const { path } = tempJournal();
    const store = createFileDispatchStore(path);
    writeFileSync(path, JSON.stringify([base({ status: "sent" })]));
    await expect(store.get("i".repeat(64))).rejects.toMatchObject({ reason: "dispatch_store_unavailable" });
    writeFileSync(path, JSON.stringify([base(), base()]));
    await expect(store.reserve(base({ intentId: "j".repeat(64) }) as DispatchRecord)).rejects.toMatchObject({ reason: "dispatch_store_unavailable" });
  });

  it("a write that would store an invalid row or result is refused and leaves the journal unchanged", async () => {
    const { path } = tempJournal();
    const store = createFileDispatchStore(path);
    await store.reserve(base() as DispatchRecord);
    const before = readFileSync(path, "utf8");
    await expect(store.markSucceeded("i".repeat(64), { ...result(), mode: "live" } as never, 2)).rejects.toMatchObject({ reason: "dispatch_store_unavailable" });
    await expect(store.reserve(base({ intentId: "k".repeat(64), currency: "EUR" }) as DispatchRecord)).rejects.toMatchObject({ reason: "dispatch_store_unavailable" });
    expect(readFileSync(path, "utf8")).toBe(before);
  });
});

describe("finding 3: the first Metal receipt must belong to the recorded transaction", () => {
  const IS_MIP20 = toFunctionSelector("isMIP20(address)");
  const DECIMALS = toFunctionSelector("decimals()");
  const BALANCE_OF = toFunctionSelector("balanceOf(address)");
  function fakeRpc(receiptHash: (sent: Hex) => Hex) {
    const calls: string[] = [];
    let sent: Hex | undefined;
    const transport = custom({
      async request({ method, params }: { method: string; params?: any }) {
        calls.push(method);
        switch (method) {
          case "eth_chainId": return toHex(63825);
          case "eth_call": {
            const data = String(params[0].data ?? params[0].input);
            if (data.startsWith(IS_MIP20)) return encodeAbiParameters([{ type: "bool" }], [true]);
            if (data.startsWith(DECIMALS)) return encodeAbiParameters([{ type: "uint8" }], [18]);
            if (data.startsWith(BALANCE_OF)) return encodeAbiParameters([{ type: "uint256" }], [10n ** 24n]);
            break;
          }
          case "eth_estimateGas": return "0x5208";
          case "eth_getTransactionCount": return "0x0";
          case "eth_gasPrice": return "0x1";
          case "eth_maxPriorityFeePerGas": return "0x0";
          case "eth_blockNumber": return "0x2";
          case "eth_getBlockByNumber": return { number: "0x2", hash: `0x${"22".repeat(32)}`, baseFeePerGas: "0x1", timestamp: "0x1", transactions: [] };
          case "eth_sendRawTransaction": sent = keccak256(params[0]); return sent;
          case "eth_getTransactionReceipt": return {
            transactionHash: receiptHash(sent!), transactionIndex: "0x0", blockHash: `0x${"11".repeat(32)}`, blockNumber: "0x1", from: PAYEE, to: PAYEE,
            cumulativeGasUsed: "0x1", gasUsed: "0x1", effectiveGasPrice: "0x1", contractAddress: null, logs: [], logsBloom: `0x${"00".repeat(256)}`, status: "0x1", type: "0x0",
          };
        }
        throw new Error(`unexpected RPC ${method} in an offline test`);
      },
    }, { retryCount: 0 });
    return { calls, transport };
  }

  it("refuses a receipt for another transaction on the first (non-reconcile) path, and sends exactly once", async () => {
    const rpc = fakeRpc(() => `0x${"cd".repeat(32)}`);
    const payerKey = generatePrivateKey();
    const client = createMetalTestnetClient({ rpcUrl: "http://offline.invalid", payerKey, transport: rpc.transport, receiptTimeoutMs: 5_000 });
    const recorded: string[] = [];
    await expect(client.transfer({ from: privateKeyToAccount(payerKey).address, to: PAYEE, amount: 10n ** 18n, memo: "m", feeCap: 1_000_000n, beforeSign: async () => undefined, onSigned: async h => { recorded.push(h); } }))
      .rejects.toMatchObject({ reason: "metal_reference_mismatch" });
    expect(recorded).toHaveLength(1);
    expect(rpc.calls.filter(m => m === "eth_sendRawTransaction")).toHaveLength(1);
  });
});
