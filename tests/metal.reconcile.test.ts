/**
 * Metal reconcile after a restart, and tx-reference binding. No RPC: every client here uses an in-process viem
 * custom transport that answers only eth_chainId, eth_call (isMIP20 / decimals) and eth_getTransactionReceipt.
 */
import { custom, encodeAbiParameters, toFunctionSelector, toHex, type Hex } from "viem";
import { generatePrivateKey, privateKeyToAccount } from "viem/accounts";
import { describe, expect, it, vi } from "vitest";
import { createMetalTestnetClient } from "../shopper/metal.js";
import { createMetalUsdzAdapter, type MetalClient, type PaymentRequest } from "../shopper/payments.js";
import { boundFixture, boundLedger } from "./support/dispatch.js";

const IS_MIP20 = toFunctionSelector("isMIP20(address)");
const DECIMALS = toFunctionSelector("decimals()");
const TX = `0x${"ab".repeat(32)}` as Hex;
const OTHER_TX = `0x${"cd".repeat(32)}` as Hex;
const payee = "0x0000000000000000000000000000000000000002";

function fakeRpc(net: { chainId?: number; isMip20?: boolean; decimals?: number; receiptHash?: Hex | null } = {}) {
  const calls: string[] = [];
  const transport = custom({
    async request({ method, params }: { method: string; params?: unknown }) {
      calls.push(method);
      if (method === "eth_chainId") return toHex(net.chainId ?? 63825);
      if (method === "eth_call") {
        const data = String((params as Array<{ data?: string; input?: string }>)[0]?.data ?? (params as Array<{ input?: string }>)[0]?.input);
        if (data.startsWith(IS_MIP20)) return encodeAbiParameters([{ type: "bool" }], [net.isMip20 ?? true]);
        if (data.startsWith(DECIMALS)) return encodeAbiParameters([{ type: "uint8" }], [net.decimals ?? 18]);
      }
      if (method === "eth_getTransactionReceipt") {
        if (!net.receiptHash) return null;
        return { transactionHash: net.receiptHash, transactionIndex: "0x0", blockHash: `0x${"11".repeat(32)}`, blockNumber: "0x1", from: payee, to: payee,
          cumulativeGasUsed: "0x1", gasUsed: "0x1", effectiveGasPrice: "0x1", contractAddress: null, logs: [], logsBloom: `0x${"00".repeat(256)}`, status: "0x1", type: "0x0" };
      }
      throw new Error(`unexpected RPC ${method} in an offline test`);
    },
  }, { retryCount: 0 });
  return { calls, transport };
}

function restartedClient(net: Parameters<typeof fakeRpc>[0] = {}) {
  const rpc = fakeRpc(net);
  const payerKey = generatePrivateKey(); // throwaway, generated per test
  const client = createMetalTestnetClient({ rpcUrl: "http://offline.invalid", payerKey, transport: rpc.transport });
  return { ...rpc, client, payer: privateKeyToAccount(payerKey).address };
}
const reconcile = (c: ReturnType<typeof restartedClient>, txHash: string = TX) => c.client.reconcile!({ txHash, from: c.payer, to: payee, amount: 10n ** 18n });

describe("Metal reconcile after a restart checks the network before trusting a receipt", () => {
  it.each([
    ["wrong chain id", { chainId: 1 }],
    ["USDZ not a MIP20 token", { isMip20: false }],
    ["wrong USDZ decimals", { decimals: 6 }],
  ] as const)("refuses on %s and never reads the receipt", async (_name, net) => {
    const c = restartedClient({ ...net, receiptHash: TX });
    await expect(reconcile(c)).rejects.toMatchObject({ reason: "metal_network_check" });
    expect(c.calls).not.toContain("eth_getTransactionReceipt");
  });

  it("checks chain, token and decimals first, then reads the receipt (not mined stays pending)", async () => {
    const c = restartedClient({ receiptHash: null });
    await expect(reconcile(c)).resolves.toBeNull();
    expect(c.calls).toEqual(["eth_chainId", "eth_call", "eth_call", "eth_getTransactionReceipt"]);
  });

  it("refuses a receipt that belongs to a different transaction than the recorded one", async () => {
    const c = restartedClient({ receiptHash: OTHER_TX });
    await expect(reconcile(c)).rejects.toMatchObject({ reason: "metal_reference_mismatch" });
  });
});

describe("Metal adapter binds the result to the recorded tx hash and never resends", () => {
  const fx = boundFixture({ intentId: "ref-intent", quoteId: "ref-checkout", payee });
  const request = (): PaymentRequest => fx.request();

  it("a finalized transfer reporting a different hash than it recorded is not settled; retry reconciles, no resend", async () => {
    const transfer = vi.fn(async ({ onSigned }: { onSigned?: (h: string) => Promise<void> }) => { await onSigned?.(TX); return { txHash: OTHER_TX, finalized: true }; });
    const client: MetalClient = { chainId: 63825, mode: "mock", balanceOf: async () => 0n, transfer, reconcile: async () => null };
    const ledger = boundLedger([fx]);
    const rail = createMetalUsdzAdapter(client, payee, ledger);
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "dispatch_result_mismatch" });
    expect(await ledger.settled("ref-checkout", OTHER_TX)).toBeNull();
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(transfer).toHaveBeenCalledTimes(1);
  });

  it("a finalized reconcile result for a different hash than the recorded one is refused, no resend", async () => {
    const transfer = vi.fn(async ({ onSigned }: { onSigned?: (h: string) => Promise<void> }) => { await onSigned?.(TX); throw new Error("receipt timeout"); });
    const client: MetalClient = { chainId: 63825, mode: "mock", balanceOf: async () => 0n, transfer, reconcile: async () => ({ txHash: OTHER_TX, finalized: true }) };
    const ledger = boundLedger([fx]);
    const rail = createMetalUsdzAdapter(client, payee, ledger);
    await expect(rail.pay(request())).rejects.toThrow("receipt timeout");
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "dispatch_result_mismatch" });
    expect(await ledger.settled("ref-checkout", OTHER_TX)).toBeNull();
    expect(transfer).toHaveBeenCalledTimes(1);
  });

  it("a non-final reconcile of the recorded hash stays pending", async () => {
    const transfer = vi.fn(async ({ onSigned }: { onSigned?: (h: string) => Promise<void> }) => { await onSigned?.(TX); throw new Error("receipt timeout"); });
    const client: MetalClient = { chainId: 63825, mode: "mock", balanceOf: async () => 0n, transfer, reconcile: async ({ txHash }) => ({ txHash, finalized: false }) };
    const rail = createMetalUsdzAdapter(client, payee, boundLedger([fx]));
    await expect(rail.pay(request())).rejects.toThrow("receipt timeout");
    await expect(rail.pay(request())).rejects.toMatchObject({ reason: "dispatch_pending_reconcile" });
    expect(transfer).toHaveBeenCalledTimes(1);
  });
});
