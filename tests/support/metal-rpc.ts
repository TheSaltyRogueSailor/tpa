/**
 * Offline in-process JSON-RPC for the real Metal testnet client (createMetalTestnetClient's `transport` seam).
 * No network: every call is answered here, and any unexpected method throws. `onCall` lets a test act at a precise
 * point of preparation (for example advance a trusted clock during gas estimation).
 */
import { custom, encodeAbiParameters, keccak256, toFunctionSelector, toHex, type Hex } from "viem";

const IS_MIP20 = toFunctionSelector("isMIP20(address)");
const DECIMALS = toFunctionSelector("decimals()");
const BALANCE_OF = toFunctionSelector("balanceOf(address)");

export function offlineMetalRpc(options: { onCall?: (method: string) => void } = {}) {
  const calls: string[] = [];
  let sent: Hex | undefined;
  const transport = custom({
    async request({ method, params }: { method: string; params?: any }) {
      calls.push(method);
      options.onCall?.(method);
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
          transactionHash: sent, transactionIndex: "0x0", blockHash: `0x${"11".repeat(32)}`, blockNumber: "0x1", from: "0x0000000000000000000000000000000000000002", to: "0x0000000000000000000000000000000000000002",
          cumulativeGasUsed: "0x1", gasUsed: "0x1", effectiveGasPrice: "0x1", contractAddress: null, logs: [], logsBloom: `0x${"00".repeat(256)}`, status: "0x1", type: "0x0",
        };
      }
      throw new Error(`unexpected RPC ${method} in an offline test`);
    },
  }, { retryCount: 0 });
  return { calls, transport, sends: () => calls.filter(m => m === "eth_sendRawTransaction").length };
}
