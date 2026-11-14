/**
 * TPA Shield MCP server (stdio). Lets any MCP-capable AI agent ask TPA, before it moves money,
 * whether a checkout, payment or transfer passes the TPA checks. Read-only: no signing, no
 * transactions, no wallet keys, no secrets. Only check_token reads the network (public Solana RPC and
 * the free RugCheck API); every other tool is offline.
 *
 * Run: pnpm mcp:build && node .mcp-build/mcp/server.js
 */
import { realpathSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import { z } from "zod";
import { SHIELD_VERSION, checkCheckout, checkPayment, checkTransfer, explainReason, getPolicy, transferArgs } from "./checks.js";
import { checkToken, checkTokenArgs, tokenGatePolicy, type TokenGateIo } from "./token.js";
import { DEFAULT_SOLANA_RPC_URL } from "./token-gate/guard.js";

const READ_ONLY = { readOnlyHint: true, destructiveHint: false, idempotentHint: true, openWorldHint: false } as const;
/** check_token reads public network data, so it is not closed-world (and not idempotent: chain state changes). */
const READ_ONLY_NETWORK = { readOnlyHint: true, destructiveHint: false, idempotentHint: false, openWorldHint: true } as const;

export type TpaShieldServerOptions = { tokenGate?: TokenGateIo };

/** Only an https RPC URL (or plain http on localhost) is accepted for the Solana RPC override. */
export function resolveSolanaRpcUrl(value: string | undefined): string {
  if (!value) return DEFAULT_SOLANA_RPC_URL;
  let url: URL;
  try { url = new URL(value); } catch { throw new Error("TPA_SHIELD_SOLANA_RPC_URL is not a valid URL."); }
  const local = url.hostname === "127.0.0.1" || url.hostname === "localhost";
  if (url.protocol !== "https:" && !(url.protocol === "http:" && local)) throw new Error("TPA_SHIELD_SOLANA_RPC_URL must use https.");
  return url.toString();
}

const checkoutDoc = "A TPA checkout object: { currency: 'USD'|'DOGE', recipient, merchant: { id, name }, items: [{ sku, qty, unitPriceBaseUnits }], shipping: { method, costBaseUnits }, taxBaseUnits, totalBaseUnits }. Money is integer base units in strings (USD cents).";
const checkoutValue = z.record(z.string(), z.unknown()).describe(checkoutDoc);

function result(value: unknown) {
  return { content: [{ type: "text" as const, text: JSON.stringify(value, null, 2) }] };
}

export function createTpaShieldServer(options: TpaShieldServerOptions = {}): McpServer {
  const server = new McpServer(
    { name: "tpa-shield", version: SHIELD_VERSION },
    { instructions: "Call TPA Shield before moving money. check_payment compares what you are about to pay with what the owner approved; block means do not pay. A pass is a pre-flight result, not an approval: the owner's passkey approval is still required. check_token screens a Solana token for rug-pull and honeypot risk; block means do not buy or accept it." },
  );

  server.registerTool("check_checkout", {
    title: "Check a checkout",
    description: "Validate a checkout before asking the owner to approve it: schema, one line per SKU, total = items + shipping + tax, and the recipient rule for the currency. Returns pass or block with reasons.",
    inputSchema: { checkout: checkoutValue },
    annotations: READ_ONLY,
  }, async ({ checkout }) => result(checkCheckout(checkout)));

  server.registerTool("check_payment", {
    title: "Check a payment against the approved checkout",
    description: "Run before paying. Compares the checkout you are about to pay with the checkout the owner approved, using the same exact-match TPA runs at payment time. Any change to merchant, recipient, currency, items, prices, shipping, tax or total returns block.",
    inputSchema: {
      approved: checkoutValue.describe(`The checkout the owner approved. ${checkoutDoc}`),
      presented: checkoutValue.describe("The checkout about to be paid, exactly as the merchant presents it now."),
    },
    annotations: READ_ONLY,
  }, async ({ approved, presented }) => result(checkPayment(approved, presented)));

  server.registerTool("check_transfer", {
    title: "Check a simple transfer",
    description: "Check a simple transfer (amount, recipient, currency) before it moves. Optionally pass the approved transfer to block any change. Give amountBaseUnits (integer string) or amount (decimal string).",
    inputSchema: {
      transfer: transferArgs.describe("The transfer about to happen: { currency, recipient, amountBaseUnits | amount }."),
      approved: transferArgs.optional().describe("Optional: the transfer the owner approved."),
    },
    annotations: READ_ONLY,
  }, async ({ transfer, approved }) => result(checkTransfer(transfer, approved)));

  server.registerTool("check_token", {
    title: "Check a Solana token for rug-pull and honeypot risk",
    description: "Run before buying or accepting a Solana token. Checks freeze authority (honeypot risk), mint authority, dangerous Token-2022 extensions, transfer fees, the free RugCheck report, and, if you pass pump.fun trades and the creator wallet, holder concentration, bundled launches and creator selling. Returns pass, warn or block with reasons. Read-only network reads; no keys.",
    inputSchema: checkTokenArgs,
    annotations: READ_ONLY_NETWORK,
  }, async args => result(await checkToken(args, options.tokenGate)));

  server.registerTool("get_policy", {
    title: "Get the TPA policy",
    description: "Return what TPA Shield checks, its limits and recipient rules, what only the full TPA service enforces (passkey, signatures, single use, expiry), and what it does not check.",
    annotations: READ_ONLY,
  }, async () => {
    const policy = getPolicy();
    return result({ ...policy, preflightChecks: { ...policy.preflightChecks, check_token: "Solana token rug-pull and honeypot gate. See tokenGate." }, tokenGate: tokenGatePolicy() });
  });

  server.registerTool("explain_decision", {
    title: "Explain a TPA reason code",
    description: "Turn a TPA reason code (for example terms_changed:merchant_mismatch) into plain language and a category.",
    inputSchema: { code: z.string().min(1).max(128).describe("A reason code from a TPA Shield decision or the TPA audit log.") },
    annotations: READ_ONLY,
  }, async ({ code }) => result(explainReason(code)));

  return server;
}

export async function main(): Promise<void> {
  const server = createTpaShieldServer({ tokenGate: { rpcUrl: resolveSolanaRpcUrl(process.env.TPA_SHIELD_SOLANA_RPC_URL) } });
  await server.connect(new StdioServerTransport());
  console.error(`tpa-shield MCP server ${SHIELD_VERSION} running on stdio (read-only)`);
}

const entry = process.argv[1];
if (entry && realpathSync(entry) === realpathSync(fileURLToPath(import.meta.url))) {
  main().catch(error => {
    console.error(`tpa-shield failed to start: ${error instanceof Error ? error.name : "Error"}`);
    process.exit(1);
  });
}
