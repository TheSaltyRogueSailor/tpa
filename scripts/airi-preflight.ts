/**
 * Read-only Airi preflight for the live Airwallex rail: `airi-cli auth whoami` and `airi-cli payment-methods list`.
 * Prints the session expiry and each payment method as id + brand + last 4 digits only. It never creates a mandate,
 * never fetches a credential and never signs in (a human runs `airi-cli auth login`).
 *
 *   pnpm airi:preflight
 */
import { createAiriCliRunner, createAiriClient, maskPaymentMethod } from "../shopper/airi.js";

async function main() {
  const client = createAiriClient(createAiriCliRunner());
  const me = await client.whoami();
  console.log(`Airi session: ${me.authenticated ? `signed in (client "${me.clientName ?? "?"}", expires ${me.sessionExpires ?? "?"})` : "NOT signed in; run `airi-cli auth login --client-name \"TPA Shopper\"`"}`);
  if (!me.authenticated) { process.exitCode = 1; return; }
  const methods = await client.listPaymentMethods();
  if (!methods.length) {
    console.log("No agent-enabled payment methods. In https://app.airi.com add a card or make an existing card available to agents, then re-run.");
    process.exitCode = 1;
    return;
  }
  for (const m of methods) console.log(`  ${m.id}  ${maskPaymentMethod(m)}${m.nickname ? `  (${m.nickname})` : ""}`);
  console.log("Set AIRI_PAYMENT_METHOD_ID to one of these ids for AIRI_LIVE=1.");
}
main().catch(error => { console.error(error instanceof Error ? `${error.name}: ${error.message}` : "Airi preflight failed"); process.exitCode = 1; });
