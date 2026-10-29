import { createDispatchLedger, createMemoryDispatchStore, type BoundIntent, type DispatchLedger, type PaymentRequest } from "../../shopper/payments.js";
import type { TpaDispatchStore } from "../../src/dispatch.js";

/** Test-only intent reader: reports each given request's intent as consumed under exactly that request's terms. */
export function consumedLookup(...requests: PaymentRequest[]) {
  return async (intentId: string): Promise<BoundIntent | null> => {
    const r = requests.find(x => x.receipt.intentId === intentId);
    return r ? { id: intentId, mandateHash: r.receipt.mandateHash, state: "consumed", mandate: { version: "3.0", currency: r.currency, amountBaseUnits: r.amountBaseUnits, merchant: { id: r.merchant.id } } } : null;
  };
}
/** A permission-bound ledger for unit tests (memory store unless one is given). */
export function boundLedger(requests: PaymentRequest[], store: TpaDispatchStore = createMemoryDispatchStore()): DispatchLedger {
  return createDispatchLedger({ store, lookupIntent: consumedLookup(...requests) });
}
