import { createHash } from "node:crypto";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { tpaCeremonies, tpaCredentials, tpaIntents } from "../src/schema.js";
import { canonicalTpaMandate, type TpaCheckoutMandate, type TpaTransferMandate } from "../src/domain.js";
import { createTpaStore } from "../src/store.js";
import type { TpaHostAdapter } from "../src/host/contracts.js";

const NOW = 1_700_000_000_000;
const SESSION_A = "a".repeat(64);
const SESSION_B = "b".repeat(64);
const ORIGIN = "https://tpa.example.test";
const OTHER_ORIGIN = "https://other.example.test";
const ID = (character: string) => character.repeat(64);
const CREDENTIAL_ID = "synthetic_credential";
const credentialHash = createHash("sha256").update(CREDENTIAL_ID, "utf8").digest("hex");
const digest = (value: string) => createHash("sha256").update(value, "utf8").digest("hex");

type State = { ownerEnabled: boolean; ceremonies: Record<string, any>[]; credentials: Record<string, any>[]; intents: Record<string, any>[]; failCredentialInsert?: boolean };
let clock = NOW;

function conditionText(condition: any): string {
  const render = (value: any): string => {
    if (value == null) return "";
    if (value.queryChunks) return value.queryChunks.map(render).join("");
    if (value.constructor?.name === "StringChunk") return value.value.join("");
    if (value.constructor?.name === "Param") return JSON.stringify(value.value);
    if (value.name && value.table) return `$${value.name}`;
    return String(value.value ?? "");
  };
  return render(condition);
}
function quoted(condition: unknown, field: string): string | undefined {
  const found = conditionText(condition).match(new RegExp(`\\$${field}\\s*=\\s*("(?:[^"\\\\]|\\\\.)*")`));
  return found ? JSON.parse(found[1]!) : undefined;
}
function intentMatches(rows: Record<string, any>[], condition: unknown) {
  const text = conditionText(condition); const id = quoted(condition, "id"); const hash = quoted(condition, "mandateHash"); const session = quoted(condition, "sessionHash"); const origin = quoted(condition, "origin");
  const match = text.match(/\$mandateJson, '\$\.nonce'\)\) = ("(?:[^"\\]|\\.)*")/); const nonce = match ? JSON.parse(match[1]!) : undefined;
  return rows.filter(row => (!id || row.id === id) && (!hash || row.mandateHash === hash) && (!session || row.sessionHash === session) && (!origin || row.origin === origin) && (!nonce || JSON.parse(row.mandateJson).nonce === nonce));
}

/** No database: serialized cloned transaction state models the required row-lock behavior. */
class MemoryDb {
  private mutex = Promise.resolve();
  constructor(public state: State, readonly hooks: { advanceOnCredentialSelect?: number } = {}) {}
  select(fields: Record<string, unknown>) {
    return new SelectQuery((table, condition) => {
      const keys = Object.keys(fields);
      if (keys.includes("count")) {
        const rows = table === tpaCredentials ? this.state.credentials.filter(row => row.revokedAtMs == null) : table === tpaIntents ? intentMatches(this.state.intents, condition) : this.state.ceremonies;
        return [{ count: rows.length }];
      }
      if (table === tpaCeremonies) { const id = quoted(condition, "id"); return this.state.ceremonies.filter(row => !id || row.id === id); }
      if (table === tpaCredentials) { if (keys.includes("publicKeyBase64") && this.hooks.advanceOnCredentialSelect != null) clock = this.hooks.advanceOnCredentialSelect; const hash = quoted(condition, "credentialIdHash"); return this.state.credentials.filter(row => !hash || row.credentialIdHash === hash); }
      if (table === tpaIntents) return intentMatches(this.state.intents, condition);
      return [];
    });
  }
  insert(table: unknown) { return { values: async (values: Record<string, any>) => { if (table === tpaCredentials && this.state.failCredentialInsert) throw new Error("synthetic insert failure"); if (table === tpaCredentials) this.state.credentials.push(structuredClone(values)); else if (table === tpaIntents) this.state.intents.push(structuredClone(values)); else if (table === tpaCeremonies) this.state.ceremonies.push(structuredClone(values)); } }; }
  update(table: unknown) { return { set: (values: Record<string, unknown>) => ({ where: async () => [{ affectedRows: this.apply(table, values) }] }) }; }
  private apply(table: unknown, values: Record<string, unknown>) {
    if (table === tpaCeremonies) { const row = this.state.ceremonies[0]; if (!row) return 0; if ("consumedAtMs" in values) { if (row.consumedAtMs != null) return 0; Object.assign(row, values); return 1; } if ("completedAtMs" in values) { if (row.completedAtMs != null || row.registeredCredentialIdHash != null) return 0; Object.assign(row, values); return 1; } }
    if (table === tpaCredentials) { const row = this.state.credentials[0]; if (!row || row.revokedAtMs != null) return 0; if ("counter" in values) { const changed = row.counter === values.counter ? 0 : 1; Object.assign(row, values); return changed; } if ("revokedAtMs" in values) { Object.assign(row, values); return 1; } }
    if (table === tpaIntents) { const row = this.state.intents[0]; if (!row) return 0; if ("state" in values) { const expected = values.state === "authorized" ? "pending" : values.state === "consumed" ? "authorized" : row.state; if (row.state !== expected) return 0; Object.assign(row, values); return 1; } }
    return 0;
  }
  async transaction<T>(callback: (tx: MemoryDb) => Promise<T>): Promise<T> { let release!: () => void; const prior = this.mutex; this.mutex = new Promise(resolve => { release = resolve; }); await prior; const draft = structuredClone(this.state) as State; try { const result = await callback(new MemoryDb(draft, this.hooks)); this.state = draft; return result; } finally { release(); } }
}
class SelectQuery<T = Record<string, any>> implements PromiseLike<T[]> { private maximum = Infinity; private table: unknown; private condition: unknown; constructor(private readonly rows: (table: unknown, condition: unknown) => T[]) {} from(table: unknown) { this.table = table; return this; } where(condition: unknown) { this.condition = condition; return this; } orderBy(..._fields: unknown[]) { return this; } limit(value: number) { this.maximum = value; return this; } for(_mode: string) { return this; } then<TResult1 = T[], TResult2 = never>(ok?: ((value: T[]) => TResult1 | PromiseLike<TResult1>) | null, no?: ((reason: unknown) => TResult2 | PromiseLike<TResult2>) | null) { return Promise.resolve(this.rows(this.table, this.condition).slice(0, this.maximum)).then(ok, no); } }

let database: MemoryDb; let advanceOnOwnerLock: number | undefined; let store: ReturnType<typeof createTpaStore>;
function mandate(overrides: Partial<TpaTransferMandate> = {}): TpaTransferMandate { const issuedAt = Math.floor(NOW / 1_000); return { type: "TPA-mandate", version: "2.0", action: "transfer-authorization-pilot", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot", amountBaseUnits: "1", recipient: "user:2", feeBaseUnits: "0", nonce: ID("d"), issuedAt, expires: issuedAt + 300, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v2", ...overrides }; }
function checkoutMandate(): TpaCheckoutMandate { const issuedAt = Math.floor(NOW / 1_000); return { type: "TPA-mandate", version: "3.0", action: "checkout-authorization", issuerUserId: 1, currency: "USD", paymentNetwork: "internal-usd-pilot", merchant: { id: "acme", name: "Acme" }, items: [{ sku: "ITEM", qty: 1, unitPriceBaseUnits: "1" }], shipping: { method: "standard", costBaseUnits: "0" }, subtotalBaseUnits: "1", taxBaseUnits: "0", amountBaseUnits: "1", recipient: "user:2", feeBaseUnits: "0", nonce: ID("e"), issuedAt, expires: issuedAt + 300, scope: "single_use", ledgerDomain: "dingdong-tpa/rootstock-testnet/attestation-v3" }; }
function intent(overrides: Record<string, any> = {}) { const value = mandate(); return { id: ID("a"), userId: 1, sessionHash: SESSION_A, origin: ORIGIN, mandateJson: JSON.stringify(value), mandateHash: digest(canonicalTpaMandate(value)), state: "pending", authorizedCredentialIdHash: null, createdAtMs: NOW - 1, expiresAtMs: value.expires * 1_000, authorizedAtMs: null, consumedAtMs: null, revokedAtMs: null, ...overrides }; }
function credential(overrides: Record<string, any> = {}) { return { credentialIdHash: credentialHash, credentialId: CREDENTIAL_ID, publicKeyBase64: "public_key", counter: 0, transportsJson: "[]", label: "Registered device", deviceType: "singleDevice", backedUp: false, createdAtMs: NOW - 1, revokedAtMs: null, userId: 1, ...overrides }; }
function registrationCeremony(overrides: Record<string, any> = {}) { return { id: ID("c"), userId: 1, sessionHash: SESSION_A, origin: ORIGIN, kind: "registration", challenge: "c".repeat(43), intentId: null, label: "Registered device", expiresAtMs: NOW + 1_000, consumedAtMs: NOW - 1, completedAtMs: null, registeredCredentialIdHash: null, createdAtMs: NOW - 2, ...overrides }; }
function reset(state: Partial<State> = {}, hooks: { advanceOnOwnerLock?: number; advanceOnCredentialSelect?: number } = {}) { clock = NOW; advanceOnOwnerLock = hooks.advanceOnOwnerLock; database = new MemoryDb({ ownerEnabled: true, ceremonies: [], credentials: [], intents: [], ...state }, { advanceOnCredentialSelect: hooks.advanceOnCredentialSelect }); const host: TpaHostAdapter = { getDb: async () => database as never, assertOwnerForUpdate: async (_tx, userId) => { if (advanceOnOwnerLock != null) clock = advanceOnOwnerLock; if (userId !== 1 || !database.state.ownerEnabled) throw new Error("denied"); } }; store = createTpaStore(host); }
const boundA = { userId: 1, sessionHash: SESSION_A, origin: ORIGIN }; const boundB = { userId: 1, sessionHash: SESSION_B, origin: ORIGIN }; const reject = (kind: string) => expect.objectContaining({ kind });
beforeEach(() => { vi.spyOn(Date, "now").mockImplementation(() => clock); reset(); }); afterEach(() => vi.restoreAllMocks());

describe("standalone final lifecycle extraction", () => {
  it("denies host-disabled owners before data mutation", async () => { reset({ ownerEnabled: false, ceremonies: [registrationCeremony()] }); await expect(store.saveVerifiedCredential({ ...boundA, ceremonyId: ID("c"), credentialId: CREDENTIAL_ID, publicKeyBase64: "public_key", counter: 0, transports: [], label: "Registered device", deviceType: "singleDevice", backedUp: false })).rejects.toEqual(reject("unavailable")); expect(database.state.credentials).toEqual([]); });
  it("rejects future issue time and expiry beyond the trusted five-minute bound", async () => { await expect(store.createIntent({ ...boundA, id: ID("1"), mandate: mandate({ issuedAt: Math.floor(NOW / 1_000) + 1 }) })).rejects.toEqual(reject("intent")); await expect(store.createIntent({ ...boundA, id: ID("2"), mandate: mandate({ expires: Math.floor(NOW / 1_000) + 301 }) })).rejects.toEqual(reject("intent")); });
  it("rechecks mandate expiry after owner-lock delay", async () => { reset({}, { advanceOnOwnerLock: NOW + 1_000 }); await expect(store.createIntent({ ...boundA, id: ID("3"), mandate: mandate({ expires: Math.floor((NOW + 1_000) / 1_000) }) })).rejects.toEqual(reject("intent")); expect(database.state.intents).toEqual([]); });
  it("rejects duplicate mandate and altered mandate with a reused nonce", async () => { const original = mandate(); reset({ intents: [intent({ mandateJson: JSON.stringify(original), mandateHash: digest(canonicalTpaMandate(original)) })] }); await expect(store.createIntent({ ...boundA, id: ID("4"), mandate: original })).rejects.toEqual(reject("intent")); await expect(store.createIntent({ ...boundA, id: ID("5"), mandate: mandate({ amountBaseUnits: "2" }) })).rejects.toEqual(reject("intent")); });
  it("serializes concurrent canonical-hash or nonce-equivalent creates", async () => { const value = mandate(); const changed = mandate({ amountBaseUnits: "2" }); const outcomes = await Promise.allSettled([store.createIntent({ ...boundA, id: ID("6"), mandate: value }), store.createIntent({ ...boundA, id: ID("7"), mandate: value }), store.createIntent({ ...boundA, id: ID("8"), mandate: changed })]); expect(outcomes.filter(outcome => outcome.status === "fulfilled")).toHaveLength(1); expect(database.state.intents).toHaveLength(1); });
  it("claims a registration ceremony once and binds label, session, origin, and post-lock lifetime", async () => { const value = { ...boundA, ceremonyId: ID("c"), credentialId: CREDENTIAL_ID, publicKeyBase64: "public_key", counter: 0, transports: [], label: "Registered device", deviceType: "singleDevice", backedUp: false }; reset({ ceremonies: [registrationCeremony()] }); const outcomes = await Promise.allSettled([store.saveVerifiedCredential(value), store.saveVerifiedCredential({ ...value, credentialId: "different_credential" })]); expect(outcomes.filter(outcome => outcome.status === "fulfilled")).toHaveLength(1); expect(database.state.ceremonies[0]).toMatchObject({ completedAtMs: NOW, registeredCredentialIdHash: digest(CREDENTIAL_ID) }); reset({ ceremonies: [registrationCeremony({ expiresAtMs: NOW + 1 })] }, { advanceOnCredentialSelect: NOW + 1 }); await expect(store.saveVerifiedCredential(value)).rejects.toEqual(reject("ceremony")); });
  it("rolls ceremony completion back when credential persistence fails", async () => { reset({ ceremonies: [registrationCeremony()], failCredentialInsert: true }); await expect(store.saveVerifiedCredential({ ...boundA, ceremonyId: ID("c"), credentialId: CREDENTIAL_ID, publicKeyBase64: "public_key", counter: 0, transports: [], label: "Registered device", deviceType: "singleDevice", backedUp: false })).rejects.toEqual(reject("unavailable")); expect(database.state.ceremonies[0]).toMatchObject({ completedAtMs: null, registeredCredentialIdHash: null }); });
  it("rolls credential persistence and ceremony completion back when its atomic audit hook refuses", async () => { reset({ ceremonies: [registrationCeremony()] }); await expect(store.saveVerifiedCredential({ ...boundA, ceremonyId: ID("c"), credentialId: CREDENTIAL_ID, publicKeyBase64: "public_key", counter: 0, transports: [], label: "Registered device", deviceType: "singleDevice", backedUp: false, afterSave: async () => { throw new Error("audit unavailable"); } })).rejects.toEqual(reject("unavailable")); expect(database.state.credentials).toEqual([]); expect(database.state.ceremonies[0]).toMatchObject({ completedAtMs: null, registeredCredentialIdHash: null }); });
  it("uses an exact owner-session-origin direct read rather than a status listing", async () => { reset({ intents: [intent()] }); await expect(store.readIntent({ ...boundA, intentId: ID("a") })).resolves.toMatchObject({ id: ID("a"), state: "pending" }); await expect(store.readIntent({ ...boundB, intentId: ID("a") })).resolves.toBeNull(); await expect(store.readIntent({ ...boundA, intentId: ID("z") })).resolves.toBeNull(); });
  it("rejects a raw v3 create without an evidence lifecycle hook", async () => { await expect(store.createIntent({ ...boundA, id: ID("f"), mandate: checkoutMandate() })).rejects.toEqual(reject("integrity")); expect(database.state.intents).toEqual([]); });
  it("allows same-origin session recovery for status/revoke but keeps authorize and consume exact-session", async () => { reset({ intents: [intent()], credentials: [credential()] }); expect((await store.tpaStatus(boundB)).intents).toHaveLength(1); await expect(store.finalizeAuthorization({ ...boundB, intentId: ID("a"), credentialId: CREDENTIAL_ID, newCounter: 0 })).rejects.toEqual(reject("intent")); expect((await store.revokeIntent({ ...boundB, intentId: ID("a") })).state).toBe("revoked"); reset({ intents: [intent({ state: "authorized", authorizedCredentialIdHash: credentialHash })], credentials: [credential()] }); await expect(store.consumeIntent({ ...boundB, intentId: ID("a") })).rejects.toEqual(reject("intent")); reset({ intents: [intent({ origin: OTHER_ORIGIN })] }); await expect(store.revokeIntent({ ...boundB, intentId: ID("a") })).rejects.toEqual(reject("intent")); });
});
