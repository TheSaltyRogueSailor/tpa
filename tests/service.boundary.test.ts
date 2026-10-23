import { describe, expect, it, vi } from "vitest";
import { createTpaAuthority } from "../src/config.js";
import { createTpaService } from "../src/service.js";

const authority = createTpaAuthority({ enabled: true, origin: "https://tpa.example.test", rpID: "tpa.example.test" });
const owner = { principalId: 1, sessionHash: "a".repeat(64), owner: true as const };
const headers = { origin: "https://tpa.example.test" };

function fakeStore() {
  return {
    tpaStatus: vi.fn(async () => ({ credentials: [], intents: [] })),
    startRegistration: vi.fn(), startAuthorization: vi.fn(), consumeRegistrationCeremony: vi.fn(), consumeAuthorizationCeremony: vi.fn(), saveVerifiedCredential: vi.fn(), getCredentialForAuthentication: vi.fn(), createIntent: vi.fn(), finalizeAuthorization: vi.fn(), consumeIntent: vi.fn(), revokeIntent: vi.fn(), revokeCredential: vi.fn(),
  } as any;
}

describe("explicit host authentication and origin boundary", () => {
  it("does not accept a missing host identity or call persistence", async () => { const store = fakeStore(); const service = createTpaService({ store, authority }); await expect(service.createIntent({ owner: undefined, headers }, { currency: "USD", amountBaseUnits: "1", recipient: "user:2", consent: true })).rejects.toMatchObject({ code: "unauthenticated" }); expect(store.createIntent).not.toHaveBeenCalled(); });
  it("does not treat an arbitrary caller as an owner", async () => { const store = fakeStore(); const service = createTpaService({ store, authority }); await expect(service.createIntent({ owner: { ...owner, owner: false } as any, headers }, { currency: "USD", amountBaseUnits: "1", recipient: "user:2", consent: true })).rejects.toMatchObject({ code: "forbidden" }); expect(store.createIntent).not.toHaveBeenCalled(); });
  it("requires the configured exact Origin and does not derive it from Host", async () => { const store = fakeStore(); const service = createTpaService({ store, authority }); await expect(service.createIntent({ owner, headers: { origin: "https://attacker.test", host: "tpa.example.test" } }, { currency: "USD", amountBaseUnits: "1", recipient: "user:2", consent: true })).rejects.toMatchObject({ code: "forbidden" }); expect(store.createIntent).not.toHaveBeenCalled(); });
  it("exposes no records to status when authority is disabled or origin mismatched", async () => { const store = fakeStore(); const disabled = createTpaService({ store, authority: createTpaAuthority({ enabled: false, origin: "https://tpa.example.test", rpID: "tpa.example.test" }) }); expect(await disabled.status({ owner, headers })).toMatchObject({ enabled: false, credentials: [], intents: [] }); const service = createTpaService({ store, authority }); expect(await service.status({ owner, headers: { origin: "https://evil.test" } })).toMatchObject({ originMatches: false, credentials: [], intents: [] }); expect(store.tpaStatus).not.toHaveBeenCalled(); });
});
