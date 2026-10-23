import { createHash, generateKeyPairSync, randomBytes, sign } from "node:crypto";
import { describe, expect, it } from "vitest";
// Tiny CBOR is the maintained transitive encoder used by the installed
// SimpleWebAuthn server package; it creates the real COSE and attestation CBOR.
import { encodeCBOR } from "@levischuck/tiny-cbor";
import {
  parseAuthenticationResponse,
  parseRegistrationResponse,
  verifyAuthentication,
  verifyRegistration,
} from "../src/webauthn.js";

const ORIGIN = "https://tpa.example.test";
const RP_ID = "tpa.example.test";
const b64 = (value: Uint8Array | string) => Buffer.from(value).toString("base64url");

type Fixture = ReturnType<typeof fixture>;

/** Ephemeral P-256 test authenticator; neither wallet material nor test secrets are emitted. */
function fixture() {
  const challenge = randomBytes(32).toString("base64url");
  const credentialId = randomBytes(32);
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const jwk = pair.publicKey.export({ format: "jwk" });
  const coseKey = encodeCBOR(new Map<number, number | Uint8Array>([
    [1, 2], [3, -7], [-1, 1],
    [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")],
  ]));
  const clientData = (type: "webauthn.create" | "webauthn.get", value = challenge, origin = ORIGIN) =>
    Buffer.from(JSON.stringify({ type, challenge: value, origin, crossOrigin: false }));
  const authenticatorData = (flags: number, counter: number, attested = false, rpID = RP_ID) => {
    const bytes: Uint8Array[] = [
      createHash("sha256").update(rpID).digest(), Buffer.from([flags]), Buffer.from([0, 0, 0, counter]),
    ];
    if (attested) bytes.push(Buffer.alloc(16), Buffer.from([0, credentialId.length]), credentialId, coseKey);
    return Buffer.concat(bytes);
  };
  const registration = (overrides: { challenge?: string; origin?: string; rpID?: string; flags?: number } = {}) => {
    const data = clientData("webauthn.create", overrides.challenge, overrides.origin);
    const auth = authenticatorData(overrides.flags ?? 0x45, 0, true, overrides.rpID);
    return {
      id: b64(credentialId), rawId: b64(credentialId), type: "public-key" as const, clientExtensionResults: {},
      response: {
        clientDataJSON: b64(data),
        attestationObject: b64(encodeCBOR(new Map<string, Parameters<typeof encodeCBOR>[0]>([["fmt", "none"], ["authData", auth], ["attStmt", new Map()]]))),
      },
    };
  };
  const assertion = (overrides: { challenge?: string; origin?: string; rpID?: string; flags?: number; corruptSignature?: boolean } = {}) => {
    const data = clientData("webauthn.get", overrides.challenge, overrides.origin);
    const auth = authenticatorData(overrides.flags ?? 0x05, 1, false, overrides.rpID);
    const signed = Buffer.concat([auth, createHash("sha256").update(data).digest()]);
    const signature = Buffer.from(sign("sha256", signed, pair.privateKey));
    if (overrides.corruptSignature) signature[0] = (signature[0] ?? 0) ^ 0x01;
    return {
      id: b64(credentialId), rawId: b64(credentialId), type: "public-key" as const, clientExtensionResults: {},
      response: { clientDataJSON: b64(data), authenticatorData: b64(auth), signature: b64(signature) },
    };
  };
  return { challenge, registration, assertion };
}

async function verifiedRegistration(value: Fixture) {
  return verifyRegistration({
    response: parseRegistrationResponse(value.registration()), challenge: value.challenge, origin: ORIGIN, rpID: RP_ID,
  });
}

describe("real synthetic ES256 WebAuthn verification", () => {
  it("accepts an attestation:none P-256 registration and a correctly signed UV assertion", async () => {
    const value = fixture();
    const registration = await verifiedRegistration(value);
    expect(registration.verified).toBe(true);
    expect(registration.registrationInfo?.userVerified).toBe(true);

    const assertion = await verifyAuthentication({
      response: parseAuthenticationResponse(value.assertion()), challenge: value.challenge, origin: ORIGIN, rpID: RP_ID,
      credential: {
        id: value.assertion().id,
        publicKey: registration.registrationInfo!.credential.publicKey,
        counter: 0,
      },
    });
    expect(assertion).toMatchObject({ verified: true, authenticationInfo: { userVerified: true, newCounter: 1 } });
  });

  it("rejects registration mismatch on challenge, origin, RP ID, and absent user verification", async () => {
    const value = fixture();
    await expect(verifyRegistration({ response: parseRegistrationResponse(value.registration({ challenge: "wrong" })), challenge: value.challenge, origin: ORIGIN, rpID: RP_ID })).rejects.toThrow(/challenge/i);
    await expect(verifyRegistration({ response: parseRegistrationResponse(value.registration({ origin: "https://evil.example" })), challenge: value.challenge, origin: ORIGIN, rpID: RP_ID })).rejects.toThrow(/origin/i);
    await expect(verifyRegistration({ response: parseRegistrationResponse(value.registration({ rpID: "evil.example" })), challenge: value.challenge, origin: ORIGIN, rpID: RP_ID })).rejects.toThrow(/RP ID|RPID|relying party/i);
    await expect(verifyRegistration({ response: parseRegistrationResponse(value.registration({ flags: 0x41 })), challenge: value.challenge, origin: ORIGIN, rpID: RP_ID })).rejects.toThrow(/User verification/i);
  });

  it("rejects assertion bad signature, challenge, origin, RP ID, and absent UV after a valid registration", async () => {
    const value = fixture();
    const registration = await verifiedRegistration(value);
    const credential = { id: value.assertion().id, publicKey: registration.registrationInfo!.credential.publicKey, counter: 0 };
    const verify = (response: ReturnType<Fixture["assertion"]>) => verifyAuthentication({ response: parseAuthenticationResponse(response), challenge: value.challenge, origin: ORIGIN, rpID: RP_ID, credential });
    await expect(verify(value.assertion({ corruptSignature: true }))).rejects.toThrow(/signature|ECDSA/i);
    await expect(verify(value.assertion({ challenge: "wrong" }))).rejects.toThrow(/challenge/i);
    await expect(verify(value.assertion({ origin: "https://evil.example" }))).rejects.toThrow(/origin/i);
    await expect(verify(value.assertion({ rpID: "evil.example" }))).rejects.toThrow(/RP ID|RPID|relying party/i);
    await expect(verify(value.assertion({ flags: 0x01 }))).rejects.toThrow(/User verification/i);
  });
});
