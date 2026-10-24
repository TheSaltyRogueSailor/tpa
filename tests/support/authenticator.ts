import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import { encodeCBOR } from "@levischuck/tiny-cbor";

const b64 = (value: Uint8Array | string) => Buffer.from(value).toString("base64url");

/** Synthetic platform authenticator: real P-256 keys, real COSE/CBOR, real ECDSA signatures. */
export function syntheticAuthenticator(ORIGIN: string, RP_ID: string) {
  const credentialId = randomBytes(32);
  const pair = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  let counter = 0;
  const jwk = pair.publicKey.export({ format: "jwk" });
  const coseKey = encodeCBOR(new Map<number, number | Uint8Array>([[1, 2], [3, -7], [-1, 1], [-2, Buffer.from(jwk.x!, "base64url")], [-3, Buffer.from(jwk.y!, "base64url")]]));
  const clientData = (type: string, challenge: string) => Buffer.from(JSON.stringify({ type, challenge, origin: ORIGIN, crossOrigin: false }));
  const authData = (flags: number, count: number, attested: boolean) => {
    const parts: Uint8Array[] = [createHash("sha256").update(RP_ID).digest(), Buffer.from([flags]), Buffer.from([(count >>> 24) & 255, (count >>> 16) & 255, (count >>> 8) & 255, count & 255])];
    if (attested) parts.push(Buffer.alloc(16), Buffer.from([0, credentialId.length]), credentialId, coseKey);
    return Buffer.concat(parts);
  };
  return {
    id: b64(credentialId),
    register(challenge: string) {
      const auth = authData(0x45, 0, true);
      return { id: b64(credentialId), rawId: b64(credentialId), type: "public-key" as const, clientExtensionResults: {}, response: { clientDataJSON: b64(clientData("webauthn.create", challenge)), attestationObject: b64(encodeCBOR(new Map<string, Parameters<typeof encodeCBOR>[0]>([["fmt", "none"], ["authData", auth], ["attStmt", new Map()]]))) } };
    },
    assert(challenge: string, opts: { signWith?: KeyObject; corruptSignature?: boolean; tamperClientData?: boolean } = {}) {
      counter += 1;
      const data = clientData("webauthn.get", challenge);
      const auth = authData(0x05, counter, false);
      const signature = Buffer.from(sign("sha256", Buffer.concat([auth, createHash("sha256").update(data).digest()]), opts.signWith ?? pair.privateKey));
      if (opts.corruptSignature) signature[signature.length - 1] = signature[signature.length - 1]! ^ 0x01;
      const sentData = opts.tamperClientData ? Buffer.from(data.toString().replace("crossOrigin\":false", "crossOrigin\":false ")) : data;
      return { id: b64(credentialId), rawId: b64(credentialId), type: "public-key" as const, clientExtensionResults: {}, response: { clientDataJSON: b64(sentData), authenticatorData: b64(auth), signature: b64(signature) } };
    },
  };
}

export type SyntheticAuthenticator = ReturnType<typeof syntheticAuthenticator>;
