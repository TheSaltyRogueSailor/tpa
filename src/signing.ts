import { createPrivateKey, createPublicKey, sign, verify, type KeyObject } from "node:crypto";

/**
 * Server mandate signatures (Ed25519) with key ids for rotation.
 *
 * The signed message is domain-separated and binds the key id:
 *   "TPA-MANDATE-SIG/1\n" + keyId + "\n" + canonicalTpaMandate(mandate)
 * Only the active key signs. Any configured verification key (active or retired)
 * may verify, so outstanding mandates survive a rotation until they expire.
 */
export const TPA_MANDATE_SIGNATURE_ALGORITHM = "Ed25519" as const;
const KEY_ID = /^[A-Za-z0-9._-]{1,64}$/;
const SIGNATURE = /^[A-Za-z0-9_-]{86}$/;

export type TpaMandateSignature = { keyId: string; algorithm: typeof TPA_MANDATE_SIGNATURE_ALGORITHM; signature: string };

export type TpaMandateSigner = {
  readonly activeKeyId: string;
  readonly keyIds: readonly string[];
  sign(canonicalMandate: string): TpaMandateSignature;
  /** Returns a reason when the signature does not verify, otherwise null. */
  verify(canonicalMandate: string, signature: { keyId: string; algorithm: string; signature: string }): null | "unknown_key" | "bad_signature";
  /** Public keys only (SPKI DER, base64), safe to publish for third-party verification. */
  publicKeys(): Record<string, string>;
};

function message(keyId: string, canonical: string): Buffer {
  return Buffer.from(`TPA-MANDATE-SIG/1\n${keyId}\n${canonical}`, "utf8");
}

function asPrivateKey(value: KeyObject | string): KeyObject {
  const key = typeof value === "string" ? createPrivateKey(value.includes("BEGIN") ? value : { key: Buffer.from(value, "base64"), format: "der", type: "pkcs8" }) : value;
  if (key.type !== "private" || key.asymmetricKeyType !== "ed25519") throw new Error("TPA mandate signing key must be an Ed25519 private key.");
  return key;
}

function asPublicKey(value: KeyObject | string): KeyObject {
  const key = typeof value === "string" ? createPublicKey(value.includes("BEGIN") ? value : { key: Buffer.from(value, "base64"), format: "der", type: "spki" }) : value;
  const publicKey = key.type === "private" ? createPublicKey(key) : key;
  if (publicKey.type !== "public" || publicKey.asymmetricKeyType !== "ed25519") throw new Error("TPA mandate verification keys must be Ed25519 public keys.");
  return publicKey;
}

export function createTpaMandateSigner(config: {
  activeKeyId: string;
  privateKey: KeyObject | string;
  /** Additional (for example retired) verification keys by key id. */
  verificationKeys?: Record<string, KeyObject | string>;
}): TpaMandateSigner {
  if (!KEY_ID.test(config.activeKeyId)) throw new Error("Invalid TPA mandate signing key id.");
  const privateKey = asPrivateKey(config.privateKey);
  const keys = new Map<string, KeyObject>([[config.activeKeyId, createPublicKey(privateKey)]]);
  for (const [keyId, value] of Object.entries(config.verificationKeys ?? {})) {
    if (!KEY_ID.test(keyId)) throw new Error("Invalid TPA mandate verification key id.");
    const publicKey = asPublicKey(value);
    const existing = keys.get(keyId);
    if (existing && !existing.equals(publicKey)) throw new Error("Conflicting TPA mandate keys share one key id.");
    keys.set(keyId, publicKey);
  }
  return {
    activeKeyId: config.activeKeyId,
    keyIds: [...keys.keys()],
    sign(canonical) {
      return { keyId: config.activeKeyId, algorithm: TPA_MANDATE_SIGNATURE_ALGORITHM, signature: sign(null, message(config.activeKeyId, canonical), privateKey).toString("base64url") };
    },
    verify(canonical, value) {
      const publicKey = keys.get(value.keyId);
      if (!publicKey || value.algorithm !== TPA_MANDATE_SIGNATURE_ALGORITHM) return "unknown_key";
      if (!SIGNATURE.test(value.signature)) return "bad_signature";
      try { return verify(null, message(value.keyId, canonical), publicKey, Buffer.from(value.signature, "base64url")) ? null : "bad_signature"; }
      catch { return "bad_signature"; }
    },
    publicKeys() {
      return Object.fromEntries([...keys].map(([keyId, key]) => [keyId, key.export({ format: "der", type: "spki" }).toString("base64")]));
    },
  };
}

/**
 * Environment loader. Returns undefined when signing is not configured (checkout
 * mandates are then refused). Values come from the host secret manager:
 *   TPA_MANDATE_SIGNING_KEY_ID   active key id, e.g. "tpa-2026-10"
 *   TPA_MANDATE_SIGNING_KEY      Ed25519 private key: PKCS#8 PEM, or base64 PKCS#8 DER
 *   TPA_MANDATE_VERIFY_KEYS      optional retired keys: "kid1=<base64 SPKI DER>,kid2=<...>"
 */
export function tpaMandateSignerFromEnv(environment: NodeJS.ProcessEnv = process.env): TpaMandateSigner | undefined {
  const keyId = environment.TPA_MANDATE_SIGNING_KEY_ID;
  const privateKey = environment.TPA_MANDATE_SIGNING_KEY;
  if (!keyId || !privateKey) return undefined;
  const verificationKeys: Record<string, string> = {};
  for (const entry of (environment.TPA_MANDATE_VERIFY_KEYS ?? "").split(",").map(item => item.trim()).filter(Boolean)) {
    const separator = entry.indexOf("=");
    if (separator < 1) throw new Error("TPA_MANDATE_VERIFY_KEYS entries must be keyId=base64SpkiDer.");
    verificationKeys[entry.slice(0, separator)] = entry.slice(separator + 1);
  }
  return createTpaMandateSigner({ activeKeyId: keyId, privateKey: privateKey.replace(/\\n/g, "\n"), verificationKeys });
}
