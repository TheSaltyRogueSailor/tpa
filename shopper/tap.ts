/**
 * Visa Trusted Agent Protocol (TAP): agent recognition signature and agentic payment container.
 *
 * Source of truth (verified 2026-10-28):
 *   - Visa TAP merchant specification:
 *     https://developer.visa.com/capabilities/trusted-agent-protocol/trusted-agent-protocol-specifications
 *   - Visa reference implementation: https://github.com/visa/trusted-agent-protocol (commit 16d59bd),
 *     cdn-proxy/server.js (base string construction, nonce cache, timestamp checks).
 *   - RFC 9421 HTTP Message Signatures: https://www.rfc-editor.org/rfc/rfc9421
 *
 * What the spec requires and what this module does:
 *   - Signature-Input / Signature headers per RFC 9421, covering at least "@authority" and "@path".
 *   - Required params: created, expires, keyid, alg, nonce, tag.
 *   - tag is "agent-browser-auth" (browsing / product pages) or "agent-payer-auth" (checkout / payment).
 *   - Merchant verification: block if the tag is missing, any required field is missing, created is
 *     not in the past, expires is not in the future, expires - created > 8 minutes, the nonce was seen
 *     in the last 8 minutes, the key cannot be found, or the signature does not verify.
 *   - Agentic Payment Container in the request body: { nonce, kid, alg, ...payment data, signature },
 *     signed with the same key as the message signature, nonce equal to the message signature nonce;
 *     signature base = all fields in the order received except `signature`.
 * Algorithm: Ed25519 (the spec examples and the reference cdn-proxy both use it).
 */
import { createHash, createPublicKey, randomBytes, sign as edSign, verify as edVerify, type KeyObject } from "node:crypto";

export const TAP_TAGS = ["agent-browser-auth", "agent-payer-auth"] as const;
export type TapTag = (typeof TAP_TAGS)[number];
export const TAP_MAX_WINDOW_SECONDS = 8 * 60;
export const TAP_COMPONENTS = ["@authority", "@path"] as const;
const LABEL = "sig2";

export class TapError extends Error {
  constructor(readonly reason: TapRejectReason, message: string) { super(message); this.name = "TapError"; }
}
export type TapRejectReason =
  | "not_signed" | "missing_field" | "bad_tag" | "wrong_tag" | "created_in_future" | "expired" | "window_too_long"
  | "nonce_replayed" | "unknown_key" | "bad_signature" | "container_missing_field" | "container_nonce_mismatch"
  | "container_kid_mismatch" | "container_bad_signature";

/* ------------------------------- keys ------------------------------- */
export type TapJwk = { kty: "OKP"; crv: "Ed25519"; kid: string; use: "sig"; alg: "EdDSA"; x: string };
export function publicJwk(publicKey: KeyObject): TapJwk {
  const jwk = publicKey.export({ format: "jwk" }) as { x: string };
  // RFC 7638 JWK thumbprint, the same shape as the keyid values in Visa's examples.
  const kid = createHash("sha256").update(`{"crv":"Ed25519","kty":"OKP","x":"${jwk.x}"}`).digest("base64url");
  return { kty: "OKP", crv: "Ed25519", kid, use: "sig", alg: "EdDSA", x: jwk.x };
}
/** Stand-in for the scheme's Public Keys Retrieval Service (GET /keys?keyID=...). */
export type TapKeyStore = { get(keyId: string): TapJwk | undefined };
export function createTapKeyDirectory(keys: TapJwk[] = []): TapKeyStore & { add(key: TapJwk): void } {
  const map = new Map(keys.map(k => [k.kid, k]));
  return { get: id => map.get(id), add: key => { map.set(key.kid, key); } };
}

/* ---------------------------- signature base ---------------------------- */
export type TapParams = { created: number; expires: number; keyid: string; alg: string; nonce: string; tag: string };
export function serializeSignatureParams(components: readonly string[], p: TapParams): string {
  return `(${components.map(c => `"${c}"`).join(" ")});created=${p.created};expires=${p.expires};keyid="${p.keyid}";alg="${p.alg}";nonce="${p.nonce}";tag="${p.tag}"`;
}
/** RFC 9421 section 2.5 signature base for the covered derived components. */
export function signatureBase(request: { authority: string; path: string }, components: readonly string[], paramsText: string): string {
  const lines = components.map(c => {
    if (c === "@authority") return `"@authority": ${request.authority.toLowerCase()}`;
    if (c === "@path") return `"@path": ${request.path}`;
    throw new TapError("missing_field", `Unsupported covered component ${c}.`);
  });
  lines.push(`"@signature-params": ${paramsText}`);
  return lines.join("\n");
}

/* -------------------------------- agent -------------------------------- */
export type TapSigner = { keyId: string; jwk: TapJwk; signRequest(req: { authority: string; path: string; tag: TapTag; nonce?: string; nowSeconds: number; ttlSeconds?: number }): { headers: Record<string, string>; nonce: string; base: string }; signContainer<T extends Record<string, unknown>>(nonce: string, payload: T): T & { nonce: string; kid: string; alg: string; signature: string } };
export function createTapSigner(privateKey: KeyObject): TapSigner {
  const jwk = publicJwk(createPublicKey(privateKey));
  return {
    keyId: jwk.kid, jwk,
    signRequest({ authority, path, tag, nonce = randomBytes(64).toString("base64"), nowSeconds, ttlSeconds = 300 }) {
      const params: TapParams = { created: nowSeconds, expires: nowSeconds + ttlSeconds, keyid: jwk.kid, alg: "ed25519", nonce, tag };
      const paramsText = serializeSignatureParams(TAP_COMPONENTS, params);
      const base = signatureBase({ authority, path }, TAP_COMPONENTS, paramsText);
      const sig = edSign(null, Buffer.from(base, "utf8"), privateKey).toString("base64");
      return { headers: { "signature-input": `${LABEL}=${paramsText}`, signature: `${LABEL}=:${sig}:` }, nonce, base };
    },
    signContainer(nonce, payload) {
      const unsigned = { nonce, kid: jwk.kid, alg: "ed25519", ...payload };
      const signature = edSign(null, Buffer.from(JSON.stringify(unsigned), "utf8"), privateKey).toString("base64");
      return { ...unsigned, signature } as never;
    },
  };
}

/* ------------------------------- merchant ------------------------------- */
function parseSignatureInput(header: string): { label: string; components: string[]; paramsText: string; params: Record<string, string> } {
  const match = /^\s*([a-z0-9_-]+)=(\(([^)]*)\)(.*))$/i.exec(header);
  if (!match) throw new TapError("not_signed", "Signature-Input is not an RFC 9421 dictionary member.");
  const components = [...match[3]!.matchAll(/"([^"]+)"/g)].map(m => m[1]!);
  const params: Record<string, string> = {};
  for (const part of match[4]!.split(";").slice(1)) {
    const eq = part.indexOf("=");
    if (eq < 0) continue;
    params[part.slice(0, eq).trim()] = part.slice(eq + 1).trim().replace(/^"(.*)"$/, "$1");
  }
  return { label: match[1]!, components, paramsText: match[2]!.trim(), params };
}

export type TapVerified = { keyId: string; tag: TapTag; nonce: string; created: number; expires: number };
export type TapVerifier = { verifyRequest(req: { authority: string; path: string; headers: Record<string, string | string[] | undefined>; nowSeconds: number; requireTag?: TapTag }): TapVerified; verifyContainer(container: unknown, request: TapVerified): void };

/** Merchant-side verifier implementing the TAP verification steps, with an 8-minute nonce cache. */
export function createTapVerifier(keys: TapKeyStore): TapVerifier {
  const seen = new Map<string, number>();
  const header = (h: Record<string, string | string[] | undefined>, name: string) => { const v = h[name] ?? h[name.toLowerCase()]; return Array.isArray(v) ? v.join(", ") : v; };
  return {
    verifyRequest({ authority, path, headers, nowSeconds, requireTag }) {
      const input = header(headers, "signature-input");
      const sigHeader = header(headers, "signature");
      if (!input || !sigHeader) throw new TapError("not_signed", "No TAP message signature on the request.");
      const parsed = parseSignatureInput(input);
      const { created, expires, keyid, alg, nonce, tag } = parsed.params;
      if (tag === undefined || !(TAP_TAGS as readonly string[]).includes(tag)) throw new TapError("bad_tag", "Signature-Input has no agent-browser-auth or agent-payer-auth tag.");
      if (!created || !expires || !keyid || !alg || !nonce || !parsed.components.includes("@authority") || !parsed.components.includes("@path")) {
        throw new TapError("missing_field", "A required TAP signature field is missing.");
      }
      if (requireTag && tag !== requireTag) throw new TapError("wrong_tag", `This endpoint requires tag ${requireTag}, got ${tag}.`);
      const c = Number(created), e = Number(expires);
      if (!Number.isInteger(c) || !Number.isInteger(e)) throw new TapError("missing_field", "created/expires must be integers.");
      if (c > nowSeconds) throw new TapError("created_in_future", "created is not in the past.");
      if (e <= nowSeconds) throw new TapError("expired", "The signature has expired.");
      if (e - c > TAP_MAX_WINDOW_SECONDS) throw new TapError("window_too_long", "created and expires are more than 8 minutes apart.");
      for (const [n, at] of seen) if (nowSeconds - at > TAP_MAX_WINDOW_SECONDS) seen.delete(n);
      if (seen.has(nonce)) throw new TapError("nonce_replayed", "This nonce was already used in the last 8 minutes.");
      const jwk = keys.get(keyid);
      if (!jwk) throw new TapError("unknown_key", "keyid is not in the trusted key directory.");
      if (alg.toLowerCase() !== "ed25519") throw new TapError("bad_signature", `Unsupported alg ${alg}.`);
      const sigMatch = new RegExp(`${parsed.label}=:([A-Za-z0-9+/=]+):`).exec(sigHeader);
      if (!sigMatch) throw new TapError("bad_signature", "Signature header has no value for the Signature-Input label.");
      const base = signatureBase({ authority, path }, parsed.components, parsed.paramsText);
      const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
      if (!edVerify(null, Buffer.from(base, "utf8"), key, Buffer.from(sigMatch[1]!, "base64"))) throw new TapError("bad_signature", "Message signature does not verify.");
      seen.set(nonce, nowSeconds);
      return { keyId: keyid, tag: tag as TapTag, nonce, created: c, expires: e };
    },
    verifyContainer(container, request) {
      if (!container || typeof container !== "object") throw new TapError("container_missing_field", "agenticPaymentContainer is missing.");
      const { signature, ...rest } = container as Record<string, unknown>;
      if (typeof signature !== "string" || typeof rest.nonce !== "string" || typeof rest.kid !== "string" || typeof rest.alg !== "string") {
        throw new TapError("container_missing_field", "agenticPaymentContainer needs nonce, kid, alg and signature.");
      }
      if (rest.nonce !== request.nonce) throw new TapError("container_nonce_mismatch", "Payment container nonce differs from the message signature nonce.");
      if (rest.kid !== request.keyId) throw new TapError("container_kid_mismatch", "Payment container kid differs from the message signature keyid.");
      const jwk = keys.get(rest.kid)!;
      const key = createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: jwk.x }, format: "jwk" });
      if (!edVerify(null, Buffer.from(JSON.stringify(rest), "utf8"), key, Buffer.from(signature, "base64"))) {
        throw new TapError("container_bad_signature", "Payment container signature does not verify.");
      }
    },
  };
}
