import {
  generateAuthenticationOptions,
  generateRegistrationOptions,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from "@simplewebauthn/server";
import type { AuthenticationResponseJSON, RegistrationResponseJSON, WebAuthnCredential } from "@simplewebauthn/server";
import { z } from "zod";

const MAX_RESPONSE_BYTES = 64 * 1024;
const base64url = z.string().regex(/^[A-Za-z0-9_-]+$/);
const credentialID = base64url.max(1364);
const extensionResults = z.record(z.string().max(80), z.unknown()).default({});

export const registrationResponseInput = z.object({
  id: credentialID,
  rawId: credentialID,
  type: z.literal("public-key"),
  authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
  clientExtensionResults: extensionResults,
  response: z.object({
    clientDataJSON: base64url.max(12_000),
    attestationObject: base64url.max(52_000),
    authenticatorData: base64url.max(12_000).optional(),
    transports: z.array(z.enum(["ble", "cable", "hybrid", "internal", "nfc", "smart-card", "usb"])).max(8).optional(),
    publicKeyAlgorithm: z.number().int().min(-100_000).max(100_000).optional(),
    publicKey: base64url.max(12_000).optional(),
  }).strict(),
}).strict().superRefine((value, context) => {
  if (value.id !== value.rawId) context.addIssue({ code: "custom", message: "Credential identifier mismatch." });
});

export const authenticationResponseInput = z.object({
  id: credentialID,
  rawId: credentialID,
  type: z.literal("public-key"),
  authenticatorAttachment: z.enum(["platform", "cross-platform"]).optional(),
  clientExtensionResults: extensionResults,
  response: z.object({
    clientDataJSON: base64url.max(12_000),
    authenticatorData: base64url.max(12_000),
    signature: base64url.max(12_000),
    userHandle: base64url.max(12_000).optional(),
  }).strict(),
}).strict().superRefine((value, context) => {
  if (value.id !== value.rawId) context.addIssue({ code: "custom", message: "Credential identifier mismatch." });
});

export type RegistrationResponse = z.infer<typeof registrationResponseInput>;
export type AuthenticationResponse = z.infer<typeof authenticationResponseInput>;

function bounded<T>(schema: z.ZodType<T>, value: unknown): T {
  const parsed = schema.parse(value);
  if (Buffer.byteLength(JSON.stringify(parsed), "utf8") > MAX_RESPONSE_BYTES) throw new Error("WebAuthn response is too large.");
  return parsed;
}

export function parseRegistrationResponse(value: unknown): RegistrationResponse { return bounded(registrationResponseInput, value); }
export function parseAuthenticationResponse(value: unknown): AuthenticationResponse { return bounded(authenticationResponseInput, value); }

function challengeBytes(challenge: string): Uint8Array<ArrayBuffer> {
  if (!/^[A-Za-z0-9_-]{43}$/.test(challenge)) throw new Error("Invalid stored challenge.");
  const bytes = Buffer.from(challenge, "base64url");
  if (bytes.length !== 32 || bytes.toString("base64url") !== challenge) throw new Error("Invalid stored challenge.");
  return new Uint8Array(bytes);
}

export async function registrationOptions(input: { challenge: string; rpID: string; userId: number; userName: string; excludeCredentials: Array<{ id: string; transports?: string[] }> }) {
  return generateRegistrationOptions({
    rpName: "TPA authorization pilot",
    rpID: input.rpID,
    userID: new TextEncoder().encode(String(input.userId)),
    userName: input.userName,
    userDisplayName: input.userName,
    challenge: challengeBytes(input.challenge),
    timeout: 120_000,
    attestationType: "none",
    excludeCredentials: input.excludeCredentials,
    authenticatorSelection: { residentKey: "preferred", userVerification: "required" },
  });
}

export async function authenticationOptions(input: { challenge: string; rpID: string; allowCredentials: Array<{ id: string; transports?: string[] }> }) {
  return generateAuthenticationOptions({ rpID: input.rpID, challenge: challengeBytes(input.challenge), timeout: 120_000, allowCredentials: input.allowCredentials, userVerification: "required" });
}

export async function verifyRegistration(input: { response: RegistrationResponse; challenge: string; origin: string; rpID: string }) {
  return verifyRegistrationResponse({
    response: input.response as RegistrationResponseJSON,
    expectedChallenge: input.challenge,
    expectedOrigin: input.origin,
    expectedRPID: input.rpID,
    expectedType: "webauthn.create",
    requireUserPresence: true,
    requireUserVerification: true,
  });
}

export async function verifyAuthentication(input: { response: AuthenticationResponse; challenge: string; origin: string; rpID: string; credential: WebAuthnCredential }) {
  return verifyAuthenticationResponse({
    response: input.response as AuthenticationResponseJSON,
    expectedChallenge: input.challenge,
    expectedOrigin: input.origin,
    expectedRPID: input.rpID,
    expectedType: "webauthn.get",
    credential: input.credential,
    requireUserVerification: true,
    advancedFIDOConfig: { userVerification: "required" },
  });
}
