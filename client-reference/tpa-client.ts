import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { assertFreshTpaReview, type TpaReviewIntent } from "../src/review.js";
import type { TpaCheckoutInput, TpaCheckoutIntentInput, TpaTransferInput } from "../src/domain.js";

export type TpaClient = ReturnType<typeof createTpaClient>;

/**
 * Small browser reference: callers supply a same-origin endpoint, and the host
 * session cookie authenticates requests. No identity is included in the payload.
 */
export function createTpaClient(baseUrl = "/tpa-api") {
  async function call<T>(path: string, body?: unknown): Promise<T> {
    const response = await fetch(`${baseUrl}${path}`, {
      method: body === undefined ? "GET" : "POST",
      credentials: "same-origin",
      cache: "no-store",
      redirect: "error",
      headers: body === undefined ? { "x-tpa-origin": window.location.origin } : { "Content-Type": "application/json", "x-tpa-origin": window.location.origin },
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    if (!response.ok) {
      const failure = await response.json().catch(() => ({ error: "TPA request failed." }));
      throw Object.assign(new Error(failure.error), { code: failure.code, reason: failure.reason });
    }
    return response.json() as Promise<T>;
  }

  return {
    status: () => call<{ intents: TpaReviewIntent[]; credentials: unknown[]; enabled: boolean }>("/status"),
    /** Checkout mandate (merchant, items, shipping, tax, total). Legacy transfer input only if the server allows it. */
    createIntent: (input: TpaCheckoutIntentInput | (TpaTransferInput & { consent: true })) => call<TpaReviewIntent>("/intents", input),
    async register(label: string) {
      const start = await call<{ ceremonyId: string; options: Parameters<typeof startRegistration>[0]["optionsJSON"] }>("/registration/options", { label, consent: true });
      const response = await startRegistration({ optionsJSON: start.options });
      return call("/registration/verify", { ceremonyId: start.ceremonyId, response });
    },
    async authorize(reviewed: TpaReviewIntent) {
      const latest = (await call<{ intents: TpaReviewIntent[] }>("/status")).intents.find(intent => intent.id === reviewed.id);
      assertFreshTpaReview(reviewed, latest, "authorize", Date.now());
      const start = await call<{ ceremonyId: string; options: Parameters<typeof startAuthentication>[0]["optionsJSON"]; mandateHash: string; challengeBinding?: { bindingNonce: string } }>("/authentication/options", { intentId: reviewed.id, consent: true });
      if (start.mandateHash !== reviewed.mandateHash) throw new Error("Request changed. Refresh and review it again.");
      if (start.challengeBinding && start.options.challenge !== await bindChallenge(reviewed.mandateHash, start.challengeBinding.bindingNonce)) {
        throw new Error("The passkey challenge is not bound to the reviewed request.");
      }
      const response = await startAuthentication({ optionsJSON: start.options });
      return call("/authorize", { intentId: reviewed.id, ceremonyId: start.ceremonyId, response, consent: true });
    },
    /** `checkout` is the actual cart at payment time; the server refuses with code "terms_changed" on any difference. */
    async consume(reviewed: TpaReviewIntent, checkout?: TpaCheckoutInput) {
      const latest = (await call<{ intents: TpaReviewIntent[] }>("/status")).intents.find(intent => intent.id === reviewed.id);
      assertFreshTpaReview(reviewed, latest, "consume", Date.now());
      return call("/consume", { intentId: reviewed.id, consent: true, ...(checkout ? { checkout } : {}) });
    },
    async revoke(reviewed: TpaReviewIntent) {
      const latest = (await call<{ intents: TpaReviewIntent[] }>("/status")).intents.find(intent => intent.id === reviewed.id);
      assertFreshTpaReview(reviewed, latest, "revoke", Date.now());
      return call("/revoke", { intentId: reviewed.id, consent: true });
    },
  };
}

/** base64url(SHA-256(mandateHash bytes || bindingNonce bytes)); mirrors deriveTpaMandateChallenge on the server. */
async function bindChallenge(mandateHash: string, bindingNonce: string): Promise<string> {
  const hex = mandateHash.match(/../g)!.map(byte => parseInt(byte, 16));
  const nonce = Uint8Array.from(atob(bindingNonce.replace(/-/g, "+").replace(/_/g, "/").padEnd(Math.ceil(bindingNonce.length / 4) * 4, "=")), c => c.charCodeAt(0));
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", Uint8Array.from([...hex, ...nonce])));
  return btoa(String.fromCharCode(...digest)).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
