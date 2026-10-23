import { startAuthentication, startRegistration } from "@simplewebauthn/browser";
import { assertFreshTpaReview, type TpaReviewIntent } from "../src/review.js";
import type { TpaTransferInput } from "../src/domain.js";

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
    if (!response.ok) throw new Error((await response.json().catch(() => ({ error: "TPA request failed." }))).error);
    return response.json() as Promise<T>;
  }

  return {
    status: () => call<{ intents: TpaReviewIntent[]; credentials: unknown[]; enabled: boolean }>("/status"),
    createIntent: (input: TpaTransferInput) => call<TpaReviewIntent>("/intents", input),
    async register(label: string) {
      const start = await call<{ ceremonyId: string; options: Parameters<typeof startRegistration>[0]["optionsJSON"] }>("/registration/options", { label, consent: true });
      const response = await startRegistration({ optionsJSON: start.options });
      return call("/registration/verify", { ceremonyId: start.ceremonyId, response });
    },
    async authorize(reviewed: TpaReviewIntent) {
      const latest = (await call<{ intents: TpaReviewIntent[] }>("/status")).intents.find(intent => intent.id === reviewed.id);
      assertFreshTpaReview(reviewed, latest, "authorize", Date.now());
      const start = await call<{ ceremonyId: string; options: Parameters<typeof startAuthentication>[0]["optionsJSON"] }>("/authentication/options", { intentId: reviewed.id, consent: true });
      const response = await startAuthentication({ optionsJSON: start.options });
      return call("/authorize", { intentId: reviewed.id, ceremonyId: start.ceremonyId, response, consent: true });
    },
    async consume(reviewed: TpaReviewIntent) {
      const latest = (await call<{ intents: TpaReviewIntent[] }>("/status")).intents.find(intent => intent.id === reviewed.id);
      assertFreshTpaReview(reviewed, latest, "consume", Date.now());
      return call("/consume", { intentId: reviewed.id, consent: true });
    },
    async revoke(reviewed: TpaReviewIntent) {
      const latest = (await call<{ intents: TpaReviewIntent[] }>("/status")).intents.find(intent => intent.id === reviewed.id);
      assertFreshTpaReview(reviewed, latest, "revoke", Date.now());
      return call("/revoke", { intentId: reviewed.id, consent: true });
    },
  };
}
