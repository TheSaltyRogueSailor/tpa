import express, { type NextFunction, type Request, type RequestHandler, type Response, type Router } from "express";
import type { TpaAuthenticatedOwner } from "../host/contracts.js";
import { TpaServiceError, type TpaService } from "../service.js";

export const TPA_BODY_LIMIT = 65_536;

export type ResolveAuthenticatedOwner = (request: Request) => Promise<TpaAuthenticatedOwner | undefined>;

/**
 * Builds a bounded, no-store JSON router. `resolveAuthenticatedOwner` must
 * authenticate the host's session/cookie/token and enforce current revocation,
 * ban, and owner semantics. It must never take identity from a query/body field.
 */
export function createTpaExpressRouter(service: TpaService, resolveAuthenticatedOwner: ResolveAuthenticatedOwner): Router {
  const router = express.Router();
  router.use((request, response, next) => {
    response.set({
      "Cache-Control": "no-store, private, max-age=0",
      "CDN-Cache-Control": "no-store",
      "Surrogate-Control": "no-store",
      "Referrer-Policy": "no-referrer",
      "X-Frame-Options": "DENY",
      "X-Content-Type-Options": "nosniff",
    });
    if (!request.is("application/json") && request.method !== "GET") return response.status(415).json({ error: "TPA requests require JSON." });
    return next();
  });
  router.use(express.json({ limit: TPA_BODY_LIMIT, strict: true }));

  const context = async (request: Request) => ({ owner: await resolveAuthenticatedOwner(request), headers: request.headers });
  const respond = (operation: (request: Request) => Promise<unknown>): RequestHandler => async (request, response) => {
    try { response.json(await operation(request)); }
    catch (error) { sendError(response, error); }
  };

  router.get("/status", respond(async request => service.status(await context(request))));
  router.post("/registration/options", respond(async request => service.registrationOptions(await context(request), request.body)));
  router.post("/registration/verify", respond(async request => service.registrationVerify(await context(request), request.body)));
  router.post("/intents", respond(async request => service.createIntent(await context(request), request.body)));
  router.post("/authentication/options", respond(async request => service.authenticationOptions(await context(request), request.body)));
  router.post("/authorize", respond(async request => service.authorize(await context(request), request.body)));
  router.post("/consume", respond(async request => service.consume(await context(request), request.body)));
  router.post("/revoke", respond(async request => service.revoke(await context(request), request.body)));
  router.post("/credentials/revoke", respond(async request => service.revokeCredential(await context(request), request.body)));
  router.use((_request, response) => response.status(404).json({ error: "Unknown TPA endpoint." }));
  router.use(tpaJsonErrorHandler);
  return router;
}

function sendError(response: Response, error: unknown): void {
  if (error instanceof TpaServiceError) {
    const status = error.code === "unauthenticated" ? 401 : error.code === "forbidden" ? 403 : error.code === "rate" ? 429 : error.code === "invalid" ? 400 : error.code === "unavailable" ? 503 : 412;
    response.status(status).json({ error: error.message, code: error.code });
    return;
  }
  // Zod and malformed JSON details are not reflected to a credential endpoint.
  response.status(400).json({ error: "Invalid TPA request.", code: "invalid" });
}

/** Use before generic JSON parsing when mounting the router in an Express host. */
export function tpaJsonErrorHandler(error: unknown, _request: Request, response: Response, next: NextFunction): void {
  if (error && typeof error === "object" && "type" in error) {
    const type = String((error as { type: unknown }).type);
    response.status(type === "entity.too.large" ? 413 : 400).json({ error: "Invalid TPA request." });
    return;
  }
  next(error);
}
