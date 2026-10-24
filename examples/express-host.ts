import express from "express";
import { createMinimalOwnerAdapter, createTpaAuthority, createTpaExpressRouter, createTpaMySqlConnection, createTpaEvidenceStore, createTpaService, createTpaStore, tpaMandateSignerFromEnv, type TpaAuthenticatedOwner } from "../src/index.js";

export type ReferenceTpaApp = { app: express.Express; close: () => Promise<void> };

/**
 * Complete reference mount, not an authentication replacement. The caller must
 * supply its actual server-side session resolver (cookie validation, expiry,
 * revocation, current-principal enablement/ban and designated-owner checks).
 * No listen(), principal creation, privilege grant, migration or payment runs here.
 */
export function createReferenceTpaApp(resolveHostSession: (request: express.Request) => Promise<TpaAuthenticatedOwner | undefined>): ReferenceTpaApp {
  const authority = createTpaAuthority({
    enabled: process.env.TPA_AUTHORIZATION_ENABLED === "true",
    origin: process.env.TPA_ORIGIN,
    rpID: process.env.TPA_RP_ID,
    localDevelopment: process.env.NODE_ENV === "development",
  });
  if (!authority.valid) throw new Error("Set an exact HTTPS TPA_ORIGIN and matching TPA_RP_ID before mounting TPA.");
  const url = process.env.TPA_DATABASE_URL;
  if (!url) throw new Error("Set TPA_DATABASE_URL in the deployment secret store before mounting TPA.");
  const connection = createTpaMySqlConnection(url);
  const adapter = createMinimalOwnerAdapter(async () => connection.db);
  const store = createTpaStore(adapter);
  // Mandate signing key comes from the deployment secret store (see .env.example and
  // scripts/generate-mandate-signing-key.mjs). Without it, checkout mandates are refused.
  const signer = tpaMandateSignerFromEnv(process.env);
  if (!signer) throw new Error("Set TPA_MANDATE_SIGNING_KEY_ID and TPA_MANDATE_SIGNING_KEY in the deployment secret store before mounting TPA.");
  const service = createTpaService({ store, authority, signer, evidence: createTpaEvidenceStore(adapter) });
  const app = express();
  app.disable("x-powered-by");
  // This includes its own bounded JSON parser and generic parser-error handler.
  app.use("/tpa-api", createTpaExpressRouter(service, resolveHostSession));
  return { app, close: () => connection.close() };
}
