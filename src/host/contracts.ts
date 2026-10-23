import type { MySql2Database } from "drizzle-orm/mysql2";
import type { tpaSchema } from "../schema.js";

/** Concrete Drizzle database shape used by the standalone persistence store. */
export type TpaDatabase = MySql2Database<typeof tpaSchema>;

/** Throw this from a host adapter when the principal is absent, disabled, or not the designated owner. */
export class TpaHostAuthorizationError extends Error {
  constructor(message = "The authenticated principal is not permitted to use TPA.") {
    super(message);
    this.name = "TpaHostAuthorizationError";
  }
}

/**
 * Mandatory host boundary. The adapter must run its principal check and lock
 * in the same MySQL transaction supplied by the store. The library never
 * receives raw login cookies, password hashes, wallet keys, or a query-string identity.
 */
export interface TpaHostAdapter {
  getDb(): Promise<TpaDatabase | undefined>;
  assertOwnerForUpdate(transaction: unknown, userId: number): Promise<void>;
}

/** Identity issued by the host's existing authenticated session middleware. */
export type TpaAuthenticatedOwner = Readonly<{
  principalId: number;
  sessionHash: string;
  owner: true;
}>;
