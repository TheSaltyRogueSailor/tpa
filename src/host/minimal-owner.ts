import { eq } from "drizzle-orm";
import type { TpaDatabase, TpaHostAdapter } from "./contracts.js";
import { TpaHostAuthorizationError } from "./contracts.js";
import { tpaPrincipals } from "../schema.js";

/**
 * Complete adapter for the included `tpa_principals` contract table. Production
 * hosts with their own identity table should implement TpaHostAdapter instead.
 */
export function createMinimalOwnerAdapter(getDb: () => Promise<TpaDatabase | undefined>): TpaHostAdapter {
  return {
    getDb,
    async assertOwnerForUpdate(transaction: unknown, userId: number): Promise<void> {
      const tx = transaction as TpaDatabase;
      const [principal] = await tx.select({ id: tpaPrincipals.id, enabled: tpaPrincipals.enabled, isOwner: tpaPrincipals.isOwner })
        .from(tpaPrincipals)
        .where(eq(tpaPrincipals.id, userId))
        .for("update");
      if (!principal || !principal.enabled || !principal.isOwner) throw new TpaHostAuthorizationError();
    },
  };
}
