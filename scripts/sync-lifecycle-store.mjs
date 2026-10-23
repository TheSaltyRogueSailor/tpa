#!/usr/bin/env node
/**
 * Extracts only the TPA persistence implementation from a supplied DingDong
 * store source into this standalone package. It never writes to its input.
 *
 * Usage:
 * node scripts/sync-lifecycle-store.mjs /absolute/path/to/server/tpa/store.ts
 *
 * This intentionally fails rather than guessing if upstream structure changes.
 */
import { readFile, writeFile } from "node:fs/promises";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const sourcePath = process.argv[2];
if (!sourcePath) throw new Error("Usage: node scripts/sync-lifecycle-store.mjs /absolute/path/to/store.ts");
const here = dirname(fileURLToPath(import.meta.url));
const outputPath = resolve(here, "../src/store.ts");
let source = await readFile(resolve(sourcePath), "utf8");
for (const marker of ["export class TpaStoreError", "async function database()", "async function lockOwner", "export async function startRegistration", "export async function tpaStatus"]) {
  if (!source.includes(marker)) throw new Error(`Unsupported source: missing ${marker}`);
}

source = source
  .replace('import { tpaCeremonies, tpaCredentials, tpaIntents, users } from "../../drizzle/schema";\n', 'import { tpaCeremonies, tpaCredentials, tpaIntents } from "./schema.js";\nimport type { TpaHostAdapter } from "./host/contracts.js";\n')
  .replace('from "../../shared/tpa";', 'from "./domain.js";')
  .replace('import { getDb } from "../db";\n', '')
  .replace('import { isPersonalWalletOwner } from "../personalWalletAccess";\n', '')
  .replace('type Tx = any;\n', 'type Tx = any;\ntype StoreInput = { host: TpaHostAdapter };\n')
  .replace(/async function database\(\) \{\n  const db = await getDb\(\);/g, 'async function database(host: TpaHostAdapter) {\n  const db = await host.getDb();')
  .replace(/async function lockOwner\(tx: Tx, userId: number\): Promise<void> \{\n  const \[owner\] = await tx\.select\(\{ id: users\.id, role: users\.role, isBanned: users\.isBanned, openId: users\.openId \}\)\.from\(users\)\.where\(eq\(users\.id, userId\)\)\.for\("update"\);\n  if \(!isPersonalWalletOwner\(owner\)\) throw new TpaStoreError\("unavailable"\);\n\}/g, 'async function lockOwner(host: TpaHostAdapter, tx: Tx, userId: number): Promise<void> {\n  try { await host.assertOwnerForUpdate(tx, userId); }\n  catch { throw new TpaStoreError("unavailable"); }\n}')
  .replace(/input: \{/g, 'input: StoreInput & {')
  .replace(/await database\(\);/g, 'await database(input.host);')
  .replace(/await lockOwner\(tx, input\.userId\);/g, 'await lockOwner(input.host, tx, input.userId);');

if (source.includes("import { getDb }") || source.includes("isPersonalWalletOwner") || source.includes("../../") || !source.includes("host.assertOwnerForUpdate")) {
  throw new Error("Transformation safety check failed; output was not written.");
}
const exported = ["startRegistration", "startAuthorization", "getCredentialForAuthentication", "consumeRegistrationCeremony", "consumeAuthorizationCeremony", "saveVerifiedCredential", "createIntent", "finalizeAuthorization", "consumeIntent", "revokeIntent", "revokeCredential", "tpaStatus"];
source += `\n\n/** Binds the persistence operations to one explicit host adapter; no global database or auth singleton is used. */\nexport function createTpaStore(host: TpaHostAdapter) {\n  return {\n${exported.map(name => `    ${name}: (input: Omit<Parameters<typeof ${name}>[0], "host">) => ${name}({ ...input, host }),`).join("\n")}\n  };\n}\n\nexport type TpaStore = ReturnType<typeof createTpaStore>;\n`;
await writeFile(outputPath, source, "utf8");
console.log(`Wrote ${outputPath} from ${resolve(sourcePath)}; adapter and domain imports were isolated.`);
