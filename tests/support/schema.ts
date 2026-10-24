import { readFileSync } from "node:fs";
import type mysql from "mysql2/promise";

const MIGRATIONS = ["0000_tpa_standalone.sql", "0001_tpa_mandate_hardening.sql"];

/** Drops and recreates every tpa_* table from the shipped migrations. Disposable test schemas only. */
export async function resetTpaSchema(pool: mysql.Pool) {
  await pool.query("DROP TABLE IF EXISTS tpa_audit_events, tpa_challenge_bindings, tpa_mandate_signatures, tpa_ceremonies, tpa_intents, tpa_credentials, tpa_principals");
  for (const file of MIGRATIONS) {
    const ddl = readFileSync(new URL(`../../migrations/${file}`, import.meta.url), "utf8");
    for (const statement of ddl.replace(/^--.*$/gm, "").split(";").map(s => s.trim()).filter(Boolean)) await pool.query(statement);
  }
  await pool.query("INSERT INTO tpa_principals (id, isOwner, enabled) VALUES (1, TRUE, TRUE)");
}
