import mysql from "mysql2/promise";
import { drizzle } from "drizzle-orm/mysql2";
import { tpaSchema } from "./schema.js";
import type { TpaDatabase } from "./host/contracts.js";

export type TpaMySqlConnection = {
  db: TpaDatabase;
  close(): Promise<void>;
};

/** Creates a MySQL pool only when called by the integrating host; no connection is made at import time. */
export function createTpaMySqlConnection(databaseUrl: string): TpaMySqlConnection {
  if (!databaseUrl) throw new Error("A non-empty MySQL database URL is required.");
  const pool = mysql.createPool(databaseUrl);
  return { db: drizzle({ client: pool, schema: tpaSchema } as never), close: () => pool.end() };
}
