#!/usr/bin/env node
/**
 * Generates an Ed25519 mandate signing key for a NEW key id.
 * The private key is written to a 0600 file (never printed); only the key id and
 * PUBLIC key are printed. Load the private key into the host secret manager as
 * TPA_MANDATE_SIGNING_KEY, then delete the file. Never commit it.
 *
 * Usage: node scripts/generate-mandate-signing-key.mjs <keyId> <output-private-key-file>
 */
import { generateKeyPairSync } from "node:crypto";
import { existsSync, writeFileSync } from "node:fs";

const [keyId, output] = process.argv.slice(2);
if (!keyId || !/^[A-Za-z0-9._-]{1,64}$/.test(keyId) || !output) throw new Error("Usage: generate-mandate-signing-key.mjs <keyId> <output-file>");
if (existsSync(output)) throw new Error("Refusing to overwrite an existing file.");
const { privateKey, publicKey } = generateKeyPairSync("ed25519");
writeFileSync(output, privateKey.export({ format: "der", type: "pkcs8" }).toString("base64") + "\n", { mode: 0o600, flag: "wx" });
console.log(`TPA_MANDATE_SIGNING_KEY_ID=${keyId}`);
console.log(`public key (for TPA_MANDATE_VERIFY_KEYS after rotation): ${keyId}=${publicKey.export({ format: "der", type: "spki" }).toString("base64")}`);
console.log(`private key written to ${output} (mode 0600); load it into your secret manager, then delete the file.`);
