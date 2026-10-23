import { createHash, timingSafeEqual } from "node:crypto";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

function decodeBase58(value: string): Buffer | null {
  if (value.length < 26 || value.length > 35) return null;
  let number = 0n;
  for (const character of value) {
    const position = ALPHABET.indexOf(character);
    if (position < 0) return null;
    number = number * 58n + BigInt(position);
  }
  let hex = number.toString(16);
  if (hex.length % 2) hex = `0${hex}`;
  const body = hex === "00" ? Buffer.alloc(0) : Buffer.from(hex, "hex");
  let leading = 0;
  while (value[leading] === "1") leading++;
  return Buffer.concat([Buffer.alloc(leading), body]);
}

/** Synchronous checksum-only Dogecoin mainnet public-address validation; it makes no network or wallet call. */
export function isDogecoinAddress(address: string): boolean {
  const decoded = decodeBase58(address);
  if (!decoded || decoded.length !== 25 || ![0x1e, 0x16].includes(decoded[0]!)) return false;
  const payload = decoded.subarray(0, 21);
  const expected = createHash("sha256").update(createHash("sha256").update(payload).digest()).digest().subarray(0, 4);
  return timingSafeEqual(decoded.subarray(21), expected);
}
