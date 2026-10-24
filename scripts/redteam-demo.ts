/**
 * TPA red-team demo: one legit checkout, then five attack types, all against the REAL
 * TPA service (src/service.ts), the real mandate rules (src/domain.ts), real Ed25519
 * server signatures (src/signing.ts) and real WebAuthn ES256 verification (src/webauthn.ts),
 * using the same synthetic passkey the test suite uses (tests/support/authenticator.ts).
 *
 * Runs fully local and in memory: no MySQL, no network, no payment, no chain submission.
 * Persistence is the demo-only in-memory port in scripts/demo/memory-store.ts.
 * The Ed25519 key is generated in memory per run and never printed or written anywhere.
 *
 *   pnpm demo                      # colored terminal output
 *   pnpm demo -- --html <file>     # also write a static HTML report of this run
 */
import { createHash, generateKeyPairSync, randomBytes } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { createTpaAuthority } from "../src/config.js";
import { canonicalTpaMandate, formatBaseUnits, type TpaCheckoutInput } from "../src/domain.js";
import { createTpaService, TpaServiceError } from "../src/service.js";
import { createTpaMandateSigner } from "../src/signing.js";
import { syntheticAuthenticator } from "../tests/support/authenticator.js";
import { createMemoryTpaPersistence } from "./demo/memory-store.js";

/* ------------------------------ presentation ------------------------------ */
const useColor = process.env.FORCE_COLOR ? process.env.FORCE_COLOR !== "0" : !process.env.NO_COLOR;
const paint = (code: string) => (text: string) => (useColor ? `\x1b[${code}m${text}\x1b[0m` : text);
const green = paint("1;32"), red = paint("1;31"), dim = paint("2"), bold = paint("1"), cyan = paint("1;36"), yellow = paint("33");
const say = (line = "") => { console.log(line); };
const usd = (baseUnits: string) => `$${formatBaseUnits(baseUnits, "USD")}`;

/* --------------------------------- setup --------------------------------- */
const ORIGIN = "https://tpa.example.test";
const RP_ID = "tpa.example.test";
const owner = { principalId: 1, sessionHash: randomBytes(32).toString("hex"), owner: true as const };
const ctx = { owner, headers: { origin: ORIGIN } };
let skewMs = 0;
const now = () => Date.now() + skewMs;
const tick = (ms: number) => { skewMs += ms; };

const memory = createMemoryTpaPersistence({ ownerIds: [owner.principalId] });
const KEY_ID = "tpa-demo-key-1";
const signer = createTpaMandateSigner({ activeKeyId: KEY_ID, privateKey: generateKeyPairSync("ed25519").privateKey });
const service = createTpaService({ store: memory.store, evidence: memory.evidence, signer, authority: createTpaAuthority({ enabled: true, origin: ORIGIN, rpID: RP_ID }), now });
const phone = syntheticAuthenticator(ORIGIN, RP_ID);

/** $37.80: 2 x $7.50 mug + 1 x $15.00 tee = $30.00, + $5.00 standard shipping + $2.80 tax. */
const CART: TpaCheckoutInput = {
  currency: "USD", recipient: "user:42", merchant: { id: "acme-store", name: "Acme Store" },
  items: [{ sku: "MUG-01", qty: 2, unitPriceBaseUnits: "750" }, { sku: "TEE-02", qty: 1, unitPriceBaseUnits: "1500" }],
  shipping: { method: "standard", costBaseUnits: "500" }, taxBaseUnits: "280", totalBaseUnits: "3780",
};
/** $1,353.92 laptop order the owner never approved. */
const LAPTOP: TpaCheckoutInput = {
  ...CART, items: [{ sku: "LAPTOP-15", qty: 1, unitPriceBaseUnits: "124900" }], shipping: { method: "standard", costBaseUnits: "500" }, taxBaseUnits: "9992", totalBaseUnits: "135392",
};
const describeCart = (cart: TpaCheckoutInput) => `${cart.merchant.name}: ${cart.items.map(i => `${i.qty} x ${i.sku} @ ${usd(i.unitPriceBaseUnits)}`).join(", ")}, shipping ${usd(cart.shipping.costBaseUnits)}, tax ${usd(cart.taxBaseUnits)}, total ${usd(cart.totalBaseUnits)}`;

/* ------------------------------ real flow steps ------------------------------ */
async function agentRequestsMandate(cart: TpaCheckoutInput) {
  return service.createIntent(ctx, { ...cart, consent: true }) as Promise<Awaited<ReturnType<typeof service.createIntent>> & { serverSignature?: { keyId: string; valid: boolean } }>;
}
/** The owner sees the mandate on their phone and approves it with the passkey. */
async function ownerApprovesWithPasskey(intentId: string) {
  const started = await service.authenticationOptions(ctx, { intentId, consent: true });
  const assertion = phone.assert(started.options.challenge);
  return service.authorize(ctx, { intentId, ceremonyId: started.ceremonyId, response: assertion, consent: true });
}
/** The checkout most recently submitted to the merchant step, recorded for the JSON / animated output. */
let lastCheckout: TpaCheckoutInput | undefined;
const merchantCharges = (intentId: string, checkout: TpaCheckoutInput) => { lastCheckout = checkout; return service.consume(ctx, { intentId, consent: true, checkout }); };

/* ------------------------------ case runner ------------------------------ */
type Result = { id: string; group: string; title: string; story: string; expected: string; outcome: "ALLOWED" | "BLOCKED"; code: string; meaning: string; asExpected: boolean; intentId?: string; checkout?: TpaCheckoutInput };
const results: Result[] = [];
const MEANING: Record<string, string> = {
  ALLOWED: "checkout matched the signed, passkey-approved mandate",
  "terms_changed:merchant_mismatch": "a different store than the one the owner approved",
  "terms_changed:items_mismatch": "the items or prices differ from what the owner approved",
  "terms_changed:checkout_total_inconsistent": "the total does not add up from the approved items, shipping and tax",
  intent: "the approval cannot be used: already used, never approved, expired or revoked",
  "mandate_signature_invalid:bad_signature": "the server's signature on the mandate does not verify",
  "mandate_signature_invalid:hash_mismatch": "the mandate was altered after the server signed it",
  ceremony: "the passkey signature was not made for this purchase",
  challenge_unbound: "the passkey prompt was not tied to this purchase's mandate",
};
const codeOf = (error: unknown) => (error instanceof TpaServiceError ? (error.reason ? `${error.code}:${error.reason}` : error.code) : `unexpected:${String(error)}`);

async function runCase(caseId: string, group: string, title: string, story: string, expected: string, attempt: () => Promise<unknown>, intentId?: string, shown?: TpaCheckoutInput) {
  let outcome: Result["outcome"], code: string;
  const id = intentId;
  lastCheckout = undefined;
  try { await attempt(); outcome = "ALLOWED"; code = "ALLOWED"; }
  catch (error) { outcome = "BLOCKED"; code = codeOf(error); }
  const result: Result = { id: caseId, group, title, story, expected, outcome, code, meaning: MEANING[code] ?? "unexpected result", asExpected: code === expected, intentId: id, checkout: shown ?? lastCheckout };
  results.push(result);
  const badge = outcome === "ALLOWED" ? green("  ALLOWED ") : red("  BLOCKED ");
  say(`${badge} ${bold(title)}`);
  say(`           ${dim(story)}`);
  say(`           ${outcome === "ALLOWED" ? green(`result: ${code}`) : red(`reason code: ${code}`)} ${dim(`(${result.meaning})`)}${result.asExpected ? "" : yellow(`  << expected ${expected}`)}`);
  say();
}
const section = (title: string) => { say(cyan(`== ${title} ==`)); say(); };

/* ---------------------------------- run ---------------------------------- */
async function main() {
  const argValue = (flag: string) => { const index = process.argv.indexOf(flag); return index > 0 ? process.argv[index + 1] : undefined; };
  const htmlPath = argValue("--html");
  const jsonPath = argValue("--json");
  const animatedPath = argValue("--animated");

  say(cyan("=================================================================="));
  say(cyan("   TPA: Triple Protection Authentication") + dim("   red-team demo"));
  say(cyan("=================================================================="));
  say("   1. The server signs the exact checkout (Ed25519 mandate)");
  say("   2. The owner approves that exact mandate with a passkey");
  say("   3. At payment time the checkout must match it exactly, once");
  say(dim("   Local and in memory: no database, no network, no real payment."));
  say();

  // One-time setup: the owner registers a passkey (synthetic authenticator, real ES256 + WebAuthn verification).
  const reg = await service.registrationOptions(ctx, { label: "Raul's phone", consent: true });
  await service.registrationVerify(ctx, { ceremonyId: reg.ceremonyId, response: phone.register(reg.options.challenge) });
  say(dim(`Setup: owner registered a passkey ("Raul's phone"). Server signing key id: ${KEY_ID} (key itself is never shown).`));
  say(dim(`Cart the AI agent builds: ${describeCart(CART)}`));
  say();

  /* Case 0: control */
  section("Case 0 (control): a legit checkout");
  const legit = await agentRequestsMandate(CART);
  say(dim(`  Mandate ${legit.mandateHash.slice(0, 16)}... signed by ${legit.serverSignature?.keyId}, signature valid: ${legit.serverSignature?.valid}`));
  tick(2_000);
  await ownerApprovesWithPasskey(legit.id);
  tick(2_000);
  await runCase("control", "Case 0", "Agent checks out the exact cart the owner approved", "Agent shops, server signs the mandate, owner approves with passkey, merchant charges the same cart.", "ALLOWED",
    () => merchantCharges(legit.id, CART), legit.id);

  /* Attack 1: terms changed at checkout */
  section("Attack 1: changing the deal at checkout");
  const a1 = await agentRequestsMandate(CART);
  await ownerApprovesWithPasskey(a1.id);
  tick(1_000);
  await runCase("merchant-swap", "Attack 1", "Swapped merchant", "Owner approved Acme Store; the checkout that shows up is from Evil Store.", "terms_changed:merchant_mismatch",
    () => merchantCharges(a1.id, { ...CART, merchant: { id: "evil-store", name: "Evil Store" } }), a1.id);
  await runCase("price-raised", "Attack 1", "Price raised on an item", "Mug price quietly raised from $7.50 to $17.50 (total recomputed to $57.80).", "terms_changed:items_mismatch",
    () => merchantCharges(a1.id, { ...CART, items: [{ sku: "MUG-01", qty: 2, unitPriceBaseUnits: "1750" }, CART.items[1]!], totalBaseUnits: "5780" }), a1.id);
  await runCase("total-inflated", "Attack 1", "Total inflated", "Same items, but the total charged is $97.80 instead of $37.80.", "terms_changed:checkout_total_inconsistent",
    () => merchantCharges(a1.id, { ...CART, totalBaseUnits: "9780" }), a1.id);

  /* Attack 2: replay */
  section("Attack 2: replaying a used approval");
  tick(1_000);
  await runCase("replay", "Attack 2", "Replay the already-paid Case 0 mandate", "Agent tries to charge the same approved cart a second time.", "intent",
    () => merchantCharges(legit.id, CART), legit.id);

  /* Attack 3: forged or tampered mandate */
  section("Attack 3: forging or tampering with the signed mandate");
  const a3 = await agentRequestsMandate(CART);
  await ownerApprovesWithPasskey(a3.id);
  const attackerKey = createTpaMandateSigner({ activeKeyId: KEY_ID, privateKey: generateKeyPairSync("ed25519").privateKey });
  const stored = memory.tamper.signatures.get(a3.id)!;
  memory.tamper.signatures.set(a3.id, { ...stored, ...attackerKey.sign(canonicalTpaMandate(a3.mandate)) });
  tick(1_000);
  await runCase("forged-signature", "Attack 3", "Forged server signature", "Attacker re-signs the mandate with their own key under the real key id.", "mandate_signature_invalid:bad_signature",
    () => merchantCharges(a3.id, CART), a3.id);

  const a3b = await agentRequestsMandate(CART);
  await ownerApprovesWithPasskey(a3b.id);
  const row = memory.tamper.intents.get(a3b.id)!;
  const evilCart = { ...CART, merchant: { id: "evil-store", name: "Evil Store" } };
  const rewritten = { ...a3b.mandate, merchant: evilCart.merchant };
  row.mandateJson = JSON.stringify(rewritten);
  row.mandateHash = createHash("sha256").update(canonicalTpaMandate(rewritten)).digest("hex");
  tick(1_000);
  await runCase("tampered-mandate", "Attack 3", "Tampered mandate in storage", "Attacker edits the stored mandate to pay Evil Store and recomputes its hash.", "mandate_signature_invalid:hash_mismatch",
    () => merchantCharges(a3b.id, evilCart), a3b.id);

  /* Attack 4: no passkey, or the wrong passkey approval */
  section("Attack 4: skipping or reusing the passkey approval");
  const a4 = await agentRequestsMandate(LAPTOP);
  await runCase("no-passkey", "Attack 4", "No passkey approval at all", `Agent creates a ${usd(LAPTOP.totalBaseUnits)} laptop mandate and tries to pay without the owner approving.`, "intent",
    () => merchantCharges(a4.id, LAPTOP), a4.id);

  const small = await agentRequestsMandate({ ...CART, taxBaseUnits: "281", totalBaseUnits: "3781" });
  const smallPrompt = await service.authenticationOptions(ctx, { intentId: small.id, consent: true });
  const ownersSignatureForSmall = phone.assert(smallPrompt.options.challenge);
  const laptopPrompt = await service.authenticationOptions(ctx, { intentId: a4.id, consent: true });
  await runCase("passkey-other-mandate", "Attack 4", "Passkey approval for a different mandate", "Owner approves a $37.81 mug order; the agent submits that passkey signature for the laptop instead.", "ceremony",
    () => service.authorize(ctx, { intentId: a4.id, ceremonyId: laptopPrompt.ceremonyId, response: ownersSignatureForSmall, consent: true }), a4.id, LAPTOP);

  const laptopC: TpaCheckoutInput = { ...LAPTOP, taxBaseUnits: "9993", totalBaseUnits: "135393" };
  const a4c = await agentRequestsMandate(laptopC);
  const unboundCeremony = randomBytes(32).toString("hex");
  const genericChallenge = randomBytes(32).toString("base64url");
  await memory.store.startAuthorization({ userId: owner.principalId, sessionHash: owner.sessionHash, origin: ORIGIN, ceremonyId: unboundCeremony, challenge: genericChallenge, intentId: a4c.id, now: now() });
  await runCase("passkey-unbound", "Attack 4", "Passkey prompt not tied to the mandate", "Owner is tricked into a generic sign-in style passkey prompt; it is used to approve the laptop.", "challenge_unbound",
    () => service.authorize(ctx, { intentId: a4c.id, ceremonyId: unboundCeremony, response: phone.assert(genericChallenge), consent: true }), a4c.id, laptopC);

  /* Attack 5: expired and revoked */
  section("Attack 5: using an expired or revoked approval");
  const a5 = await agentRequestsMandate(CART);
  await ownerApprovesWithPasskey(a5.id);
  tick(301_000);
  await runCase("expired", "Attack 5", "Expired mandate", "Approved mandate is used after its 5 minute lifetime (simulated clock +5m01s).", "intent",
    () => merchantCharges(a5.id, CART), a5.id);

  const a5b = await agentRequestsMandate(CART);
  await ownerApprovesWithPasskey(a5b.id);
  await service.revoke(ctx, { intentId: a5b.id, consent: true });
  tick(1_000);
  await runCase("revoked", "Attack 5", "Revoked mandate", "Owner approves, then changes their mind and revokes; the agent tries to pay anyway.", "intent",
    () => merchantCharges(a5b.id, CART), a5b.id);

  /* --------------------------- audit log --------------------------- */
  const audit = (await service.auditLog(ctx, { limit: 500 })).reverse();
  section("Audit log (every approval and every refusal, oldest first)");
  say(dim("  #   time (UTC)  action                  outcome   reason code                                intent    mandate     key id"));
  for (const entry of audit) {
    const color = entry.outcome === "refused" ? red : entry.outcome === "approved" ? green : (s: string) => s;
    say(`  ${String(entry.id).padStart(2)}  ${new Date(entry.atMs).toISOString().slice(11, 19)}    ${entry.action.padEnd(22)}  ${color(entry.outcome.padEnd(8))}  ${entry.reasonCode.padEnd(41)}  ${(entry.intentId ?? "-").slice(0, 8).padEnd(8)}  ${(entry.mandateHash ?? "-").slice(0, 10).padEnd(10)}  ${entry.keyId ?? "-"}`);
  }
  say();

  // Every blocked attempt must appear in the audit log as a refusal with the same reason code.
  const refusals = audit.filter(a => a.outcome === "refused");
  for (const result of results.filter(r => r.outcome === "BLOCKED")) {
    if (!refusals.some(a => a.intentId === result.intentId && a.reasonCode === result.code)) { result.asExpected = false; say(yellow(`  audit row missing for: ${result.title}`)); }
  }
  // No secrets: no signatures, passkey challenges, binding nonces, session tokens or key material in the log.
  const dump = JSON.stringify(audit);
  const leaked = [owner.sessionHash, ...memory.secretValues(), ...Object.values(signer.publicKeys())].filter(secret => secret && dump.includes(secret));
  say(leaked.length === 0 ? green("  Audit log check: no signatures, passkey challenges, nonces, session tokens or keys in any entry.") : red(`  Audit log check FAILED: ${leaked.length} secret value(s) found.`));
  say(dim(`  Audit fields: ${Object.keys(audit[0] ?? {}).join(", ")}`));
  say();

  /* ---------------------------- summary ---------------------------- */
  const allowed = results.filter(r => r.outcome === "ALLOWED").length;
  const blocked = results.filter(r => r.outcome === "BLOCKED").length;
  const ok = results.every(r => r.asExpected) && leaked.length === 0;
  say(cyan("=================================================================="));
  say(bold(`  ${green(`${allowed} legit checkout allowed`)}, ${red(`${blocked} attacks blocked`)} across 5 attack types.`));
  say("  TPA blocks these five attack types: changed terms at checkout, replay,");
  say("  forged or tampered mandates, missing or misused passkey approval,");
  say("  and expired or revoked mandates.");
  say(ok ? green("  Every case behaved as expected.") : red("  Some cases did NOT behave as expected (see above)."));
  say(cyan("=================================================================="));

  if (htmlPath) { writeFileSync(htmlPath, renderHtml(results, audit, { allowed, blocked, ok, generatedAt: new Date().toISOString() })); say(dim(`HTML report written to ${htmlPath}`)); }
  if (jsonPath || animatedPath) {
    const data = buildRunData(results, audit, { allowed, blocked, ok });
    if (jsonPath) { writeFileSync(jsonPath, `${JSON.stringify(data, null, 2)}\n`); say(dim(`JSON results written to ${jsonPath}`)); }
    if (animatedPath) { writeFileSync(animatedPath, renderAnimatedHtml(data)); say(dim(`Animated page written to ${animatedPath}`)); }
  }
  if (!ok) process.exitCode = 1;
}

/* ------------------------- JSON + animated page ------------------------- */
type AuditEntry = { id: number; atMs: number; action: string; outcome: string; reasonCode: string; intentId: string | null; mandateHash?: string | null; keyId?: string | null };
/**
 * Machine-readable copy of this run: every case with its real outcome and reason code, the checkout
 * that was submitted, and the audit rows it produced. Audit rows only (no signatures, challenges or keys).
 */
function buildRunData(rows: Result[], audit: AuditEntry[], meta: { allowed: number; blocked: number; ok: boolean }) {
  const cart = (c?: TpaCheckoutInput) => c && ({
    merchant: c.merchant.name, currency: c.currency,
    items: c.items.map(i => ({ sku: i.sku, qty: i.qty, unitPrice: usd(i.unitPriceBaseUnits) })),
    shipping: usd(c.shipping.costBaseUnits), tax: usd(c.taxBaseUnits), total: usd(c.totalBaseUnits),
  });
  // Attach each audit row to the case it belongs to: everything up to and including that case's decisive row.
  let cursor = 0;
  const cases = rows.map(r => {
    const decisive = r.outcome === "ALLOWED" ? (a: AuditEntry) => a.action === "consumed" && a.intentId === r.intentId
      : (a: AuditEntry) => a.outcome === "refused" && a.intentId === r.intentId && a.reasonCode === r.code;
    const found = audit.findIndex((a, index) => index >= cursor && decisive(a));
    const end = found >= 0 ? found + 1 : cursor;
    const auditIds = audit.slice(cursor, end).map(a => a.id);
    cursor = end;
    return { id: r.id, group: r.group, title: r.title, story: r.story, outcome: r.outcome, code: r.code, meaning: r.meaning, asExpected: r.asExpected, checkout: cart(r.checkout), auditIds };
  });
  return {
    generatedAt: new Date().toISOString(), source: "pnpm demo (scripts/redteam-demo.ts): local, in-memory run of the real TPA service",
    approvedCart: cart(CART), summary: { allowed: meta.allowed, blocked: meta.blocked, attackTypes: new Set(rows.filter(r => r.outcome === "BLOCKED").map(r => r.group)).size, allAsExpected: meta.ok },
    cases, trailingAuditIds: audit.slice(cursor).map(a => a.id),
    audit: audit.map(a => ({ id: a.id, time: new Date(a.atMs).toISOString().slice(11, 19), action: a.action, outcome: a.outcome, reasonCode: a.reasonCode, intent: (a.intentId ?? "-").slice(0, 8), mandate: (a.mandateHash ?? "-").slice(0, 10), keyId: a.keyId ?? "-" })),
  };
}
/** Embeds the run data into scripts/demo/animated-page.html (self-contained, no network). */
function renderAnimatedHtml(data: ReturnType<typeof buildRunData>) {
  const template = readFileSync(new URL("../../scripts/demo/animated-page.html", import.meta.url), "utf8");
  const json = JSON.stringify(data).replace(/</g, "\\u003c");
  return template.replace("/*__TPA_DEMO_DATA__*/null", () => json);
}

/* ------------------------------ HTML report ------------------------------ */
const esc = (value: unknown) => String(value).replace(/[&<>"']/g, c => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[c]!);
function renderHtml(rows: Result[], audit: Array<{ id: number; atMs: number; action: string; outcome: string; reasonCode: string; intentId: string | null; mandateHash?: string | null; keyId?: string | null }>, meta: { allowed: number; blocked: number; ok: boolean; generatedAt: string }) {
  const cards = rows.map(r => `<div class="case ${r.outcome === "ALLOWED" ? "ok" : "no"}"><div class="badge">${r.outcome}</div><div><div class="grp">${esc(r.group)}</div><h3>${esc(r.title)}</h3><p>${esc(r.story)}</p><p class="code">${r.outcome === "ALLOWED" ? "result" : "reason code"}: <b>${esc(r.code)}</b> <span>(${esc(r.meaning)})</span></p></div></div>`).join("\n");
  const auditRows = audit.map(a => `<tr class="${esc(a.outcome)}"><td>${a.id}</td><td>${esc(new Date(a.atMs).toISOString().slice(11, 19))}</td><td>${esc(a.action)}</td><td>${esc(a.outcome)}</td><td>${esc(a.reasonCode)}</td><td>${esc((a.intentId ?? "-").slice(0, 8))}</td><td>${esc((a.mandateHash ?? "-").slice(0, 10))}</td><td>${esc(a.keyId ?? "-")}</td></tr>`).join("\n");
  return `<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>TPA: Triple Protection Authentication - red-team demo</title>
<style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;background:#0d1117;color:#e6edf3;margin:0;padding:32px;max-width:1000px;margin:auto}
h1{margin:0;font-size:30px}.sub{color:#8b949e;margin:6px 0 20px}.pillars{display:flex;gap:12px;margin-bottom:28px}.pillars div{flex:1;background:#161b22;border:1px solid #30363d;border-radius:10px;padding:12px;font-size:14px}
.case{display:flex;gap:16px;align-items:flex-start;background:#161b22;border:1px solid #30363d;border-left:6px solid;border-radius:10px;padding:14px 16px;margin:10px 0}
.case.ok{border-left-color:#2ea043}.case.no{border-left-color:#f85149}.badge{font-weight:800;min-width:90px;padding:6px 8px;border-radius:6px;text-align:center;font-size:13px}
.ok .badge{background:#2ea04333;color:#3fb950}.no .badge{background:#f8514933;color:#ff7b72}.grp{color:#8b949e;font-size:12px;text-transform:uppercase;letter-spacing:.06em}
h3{margin:2px 0 4px;font-size:17px}p{margin:4px 0;color:#c9d1d9;font-size:14px}.code b{font-family:ui-monospace,Menlo,monospace}.code span{color:#8b949e}
.summary{font-size:22px;font-weight:700;margin:28px 0 6px}.g{color:#3fb950}.r{color:#ff7b72}
table{width:100%;border-collapse:collapse;font-family:ui-monospace,Menlo,monospace;font-size:12px;margin-top:10px}td,th{padding:5px 6px;border-bottom:1px solid #21262d;text-align:left}
tr.refused td:nth-child(4){color:#ff7b72}tr.approved td:nth-child(4){color:#3fb950}.foot{color:#8b949e;font-size:12px;margin-top:24px}
</style></head><body>
<h1>TPA: Triple Protection Authentication</h1>
<div class="sub">Red-team demo: one legit AI-agent checkout, then five attack types. Generated ${esc(meta.generatedAt)} from a local, in-memory run of the real TPA service.</div>
<div class="pillars"><div><b>1. Signed mandate</b><br>The server signs the exact checkout: merchant, items, shipping, tax, total.</div><div><b>2. Passkey approval</b><br>The owner approves that exact mandate with a passkey.</div><div><b>3. Exact match, once</b><br>At payment time the checkout must match, and the approval works once.</div></div>
${cards}
<div class="summary"><span class="g">${meta.allowed} legit checkout allowed</span>, <span class="r">${meta.blocked} attacks blocked</span> across 5 attack types.</div>
<p>TPA blocks these five attack types: changed terms at checkout, replay, forged or tampered mandates, missing or misused passkey approval, and expired or revoked mandates.</p>
<h2>Audit log</h2><p>Every approval and refusal, oldest first. No signatures, passkey challenges, nonces, session tokens or keys are stored in it.</p>
<table><tr><th>#</th><th>time (UTC)</th><th>action</th><th>outcome</th><th>reason code</th><th>intent</th><th>mandate</th><th>key id</th></tr>
${auditRows}
</table>
<div class="foot">Pilot scope: TPA authorizes; it does not move money, contact a payment processor, or write to a blockchain. Run locally with <code>pnpm demo</code>.</div>
</body></html>
`;
}

main().catch(error => { console.error(red(`Demo crashed: ${error instanceof Error ? error.message : String(error)}`)); process.exitCode = 1; });
