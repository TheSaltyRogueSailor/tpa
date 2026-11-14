// Synthetic pump.fun trade fixtures for the token gate tests (no network).
// Ported from the TSRS TPA gate test fixtures (artifacts/api-server/test/fixtures.ts).
import type { MintInfo, PumpTrade } from "../../mcp/token-gate/guard.js";

let n = 0;
export const wallet = (tag: string) => `${tag}_${(++n).toString(36)}`;

/** Constant-product pump.fun curve that emits PumpTrade records. */
export class Curve {
  vSol = 30; vTok = 1_073_000_000; realTok = 793_100_000;
  trades: PumpTrade[] = [];
  bal = new Map<string, number>();
  constructor(public mint = "MINTfixture", public t0 = 1_000_000, public slot0 = 1000) {}
  buy(user: string, sol: number, dtMs: number, slot = this.slot0 + Math.floor(dtMs / 400)): PumpTrade {
    const k = this.vSol * this.vTok; const nv = this.vSol + sol * 0.99; const tokens = this.vTok - k / nv;
    this.vSol = nv; this.vTok -= tokens; this.realTok -= tokens;
    this.bal.set(user, (this.bal.get(user) ?? 0) + tokens);
    return this.push(user, true, sol, tokens, dtMs, slot);
  }
  sell(user: string, fraction: number, dtMs: number, slot = this.slot0 + Math.floor(dtMs / 400)): PumpTrade {
    const tokens = (this.bal.get(user) ?? 0) * fraction; const k = this.vSol * this.vTok;
    const nt = this.vTok + tokens; const sol = this.vSol - k / nt;
    this.vTok = nt; this.vSol -= sol; this.realTok += tokens;
    this.bal.set(user, (this.bal.get(user) ?? 0) - tokens);
    return this.push(user, false, sol, tokens, dtMs, slot);
  }
  private push(user: string, isBuy: boolean, sol: number, tokens: number, dtMs: number, slot: number): PumpTrade {
    const t: PumpTrade = { sig: `sig${this.trades.length}`, slot, mint: this.mint, user, isBuy, sol, tokens,
      ts: Math.floor((this.t0 + dtMs) / 1000), vSol: this.vSol, vTok: this.vTok, realTok: this.realTok,
      t: this.t0 + dtMs, price: this.vSol / this.vTok };
    this.trades.push(t);
    return t;
  }
  get now() { return this.trades.length ? this.trades[this.trades.length - 1]!.t : this.t0; }
}

export const SAFE_MINT: MintInfo = { program: "spl-token", mintAuthority: null, freezeAuthority: null, extensions: [], transferFeeBps: 0, supply: 1e9 };

/** Healthy organic climb: modest dev buy, 12 distinct buyers over ~12 s, a couple of small sells. */
export function healthy(): { curve: Curve; creator: string } {
  const c = new Curve("HEALTHYmint"); const creator = wallet("dev");
  c.buy(creator, 0.5, 0);
  const buyers: string[] = [];
  for (let i = 0; i < 12; i++) { const u = wallet("b"); buyers.push(u); c.buy(u, 0.3 + (i % 4) * 0.1, 800 + i * 900); }
  c.sell(buyers[0]!, 0.5, 9000);
  c.sell(buyers[3]!, 0.3, 11_000);
  c.buy(wallet("b"), 0.6, 12_000);
  return { curve: c, creator };
}

/** Rug-like: creator holds ~18% and starts dumping into the buyers. */
export function rugLike(): { curve: Curve; creator: string } {
  const c = new Curve("RUGmint"); const creator = wallet("dev");
  c.buy(creator, 6, 0);
  for (let i = 0; i < 8; i++) c.buy(wallet("b"), 0.5, 1000 + i * 700);
  c.sell(creator, 0.4, 7000);
  return { curve: c, creator };
}

/** Honeypot-like: buys only, nobody can sell, freeze authority still set. */
export function honeypotLike(): { curve: Curve; creator: string; mint: MintInfo } {
  const c = new Curve("HONEYmint"); const creator = wallet("dev");
  c.buy(creator, 0.4, 0);
  for (let i = 0; i < 10; i++) c.buy(wallet("b"), 0.4, 700 + i * 700);
  return { curve: c, creator, mint: { ...SAFE_MINT, freezeAuthority: creator } };
}

/** Bundled launch: 5 sniper wallets buy big in the creation slot. */
export function bundled(): { curve: Curve; creator: string } {
  const c = new Curve("BUNDLEmint"); const creator = wallet("dev");
  c.buy(creator, 0.5, 0, c.slot0);
  for (let i = 0; i < 5; i++) c.buy(wallet("snipe"), 2.2, 0, c.slot0);
  for (let i = 0; i < 8; i++) c.buy(wallet("b"), 0.3, 2000 + i * 800);
  return { curve: c, creator };
}
