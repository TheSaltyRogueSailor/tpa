#!/usr/bin/env node
/**
 * Records examples/redteam-demo-animated.html to an MP4 (H.264, yuv420p) with no npm dependencies:
 * launches the system Chrome/Chromium headless, drives it over the DevTools protocol (Node's built-in
 * WebSocket), steps the page's own clock frame by frame (window.__tpa.render(ms)) and pipes the
 * screenshots into ffmpeg. Because time is stepped, not real, the video is smooth however slow capture is.
 *
 *   node scripts/record-demo-video.mjs [page.html] [out.mp4] [--fps 30] [--scale 1.5] [--frames-dir dir]
 *   node scripts/record-demo-video.mjs [page.html] --stills 9500:a.png,15000:b.png   # just stills at those ms
 *   (--scale 1.5 renders the 1280x720 stage at 1920x1080)
 */
import { spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { pathToFileURL } from "node:url";

const args = process.argv.slice(2);
const flag = (name, fallback) => { const i = args.indexOf(name); if (i < 0) return fallback; const v = args[i + 1]; args.splice(i, 2); return v; };
const fps = Number(flag("--fps", "30"));
const scale = Number(flag("--scale", "1.5"));
const framesDir = flag("--frames-dir", undefined);
const stills = flag("--stills", undefined);
const page = resolve(args[0] ?? "examples/redteam-demo-animated.html");
const out = resolve(args[1] ?? "artifacts/tpa-demo.mp4");
const chrome = [process.env.CHROME_PATH, "/usr/bin/google-chrome", "/usr/bin/chromium", "/usr/bin/chromium-browser"].find(p => p && existsSync(p));
if (!chrome) throw new Error("No Chrome/Chromium found; set CHROME_PATH");
if (!existsSync(page)) throw new Error(`Page not found: ${page} (run pnpm demo:animated first)`);
mkdirSync(resolve(out, ".."), { recursive: true });

const profile = mkdtempSync(join(tmpdir(), "tpa-rec-"));
const browser = spawn(chrome, ["--headless=new", "--remote-debugging-port=0", `--user-data-dir=${profile}`, "--no-first-run", "--no-default-browser-check",
  "--disable-gpu", "--hide-scrollbars", "--mute-audio", "--force-color-profile=srgb", "--font-render-hinting=none", "about:blank"], { stdio: ["ignore", "ignore", "pipe"] });
const wsUrl = await new Promise((ok, fail) => {
  let buf = ""; const timer = setTimeout(() => fail(new Error("Chrome did not start")), 20000);
  browser.stderr.on("data", d => { buf += d; const m = buf.match(/DevTools listening on (ws:\/\/\S+)/); if (m) { clearTimeout(timer); ok(m[1]); } });
  browser.on("exit", code => fail(new Error(`Chrome exited (${code})`)));
});

// minimal CDP client
const ws = new WebSocket(wsUrl); await new Promise((ok, fail) => { ws.onopen = ok; ws.onerror = fail; });
let nextId = 1; const pending = new Map();
ws.onmessage = ev => { const msg = JSON.parse(ev.data); const p = pending.get(msg.id); if (!p) return; pending.delete(msg.id); msg.error ? p.fail(new Error(msg.error.message)) : p.ok(msg.result); };
const send = (method, params = {}, sessionId) => new Promise((ok, fail) => { const id = nextId++; pending.set(id, { ok, fail }); ws.send(JSON.stringify({ id, method, params, sessionId })); });

const { targetId } = await send("Target.createTarget", { url: "about:blank" });
const { sessionId } = await send("Target.attachToTarget", { targetId, flatten: true });
const S = (method, params) => send(method, params, sessionId);
await S("Page.enable"); await S("Runtime.enable");
await S("Emulation.setDeviceMetricsOverride", { width: 1280, height: 720, deviceScaleFactor: scale, mobile: false });
await S("Page.navigate", { url: `${pathToFileURL(page).href}?record` });
const evaluate = async expression => (await S("Runtime.evaluate", { expression, awaitPromise: true, returnByValue: true })).result.value;
for (let i = 0; i < 100 && !(await evaluate("!!(window.__tpa && document.readyState === 'complete')")); i++) await new Promise(r => setTimeout(r, 100));
await evaluate("document.fonts.ready.then(() => true)");
const duration = await evaluate("window.__tpa.duration");
if (!duration) throw new Error("window.__tpa not found on the page");
const frames = Math.ceil((duration / 1000) * fps);
const W = Math.round(1280 * scale), H = Math.round(720 * scale);
const cleanup = async () => {
  const exited = browser.exitCode === null ? new Promise(r => browser.once("exit", r)) : Promise.resolve();
  await send("Browser.close").catch(() => {});
  ws.close();
  await Promise.race([exited, new Promise(r => setTimeout(r, 3000))]);
  if (browser.exitCode === null) browser.kill("SIGKILL");
  await new Promise(r => setTimeout(r, 300));
  try { rmSync(profile, { recursive: true, force: true, maxRetries: 5, retryDelay: 200 }); } catch { /* temp profile; leave it if Chrome still holds files */ }
};
const shoot = async ms => {
  // render this exact instant, then wait for two animation frames so layout and paint are committed
  await evaluate(`new Promise(r => { window.__tpa.render(${ms}); requestAnimationFrame(() => requestAnimationFrame(() => r(true))); })`);
  return Buffer.from((await S("Page.captureScreenshot", { format: "png", captureBeyondViewport: false })).data, "base64");
};
if (stills) {
  for (const spec of stills.split(",")) { const [ms, file] = spec.split(":"); writeFileSync(resolve(file), await shoot(Number(ms))); console.log(`still ${ms} ms -> ${resolve(file)}`); }
  await cleanup(); process.exit(0);
}
console.log(`Recording ${frames} frames (${(duration / 1000).toFixed(1)} s at ${fps} fps, ${W}x${H}) -> ${out}`);

const ffmpeg = spawn("ffmpeg", ["-y", "-loglevel", "error", "-f", "image2pipe", "-framerate", String(fps), "-c:v", "png", "-i", "-",
  "-vf", `scale=${W}:${H}:flags=lanczos,format=yuv420p`, "-c:v", "libx264", "-preset", "slow", "-crf", "18", "-profile:v", "high", "-pix_fmt", "yuv420p",
  "-r", String(fps), "-movflags", "+faststart", out], { stdio: ["pipe", "inherit", "inherit"] });
const ffDone = new Promise((ok, fail) => ffmpeg.on("exit", code => (code === 0 ? ok() : fail(new Error(`ffmpeg exited ${code}`)))));
if (framesDir) mkdirSync(framesDir, { recursive: true });

const started = Date.now();
for (let f = 0; f < frames; f++) {
  const ms = (f * 1000) / fps;
  const png = await shoot(ms);
  if (framesDir) writeFileSync(join(framesDir, `f${String(f).padStart(5, "0")}.png`), png);
  if (!ffmpeg.stdin.write(png)) await new Promise(r => ffmpeg.stdin.once("drain", r));
  if (f % (fps * 5) === 0) process.stdout.write(`  ${(ms / 1000).toFixed(0)}s / ${(duration / 1000).toFixed(0)}s  (${((Date.now() - started) / 1000).toFixed(0)}s elapsed)\n`);
}
ffmpeg.stdin.end(); await ffDone;
await cleanup();
console.log(`Done: ${out}`);
