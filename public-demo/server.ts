/**
 * Public demo process for Render. This is not the loopback owner dashboard.
 * It binds all interfaces, serves a read-only snapshot, and never mounts TPA mutation routes.
 */
import { createServer } from "node:http";
import { pathToFileURL } from "node:url";
import { createPublicDemoApp } from "./app.js";
import { assertPublicDemoHost, operatorMessage, resolveListen } from "./config.js";

export async function startPublicDemo(env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): Promise<void> {
  try {
    assertPublicDemoHost(env, cwd);
    const listen = resolveListen(env);
    const { app } = await createPublicDemoApp({ env, cwd });
    const server = createServer(app);
    server.on("error", () => {
      console.error("Refusing to continue because the public demo port is unavailable.");
      process.exitCode = 1;
    });
    server.listen(listen.port, listen.host, () => {
      console.log(`TPA public demo http://${listen.host}:${listen.port}/dashboard`);
      console.log("Mock payment rail, real executed security checks. Live payment rails are disabled.");
    });
  } catch (error) {
    console.error(operatorMessage(error));
    process.exitCode = 1;
  }
}

const entry = process.argv[1];
if (entry && import.meta.url === pathToFileURL(entry).href) void startPublicDemo();
