// Seed upgrade must add new native implementations without overriding admin edits.
import test from "node:test"; import assert from "node:assert/strict";
import { spawn } from "node:child_process"; import fs from "node:fs"; import os from "node:os"; import path from "node:path";
const root = new URL("..", import.meta.url).pathname;
function boot(dataDir) { return new Promise((resolve, reject) => { const p = spawn(process.execPath, ["server.mjs"], { cwd: root, env: { ...process.env, ADMIN_PASSWORD: "x", PORT: "0", DATA_DIR: dataDir } }); let out = "";
  p.stdout.on("data", (d) => { out += d; if (out.includes("listening")) { p.kill(); resolve(out); } }); p.stderr.on("data", (d) => (out += d)); p.on("exit", (c) => c && !out.includes("listening") && reject(new Error(out))); }); }
const read = (d) => JSON.parse(fs.readFileSync(path.join(d, "catalog.json"), "utf8"));
test("upgrade fills natives, keeps renames/hides/deletions, is idempotent", async () => {
  const seed = JSON.parse(fs.readFileSync(path.join(root, "seed/catalog.json"), "utf8"));
  const old = structuredClone(seed); delete old.seedIds; for (const t of old.tabs) for (const x of t.tools) if (x.id !== "md5") x.native = null; // pretend an older seed with almost nothing native
  const cl = old.tabs.find((t) => t.id === "cipher-lab"); cl.tools.find((t) => t.id === "md5").name = "Renamed"; cl.tools.find((t) => t.id === "sha3").visible = false; cl.tools.splice(cl.tools.findIndex((t) => t.id === "rc4"), 1);
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "it-up-")); fs.writeFileSync(path.join(dir, "catalog.json"), JSON.stringify(old));
  const log = await boot(dir); assert.match(log, /\[seed\] upgraded catalog/);
  const c = read(dir); const t = c.tabs.find((x) => x.id === "cipher-lab").tools; const g = (id) => t.find((x) => x.id === id);
  assert.equal(g("md5").name, "Renamed"); assert.equal(g("sha3").visible, false); assert.ok(g("sha3").native); assert.equal(g("rc4"), undefined); assert.ok(g("chacha").native);
  const nativeAfter = c.tabs.reduce((n, x) => n + x.tools.filter((y) => y.native).length, 0); assert.equal(nativeAfter, seed.tabs.reduce((n, x) => n + x.tools.filter((y) => y.native).length, 0) - 1);
  const log2 = await boot(dir); assert.doesNotMatch(log2, /\[seed\] upgraded/);
  fs.rmSync(dir, { recursive: true });
});
