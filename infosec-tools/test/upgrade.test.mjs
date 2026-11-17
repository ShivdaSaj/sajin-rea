// Catalog migrations on start-up: v1 tabs -> v2 toolkits, and seed upgrades that respect admin edits.
import test from "node:test"; import assert from "node:assert/strict";
import { spawn } from "node:child_process"; import fs from "node:fs"; import os from "node:os"; import path from "node:path";
const root = new URL("..", import.meta.url).pathname;
function boot(dataDir) { return new Promise((resolve, reject) => { const p = spawn(process.execPath, ["server.mjs"], { cwd: root, env: { ...process.env, ADMIN_PASSWORD: "x", PORT: "0", DATA_DIR: dataDir } }); let out = "";
  p.stdout.on("data", (d) => { out += d; if (out.includes("listening")) { p.kill(); resolve(out); } }); p.stderr.on("data", (d) => (out += d)); p.on("exit", (c) => c && !out.includes("listening") && reject(new Error(out))); }); }
const read = (d) => JSON.parse(fs.readFileSync(path.join(d, "catalog.json"), "utf8"));
const seed = JSON.parse(fs.readFileSync(path.join(root, "seed/catalog.json"), "utf8"));
const V1 = { "it-toolkit": ["it-utilities", "IT Utilities"], "cyberchef-toolkit": ["cipher-lab", "Cipher Lab"], "web-toolkit": ["web-recon", "Web Recon"], "network-toolkit": ["network-toolkit", "Network Toolkit"] };

test("v1 catalog migrates to v2 toolkits, drops link-only tools, keeps admin edits", async () => {
  // Rebuild a v1-shaped catalog from the v2 seed: old ids/names, no categories/site, Ref names, plus link-only tools.
  const v1 = { version: 1, generatedAt: "2026-11-01T00:00:00.000Z", title: "Infosec Tools", tabs: seed.tabs.map((t) => ({ id: V1[t.id][0], name: V1[t.id][1], description: "old", icon: "wrench", source: t.source, sourceUrl: t.sourceUrl, visible: true,
    tools: t.tools.map((x) => ({ ...x, featured: undefined, category: x.category.replace(/^Reference/, "Ref") })) })) };
  v1.seedGeneratedAt = v1.generatedAt; v1.seedIds = v1.tabs.flatMap((t) => t.tools.map((x) => `${t.id}/${x.id}`));
  const cl = v1.tabs.find((t) => t.id === "cipher-lab");
  cl.tools.push({ id: "pgp-encrypt", name: "PGP Encrypt", description: "", category: "Encryption / Encoding", keywords: [], native: null, external: "https://example.org", visible: true });
  cl.tools.find((t) => t.id === "md5").name = "MD5 (renamed)"; cl.tools.find((t) => t.id === "sha3").visible = false;
  const wr = v1.tabs.find((t) => t.id === "web-recon"); wr.name = "My Recon"; // admin-renamed tab keeps its name
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "it-v2-")); fs.writeFileSync(path.join(dir, "catalog.json"), JSON.stringify(v1));
  const log = await boot(dir); assert.match(log, /migrated catalog to v2 toolkits: 1 link-only tools removed/);
  const c = read(dir);
  assert.equal(c.version, 2);
  assert.deepEqual(c.tabs.map((t) => t.id), ["it-toolkit", "cyberchef-toolkit", "web-toolkit", "network-toolkit"]);
  const cc = c.tabs.find((t) => t.id === "cyberchef-toolkit");
  assert.equal(cc.name, "CyberChef Toolkit"); assert.equal(cc.accent, "#a78bfa"); assert.ok(cc.categories.length >= 10);
  assert.equal(cc.tools.find((t) => t.id === "pgp-encrypt"), undefined);
  assert.equal(cc.tools.find((t) => t.id === "md5").name, "MD5 (renamed)"); assert.equal(cc.tools.find((t) => t.id === "sha3").visible, false);
  assert.equal(c.tabs.find((t) => t.id === "web-toolkit").name, "My Recon");
  const nt = c.tabs.find((t) => t.id === "network-toolkit"); assert.ok(nt.tools.every((t) => !t.category.startsWith("Ref ·"))); assert.ok(nt.categories.some((x) => x.name === "Reference"));
  assert.ok(c.tabs.every((t) => t.tools.every((x) => x.native)));
  assert.equal(c.site.title, "Infosec Tools");
  assert.ok(fs.readdirSync(path.join(dir, "backups")).some((f) => f.endsWith("-pre-v2.json")));
  const log2 = await boot(dir); assert.doesNotMatch(log2, /migrated|upgraded/);
  fs.rmSync(dir, { recursive: true });
});

test("seed upgrade adds new tools but never restores admin deletions", async () => {
  const old = structuredClone(seed); old.seedGeneratedAt = "2026-01-01T00:00:00.000Z";
  old.seedIds = seed.tabs.flatMap((t) => t.tools.map((x) => `${t.id}/${x.id}`)).filter((k) => k !== "it-toolkit/token-generator"); // pretend token-generator is new
  const it = old.tabs.find((t) => t.id === "it-toolkit");
  it.tools = it.tools.filter((t) => t.id !== "token-generator" && t.id !== "uuid-generator"); // token-generator new to seed; uuid-generator deleted by admin
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "it-up-")); fs.writeFileSync(path.join(dir, "catalog.json"), JSON.stringify(old));
  const log = await boot(dir); assert.match(log, /\[seed\] upgraded catalog/);
  const t = read(dir).tabs.find((x) => x.id === "it-toolkit").tools;
  assert.ok(t.find((x) => x.id === "token-generator")); assert.equal(t.find((x) => x.id === "uuid-generator"), undefined);
  const log2 = await boot(dir); assert.doesNotMatch(log2, /\[seed\] upgraded/);
  fs.rmSync(dir, { recursive: true });
});
