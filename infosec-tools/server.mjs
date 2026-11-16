// Infosec Tools server: static frontend, public catalog API, server-side checks,
// and a password-protected admin API for editing the catalog. No npm dependencies.
import http from "node:http";
import fs from "node:fs";
import fsp from "node:fs/promises";
import path from "node:path";
import crypto from "node:crypto";
import { fileURLToPath } from "node:url";
import { serverOps } from "./lib/server-ops.mjs";

const ROOT = path.dirname(fileURLToPath(import.meta.url));
const PUBLIC = path.join(ROOT, "public");
const DATA_DIR = process.env.DATA_DIR || path.join(ROOT, "data");
const CATALOG_FILE = path.join(DATA_DIR, "catalog.json");
const PORT = Number(process.env.PORT || 8080);
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || "";
const SESSION_HOURS = Number(process.env.SESSION_HOURS || 12);
const TRUST_PROXY = process.env.TRUST_PROXY !== "false";
const SECURE_COOKIE = process.env.COOKIE_SECURE !== "false";

// ---------- catalog store ----------
fs.mkdirSync(path.join(DATA_DIR, "backups"), { recursive: true });
if (!fs.existsSync(CATALOG_FILE)) { const seed = JSON.parse(fs.readFileSync(path.join(ROOT, "seed", "catalog.json"), "utf8")); seed.seedGeneratedAt = seed.generatedAt; seed.seedIds = seed.tabs.flatMap((t) => t.tools.map((x) => `${t.id}/${x.id}`)); seed.seedNative = seed.tabs.flatMap((t) => t.tools.filter((x) => x.native).map((x) => `${t.id}/${x.id}`)); fs.writeFileSync(CATALOG_FILE, JSON.stringify(seed, null, 1)); }
let catalog = JSON.parse(fs.readFileSync(CATALOG_FILE, "utf8"));

// Seed upgrade: when a new release ships a newer seed catalog, bring its improvements into the
// stored (admin-editable) catalog without overwriting admin decisions:
//  - a tool gains a native implementation only if the previous seed had none for it either;
//  - tools/tabs new to the seed are added; ones the admin deleted are not restored;
//  - names, descriptions, visibility and order are left as the admin set them.
function upgradeFromSeed() {
  const seed = JSON.parse(fs.readFileSync(path.join(ROOT, "seed", "catalog.json"), "utf8"));
  if (catalog.seedGeneratedAt === seed.generatedAt) return;
  const key = (t, x) => `${t}/${x}`;
  const firstUpgrade = !Array.isArray(catalog.seedIds);
  // Phase 1 shipped the full inventory, so on the first upgrade every current seed tool counts as
  // "previously seeded": nothing is re-added, and tools the admin deleted stay deleted.
  const prevIds = new Set(catalog.seedIds || seed.tabs.flatMap((t) => t.tools.map((x) => key(t.id, x.id))));
  const prevNative = new Set(catalog.seedNative || []);
  let filled = 0, added = 0, tabsAdded = 0;
  for (const st of seed.tabs) {
    let tab = catalog.tabs.find((t) => t.id === st.id);
    if (!tab) { if (st.tools.some((x) => prevIds.has(key(st.id, x.id)))) continue; catalog.tabs.push(structuredClone(st)); tabsAdded++; continue; }
    for (const sx of st.tools) {
      const k = key(st.id, sx.id); const cur = tab.tools.find((x) => x.id === sx.id);
      if (!cur) { if (!prevIds.has(k)) { tab.tools.push(structuredClone(sx)); added++; } continue; }
      if (!cur.native && sx.native && (firstUpgrade || !prevNative.has(k))) { cur.native = structuredClone(sx.native); filled++; }
    }
  }
  catalog.seedGeneratedAt = seed.generatedAt;
  catalog.seedIds = seed.tabs.flatMap((t) => t.tools.map((x) => key(t.id, x.id)));
  catalog.seedNative = seed.tabs.flatMap((t) => t.tools.filter((x) => x.native).map((x) => key(t.id, x.id)));
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  fs.copyFileSync(CATALOG_FILE, path.join(DATA_DIR, "backups", `catalog-${stamp}-pre-upgrade.json`));
  fs.writeFileSync(CATALOG_FILE + ".tmp", JSON.stringify(catalog, null, 1)); fs.renameSync(CATALOG_FILE + ".tmp", CATALOG_FILE);
  console.log(`[seed] upgraded catalog to seed ${seed.generatedAt}: ${filled} tools gained native implementations, ${added} tools and ${tabsAdded} tabs added`);
}
upgradeFromSeed();
const provenance = JSON.parse(fs.readFileSync(path.join(ROOT, "seed", "provenance.json"), "utf8"));

const ID_RE = /^[a-z0-9][a-z0-9._-]{0,80}$/i;
const str = (v, max = 2000) => (typeof v === "string" ? v.slice(0, max) : "");
function validateCatalog(c) {
  if (!c || typeof c !== "object" || !Array.isArray(c.tabs)) throw httpError(400, "Catalog must have a tabs array");
  const tabIds = new Set();
  const tabs = c.tabs.map((t) => {
    if (!ID_RE.test(t.id || "") || tabIds.has(t.id)) throw httpError(400, `Invalid or duplicate tab id "${t.id}"`); tabIds.add(t.id);
    if (!str(t.name, 80).trim()) throw httpError(400, `Tab "${t.id}" needs a name`);
    const toolIds = new Set();
    const tools = (Array.isArray(t.tools) ? t.tools : []).map((x) => {
      if (!ID_RE.test(x.id || "") || toolIds.has(x.id)) throw httpError(400, `Invalid or duplicate tool id "${x.id}" in tab "${t.id}"`); toolIds.add(x.id);
      if (!str(x.name, 120).trim()) throw httpError(400, `Tool "${x.id}" needs a name`);
      const ext = str(x.external, 2000); if (ext && !/^https?:\/\//i.test(ext)) throw httpError(400, `Tool "${x.id}" link must start with http(s)://`);
      let native = null;
      if (x.native && x.native.op) { native = { op: str(x.native.op, 80), mode: x.native.mode === "server" ? "server" : "client" }; if (x.native.preset && typeof x.native.preset === "object") native.preset = Object.fromEntries(Object.entries(x.native.preset).slice(0, 20).map(([k, v]) => [str(k, 40), str(String(v), 400)])); }
      if (native?.mode === "server" && !serverOps[native.op]) throw httpError(400, `Tool "${x.id}" uses unknown server op "${native.op}"`);
      return { id: x.id, name: str(x.name, 120).trim(), description: str(x.description, 2000), category: str(x.category, 120) || "General", keywords: (Array.isArray(x.keywords) ? x.keywords : []).slice(0, 30).map((k) => str(String(k), 60)), native, external: ext, visible: x.visible !== false, featured: !!x.featured };
    });
    const src = str(t.sourceUrl, 500); if (src && !/^https?:\/\//i.test(src)) throw httpError(400, `Tab "${t.id}" source URL must start with http(s)://`);
    return { id: t.id, name: str(t.name, 80).trim(), description: str(t.description, 1000), icon: str(t.icon, 30) || "wrench", source: str(t.source, 60), sourceUrl: src, visible: t.visible !== false, tools };
  });
  // Seed bookkeeping is server-owned: carry it over regardless of what the client sent.
  return { version: 1, title: str(c.title, 80) || "Infosec Tools", tagline: str(c.tagline, 200), updatedAt: new Date().toISOString(), seedGeneratedAt: catalog.seedGeneratedAt, seedIds: catalog.seedIds, seedNative: catalog.seedNative, tabs };
}
async function saveCatalog(next, who) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  await fsp.copyFile(CATALOG_FILE, path.join(DATA_DIR, "backups", `catalog-${stamp}.json`)).catch(() => {});
  const tmp = CATALOG_FILE + ".tmp"; await fsp.writeFile(tmp, JSON.stringify(next, null, 1)); await fsp.rename(tmp, CATALOG_FILE);
  catalog = next;
  const backups = (await fsp.readdir(path.join(DATA_DIR, "backups"))).sort(); for (const f of backups.slice(0, -50)) await fsp.unlink(path.join(DATA_DIR, "backups", f)).catch(() => {});
  console.log(`[admin] catalog saved by ${who} (${next.tabs.reduce((n, t) => n + t.tools.length, 0)} tools)`);
}
const publicCatalog = () => ({ title: catalog.title, tagline: catalog.tagline, updatedAt: catalog.updatedAt, provenance, tabs: catalog.tabs.filter((t) => t.visible).map((t) => ({ ...t, tools: t.tools.filter((x) => x.visible) })) });

// ---------- auth ----------
const sessions = new Map(); // token -> expiry
const attempts = new Map(); // ip -> {count, until}
const sha = (s) => crypto.createHash("sha256").update(s).digest();
function checkPassword(pw) { return ADMIN_PASSWORD.length > 0 && crypto.timingSafeEqual(sha(String(pw)), sha(ADMIN_PASSWORD)); }
function cookies(req) { return Object.fromEntries((req.headers.cookie || "").split(";").map((c) => c.trim().split("=")).filter((x) => x[0]).map(([k, ...v]) => [k, decodeURIComponent(v.join("="))])); }
function isAdmin(req) { const t = cookies(req).it_session; const exp = t && sessions.get(t); if (!exp) return false; if (exp < Date.now()) { sessions.delete(t); return false; } return true; }
const clientIp = (req) => (TRUST_PROXY && String(req.headers["x-forwarded-for"] || "").split(",")[0].trim()) || req.socket.remoteAddress || "?";
const sessionCookie = (token, maxAge) => `it_session=${token}; Path=/; HttpOnly; SameSite=Strict; Max-Age=${maxAge}${SECURE_COOKIE ? "; Secure" : ""}`;

// ---------- rate limiting (server-side checks) ----------
const buckets = new Map();
function rateLimit(ip, limit = 40, windowMs = 60000) { const now = Date.now(); const b = buckets.get(ip) || { n: 0, reset: now + windowMs }; if (now > b.reset) { b.n = 0; b.reset = now + windowMs; } b.n++; buckets.set(ip, b); return b.n <= limit; }
setInterval(() => { const now = Date.now(); for (const [k, b] of buckets) if (now > b.reset) buckets.delete(k); for (const [k, e] of sessions) if (e < now) sessions.delete(k); for (const [k, a] of attempts) if (a.until < now) attempts.delete(k); }, 60000).unref();

// ---------- http helpers ----------
function httpError(status, message) { const e = new Error(message); e.status = status; return e; }
const SEC_HEADERS = {
  "Content-Security-Policy": "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:; media-src 'self' blob:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
  "X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY", "Referrer-Policy": "strict-origin-when-cross-origin", "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
  "Cross-Origin-Opener-Policy": "same-origin", "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
};
function send(res, status, body, headers = {}) { res.writeHead(status, { ...SEC_HEADERS, ...headers }); res.end(body); }
const json = (res, status, obj, headers = {}) => send(res, status, JSON.stringify(obj), { "Content-Type": "application/json; charset=utf-8", "Cache-Control": "no-store", ...headers });
async function readJson(req, max = 5 * 1024 * 1024) { const chunks = []; let n = 0; for await (const c of req) { n += c.length; if (n > max) throw httpError(413, "Request too large"); chunks.push(c); } try { return JSON.parse(Buffer.concat(chunks).toString("utf8") || "{}"); } catch { throw httpError(400, "Invalid JSON body"); } }
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml", ".png": "image/png", ".ico": "image/x-icon", ".webmanifest": "application/manifest+json" };

async function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname); if (rel === "/" || !path.extname(rel)) rel = rel.startsWith("/admin") ? "/admin.html" : "/index.html";
  const file = path.normalize(path.join(PUBLIC, rel)); if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, "Forbidden");
  try { const data = await fsp.readFile(file); send(res, 200, data, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream", "Cache-Control": /\.(html)$/.test(file) ? "no-cache" : "public, max-age=300" }); }
  catch { send(res, 404, "Not found", { "Content-Type": "text/plain" }); }
}

// ---------- routes ----------
async function handle(req, res) {
  const url = new URL(req.url, "http://localhost"); const p = url.pathname; const ip = clientIp(req);
  if (p === "/healthz") return json(res, 200, { ok: true });
  if (p === "/api/catalog" && req.method === "GET") return json(res, 200, publicCatalog());

  if (p.startsWith("/api/run/") && req.method === "POST") {
    const op = serverOps[p.slice(9)]; if (!op) throw httpError(404, "Unknown check");
    if (!rateLimit(ip)) throw httpError(429, "Too many requests — wait a minute and try again");
    const body = await readJson(req, 64 * 1024);
    const started = Date.now();
    try { const out = await Promise.race([op.run(String(body.target || ""), body.args || {}), new Promise((_, rej) => setTimeout(() => rej(httpError(504, "Check timed out after 45 s")), 45000))]); return json(res, 200, { ok: true, ms: Date.now() - started, ...out }); }
    catch (e) { return json(res, e.status && e.status < 500 ? e.status : 502, { ok: false, error: e.status ? e.message : `Check failed: ${e.code || e.message}` }); }
  }

  if (p === "/api/admin/status") return json(res, 200, { enabled: ADMIN_PASSWORD.length > 0, authenticated: isAdmin(req) });
  if (p === "/api/admin/login" && req.method === "POST") {
    if (!ADMIN_PASSWORD) throw httpError(503, "Admin is disabled: set ADMIN_PASSWORD on the server");
    const a = attempts.get(ip); if (a && a.count >= 5 && a.until > Date.now()) throw httpError(429, "Too many failed attempts — try again in 15 minutes");
    const body = await readJson(req, 4096);
    if (!checkPassword(body.password)) { const n = (a?.count || 0) + 1; attempts.set(ip, { count: n, until: Date.now() + 15 * 60000 }); console.warn(`[admin] failed login from ${ip}`); throw httpError(401, "Wrong password"); }
    attempts.delete(ip); const token = crypto.randomBytes(32).toString("hex"); sessions.set(token, Date.now() + SESSION_HOURS * 3600e3);
    console.log(`[admin] login from ${ip}`); return json(res, 200, { ok: true }, { "Set-Cookie": sessionCookie(token, SESSION_HOURS * 3600) });
  }
  if (p === "/api/admin/logout" && req.method === "POST") { const t = cookies(req).it_session; if (t) sessions.delete(t); return json(res, 200, { ok: true }, { "Set-Cookie": sessionCookie("", 0) }); }

  if (p.startsWith("/api/admin/")) {
    if (!isAdmin(req)) throw httpError(401, "Not signed in");
    if (req.method !== "GET" && req.headers["x-requested-with"] !== "infosec-tools") throw httpError(403, "Missing CSRF header");
    if (p === "/api/admin/catalog" && req.method === "GET") return json(res, 200, catalog);
    if (p === "/api/admin/catalog" && req.method === "PUT") { const next = validateCatalog(await readJson(req)); await saveCatalog(next, ip); return json(res, 200, { ok: true, updatedAt: next.updatedAt }); }
    if (p === "/api/admin/server-ops" && req.method === "GET") return json(res, 200, Object.fromEntries(Object.entries(serverOps).map(([k, v]) => [k, v.name])));
    if (p === "/api/admin/backups" && req.method === "GET") return json(res, 200, (await fsp.readdir(path.join(DATA_DIR, "backups"))).sort().reverse());
    if (p === "/api/admin/restore" && req.method === "POST") { const { file } = await readJson(req, 4096); if (!/^catalog-[\w-]+\.json$/.test(file || "")) throw httpError(400, "Invalid backup name"); const next = validateCatalog(JSON.parse(await fsp.readFile(path.join(DATA_DIR, "backups", file), "utf8"))); await saveCatalog(next, ip); return json(res, 200, { ok: true }); }
    if (p === "/api/admin/reset" && req.method === "POST") { const seed = JSON.parse(await fsp.readFile(path.join(ROOT, "seed", "catalog.json"), "utf8")); const next = validateCatalog(seed); next.seedGeneratedAt = seed.generatedAt; next.seedIds = seed.tabs.flatMap((t) => t.tools.map((x) => `${t.id}/${x.id}`)); next.seedNative = seed.tabs.flatMap((t) => t.tools.filter((x) => x.native).map((x) => `${t.id}/${x.id}`)); await saveCatalog(next, ip); return json(res, 200, { ok: true }); }
    throw httpError(404, "Unknown admin endpoint");
  }
  if (p.startsWith("/api/")) throw httpError(404, "Unknown endpoint");
  if (req.method !== "GET" && req.method !== "HEAD") throw httpError(405, "Method not allowed");
  return serveStatic(req, res, p);
}

const server = http.createServer((req, res) => { handle(req, res).catch((e) => { if (!e.status) console.error(e); if (!res.headersSent) json(res, e.status || 500, { ok: false, error: e.status ? e.message : "Internal error" }); }); });
server.headersTimeout = 20000; server.requestTimeout = 60000;
server.listen(PORT, () => console.log(`Infosec Tools listening on :${PORT} (admin ${ADMIN_PASSWORD ? "enabled" : "DISABLED — set ADMIN_PASSWORD"}, data ${DATA_DIR})`));
process.on("SIGTERM", () => server.close(() => process.exit(0)));
