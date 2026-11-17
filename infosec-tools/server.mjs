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
const SEED = JSON.parse(fs.readFileSync(path.join(ROOT, "seed", "catalog.json"), "utf8"));
const key = (t, x) => `${t}/${x}`;
const topCat = (c) => String(c || "General").split(" · ")[0];
function stampSeed(c, seed = SEED) {
  c.seedGeneratedAt = seed.generatedAt;
  c.seedIds = seed.tabs.flatMap((t) => t.tools.map((x) => key(t.id, x.id)));
  c.seedNative = seed.tabs.flatMap((t) => t.tools.filter((x) => x.native).map((x) => key(t.id, x.id)));
  return c;
}
// Every top-level category used by a tool gets a card entry (seed metadata if known, blank otherwise).
function syncCategories(tab, seedTab) {
  tab.categories = Array.isArray(tab.categories) ? tab.categories : [];
  for (const name of new Set(tab.tools.map((x) => topCat(x.category)))) {
    if (tab.categories.some((c) => c.name === name)) continue;
    const m = seedTab?.categories?.find((c) => c.name === name);
    tab.categories.push(m ? structuredClone(m) : { name, icon: "sparkle", description: "" });
  }
}
function writeCatalogSync(c, backupTag) {
  if (backupTag && fs.existsSync(CATALOG_FILE)) fs.copyFileSync(CATALOG_FILE, path.join(DATA_DIR, "backups", `catalog-${new Date().toISOString().replace(/[:.]/g, "-")}-${backupTag}.json`));
  fs.writeFileSync(CATALOG_FILE + ".tmp", JSON.stringify(c, null, 1)); fs.renameSync(CATALOG_FILE + ".tmp", CATALOG_FILE);
}
fs.mkdirSync(path.join(DATA_DIR, "backups"), { recursive: true });
if (!fs.existsSync(CATALOG_FILE)) writeCatalogSync(stampSeed(structuredClone(SEED)));
let catalog = JSON.parse(fs.readFileSync(CATALOG_FILE, "utf8"));

// v1 -> v2: the four tabs become toolkits with new ids and names, link-only tools are removed,
// and each toolkit gains category cards. Admin renames are kept; a backup is written first.
const V1_TABS = { "it-utilities": ["it-toolkit", "IT Utilities"], "cipher-lab": ["cyberchef-toolkit", "Cipher Lab"], "web-recon": ["web-toolkit", "Web Recon"], "network-toolkit": ["network-toolkit", "Network Toolkit"] };
function migrateToV2(c, seed = SEED) {
  if ((c.version || 1) >= 2) return null;
  let removed = 0;
  for (const tab of c.tabs) {
    const [newId, oldName] = V1_TABS[tab.id] || [tab.id, null];
    const st = seed.tabs.find((s) => s.id === newId);
    tab.id = newId;
    if (st) {
      if (tab.name === oldName) { tab.name = st.name; tab.description = st.description; tab.icon = st.icon; }
      tab.tagline ??= st.tagline; tab.accent ??= st.accent;
    }
    const before = tab.tools.length; tab.tools = tab.tools.filter((x) => x.native); removed += before - tab.tools.length;
    for (const x of tab.tools) {
      x.category = String(x.category || "General").replace(/^Ref( · |$)/, "Reference$1");
      if (x.featured === undefined && st?.tools.find((s) => s.id === x.id)?.featured) x.featured = true;
    }
    syncCategories(tab, st);
  }
  c.site = { ...seed.site, ...(c.site || {}), title: c.title || seed.site.title };
  c.version = 2; stampSeed(c, seed);
  return removed;
}
{ const removed = migrateToV2(catalog); if (removed !== null) { writeCatalogSync(catalog, "pre-v2"); console.log(`[seed] migrated catalog to v2 toolkits: ${removed} link-only tools removed`); } }

// Seed upgrade: when a new release ships a newer seed catalog, bring its improvements into the
// stored (admin-editable) catalog without overwriting admin decisions:
//  - a tool gains a native implementation only if the previous seed had none for it either;
//  - tools/tabs new to the seed are added; ones the admin deleted are not restored;
//  - names, descriptions, visibility and order are left as the admin set them.
function upgradeFromSeed() {
  const seed = SEED;
  if (catalog.seedGeneratedAt === seed.generatedAt) return;
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
    syncCategories(tab, st);
  }
  stampSeed(catalog, seed);
  writeCatalogSync(catalog, "pre-upgrade");
  console.log(`[seed] upgraded catalog to seed ${seed.generatedAt}: ${filled} tools gained native implementations, ${added} tools and ${tabsAdded} tabs added`);
}
upgradeFromSeed();
const provenance = JSON.parse(fs.readFileSync(path.join(ROOT, "seed", "provenance.json"), "utf8"));

const ID_RE = /^[a-z0-9][a-z0-9._-]{0,80}$/i;
const COLOR_RE = /^#[0-9a-f]{6}$/i;
const THEMES = ["dark", "light", "ember", "terminal", "ocean", "paper", "contrast"];
const str = (v, max = 2000) => (typeof v === "string" ? v.slice(0, max) : "");
const SITE_FIELDS = { title: 80, brandPrefix: 40, brandSuffix: 40, eyebrow: 80, heading: 80, highlight: 80, headingEnd: 80, lead: 400, footer: 600 };
function validateSite(s = {}) {
  const out = {}; for (const [k, max] of Object.entries(SITE_FIELDS)) out[k] = str(s[k], max) || SEED.site[k] || "";
  out.theme = THEMES.includes(s.theme) ? s.theme : "dark";
  out.accent = COLOR_RE.test(s.accent || "") ? s.accent : ""; out.accent2 = COLOR_RE.test(s.accent2 || "") ? s.accent2 : "";
  return out;
}
function validateCatalog(c) {
  if (!c || typeof c !== "object" || !Array.isArray(c.tabs)) throw httpError(400, "Catalog must have a tabs array");
  const tabIds = new Set();
  const tabs = c.tabs.map((t) => {
    if (!ID_RE.test(t.id || "") || tabIds.has(t.id)) throw httpError(400, `Invalid or duplicate toolkit id "${t.id}"`); tabIds.add(t.id);
    if (!str(t.name, 80).trim()) throw httpError(400, `Toolkit "${t.id}" needs a name`);
    const toolIds = new Set();
    const tools = (Array.isArray(t.tools) ? t.tools : []).map((x) => {
      if (!ID_RE.test(x.id || "") || toolIds.has(x.id)) throw httpError(400, `Invalid or duplicate tool id "${x.id}" in toolkit "${t.name}"`); toolIds.add(x.id);
      if (!str(x.name, 120).trim()) throw httpError(400, `Tool "${x.id}" needs a name`);
      const ext = str(x.external, 2000); if (ext && !/^https?:\/\//i.test(ext)) throw httpError(400, `Tool "${x.name}" link must start with http(s)://`);
      let native = null;
      if (x.native && x.native.op) { native = { op: str(x.native.op, 80), mode: x.native.mode === "server" ? "server" : "client" }; if (x.native.preset && typeof x.native.preset === "object") native.preset = Object.fromEntries(Object.entries(x.native.preset).slice(0, 20).map(([k, v]) => [str(k, 40), str(String(v), 400)])); }
      if (native?.mode === "server" && !serverOps[native.op]) throw httpError(400, `Tool "${x.name}" uses unknown server check "${native.op}"`);
      if (!native && !ext) throw httpError(400, `Tool "${x.name}" needs an implementation or a link`);
      return { id: x.id, name: str(x.name, 120).trim(), description: str(x.description, 2000), category: str(x.category, 120).trim() || "General", keywords: (Array.isArray(x.keywords) ? x.keywords : []).slice(0, 30).map((k) => str(String(k), 60)), native, external: ext, visible: x.visible !== false, featured: !!x.featured };
    });
    const src = str(t.sourceUrl, 500); if (src && !/^https?:\/\//i.test(src)) throw httpError(400, `Toolkit "${t.name}" source URL must start with http(s)://`);
    const catNames = new Set();
    const categories = (Array.isArray(t.categories) ? t.categories : []).map((cat) => ({ name: str(cat?.name, 120).trim(), icon: str(cat?.icon, 30) || "sparkle", description: str(cat?.description, 400) }))
      .filter((cat) => cat.name && !catNames.has(cat.name) && catNames.add(cat.name));
    const tab = { id: t.id, name: str(t.name, 80).trim(), tagline: str(t.tagline, 200), description: str(t.description, 1000), icon: str(t.icon, 30) || "toolbox", accent: COLOR_RE.test(t.accent || "") ? t.accent : "#22d3ee",
      source: str(t.source, 60), sourceUrl: src, visible: t.visible !== false, categories, tools };
    syncCategories(tab, null);
    return tab;
  });
  const site = validateSite(c.site);
  // Seed bookkeeping is server-owned: carry it over regardless of what the client sent.
  return { version: 2, title: site.title || "Infosec Tools", site, updatedAt: new Date().toISOString(), seedGeneratedAt: catalog.seedGeneratedAt, seedIds: catalog.seedIds, seedNative: catalog.seedNative, tabs };
}
async function saveCatalog(next, who) {
  const stamp = new Date().toISOString().replace(/[:.]/g, "-");
  await fsp.copyFile(CATALOG_FILE, path.join(DATA_DIR, "backups", `catalog-${stamp}.json`)).catch(() => {});
  const tmp = CATALOG_FILE + ".tmp"; await fsp.writeFile(tmp, JSON.stringify(next, null, 1)); await fsp.rename(tmp, CATALOG_FILE);
  catalog = next;
  const backups = (await fsp.readdir(path.join(DATA_DIR, "backups"))).sort(); for (const f of backups.slice(0, -50)) await fsp.unlink(path.join(DATA_DIR, "backups", f)).catch(() => {});
  console.log(`[admin] catalog saved by ${who} (${next.tabs.reduce((n, t) => n + t.tools.length, 0)} tools)`);
}
const publicCatalog = () => ({ title: catalog.title, site: validateSite(catalog.site), updatedAt: catalog.updatedAt, provenance,
  tabs: catalog.tabs.filter((t) => t.visible).map((t) => { const tools = t.tools.filter((x) => x.visible); const used = new Set(tools.map((x) => topCat(x.category))); return { ...t, categories: (t.categories || []).filter((c) => used.has(c.name)), tools }; }) });

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
const MIME = { ".html": "text/html; charset=utf-8", ".js": "text/javascript; charset=utf-8", ".css": "text/css; charset=utf-8", ".json": "application/json", ".svg": "image/svg+xml", ".txt": "text/plain; charset=utf-8", ".png": "image/png", ".woff2": "font/woff2", ".ico": "image/x-icon", ".webmanifest": "application/manifest+json" };

async function serveStatic(req, res, pathname) {
  let rel = decodeURIComponent(pathname); if (rel === "/" || !path.extname(rel)) rel = rel.startsWith("/admin") ? "/admin.html" : "/index.html";
  const file = path.normalize(path.join(PUBLIC, rel)); if (!file.startsWith(PUBLIC + path.sep)) return send(res, 403, "Forbidden");
  try { let data = await fsp.readFile(file);
    // The configured theme is applied before first paint (theme.js only overrides it with the visitor's own toggle).
    if (file.endsWith(".html")) { const site = validateSite(catalog.site); data = data.toString("utf8").replaceAll("{{THEME}}", site.theme).replaceAll("{{MODE}}", ["light", "paper"].includes(site.theme) ? "light" : "dark")
      .replaceAll("{{ACCENT_STYLE}}", [site.accent && `--accent:${site.accent}`, site.accent2 && `--accent-2:${site.accent2}`].filter(Boolean).join(";")).replaceAll("{{TITLE}}", site.title.replace(/[<>&"]/g, "")); }
    send(res, 200, data, { "Content-Type": MIME[path.extname(file)] || "application/octet-stream", "Cache-Control": /\.(html)$/.test(file) ? "no-cache" : "public, max-age=300" }); }
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
    if (p === "/api/admin/restore" && req.method === "POST") { const { file } = await readJson(req, 4096); if (!/^catalog-[\w-]+\.json$/.test(file || "")) throw httpError(400, "Invalid backup name"); const raw = JSON.parse(await fsp.readFile(path.join(DATA_DIR, "backups", file), "utf8")); migrateToV2(raw); const next = validateCatalog(raw); await saveCatalog(next, ip); return json(res, 200, { ok: true }); }
    if (p === "/api/admin/reset" && req.method === "POST") { const next = stampSeed(validateCatalog(structuredClone(SEED))); await saveCatalog(next, ip); return json(res, 200, { ok: true }); }
    if (p === "/api/admin/meta" && req.method === "GET") return json(res, 200, { themes: THEMES });
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
