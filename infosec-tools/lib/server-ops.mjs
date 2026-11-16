// Server-side checks for Web Recon and network lookups. Each op takes a target string
// and returns { text, data } (text for display, data as structured JSON).
import { Resolver } from "node:dns/promises";
import net from "node:net";
import tls from "node:tls";
import { normalizeHost, resolvePublic, safeFetch, safeRequest, TargetError, isPublicIp, publicResolver as dns } from "./netsafe.mjs";

const hostOf = (t) => normalizeHost(t).host;
const urlOf = (t) => { const s = String(t).trim(); return /^https?:\/\//i.test(s) ? s : `https://${s}`; };
const tryq = async (fn) => { try { return await fn(); } catch (e) { return e.code === "ENODATA" || e.code === "ENOTFOUND" ? [] : { error: e.code || e.message }; } };
const domainOf = (h) => h.replace(/^www\./, "");
const fmt = (obj) => JSON.stringify(obj, null, 2);
const kv = (rows) => rows.filter(([, v]) => v !== undefined && v !== null && v !== "").map(([k, v]) => `${k.padEnd(24)} ${Array.isArray(v) ? v.join(", ") : v}`).join("\n");

async function dnsAll(host) {
  const [A, AAAA, MX, NS, TXT, CNAME, SOA, CAA, SRV] = await Promise.all([
    tryq(() => dns.resolve4(host, { ttl: true })), tryq(() => dns.resolve6(host, { ttl: true })), tryq(() => dns.resolveMx(host)), tryq(() => dns.resolveNs(host)),
    tryq(async () => (await dns.resolveTxt(host)).map((t) => t.join(""))), tryq(() => dns.resolveCname(host)), tryq(() => dns.resolveSoa(host)), tryq(() => dns.resolveCaa(host)), tryq(() => dns.resolveSrv(`_sip._tcp.${host}`))]);
  return { A, AAAA, MX, NS, TXT, CNAME, SOA, CAA };
}
const dnsText = (d) => Object.entries(d).map(([k, v]) => `${k}:\n${Array.isArray(v) ? (v.length ? v.map((x) => "  " + (typeof x === "object" ? Object.entries(x).map(([a, b]) => `${a}=${b}`).join(" ") : x)).join("\n") : "  (none)") : "  " + (v?.error ? `error: ${v.error}` : Object.entries(v || {}).map(([a, b]) => `${a}=${b}`).join(" "))}`).join("\n");

async function doh(name, type) {
  const r = await fetch(`https://cloudflare-dns.com/dns-query?name=${encodeURIComponent(name)}&type=${type}&do=1`, { headers: { accept: "application/dns-json" }, signal: AbortSignal.timeout(8000) });
  if (!r.ok) throw new Error(`DoH HTTP ${r.status}`); return r.json();
}

function certChain(host, port = 443) {
  return new Promise((resolve, reject) => {
    resolvePublic(host).then((ips) => {
      const s = tls.connect({ host: ips.find(net.isIPv4) || ips[0], port, servername: net.isIP(host) ? undefined : host, rejectUnauthorized: false, timeout: 10000, ALPNProtocols: ["h2", "http/1.1"] }, () => {
        const chain = []; let c = s.getPeerCertificate(true); const seen = new Set();
        while (c && c.raw && !seen.has(c.fingerprint256)) { seen.add(c.fingerprint256); chain.push(c); c = c.issuerCertificate; }
        const info = { authorized: s.authorized, authorizationError: s.authorizationError || null, protocol: s.getProtocol(), cipher: s.getCipher(), alpn: s.alpnProtocol, ephemeral: s.getEphemeralKeyInfo?.() };
        s.end(); resolve({ chain, info });
      });
      s.on("timeout", () => s.destroy(new Error("TLS connection timed out"))); s.on("error", reject);
    }, reject);
  });
}
const certSummary = (c) => ({ subject: c.subject?.CN || JSON.stringify(c.subject), issuer: c.issuer?.CN || c.issuer?.O, validFrom: c.valid_from, validTo: c.valid_to, daysLeft: Math.round((new Date(c.valid_to) - Date.now()) / 864e5), san: c.subjectaltname, serial: c.serialNumber, sha256: c.fingerprint256, keyBits: c.bits, keyType: c.asn1Curve || (c.bits ? "RSA" : undefined) });

function tlsVersion(host, version) {
  return new Promise((resolve) => resolvePublic(host).then((ips) => {
    const s = tls.connect({ host: ips.find(net.isIPv4) || ips[0], port: 443, servername: host, minVersion: version, maxVersion: version, rejectUnauthorized: false, timeout: 6000 }, () => { const c = s.getCipher(); s.end(); resolve({ version, supported: true, cipher: c?.name }); });
    s.on("error", (e) => resolve({ version, supported: false, error: e.code || e.message })); s.on("timeout", () => { s.destroy(); resolve({ version, supported: false, error: "timeout" }); });
  }, (e) => resolve({ version, supported: false, error: e.message })));
}

function tcpProbe(ip, port, timeout = 2500) {
  return new Promise((resolve) => { const s = net.connect({ host: ip, port, timeout }); const t0 = Date.now();
    s.on("connect", () => { s.destroy(); resolve({ port, open: true, ms: Date.now() - t0 }); }); s.on("timeout", () => { s.destroy(); resolve({ port, open: false, reason: "filtered/timeout" }); }); s.on("error", (e) => resolve({ port, open: false, reason: e.code })); });
}

// RDAP via the IANA bootstrap registries (RFC 9224): find the authoritative server, then query it.
const UA = { "User-Agent": "InfosecTools/1.0 (+https://infosectools.sajinshivdas.online)", Accept: "application/rdap+json, application/json" };
const bootCache = new Map();
async function bootstrap(kind) {
  const hit = bootCache.get(kind); if (hit && hit.at > Date.now() - 864e5) return hit.data;
  const r = await fetch(`https://data.iana.org/rdap/${kind}.json`, { headers: UA, signal: AbortSignal.timeout(12000) });
  if (!r.ok) throw new TargetError(`IANA RDAP bootstrap unavailable (HTTP ${r.status})`);
  const data = (await r.json()).services; bootCache.set(kind, { at: Date.now(), data }); return data;
}
const v4n = (ip) => ip.split(".").reduce((a, b) => a * 256 + +b, 0);
async function rdapBase(kind, q) {
  if (kind === "domain") { const labels = q.toLowerCase().split("."); const svc = await bootstrap("dns");
    for (let i = 0; i < labels.length; i++) { const suffix = labels.slice(i).join("."); const m = svc.find(([tlds]) => tlds.includes(suffix)); if (m) return m[1][0]; } }
  if (kind === "ip" && net.isIPv4(q)) { const svc = await bootstrap("ipv4"); let best = null;
    for (const [cidrs, urls] of svc) for (const c of cidrs) { const [n, b] = c.split("/"); const bits = +b; const size = 2 ** (32 - bits); const start = v4n(n); if (v4n(q) >= start && v4n(q) < start + size && (!best || bits > best.bits)) best = { bits, url: urls[0] }; }
    if (best) return best.url; }
  if (kind === "ip" && net.isIPv6(q)) { const svc = await bootstrap("ipv6"); const full = q.toLowerCase(); let best = null;
    const toBig = (a) => { const [h, t = ""] = a.split("::"); const hp = h ? h.split(":") : [], tp = t ? t.split(":") : []; const g = [...hp, ...Array(8 - hp.length - tp.length).fill("0"), ...tp]; return g.reduce((x, y) => (x << 16n) | BigInt(parseInt(y || "0", 16)), 0n); };
    const qb = toBig(full); for (const [cidrs, urls] of svc) for (const c of cidrs) { const [n, b] = c.split("/"); const bits = BigInt(b); if ((qb >> (128n - bits)) === (toBig(n) >> (128n - bits)) && (!best || bits > best.bits)) best = { bits, url: urls[0] }; }
    if (best) return best.url; }
  if (kind === "autnum") { const svc = await bootstrap("asn"); const n = Number(q); const m = svc.find(([ranges]) => ranges.some((r) => { const [a, b = a] = r.split("-").map(Number); return n >= a && n <= b; })); if (m) return m[1][0]; }
  throw new TargetError(`No RDAP server is registered for "${q}"`);
}
async function rdap(kind, q) {
  const base = await rdapBase(kind, q); const url = `${base.replace(/\/?$/, "/")}${kind}/${encodeURIComponent(q)}`;
  const r = await fetch(url, { headers: UA, redirect: "follow", signal: AbortSignal.timeout(15000) });
  if (r.status === 404) throw new TargetError(`Not found in the registry (${new URL(base).host})`);
  if (!r.ok) throw new TargetError(`RDAP lookup failed at ${new URL(base).host} (HTTP ${r.status})`);
  return r.json();
}
const vcardName = (e) => e?.vcardArray?.[1]?.find((x) => x[0] === "fn")?.[3];
const rdapEvents = (j) => Object.fromEntries((j.events || []).map((e) => [e.eventAction, e.eventDate]));

const SEC_HEADERS = {
  "strict-transport-security": "Forces HTTPS (HSTS)", "content-security-policy": "Restricts script/content sources (CSP)", "x-frame-options": "Clickjacking protection",
  "x-content-type-options": "Stops MIME sniffing", "referrer-policy": "Controls referrer leakage", "permissions-policy": "Restricts browser features",
  "cross-origin-opener-policy": "Isolates browsing context (COOP)", "cross-origin-resource-policy": "Restricts cross-origin reads (CORP)", "cross-origin-embedder-policy": "Requires CORP/CORS for embeds (COEP)",
};
const LEAKY = ["server", "x-powered-by", "x-aspnet-version", "x-aspnetmvc-version", "x-generator", "via"];

function parseMeta(html) {
  const tags = {}; for (const m of html.matchAll(/<meta\s+[^>]*>/gi)) { const t = m[0]; const k = (t.match(/(?:property|name)\s*=\s*["']([^"']+)["']/i) || [])[1]; const v = (t.match(/content\s*=\s*["']([^"']*)["']/i) || [])[1]; if (k && v !== undefined) tags[k.toLowerCase()] = v; }
  tags.title = (html.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1]?.trim(); tags.canonical = (html.match(/<link[^>]+rel=["']canonical["'][^>]*href=["']([^"']+)/i) || [])[1];
  return tags;
}

const TECH = [["Cloudflare", (h) => h["cf-ray"] || /cloudflare/i.test(h.server || "")], ["nginx", (h) => /nginx/i.test(h.server || "")], ["Apache", (h) => /apache/i.test(h.server || "")], ["Microsoft IIS", (h) => /iis/i.test(h.server || "")], ["LiteSpeed", (h) => /litespeed/i.test(h.server || "")], ["Caddy", (h) => /caddy/i.test(h.server || "")], ["Traefik", (h, b) => /traefik/i.test(h.server || "")],
  ["Vercel", (h) => h["x-vercel-id"]], ["Netlify", (h) => h["x-nf-request-id"]], ["AWS CloudFront", (h) => h["x-amz-cf-id"]], ["Fastly", (h) => h["x-served-by"]?.includes("cache-")], ["Akamai", (h) => h["x-akamai-transformed"]], ["PHP", (h) => /php/i.test(h["x-powered-by"] || "")], ["Express", (h) => /express/i.test(h["x-powered-by"] || "")], ["ASP.NET", (h) => h["x-aspnet-version"] || /asp\.net/i.test(h["x-powered-by"] || "")],
  ["WordPress", (h, b) => /wp-content|wp-includes/i.test(b)], ["Drupal", (h, b) => /drupal/i.test(h["x-generator"] || "") || /sites\/default\/files/.test(b)], ["Joomla", (h, b) => /joomla/i.test(b)], ["Shopify", (h, b) => /cdn\.shopify\.com/.test(b)], ["Wix", (h, b) => /wix\.com|wixstatic/.test(b)], ["Squarespace", (h, b) => /squarespace/i.test(b)], ["Ghost", (h, b) => /ghost/i.test(h["x-ghost-cache-status"] || "") || /content="Ghost/.test(b)],
  ["React", (h, b) => /react(-dom)?(\.production)?(\.min)?\.js|data-reactroot|__NEXT_DATA__/.test(b)], ["Next.js", (h, b) => /__NEXT_DATA__|\/_next\//.test(b) || h["x-nextjs-cache"]], ["Nuxt", (h, b) => /__NUXT__|\/_nuxt\//.test(b)], ["Vue.js", (h, b) => /vue(\.runtime)?(\.min)?\.js|data-v-[0-9a-f]{8}/.test(b)], ["Angular", (h, b) => /ng-version=/.test(b)], ["Svelte/SvelteKit", (h, b) => /__sveltekit|svelte-/.test(b)], ["Astro", (h, b) => /astro-island|\/_astro\//.test(b)],
  ["jQuery", (h, b) => /jquery[.-]?\d?/i.test(b)], ["Bootstrap", (h, b) => /bootstrap(\.min)?\.(css|js)/.test(b)], ["Tailwind CSS", (h, b) => /tailwind/i.test(b)], ["Google Analytics", (h, b) => /googletagmanager\.com\/gtag|google-analytics\.com/.test(b)], ["Google Tag Manager", (h, b) => /googletagmanager\.com\/gtm/.test(b)], ["Plausible", (h, b) => /plausible\.io/.test(b)], ["Matomo", (h, b) => /matomo|piwik/i.test(b)], ["reCAPTCHA", (h, b) => /recaptcha/.test(b)], ["hCaptcha", (h, b) => /hcaptcha/.test(b)], ["Font Awesome", (h, b) => /font-?awesome/i.test(b)], ["Google Fonts", (h, b) => /fonts\.googleapis\.com/.test(b)]];

const WAF = [["Cloudflare", (h) => h["cf-ray"]], ["AWS WAF / CloudFront", (h) => h["x-amz-cf-id"] || h["x-amzn-requestid"]], ["Akamai", (h) => h["x-akamai-transformed"] || /akamai/i.test(h.server || "")], ["Sucuri", (h) => h["x-sucuri-id"] || /sucuri/i.test(h.server || "")], ["Imperva Incapsula", (h) => h["x-iinfo"] || /incap_ses|visid_incap/.test(h["set-cookie"] || "")], ["F5 BIG-IP", (h) => /bigip|f5/i.test(h.server || "") || /BIGipServer/.test(h["set-cookie"] || "")], ["Fastly", (h) => h["x-fastly-request-id"]], ["Azure Front Door", (h) => h["x-azure-ref"]], ["Barracuda", (h) => /barra_counter_session/.test(h["set-cookie"] || "")], ["Wordfence", () => false], ["ModSecurity", (h) => /mod_security|modsecurity/i.test(h.server || "")]];

const PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017];
const DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp", "mandrill", "mxvault", "hostingermail-a", "hostingermail-b", "zoho", "protonmail"];
const DNSBL = ["zen.spamhaus.org", "bl.spamcop.net", "b.barracudacentral.org", "dnsbl.sorbs.net", "psbl.surriel.com"];
const RESOLVERS = { Cloudflare: "1.1.1.1", Google: "8.8.8.8", Quad9: "9.9.9.9", OpenDNS: "208.67.222.222", AdGuard: "94.140.14.14", "Level3/Lumen": "4.2.2.1" };

async function headersOf(t) { const r = await safeFetch(urlOf(t), { maxBytes: 1024 * 1024 }); return r; }

export const serverOps = {
  "dns-records": { name: "DNS Records (all types)", run: async (t) => { const h = hostOf(t); const d = await dnsAll(h);
    if (Object.values(d).every((v) => Array.isArray(v) && !v.length)) return { text: `No DNS records found for ${h} — the name may not exist.`, data: d };
    return { text: dnsText(d), data: d }; } },
  "dns-lookup": { name: "DNS Lookup", args: ["type"], run: async (t, a) => { const h = hostOf(t); const type = String(a.type || "A").toUpperCase(); const map = { A: () => dns.resolve4(h, { ttl: true }), AAAA: () => dns.resolve6(h, { ttl: true }), MX: () => dns.resolveMx(h), NS: () => dns.resolveNs(h), TXT: async () => (await dns.resolveTxt(h)).map((x) => x.join("")), CNAME: () => dns.resolveCname(h), SOA: () => dns.resolveSoa(h), CAA: () => dns.resolveCaa(h), SRV: () => dns.resolveSrv(h), PTR: () => dns.reverse(h), NAPTR: () => dns.resolveNaptr(h) };
    if (!map[type]) throw new TargetError("Unsupported record type"); const v = await tryq(map[type]); return { text: dnsText({ [type]: v }), data: { [type]: v } }; } },
  "dns-propagation": { name: "DNS Propagation Check", args: ["type"], run: async (t, a) => { const h = hostOf(t); const type = String(a.type || "A").toUpperCase(); const out = {};
    await Promise.all(Object.entries(RESOLVERS).map(async ([name, ip]) => { const r = new Resolver({ timeout: 4000, tries: 1 }); r.setServers([ip]); try { const v = type === "TXT" ? (await r.resolveTxt(h)).map((x) => x.join("")) : await r.resolve(h, type); out[name] = v.map((x) => (typeof x === "object" ? JSON.stringify(x) : x)); } catch (e) { out[name] = [`(${e.code || e.message})`]; } }));
    const uniq = new Set(Object.values(out).map((v) => [...v].sort().join("|"))); return { text: Object.entries(out).map(([k, v]) => `${k.padEnd(14)} ${v.join(", ")}`).join("\n") + `\n\n${uniq.size === 1 ? "Consistent across all resolvers" : `${uniq.size} different answers — propagation in progress or geo-DNS`}`, data: out }; } },
  "reverse-dns": { name: "Reverse DNS (PTR) Lookup", run: async (t) => { const ip = String(t).trim(); if (!net.isIP(ip)) throw new TargetError("Enter an IP address"); const v = await tryq(() => dns.reverse(ip)); return { text: Array.isArray(v) && v.length ? v.join("\n") : "No PTR record", data: v }; } },
  "txt-records": { name: "TXT Records", run: async (t) => { const v = await tryq(async () => (await dns.resolveTxt(hostOf(t))).map((x) => x.join(""))); return { text: Array.isArray(v) ? v.join("\n") || "(none)" : v.error, data: v }; } },
  "mail-config": { name: "Email Configuration (MX/SPF/DMARC/DKIM)", run: async (t) => { const d = domainOf(hostOf(t));
    const [mx, txt, dmarc] = await Promise.all([tryq(() => dns.resolveMx(d)), tryq(async () => (await dns.resolveTxt(d)).map((x) => x.join(""))), tryq(async () => (await dns.resolveTxt(`_dmarc.${d}`)).map((x) => x.join("")))]);
    const spf = Array.isArray(txt) ? txt.filter((x) => /^v=spf1/i.test(x)) : []; const dk = {};
    await Promise.all(DKIM_SELECTORS.map(async (s) => { const r = await tryq(async () => (await dns.resolveTxt(`${s}._domainkey.${d}`)).map((x) => x.join(""))); if (Array.isArray(r) && r.length) dk[s] = r[0].slice(0, 120); else { const c = await tryq(() => dns.resolveCname(`${s}._domainkey.${d}`)); if (Array.isArray(c) && c.length) dk[s] = `CNAME → ${c[0]}`; } }));
    const bimi = await tryq(async () => (await dns.resolveTxt(`default._bimi.${d}`)).map((x) => x.join(""))); const mtasts = await tryq(async () => (await dns.resolveTxt(`_mta-sts.${d}`)).map((x) => x.join("")));
    const issues = []; if (!Array.isArray(mx) || !mx.length) issues.push("No MX records"); if (!spf.length) issues.push("No SPF record"); if (spf.length > 1) issues.push("Multiple SPF records (invalid)"); if (spf[0] && /\+all/.test(spf[0])) issues.push("SPF uses +all (allows anyone)");
    const dm = Array.isArray(dmarc) ? dmarc.find((x) => /^v=DMARC1/i.test(x)) : null; if (!dm) issues.push("No DMARC record"); else if (/p=none/i.test(dm)) issues.push("DMARC policy is p=none (monitor only)"); if (!Object.keys(dk).length) issues.push("No DKIM key found at common selectors");
    const data = { mx, spf, dmarc: dm, dkim: dk, bimi, mtaSts: mtasts, issues };
    return { text: `MX:\n${Array.isArray(mx) ? mx.sort((a, b) => a.priority - b.priority).map((m) => `  ${m.priority} ${m.exchange}`).join("\n") || "  (none)" : "  error"}\n\nSPF:\n  ${spf.join("\n  ") || "(none)"}\n\nDMARC:\n  ${dm || "(none)"}\n\nDKIM (common selectors):\n${Object.entries(dk).map(([k, v]) => `  ${k}: ${v}`).join("\n") || "  (none found)"}\n\nBIMI: ${Array.isArray(bimi) && bimi[0] ? bimi[0] : "(none)"}\nMTA-STS: ${Array.isArray(mtasts) && mtasts[0] ? mtasts[0] : "(none)"}\n\nFindings:\n${issues.map((x) => "  ⚠ " + x).join("\n") || "  ✓ No problems found"}`, data }; } },
  "spf-check": { name: "SPF Record Check", run: async (t) => { const d = domainOf(hostOf(t)); const txt = await tryq(async () => (await dns.resolveTxt(d)).map((x) => x.join(""))); const spf = (Array.isArray(txt) ? txt : []).filter((x) => /^v=spf1/i.test(x));
    if (!spf.length) return { text: "No SPF record found", data: null }; const mech = spf[0].split(/\s+/).slice(1); const lookups = mech.filter((m) => /^[+~?-]?(include|a|mx|ptr|exists|redirect)/i.test(m)).length;
    return { text: `Record: ${spf[0]}\n\nMechanisms:\n${mech.map((m) => "  " + m).join("\n")}\n\nDNS-lookup mechanisms: ${lookups} (limit 10)\nAll policy: ${(mech.find((m) => /all$/.test(m)) || "none")}\n${spf.length > 1 ? "⚠ Multiple SPF records — receivers will fail SPF\n" : ""}`, data: { spf, lookups } }; } },
  "dmarc-check": { name: "DMARC Record Check", run: async (t) => { const d = domainOf(hostOf(t)); const v = await tryq(async () => (await dns.resolveTxt(`_dmarc.${d}`)).map((x) => x.join(""))); const rec = Array.isArray(v) ? v.find((x) => /^v=DMARC1/i.test(x)) : null;
    if (!rec) return { text: `No DMARC record at _dmarc.${d}`, data: null }; const tags = Object.fromEntries(rec.split(";").map((x) => x.trim().split("=")).filter((x) => x[0]).map(([k, ...v]) => [k, v.join("=")]));
    return { text: `Record: ${rec}\n\n${kv([["Policy (p)", tags.p], ["Subdomain policy (sp)", tags.sp], ["Percentage (pct)", tags.pct || "100"], ["Aggregate reports (rua)", tags.rua], ["Forensic reports (ruf)", tags.ruf], ["DKIM alignment (adkim)", tags.adkim || "r"], ["SPF alignment (aspf)", tags.aspf || "r"]])}`, data: tags }; } },
  "dkim-check": { name: "DKIM Record Lookup", args: ["selector"], run: async (t, a) => { const d = domainOf(hostOf(t)); const sels = a.selector ? [a.selector] : DKIM_SELECTORS; const out = {};
    await Promise.all(sels.map(async (s) => { const r = await tryq(async () => (await dns.resolveTxt(`${s}._domainkey.${d}`)).map((x) => x.join(""))); if (Array.isArray(r) && r.length) out[s] = r[0]; }));
    return { text: Object.entries(out).map(([k, v]) => `${k}._domainkey.${d}\n  ${v}`).join("\n\n") || "No DKIM records found for the tried selectors", data: out }; } },
  "dnssec": { name: "DNSSEC Validation", run: async (t) => { const d = domainOf(hostOf(t)); const [k, ds, a] = await Promise.all([doh(d, "DNSKEY"), doh(d, "DS"), doh(d, "A")]);
    const data = { dnskey: (k.Answer || []).filter((x) => x.type === 48).length, ds: (ds.Answer || []).filter((x) => x.type === 43).length, authenticated: !!a.AD, status: a.Status };
    return { text: `DNSKEY records: ${data.dnskey}\nDS records (at parent): ${data.ds}\nValidated (AD flag): ${data.authenticated ? "yes" : "no"}\n\n${data.dnskey && data.ds && data.authenticated ? "✓ DNSSEC is enabled and validates" : data.dnskey && !data.ds ? "⚠ Zone is signed but no DS at parent — chain of trust broken" : "✗ DNSSEC not enabled"}`, data }; } },
  "dns-server": { name: "DNS Server / Nameservers", run: async (t) => { const d = domainOf(hostOf(t)); const ns = await tryq(() => dns.resolveNs(d)); if (!Array.isArray(ns)) return { text: "Could not resolve NS", data: ns };
    const rows = await Promise.all(ns.map(async (n) => { const ips = await tryq(() => dns.resolve4(n)); return { ns: n, ips: Array.isArray(ips) ? ips : [] }; })); const soa = await tryq(() => dns.resolveSoa(d));
    return { text: rows.map((r) => `${r.ns.padEnd(32)} ${r.ips.join(", ")}`).join("\n") + (soa && !soa.error && !Array.isArray(soa) ? `\n\nSOA primary: ${soa.nsname}\nSOA admin: ${soa.hostmaster}\nSerial: ${soa.serial}\nRefresh/Retry/Expire/Min: ${soa.refresh}/${soa.retry}/${soa.expire}/${soa.minttl}` : ""), data: { ns: rows, soa } }; } },
  "caa-check": { name: "CAA Record Check", run: async (t) => { const v = await tryq(() => dns.resolveCaa(domainOf(hostOf(t)))); return { text: Array.isArray(v) && v.length ? v.map((x) => Object.entries(x).map(([a, b]) => `${a}=${b}`).join(" ")).join("\n") : "No CAA records — any CA may issue certificates", data: v }; } },
  "get-ip": { name: "IP Info", run: async (t) => { const h = hostOf(t); const ips = await resolvePublic(h).catch(async () => [...(await tryq(() => dns.resolve4(h))), ...(await tryq(() => dns.resolve6(h)))]); return { text: `${h} resolves to:\n${[].concat(ips).map((x) => "  " + x).join("\n")}`, data: ips }; } },
  "ssl": { name: "SSL Certificate Chain", run: async (t) => { const h = hostOf(t); const { chain, info } = await certChain(h); const s = chain.map(certSummary);
    return { text: `Trusted: ${info.authorized ? "yes" : `NO (${info.authorizationError})`}\nProtocol: ${info.protocol}  Cipher: ${info.cipher?.name}  ALPN: ${info.alpn || "none"}\n\n` + s.map((c, i) => `#${i} ${i === 0 ? "Leaf" : i === s.length - 1 ? "Root/top" : "Intermediate"}\n${kv([["Subject", c.subject], ["Issuer", c.issuer], ["Valid from", c.validFrom], ["Valid to", c.validTo], ["Days left", c.daysLeft], ["Key", c.keyBits ? `${c.keyType} ${c.keyBits} bits` : c.keyType], ["SANs", i === 0 ? c.san : undefined], ["SHA-256", c.sha256]])}`).join("\n\n"), data: { info, chain: s } }; } },
  "tls-connection": { name: "TLS Connection", run: async (t) => { const { info } = await certChain(hostOf(t)); return { text: kv([["Negotiated protocol", info.protocol], ["Cipher suite", info.cipher?.name], ["Cipher standard name", info.cipher?.standardName], ["ALPN", info.alpn || "none"], ["Key exchange", info.ephemeral ? `${info.ephemeral.type} ${info.ephemeral.name || ""} ${info.ephemeral.size || ""}` : "n/a"], ["Certificate trusted", info.authorized ? "yes" : info.authorizationError]]), data: info }; } },
  "tls-versions": { name: "TLS Protocol Versions", run: async (t) => { const h = hostOf(t); const r = await Promise.all(["TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3"].map((v) => tlsVersion(h, v)));
    return { text: r.map((x) => `${x.version.padEnd(8)} ${x.supported ? "✓ supported" + (x.cipher ? ` (${x.cipher})` : "") : "✗ " + x.error}`).join("\n") + `\n\n${r.slice(0, 2).some((x) => x.supported) ? "⚠ Legacy TLS 1.0/1.1 enabled — disable it" : "✓ No legacy TLS versions"}`, data: r }; } },
  "headers": { name: "HTTP Headers", run: async (t) => { const r = await headersOf(t); return { text: `HTTP ${r.status} ${r.statusText}  (${r.timeMs} ms, ${r.ip})\n\n` + Object.entries(r.headers).map(([k, v]) => `${k}: ${[].concat(v).join(", ")}`).join("\n"), data: { status: r.status, headers: r.headers } }; } },
  "http-security": { name: "HTTP Security Headers", run: async (t) => { const r = await headersOf(t); const h = r.headers; let score = 0; const rows = Object.entries(SEC_HEADERS).map(([k, d]) => { const ok = !!h[k]; if (ok) score++; return `${ok ? "✓" : "✗"} ${k.padEnd(30)} ${ok ? String(h[k]).slice(0, 90) : "missing — " + d}`; });
    const leaks = LEAKY.filter((k) => h[k]).map((k) => `⚠ ${k}: ${h[k]} (version/technology disclosure)`); const grade = ["F", "F", "E", "D", "C", "C", "B", "B", "A", "A+"][score];
    return { text: `Grade: ${grade} (${score}/${Object.keys(SEC_HEADERS).length})\n\n${rows.join("\n")}${leaks.length ? "\n\n" + leaks.join("\n") : ""}`, data: { score, grade, present: Object.keys(SEC_HEADERS).filter((k) => h[k]) } }; } },
  "hsts": { name: "HSTS Check", run: async (t) => { const r = await headersOf(t); const v = r.headers["strict-transport-security"]; if (!v) return { text: "✗ No Strict-Transport-Security header", data: null };
    const age = Number((v.match(/max-age=(\d+)/i) || [])[1] || 0); const sub = /includesubdomains/i.test(v), pre = /preload/i.test(v);
    return { text: `Header: ${v}\nmax-age: ${age} s (${(age / 86400).toFixed(0)} days)\nincludeSubDomains: ${sub}\npreload: ${pre}\n\n${age >= 31536000 && sub && pre ? "✓ Eligible for the HSTS preload list" : "⚠ Preload requires max-age ≥ 31536000, includeSubDomains and preload"}`, data: { age, sub, pre } }; } },
  "cookies": { name: "Cookies", run: async (t) => { const r = await headersOf(t); const c = [].concat(r.headers["set-cookie"] || []); if (!c.length) return { text: "No cookies set on the first response", data: [] };
    const rows = c.map((s) => { const [nv, ...attrs] = s.split(";").map((x) => x.trim()); const a = attrs.map((x) => x.toLowerCase()); return { name: nv.split("=")[0], secure: a.includes("secure"), httpOnly: a.includes("httponly"), sameSite: (attrs.find((x) => /^samesite/i.test(x)) || "").split("=")[1] || "not set", raw: s.slice(0, 200) }; });
    return { text: rows.map((x) => `${x.name}\n  Secure: ${x.secure ? "✓" : "✗"}  HttpOnly: ${x.httpOnly ? "✓" : "✗"}  SameSite: ${x.sameSite}`).join("\n"), data: rows }; } },
  "redirects": { name: "Redirect Chain", run: async (t) => { const r = await safeFetch(urlOf(t).replace(/^https:/, String(t).startsWith("https") ? "https:" : "http:")); return { text: r.hops.map((h, i) => `${i + 1}. ${h.status}  ${h.url}${h.location ? `\n     → ${h.location}` : ""}`).join("\n"), data: r.hops }; } },
  "status": { name: "Server Status / Response Time", run: async (t) => { const r = await safeFetch(urlOf(t), { maxBytes: 512 * 1024 }); return { text: kv([["Status", `${r.status} ${r.statusText}`], ["Up", r.status < 500 ? "yes" : "no (server error)"], ["Response time", `${r.timeMs} ms`], ["Final URL", r.url], ["Server IP", r.ip], ["Body size", `${r.body.length} bytes${r.truncated ? "+" : ""}`]]), data: { status: r.status, timeMs: r.timeMs } }; } },
  "robots-txt": { name: "Crawl Rules (robots.txt)", run: async (t) => { const { url } = normalizeHost(urlOf(t)); const r = await safeFetch(`${url.protocol}//${url.host}/robots.txt`); return { text: r.status === 200 ? r.body.slice(0, 20000) : `No robots.txt (HTTP ${r.status})`, data: { status: r.status } }; } },
  "security-txt": { name: "security.txt", run: async (t) => { const { url } = normalizeHost(urlOf(t)); for (const p of ["/.well-known/security.txt", "/security.txt"]) { const r = await safeFetch(`${url.protocol}//${url.host}${p}`).catch(() => null); if (r?.status === 200 && /contact:/i.test(r.body)) return { text: `Found at ${p}\n\n${r.body.slice(0, 8000)}`, data: { path: p } }; } return { text: "✗ No security.txt found (RFC 9116)", data: null }; } },
  "sitemap": { name: "Listed Pages (sitemap.xml)", run: async (t) => { const { url } = normalizeHost(urlOf(t)); const base = `${url.protocol}//${url.host}`; let src = `${base}/sitemap.xml`;
    const robots = await safeFetch(`${base}/robots.txt`).catch(() => null); const fromRobots = robots?.status === 200 ? (robots.body.match(/^sitemap:\s*(\S+)/im) || [])[1] : null; if (fromRobots) src = fromRobots;
    const r = await safeFetch(src); if (r.status !== 200) return { text: `No sitemap at ${src} (HTTP ${r.status})`, data: null }; const locs = [...r.body.matchAll(/<loc>\s*([^<]+?)\s*<\/loc>/g)].map((m) => m[1]);
    return { text: `Source: ${src}\n${locs.length} URL(s)\n\n${locs.slice(0, 500).join("\n")}`, data: locs }; } },
  "social-tags": { name: "Social Tags / Meta", run: async (t) => { const r = await safeFetch(urlOf(t)); const m = parseMeta(r.body); return { text: Object.entries(m).filter(([, v]) => v).map(([k, v]) => `${k.padEnd(24)} ${String(v).slice(0, 200)}`).join("\n") || "No meta tags", data: m }; } },
  "linked-pages": { name: "Linked Pages", run: async (t) => { const r = await safeFetch(urlOf(t)); const base = new URL(r.url); const int = new Set(), ext = new Set();
    for (const m of r.body.matchAll(/<a\s[^>]*href\s*=\s*["']([^"'#]+)/gi)) { try { const u = new URL(m[1], base); if (!/^https?:$/.test(u.protocol)) continue; (u.hostname === base.hostname ? int : ext).add(u.href); } catch { /* skip */ } }
    return { text: `Internal (${int.size}):\n${[...int].slice(0, 300).join("\n")}\n\nExternal (${ext.size}):\n${[...ext].slice(0, 300).join("\n")}`, data: { internal: [...int], external: [...ext] } }; } },
  "tech-stack": { name: "Tech Stack Detection", run: async (t) => { const r = await safeFetch(urlOf(t)); const h = r.headers; const found = TECH.filter(([, f]) => { try { return f(h, r.body); } catch { return false; } }).map(([n]) => n);
    return { text: found.length ? found.map((x) => "• " + x).join("\n") + `\n\nServer header: ${h.server || "(hidden)"}\nX-Powered-By: ${h["x-powered-by"] || "(hidden)"}` : "No known technologies detected from headers/HTML", data: found }; } },
  "firewall": { name: "Firewall / WAF Detection", run: async (t) => { const r = await safeFetch(urlOf(t)); const h = { ...r.headers, "set-cookie": [].concat(r.headers["set-cookie"] || []).join(";") }; const found = WAF.filter(([, f]) => f(h)).map(([n]) => n);
    return { text: found.length ? `Detected: ${found.join(", ")}` : "No WAF/CDN signature detected (it may still exist)", data: found }; } },
  "ports": { name: "Open Ports (common)", run: async (t) => { const h = hostOf(t); const ips = await resolvePublic(h); const ip = ips.find(net.isIPv4) || ips[0]; const r = await Promise.all(PORTS.map((p) => tcpProbe(ip, p)));
    return { text: `Target ${h} (${ip})\n\nOpen:\n${r.filter((x) => x.open).map((x) => `  ${String(x.port).padStart(5)}  open (${x.ms} ms)`).join("\n") || "  none"}\n\nClosed/filtered: ${r.filter((x) => !x.open).map((x) => x.port).join(", ")}`, data: r }; } },
  "port-check": { name: "TCP Port Check", args: ["port"], run: async (t, a) => { const h = hostOf(t); const port = Number(a.port); if (!(port > 0 && port < 65536)) throw new TargetError("Port must be 1–65535"); const ips = await resolvePublic(h); const r = await tcpProbe(ips.find(net.isIPv4) || ips[0], port, 5000); return { text: `${h}:${port} is ${r.open ? `OPEN (${r.ms} ms)` : `closed/filtered (${r.reason})`}`, data: r }; } },
  "whois": { name: "Domain Registration (RDAP/WHOIS)", run: async (t) => { const d = domainOf(hostOf(t)); const j = await rdap("domain", d); const ev = rdapEvents(j); const reg = (j.entities || []).find((e) => e.roles?.includes("registrar"));
    return { text: kv([["Domain", j.ldhName], ["Registrar", vcardName(reg)], ["Registered", ev.registration], ["Expires", ev.expiration], ["Last changed", ev["last changed"]], ["Status", j.status], ["Nameservers", (j.nameservers || []).map((n) => n.ldhName)], ["DNSSEC", j.secureDNS?.delegationSigned ? "signed" : "unsigned"]]), data: { ldhName: j.ldhName, events: ev, status: j.status, registrar: vcardName(reg) } }; } },
  "ip-whois": { name: "IP / ASN Owner (RDAP)", run: async (t) => { const s = String(t).trim(); const ip = net.isIP(s) ? s : (await resolvePublic(hostOf(s)))[0]; const j = await rdap("ip", ip); const org = (j.entities || []).map(vcardName).filter(Boolean);
    return { text: kv([["IP", ip], ["Network", j.name], ["Range", j.startAddress && `${j.startAddress} – ${j.endAddress}`], ["CIDR", (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`)], ["Country", j.country], ["Type", j.type], ["Organisation", org], ["Registry", j.port43]]), data: { ip, name: j.name, country: j.country, org } }; } },
  "asn-lookup": { name: "ASN Lookup", run: async (t) => { const q = String(t).trim().replace(/^as/i, ""); if (!/^\d+$/.test(q)) throw new TargetError("Enter an AS number, e.g. AS13335"); const j = await rdap("autnum", q); return { text: kv([["ASN", `AS${j.startAutnum}`], ["Name", j.name], ["Country", j.country], ["Organisation", (j.entities || []).map(vcardName).filter(Boolean)], ["Registered", rdapEvents(j).registration]]), data: { name: j.name } }; } },
  "blocklists": { name: "IP Blocklist (DNSBL) Check", run: async (t) => { const s = String(t).trim(); const ip = net.isIP(s) ? s : (await resolvePublic(hostOf(s))).find(net.isIPv4); if (!net.isIPv4(ip)) throw new TargetError("DNSBL checks need an IPv4 address"); const rev = ip.split(".").reverse().join(".");
    const r = await Promise.all(DNSBL.map(async (z) => { const v = await tryq(() => dns.resolve4(`${rev}.${z}`)); return { list: z, listed: Array.isArray(v) && v.length > 0 && !v.some((x) => x.startsWith("127.255.255")), answer: Array.isArray(v) ? v.join(",") : "" }; }));
    return { text: `IP ${ip}\n\n${r.map((x) => `${x.listed ? "⚠ LISTED" : "✓ clean "}  ${x.list}${x.answer ? "  (" + x.answer + ")" : ""}`).join("\n")}`, data: r }; } },
  "subdomains": { name: "Subdomains (Certificate Transparency)", run: async (t) => { const d = domainOf(hostOf(t)); const r = await fetch(`https://crt.sh/?q=%25.${encodeURIComponent(d)}&output=json`, { signal: AbortSignal.timeout(25000) }); if (!r.ok) throw new TargetError(`crt.sh returned HTTP ${r.status} — try again shortly`);
    const names = new Set(); for (const e of await r.json()) for (const n of String(e.name_value).split("\n")) if (n.endsWith(d) && !n.startsWith("*")) names.add(n.toLowerCase());
    const list = [...names].sort(); return { text: `${list.length} name(s) seen in CT logs\n\n${list.join("\n")}`, data: list }; } },
  "archives": { name: "Archive History (Wayback Machine)", run: async (t) => { const d = hostOf(t); const r = await fetch(`https://archive.org/wayback/available?url=${encodeURIComponent(d)}`, { signal: AbortSignal.timeout(12000) }).then((x) => x.json()); const s = r.archived_snapshots?.closest;
    const cdx = await fetch(`https://web.archive.org/cdx/search/cdx?url=${encodeURIComponent(d)}&output=json&fl=timestamp&collapse=timestamp:4&limit=200`, { signal: AbortSignal.timeout(15000) }).then((x) => x.json()).catch(() => []);
    const years = cdx.slice(1).map((x) => x[0].slice(0, 4)); return { text: s ? `Latest snapshot: ${s.timestamp}\n${s.url}\n\nYears with snapshots: ${years.join(", ") || "n/a"}\nFirst seen: ${years[0] || "n/a"}` : "No archived snapshots", data: { latest: s, years } }; } },
  "server-info": { name: "Server Info", run: async (t) => { const h = hostOf(t); const ips = await resolvePublic(h); const r = await safeRequest(urlOf(t)).catch(() => null); let owner = null; try { const j = await rdap("ip", ips[0]); owner = { network: j.name, country: j.country, org: (j.entities || []).map(vcardName).filter(Boolean) }; } catch { /* optional */ }
    const ptr = await tryq(() => dns.reverse(ips[0]));
    return { text: kv([["Hostname", h], ["IP addresses", ips], ["Reverse DNS", Array.isArray(ptr) ? ptr : ""], ["Server header", r?.headers?.server], ["Powered by", r?.headers?.["x-powered-by"]], ["Network", owner?.network], ["Country", owner?.country], ["Owner", owner?.org]]), data: { ips, owner } }; } },
  "hosts": { name: "Associated Hosts (shared IP)", run: async (t) => { const h = hostOf(t); const { chain } = await certChain(h); const san = (chain[0]?.subjectaltname || "").split(",").map((x) => x.trim().replace(/^DNS:/, "")).filter(Boolean); return { text: `Names on the same certificate (${san.length}):\n${san.join("\n")}`, data: san }; } },
};
export { isPublicIp };
