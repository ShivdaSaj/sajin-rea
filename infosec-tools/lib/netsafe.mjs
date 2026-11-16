// Outbound-request guard: every server-side check resolves the target itself and
// refuses private, loopback, link-local, CGNAT, multicast and reserved addresses,
// then connects to the vetted IP only (no DNS rebinding between check and use).
import { Resolver } from "node:dns/promises";
import net from "node:net";
import http from "node:http";
import https from "node:https";

const V4_BLOCK = [["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12], ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.88.99.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24], ["224.0.0.0", 4], ["240.0.0.0", 4]];
const v4int = (ip) => ip.split(".").reduce((a, b) => ((a << 8) | +b) >>> 0, 0);
const BLOCKS = V4_BLOCK.map(([n, b]) => [v4int(n), b === 0 ? 0 : (0xffffffff << (32 - b)) >>> 0]);

// Query public resolvers directly. The host's own resolver can answer its hostname with a
// loopback address (systemd-resolved does this), which would give wrong recon results.
export const publicResolver = new Resolver({ timeout: 4000, tries: 2 });
publicResolver.setServers(["1.1.1.1", "8.8.8.8", "9.9.9.9", "2606:4700:4700::1111"]);

export function isPublicIp(ip) {
  if (net.isIPv4(ip)) { const n = v4int(ip); return !BLOCKS.some(([b, m]) => ((n & m) >>> 0) === b); }
  if (net.isIPv6(ip)) {
    const l = ip.toLowerCase();
    if (l === "::" || l === "::1") return false;
    const mapped = l.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/); if (mapped) return isPublicIp(mapped[1]);
    if (/^(fe[89ab]|fc|fd|ff)/.test(l)) return false; // link-local, ULA, multicast
    if (l.startsWith("2001:db8") || l.startsWith("64:ff9b") || l.startsWith("100::")) return false;
    return /^[23]/.test(l); // global unicast 2000::/3 only
  }
  return false;
}

export class TargetError extends Error { constructor(msg) { super(msg); this.status = 400; } }

export function normalizeHost(input) {
  let s = String(input || "").trim();
  if (!s) throw new TargetError("Enter a domain, URL or IP address");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(s)) s = "http://" + s;
  let u; try { u = new URL(s); } catch { throw new TargetError("That does not look like a valid domain or URL"); }
  const host = u.hostname.replace(/^\[|\]$/g, "").replace(/\.$/, "").toLowerCase();
  if (!host || host.length > 253) throw new TargetError("Invalid hostname");
  if (!net.isIP(host) && !/^[a-z0-9_]([a-z0-9_-]{0,62})(\.[a-z0-9_]([a-z0-9-]{0,62}))*$/i.test(host)) throw new TargetError("Invalid hostname");
  if (/^(localhost|.*\.local|.*\.internal|.*\.localhost|.*\.lan|.*\.home\.arpa)$/.test(host)) throw new TargetError("Internal hostnames are not allowed");
  return { host, url: u };
}

export async function resolvePublic(host) {
  let ips;
  if (net.isIP(host)) ips = [host];
  else {
    const res = await Promise.allSettled([publicResolver.resolve4(host), publicResolver.resolve6(host)]);
    ips = res.flatMap((r) => (r.status === "fulfilled" ? r.value : []));
  }
  if (!ips.length) throw new TargetError(`Could not resolve ${host}`);
  const bad = ips.filter((ip) => !isPublicIp(ip));
  if (bad.length) throw new TargetError(`${host} resolves to a non-public address (${bad[0]}); refusing to connect`);
  return ips;
}

// Fetch one URL without following redirects. Body is capped (default 2 MiB).
export async function safeRequest(urlString, { method = "GET", headers = {}, timeout = 10000, maxBytes = 2 * 1024 * 1024 } = {}) {
  const { url, host } = normalizeHost(urlString);
  if (!/^https?:$/.test(url.protocol)) throw new TargetError("Only http and https URLs are allowed");
  const port = Number(url.port || (url.protocol === "https:" ? 443 : 80));
  if (![80, 443, 8080, 8443].includes(port)) throw new TargetError("Only ports 80, 443, 8080 and 8443 are allowed");
  const ips = await resolvePublic(host);
  const ip = ips.find((x) => net.isIPv4(x)) || ips[0];
  const lib = url.protocol === "https:" ? https : http;
  const started = Date.now();
  return new Promise((resolve, reject) => {
    const req = lib.request({
      host: ip, port, method, path: url.pathname + url.search, servername: net.isIP(host) ? undefined : host,
      headers: { Host: url.host, "User-Agent": "InfosecTools/1.0 (+https://infosectools.sajinshivdas.online)", Accept: "*/*", ...headers },
      timeout, rejectUnauthorized: false, lookup: undefined,
    }, (res) => {
      const chunks = []; let size = 0;
      res.on("data", (c) => { size += c.length; if (size <= maxBytes) chunks.push(c); else res.destroy(); });
      res.on("close", () => resolve({ status: res.statusCode, statusText: res.statusMessage, headers: res.headers, rawHeaders: res.rawHeaders, body: Buffer.concat(chunks).toString("utf8"), truncated: size > maxBytes, ip, timeMs: Date.now() - started, url: url.href, tls: res.socket?.getPeerCertificate ? { authorized: res.socket.authorized, error: res.socket.authorizationError } : null }));
    });
    req.on("timeout", () => req.destroy(new Error(`Timed out after ${timeout} ms`)));
    req.on("error", reject);
    req.end();
  });
}

// Follow redirects manually so every hop passes the guard.
export async function safeFetch(urlString, opts = {}) {
  const hops = []; let current = urlString;
  for (let i = 0; i < (opts.maxRedirects ?? 8); i++) {
    const r = await safeRequest(current, opts); hops.push({ url: r.url, status: r.status, location: r.headers.location });
    if (r.status >= 300 && r.status < 400 && r.headers.location) { current = new URL(r.headers.location, r.url).href; continue; }
    return { ...r, hops };
  }
  throw new TargetError("Too many redirects");
}
