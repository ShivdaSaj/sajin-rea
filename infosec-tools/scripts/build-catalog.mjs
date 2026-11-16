// Build seed/catalog.json from the four REA-derived inventories plus the native op mapping.
// Run: node scripts/build-catalog.mjs
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { registry } from "../public/ops/index.js";
import { serverOps } from "../lib/server-ops.mjs";

const root = path.join(path.dirname(fileURLToPath(import.meta.url)), "..");
const seed = (f) => JSON.parse(fs.readFileSync(path.join(root, "seed", f), "utf8"));

// source tool id -> native op ("op" or "op?arg=value&..." to preset arguments; "server:" prefix = server-side op)
const MAP = {
  ittools: {
    "token-generator": "token", "hash-text": "hash-all", "uuid-generator": "uuid", "ulid-generator": "ulid", "encryption": "aes-encrypt", "hmac-generator": "hmac",
    "rsa-key-pair-generator": "rsa-keygen", "password-strength-analyser": "password-strength", "date-converter": "unix-timestamp", "base-converter": "base-convert",
    "roman-numeral-converter": "roman", "base64-string-converter": "base64-encode", "color-converter": "color-convert", "case-converter": "case-convert", "text-to-nato-alphabet": "nato-alphabet",
    "text-to-binary": "binary-encode", "text-to-unicode": "unicode-escape", "json-to-yaml-converter": "json-to-yaml", "list-converter": "list-convert", "json-to-xml": "json-to-xml",
    "markdown-to-html": "markdown-to-html", "url-encoder": "url-encode", "html-entities": "html-encode", "url-parser": "url-parse", "basic-auth-generator": "basic-auth", "otp-generator": "otp",
    "jwt-parser": "jwt-decode", "slugify-string": "slugify", "user-agent-parser": "user-agent", "json-prettify": "json-format", "json-minify": "json-minify", "json-to-csv": "json-to-csv",
    "chmod-calculator": "chmod", "xml-formatter": "xml-format", "regex-tester": "regex-tester", "ipv4-subnet-calculator": "subnet-calc", "ipv4-address-converter": "ip-convert",
    "ipv4-range-expander": "range-to-cidr", "mac-address-generator": "mac-generate", "ipv6-ula-generator": "ipv6-ula", "percentage-calculator": "percentage", "temperature-converter": "temperature",
    "lorem-ipsum-generator": "lorem-ipsum", "text-statistics": "text-stats", "string-obfuscator": "string-obfuscate", "text-diff": "text-diff", "numeronym-generator": "numeronym",
  },
  "networking-toolbox": {
    "subnetting--ipv4-subnet-calculator": "subnet-calc", "subnetting--ipv6-subnet-calculator": "ipv6-subnet", "subnetting--vlsm-calculator": "vlsm", "subnetting--supernet-calculator": "cidr-summarize", "subnetting--planner": "vlsm",
    "cidr--mask-converter--cidr-to-subnet-mask": "cidr-to-mask", "cidr--mask-converter--subnet-mask-to-cidr": "mask-to-cidr", "cidr--range-to-cidr": "range-to-cidr", "cidr--summarize": "cidr-summarize",
    "cidr--split": "cidr-split", "cidr--next-available": "cidr-next", "cidr--gaps": "cidr-gaps", "cidr--deaggregate": "cidr-deaggregate", "cidr--compare": "cidr-compare", "cidr--allocator": "vlsm",
    "cidr--alignment": "cidr-alignment", "cidr--wildcard-mask": "wildcard-mask", "cidr--set-operations--diff": "cidr-diff", "cidr--set-operations--overlap": "cidr-overlap", "cidr--set-operations--contains": "cidr-contains",
    "ip-address-convertor--representations": "ip-convert", "ip-address-convertor--random": "random-ip", "ip-address-convertor--validator": "ip-validate", "ip-address-convertor--enumerate": "cidr-to-range",
    "ip-address-convertor--notation--ipv6-expand": "ipv6-expand", "ip-address-convertor--notation--ipv6-compress": "ipv6-compress", "ip-address-convertor--notation--normalize": "ipv6-compress",
    "ip-address-convertor--families--ipv4-to-ipv6": "ip-convert", "ip-address-convertor--eui64": "eui64", "ip-address-convertor--ula-generator": "ipv6-ula", "ip-address-convertor--mac-address": "mac-format",
    "dns--generators--ptr-generator": "reverse-dns-name", "dns--reverse--ptr-generator": "reverse-dns-name", "dns--generators--idn-punycode": "punycode-encode", "dns--label-normalizer": "punycode-encode",
    "diagnostics--dns--lookup": "server:dns-lookup", "diagnostics--dns--reverse-lookup": "server:reverse-dns", "diagnostics--dns--propagation": "server:dns-propagation", "diagnostics--dns--spf-evaluator": "server:spf-check",
    "diagnostics--dns--dmarc-check": "server:dmarc-check", "diagnostics--dns--caa-effective": "server:caa-check", "diagnostics--dns--ns-soa-check": "server:dns-server", "diagnostics--dns--dnssec-adflag": "server:dnssec",
    "diagnostics--dns--dnssec-validation-chain": "server:dnssec", "diagnostics--dns--blacklist-checker": "server:blocklists", "diagnostics--dns--soa-serial": "server:dns-server",
    "diagnostics--http--headers": "server:headers", "diagnostics--http--redirect-trace": "server:redirects", "diagnostics--http--security": "server:http-security", "diagnostics--http--perf": "server:status",
    "diagnostics--http--cookie-security": "server:cookies", "diagnostics--tls--certificate": "server:ssl", "diagnostics--tls--versions": "server:tls-versions", "diagnostics--tls--alpn": "server:tls-connection",
    "diagnostics--tls--handshake-analyzer": "server:tls-connection", "diagnostics--tls--ct-log-search": "server:subdomains", "diagnostics--network--tcp-port-check": "server:port-check",
    "diagnostics--network--http-ping": "server:status", "diagnostics--network--asn-geo-lookup": "server:ip-whois", "diagnostics--email--mx-health": "server:mail-config", "diagnostics--email--spf-check": "server:spf-check",
    "diagnostics--email--dmarc-check": "server:dmarc-check", "diagnostics--rdap--domain": "server:whois", "diagnostics--rdap--ip": "server:ip-whois", "diagnostics--rdap--asn": "server:asn-lookup",
    "reference--ports": "port-reference",
  },
  webcheck: {
    "get-ip": "server:get-ip", ssl: "server:ssl", dns: "server:dns-records", cookies: "server:cookies", "robots-txt": "server:robots-txt", headers: "server:headers", location: "server:server-info",
    hosts: "server:hosts", redirects: "server:redirects", "txt-records": "server:txt-records", status: "server:status", ports: "server:ports", "server-info": "server:server-info",
    domain: "server:whois", whois: "server:whois", dnssec: "server:dnssec", hsts: "server:hsts", "dns-server": "server:dns-server", "tech-stack": "server:tech-stack", sitemap: "server:sitemap",
    "security-txt": "server:security-txt", "linked-pages": "server:linked-pages", "social-tags": "server:social-tags", "mail-config": "server:mail-config", firewall: "server:firewall",
    "http-security": "server:http-security", archives: "server:archives", "block-lists": "server:blocklists", "tls-connection": "server:tls-connection", "tls-security-audit": "server:tls-versions",
    "tls-client-compat": "server:tls-versions", subdomains: "server:subdomains",
  },
  cyberchef: {
    "To Base64": "base64-encode", "From Base64": "base64-decode", "To Base32": "base32-encode", "From Base32": "base32-decode", "To Base58": "base58-encode", "From Base58": "base58-decode",
    "To Hex": "hex-encode", "From Hex": "hex-decode", "To Binary": "binary-encode", "From Binary": "binary-decode", "To Octal": "octal-encode", "From Octal": "octal-decode",
    "To Decimal": "decimal-encode", "From Decimal": "decimal-decode", "To Charcode": "charcode-encode", "From Charcode": "charcode-decode", "URL Encode": "url-encode", "URL Decode": "url-decode",
    "To HTML Entity": "html-encode", "From HTML Entity": "html-decode", "Escape Unicode Characters": "unicode-escape", "Unescape Unicode Characters": "unicode-unescape", "Escape string": "unicode-escape",
    "Unescape string": "unicode-unescape", "To Quoted Printable": "quoted-printable-encode", "From Quoted Printable": "quoted-printable-decode", "To Punycode": "punycode-encode",
    "ROT13": "rot13", "ROT47": "rot47", "Atbash Cipher": "atbash", "Vigenère Encode": "vigenere-encode", "Vigenère Decode": "vigenere-decode", "Affine Cipher Encode": "affine-encode",
    "Affine Cipher Decode": "affine-decode", "To Morse Code": "morse-encode", "From Morse Code": "morse-decode", "A1Z26 Cipher Encode": "a1z26-encode", "A1Z26 Cipher Decode": "a1z26-decode",
    "Bacon Cipher Encode": "bacon-encode", "Bacon Cipher Decode": "bacon-decode", "XOR": "xor", "Reverse": "reverse", "AES Encrypt": "aes-encrypt", "AES Decrypt": "aes-decrypt",
    "Derive PBKDF2 key": "pbkdf2", "Generate RSA Key Pair": "rsa-keygen", "JWT Decode": "jwt-decode", "JWT Sign": "jwt-sign", "JWT Verify": "jwt-verify", "Generate TOTP": "otp",
    "MD5": "md5", "SHA1": "sha1", "SHA2": "sha256", "HMAC": "hmac", "CRC-32 Checksum": "crc32", "Adler-32 Checksum": "adler32", "Generate all hashes": "hash-all", "Analyse hash": "hash-identify",
    "Luhn Checksum": "luhn-check", "Fletcher-32 Checksum": null, "Generate UUID": "uuid", "Pseudo-Random Number Generator": "random-bytes", "Pseudo-Random Integer Generator": "random-number",
    "To Upper case": "case-convert?case=UPPERCASE", "To Lower case": "case-convert?case=lowercase", "To Snake case": "case-convert?case=snake_case", "To Camel case": "case-convert?case=camelCase",
    "To Kebab case": "case-convert?case=kebab-case", "Swap case": "case-convert?case=aLtErNaTiNg", "Alternating Caps": "case-convert?case=aLtErNaTiNg", "Sort": "sort-lines", "Unique": "unique-lines",
    "Remove whitespace": "remove-whitespace", "Find / Replace": "find-replace", "Regular expression": "regex-tester", "Count occurrences": "count-occurrences", "Head": "head-tail?which=Head",
    "Tail": "head-tail?which=Tail", "Add line numbers": "add-line-numbers", "Remove line numbers": "remove-line-numbers", "Diff": "text-diff", "Split": "split-join", "Strip HTML tags": "html-strip",
    "Escape Unicode": "unicode-escape", "Frequency distribution": "frequency-analysis", "Entropy": "entropy", "Chi Square": null, "Text to NATO Alphabet": "nato-alphabet",
    "JSON Beautify": "json-format", "JSON Minify": "json-minify", "JSON to CSV": "json-to-csv", "CSV to JSON": "csv-to-json", "XML Beautify": "xml-format", "To Unix Timestamp": "unix-timestamp",
    "From Unix Timestamp": "unix-timestamp", "Parse URI": "url-parse", "Parse User Agent": "user-agent", "Parse colour code": "color-convert", "Parse UNIX file permissions": "chmod",
    "Change IP format": "ip-convert", "Parse IP range": "cidr-to-range", "Group IP addresses": "ip-sort", "Parse IPv6 address": "ip-convert", "Parse IPv4 header": null,
    "Defang URL": "defang-url", "Fang URL": "fang-url", "Defang IP Addresses": "defang-url", "Extract URLs": "extract-urls", "Extract email addresses": "extract-emails",
    "Extract IP addresses": "extract-ipv4", "Extract domains": "extract-domains", "Extract MAC addresses": "extract-mac", "Extract hashes": "extract-hashes", "Extract file paths": "extract-file-paths",
    "Extract dates": "extract-dates", "Convert data units": "byte-convert", "Convert distance": null, "DNS over HTTPS": "server:dns-lookup",
  },
};

// Web-Check ships one flat list; group its checks so the tab is navigable.
const WEBCHECK_GROUPS = {
  "DNS & Domain": ["dns", "txt-records", "dnssec", "dns-server", "domain", "whois", "subdomains"],
  "TLS & Certificates": ["ssl", "tls-connection", "tls-security-audit", "tls-client-compat", "hsts"],
  "HTTP & Security": ["headers", "http-security", "cookies", "redirects", "firewall", "security-txt", "status"],
  "Infrastructure": ["get-ip", "location", "server-info", "hosts", "ports", "trace-route", "carbon"],
  "Content & SEO": ["robots-txt", "sitemap", "linked-pages", "social-tags", "tech-stack", "quality", "screenshot", "archives", "rank"],
  "Email": ["mail-config"],
  "Threat Intelligence": ["vulnerabilities", "block-lists", "threats"],
};
const webcheckGroup = (id) => Object.entries(WEBCHECK_GROUPS).find(([, ids]) => ids.includes(id))?.[0] || "Other checks";
const ICON = { ittools: "wrench", cyberchef: "flask", webcheck: "radar", "networking-toolbox": "network" };
const TABS = [
  { id: "it-utilities", source: "ittools", name: "IT Utilities", description: "Everyday developer & sysadmin utilities: generators, converters, formatters and calculators.", sourceUrl: "https://ittools.sajinshivdas.online", link: (t) => `https://ittools.sajinshivdas.online${t.path}` },
  { id: "cipher-lab", source: "cyberchef", name: "Cipher Lab", description: "Encode, decode, encrypt, hash and analyse data — the cyber Swiss-army knife, with chainable recipes.", sourceUrl: "https://cyberchef.sajinshivdas.online", link: (t) => `https://cyberchef.sajinshivdas.online/#recipe=${encodeURIComponent(t.name.replace(/ /g, "_"))}()` },
  { id: "web-recon", source: "webcheck", name: "Web Recon", description: "Website intelligence and OSINT: DNS, TLS, headers, mail security, technology and exposure checks.", sourceUrl: "https://webcheck.sajinshivdas.online", link: () => "https://webcheck.sajinshivdas.online/check" },
  { id: "network-toolkit", source: "networking-toolbox", name: "Network Toolkit", description: "Subnetting, CIDR, IPv6, DNS, DHCP and live network diagnostics for network engineers.", sourceUrl: "https://networking-toolbox.sajinshivdas.online", link: (t) => `https://networking-toolbox.sajinshivdas.online${t.path}` },
];

const missing = [];
function nativeOf(spec) {
  if (!spec) return null;
  const [key, q] = spec.split("?"); const server = key.startsWith("server:"); const op = server ? key.slice(7) : key;
  if (!(server ? serverOps[op] : registry[op])) { missing.push(spec); return null; }
  return { op, mode: server ? "server" : "client", preset: q ? Object.fromEntries(new URLSearchParams(q)) : undefined };
}

const catalog = { version: 1, generatedAt: new Date().toISOString(), title: "Infosec Tools", tabs: [] };
for (const tab of TABS) {
  const src = seed(`${tab.source}.json`); const seen = new Set(); const tools = [];
  const cats = [...src.categories, ...(src.uncategorized?.length ? [{ name: "Other", tools: src.uncategorized }] : [])];
  for (const cat of cats) for (const t of cat.tools) {
    if (seen.has(t.id)) continue; seen.add(t.id);
    const native = nativeOf(MAP[tab.source][tab.source === "cyberchef" ? t.name : t.id]);
    tools.push({ id: t.id, name: t.name, description: t.description || t.use || "", category: tab.source === "webcheck" ? webcheckGroup(t.id) : tab.source === "networking-toolbox" && t.group ? `${cat.name} · ${t.group}` : cat.name,
      keywords: t.keywords || [], native, external: tab.link(t), visible: true });
  }
  catalog.tabs.push({ id: tab.id, name: tab.name, description: tab.description, icon: ICON[tab.source], source: tab.source, sourceUrl: tab.sourceUrl, visible: true, tools });
}
fs.writeFileSync(path.join(root, "seed", "catalog.json"), JSON.stringify(catalog, null, 1));
for (const t of catalog.tabs) console.log(`${t.name.padEnd(16)} ${t.tools.length} tools, ${t.tools.filter((x) => x.native).length} native`);
const total = catalog.tabs.reduce((n, t) => n + t.tools.length, 0), nat = catalog.tabs.reduce((n, t) => n + t.tools.filter((x) => x.native).length, 0);
console.log(`Total ${total} tools, ${nat} native (${((nat / total) * 100).toFixed(1)}%)`);
if (missing.length) { console.error("Unknown ops in MAP:", missing.join(", ")); process.exit(1); }
