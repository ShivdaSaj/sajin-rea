import { lines, select, opt } from "./util.js";

// ---------- IPv4 ----------
export function ip4ToInt(s) {
  const p = String(s).trim().split(".");
  if (p.length !== 4 || p.some((x) => !/^\d{1,3}$/.test(x) || +x > 255)) throw new Error(`Invalid IPv4 address "${s}"`);
  return ((+p[0] << 24) | (+p[1] << 16) | (+p[2] << 8) | +p[3]) >>> 0;
}
export const intToIp4 = (n) => [24, 16, 8, 0].map((s) => (n >>> s) & 255).join(".");
const maskOf = (bits) => (bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0);
export function parseCidr4(s) {
  const [ip, b] = String(s).trim().split("/"); const bits = b === undefined ? 32 : Number(b);
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) throw new Error(`Invalid prefix in "${s}"`);
  const addr = ip4ToInt(ip); const net = (addr & maskOf(bits)) >>> 0;
  return { addr, bits, net, bcast: (net | (~maskOf(bits) >>> 0)) >>> 0, size: 2 ** (32 - bits) };
}
const cidrStr = (net, bits) => `${intToIp4(net)}/${bits}`;
function maskToBits(mask) { const m = ip4ToInt(mask); const bits = 32 - Math.log2((~m >>> 0) + 1); if (!Number.isInteger(bits) || maskOf(bits) !== m) throw new Error("Not a contiguous subnet mask"); return bits; }
function classify4(n) {
  const r = [[0x0a000000, 8, "Private (RFC 1918)"], [0xac100000, 12, "Private (RFC 1918)"], [0xc0a80000, 16, "Private (RFC 1918)"], [0x7f000000, 8, "Loopback"], [0xa9fe0000, 16, "Link-local (APIPA)"],
    [0x64400000, 10, "Carrier-grade NAT (RFC 6598)"], [0xe0000000, 4, "Multicast"], [0xf0000000, 4, "Reserved (Class E)"], [0x00000000, 8, "\"This\" network"], [0xc0000200, 24, "Documentation (TEST-NET-1)"],
    [0xc6336400, 24, "Documentation (TEST-NET-2)"], [0xcb007100, 24, "Documentation (TEST-NET-3)"], [0xc6120000, 15, "Benchmarking (RFC 2544)"], [0xc0000000, 24, "IETF protocol assignments"], [0xffffffff, 32, "Limited broadcast"]];
  for (const [net, bits, label] of r) if (((n & maskOf(bits)) >>> 0) === net) return label;
  return "Public (globally routable)";
}
const cls = (n) => { const f = n >>> 24; return f < 128 ? "A" : f < 192 ? "B" : f < 224 ? "C" : f < 240 ? "D (multicast)" : "E (reserved)"; };

// Smallest CIDR set covering [start, end] inclusive.
export function rangeToCidrs(start, end) {
  const out = []; let s = start;
  while (s <= end) {
    let bits = 32; while (bits > 0) { const nb = bits - 1; const m = maskOf(nb); if (((s & m) >>> 0) !== s || ((s | (~m >>> 0)) >>> 0) > end) break; bits = nb; }
    out.push(cidrStr(s, bits)); const next = s + 2 ** (32 - bits); if (next > 0xffffffff) break; s = next;
  }
  return out;
}
function mergeRanges(cidrs) {
  const rs = cidrs.map(parseCidr4).map((c) => [c.net, c.bcast]).sort((a, b) => a[0] - b[0]); const out = [];
  for (const r of rs) { const last = out.at(-1); if (last && r[0] <= last[1] + 1) last[1] = Math.max(last[1], r[1]); else out.push([...r]); }
  return out;
}
const cidrList = (s) => String(s).split(/[\s,;]+/).map((x) => x.trim()).filter(Boolean);
function subtract(ranges, sub) {
  let out = ranges;
  for (const [s, e] of sub) out = out.flatMap(([a, b]) => (e < a || s > b ? [[a, b]] : [...(s > a ? [[a, s - 1]] : []), ...(e < b ? [[e + 1, b]] : [])]));
  return out;
}
const rangesToCidrs = (rs) => rs.flatMap(([a, b]) => rangeToCidrs(a, b));

// ---------- IPv6 ----------
export function ip6ToBig(s) {
  let str = String(s).trim().replace(/^\[|\]$/g, "").split("%")[0];
  let tail = [];
  const v4 = str.match(/(\d+\.\d+\.\d+\.\d+)$/);
  if (v4) { const n = ip4ToInt(v4[1]); tail = [(n >>> 16).toString(16), (n & 0xffff).toString(16)]; str = str.slice(0, -v4[1].length).replace(/:$/, ":") + "x"; }
  const halves = str.split("::"); if (halves.length > 2) throw new Error(`Invalid IPv6 address "${s}"`);
  const part = (h) => (h ? h.split(":").filter((x) => x !== "x") : []);
  let head = part(halves[0]), back = halves.length === 2 ? part(halves[1]) : [];
  if (v4) { if (halves.length === 2) back = back.concat(tail); else head = head.concat(tail); }
  const fill = 8 - head.length - back.length;
  if (halves.length === 1 && fill !== 0) throw new Error(`Invalid IPv6 address "${s}"`);
  if (fill < 0) throw new Error(`Invalid IPv6 address "${s}"`);
  const groups = [...head, ...Array(halves.length === 2 ? fill : 0).fill("0"), ...back];
  let n = 0n; for (const g of groups) { if (!/^[0-9a-f]{1,4}$/i.test(g)) throw new Error(`Invalid IPv6 group "${g}"`); n = (n << 16n) | BigInt(parseInt(g, 16)); }
  return n;
}
export const bigToGroups = (n) => Array.from({ length: 8 }, (_, i) => Number((n >> BigInt(16 * (7 - i))) & 0xffffn));
export const expand6 = (n) => bigToGroups(n).map((g) => g.toString(16).padStart(4, "0")).join(":");
export function compress6(n) {
  const g = bigToGroups(n).map((x) => x.toString(16)); let best = [-1, 0], cur = [-1, 0];
  g.forEach((x, i) => { if (x === "0") { if (cur[0] < 0) cur = [i, 1]; else cur[1]++; if (cur[1] > best[1]) best = [...cur]; } else cur = [-1, 0]; });
  if (best[1] < 2) return g.join(":");
  return (g.slice(0, best[0]).join(":") + "::" + g.slice(best[0] + best[1]).join(":"));
}
function classify6(n) {
  const t = [[0n, 128, "Unspecified"], [1n, 128, "Loopback"], [0xfe80n << 112n, 10, "Link-local unicast"], [0xfc00n << 112n, 7, "Unique local (ULA)"], [0xff00n << 112n, 8, "Multicast"],
    [0x20010db8n << 96n, 32, "Documentation"], [0x2002n << 112n, 16, "6to4"], [0x20010000n << 96n, 32, "Teredo"], [0xffffn << 32n, 96, "IPv4-mapped"], [0x0064ff9bn << 96n, 96, "NAT64 well-known prefix"], [0x2000n << 112n, 3, "Global unicast"]];
  for (const [p, bits, label] of t) { const sh = BigInt(128 - bits); if (n >> sh === p >> sh) return label; }
  return "Reserved";
}
function parseCidr6(s) { const [a, b] = String(s).trim().split("/"); const bits = b === undefined ? 128 : Number(b); if (!(bits >= 0 && bits <= 128)) throw new Error("Invalid IPv6 prefix"); const n = ip6ToBig(a); const host = (1n << BigInt(128 - bits)) - 1n; return { n, bits, net: n & ~host & ((1n << 128n) - 1n), last: (n & ~host) | host }; }
const isV6 = (s) => String(s).includes(":");

function randomMac(prefix, sep) {
  const b = crypto.getRandomValues(new Uint8Array(6)); const pre = String(prefix || "").replace(/[^0-9a-f]/gi, "").match(/.{2}/g) || [];
  pre.forEach((h, i) => { if (i < 6) b[i] = parseInt(h, 16); }); if (!pre.length) b[0] = (b[0] & 0xfe) | 0x02;
  return Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(sep);
}

export const ops = {
  "subnet-calc": { name: "IPv4 Subnet Calculator", run: (i) => { const c = parseCidr4(String(i).includes("/") ? i : i.trim().includes(" ") ? i.trim().split(/\s+/)[0] + "/" + maskToBits(i.trim().split(/\s+/)[1]) : i + "/24");
    const m = maskOf(c.bits); const hosts = c.bits >= 31 ? c.size : c.size - 2;
    return [`Address:           ${intToIp4(c.addr)}`, `Network:           ${cidrStr(c.net, c.bits)}`, `Netmask:           ${intToIp4(m)}  (/${c.bits})`, `Wildcard mask:     ${intToIp4(~m >>> 0)}`,
      `Broadcast:         ${c.bits >= 31 ? "n/a" : intToIp4(c.bcast)}`, `First usable host: ${intToIp4(c.bits >= 31 ? c.net : c.net + 1)}`, `Last usable host:  ${intToIp4(c.bits >= 31 ? c.bcast : c.bcast - 1)}`,
      `Total addresses:   ${c.size.toLocaleString()}`, `Usable hosts:      ${hosts.toLocaleString()}`, `Class:             ${cls(c.addr)}`, `Type:              ${classify4(c.addr)}`,
      `Binary netmask:    ${m.toString(2).padStart(32, "0").match(/.{8}/g).join(".")}`, `Hex network:       0x${c.net.toString(16).padStart(8, "0")}`, `in-addr.arpa:      ${intToIp4(c.net).split(".").reverse().slice(4 - Math.max(1, Math.ceil(c.bits / 8))).join(".")}.in-addr.arpa`].join("\n"); },
    placeholder: "192.168.10.37/26  or  10.0.0.5 255.255.255.0" },
  "cidr-to-mask": { name: "CIDR to Subnet Mask", run: (i) => lines(i).filter(Boolean).map((l) => { const b = Number(String(l).replace(/.*\//, "")); if (!(b >= 0 && b <= 32)) throw new Error("Prefix must be 0–32"); return `/${b} → ${intToIp4(maskOf(b))}  (wildcard ${intToIp4(~maskOf(b) >>> 0)}, ${(2 ** (32 - b)).toLocaleString()} addresses)`; }).join("\n"), placeholder: "/24" },
  "mask-to-cidr": { name: "Subnet Mask to CIDR", run: (i) => lines(i).filter(Boolean).map((l) => `${l.trim()} → /${maskToBits(l.trim())}`).join("\n"), placeholder: "255.255.252.0" },
  "wildcard-mask": { name: "Wildcard Mask Calculator", run: (i) => lines(i).filter(Boolean).map((l) => { const s = l.trim(); const bits = s.includes(".") ? (s.includes("/") ? Number(s.split("/")[1]) : maskToBits(s)) : Number(s.replace("/", "")); const c = s.includes("/") && s.includes(".") ? parseCidr4(s) : null;
    return `${s}: wildcard ${intToIp4(~maskOf(bits) >>> 0)}${c ? `  →  ACL: permit ip ${intToIp4(c.net)} ${intToIp4(~maskOf(bits) >>> 0)}` : ""}`; }).join("\n"), placeholder: "10.1.0.0/16 or 255.255.255.0" },
  "cidr-split": { name: "CIDR Subnet Splitter", run: (i, a) => { const c = parseCidr4(i); const nb = Number(a.newPrefix); if (!(nb >= c.bits && nb <= 32)) throw new Error(`New prefix must be between /${c.bits} and /32`); const count = 2 ** (nb - c.bits); if (count > 4096) throw new Error(`That makes ${count} subnets — choose a smaller split (max 4096)`);
    return Array.from({ length: count }, (_, k) => { const n = c.net + k * 2 ** (32 - nb); return `${cidrStr(n, nb).padEnd(19)} ${intToIp4(n)} – ${intToIp4(n + 2 ** (32 - nb) - 1)}`; }).join("\n"); }, args: [opt("newPrefix", "New prefix length", "number", { default: 26 })], placeholder: "10.0.0.0/24" },
  "cidr-summarize": { name: "CIDR Summarizer / Aggregator", run: (i) => rangesToCidrs(mergeRanges(cidrList(i))).join("\n"), placeholder: "10.0.0.0/24\n10.0.1.0/24\n10.0.2.0/23" },
  "range-to-cidr": { name: "IP Range to CIDR", run: (i) => { const [a, b] = String(i).split(/\s*[-–]\s*|\s+/).filter(Boolean); const s = ip4ToInt(a), e = ip4ToInt(b ?? a); if (e < s) throw new Error("End must be ≥ start"); return rangeToCidrs(s, e).join("\n"); }, placeholder: "192.168.0.10 - 192.168.0.200" },
  "cidr-to-range": { name: "CIDR to IP Range", run: (i) => cidrList(i).map((s) => { const c = parseCidr4(s); return `${s}: ${intToIp4(c.net)} – ${intToIp4(c.bcast)} (${c.size.toLocaleString()} addresses)`; }).join("\n") },
  "cidr-contains": { name: "CIDR Contains Check", run: (i, a) => { const c = parseCidr4(a.cidr); return cidrList(i).map((x) => { const t = parseCidr4(x); const inside = t.net >= c.net && t.bcast <= c.bcast; return `${x}: ${inside ? "INSIDE" : "outside"} ${a.cidr}`; }).join("\n"); }, args: [opt("cidr", "Container CIDR", "text", { default: "10.0.0.0/8" })], placeholder: "10.20.30.40\n192.168.1.0/24" },
  "cidr-overlap": { name: "CIDR Overlap Check", run: (i) => { const l = cidrList(i).map((s) => [s, parseCidr4(s)]); const out = []; for (let x = 0; x < l.length; x++) for (let y = x + 1; y < l.length; y++) { const A = l[x][1], B = l[y][1]; if (A.net <= B.bcast && B.net <= A.bcast) out.push(`${l[x][0]} overlaps ${l[y][0]}`); } return out.length ? out.join("\n") : "No overlaps"; }, placeholder: "10.0.0.0/16\n10.0.128.0/17\n192.168.0.0/24" },
  "cidr-diff": { name: "CIDR Set Difference", run: (i, a) => rangesToCidrs(subtract(mergeRanges(cidrList(i)), mergeRanges(cidrList(a.remove)))).join("\n") || "(empty)", args: [opt("remove", "Subtract these CIDRs", "textarea", { default: "10.0.5.0/24" })], placeholder: "10.0.0.0/16" },
  "cidr-gaps": { name: "CIDR Gap Finder", run: (i, a) => { const parent = parseCidr4(a.parent); return rangesToCidrs(subtract([[parent.net, parent.bcast]], mergeRanges(cidrList(i)))).join("\n") || "No gaps"; }, args: [opt("parent", "Parent block", "text", { default: "10.0.0.0/22" })], placeholder: "10.0.0.0/24\n10.0.2.0/24" },
  "cidr-next": { name: "Next Available Subnet", run: (i, a) => { const parent = parseCidr4(a.parent), want = Number(a.prefix); const used = mergeRanges(cidrList(i)); const size = 2 ** (32 - want);
    for (let n = parent.net; n + size - 1 <= parent.bcast; n += size) if (!used.some(([s, e]) => n <= e && n + size - 1 >= s)) return cidrStr(n, want); return "No free subnet of that size"; },
    args: [opt("parent", "Parent block", "text", { default: "10.0.0.0/16" }), opt("prefix", "Wanted prefix", "number", { default: 24 })], placeholder: "Allocated subnets, one per line" },
  "cidr-compare": { name: "CIDR List Compare", run: (i, a) => { const A = new Set(cidrList(i)), B = new Set(cidrList(a.other)); return `Added:\n${[...B].filter((x) => !A.has(x)).join("\n") || "(none)"}\n\nRemoved:\n${[...A].filter((x) => !B.has(x)).join("\n") || "(none)"}\n\nUnchanged:\n${[...A].filter((x) => B.has(x)).join("\n") || "(none)"}`; }, args: [opt("other", "New list", "textarea")], placeholder: "Old list" },
  "cidr-deaggregate": { name: "CIDR Deaggregate", run: (i, a) => { const c = parseCidr4(i); const nb = Number(a.prefix); if (nb < c.bits) throw new Error("Target prefix must be longer"); return ops["cidr-split"].run(i, { newPrefix: nb }); }, args: [opt("prefix", "Target prefix", "number", { default: 24 })], placeholder: "10.0.0.0/22" },
  "cidr-alignment": { name: "CIDR Alignment Check", run: (i) => cidrList(i).map((s) => { const [ip, b] = s.split("/"); const n = ip4ToInt(ip), bits = Number(b ?? 32); const net = (n & maskOf(bits)) >>> 0; return net === n ? `${s}: aligned` : `${s}: NOT aligned — nearest valid network is ${cidrStr(net, bits)}`; }).join("\n"), placeholder: "10.0.0.16/28\n10.0.0.20/28" },
  "ip-convert": { name: "IP Address Converter", run: (i) => { const s = String(i).trim(); if (isV6(s)) { const n = ip6ToBig(s); return `Compressed: ${compress6(n)}\nExpanded:   ${expand6(n)}\nDecimal:    ${n}\nHex:        0x${n.toString(16).padStart(32, "0")}\nBinary:     ${n.toString(2).padStart(128, "0").match(/.{16}/g).join(":")}\nType:       ${classify6(n)}`; }
    const n = /^\d+$/.test(s) ? Number(s) >>> 0 : /^0x[0-9a-f]+$/i.test(s) ? parseInt(s, 16) >>> 0 : ip4ToInt(s);
    return `Dotted:   ${intToIp4(n)}\nDecimal:  ${n}\nHex:      0x${n.toString(16).padStart(8, "0")}\nOctal:    ${intToIp4(n).split(".").map((x) => "0" + (+x).toString(8)).join(".")}\nBinary:   ${n.toString(2).padStart(32, "0").match(/.{8}/g).join(".")}\nIPv6-mapped: ::ffff:${intToIp4(n)}\nClass:    ${cls(n)}\nType:     ${classify4(n)}`; }, placeholder: "192.168.1.1, 3232235777, 0xC0A80101 or an IPv6 address" },
  "ip-classify": { name: "IP Address Type", run: (i) => cidrList(i).map((s) => (isV6(s) ? `${s}: ${classify6(ip6ToBig(s))}` : `${s}: ${classify4(ip4ToInt(s))}`)).join("\n") },
  "ip-validate": { name: "IP Address Validator", run: (i) => cidrList(i).map((s) => { try { if (isV6(s)) { ip6ToBig(s); return `${s}: valid IPv6`; } ip4ToInt(s); return `${s}: valid IPv4`; } catch { return `${s}: INVALID`; } }).join("\n") },
  "ipv6-expand": { name: "IPv6 Expand", run: (i) => cidrList(i).map((s) => expand6(ip6ToBig(s))).join("\n"), placeholder: "2001:db8::1" },
  "ipv6-compress": { name: "IPv6 Compress", run: (i) => cidrList(i).map((s) => compress6(ip6ToBig(s))).join("\n"), placeholder: "2001:0db8:0000:0000:0000:0000:0000:0001" },
  "ipv6-subnet": { name: "IPv6 Subnet Calculator", run: (i) => { const c = parseCidr6(i.includes("/") ? i : i + "/64"); return `Network:  ${compress6(c.net)}/${c.bits}\nFirst:    ${compress6(c.net)}\nLast:     ${compress6(c.last)}\nExpanded: ${expand6(c.net)}\nAddresses: 2^${128 - c.bits} = ${(1n << BigInt(128 - c.bits)).toLocaleString()}\n/64 subnets: ${c.bits <= 64 ? (1n << BigInt(64 - c.bits)).toLocaleString() : "n/a"}\nType:     ${classify6(c.n)}`; }, placeholder: "2001:db8:abcd::/48" },
  "ipv6-ula": { name: "IPv6 ULA Generator", input: false, run: () => { const b = crypto.getRandomValues(new Uint8Array(5)); const g = Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(""); const p = `fd${g.slice(0, 2)}:${g.slice(2, 6)}:${g.slice(6, 10)}`; return `Prefix:  ${p}::/48\nExample subnet: ${p}:1::/64\nExample host:   ${p}:1::1`; } },
  "eui64": { name: "MAC to IPv6 EUI-64", run: (i, a) => { const h = String(i).replace(/[^0-9a-f]/gi, ""); if (h.length !== 12) throw new Error("Enter a 48-bit MAC address"); const b = h.match(/.{2}/g).map((x) => parseInt(x, 16)); b[0] ^= 2; const e = [...b.slice(0, 3), 0xff, 0xfe, ...b.slice(3)]; const iid = e.map((x) => x.toString(16).padStart(2, "0")).join("").match(/.{4}/g).map((x) => x.replace(/^0+(?=.)/, "")).join(":"); return `Interface ID: ${iid}\nLink-local:   fe80::${iid}\nWith prefix:  ${String(a.prefix).replace(/::?\/?\d*$/, "")}:${iid}`; }, args: [opt("prefix", "Prefix (/64)", "text", { default: "2001:db8:1:2::/64" })], placeholder: "00:1A:2B:3C:4D:5E" },
  "reverse-dns-name": { name: "Reverse DNS (PTR) Name Generator", run: (i) => cidrList(i).map((s) => isV6(s) ? `${s} → ${expand6(ip6ToBig(s)).replace(/:/g, "").split("").reverse().join(".")}.ip6.arpa` : `${s} → ${s.split("/")[0].split(".").reverse().join(".")}.in-addr.arpa`).join("\n"), placeholder: "203.0.113.7\n2001:db8::1" },
  "mac-generate": { name: "MAC Address Generator", input: false, run: (_, a) => Array.from({ length: Math.min(Number(a.count) || 1, 500) }, () => randomMac(a.prefix, a.sep === "Dash" ? "-" : a.sep === "None" ? "" : ":")).join("\n"), args: [opt("count", "How many", "number", { default: 5 }), opt("prefix", "OUI prefix (optional)", "text"), select("sep", "Separator", ["Colon", "Dash", "None"])] },
  "mac-format": { name: "MAC Address Formatter", run: (i) => lines(i).filter(Boolean).map((l) => { const h = l.replace(/[^0-9a-f]/gi, "").toLowerCase(); if (h.length !== 12) return `${l}: invalid`; const p = h.match(/.{2}/g); const b0 = parseInt(p[0], 16);
    return `${p.join(":")}  |  ${p.join("-").toUpperCase()}  |  ${h.match(/.{4}/g).join(".")}  |  ${b0 & 1 ? "multicast" : "unicast"}, ${b0 & 2 ? "locally administered" : "globally unique (OUI " + p.slice(0, 3).join(":").toUpperCase() + ")"}`; }).join("\n"), placeholder: "001A.2B3C.4D5E" },
  "random-ip": { name: "Random IP Generator", input: false, run: (_, a) => { const c = parseCidr4(a.cidr); const r = new Uint32Array(Math.min(Number(a.count) || 1, 500)); crypto.getRandomValues(r); return Array.from(r, (x) => intToIp4(c.net + (x % c.size))).join("\n"); }, args: [opt("cidr", "Within CIDR", "text", { default: "10.0.0.0/8" }), opt("count", "How many", "number", { default: 10 })] },
  "ip-sort": { name: "Sort IP Addresses", run: (i, a) => { let l = cidrList(i); if (a.unique) l = [...new Set(l)]; return l.sort((x, y) => (isV6(x) || isV6(y) ? x.localeCompare(y) : ip4ToInt(x.split("/")[0]) - ip4ToInt(y.split("/")[0]))).join("\n"); }, args: [opt("unique", "Remove duplicates", "checkbox", { default: true })] },
  "vlsm": { name: "VLSM Subnet Planner", run: (i, a) => { const parent = parseCidr4(a.parent); const needs = cidrList(i).map(Number).filter((n) => n > 0).sort((x, y) => y - x); let next = parent.net; const out = [];
    for (const h of needs) { const bits = 32 - Math.ceil(Math.log2(h + 2)); const size = 2 ** (32 - bits); next = Math.ceil(next / size) * size; if (next + size - 1 > parent.bcast) { out.push(`${h} hosts: does not fit`); continue; } out.push(`${String(h).padStart(6)} hosts → ${cidrStr(next, bits).padEnd(18)} (${size - 2} usable, ${intToIp4(next + 1)} – ${intToIp4(next + size - 2)})`); next += size; }
    return out.join("\n"); }, args: [opt("parent", "Address block", "text", { default: "192.168.0.0/24" })], placeholder: "Host counts, e.g. 100 50 20 2" },
  "port-reference": { name: "Common Ports Reference", run: (i) => { const q = String(i).trim().toLowerCase(); const rows = PORTS.filter(([p, proto, n]) => !q || String(p) === q || n.toLowerCase().includes(q) || proto.includes(q)); return rows.map(([p, proto, n]) => `${String(p).padStart(5)}/${proto.padEnd(7)} ${n}`).join("\n") || "No match"; }, placeholder: "Port number or service name (blank = all)" },
};

const PORTS = [[20, "tcp", "FTP data"], [21, "tcp", "FTP control"], [22, "tcp", "SSH / SCP / SFTP"], [23, "tcp", "Telnet"], [25, "tcp", "SMTP"], [53, "tcp/udp", "DNS"], [67, "udp", "DHCP server"], [68, "udp", "DHCP client"], [69, "udp", "TFTP"], [80, "tcp", "HTTP"], [88, "tcp/udp", "Kerberos"], [110, "tcp", "POP3"], [119, "tcp", "NNTP"], [123, "udp", "NTP"], [135, "tcp", "MS RPC"], [137, "udp", "NetBIOS name"], [139, "tcp", "NetBIOS session / SMB"], [143, "tcp", "IMAP"], [161, "udp", "SNMP"], [162, "udp", "SNMP trap"], [179, "tcp", "BGP"], [389, "tcp/udp", "LDAP"], [443, "tcp/udp", "HTTPS / QUIC"], [445, "tcp", "SMB"], [465, "tcp", "SMTPS"], [500, "udp", "IKE (IPsec)"], [514, "udp", "Syslog"], [515, "tcp", "LPD"], [520, "udp", "RIP"], [546, "udp", "DHCPv6 client"], [547, "udp", "DHCPv6 server"], [587, "tcp", "SMTP submission"], [636, "tcp", "LDAPS"], [853, "tcp", "DNS over TLS"], [873, "tcp", "rsync"], [993, "tcp", "IMAPS"], [995, "tcp", "POP3S"], [1194, "udp", "OpenVPN"], [1433, "tcp", "MS SQL"], [1521, "tcp", "Oracle DB"], [1701, "udp", "L2TP"], [1723, "tcp", "PPTP"], [1812, "udp", "RADIUS auth"], [1813, "udp", "RADIUS accounting"], [2049, "tcp/udp", "NFS"], [2375, "tcp", "Docker API (plain)"], [2376, "tcp", "Docker API (TLS)"], [3306, "tcp", "MySQL / MariaDB"], [3389, "tcp", "RDP"], [4500, "udp", "IPsec NAT-T"], [5060, "tcp/udp", "SIP"], [5061, "tcp", "SIP-TLS"], [5432, "tcp", "PostgreSQL"], [5672, "tcp", "AMQP"], [5900, "tcp", "VNC"], [6379, "tcp", "Redis"], [6443, "tcp", "Kubernetes API"], [8080, "tcp", "HTTP alternate"], [8443, "tcp", "HTTPS alternate"], [9000, "tcp", "Portainer / various"], [9090, "tcp", "Prometheus"], [9200, "tcp", "Elasticsearch"], [11211, "tcp/udp", "Memcached"], [27017, "tcp", "MongoDB"], [51820, "udp", "WireGuard"]];
