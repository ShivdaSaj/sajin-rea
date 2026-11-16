// Packet & protocol tools: Ethernet/IPv4/TCP/UDP/TLS parsers, JA3/JA3S/JA4/JA4S, HASSH,
// HTTP header strip / dechunk, schema-less Protobuf decode and encode.
import { utf8, fromUtf8, hexToBytes, bytesToHex, select, opt } from "./util.js";
import { md5 } from "./hashing.js";

const hexIn = (i) => { const s = String(i).replace(/0x/gi, "").replace(/[^0-9a-f]/gi, ""); if (!s) throw new Error("Paste the packet as hex"); return hexToBytes(s); };
const u16 = (b, o) => (b[o] << 8) | b[o + 1], u32 = (b, o) => ((b[o] << 24) | (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]) >>> 0;
const mac = (b, o) => Array.from(b.subarray(o, o + 6), (x) => x.toString(16).padStart(2, "0")).join(":");
const ip4 = (b, o) => Array.from(b.subarray(o, o + 4)).join(".");
const ETYPES = { 0x0800: "IPv4", 0x0806: "ARP", 0x86dd: "IPv6", 0x8100: "802.1Q VLAN", 0x88cc: "LLDP", 0x888e: "EAPOL", 0x8847: "MPLS" };
const PROTOS = { 1: "ICMP", 2: "IGMP", 6: "TCP", 17: "UDP", 41: "IPv6", 47: "GRE", 50: "ESP", 51: "AH", 58: "ICMPv6", 89: "OSPF", 132: "SCTP" };
const kv = (rows) => rows.map(([k, v]) => `${k.padEnd(22)} ${v}`).join("\n");
const sha256 = async (s) => bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", utf8(s))));

function parseEth(b) { if (b.length < 14) throw new Error("Too short for an Ethernet frame"); let type = u16(b, 12), off = 14; const vlan = []; while (type === 0x8100 && off + 4 <= b.length) { vlan.push(u16(b, off) & 0xfff); type = u16(b, off + 2); off += 4; } return { dst: mac(b, 0), src: mac(b, 6), type, vlan, off }; }
function parseIp4(b, o = 0) { if ((b[o] >> 4) !== 4) throw new Error("Not an IPv4 header (version nibble is not 4)"); const ihl = (b[o] & 15) * 4; const ff = u16(b, o + 6); let sum = 0; for (let k = 0; k < ihl; k += 2) if (k !== 10) sum += u16(b, o + k); while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16); const calc = ~sum & 0xffff;
  return { ihl, tos: b[o + 1], len: u16(b, o + 2), id: u16(b, o + 4), df: !!(ff & 0x4000), mf: !!(ff & 0x2000), frag: (ff & 0x1fff) * 8, ttl: b[o + 8], proto: b[o + 9], csum: u16(b, o + 10), csumOk: calc === u16(b, o + 10), src: ip4(b, o + 12), dst: ip4(b, o + 16), off: o + ihl }; }
function parseTcp(b, o = 0) { const doff = (b[o + 12] >> 4) * 4; const fl = b[o + 13]; const names = ["FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR"].filter((_, k) => (fl >> k) & 1); const opts = []; let p = o + 20;
  while (p < o + doff) { const k = b[p]; if (k === 0) break; if (k === 1) { p++; continue; } const l = b[p + 1]; const v = b.subarray(p + 2, p + l); opts.push(k === 2 ? `MSS=${u16(v, 0)}` : k === 3 ? `WScale=${v[0]}` : k === 4 ? "SACK-permitted" : k === 8 ? `TS=${u32(v, 0)}/${u32(v, 4)}` : `opt${k}`); p += Math.max(2, l); }
  return { sport: u16(b, o), dport: u16(b, o + 2), seq: u32(b, o + 4), ack: u32(b, o + 8), doff, flags: names, win: u16(b, o + 14), csum: u16(b, o + 16), urg: u16(b, o + 18), opts, off: o + doff }; }
function parseUdp(b, o = 0) { return { sport: u16(b, o), dport: u16(b, o + 2), len: u16(b, o + 4), csum: u16(b, o + 6), off: o + 8 }; }

// ---------- TLS handshake ----------
const GREASE = (v) => (v & 0x0f0f) === 0x0a0a && (v >> 8) === (v & 0xff);
const TLSV = { 0x0300: "SSL 3.0", 0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3" };
const EXT = { 0: "server_name", 1: "max_fragment_length", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats", 13: "signature_algorithms", 16: "ALPN", 18: "SCT", 21: "padding", 23: "extended_master_secret", 27: "compress_certificate", 28: "record_size_limit", 35: "session_ticket", 41: "pre_shared_key", 42: "early_data", 43: "supported_versions", 45: "psk_key_exchange_modes", 49: "post_handshake_auth", 50: "signature_algorithms_cert", 51: "key_share", 57: "quic_transport_parameters", 0xff01: "renegotiation_info", 17513: "application_settings", 0xfe0d: "encrypted_client_hello" };
function findHandshake(b) { // accept a raw TLS record, a handshake message, or a whole frame containing one
  for (let o = 0; o + 6 < b.length; o++) { if (b[o] === 0x16 && b[o + 1] === 3 && b[o + 2] <= 4 && (b[o + 5] === 1 || b[o + 5] === 2)) return o + 5; } if (b[0] === 1 || b[0] === 2) return 0; throw new Error("No TLS ClientHello/ServerHello found in the input"); }
function parseHello(b) { let o = findHandshake(b); const type = b[o]; const len = (b[o + 1] << 16) | (b[o + 2] << 8) | b[o + 3]; o += 4; const end = Math.min(b.length, o + len); const h = { type: type === 1 ? "ClientHello" : "ServerHello", version: u16(b, o) }; o += 2 + 32; const sid = b[o]; o += 1 + sid;
  if (type === 1) { const cl = u16(b, o); o += 2; h.ciphers = []; for (let k = 0; k < cl; k += 2) h.ciphers.push(u16(b, o + k)); o += cl; const cm = b[o]; o += 1 + cm; } else { h.cipher = u16(b, o); o += 3; }
  h.exts = []; h.sni = null; h.alpn = []; h.groups = []; h.pointFormats = []; h.sigAlgs = []; h.supportedVersions = [];
  if (o + 2 <= end) { const el = u16(b, o); o += 2; const ee = Math.min(end, o + el); while (o + 4 <= ee) { const t = u16(b, o), l = u16(b, o + 2); const d = b.subarray(o + 4, o + 4 + l); h.exts.push(t);
    if (t === 0 && l > 5) h.sni = fromUtf8(d.subarray(5, 5 + u16(d, 3))); if (t === 16) { let p = 2; while (p < d.length) { const n = d[p]; h.alpn.push(fromUtf8(d.subarray(p + 1, p + 1 + n))); p += 1 + n; } }
    if (t === 10) for (let p = 2; p + 1 < d.length; p += 2) h.groups.push(u16(d, p)); if (t === 11) for (let p = 1; p < d.length; p++) h.pointFormats.push(d[p]); if (t === 13) for (let p = 2; p + 1 < d.length; p += 2) h.sigAlgs.push(u16(d, p));
    if (t === 43) { if (type === 1) for (let p = 1; p + 1 < d.length; p += 2) h.supportedVersions.push(u16(d, p)); else h.supportedVersions.push(u16(d, 0)); } o += 4 + l; } }
  return h; }
const nog = (a) => a.filter((x) => !GREASE(x));
function ja3(h) { const s = `${h.version},${nog(h.ciphers).join("-")},${nog(h.exts).join("-")},${nog(h.groups).join("-")},${h.pointFormats.join("-")}`; return { s, hash: bytesToHex(md5(utf8(s))) }; }
function ja3s(h) { const s = `${h.version},${h.cipher},${nog(h.exts).join("-")}`; return { s, hash: bytesToHex(md5(utf8(s))) }; }
const ver4 = (v) => ({ 0x0304: "13", 0x0303: "12", 0x0302: "11", 0x0301: "10", 0x0300: "s3" })[v] || "00";
const alpnCode = (a) => { if (!a) return "00"; const f = a[0], l = a.at(-1); const an = (c) => /[A-Za-z0-9]/.test(c); return an(f) && an(l) ? f + l : bytesToHex(utf8(f)).slice(0, 1) + bytesToHex(utf8(l)).slice(-1); };
const h4 = (n) => n.toString(16).padStart(4, "0");
async function ja4(h, proto) { const v = Math.max(h.version, ...nog(h.supportedVersions)); const ciphers = nog(h.ciphers), exts = nog(h.exts);
  const a = `${proto}${ver4(v)}${h.sni ? "d" : "i"}${String(Math.min(ciphers.length, 99)).padStart(2, "0")}${String(Math.min(exts.length, 99)).padStart(2, "0")}${alpnCode(h.alpn[0])}`;
  const b = ciphers.length ? (await sha256(ciphers.map(h4).sort().join(","))).slice(0, 12) : "000000000000";
  const extList = exts.filter((x) => x !== 0 && x !== 16).map(h4).sort().join(","); const sig = h.sigAlgs.filter((x) => !GREASE(x)).map(h4).join(",");
  const c = extList ? (await sha256(sig ? `${extList}_${sig}` : extList)).slice(0, 12) : "000000000000"; return { full: `${a}_${b}_${c}`, raw: `${a}_${ciphers.map(h4).sort().join(",")}_${extList}${sig ? `_${sig}` : ""}` }; }
async function ja4s(h, proto) { const v = h.supportedVersions[0] || h.version; const exts = h.exts; const a = `${proto}${ver4(v)}${String(Math.min(exts.length, 99)).padStart(2, "0")}${alpnCode(h.alpn[0])}`; const c = exts.length ? (await sha256(exts.map(h4).join(","))).slice(0, 12) : "000000000000"; return `${a}_${h4(h.cipher)}_${c}`; }

// ---------- SSH KEXINIT (HASSH) ----------
function parseKexinit(b) { let o = 0; const s = fromUtf8(b.subarray(0, 8)); if (s.startsWith("SSH-")) { const nl = b.indexOf(10); o = nl + 1; }
  // optional binary packet header: uint32 packet_length, byte padding_length, byte msg 20
  if (b[o] !== 20 && b[o + 5] === 20) o += 5; if (b[o] !== 20) throw new Error("No SSH_MSG_KEXINIT (type 20) found"); o += 1 + 16; const lists = [];
  for (let k = 0; k < 10; k++) { const n = u32(b, o); lists.push(fromUtf8(b.subarray(o + 4, o + 4 + n))); o += 4 + n; } return lists; }

// ---------- HTTP ----------
function dechunk(s) { let out = "", i = 0; const t = String(s).replace(/\r\n/g, "\n"); for (;;) { const nl = t.indexOf("\n", i); if (nl < 0) break; const size = parseInt(t.slice(i, nl).split(";")[0].trim(), 16); if (isNaN(size)) throw new Error(`Bad chunk size at offset ${i}`); if (size === 0) break; out += t.substr(nl + 1, size); i = nl + 1 + size + 1; } return out; }

// ---------- Protobuf ----------
function readVarint(b, o) { let v = 0n, s = 0n, i = o; for (;;) { if (i >= b.length) throw new Error("Truncated varint"); const x = b[i++]; v |= BigInt(x & 0x7f) << s; s += 7n; if (!(x & 0x80)) break; if (s > 70n) throw new Error("Varint too long"); } return [v, i]; }
function pbDecode(b, depth = 0) { const out = []; let o = 0; while (o < b.length) { const [key, p] = readVarint(b, o); o = p; const field = Number(key >> 3n), wt = Number(key & 7n); if (!field) throw new Error("Invalid field number 0");
    if (wt === 0) { const [v, q] = readVarint(b, o); o = q; const signed = BigInt.asIntN(64, v); const zz = (v >> 1n) ^ -(v & 1n); out.push({ field, type: "varint", value: v.toString(), ...(signed < 0n ? { int64: signed.toString() } : {}), ...(v > 1n ? { sint: zz.toString() } : {}) }); }
    else if (wt === 1) { const dv = new DataView(b.buffer, b.byteOffset + o, 8); out.push({ field, type: "fixed64", value: dv.getBigUint64(0, true).toString(), double: dv.getFloat64(0, true) }); o += 8; }
    else if (wt === 5) { const dv = new DataView(b.buffer, b.byteOffset + o, 4); out.push({ field, type: "fixed32", value: dv.getUint32(0, true), float: +dv.getFloat32(0, true).toPrecision(7) }); o += 4; }
    else if (wt === 2) { const [len, q] = readVarint(b, o); o = q; const n = Number(len); if (o + n > b.length) throw new Error("Truncated length-delimited field"); const sub = b.subarray(o, o + n); o += n; let nested = null; if (depth < 20 && n) { try { nested = pbDecode(sub, depth + 1); } catch { /* not a message */ } }
      const str = fromUtf8(sub); const printable = n && /^[\x09\x0a\x0d\x20-\x7e -￿]*$/.test(str) && !str.includes("�"); out.push(nested && !printable ? { field, type: "message", value: nested } : printable ? { field, type: "string", value: str } : { field, type: "bytes", value: bytesToHex(sub) }); }
    else throw new Error(`Unsupported wire type ${wt} (groups are deprecated)`); } return out; }
const pbShow = (msg, ind = "") => msg.map((f) => f.type === "message" ? `${ind}${f.field}: {\n${pbShow(f.value, ind + "  ")}\n${ind}}` : `${ind}${f.field} (${f.type}): ${typeof f.value === "string" && f.type === "string" ? JSON.stringify(f.value) : f.value}${f.sint ? `  [sint ${f.sint}]` : ""}${f.int64 ? `  [int64 ${f.int64}]` : ""}${f.double !== undefined ? `  [double ${f.double}]` : ""}${f.float !== undefined ? `  [float ${f.float}]` : ""}`).join("\n");
function pbEncode(obj) { const out = []; const varint = (v) => { let x = BigInt(v); if (x < 0n) x = BigInt.asUintN(64, x); do { let b = Number(x & 0x7fn); x >>= 7n; if (x) b |= 0x80; out.push(b); } while (x); };
  for (const [k, raw] of Object.entries(obj)) { const field = Number(k); if (!(field > 0)) throw new Error(`Keys must be field numbers, got "${k}"`); for (const v of Array.isArray(raw) ? raw : [raw]) {
    if (typeof v === "boolean" || (typeof v === "number" && Number.isInteger(v)) || (typeof v === "string" && /^-?\d+n$/.test(v))) { varint((field << 3) | 0); varint(typeof v === "boolean" ? (v ? 1 : 0) : String(v).replace(/n$/, "")); }
    else if (typeof v === "number") { varint((field << 3) | 1); const b = new Uint8Array(8); new DataView(b.buffer).setFloat64(0, v, true); out.push(...b); }
    else { const body = typeof v === "string" ? utf8(v) : pbEncode(v); varint((field << 3) | 2); varint(body.length); out.push(...body); } } } return new Uint8Array(out); }

export const ops = {
  "parse-ethernet": { name: "Parse Ethernet frame", run: (i) => { const b = hexIn(i); const e = parseEth(b); const rows = [["Destination MAC", e.dst], ["Source MAC", e.src], ...(e.vlan.length ? [["VLAN IDs", e.vlan.join(", ")]] : []), ["EtherType", `0x${e.type.toString(16).padStart(4, "0")} (${ETYPES[e.type] || "unknown"})`], ["Payload", `${b.length - e.off} bytes`]];
    if (e.type === 0x0800) { const ip = parseIp4(b, e.off); rows.push(["IPv4", `${ip.src} → ${ip.dst} ${PROTOS[ip.proto] || ip.proto}, TTL ${ip.ttl}`]); if (ip.proto === 6) { const t = parseTcp(b, ip.off); rows.push(["TCP", `${t.sport} → ${t.dport} [${t.flags.join(",")}] seq ${t.seq}`]); } if (ip.proto === 17) { const u = parseUdp(b, ip.off); rows.push(["UDP", `${u.sport} → ${u.dport} len ${u.len}`]); } } return kv(rows); }, placeholder: "Hex of an Ethernet frame (e.g. from Wireshark: Copy → as Hex Stream)" },
  "parse-ipv4": { name: "Parse IPv4 header", run: (i) => { const ip = parseIp4(hexIn(i)); return kv([["Version", 4], ["Header length", `${ip.ihl} bytes`], ["DSCP / ECN", `${ip.tos >> 2} / ${ip.tos & 3}`], ["Total length", ip.len], ["Identification", `0x${ip.id.toString(16)} (${ip.id})`], ["Flags", `${ip.df ? "DF " : ""}${ip.mf ? "MF" : ""}`.trim() || "none"], ["Fragment offset", ip.frag], ["TTL", ip.ttl], ["Protocol", `${ip.proto} (${PROTOS[ip.proto] || "?"})`], ["Header checksum", `0x${ip.csum.toString(16).padStart(4, "0")} ${ip.csumOk ? "✓ correct" : "✗ incorrect"}`], ["Source", ip.src], ["Destination", ip.dst]]); }, placeholder: "4500003c1c4640004006b1e6ac100a63ac100a0c" },
  "strip-ipv4": { name: "Strip IPv4 header", run: (i) => { const b = hexIn(i); return bytesToHex(b.subarray(parseIp4(b).off)); } },
  "parse-tcp": { name: "Parse TCP", run: (i) => { const t = parseTcp(hexIn(i)); return kv([["Source port", t.sport], ["Destination port", t.dport], ["Sequence", t.seq], ["Acknowledgement", t.ack], ["Header length", `${t.doff} bytes`], ["Flags", t.flags.join(", ") || "none"], ["Window", t.win], ["Checksum", `0x${t.csum.toString(16).padStart(4, "0")}`], ["Urgent pointer", t.urg], ["Options", t.opts.join(", ") || "none"]]); } },
  "strip-tcp": { name: "Strip TCP header", run: (i) => { const b = hexIn(i); return bytesToHex(b.subarray(parseTcp(b).off)); } },
  "parse-udp": { name: "Parse UDP", run: (i) => { const u = parseUdp(hexIn(i)); return kv([["Source port", u.sport], ["Destination port", u.dport], ["Length", u.len], ["Checksum", `0x${u.csum.toString(16).padStart(4, "0")}`]]); } },
  "strip-udp": { name: "Strip UDP header", run: (i) => bytesToHex(hexIn(i).subarray(8)) },
  "parse-tls-record": { name: "Parse TLS record", run: async (i) => { const b = hexIn(i); const h = parseHello(b); const rows = [["Handshake", h.type], ["Legacy version", `${TLSV[h.version] || h.version}`]];
    if (h.type === "ClientHello") rows.push(["SNI", h.sni || "(none)"], ["ALPN", h.alpn.join(", ") || "(none)"], ["Supported versions", nog(h.supportedVersions).map((v) => TLSV[v] || v).join(", ") || "(none)"], ["Cipher suites", `${nog(h.ciphers).length}: ${nog(h.ciphers).map(h4).join(" ")}`], ["Groups", nog(h.groups).join(", ")], ["Extensions", nog(h.exts).map((e) => EXT[e] || e).join(", ")]);
    else rows.push(["Cipher", `0x${h4(h.cipher)}`], ["Negotiated version", TLSV[h.supportedVersions[0]] || TLSV[h.version]], ["Extensions", h.exts.map((e) => EXT[e] || e).join(", ")]);
    return kv(rows); }, placeholder: "Hex of a TLS ClientHello/ServerHello record (16 03 01 …)" },
  ja3: { name: "JA3 Fingerprint", run: (i) => { const h = parseHello(hexIn(i)); if (h.type !== "ClientHello") throw new Error("JA3 needs a ClientHello (use JA3S for ServerHello)"); const r = ja3(h); return `JA3: ${r.hash}\nJA3 string: ${r.s}`; } },
  ja3s: { name: "JA3S Fingerprint", run: (i) => { const h = parseHello(hexIn(i)); if (h.type !== "ServerHello") throw new Error("JA3S needs a ServerHello"); const r = ja3s(h); return `JA3S: ${r.hash}\nJA3S string: ${r.s}`; } },
  ja4: { name: "JA4 Fingerprint", run: async (i, a) => { const h = parseHello(hexIn(i)); if (h.type !== "ClientHello") throw new Error("JA4 needs a ClientHello"); const r = await ja4(h, a.proto === "QUIC" ? "q" : "t"); return `JA4: ${r.full}\nJA4_r: ${r.raw}`; }, args: [select("proto", "Transport", ["TCP", "QUIC"])] },
  ja4s: { name: "JA4Server Fingerprint", run: async (i, a) => { const h = parseHello(hexIn(i)); if (h.type !== "ServerHello") throw new Error("JA4S needs a ServerHello"); return `JA4S: ${await ja4s(h, a.proto === "QUIC" ? "q" : "t")}`; }, args: [select("proto", "Transport", ["TCP", "QUIC"])] },
  hassh: { name: "HASSH Client Fingerprint", run: (i) => { const l = parseKexinit(hexIn(i)); const s = [l[0], l[2], l[4], l[6]].join(";"); return `HASSH: ${bytesToHex(md5(utf8(s)))}\nHASSH string: ${s}`; }, placeholder: "Hex of the client's SSH_MSG_KEXINIT packet" },
  "hassh-server": { name: "HASSH Server Fingerprint", run: (i) => { const l = parseKexinit(hexIn(i)); const s = [l[0], l[3], l[5], l[7]].join(";"); return `HASSHServer: ${bytesToHex(md5(utf8(s)))}\nHASSHServer string: ${s}`; }, placeholder: "Hex of the server's SSH_MSG_KEXINIT packet" },
  "strip-http-headers": { name: "Strip HTTP headers", run: (i) => { const s = String(i); const k = s.search(/\r?\n\r?\n/); return k < 0 ? s : s.slice(k).replace(/^\r?\n\r?\n/, ""); } },
  "dechunk-http": { name: "Dechunk HTTP response", run: (i) => { const s = String(i); const k = s.search(/\r?\n\r?\n/); const body = /^HTTP\/|^[A-Z-]+:/m.test(s.slice(0, Math.max(k, 0))) && k >= 0 ? s.slice(k).replace(/^\r?\n\r?\n/, "") : s; return dechunk(body); }, placeholder: "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n" },
  "protobuf-decode": { name: "Protobuf Decode", run: (i, a) => { const s = String(i).trim(); const b = /^[0-9a-f\s]+$/i.test(s) ? hexToBytes(s) : Uint8Array.from(atob(s.replace(/\s/g, "")), (c) => c.charCodeAt(0)); const m = pbDecode(b); return a.format === "JSON" ? JSON.stringify(m, null, 2) : pbShow(m); }, args: [select("format", "Output", ["Tree", "JSON"])], placeholder: "Hex or base64 of a protobuf message, e.g. 089601" },
  "protobuf-encode": { name: "Protobuf Encode", run: (i) => bytesToHex(pbEncode(JSON.parse(i))), placeholder: '{"1": 150, "2": "testing", "3": {"1": 1}}' },
};
export { parseHello, ja3, ja3s, ja4, pbDecode, pbEncode };
