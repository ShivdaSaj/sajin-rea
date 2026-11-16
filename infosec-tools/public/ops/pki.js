// Phase 2 PKI: DER/ASN.1 parsing, X.509 / CSR / CRL, OIDs, PEM/JWK, RSA & ECDSA via WebCrypto, SSH keys.
import { utf8, fromUtf8, hexToBytes, bytesToHex, bytesToBase64, base64ToBytes, select, opt } from "./util.js";

export const OIDS = {
  "1.2.840.113549.1.1.1": "rsaEncryption", "1.2.840.113549.1.1.5": "sha1WithRSAEncryption", "1.2.840.113549.1.1.11": "sha256WithRSAEncryption", "1.2.840.113549.1.1.12": "sha384WithRSAEncryption", "1.2.840.113549.1.1.13": "sha512WithRSAEncryption", "1.2.840.113549.1.1.10": "RSASSA-PSS",
  "1.2.840.10045.2.1": "ecPublicKey", "1.2.840.10045.4.3.2": "ecdsa-with-SHA256", "1.2.840.10045.4.3.3": "ecdsa-with-SHA384", "1.2.840.10045.4.3.4": "ecdsa-with-SHA512", "1.2.840.10045.3.1.7": "prime256v1 (P-256)", "1.3.132.0.34": "secp384r1 (P-384)", "1.3.132.0.35": "secp521r1 (P-521)", "1.3.132.0.10": "secp256k1",
  "1.3.101.112": "Ed25519", "1.3.101.113": "Ed448", "1.3.101.110": "X25519",
  "2.5.4.3": "CN", "2.5.4.6": "C", "2.5.4.7": "L", "2.5.4.8": "ST", "2.5.4.10": "O", "2.5.4.11": "OU", "2.5.4.5": "serialNumber", "1.2.840.113549.1.9.1": "emailAddress", "0.9.2342.19200300.100.1.25": "DC",
  "2.5.29.14": "subjectKeyIdentifier", "2.5.29.15": "keyUsage", "2.5.29.17": "subjectAltName", "2.5.29.19": "basicConstraints", "2.5.29.31": "cRLDistributionPoints", "2.5.29.32": "certificatePolicies", "2.5.29.35": "authorityKeyIdentifier", "2.5.29.37": "extKeyUsage", "2.5.29.20": "cRLNumber",
  "1.3.6.1.5.5.7.1.1": "authorityInfoAccess", "1.3.6.1.4.1.11129.2.4.2": "CT precertificate SCTs", "1.3.6.1.5.5.7.48.1": "OCSP", "1.3.6.1.5.5.7.48.2": "caIssuers",
  "1.3.6.1.5.5.7.3.1": "serverAuth", "1.3.6.1.5.5.7.3.2": "clientAuth", "1.3.6.1.5.5.7.3.3": "codeSigning", "1.3.6.1.5.5.7.3.4": "emailProtection", "1.3.6.1.5.5.7.3.8": "timeStamping", "1.3.6.1.5.5.7.3.9": "OCSPSigning",
  "1.2.840.113549.1.9.14": "extensionRequest", "2.23.140.1.2.1": "DV certificate", "2.23.140.1.2.2": "OV certificate", "2.23.140.1.1": "EV certificate",
};
const TAGS = { 1: "BOOLEAN", 2: "INTEGER", 3: "BIT STRING", 4: "OCTET STRING", 5: "NULL", 6: "OBJECT IDENTIFIER", 10: "ENUMERATED", 12: "UTF8String", 16: "SEQUENCE", 17: "SET", 19: "PrintableString", 20: "T61String", 22: "IA5String", 23: "UTCTime", 24: "GeneralizedTime", 30: "BMPString" };

// ---------- DER ----------
export function parseDer(b, off = 0, end = b.length, depth = 0) {
  const nodes = [];
  while (off < end) {
    if (depth > 40) throw new Error("ASN.1 nesting too deep");
    const start = off; const t = b[off++]; let tag = t & 0x1f; if (tag === 0x1f) { tag = 0; let x; do { x = b[off++]; tag = tag * 128 + (x & 0x7f); } while (x & 0x80); }
    let len = b[off++]; if (len === undefined) throw new Error("Truncated ASN.1");
    if (len & 0x80) { const n = len & 0x7f; if (n === 0 || n > 4) throw new Error("Unsupported ASN.1 length"); len = 0; for (let i = 0; i < n; i++) len = len * 256 + b[off++]; }
    if (off + len > end) throw new Error(`ASN.1 length exceeds data at offset ${start}`);
    const node = { cls: t >> 6, constructed: !!(t & 0x20), tag, start, hdr: off - start, len, value: b.subarray(off, off + len) };
    if (node.constructed) node.children = parseDer(b, off, off + len, depth + 1);
    else if (node.cls === 0 && (tag === 3 || tag === 4) && len > 1) { try { const inner = tag === 3 ? b.subarray(off + 1, off + len) : node.value; if (inner[0] === 0x30 && inner.length > 2) { const c = parseDer(inner, 0, inner.length, depth + 1); if (c.length && c[0].start === 0 && c.at(-1).start + c.at(-1).hdr + c.at(-1).len === inner.length) node.encapsulated = c; } } catch { /* not encapsulated */ } }
    nodes.push(node); off += len;
  }
  return nodes;
}
export function oidToString(v) { const out = [Math.floor(v[0] / 40), v[0] % 40]; let n = 0; for (let i = 1; i < v.length; i++) { n = n * 128 + (v[i] & 0x7f); if (!(v[i] & 0x80)) { out.push(n); n = 0; } } if (v[0] >= 80) { out[0] = 2; out[1] = v[0] - 80; } return out.join("."); }
export function oidToBytes(s) { const p = s.trim().split(".").map(Number); if (p.length < 2 || p.some((x) => !Number.isInteger(x) || x < 0)) throw new Error("Invalid OID"); const out = [p[0] * 40 + p[1]]; for (const n of p.slice(2)) { const g = []; let x = n; do { g.unshift(x & 0x7f); x = Math.floor(x / 128); } while (x > 0); out.push(...g.map((y, i) => (i < g.length - 1 ? y | 0x80 : y))); } return new Uint8Array(out); }
const bigHex = (v) => bytesToHex(v[0] === 0 && v.length > 1 ? v.subarray(1) : v);
function strVal(n) { if (n.tag === 30) { let s = ""; for (let i = 0; i < n.value.length; i += 2) s += String.fromCharCode((n.value[i] << 8) | n.value[i + 1]); return s; } return fromUtf8(n.value); }
function timeVal(n) { const s = fromUtf8(n.value); const m = n.tag === 23 ? s.match(/^(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?Z$/) : s.match(/^(\d{4})(\d\d)(\d\d)(\d\d)(\d\d)(\d\d)?/); if (!m) return s; const y = n.tag === 23 ? (+m[1] < 50 ? 2000 + +m[1] : 1900 + +m[1]) : +m[1]; return new Date(Date.UTC(y, +m[2] - 1, +m[3], +m[4], +m[5], +(m[6] || 0))).toISOString().replace(".000", ""); }
function describe(n) {
  if (n.cls !== 0) return n.constructed ? `[${n.tag}]` : `[${n.tag}] ${bytesToHex(n.value).slice(0, 64)}${/^[\x20-\x7e]+$/.test(fromUtf8(n.value)) ? `  "${fromUtf8(n.value)}"` : ""}`;
  const name = TAGS[n.tag] || `TAG ${n.tag}`; if (n.constructed) return name;
  if (n.tag === 6) { const o = oidToString(n.value); return `${name} ${o}${OIDS[o] ? ` (${OIDS[o]})` : ""}`; }
  if (n.tag === 2 || n.tag === 10) return `${name} ${n.len <= 6 ? BigInt("0x" + (bytesToHex(n.value) || "0")).toString() : "0x" + bigHex(n.value)}`;
  if (n.tag === 1) return `${name} ${n.value[0] ? "TRUE" : "FALSE"}`;
  if (n.tag === 5) return name;
  if ([12, 19, 20, 22, 30].includes(n.tag)) return `${name} "${strVal(n)}"`;
  if (n.tag === 23 || n.tag === 24) return `${name} ${timeVal(n)}`;
  return `${name} (${n.len} bytes) ${bytesToHex(n.value).slice(0, 96)}${n.len > 48 ? "…" : ""}`;
}
export function dumpAsn1(nodes, ind = "") { return nodes.map((n) => `${ind}${describe(n)}${n.children ? "\n" + dumpAsn1(n.children, ind + "  ") : ""}${n.encapsulated ? "\n" + ind + "  ↳ encapsulates:\n" + dumpAsn1(n.encapsulated, ind + "    ") : ""}`).join("\n"); }

// ---------- PEM ----------
export function pemDecode(text) { let r; try { r = pemDecodeRaw(text); } catch { throw new Error("Input is not valid PEM, base64 or hex"); } if (!r.der.length) throw new Error("No PEM, base64 or hex data found"); return r; }
function pemDecodeRaw(text) { const s = String(text).trim(); const m = s.match(/-----BEGIN ([A-Z0-9 ]+)-----([\s\S]*?)-----END \1-----/); if (m) return { label: m[1], der: base64ToBytes(m[2].replace(/[^A-Za-z0-9+/=]/g, "")) }; if (/^[0-9a-f\s:]+$/i.test(s)) return { label: null, der: hexToBytes(s) }; return { label: null, der: base64ToBytes(s) }; }
export const pemEncode = (label, der) => `-----BEGIN ${label}-----\n${bytesToBase64(der).match(/.{1,64}/g).join("\n")}\n-----END ${label}-----`;

// ---------- DER encode helpers ----------
const derLen = (n) => (n < 128 ? [n] : n < 256 ? [0x81, n] : n < 65536 ? [0x82, n >> 8, n & 255] : [0x83, n >> 16, (n >> 8) & 255, n & 255]);
const der = (tag, content) => new Uint8Array([tag, ...derLen(content.length), ...content]);
const seq = (...parts) => der(0x30, parts.flatMap((p) => [...p]));
const derInt = (b) => der(0x02, b[0] & 0x80 ? [0, ...b] : [...b]);
const derOid = (s) => der(0x06, [...oidToBytes(s)]);

// ---------- names, extensions, certificates ----------
const nameStr = (n) => (n.children || []).map((rdn) => rdn.children.map((atv) => { const o = oidToString(atv.children[0].value); return `${OIDS[o] || o}=${strVal(atv.children[1])}`; }).join("+")).join(", ");
function algName(seqNode) { const o = oidToString(seqNode.children[0].value); let s = OIDS[o] || o; if (seqNode.children[1]?.tag === 6) { const p = oidToString(seqNode.children[1].value); s += ` / ${OIDS[p] || p}`; } return s; }
function spkiInfo(spki) {
  const alg = spki.children[0]; const o = oidToString(alg.children[0].value); const key = spki.children[1].value.subarray(1);
  if (OIDS[o] === "rsaEncryption") { const k = parseDer(key)[0]; const mod = k.children[0].value; const bits = (mod[0] === 0 ? mod.length - 1 : mod.length) * 8; return `RSA ${bits}-bit, exponent ${BigInt("0x" + bytesToHex(k.children[1].value))}\n    modulus ${bigHex(mod).slice(0, 64)}…`; }
  if (OIDS[o] === "ecPublicKey") { const c = oidToString(alg.children[1].value); return `EC ${OIDS[c] || c}\n    point ${bytesToHex(key).slice(0, 66)}…`; }
  return `${OIDS[o] || o} ${bytesToHex(key)}`;
}
function extText(oid, valNode) {
  const v = valNode.encapsulated?.[0] || parseDer(valNode.value)[0]; const name = OIDS[oid];
  try {
    if (name === "subjectAltName") return v.children.map((g) => (g.tag === 2 ? `DNS:${fromUtf8(g.value)}` : g.tag === 7 ? `IP:${g.value.length === 4 ? [...g.value].join(".") : bytesToHex(g.value).match(/.{4}/g).join(":")}` : g.tag === 1 ? `email:${fromUtf8(g.value)}` : g.tag === 6 ? `URI:${fromUtf8(g.value)}` : `[${g.tag}]`)).join(", ");
    if (name === "basicConstraints") return `CA:${v.children?.[0]?.tag === 1 && v.children[0].value[0] ? "TRUE" : "FALSE"}${v.children?.find((c) => c.tag === 2) ? `, pathlen:${v.children.find((c) => c.tag === 2).value[0]}` : ""}`;
    if (name === "keyUsage") { const bits = v.value; const names = ["digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment", "keyAgreement", "keyCertSign", "cRLSign", "encipherOnly", "decipherOnly"]; return names.filter((_, i) => (bits[1 + (i >> 3)] >> (7 - (i & 7))) & 1).join(", "); }
    if (name === "extKeyUsage") return v.children.map((c) => OIDS[oidToString(c.value)] || oidToString(c.value)).join(", ");
    if (name === "subjectKeyIdentifier") return bytesToHex(v.value).match(/../g).join(":");
    if (name === "authorityKeyIdentifier") return bytesToHex(v.children.find((c) => c.tag === 0)?.value || new Uint8Array()).match(/../g)?.join(":") || "";
    if (name === "authorityInfoAccess") return v.children.map((ad) => `${OIDS[oidToString(ad.children[0].value)] || "?"}: ${fromUtf8(ad.children[1].value)}`).join("; ");
    if (name === "cRLDistributionPoints") { const urls = []; const walk = (n) => { if (n.cls === 2 && n.tag === 6 && !n.constructed) urls.push(fromUtf8(n.value)); (n.children || []).forEach(walk); }; walk(v); return urls.join(", "); }
    if (name === "certificatePolicies") return v.children.map((p) => { const o = oidToString(p.children[0].value); return OIDS[o] || o; }).join(", ");
  } catch { /* fall through */ }
  return `(${valNode.len} bytes)`;
}
function extensions(list) { return list.map((e) => { const oid = oidToString(e.children[0].value); const critical = e.children[1].tag === 1 && e.children[1].value[0]; const val = e.children.at(-1); return `  ${OIDS[oid] || oid}${critical ? " (critical)" : ""}: ${extText(oid, val)}`; }).join("\n"); }

export function parseCertificate(derBytes) {
  try { return parseCertificateRaw(derBytes); } catch { throw new Error("Not a valid X.509 certificate"); }
}
function parseCertificateRaw(derBytes) {
  const cert = parseDer(derBytes)[0]; const tbs = cert.children[0]; let i = 0; const f = tbs.children;
  const version = f[0].cls === 2 && f[0].tag === 0 ? f[i++].children[0].value[0] + 1 : 1;
  const serial = f[i++], sigAlg = f[i++], issuer = f[i++], validity = f[i++], subject = f[i++], spki = f[i++];
  const ext = f.slice(i).find((x) => x.cls === 2 && x.tag === 3);
  return { cert, tbs, version, serial: bigHex(serial.value), sigAlg: algName(sigAlg), issuer: nameStr(issuer), subject: nameStr(subject), notBefore: timeVal(validity.children[0]), notAfter: timeVal(validity.children[1]), spki, extensions: ext ? ext.children[0].children : [] };
}
async function sha(alg, b) { return bytesToHex(new Uint8Array(await crypto.subtle.digest(alg, b))); }
const spkiDer = (c, derBytes) => derBytes.subarray(c.spki.start, c.spki.start + c.spki.hdr + c.spki.len);

// ---------- WebCrypto key import ----------
function pkcs1ToPkcs8(rsaDer) { return seq(derInt([0]), seq(derOid("1.2.840.113549.1.1.1"), new Uint8Array([5, 0])), der(0x04, [...rsaDer])); }
function sec1ToPkcs8(ecDer) { const n = parseDer(ecDer)[0]; const params = n.children.find((c) => c.cls === 2 && c.tag === 0); if (!params) throw new Error("SEC1 key has no curve parameters"); const curve = oidToString(params.children[0].value); return seq(derInt([0]), seq(derOid("1.2.840.10045.2.1"), derOid(curve)), der(0x04, [...ecDer])); }
const CURVES = { "1.2.840.10045.3.1.7": "P-256", "1.3.132.0.34": "P-384", "1.3.132.0.35": "P-521" };
function keyInfo(pem) { try { return keyInfoRaw(pem); } catch (e) { throw new Error(/^(No PEM|Input is not|Not a valid)/.test(e.message) ? e.message : "Not a recognised PEM key or certificate (PKCS#8, PKCS#1, SEC1, SPKI or X.509)"); } }
function keyInfoRaw(pem) {
  let { label, der: d } = pemDecode(pem);
  if (label === "RSA PRIVATE KEY") return { format: "pkcs8", der: pkcs1ToPkcs8(d), kind: "RSA", private: true };
  if (label === "EC PRIVATE KEY") { const c = oidToString(parseDer(d)[0].children.find((x) => x.cls === 2 && x.tag === 0).children[0].value); return { format: "pkcs8", der: sec1ToPkcs8(d), kind: "EC", curve: CURVES[c], private: true }; }
  if (label === "RSA PUBLIC KEY") return { format: "spki", der: seq(seq(derOid("1.2.840.113549.1.1.1"), new Uint8Array([5, 0])), der(0x03, [0, ...d])), kind: "RSA", private: false };
  if (label === "CERTIFICATE") { const c = parseCertificate(d); d = spkiDer(c, d); label = "PUBLIC KEY"; }
  const top = parseDer(d)[0]; const isPriv = top.children[0].tag === 2; const alg = (isPriv ? top.children[1] : top.children[0]);
  const o = oidToString(alg.children[0].value); const kind = OIDS[o] === "rsaEncryption" ? "RSA" : OIDS[o] === "ecPublicKey" ? "EC" : OIDS[o] || o;
  return { format: isPriv ? "pkcs8" : "spki", der: d, kind, curve: kind === "EC" ? CURVES[oidToString(alg.children[1].value)] : undefined, private: isPriv };
}
async function importKey(pem, usage, alg) {
  const k = keyInfo(pem); let algo;
  if (k.kind === "RSA") algo = alg === "RSA-OAEP" ? { name: "RSA-OAEP", hash: "SHA-256" } : alg === "RSA-PSS" ? { name: "RSA-PSS", hash: "SHA-256" } : { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" };
  else if (k.kind === "EC") { if (!k.curve) throw new Error("Unsupported EC curve (WebCrypto supports P-256, P-384, P-521)"); algo = { name: "ECDSA", namedCurve: k.curve }; }
  else throw new Error(`Unsupported key type ${k.kind}`);
  return { key: await crypto.subtle.importKey(k.format, k.der, algo, true, usage), info: k };
}
const ecHash = (c) => ({ "P-256": "SHA-256", "P-384": "SHA-384", "P-521": "SHA-512" }[c]);

// ---------- SSH ----------
function sshParse(blob) { const out = []; let o = 0; while (o + 4 <= blob.length) { const n = new DataView(blob.buffer, blob.byteOffset + o).getUint32(0); out.push(blob.subarray(o + 4, o + 4 + n)); o += 4 + n; } return out; }

export const ops = {
  "parse-asn1": { name: "Parse ASN.1 hex string", run: (i) => dumpAsn1(parseDer(pemDecode(i).der)), placeholder: "Hex, base64 or PEM" },
  "parse-x509": { name: "Parse X.509 certificate", run: async (i) => { const d = pemDecode(i).der; const c = parseCertificate(d); const days = Math.round((new Date(c.notAfter) - Date.now()) / 864e5);
    return [`Version: ${c.version}`, `Serial: ${c.serial.match(/../g).join(":")}`, `Signature algorithm: ${c.sigAlg}`, `Issuer: ${c.issuer}`, `Subject: ${c.subject}`, `Valid from: ${c.notBefore}`, `Valid to: ${c.notAfter}  (${days >= 0 ? `${days} days left` : `expired ${-days} days ago`})`, `Public key: ${spkiInfo(c.spki)}`,
      `Self-signed: ${c.issuer === c.subject ? "yes" : "no"}`, `SHA-256 fingerprint: ${(await sha("SHA-256", d)).toUpperCase().match(/../g).join(":")}`, `SHA-1 fingerprint: ${(await sha("SHA-1", d)).toUpperCase().match(/../g).join(":")}`, `SPKI SHA-256 (pin): ${bytesToBase64(hexToBytes(await sha("SHA-256", spkiDer(c, d))))}`, c.extensions.length ? `Extensions:\n${extensions(c.extensions)}` : ""].filter(Boolean).join("\n"); }, placeholder: "-----BEGIN CERTIFICATE-----" },
  "parse-csr": { name: "Parse CSR", run: (i) => { try { return parseCsrText(i); } catch (e) { throw new Error(/^(No PEM|Input is not)/.test(e.message) ? e.message : "Not a valid PKCS#10 certificate request"); } } },
  "_csr_impl": { name: "", run: (i) => { const d = pemDecode(i).der; const r = parseDer(d)[0]; const info = r.children[0]; const [ver, subj, spki, attrs] = info.children;
    const extReq = attrs?.children?.find((a) => oidToString(a.children[0].value) === "1.2.840.113549.1.9.14");
    return [`Version: ${ver.value[0] + 1}`, `Subject: ${nameStr(subj)}`, `Public key: ${spkiInfo(spki)}`, `Signature algorithm: ${algName(r.children[1])}`, extReq ? `Requested extensions:\n${extensions(extReq.children[1].children[0].children)}` : ""].filter(Boolean).join("\n"); }, placeholder: "-----BEGIN CERTIFICATE REQUEST-----" },
  "parse-crl": { name: "Parse X.509 CRL", run: (i) => { try { return parseCrlText(i); } catch (e) { throw new Error(/^(No PEM|Input is not)/.test(e.message) ? e.message : "Not a valid X.509 CRL"); } } },
  "_crl_impl": { name: "", run: (i) => { const d = pemDecode(i).der; const t = parseDer(d)[0].children[0]; let k = 0; const f = t.children; if (f[0].tag === 2) k++;
    const sig = f[k++], issuer = f[k++], thisUp = f[k++]; const nextUp = f[k] && (f[k].tag === 23 || f[k].tag === 24) ? f[k++] : null; const revoked = f[k] && f[k].tag === 16 ? f[k].children : [];
    return [`Issuer: ${nameStr(issuer)}`, `Signature algorithm: ${algName(sig)}`, `This update: ${timeVal(thisUp)}`, `Next update: ${nextUp ? timeVal(nextUp) : "—"}`, `Revoked certificates: ${revoked.length}`, ...revoked.slice(0, 500).map((r) => `  ${bigHex(r.children[0].value)}  ${timeVal(r.children[1])}`)].join("\n"); }, placeholder: "-----BEGIN X509 CRL-----" },
  "oid-to-hex": { name: "Object Identifier to Hex", run: (i) => bytesToHex(oidToBytes(i)), placeholder: "1.2.840.113549.1.1.11" },
  "hex-to-oid": { name: "Hex to Object Identifier", run: (i) => { const b = hexToBytes(String(i).replace(/\s/g, "").replace(/^06[0-9a-f]{2}/i, "")); if (!b.length) throw new Error("Enter the OID's hex bytes"); const o = oidToString(b); return `${o}${OIDS[o] ? `  (${OIDS[o]})` : ""}`; }, placeholder: "2a864886f70d01010b" },
  "pem-to-hex": { name: "PEM to Hex", run: (i) => bytesToHex(pemDecode(i).der) },
  "hex-to-pem": { name: "Hex to PEM", run: (i, a) => { const b = hexToBytes(i); if (!b.length) throw new Error("Enter hex data"); return pemEncode(a.label, b); }, args: [opt("label", "Label", "text", { default: "CERTIFICATE" })] },
  "pubkey-from-cert": { name: "Public Key from Certificate", run: (i) => { const d = pemDecode(i).der; return pemEncode("PUBLIC KEY", spkiDer(parseCertificate(d), d)); } },
  "pubkey-from-private": { name: "Public Key from Private Key", run: async (i) => { const k = keyInfo(i); if (!k.private) throw new Error("That is not a private key"); const { key } = await importKey(i, ["sign"]); const jwk = await crypto.subtle.exportKey("jwk", key);
    const pubJwk = k.kind === "RSA" ? { kty: "RSA", n: jwk.n, e: jwk.e } : { kty: "EC", crv: jwk.crv, x: jwk.x, y: jwk.y }; const algo = k.kind === "RSA" ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } : { name: "ECDSA", namedCurve: jwk.crv };
    const pub = await crypto.subtle.importKey("jwk", pubJwk, algo, true, ["verify"]); return pemEncode("PUBLIC KEY", new Uint8Array(await crypto.subtle.exportKey("spki", pub))); }, placeholder: "-----BEGIN PRIVATE KEY----- (PKCS#8, PKCS#1 or SEC1)" },
  "pem-to-jwk": { name: "PEM to JWK", run: async (i) => { const k = keyInfo(i); const { key } = await importKey(i, k.private ? ["sign"] : ["verify"]); const jwk = await crypto.subtle.exportKey("jwk", key); delete jwk.key_ops; delete jwk.ext; delete jwk.alg; return JSON.stringify(jwk, null, 2); } },
  "jwk-to-pem": { name: "JWK to PEM", run: async (i) => { const jwk = JSON.parse(i); const priv = !!jwk.d; const algo = jwk.kty === "RSA" ? { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } : jwk.kty === "EC" ? { name: "ECDSA", namedCurve: jwk.crv } : null; if (!algo) throw new Error("Only RSA and EC JWKs are supported");
    const clean = { ...jwk }; delete clean.alg; delete clean.key_ops; delete clean.use; const key = await crypto.subtle.importKey("jwk", clean, algo, true, priv ? ["sign"] : ["verify"]); return pemEncode(priv ? "PRIVATE KEY" : "PUBLIC KEY", new Uint8Array(await crypto.subtle.exportKey(priv ? "pkcs8" : "spki", key))); } },
  "ecdsa-keygen": { name: "Generate ECDSA Key Pair", input: false, run: async (_, a) => { const kp = await crypto.subtle.generateKey({ name: "ECDSA", namedCurve: a.curve }, true, ["sign", "verify"]); return `${pemEncode("PUBLIC KEY", new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey)))}\n\n${pemEncode("PRIVATE KEY", new Uint8Array(await crypto.subtle.exportKey("pkcs8", kp.privateKey)))}`; }, args: [select("curve", "Curve", ["P-256", "P-384", "P-521"])] },
  "rsa-sign": { name: "RSA Sign", run: async (i, a) => { const { key } = await importKey(a.key, ["sign"], a.scheme); const sig = new Uint8Array(await crypto.subtle.sign(a.scheme === "RSA-PSS" ? { name: "RSA-PSS", saltLength: 32 } : "RSASSA-PKCS1-v1_5", key, utf8(i))); return a.format === "Base64" ? bytesToBase64(sig) : bytesToHex(sig); },
    args: [opt("key", "Private key (PEM)", "textarea"), select("scheme", "Scheme", ["RSASSA-PKCS1-v1_5", "RSA-PSS"]), select("format", "Signature format", ["Hex", "Base64"])], placeholder: "Message" },
  "rsa-verify": { name: "RSA Verify", run: async (i, a) => { const { key } = await importKey(a.key, ["verify"], a.scheme); const sig = /^[0-9a-f\s]+$/i.test(a.signature) ? hexToBytes(a.signature) : base64ToBytes(a.signature); return (await crypto.subtle.verify(a.scheme === "RSA-PSS" ? { name: "RSA-PSS", saltLength: 32 } : "RSASSA-PKCS1-v1_5", key, sig, utf8(i))) ? "✓ Signature VALID" : "✗ Signature INVALID"; },
    args: [opt("key", "Public key or certificate (PEM)", "textarea"), opt("signature", "Signature (hex or base64)", "textarea"), select("scheme", "Scheme", ["RSASSA-PKCS1-v1_5", "RSA-PSS"])], placeholder: "Message" },
  "rsa-encrypt": { name: "RSA Encrypt (OAEP)", run: async (i, a) => { const { key } = await importKey(a.key, ["encrypt"], "RSA-OAEP"); return bytesToBase64(new Uint8Array(await crypto.subtle.encrypt({ name: "RSA-OAEP" }, key, utf8(i)))); }, args: [opt("key", "Public key or certificate (PEM)", "textarea")], placeholder: "Plaintext" },
  "rsa-decrypt": { name: "RSA Decrypt (OAEP)", run: async (i, a) => { const { key } = await importKey(a.key, ["decrypt"], "RSA-OAEP"); try { return fromUtf8(new Uint8Array(await crypto.subtle.decrypt({ name: "RSA-OAEP" }, key, base64ToBytes(i)))); } catch { throw new Error("Decryption failed — wrong key or not RSA-OAEP/SHA-256 ciphertext"); } }, args: [opt("key", "Private key (PEM)", "textarea")], placeholder: "Base64 ciphertext" },
  "ecdsa-sign": { name: "ECDSA Sign", run: async (i, a) => { const { key, info } = await importKey(a.key, ["sign"]); const raw = new Uint8Array(await crypto.subtle.sign({ name: "ECDSA", hash: ecHash(info.curve) }, key, utf8(i))); return a.format === "DER" ? bytesToHex(rawToDer(raw)) : bytesToHex(raw); },
    args: [opt("key", "Private key (PEM)", "textarea"), select("format", "Signature format", ["DER", "Raw r||s (P1363)"])], placeholder: "Message" },
  "ecdsa-verify": { name: "ECDSA Verify", run: async (i, a) => { const { key, info } = await importKey(a.key, ["verify"]); let sig = hexToBytes(a.signature); if (sig[0] === 0x30) sig = derToRaw(sig, info.curve); return (await crypto.subtle.verify({ name: "ECDSA", hash: ecHash(info.curve) }, key, sig, utf8(i))) ? "✓ Signature VALID" : "✗ Signature INVALID"; },
    args: [opt("key", "Public key or certificate (PEM)", "textarea"), opt("signature", "Signature (hex, DER or raw)", "textarea")], placeholder: "Message" },
  "ecdsa-sig-convert": { name: "ECDSA Signature Conversion", run: (i, a) => { const b = hexToBytes(i); return b[0] === 0x30 ? `Raw r||s: ${bytesToHex(derToRaw(b, a.curve))}` : `DER: ${bytesToHex(rawToDer(b))}`; }, args: [select("curve", "Curve", ["P-256", "P-384", "P-521"])], placeholder: "DER or raw signature (hex)" },
  "parse-ssh-key": { name: "Parse SSH Host Key", run: async (i) => { const parts = String(i).trim().split(/\s+/); const b64 = parts.find((p) => /^AAAA/.test(p)) || parts[0]; const blob = base64ToBytes(b64); const f = sshParse(blob); const type = fromUtf8(f[0]);
    let detail = ""; if (type === "ssh-rsa") { const n = f[2][0] === 0 ? f[2].length - 1 : f[2].length; detail = `RSA ${n * 8}-bit, exponent ${BigInt("0x" + bytesToHex(f[1]))}`; } else if (type.startsWith("ecdsa-sha2-")) detail = `ECDSA ${fromUtf8(f[1])}, point ${bytesToHex(f[2]).slice(0, 40)}…`; else if (type === "ssh-ed25519") detail = `Ed25519 public key ${bytesToHex(f[1])}`;
    const sha256 = bytesToBase64(new Uint8Array(await crypto.subtle.digest("SHA-256", blob))).replace(/=+$/, ""); const { md5 } = await import("./hashing.js");
    return `Type: ${type}\n${detail}\nComment: ${parts.slice(parts.indexOf(b64) + 1).join(" ") || "(none)"}\nFingerprint SHA256:${sha256}\nFingerprint MD5:${bytesToHex(md5(blob)).match(/../g).join(":")}`; }, placeholder: "ssh-ed25519 AAAAC3Nza... user@host" },
};
function rawToDer(raw) { const h = raw.length / 2; const int = (b) => { let i = 0; while (i < b.length - 1 && b[i] === 0) i++; b = b.subarray(i); return derInt(b); }; return seq(int(raw.subarray(0, h)), int(raw.subarray(h))); }
function derToRaw(d, curve) { const n = { "P-256": 32, "P-384": 48, "P-521": 66 }[curve] || 32; const s = parseDer(d)[0]; const out = new Uint8Array(n * 2); [0, 1].forEach((k) => { let v = s.children[k].value; if (v.length > n) v = v.subarray(v.length - n); out.set(v, k * n + n - v.length); }); return out; }
const parseCsrText = (i) => ops._csr_impl.run(i); const parseCrlText = (i) => ops._crl_impl.run(i);
delete ops._csr_impl.name; Object.defineProperty(ops, "_csr_impl", { enumerable: false }); Object.defineProperty(ops, "_crl_impl", { enumerable: false });
export { keyInfo, spkiDer };
