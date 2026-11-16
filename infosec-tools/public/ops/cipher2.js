// Phase 2 ciphers: stream ciphers, TEA family, classical ciphers, brute-forcers, KDFs.
import { utf8, fromUtf8, hexToBytes, bytesToHex, bytesToBase64, base64ToBytes, parseBytes, select, opt } from "./util.js";

const keyArgs = (def = "secret") => [opt("key", "Key", "text", { default: def }), select("keyEncoding", "Key format", ["utf8", "hex", "base64"])];
const ioArgs = [select("inputEncoding", "Input format", ["utf8", "hex", "base64"]), select("output", "Output format", ["hex", "base64", "utf8"])];
const decodeIn = (i, e) => (e === "hex" ? hexToBytes(i) : e === "base64" ? base64ToBytes(i) : utf8(i));
const encodeOut = (b, e) => (e === "base64" ? bytesToBase64(b) : e === "utf8" ? fromUtf8(b) : bytesToHex(b));

// ---------- RC4 ----------
function rc4(key, data, drop = 0, ksaRounds = 1) {
  if (!key.length) throw new Error("Key is empty");
  const S = Array.from({ length: 256 }, (_, i) => i); let j = 0;
  for (let r = 0; r < ksaRounds; r++) for (let i = 0; i < 256; i++) { j = (j + S[i] + key[i % key.length]) & 255; [S[i], S[j]] = [S[j], S[i]]; }
  let i = 0; j = 0; const next = () => { i = (i + 1) & 255; j = (j + S[i]) & 255; [S[i], S[j]] = [S[j], S[i]]; return S[(S[i] + S[j]) & 255]; };
  for (let k = 0; k < drop; k++) next();
  return data.map((b) => b ^ next());
}

// ---------- ChaCha20 / Salsa20 (RFC 8439, Bernstein) ----------
const rotl = (x, n) => (x << n) | (x >>> (32 - n));
const words = (b) => { const dv = new DataView(b.buffer, b.byteOffset, b.byteLength); return Array.from({ length: b.length / 4 }, (_, i) => dv.getUint32(i * 4, true)); };
function chachaBlock(key, counter, nonce, rounds = 20) {
  const s = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574, ...words(key), counter >>> 0, ...words(nonce)]; const x = s.slice();
  const qr = (a, b, c, d) => { x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 16); x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 12); x[a] = (x[a] + x[b]) | 0; x[d] = rotl(x[d] ^ x[a], 8); x[c] = (x[c] + x[d]) | 0; x[b] = rotl(x[b] ^ x[c], 7); };
  for (let r = 0; r < rounds; r += 2) { qr(0, 4, 8, 12); qr(1, 5, 9, 13); qr(2, 6, 10, 14); qr(3, 7, 11, 15); qr(0, 5, 10, 15); qr(1, 6, 11, 12); qr(2, 7, 8, 13); qr(3, 4, 9, 14); }
  const out = new Uint8Array(64), dv = new DataView(out.buffer); for (let i = 0; i < 16; i++) dv.setUint32(i * 4, (x[i] + s[i]) >>> 0, true); return out;
}
function salsaCore(input, rounds = 20) {
  const x = input.slice();
  const qr = (a, b, c, d) => { x[b] ^= rotl((x[a] + x[d]) | 0, 7); x[c] ^= rotl((x[b] + x[a]) | 0, 9); x[d] ^= rotl((x[c] + x[b]) | 0, 13); x[a] ^= rotl((x[d] + x[c]) | 0, 18); };
  for (let r = 0; r < rounds; r += 2) { qr(0, 4, 8, 12); qr(5, 9, 13, 1); qr(10, 14, 2, 6); qr(15, 3, 7, 11); qr(0, 1, 2, 3); qr(5, 6, 7, 4); qr(10, 11, 8, 9); qr(15, 12, 13, 14); }
  return x;
}
function salsaBlock(key, nonce8, counter, rounds = 20) {
  const k = words(key.length === 16 ? new Uint8Array([...key, ...key]) : key); const c = key.length === 16 ? [0x61707865, 0x3120646e, 0x79622d36, 0x6b206574] : [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
  const n = words(nonce8); const ctr = [counter >>> 0, Math.floor(counter / 2 ** 32) >>> 0];
  const s = [c[0], k[0], k[1], k[2], k[3], c[1], n[0], n[1], ctr[0], ctr[1], c[2], k[4], k[5], k[6], k[7], c[3]];
  const x = salsaCore(s, rounds); const out = new Uint8Array(64), dv = new DataView(out.buffer); for (let i = 0; i < 16; i++) dv.setUint32(i * 4, (x[i] + s[i]) >>> 0, true); return out;
}
function hsalsa(key, nonce16) {
  const k = words(key), n = words(nonce16);
  const x = salsaCore([0x61707865, k[0], k[1], k[2], k[3], 0x3320646e, n[0], n[1], n[2], n[3], 0x79622d32, k[4], k[5], k[6], k[7], 0x6b206574]);
  const out = new Uint8Array(32), dv = new DataView(out.buffer); [0, 5, 10, 15, 6, 7, 8, 9].forEach((w, i) => dv.setUint32(i * 4, x[w] >>> 0, true)); return out;
}
function streamXor(data, blockFn) { const out = new Uint8Array(data.length); for (let off = 0, n = 0; off < data.length; off += 64, n++) { const ks = blockFn(n); for (let i = 0; i < 64 && off + i < data.length; i++) out[off + i] = data[off + i] ^ ks[i]; } return out; }
const needLen = (b, lens, what) => { if (!lens.includes(b.length)) throw new Error(`${what} must be ${lens.join(" or ")} bytes (got ${b.length})`); return b; };

// ---------- TEA family ----------
const DELTA = 0x9e3779b9;
// TEA/XTEA use big-endian 32-bit words for both key and blocks (the reference convention).
function teaBlocks(data, key, fn) {
  const kd = new DataView(needLen(key, [16], "Key").buffer, key.byteOffset); const k = [0, 1, 2, 3].map((i) => kd.getUint32(i * 4, false));
  if (data.length % 8) throw new Error("Input must be a multiple of 8 bytes");
  const out = new Uint8Array(data); const dv = new DataView(out.buffer);
  for (let off = 0; off < out.length; off += 8) { const [y, z] = fn(dv.getUint32(off, false), dv.getUint32(off + 4, false), k); dv.setUint32(off, y >>> 0, false); dv.setUint32(off + 4, z >>> 0, false); }
  return out;
}
const teaE = (v0, v1, k) => { let s = 0; for (let i = 0; i < 32; i++) { s = (s + DELTA) | 0; v0 = (v0 + ((((v1 << 4) + k[0]) ^ (v1 + s)) ^ ((v1 >>> 5) + k[1]))) | 0; v1 = (v1 + ((((v0 << 4) + k[2]) ^ (v0 + s)) ^ ((v0 >>> 5) + k[3]))) | 0; } return [v0, v1]; };
const teaD = (v0, v1, k) => { let s = (DELTA * 32) | 0; for (let i = 0; i < 32; i++) { v1 = (v1 - ((((v0 << 4) + k[2]) ^ (v0 + s)) ^ ((v0 >>> 5) + k[3]))) | 0; v0 = (v0 - ((((v1 << 4) + k[0]) ^ (v1 + s)) ^ ((v1 >>> 5) + k[1]))) | 0; s = (s - DELTA) | 0; } return [v0, v1]; };
const xteaE = (v0, v1, k) => { let s = 0; for (let i = 0; i < 32; i++) { v0 = (v0 + ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (s + k[s & 3]))) | 0; s = (s + DELTA) | 0; v1 = (v1 + ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (s + k[(s >>> 11) & 3]))) | 0; } return [v0, v1]; };
const xteaD = (v0, v1, k) => { let s = (DELTA * 32) | 0; for (let i = 0; i < 32; i++) { v1 = (v1 - ((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (s + k[(s >>> 11) & 3]))) | 0; s = (s - DELTA) | 0; v0 = (v0 - ((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (s + k[s & 3]))) | 0; } return [v0, v1]; };
function xxtea(data, key, decrypt) {
  if (data.length < 8 || data.length % 4) throw new Error("XXTEA needs a multiple of 4 bytes, at least 8 (use zero padding)");
  const v = new Uint32Array(data.length / 4); const dv = new DataView(data.buffer, data.byteOffset); for (let i = 0; i < v.length; i++) v[i] = dv.getUint32(i * 4, true);
  const kd = new DataView(needLen(key, [16], "Key").buffer, key.byteOffset); const k = [0, 1, 2, 3].map((i) => kd.getUint32(i * 4, true)); const n = v.length;
  const MX = (z, y, sum, p, e) => (((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (k[(p & 3) ^ e] ^ z));
  let rounds = 6 + Math.floor(52 / n), sum = decrypt ? (rounds * DELTA) >>> 0 : 0, y, z;
  if (!decrypt) { z = v[n - 1]; while (rounds-- > 0) { sum = (sum + DELTA) >>> 0; const e = (sum >>> 2) & 3; let p; for (p = 0; p < n - 1; p++) { y = v[p + 1]; z = v[p] = (v[p] + MX(z, y, sum, p, e)) >>> 0; } y = v[0]; z = v[n - 1] = (v[n - 1] + MX(z, y, sum, p, e)) >>> 0; } }
  else { y = v[0]; while (rounds-- > 0) { const e = (sum >>> 2) & 3; let p; for (p = n - 1; p > 0; p--) { z = v[p - 1]; y = v[p] = (v[p] - MX(z, y, sum, p, e)) >>> 0; } z = v[n - 1]; y = v[0] = (v[0] - MX(z, y, sum, p, e)) >>> 0; sum = (sum - DELTA) >>> 0; } }
  const out = new Uint8Array(data.length), ov = new DataView(out.buffer); v.forEach((x, i) => ov.setUint32(i * 4, x, true)); return out;
}
const pad8 = (b) => { const o = new Uint8Array(Math.ceil(b.length / 8) * 8 || 8); o.set(b); return o; };

// ---------- classical ----------
function railFence(s, rails, decode) {
  const n = s.length; const pattern = Array.from({ length: n }, (_, i) => { const c = 2 * (rails - 1) || 1; const m = i % c; return m < rails ? m : c - m; });
  if (!decode) return Array.from({ length: rails }, (_, r) => [...s].filter((_, i) => pattern[i] === r).join("")).join("");
  const order = [...pattern.keys()].sort((a, b) => pattern[a] - pattern[b] || a - b); const out = new Array(n); order.forEach((pos, k) => (out[pos] = s[k])); return out.join("");
}
function polybius(key) { const alpha = [...new Set((String(key).toUpperCase() + "ABCDEFGHIKLMNOPQRSTUVWXYZ").replace(/J/g, "I").replace(/[^A-Z]/g, ""))]; return alpha; }
function bifid(s, key, decode) {
  const sq = polybius(key); const t = String(s).toUpperCase().replace(/J/g, "I").replace(/[^A-Z]/g, ""); const pos = [...t].map((c) => sq.indexOf(c));
  if (!decode) { const rows = pos.map((p) => Math.floor(p / 5)), cols = pos.map((p) => p % 5); const all = [...rows, ...cols]; let o = ""; for (let i = 0; i < all.length; i += 2) o += sq[all[i] * 5 + all[i + 1]]; return o; }
  const flat = pos.flatMap((p) => [Math.floor(p / 5), p % 5]); const rows = flat.slice(0, t.length), cols = flat.slice(t.length); return rows.map((r, i) => sq[r * 5 + cols[i]]).join("");
}
// English plausibility: log-likelihood of letters under English frequencies, plus
// rewards for spaces and penalties for control/non-ASCII bytes.
const EN_FREQ = { a: 8.2, b: 1.5, c: 2.8, d: 4.3, e: 12.7, f: 2.2, g: 2.0, h: 6.1, i: 7.0, j: 0.15, k: 0.77, l: 4.0, m: 2.4, n: 6.7, o: 7.5, p: 1.9, q: 0.095, r: 6.0, s: 6.3, t: 9.1, u: 2.8, v: 0.98, w: 2.4, x: 0.15, y: 2.0, z: 0.074 };
function scoreEnglish(s) {
  let sc = 0; for (const c of s) { const k = c.charCodeAt(0); const f = EN_FREQ[c.toLowerCase()];
    if (f) sc += Math.log(f); else if (k === 32) sc += 2; else if (k === 10 || k === 13 || k === 9 || (k >= 33 && k <= 126)) sc -= 1; else sc -= 8; }
  return sc / (s.length || 1);
}

// ---------- scrypt (RFC 7914) ----------
async function pbkdf2(pass, salt, iter, len) { const k = await crypto.subtle.importKey("raw", pass, "PBKDF2", false, ["deriveBits"]); return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt, iterations: iter, hash: "SHA-256" }, k, len * 8)); }
function blockMix(B, r) { const X = B.slice((2 * r - 1) * 16, 2 * r * 16); const Y = new Uint32Array(B.length);
  for (let i = 0; i < 2 * r; i++) { for (let j = 0; j < 16; j++) X[j] ^= B[i * 16 + j]; const o = salsaCore(Array.from(X), 8); for (let j = 0; j < 16; j++) X[j] = (o[j] + X[j]) >>> 0; Y.set(X, (i % 2 ? r + (i >> 1) : i >> 1) * 16); } return Y; }
async function scrypt(pass, salt, N, r, p, len) {
  if (N < 2 || (N & (N - 1))) throw new Error("N must be a power of 2"); if (N * r > 2 ** 17) throw new Error("N·r too large for the browser (max 131072)");
  const B = await pbkdf2(pass, salt, 1, p * 128 * r);
  for (let i = 0; i < p; i++) {
    let X = new Uint32Array(B.buffer.slice(i * 128 * r, (i + 1) * 128 * r)); const V = new Array(N);
    for (let j = 0; j < N; j++) { V[j] = X; X = blockMix(X, r); }
    for (let j = 0; j < N; j++) { const k = X[(2 * r - 1) * 16] & (N - 1); const T = new Uint32Array(X.length); for (let m = 0; m < X.length; m++) T[m] = X[m] ^ V[k][m]; X = blockMix(T, r); }
    B.set(new Uint8Array(X.buffer), i * 128 * r);
  }
  return pbkdf2(pass, B, 1, len);
}

// ---------- misc ----------
async function hmac(hash, key, data) { const k = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash }, false, ["sign"]); return new Uint8Array(await crypto.subtle.sign("HMAC", k, data)); }
function isProbablePrime(n) {
  if (n < 2n) return false; for (const p of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) { if (n === p) return true; if (n % p === 0n) return false; }
  let d = n - 1n, s = 0; while (!(d & 1n)) { d >>= 1n; s++; }
  const mp = (b, e, m) => { let r = 1n; b %= m; while (e) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; e >>= 1n; } return r; };
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) { let x = mp(a, d, n); if (x === 1n || x === n - 1n) continue; let ok = false; for (let i = 1; i < s; i++) { x = (x * x) % n; if (x === n - 1n) { ok = true; break; } } if (!ok) return false; }
  return true;
}
// ROT8000: rotate within the BMP minus whitespace, controls, surrogates and private use.
const ROT8000_HIDDEN = [[0x0000, 0x0020], [0x007f, 0x00a0], [0x1680, 0x1680], [0x2000, 0x200a], [0x2028, 0x2029], [0x202f, 0x202f], [0x205f, 0x205f], [0x3000, 0x3000], [0xd800, 0xf8ff], [0xfe00, 0xfe0f], [0xfff0, 0xffff]];
let rot8000Table;
function rot8000Map() {
  if (rot8000Table) return rot8000Table;
  const valid = []; for (let c = 0; c <= 0xffff; c++) if (!ROT8000_HIDDEN.some(([lo, hi]) => c >= lo && c <= hi)) valid.push(c);
  const half = valid.length / 2; rot8000Table = new Map(valid.map((c, k) => [c, valid[(k + half) % valid.length]])); return rot8000Table;
}

export const ops = {
  rc4: { name: "RC4", run: (i, a) => encodeOut(rc4(parseBytes(a.key, a.keyEncoding), decodeIn(i, a.inputEncoding)), a.output), args: [...keyArgs("Key"), ...ioArgs] },
  "rc4-drop": { name: "RC4 Drop", run: (i, a) => encodeOut(rc4(parseBytes(a.key, a.keyEncoding), decodeIn(i, a.inputEncoding), Number(a.drop) || 0), a.output), args: [...keyArgs("Key"), opt("drop", "Bytes to drop", "number", { default: 768 }), ...ioArgs] },
  "ciphersaber2-encrypt": { name: "CipherSaber2 Encrypt", run: (i, a) => { const iv = crypto.getRandomValues(new Uint8Array(10)); const key = new Uint8Array([...utf8(a.key), ...iv]); return bytesToHex(new Uint8Array([...iv, ...rc4(key, utf8(i), 0, Math.max(1, Number(a.rounds) || 20))])); }, args: [opt("key", "Key", "text", { default: "asdfg" }), opt("rounds", "Rounds", "number", { default: 20 })] },
  "ciphersaber2-decrypt": { name: "CipherSaber2 Decrypt", run: (i, a) => { const b = hexToBytes(i); const key = new Uint8Array([...utf8(a.key), ...b.slice(0, 10)]); return fromUtf8(rc4(key, b.slice(10), 0, Math.max(1, Number(a.rounds) || 20))); }, args: [opt("key", "Key", "text", { default: "asdfg" }), opt("rounds", "Rounds", "number", { default: 20 })], placeholder: "Hex ciphertext (10-byte IV first)" },
  chacha20: { name: "ChaCha20", run: (i, a) => { const key = needLen(parseBytes(a.key, a.keyEncoding), [32], "Key"); const nonce = needLen(hexToBytes(a.nonce), [12], "Nonce"); return encodeOut(streamXor(decodeIn(i, a.inputEncoding), (n) => chachaBlock(key, (Number(a.counter) || 0) + n, nonce, Number(a.rounds))), a.output); },
    args: [opt("key", "Key (32 bytes)", "text", { default: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f" }), select("keyEncoding", "Key format", ["hex", "utf8", "base64"]), opt("nonce", "Nonce (12 bytes hex)", "text", { default: "000000000000004a00000000" }), opt("counter", "Initial counter", "number", { default: 1 }), select("rounds", "Rounds", ["20", "12", "8"]), ...ioArgs] },
  salsa20: { name: "Salsa20", run: (i, a) => { const key = needLen(parseBytes(a.key, a.keyEncoding), [16, 32], "Key"); const nonce = needLen(hexToBytes(a.nonce), [8], "Nonce"); return encodeOut(streamXor(decodeIn(i, a.inputEncoding), (n) => salsaBlock(key, nonce, (Number(a.counter) || 0) + n, Number(a.rounds))), a.output); },
    args: [opt("key", "Key (16 or 32 bytes)", "text", { default: "0000000000000000000000000000000000000000000000000000000000000000" }), select("keyEncoding", "Key format", ["hex", "utf8", "base64"]), opt("nonce", "Nonce (8 bytes hex)", "text", { default: "0000000000000000" }), opt("counter", "Initial counter", "number", { default: 0 }), select("rounds", "Rounds", ["20", "12", "8"]), ...ioArgs] },
  xsalsa20: { name: "XSalsa20", run: (i, a) => { const key = needLen(parseBytes(a.key, a.keyEncoding), [32], "Key"); const nonce = needLen(hexToBytes(a.nonce), [24], "Nonce"); const sub = hsalsa(key, nonce.slice(0, 16)); return encodeOut(streamXor(decodeIn(i, a.inputEncoding), (n) => salsaBlock(sub, nonce.slice(16), (Number(a.counter) || 0) + n)), a.output); },
    args: [opt("key", "Key (32 bytes)", "text", { default: "" }), select("keyEncoding", "Key format", ["hex", "utf8", "base64"]), opt("nonce", "Nonce (24 bytes hex)", "text", { default: "" }), opt("counter", "Initial counter", "number", { default: 0 }), ...ioArgs] },
  "tea-encrypt": { name: "TEA Encrypt (ECB)", run: (i, a) => encodeOut(teaBlocks(pad8(decodeIn(i, a.inputEncoding)), parseBytes(a.key, a.keyEncoding), teaE), a.output), args: [...keyArgs("0123456789abcdef"), ...ioArgs] },
  "tea-decrypt": { name: "TEA Decrypt (ECB)", run: (i, a) => encodeOut(teaBlocks(decodeIn(i, a.inputEncoding), parseBytes(a.key, a.keyEncoding), teaD), a.output), args: [...keyArgs("0123456789abcdef"), select("inputEncoding", "Input format", ["hex", "base64"]), select("output", "Output format", ["utf8", "hex", "base64"])] },
  "xtea-encrypt": { name: "XTEA Encrypt (ECB)", run: (i, a) => encodeOut(teaBlocks(pad8(decodeIn(i, a.inputEncoding)), parseBytes(a.key, a.keyEncoding), xteaE), a.output), args: [...keyArgs("0123456789abcdef"), ...ioArgs] },
  "xtea-decrypt": { name: "XTEA Decrypt (ECB)", run: (i, a) => encodeOut(teaBlocks(decodeIn(i, a.inputEncoding), parseBytes(a.key, a.keyEncoding), xteaD), a.output), args: [...keyArgs("0123456789abcdef"), select("inputEncoding", "Input format", ["hex", "base64"]), select("output", "Output format", ["utf8", "hex", "base64"])] },
  "xxtea-encrypt": { name: "XXTEA Encrypt", run: (i, a) => { const d = decodeIn(i, a.inputEncoding); const p = new Uint8Array(Math.max(8, Math.ceil(d.length / 4) * 4)); p.set(d); return encodeOut(xxtea(p, parseBytes(a.key, a.keyEncoding), false), a.output); }, args: [...keyArgs("0123456789abcdef"), ...ioArgs] },
  "xxtea-decrypt": { name: "XXTEA Decrypt", run: (i, a) => encodeOut(xxtea(decodeIn(i, a.inputEncoding), parseBytes(a.key, a.keyEncoding), true), a.output), args: [...keyArgs("0123456789abcdef"), select("inputEncoding", "Input format", ["hex", "base64"]), select("output", "Output format", ["utf8", "hex", "base64"])] },
  "rail-fence-encode": { name: "Rail Fence Cipher Encode", run: (i, a) => railFence(String(i), Math.max(2, Number(a.rails) || 3), false), args: [opt("rails", "Rails", "number", { default: 3 })] },
  "rail-fence-decode": { name: "Rail Fence Cipher Decode", run: (i, a) => railFence(String(i), Math.max(2, Number(a.rails) || 3), true), args: [opt("rails", "Rails", "number", { default: 3 })] },
  "bifid-encode": { name: "Bifid Cipher Encode", run: (i, a) => bifid(i, a.key, false), args: [opt("key", "Keyword", "text", { default: "" })] },
  "bifid-decode": { name: "Bifid Cipher Decode", run: (i, a) => bifid(i, a.key, true), args: [opt("key", "Keyword", "text", { default: "" })] },
  "caesar-box": { name: "Caesar Box Cipher", run: (i, a) => { const s = String(i).replace(/\s/g, ""); const h = Math.max(1, Number(a.height) || 1); const w = Math.ceil(s.length / h); let o = ""; for (let c = 0; c < w; c++) for (let r = 0; r < h; r++) o += s[r * w + c] ?? ""; return o; }, args: [opt("height", "Box height", "number", { default: 1 })] },
  substitute: { name: "Substitute", run: (i, a) => { const from = [...String(a.plaintext)], to = [...String(a.ciphertext)]; const m = new Map(from.map((c, k) => [c, to[k] ?? c])); return [...String(i)].map((c) => m.get(c) ?? c).join(""); }, args: [opt("plaintext", "Plaintext alphabet", "text", { default: "ABCDEFGHIJKLMNOPQRSTUVWXYZ" }), opt("ciphertext", "Ciphertext alphabet", "text", { default: "XYZABCDEFGHIJKLMNOPQRSTUVW" })] },
  "cetacean-encode": { name: "Cetacean Cipher Encode", run: (i) => [...String(i)].map((c) => c.charCodeAt(0).toString(2).padStart(16, "0").replace(/0/g, "e").replace(/1/g, "E")).join(" ") },
  "cetacean-decode": { name: "Cetacean Cipher Decode", run: (i) => (String(i).match(/[eE]{16}/g) || []).map((w) => String.fromCharCode(parseInt(w.replace(/e/g, "0").replace(/E/g, "1"), 2))).join("") },
  rot8000: { name: "ROT8000", run: (i) => { const m = rot8000Map(); return [...String(i)].map((ch) => { const v = m.get(ch.codePointAt(0)); return v === undefined ? ch : String.fromCharCode(v); }).join(""); } },
  "rot13-brute": { name: "ROT13 Brute Force", run: (i) => { const s = String(i); return Array.from({ length: 25 }, (_, n) => n + 1).map((n) => { const t = s.replace(/[a-z]/gi, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((c.charCodeAt(0) - b + n) % 26) + b); }); return [scoreEnglish(t), `${String(n).padStart(2)}: ${t}`]; }).sort((x, y) => y[0] - x[0]).map((x) => x[1]).join("\n"); } },
  "rot47-brute": { name: "ROT47 Brute Force", run: (i) => { const s = String(i); return Array.from({ length: 93 }, (_, n) => n + 1).map((n) => { const t = s.replace(/[!-~]/g, (c) => String.fromCharCode(33 + ((c.charCodeAt(0) - 33 + n) % 94))); return [scoreEnglish(t), `${String(n).padStart(2)}: ${t}`]; }).sort((x, y) => y[0] - x[0]).slice(0, 20).map((x) => x[1]).join("\n"); } },
  "xor-brute": { name: "XOR Brute Force (single byte)", run: (i, a) => { const d = decodeIn(i, a.inputEncoding); return Array.from({ length: 255 }, (_, k) => k + 1).map((k) => { const t = fromUtf8(d.map((b) => b ^ k)); return [scoreEnglish(t), `0x${k.toString(16).padStart(2, "0")}: ${t.slice(0, 120).replace(/[\x00-\x08\x0b-\x1f]/g, ".")}`]; }).sort((x, y) => y[0] - x[0]).slice(0, Number(a.top) || 10).map((x) => x[1]).join("\n"); }, args: [select("inputEncoding", "Input format", ["hex", "base64", "utf8"]), opt("top", "Show top N", "number", { default: 10 })] },
  hkdf: { name: "Derive HKDF key", run: async (i, a) => { const k = await crypto.subtle.importKey("raw", decodeIn(i, a.inputEncoding), "HKDF", false, ["deriveBits"]); return bytesToHex(new Uint8Array(await crypto.subtle.deriveBits({ name: "HKDF", hash: a.hash, salt: hexToBytes(a.salt || ""), info: utf8(a.info || "") }, k, (Number(a.length) || 32) * 8))); },
    args: [opt("salt", "Salt (hex)", "text"), opt("info", "Info", "text"), select("hash", "Hash", ["SHA-256", "SHA-384", "SHA-512", "SHA-1"]), opt("length", "Output length (bytes)", "number", { default: 32 }), select("inputEncoding", "Input key material format", ["hex", "utf8", "base64"])], placeholder: "Input key material" },
  "aes-key-wrap": { name: "AES Key Wrap", run: async (i, a) => { const kek = await crypto.subtle.importKey("raw", hexToBytes(a.kek), "AES-KW", false, ["wrapKey"]); const key = await crypto.subtle.importKey("raw", hexToBytes(i), { name: "AES-CBC" }, true, ["encrypt"]); return bytesToHex(new Uint8Array(await crypto.subtle.wrapKey("raw", key, kek, "AES-KW"))); },
    args: [opt("kek", "Key-encryption key (hex)", "text", { default: "000102030405060708090A0B0C0D0E0F" })], placeholder: "Key to wrap (hex, 16/24/32 bytes)" },
  "aes-key-unwrap": { name: "AES Key Unwrap", run: async (i, a) => { const kek = await crypto.subtle.importKey("raw", hexToBytes(a.kek), "AES-KW", false, ["unwrapKey"]); try { const k = await crypto.subtle.unwrapKey("raw", hexToBytes(i), kek, "AES-KW", "AES-CBC", true, ["encrypt"]); return bytesToHex(new Uint8Array(await crypto.subtle.exportKey("raw", k))); } catch { throw new Error("Unwrap failed: wrong KEK or corrupted data"); } },
    args: [opt("kek", "Key-encryption key (hex)", "text", { default: "000102030405060708090A0B0C0D0E0F" })], placeholder: "Wrapped key (hex)" },
  "fernet-encrypt": { name: "Fernet Encrypt", run: async (i, a) => { const k = base64ToBytes(a.key); needLen(k, [32], "Fernet key"); const iv = crypto.getRandomValues(new Uint8Array(16)); const ts = new Uint8Array(8); new DataView(ts.buffer).setBigUint64(0, BigInt(Math.floor(Date.now() / 1000)));
    const ek = await crypto.subtle.importKey("raw", k.slice(16), "AES-CBC", false, ["encrypt"]); const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, ek, utf8(i)));
    const body = new Uint8Array([0x80, ...ts, ...iv, ...ct]); const mac = await hmac("SHA-256", k.slice(0, 16), body); return bytesToBase64(new Uint8Array([...body, ...mac])).replace(/\+/g, "-").replace(/\//g, "_"); },
    args: [opt("key", "Fernet key (url-safe base64, 32 bytes)", "text", { default: "" })] },
  "fernet-decrypt": { name: "Fernet Decrypt", run: async (i, a) => { const k = base64ToBytes(a.key); needLen(k, [32], "Fernet key"); const t = base64ToBytes(String(i).trim()); if (t[0] !== 0x80) throw new Error("Not a Fernet token (bad version byte)");
    const body = t.slice(0, -32), mac = t.slice(-32); const expect = await hmac("SHA-256", k.slice(0, 16), body); if (bytesToHex(expect) !== bytesToHex(mac)) throw new Error("HMAC check failed — wrong key or tampered token");
    const ts = Number(new DataView(t.buffer, t.byteOffset + 1, 8).getBigUint64(0)); const dk = await crypto.subtle.importKey("raw", k.slice(16), "AES-CBC", false, ["decrypt"]);
    return `${fromUtf8(new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv: t.slice(9, 25) }, dk, t.slice(25, -32))))}\n\n(token created ${new Date(ts * 1000).toISOString()})`; }, args: [opt("key", "Fernet key (url-safe base64, 32 bytes)", "text", { default: "" })] },
  "fernet-key": { name: "Generate Fernet Key", input: false, run: () => bytesToBase64(crypto.getRandomValues(new Uint8Array(32))).replace(/\+/g, "-").replace(/\//g, "_") },
  "flask-session-decode": { name: "Flask Session Decode", run: async (i) => { let [payload] = String(i).trim().split("."); let compressed = false; if (payload.startsWith(".")) payload = payload.slice(1); if (String(i).trim().startsWith(".")) { compressed = true; payload = String(i).trim().slice(1).split(".")[0]; }
    let bytes = base64ToBytes(payload); if (compressed) { const ds = new DecompressionStream("deflate"); bytes = new Uint8Array(await new Response(new Blob([bytes]).stream().pipeThrough(ds)).arrayBuffer()); }
    const ts = String(i).trim().split(".").filter(Boolean)[1]; let when = ""; if (ts) { const b = base64ToBytes(ts); let n = 0; for (const x of b) n = n * 256 + x; when = `\n\nSigned at: ${new Date(n * 1000).toISOString()} (signature not verified)`; }
    return JSON.stringify(JSON.parse(fromUtf8(bytes)), null, 2) + when; } },
  "ctx1-encode": { name: "Citrix CTX1 Encode", run: (i) => { const s = utf8(String(i)); const b = []; for (const x of s) b.push(x, 0); let prev = 0; const out = []; for (let k = 0; k < b.length; k++) { const v = b[k] ^ prev ^ 0xa5; out.push(v); prev = v; } return out.map((v) => String.fromCharCode(0x41 + (v >> 4)) + String.fromCharCode(0x41 + (v & 15))).join(""); } },
  "ctx1-decode": { name: "Citrix CTX1 Decode", run: (i) => { const s = String(i).trim(); if (s.length % 4) throw new Error("CTX1 input length must be a multiple of 4"); const v = []; for (let k = 0; k < s.length; k += 2) v.push(((s.charCodeAt(k) - 0x41) << 4) | (s.charCodeAt(k + 1) - 0x41)); const out = v.map((x, k) => x ^ (k ? v[k - 1] : 0) ^ 0xa5); return String.fromCharCode(...out.filter((_, k) => k % 2 === 0)); } },
  scrypt: { name: "Scrypt", run: async (i, a) => bytesToHex(await scrypt(utf8(i), utf8(a.salt), Number(a.N), Number(a.r), Number(a.p), Number(a.length) || 64)), args: [opt("salt", "Salt", "text", { default: "NaCl" }), opt("N", "Cost N (power of 2)", "number", { default: 1024 }), opt("r", "Block size r", "number", { default: 8 }), opt("p", "Parallelism p", "number", { default: 1 }), opt("length", "Key length (bytes)", "number", { default: 64 })], placeholder: "Passphrase" },
  "prime-gen": { name: "Pseudo-Random Prime Generator", input: false, run: (_, a) => { const bits = Math.min(Math.max(Number(a.bits) || 64, 8), 1024); const out = []; for (let n = 0; n < Math.min(Number(a.count) || 1, 20); n++) { for (;;) { const b = crypto.getRandomValues(new Uint8Array(Math.ceil(bits / 8))); let x = 0n; for (const y of b) x = (x << 8n) | BigInt(y); x = (x >> BigInt(b.length * 8 - bits)) | (1n << BigInt(bits - 1)) | 1n; if (isProbablePrime(x)) { out.push(a.format === "Hex" ? x.toString(16) : x.toString()); break; } } } return out.join("\n"); },
    args: [opt("bits", "Bits", "number", { default: 64 }), opt("count", "How many", "number", { default: 3 }), select("format", "Format", ["Decimal", "Hex"])] },
  "is-prime": { name: "Primality Test", run: (i) => String(i).split(/[\s,]+/).filter(Boolean).map((t) => { const n = BigInt(t); return `${t}: ${isProbablePrime(n) ? "prime" : "composite"}`; }).join("\n") },
  hotp: { name: "Generate HOTP", input: false, run: async (_, a) => { const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, v = 0; const key = []; for (const c of String(a.secret).toUpperCase().replace(/[=\s]/g, "")) { const i = B32.indexOf(c); if (i < 0) throw new Error("Secret must be Base32"); v = (v << 5) | i; bits += 5; if (bits >= 8) { key.push((v >>> (bits - 8)) & 255); bits -= 8; } }
    const out = []; for (let c = Number(a.counter); c < Number(a.counter) + Math.min(Number(a.count) || 1, 50); c++) { const msg = new Uint8Array(8); new DataView(msg.buffer).setBigUint64(0, BigInt(c)); const h = await hmac("SHA-1", new Uint8Array(key), msg); const o = h[19] & 15; const code = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 10 ** Number(a.digits); out.push(`${String(c).padStart(4)}: ${String(code).padStart(Number(a.digits), "0")}`); } return out.join("\n"); },
    args: [opt("secret", "Base32 secret", "text", { default: "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ" }), opt("counter", "Counter", "number", { default: 0 }), opt("count", "How many codes", "number", { default: 5 }), select("digits", "Digits", ["6", "8"])] },
};
