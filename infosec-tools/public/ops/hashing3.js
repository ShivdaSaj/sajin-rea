// Phase 3 digests: SHA-0, SM3, Whirlpool, BLAKE3, LM hash, Argon2 (RFC 9106), SSDEEP/CTPH.
import { utf8, hexToBytes, bytesToHex, bytesToBase64, select, opt } from "./util.js";
import { blake2b } from "./hashing2.js";
import { desEncryptBlock } from "./blocks.js";

const inputOpt = select("inputEncoding", "Input format", ["utf8", "hex"]);
const inp = (i, a) => (a.inputEncoding === "hex" ? hexToBytes(i) : utf8(i));
const rotl = (x, n) => ((x << n) | (x >>> (32 - n))) >>> 0;
function mdPad(bytes, bigEndian = true) { const len = bytes.length, padLen = ((len + 8) >>> 6 << 6) + 64; const m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80; const dv = new DataView(m.buffer); const bits = BigInt(len) * 8n; dv.setUint32(padLen - 8, Number(bits >> 32n), !bigEndian ? true : false); dv.setUint32(padLen - 4, Number(bits & 0xffffffffn), !bigEndian ? true : false); return { m, dv, padLen }; }

// ---------- SHA-0 ----------
export function sha0(bytes) { const { dv, padLen } = mdPad(bytes); let h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476, 0xc3d2e1f0];
  for (let o = 0; o < padLen; o += 64) { const w = new Array(80); for (let i = 0; i < 16; i++) w[i] = dv.getUint32(o + i * 4); for (let i = 16; i < 80; i++) w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]) >>> 0; // SHA-0: no rotate here
    let [a, b, c, d, e] = h; for (let i = 0; i < 80; i++) { const [f, k] = i < 20 ? [(b & c) | (~b & d), 0x5a827999] : i < 40 ? [b ^ c ^ d, 0x6ed9eba1] : i < 60 ? [(b & c) | (b & d) | (c & d), 0x8f1bbcdc] : [b ^ c ^ d, 0xca62c1d6]; const t = (rotl(a, 5) + f + e + k + w[i]) >>> 0; e = d; d = c; c = rotl(b, 30); b = a; a = t; }
    h = h.map((x, i) => (x + [a, b, c, d, e][i]) >>> 0); }
  const out = new Uint8Array(20), ov = new DataView(out.buffer); h.forEach((x, i) => ov.setUint32(i * 4, x)); return out; }

// ---------- SM3 (GB/T 32905) ----------
export function sm3(bytes) { const { dv, padLen } = mdPad(bytes); let V = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e];
  const P0 = (x) => (x ^ rotl(x, 9) ^ rotl(x, 17)) >>> 0, P1 = (x) => (x ^ rotl(x, 15) ^ rotl(x, 23)) >>> 0;
  for (let o = 0; o < padLen; o += 64) { const W = new Array(68); for (let i = 0; i < 16; i++) W[i] = dv.getUint32(o + i * 4); for (let i = 16; i < 68; i++) W[i] = (P1(W[i - 16] ^ W[i - 9] ^ rotl(W[i - 3], 15)) ^ rotl(W[i - 13], 7) ^ W[i - 6]) >>> 0; const W1 = Array.from({ length: 64 }, (_, i) => (W[i] ^ W[i + 4]) >>> 0);
    let [A, B, C, D, E, F, G, H] = V; for (let j = 0; j < 64; j++) { const T = j < 16 ? 0x79cc4519 : 0x7a879d8a; const SS1 = rotl((rotl(A, 12) + E + rotl(T, j % 32)) >>> 0, 7); const SS2 = (SS1 ^ rotl(A, 12)) >>> 0;
      const FF = j < 16 ? A ^ B ^ C : (A & B) | (A & C) | (B & C); const GG = j < 16 ? E ^ F ^ G : (E & F) | (~E & G); const TT1 = (FF + D + SS2 + W1[j]) >>> 0, TT2 = (GG + H + SS1 + W[j]) >>> 0; D = C; C = rotl(B, 9); B = A; A = TT1; H = G; G = rotl(F, 19); F = E; E = P0(TT2); }
    V = V.map((x, i) => (x ^ [A, B, C, D, E, F, G, H][i]) >>> 0); }
  const out = new Uint8Array(32), ov = new DataView(out.buffer); V.forEach((x, i) => ov.setUint32(i * 4, x)); return out; }

// ---------- Whirlpool (ISO/IEC 10118-3), tables generated from the mini-boxes ----------
let WP;
function whirlpoolTables() {
  if (WP) return WP; const E = [1, 0xb, 9, 0xc, 0xd, 6, 0xf, 3, 0xe, 8, 7, 4, 0xa, 2, 5, 0], R = [7, 0xc, 0xb, 0xd, 0xe, 4, 9, 0xf, 6, 3, 8, 0xa, 2, 5, 1, 0]; const Ei = E.map((_, i) => E.indexOf(i));
  const S = Array.from({ length: 256 }, (_, u) => { const l = E[u >> 4], r = Ei[u & 15]; const t = R[l ^ r]; return (E[l ^ t] << 4) | Ei[r ^ t]; });
  const mul = (a, b) => { let p = 0; for (let i = 0; i < 8; i++) { if (b & 1) p ^= a; const hi = a & 0x80; a = (a << 1) & 255; if (hi) a ^= 0x1d; b >>= 1; } return p; };
  const C = [1, 1, 4, 1, 8, 5, 2, 9]; const rc = Array.from({ length: 10 }, (_, r) => Array.from({ length: 64 }, (_, k) => (k < 8 ? S[8 * r + k] : 0)));
  WP = { S, mul, C, rc }; return WP;
}
// One round ρ[k] = σ[k] ∘ θ ∘ π ∘ γ on an 8×8 byte state (row-major).
function wpRound(state, key, { S, mul, C }) {
  const g = state.map((x) => S[x]);                                                          // γ: S-box
  const p = new Array(64); for (let i = 0; i < 8; i++) for (let j = 0; j < 8; j++) p[i * 8 + j] = g[((i - j + 8) % 8) * 8 + j]; // π: shift column j down by j
  const out = new Array(64); for (let i = 0; i < 8; i++) for (let j = 0; j < 8; j++) { let v = 0; for (let k = 0; k < 8; k++) v ^= mul(p[i * 8 + k], C[(j - k + 8) % 8]); out[i * 8 + j] = v ^ key[i * 8 + j]; } // θ: row × circulant, σ: add key
  return out;
}
export function whirlpool(bytes) {
  const T = whirlpoolTables(); const len = bytes.length; const padLen = Math.ceil((len + 33) / 64) * 64; const m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80;
  let bits = BigInt(len) * 8n; for (let i = padLen - 1; i >= padLen - 32 && bits > 0n; i--) { m[i] = Number(bits & 255n); bits >>= 8n; }
  let H = new Array(64).fill(0);
  for (let o = 0; o < padLen; o += 64) { const blk = Array.from(m.subarray(o, o + 64)); let K = H.slice(); let st = blk.map((x, i) => x ^ K[i]);
    for (let r = 0; r < 10; r++) { K = wpRound(K, T.rc[r], T); st = wpRound(st, K, T); } H = H.map((h, i) => h ^ st[i] ^ blk[i]); }
  return new Uint8Array(H);
}

// ---------- BLAKE3 ----------
const B3IV = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const B3P = [2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8];
const [CHUNK_START, CHUNK_END, PARENT, ROOT, KEYED_HASH] = [1, 2, 4, 8, 16];
function b3compress(cv, m, counter, blen, flags) {
  const v = [...cv, ...B3IV.slice(0, 4), counter >>> 0, Math.floor(counter / 2 ** 32) >>> 0, blen, flags]; let msg = m.slice(); const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  const G = (a, b, c, d, x, y) => { v[a] = (v[a] + v[b] + x) | 0; v[d] = rotr(v[d] ^ v[a], 16); v[c] = (v[c] + v[d]) | 0; v[b] = rotr(v[b] ^ v[c], 12); v[a] = (v[a] + v[b] + y) | 0; v[d] = rotr(v[d] ^ v[a], 8); v[c] = (v[c] + v[d]) | 0; v[b] = rotr(v[b] ^ v[c], 7); };
  for (let r = 0; r < 7; r++) { G(0, 4, 8, 12, msg[0], msg[1]); G(1, 5, 9, 13, msg[2], msg[3]); G(2, 6, 10, 14, msg[4], msg[5]); G(3, 7, 11, 15, msg[6], msg[7]); G(0, 5, 10, 15, msg[8], msg[9]); G(1, 6, 11, 12, msg[10], msg[11]); G(2, 7, 8, 13, msg[12], msg[13]); G(3, 4, 9, 14, msg[14], msg[15]); if (r < 6) msg = B3P.map((p) => msg[p]); }
  for (let i = 0; i < 8; i++) { v[i] = (v[i] ^ v[i + 8]) >>> 0; v[i + 8] = (v[i + 8] ^ cv[i]) >>> 0; } return v.map((x) => x >>> 0);
}
const words16 = (b) => { const p = new Uint8Array(64); p.set(b); const dv = new DataView(p.buffer); return Array.from({ length: 16 }, (_, i) => dv.getUint32(i * 4, true)); };
export function blake3(bytes, outLen = 32, key = null) {
  const kw = key ? Array.from({ length: 8 }, (_, i) => new DataView(key.buffer, key.byteOffset).getUint32(i * 4, true)) : B3IV; const base = key ? KEYED_HASH : 0;
  const chunks = Math.max(1, Math.ceil(bytes.length / 1024)); const stack = []; let rootNode = null;
  const chunkOut = (ci) => { const data = bytes.subarray(ci * 1024, ci * 1024 + 1024); let cv = kw.slice(); const nb = Math.max(1, Math.ceil(data.length / 64));
    for (let b = 0; b < nb - 1; b++) cv = b3compress(cv, words16(data.subarray(b * 64, b * 64 + 64)), ci, 64, base | (b === 0 ? CHUNK_START : 0)).slice(0, 8);
    const last = data.subarray((nb - 1) * 64); return { cv, m: words16(last), counter: ci, blen: last.length, flags: base | (nb === 1 ? CHUNK_START : 0) | CHUNK_END }; };
  const nodeCv = (n) => b3compress(n.cv, n.m, n.counter, n.blen, n.flags).slice(0, 8);
  const parent = (l, r) => ({ cv: kw.slice(), m: [...l, ...r], counter: 0, blen: 64, flags: base | PARENT });
  for (let ci = 0; ci < chunks; ci++) { const node = chunkOut(ci); if (ci === chunks - 1) { rootNode = node; break; } let cv = nodeCv(node); let total = ci + 1; while ((total & 1) === 0) { cv = nodeCv(parent(stack.pop(), cv)); total >>= 1; } stack.push(cv); }
  while (stack.length) rootNode = parent(stack.pop(), nodeCv(rootNode));
  const out = new Uint8Array(outLen); for (let blk = 0, o = 0; o < outLen; blk++) { const w = b3compress(rootNode.cv, rootNode.m, blk, rootNode.blen, rootNode.flags | ROOT); const bb = new Uint8Array(64), dv = new DataView(bb.buffer); w.forEach((x, i) => dv.setUint32(i * 4, x, true)); const n = Math.min(64, outLen - o); out.set(bb.subarray(0, n), o); o += n; }
  return out;
}

// ---------- LM hash ----------
function lmHash(pw) { const p = new Uint8Array(14); const up = String(pw).toUpperCase(); for (let i = 0; i < Math.min(14, up.length); i++) p[i] = up.charCodeAt(i) & 255;
  const key7to8 = (k) => { const b = [k[0] >> 1, ((k[0] & 1) << 6) | (k[1] >> 2), ((k[1] & 3) << 5) | (k[2] >> 3), ((k[2] & 7) << 4) | (k[3] >> 4), ((k[3] & 15) << 3) | (k[4] >> 5), ((k[4] & 31) << 2) | (k[5] >> 6), ((k[5] & 63) << 1) | (k[6] >> 7), k[6] & 127]; return new Uint8Array(b.map((x) => x << 1)); };
  const magic = utf8("KGS!@#$%"); return bytesToHex(new Uint8Array([...desEncryptBlock(key7to8(p.subarray(0, 7)), magic), ...desEncryptBlock(key7to8(p.subarray(7, 14)), magic)])).toUpperCase(); }

// ---------- Argon2 (RFC 9106) ----------
const le32 = (n) => { const b = new Uint8Array(4); new DataView(b.buffer).setUint32(0, n >>> 0, true); return b; };
const cat = (...a) => { const o = new Uint8Array(a.reduce((n, x) => n + x.length, 0)); let p = 0; for (const x of a) { o.set(x, p); p += x.length; } return o; };
function Hprime(x, T) { if (T <= 64) return blake2b(cat(le32(T), x), T); const r = Math.ceil(T / 32) - 2; const out = []; let v = blake2b(cat(le32(T), x), 64); out.push(...v.subarray(0, 32)); for (let i = 1; i < r; i++) { v = blake2b(v, 64); out.push(...v.subarray(0, 32)); } v = blake2b(v, T - 32 * r); out.push(...v); return new Uint8Array(out); }
const M64 = (1n << 64n) - 1n;
function argon2(pwd, salt, { t, m, p, len, type, secret = new Uint8Array(), ad = new Uint8Array() }) {
  if (salt.length < 8) throw new Error("Salt must be at least 8 bytes"); if (m < 8 * p) throw new Error("Memory must be at least 8 × parallelism KiB"); if (m > 65536) throw new Error("Memory above 64 MiB is too much for the browser"); if (t < 1) throw new Error("Iterations must be ≥ 1");
  const typeId = { argon2d: 0, argon2i: 1, argon2id: 2 }[type];
  const H0 = blake2b(cat(le32(p), le32(len), le32(m), le32(t), le32(0x13), le32(typeId), le32(pwd.length), pwd, le32(salt.length), salt, le32(secret.length), secret, le32(ad.length), ad), 64);
  const mPrime = 4 * p * Math.floor(m / (4 * p)); const q = mPrime / p; const SL = 4; const segLen = q / SL;
  const B = Array.from({ length: mPrime }, () => new BigUint64Array(128));
  const toBlock = (b) => { const o = new BigUint64Array(128); const dv = new DataView(b.buffer, b.byteOffset); for (let i = 0; i < 128; i++) o[i] = dv.getBigUint64(i * 8, true); return o; };
  const fBlaMka = (x, y) => (x + y + 2n * (x & 0xffffffffn) * (y & 0xffffffffn)) & M64; const rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M64;
  const GB = (v, a, b, c, d) => { v[a] = fBlaMka(v[a], v[b]); v[d] = rotr(v[d] ^ v[a], 32n); v[c] = fBlaMka(v[c], v[d]); v[b] = rotr(v[b] ^ v[c], 24n); v[a] = fBlaMka(v[a], v[b]); v[d] = rotr(v[d] ^ v[a], 16n); v[c] = fBlaMka(v[c], v[d]); v[b] = rotr(v[b] ^ v[c], 63n); };
  const P = (v, idx) => { GB(v, idx[0], idx[4], idx[8], idx[12]); GB(v, idx[1], idx[5], idx[9], idx[13]); GB(v, idx[2], idx[6], idx[10], idx[14]); GB(v, idx[3], idx[7], idx[11], idx[15]); GB(v, idx[0], idx[5], idx[10], idx[15]); GB(v, idx[1], idx[6], idx[11], idx[12]); GB(v, idx[2], idx[7], idx[8], idx[13]); GB(v, idx[3], idx[4], idx[9], idx[14]); };
  const G = (X, Y) => { const R = new BigUint64Array(128); for (let i = 0; i < 128; i++) R[i] = X[i] ^ Y[i]; const Q = R.slice();
    for (let r = 0; r < 8; r++) P(Q, Array.from({ length: 16 }, (_, k) => r * 16 + k));
    for (let c = 0; c < 8; c++) P(Q, Array.from({ length: 16 }, (_, k) => (Math.floor(k / 2) * 16) + c * 2 + (k % 2)));
    for (let i = 0; i < 128; i++) Q[i] ^= R[i]; return Q; };
  for (let l = 0; l < p; l++) { B[l * q] = toBlock(Hprime(cat(H0, le32(0), le32(l)), 1024)); B[l * q + 1] = toBlock(Hprime(cat(H0, le32(1), le32(l)), 1024)); }
  const zero = new BigUint64Array(128);
  for (let pass = 0; pass < t; pass++) for (let s = 0; s < SL; s++) for (let l = 0; l < p; l++) {
    const dataIndependent = typeId === 1 || (typeId === 2 && pass === 0 && s < 2); let addrBlock = null, counter = 0;
    const nextAddr = () => { counter++; const inp = new BigUint64Array(128); [pass, l, s, mPrime, t, typeId, counter].forEach((v, k) => (inp[k] = BigInt(v))); addrBlock = G(zero, G(zero, inp)); };
    const first = pass === 0 && s === 0 ? 2 : 0;
    if (dataIndependent && first !== 0) nextAddr(); // the first segment starts at index 2, so prime the address block
    for (let idx = first; idx < segLen; idx++) {
      const cur = l * q + s * segLen + idx; const prev = cur % q === 0 ? cur + q - 1 : cur - 1;
      let pr; if (dataIndependent) { if (idx % 128 === 0) nextAddr(); pr = addrBlock[idx % 128]; } else pr = B[prev][0];
      const J1 = pr & 0xffffffffn, J2 = pr >> 32n; const refLane = pass === 0 && s === 0 ? l : Number(J2 % BigInt(p));
      let W; if (pass === 0) W = refLane === l ? s * segLen + idx - 1 : s * segLen + (idx === 0 ? -1 : 0); else W = refLane === l ? q - segLen + idx - 1 : q - segLen + (idx === 0 ? -1 : 0);
      const x = (J1 * J1) >> 32n; const y = (BigInt(W) * x) >> 32n; const zz = BigInt(W) - 1n - y;
      const start = pass === 0 || s === SL - 1 ? 0 : (s + 1) * segLen; const refIdx = (start + Number(zz)) % q;
      const nb = G(B[prev], B[refLane * q + refIdx]); if (pass === 0) B[cur] = nb; else { const o = B[cur]; for (let k = 0; k < 128; k++) o[k] ^= nb[k]; }
    }
  }
  const C = B[q - 1].slice(); for (let l = 1; l < p; l++) { const x = B[l * q + q - 1]; for (let k = 0; k < 128; k++) C[k] ^= x[k]; }
  const cb = new Uint8Array(1024), dv = new DataView(cb.buffer); C.forEach((x, i) => dv.setBigUint64(i * 8, x, true)); return Hprime(cb, len);
}
const b64nopad = (b) => bytesToBase64(b).replace(/=+$/, "");
const b64dec = (s) => Uint8Array.from(atob(s + "===".slice((s.length + 3) % 4)), (c) => c.charCodeAt(0));

// ---------- SSDEEP / CTPH (spamsum, as in ssdeep 2.x) ----------
const B64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
const SPAMSUM_LENGTH = 64, MIN_BLOCKSIZE = 3, HASH_INIT = 0x28021967;
function ssdeep(bytes) {
  let bs = MIN_BLOCKSIZE; while (bs * SPAMSUM_LENGTH < bytes.length) bs *= 2;
  for (;;) {
    const p1 = [], p2 = []; let j = 0, k = 0, h1 = HASH_INIT, h2 = HASH_INIT; const win = new Uint8Array(7); let r1 = 0, r2 = 0, r3 = 0, n = 0;
    const roll = (c) => { r2 = (r2 - r1) >>> 0; r2 = (r2 + 7 * c) >>> 0; r1 = (r1 + c) >>> 0; r1 = (r1 - win[n % 7]) >>> 0; win[n % 7] = c; n++; r3 = ((r3 << 5) >>> 0) ^ c; r3 >>>= 0; return (r1 + r2 + r3) >>> 0; };
    for (const c of bytes) { const h = roll(c); h1 = (Math.imul(h1, 0x01000193) ^ c) >>> 0; h2 = (Math.imul(h2, 0x01000193) ^ c) >>> 0;
      if (h % bs === bs - 1) { p1[j] = B64[h1 % 64]; if (j < SPAMSUM_LENGTH - 1) { h1 = HASH_INIT; j++; } }
      if (h % (bs * 2) === bs * 2 - 1) { p2[k] = B64[h2 % 64]; if (k < SPAMSUM_LENGTH / 2 - 1) { h2 = HASH_INIT; k++; } } }
    if ((r1 + r2 + r3) >>> 0 !== 0) { p1[j] = B64[h1 % 64]; p2[k] = B64[h2 % 64]; }
    if (bs > MIN_BLOCKSIZE && j < SPAMSUM_LENGTH / 2) { bs /= 2; continue; }
    return `${bs}:${p1.join("")}:${p2.join("")}`;
  }
}
function editDistance(x, y) { // insert/delete 1, substitute 3 (ssdeep weights)
  const dp = Array.from({ length: x.length + 1 }, (_, i) => [i]); for (let j = 1; j <= y.length; j++) dp[0][j] = j;
  for (let i = 1; i <= x.length; i++) for (let j = 1; j <= y.length; j++) dp[i][j] = Math.min(dp[i - 1][j] + 1, dp[i][j - 1] + 1, dp[i - 1][j - 1] + (x[i - 1] === y[j - 1] ? 0 : 3));
  return dp[x.length][y.length];
}
function ssdeepCompare(a, b) {
  const pa = String(a).trim().split(":"), pb = String(b).trim().split(":"); if (pa.length < 3 || pb.length < 3) throw new Error("Expected two hashes of the form blocksize:hash1:hash2");
  const [ba, a1, a2] = [Number(pa[0]), pa[1], pa[2].split(",")[0]], [bb, b1, b2] = [Number(pb[0]), pb[1], pb[2].split(",")[0]];
  if (ba !== bb && ba !== bb * 2 && bb !== ba * 2) return 0;
  const strip = (s) => s.replace(/(.)\1{3,}/g, "$1$1$1");
  const common7 = (x, y) => { for (let i = 0; i + 7 <= x.length; i++) if (y.includes(x.substr(i, 7))) return true; return false; };
  const score = (x, y, bs) => { x = strip(x); y = strip(y); if (x.length > SPAMSUM_LENGTH || y.length > SPAMSUM_LENGTH || !common7(x, y)) return 0;
    let sc = Math.floor((editDistance(x, y) * SPAMSUM_LENGTH) / (x.length + y.length)); sc = Math.floor((100 * sc) / SPAMSUM_LENGTH); if (sc >= 100) return 0; sc = 100 - sc;
    if (bs >= ((99 + 7) / 7) * MIN_BLOCKSIZE) return sc; return Math.min(sc, (bs / MIN_BLOCKSIZE) * Math.min(x.length, y.length)); };
  if (ba === bb && a1 === b1 && a2 === b2) return 100;
  if (ba === bb) return Math.max(score(a1, b1, ba), score(a2, b2, ba * 2));
  return ba === bb * 2 ? score(a1, b2, ba) : score(a2, b1, bb);
}

const fmtOpt = select("format", "Output format", ["hex", "Base64"]); const fmt = (b, f) => (f === "Base64" ? bytesToBase64(b) : bytesToHex(b));
export const ops = {
  sha0: { name: "SHA0", run: (i, a) => fmt(sha0(inp(i, a)), a.format), args: [fmtOpt, inputOpt] },
  sm3: { name: "SM3", run: (i, a) => fmt(sm3(inp(i, a)), a.format), args: [fmtOpt, inputOpt] },
  whirlpool: { name: "Whirlpool", run: (i, a) => fmt(whirlpool(inp(i, a)), a.format), args: [fmtOpt, inputOpt] },
  blake3: { name: "BLAKE3", run: (i, a) => { const key = a.key ? (/^[0-9a-f]{64}$/i.test(a.key) ? hexToBytes(a.key) : utf8(a.key)) : null; if (key && key.length !== 32) throw new Error("BLAKE3 key must be exactly 32 bytes"); return fmt(blake3(inp(i, a), Math.min(Number(a.length) || 32, 1024), key), a.format); }, args: [opt("length", "Output length (bytes)", "number", { default: 32 }), opt("key", "Key (32 bytes, optional)", "text"), fmtOpt, inputOpt] },
  "lm-hash": { name: "LM Hash", run: (i) => lmHash(i), placeholder: "Password" },
  argon2: { name: "Argon2", run: (i, a) => { const salt = utf8(a.salt); const tag = argon2(utf8(i), salt, { t: Number(a.t), m: Number(a.m), p: Number(a.p), len: Number(a.len), type: a.type });
    return `${a.type === "argon2id" ? "$argon2id" : `$${a.type}`}$v=19$m=${a.m},t=${a.t},p=${a.p}$${b64nopad(salt)}$${b64nopad(tag)}\n\nRaw hash: ${bytesToHex(tag)}`; },
    args: [select("type", "Variant", ["argon2id", "argon2i", "argon2d"]), opt("salt", "Salt (≥ 8 chars)", "text", { default: "somesalt" }), opt("t", "Iterations", "number", { default: 3 }), opt("m", "Memory (KiB)", "number", { default: 4096 }), opt("p", "Parallelism", "number", { default: 1 }), opt("len", "Hash length (bytes)", "number", { default: 32 })], placeholder: "Password" },
  "argon2-compare": { name: "Argon2 compare", run: (i, a) => { const m = String(a.hash).trim().match(/^\$(argon2(?:id|i|d))\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$([A-Za-z0-9+/]+)\$([A-Za-z0-9+/]+)$/); if (!m) throw new Error("Expected an encoded hash like $argon2id$v=19$m=…,t=…,p=…$salt$hash");
    const want = b64dec(m[6]); const got = argon2(utf8(i), b64dec(m[5]), { type: m[1], m: +m[2], t: +m[3], p: +m[4], len: want.length }); return bytesToHex(got) === bytesToHex(want) ? "✓ Password MATCHES the hash" : "✗ Password does NOT match"; }, args: [opt("hash", "Encoded Argon2 hash", "text")], placeholder: "Password" },
  ssdeep: { name: "SSDEEP / CTPH", input: "file", run: (f) => ssdeep(f.bytes) },
  "ssdeep-compare": { name: "Compare SSDEEP hashes", run: (i, a) => `Similarity score: ${ssdeepCompare(i, a.other)} / 100`, args: [opt("other", "Second hash", "text")], placeholder: "3:abc...:xyz..." },
};
export { argon2, lmHash, ssdeep, ssdeepCompare };
