// Phase 2 hashes and checksums, pure JS (BigInt where 64-bit lanes are needed).
import { utf8, hexToBytes, bytesToHex, bytesToBase64, select, opt } from "./util.js";
import { md5, crc32 } from "./hashing.js";

// ---------- Keccak / SHA-3 / SHAKE (FIPS 202) ----------
const RC = [1n, 0x8082n, 0x800000000000808an, 0x8000000080008000n, 0x808bn, 0x80000001n, 0x8000000080008081n, 0x8000000000008009n, 0x8an, 0x88n, 0x80008009n, 0x8000000an, 0x8000808bn, 0x800000000000008bn, 0x8000000000008089n, 0x8000000000008003n, 0x8000000000008002n, 0x8000000000000080n, 0x800an, 0x800000008000000an, 0x8000000080008081n, 0x8000000000008080n, 0x80000001n, 0x8000000080008008n];
const ROT = [0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14];
const M64 = (1n << 64n) - 1n;
const rotl64 = (x, n) => (n === 0 ? x : ((x << BigInt(n)) | (x >> BigInt(64 - n))) & M64);
function keccakF(s) {
  for (let r = 0; r < 24; r++) {
    const C = [0, 1, 2, 3, 4].map((x) => s[x] ^ s[x + 5] ^ s[x + 10] ^ s[x + 15] ^ s[x + 20]);
    for (let x = 0; x < 5; x++) { const d = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1); for (let y = 0; y < 25; y += 5) s[y + x] ^= d; }
    const B = new Array(25);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) B[y + 5 * ((2 * x + 3 * y) % 5)] = rotl64(s[x + 5 * y], ROT[x + 5 * y]);
    for (let x = 0; x < 5; x++) for (let y = 0; y < 5; y++) s[x + 5 * y] = B[x + 5 * y] ^ (~B[(x + 1) % 5 + 5 * y] & M64 & B[(x + 2) % 5 + 5 * y]);
    s[0] ^= RC[r];
  }
}
export function keccak(bytes, rateBytes, outBytes, dsByte) {
  const s = new Array(25).fill(0n);
  const padded = new Uint8Array(Math.ceil((bytes.length + 1) / rateBytes) * rateBytes); padded.set(bytes);
  padded[bytes.length] ^= dsByte; padded[padded.length - 1] ^= 0x80;
  for (let off = 0; off < padded.length; off += rateBytes) {
    for (let i = 0; i < rateBytes / 8; i++) { let lane = 0n; for (let b = 7; b >= 0; b--) lane = (lane << 8n) | BigInt(padded[off + i * 8 + b]); s[i] ^= lane; }
    keccakF(s);
  }
  const out = new Uint8Array(outBytes); let o = 0;
  for (;;) { for (let i = 0; i < rateBytes / 8 && o < outBytes; i++) { let lane = s[i]; for (let b = 0; b < 8 && o < outBytes; b++) { out[o++] = Number(lane & 0xffn); lane >>= 8n; } } if (o >= outBytes) break; keccakF(s); }
  return out;
}

// ---------- MD4 (RFC 1320) ----------
export function md4(bytes) {
  const len = bytes.length, padLen = ((len + 8) >>> 6 << 6) + 64; const m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80;
  const dv = new DataView(m.buffer); dv.setUint32(padLen - 8, (len * 8) >>> 0, true); dv.setUint32(padLen - 4, Math.floor(len / 0x20000000), true);
  let a = 0x67452301, b = 0xefcdab89, c = 0x98badcfe, d = 0x10325476; const rl = (x, n) => (x << n) | (x >>> (32 - n));
  for (let off = 0; off < padLen; off += 64) {
    const X = Array.from({ length: 16 }, (_, i) => dv.getUint32(off + i * 4, true)); const [aa, bb, cc, dd] = [a, b, c, d];
    const F = (x, y, z) => (x & y) | (~x & z), G = (x, y, z) => (x & y) | (x & z) | (y & z), H = (x, y, z) => x ^ y ^ z;
    for (const i of [0, 4, 8, 12]) { a = rl((a + F(b, c, d) + X[i]) | 0, 3); d = rl((d + F(a, b, c) + X[i + 1]) | 0, 7); c = rl((c + F(d, a, b) + X[i + 2]) | 0, 11); b = rl((b + F(c, d, a) + X[i + 3]) | 0, 19); }
    for (const i of [0, 1, 2, 3]) { a = rl((a + G(b, c, d) + X[i] + 0x5a827999) | 0, 3); d = rl((d + G(a, b, c) + X[i + 4] + 0x5a827999) | 0, 5); c = rl((c + G(d, a, b) + X[i + 8] + 0x5a827999) | 0, 9); b = rl((b + G(c, d, a) + X[i + 12] + 0x5a827999) | 0, 13); }
    for (const i of [0, 2, 1, 3]) { a = rl((a + H(b, c, d) + X[i] + 0x6ed9eba1) | 0, 3); d = rl((d + H(a, b, c) + X[i + 8] + 0x6ed9eba1) | 0, 9); c = rl((c + H(d, a, b) + X[i + 4] + 0x6ed9eba1) | 0, 11); b = rl((b + H(c, d, a) + X[i + 12] + 0x6ed9eba1) | 0, 15); }
    a = (a + aa) | 0; b = (b + bb) | 0; c = (c + cc) | 0; d = (d + dd) | 0;
  }
  const out = new Uint8Array(16), ov = new DataView(out.buffer); [a, b, c, d].forEach((v, i) => ov.setUint32(i * 4, v >>> 0, true)); return out;
}

// ---------- RIPEMD-160 ----------
export function ripemd160(bytes) {
  const len = bytes.length, padLen = ((len + 8) >>> 6 << 6) + 64; const m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80;
  const dv = new DataView(m.buffer); dv.setUint32(padLen - 8, (len * 8) >>> 0, true); dv.setUint32(padLen - 4, Math.floor(len / 0x20000000), true);
  const r = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 7, 4, 13, 1, 10, 6, 15, 3, 12, 0, 9, 5, 2, 14, 11, 8, 3, 10, 14, 4, 9, 15, 8, 1, 2, 7, 0, 6, 13, 11, 5, 12, 1, 9, 11, 10, 0, 8, 12, 4, 13, 3, 7, 15, 14, 5, 6, 2, 4, 0, 5, 9, 7, 12, 2, 10, 14, 1, 3, 8, 11, 6, 15, 13];
  const rp = [5, 14, 7, 0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 6, 11, 3, 7, 0, 13, 5, 10, 14, 15, 8, 12, 4, 9, 1, 2, 15, 5, 1, 3, 7, 14, 6, 9, 11, 8, 12, 2, 10, 0, 4, 13, 8, 6, 4, 1, 3, 11, 15, 0, 5, 12, 2, 13, 9, 7, 10, 14, 12, 15, 10, 4, 1, 5, 8, 7, 6, 2, 13, 14, 0, 3, 9, 11];
  const s = [11, 14, 15, 12, 5, 8, 7, 9, 11, 13, 14, 15, 6, 7, 9, 8, 7, 6, 8, 13, 11, 9, 7, 15, 7, 12, 15, 9, 11, 7, 13, 12, 11, 13, 6, 7, 14, 9, 13, 15, 14, 8, 13, 6, 5, 12, 7, 5, 11, 12, 14, 15, 14, 15, 9, 8, 9, 14, 5, 6, 8, 6, 5, 12, 9, 15, 5, 11, 6, 8, 13, 12, 5, 12, 13, 14, 11, 8, 5, 6];
  const sp = [8, 9, 9, 11, 13, 15, 15, 5, 7, 7, 8, 11, 14, 14, 12, 6, 9, 13, 15, 7, 12, 8, 9, 11, 7, 7, 12, 7, 6, 15, 13, 11, 9, 7, 15, 11, 8, 6, 6, 14, 12, 13, 5, 14, 13, 13, 7, 5, 15, 5, 8, 11, 14, 14, 6, 14, 6, 9, 12, 9, 12, 5, 15, 8, 8, 5, 12, 9, 12, 5, 14, 6, 8, 13, 6, 5, 15, 13, 11, 11];
  const K = [0, 0x5a827999, 0x6ed9eba1, 0x8f1bbcdc, 0xa953fd4e], KP = [0x50a28be6, 0x5c4dd124, 0x6d703ef3, 0x7a6d76e9, 0];
  const f = (j, x, y, z) => j < 16 ? x ^ y ^ z : j < 32 ? (x & y) | (~x & z) : j < 48 ? (x | ~y) ^ z : j < 64 ? (x & z) | (y & ~z) : x ^ (y | ~z);
  const rl = (x, n) => (x << n) | (x >>> (32 - n));
  let h0 = 0x67452301, h1 = 0xefcdab89, h2 = 0x98badcfe, h3 = 0x10325476, h4 = 0xc3d2e1f0;
  for (let off = 0; off < padLen; off += 64) {
    const X = Array.from({ length: 16 }, (_, i) => dv.getUint32(off + i * 4, true));
    let al = h0, bl = h1, cl = h2, dl = h3, el = h4, ar = h0, br = h1, cr = h2, dr = h3, er = h4;
    for (let j = 0; j < 80; j++) {
      let t = (rl((al + f(j, bl, cl, dl) + X[r[j]] + K[j >> 4]) | 0, s[j]) + el) | 0; al = el; el = dl; dl = rl(cl, 10); cl = bl; bl = t;
      t = (rl((ar + f(79 - j, br, cr, dr) + X[rp[j]] + KP[j >> 4]) | 0, sp[j]) + er) | 0; ar = er; er = dr; dr = rl(cr, 10); cr = br; br = t;
    }
    const t = (h1 + cl + dr) | 0; h1 = (h2 + dl + er) | 0; h2 = (h3 + el + ar) | 0; h3 = (h4 + al + br) | 0; h4 = (h0 + bl + cr) | 0; h0 = t;
  }
  const out = new Uint8Array(20), ov = new DataView(out.buffer); [h0, h1, h2, h3, h4].forEach((v, i) => ov.setUint32(i * 4, v >>> 0, true)); return out;
}

// ---------- BLAKE2b / BLAKE2s (RFC 7693) ----------
const SIGMA = [[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15], [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3], [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4], [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8], [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13], [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9], [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11], [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10], [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5], [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0]];
const IV32 = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19];
const IV64 = [0x6a09e667f3bcc908n, 0xbb67ae8584caa73bn, 0x3c6ef372fe94f82bn, 0xa54ff53a5f1d36f1n, 0x510e527fade682d1n, 0x9b05688c2b3e6c1fn, 0x1f83d9abfb41bd6bn, 0x5be0cd19137e2179n];
export function blake2b(bytes, outLen = 64, key = new Uint8Array(0)) {
  const h = IV64.slice(); h[0] ^= 0x01010000n ^ (BigInt(key.length) << 8n) ^ BigInt(outLen);
  const rotr = (x, n) => ((x >> BigInt(n)) | (x << BigInt(64 - n))) & M64;
  let data = bytes; if (key.length) { const k = new Uint8Array(128); k.set(key); data = new Uint8Array(128 + bytes.length); data.set(k); data.set(bytes, 128); }
  const blocks = Math.max(1, Math.ceil(data.length / 128)); let t = 0n;
  for (let i = 0; i < blocks; i++) {
    const blk = new Uint8Array(128); blk.set(data.subarray(i * 128, i * 128 + 128)); const last = i === blocks - 1;
    t += BigInt(last ? data.length - i * 128 : 128);
    const m = Array.from({ length: 16 }, (_, w) => { let x = 0n; for (let b = 7; b >= 0; b--) x = (x << 8n) | BigInt(blk[w * 8 + b]); return x; });
    const v = [...h, ...IV64]; v[12] ^= t & M64; v[13] ^= t >> 64n; if (last) v[14] ^= M64;
    const G = (a, b, c, d, x, y) => { v[a] = (v[a] + v[b] + x) & M64; v[d] = rotr(v[d] ^ v[a], 32); v[c] = (v[c] + v[d]) & M64; v[b] = rotr(v[b] ^ v[c], 24); v[a] = (v[a] + v[b] + y) & M64; v[d] = rotr(v[d] ^ v[a], 16); v[c] = (v[c] + v[d]) & M64; v[b] = rotr(v[b] ^ v[c], 63); };
    for (let r = 0; r < 12; r++) { const s = SIGMA[r % 10]; G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]); G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]); G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]); G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]); }
    for (let k = 0; k < 8; k++) h[k] ^= v[k] ^ v[k + 8];
  }
  const out = new Uint8Array(outLen); for (let i = 0; i < outLen; i++) out[i] = Number((h[i >> 3] >> BigInt(8 * (i & 7))) & 0xffn); return out;
}
export function blake2s(bytes, outLen = 32, key = new Uint8Array(0)) {
  const h = IV32.slice(); h[0] ^= 0x01010000 ^ (key.length << 8) ^ outLen;
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  let data = bytes; if (key.length) { const k = new Uint8Array(64); k.set(key); data = new Uint8Array(64 + bytes.length); data.set(k); data.set(bytes, 64); }
  const blocks = Math.max(1, Math.ceil(data.length / 64)); let t = 0;
  for (let i = 0; i < blocks; i++) {
    const blk = new Uint8Array(64); blk.set(data.subarray(i * 64, i * 64 + 64)); const last = i === blocks - 1; t += last ? data.length - i * 64 : 64;
    const dv = new DataView(blk.buffer); const m = Array.from({ length: 16 }, (_, w) => dv.getUint32(w * 4, true));
    const v = [...h, ...IV32]; v[12] ^= t; v[13] ^= Math.floor(t / 2 ** 32); if (last) v[14] = ~v[14];
    const G = (a, b, c, d, x, y) => { v[a] = (v[a] + v[b] + x) | 0; v[d] = rotr(v[d] ^ v[a], 16); v[c] = (v[c] + v[d]) | 0; v[b] = rotr(v[b] ^ v[c], 12); v[a] = (v[a] + v[b] + y) | 0; v[d] = rotr(v[d] ^ v[a], 8); v[c] = (v[c] + v[d]) | 0; v[b] = rotr(v[b] ^ v[c], 7); };
    for (let r = 0; r < 10; r++) { const s = SIGMA[r]; G(0, 4, 8, 12, m[s[0]], m[s[1]]); G(1, 5, 9, 13, m[s[2]], m[s[3]]); G(2, 6, 10, 14, m[s[4]], m[s[5]]); G(3, 7, 11, 15, m[s[6]], m[s[7]]); G(0, 5, 10, 15, m[s[8]], m[s[9]]); G(1, 6, 11, 12, m[s[10]], m[s[11]]); G(2, 7, 8, 13, m[s[12]], m[s[13]]); G(3, 4, 9, 14, m[s[14]], m[s[15]]); }
    for (let k = 0; k < 8; k++) h[k] = (h[k] ^ v[k] ^ v[k + 8]) >>> 0;
  }
  const out = new Uint8Array(32), ov = new DataView(out.buffer); h.forEach((x, i) => ov.setUint32(i * 4, x >>> 0, true)); return out.slice(0, outLen);
}

// ---------- MurmurHash3 x86 32-bit ----------
export function murmur3(bytes, seed = 0) {
  let h = seed >>> 0; const c1 = 0xcc9e2d51, c2 = 0x1b873593; const n = bytes.length & ~3;
  for (let i = 0; i < n; i += 4) { let k = bytes[i] | (bytes[i + 1] << 8) | (bytes[i + 2] << 16) | (bytes[i + 3] << 24); k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k; h = (h << 13) | (h >>> 19); h = (Math.imul(h, 5) + 0xe6546b64) | 0; }
  let k = 0; switch (bytes.length & 3) { case 3: k ^= bytes[n + 2] << 16; // falls through
    case 2: k ^= bytes[n + 1] << 8; // falls through
    case 1: k ^= bytes[n]; k = Math.imul(k, c1); k = (k << 15) | (k >>> 17); k = Math.imul(k, c2); h ^= k; }
  h ^= bytes.length; h ^= h >>> 16; h = Math.imul(h, 0x85ebca6b); h ^= h >>> 13; h = Math.imul(h, 0xc2b2ae35); h ^= h >>> 16; return h >>> 0;
}

// ---------- generic CRC ----------
const CRCS = {
  "CRC-8": [8, 0x07, 0x00, false, false, 0x00], "CRC-8/MAXIM": [8, 0x31, 0x00, true, true, 0x00],
  "CRC-16/ARC": [16, 0x8005, 0x0000, true, true, 0x0000], "CRC-16/CCITT-FALSE": [16, 0x1021, 0xffff, false, false, 0x0000], "CRC-16/XMODEM": [16, 0x1021, 0x0000, false, false, 0x0000],
  "CRC-16/MODBUS": [16, 0x8005, 0xffff, true, true, 0x0000], "CRC-16/KERMIT": [16, 0x1021, 0x0000, true, true, 0x0000], "CRC-16/X-25": [16, 0x1021, 0xffff, true, true, 0xffff],
  "CRC-32": [32, 0x04c11db7, 0xffffffff, true, true, 0xffffffff], "CRC-32C": [32, 0x1edc6f41, 0xffffffff, true, true, 0xffffffff], "CRC-32/BZIP2": [32, 0x04c11db7, 0xffffffff, false, false, 0xffffffff], "CRC-32/MPEG-2": [32, 0x04c11db7, 0xffffffff, false, false, 0x00000000],
};
// Generic CRC in BigInt so 8/16/32-bit widths share one exact implementation.
const reflect = (v, w) => { let r = 0n; for (let i = 0n; i < w; i++) if ((v >> i) & 1n) r |= 1n << (w - 1n - i); return r; };
export function crc(bytes, name) {
  const [wn, poly, init, refIn, refOut, xorOut] = CRCS[name]; const w = BigInt(wn), mask = (1n << w) - 1n, top = 1n << (w - 1n), P = BigInt(poly);
  let c = BigInt(init);
  for (const x of bytes) { let b = BigInt(x); if (refIn) b = reflect(b, 8n); c ^= b << (w - 8n); for (let i = 0; i < 8; i++) c = (c & top ? (c << 1n) ^ P : c << 1n) & mask; }
  if (refOut) c = reflect(c, w); return Number((c ^ BigInt(xorOut)) & mask);
}

function fletcher(bytes, bits) {
  if (bits === 8) { let a = 0, b = 0; for (const x of bytes) { a = (a + x) % 15; b = (b + a) % 15; } return ((b << 4) | a).toString(16).padStart(2, "0"); }
  if (bits === 16) { let a = 0, b = 0; for (const x of bytes) { a = (a + x) % 255; b = (b + a) % 255; } return ((b << 8) | a).toString(16).padStart(4, "0"); }
  if (bits === 32) { let a = 0, b = 0; for (let i = 0; i < bytes.length; i += 2) { a = (a + (bytes[i] | ((bytes[i + 1] ?? 0) << 8))) % 65535; b = (b + a) % 65535; } return ((b * 65536 + a) >>> 0).toString(16).padStart(8, "0"); }
  let a = 0n, b = 0n; const M = 0xffffffffn; for (let i = 0; i < bytes.length; i += 4) { let w = 0n; for (let k = 3; k >= 0; k--) w = (w << 8n) | BigInt(bytes[i + k] ?? 0); a = (a + w) % M; b = (b + a) % M; } return ((b << 32n) | a).toString(16).padStart(16, "0");
}
function inetChecksum(bytes) { let s = 0; for (let i = 0; i < bytes.length; i += 2) s += (bytes[i] << 8) | (bytes[i + 1] ?? 0); while (s >> 16) s = (s & 0xffff) + (s >> 16); return (~s & 0xffff).toString(16).padStart(4, "0"); }

const inputOpt = select("inputEncoding", "Input format", ["utf8", "hex"]);
const inp = (i, a) => (a.inputEncoding === "hex" ? hexToBytes(i) : utf8(i));
const fmt = (b, f) => (f === "Base64" ? bytesToBase64(b) : bytesToHex(b));
const fmtOpt = select("format", "Output format", ["hex", "Base64"]);

async function aesCmac(keyBytes, msg) {
  const key = await crypto.subtle.importKey("raw", keyBytes, "AES-CBC", false, ["encrypt"]);
  const E = async (blk) => new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv: new Uint8Array(16) }, key, blk)).slice(0, 16);
  const dbl = (b) => { const o = new Uint8Array(16); let carry = 0; for (let i = 15; i >= 0; i--) { o[i] = ((b[i] << 1) | carry) & 255; carry = b[i] >> 7; } if (b[0] & 0x80) o[15] ^= 0x87; return o; };
  const L = await E(new Uint8Array(16)); const K1 = dbl(L), K2 = dbl(K1);
  const n = Math.max(1, Math.ceil(msg.length / 16)); const complete = msg.length > 0 && msg.length % 16 === 0;
  const last = new Uint8Array(16); last.set(msg.subarray((n - 1) * 16)); if (!complete) last[msg.length - (n - 1) * 16] = 0x80;
  const K = complete ? K1 : K2; for (let i = 0; i < 16; i++) last[i] ^= K[i];
  let x = new Uint8Array(16);
  for (let i = 0; i < n - 1; i++) { const blk = msg.slice(i * 16, i * 16 + 16); for (let j = 0; j < 16; j++) blk[j] ^= x[j]; x = await E(blk); }
  for (let j = 0; j < 16; j++) last[j] ^= x[j]; return E(last);
}

export const ops = {
  sha3: { name: "SHA3", run: (i, a) => fmt(keccak(inp(i, a), 200 - 2 * (Number(a.size) / 8), Number(a.size) / 8, 0x06), a.format), args: [select("size", "Size", ["256", "224", "384", "512"]), fmtOpt, inputOpt] },
  keccak: { name: "Keccak", run: (i, a) => fmt(keccak(inp(i, a), 200 - 2 * (Number(a.size) / 8), Number(a.size) / 8, 0x01), a.format), args: [select("size", "Size", ["256", "224", "384", "512"]), fmtOpt, inputOpt] },
  shake: { name: "SHAKE", run: (i, a) => fmt(keccak(inp(i, a), a.capacity === "128" ? 168 : 136, Math.min(Number(a.length) || 32, 4096), 0x1f), a.format), args: [select("capacity", "Capacity", ["128", "256"]), opt("length", "Output length (bytes)", "number", { default: 32 }), fmtOpt, inputOpt] },
  md4: { name: "MD4", run: (i, a) => fmt(md4(inp(i, a)), a.format), args: [fmtOpt, inputOpt] },
  "nt-hash": { name: "NT Hash", run: (i) => { const s = String(i); const b = new Uint8Array(s.length * 2); for (let k = 0; k < s.length; k++) { const c = s.charCodeAt(k); b[k * 2] = c & 255; b[k * 2 + 1] = c >> 8; } return bytesToHex(md4(b)).toUpperCase(); }, placeholder: "Password" },
  ripemd160: { name: "RIPEMD-160", run: (i, a) => fmt(ripemd160(inp(i, a)), a.format), args: [fmtOpt, inputOpt] },
  blake2b: { name: "BLAKE2b", run: (i, a) => fmt(blake2b(inp(i, a), Number(a.size) / 8, utf8(a.key || "")), a.format), args: [select("size", "Size", ["512", "384", "256", "160", "128"]), opt("key", "Key (optional)", "text"), fmtOpt, inputOpt] },
  blake2s: { name: "BLAKE2s", run: (i, a) => fmt(blake2s(inp(i, a), Number(a.size) / 8, utf8(a.key || "")), a.format), args: [select("size", "Size", ["256", "160", "128"]), opt("key", "Key (optional)", "text"), fmtOpt, inputOpt] },
  murmur3: { name: "MurmurHash3 (32-bit)", run: (i, a) => { const h = murmur3(inp(i, a), Number(a.seed) || 0); return `hex: ${h.toString(16).padStart(8, "0")}\nunsigned: ${h}\nsigned: ${h | 0}`; }, args: [opt("seed", "Seed", "number", { default: 0 }), inputOpt] },
  fletcher: { name: "Fletcher Checksum", run: (i, a) => fletcher(inp(i, a), Number(a.bits)), args: [select("bits", "Width", ["16", "8", "32", "64"]), inputOpt] },
  "crc-any": { name: "CRC Checksum", run: (i, a) => { const b = inp(i, a); if (a.algorithm === "All") return Object.keys(CRCS).map((k) => `${k.padEnd(20)} ${crc(b, k).toString(16).padStart(CRCS[k][0] / 4, "0")}`).join("\n"); return crc(b, a.algorithm).toString(16).padStart(CRCS[a.algorithm][0] / 4, "0"); }, args: [select("algorithm", "Algorithm", ["All", ...Object.keys(CRCS)]), inputOpt] },
  "inet-checksum": { name: "TCP/IP Checksum", run: (i, a) => inetChecksum(inp(i, a)), args: [select("inputEncoding", "Input format", ["hex", "utf8"])] },
  "xor-checksum": { name: "XOR Checksum", run: (i, a) => { const w = Number(a.width); const b = inp(i, a); const out = new Uint8Array(w); b.forEach((x, k) => (out[k % w] ^= x)); return bytesToHex(out); }, args: [select("width", "Block size (bytes)", ["1", "2", "4", "8"]), inputOpt] },
  "parity-bit": { name: "Parity Bit", run: (i, a) => { const b = inp(i, a); let ones = 0; for (const x of b) for (let k = 0; k < 8; k++) ones += (x >> k) & 1; const even = ones % 2; return `1-bits: ${ones}\nEven parity bit: ${even}\nOdd parity bit: ${even ^ 1}`; }, args: [inputOpt] },
  "all-checksums": { name: "Generate all checksums", run: (i, a) => { const b = inp(i, a); const rows = [["Adler-32", null], ["CRC-32", crc32(b).toString(16).padStart(8, "0")], ...Object.keys(CRCS).filter((k) => k !== "CRC-32").map((k) => [k, crc(b, k).toString(16).padStart(CRCS[k][0] / 4, "0")]), ["Fletcher-8", fletcher(b, 8)], ["Fletcher-16", fletcher(b, 16)], ["Fletcher-32", fletcher(b, 32)], ["Fletcher-64", fletcher(b, 64)], ["TCP/IP", inetChecksum(b)], ["MurmurHash3", murmur3(b).toString(16).padStart(8, "0")]];
    let s1 = 1, s2 = 0; for (const x of b) { s1 = (s1 + x) % 65521; s2 = (s2 + s1) % 65521; } rows[0][1] = (((s2 << 16) | s1) >>> 0).toString(16).padStart(8, "0");
    return rows.map(([k, v]) => `${k.padEnd(20)} ${v}`).join("\n"); }, args: [inputOpt] },
  "hash-more": { name: "Generate all hashes (extended)", run: async (i, a) => { const b = inp(i, a); const sub = async (alg) => bytesToHex(new Uint8Array(await crypto.subtle.digest(alg, b)));
    return [["MD4", bytesToHex(md4(b))], ["MD5", bytesToHex(md5(b))], ["SHA-1", await sub("SHA-1")], ["SHA-256", await sub("SHA-256")], ["SHA-512", await sub("SHA-512")], ["SHA3-256", bytesToHex(keccak(b, 136, 32, 6))], ["SHA3-512", bytesToHex(keccak(b, 72, 64, 6))], ["Keccak-256", bytesToHex(keccak(b, 136, 32, 1))], ["RIPEMD-160", bytesToHex(ripemd160(b))], ["BLAKE2b-512", bytesToHex(blake2b(b))], ["BLAKE2s-256", bytesToHex(blake2s(b))]].map(([k, v]) => `${k.padEnd(12)} ${v}`).join("\n"); }, args: [inputOpt] },
  cmac: { name: "CMAC (AES)", run: async (i, a) => bytesToHex(await aesCmac(hexToBytes(a.key), inp(i, a))), args: [opt("key", "AES key (hex, 16/24/32 bytes)", "text", { default: "2b7e151628aed2a6abf7158809cf4f3c" }), select("inputEncoding", "Input format", ["hex", "utf8"])] },
};
