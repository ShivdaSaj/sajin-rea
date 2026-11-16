// Phase 3 block/stream ciphers: DES, 3DES, Blowfish (S-boxes from π), RC6, PRESENT, Rabbit,
// OpenSSL EVP_BytesToKey; generic ECB/CBC/CTR/OFB/CFB modes with PKCS#7 padding.
import { utf8, fromUtf8, hexToBytes, bytesToHex, bytesToBase64, base64ToBytes, parseBytes, select, opt } from "./util.js";
import { md5 } from "./hashing.js";

// ---------- π hex digits (for Blowfish) ----------
let PI_HEX;
export function piHex(n) {
  if (PI_HEX && PI_HEX.length >= n) return PI_HEX.slice(0, n);
  const bits = BigInt(4 * (n + 16)); const one = 1n << bits;
  const atanInv = (x) => { const X = BigInt(x), X2 = X * X; let term = one / X, sum = term, k = 1n, sign = -1n; while (term) { term /= X2; const t = term / (2n * k + 1n); if (!t) break; sum += sign * t; sign = -sign; k++; } return sum; };
  const pi = 16n * atanInv(5) - 4n * atanInv(239);
  PI_HEX = (pi - 3n * one).toString(16).padStart(Number(bits / 4n), "0").slice(0, n + 8); return PI_HEX.slice(0, n);
}

// ---------- Blowfish ----------
function blowfishInit() { const hex = piHex(1042 * 8); const w = (i) => parseInt(hex.substr(i * 8, 8), 16) >>> 0; return { P: Array.from({ length: 18 }, (_, i) => w(i)), S: [0, 1, 2, 3].map((b) => Uint32Array.from({ length: 256 }, (_, i) => w(18 + b * 256 + i))) }; }
let BF_INIT;
const bfF = (S, x) => ((((S[0][x >>> 24] + S[1][(x >>> 16) & 255]) >>> 0) ^ S[2][(x >>> 8) & 255]) + S[3][x & 255]) >>> 0;
function bfEnc(st, L, R) { const { P, S } = st; for (let i = 0; i < 16; i += 2) { L ^= P[i]; R ^= bfF(S, L); R ^= P[i + 1]; L ^= bfF(S, R); } L ^= P[16]; R ^= P[17]; return [R >>> 0, L >>> 0]; }
function bfDec(st, L, R) { const { P, S } = st; for (let i = 16; i > 0; i -= 2) { L ^= P[i + 1]; R ^= bfF(S, L); R ^= P[i]; L ^= bfF(S, R); } L ^= P[1]; R ^= P[0]; return [R >>> 0, L >>> 0]; }
const stream32 = (b, pos) => { let w = 0; for (let k = 0; k < 4; k++) { w = ((w << 8) | b[pos.i]) >>> 0; pos.i = (pos.i + 1) % b.length; } return w; };
export function blowfishKey(key, salt = null) {
  BF_INIT ??= blowfishInit(); const st = { P: BF_INIT.P.slice(), S: BF_INIT.S.map((s) => s.slice()) };
  const kp = { i: 0 }; for (let i = 0; i < 18; i++) st.P[i] = (st.P[i] ^ stream32(key, kp)) >>> 0;
  let L = 0, R = 0; const sp = { i: 0 };
  const next = () => { if (salt) { L ^= stream32(salt, sp); R ^= stream32(salt, sp); } [L, R] = bfEnc(st, L, R); };
  for (let i = 0; i < 18; i += 2) { next(); st.P[i] = L; st.P[i + 1] = R; }
  for (let b = 0; b < 4; b++) for (let i = 0; i < 256; i += 2) { next(); st.S[b][i] = L; st.S[b][i + 1] = R; }
  return st;
}
function bfExpand0(st, key) { const kp = { i: 0 }; for (let i = 0; i < 18; i++) st.P[i] = (st.P[i] ^ stream32(key, kp)) >>> 0; let L = 0, R = 0; for (let i = 0; i < 18; i += 2) { [L, R] = bfEnc(st, L, R); st.P[i] = L; st.P[i + 1] = R; } for (let b = 0; b < 4; b++) for (let i = 0; i < 256; i += 2) { [L, R] = bfEnc(st, L, R); st.S[b][i] = L; st.S[b][i + 1] = R; } }
const blowfishCipher = (key) => { if (key.length < 4 || key.length > 56) throw new Error("Blowfish key must be 4–56 bytes"); const st = blowfishKey(key); const io = (fn) => (blk) => { const dv = new DataView(blk.buffer, blk.byteOffset, 8); const [l, r] = fn(st, dv.getUint32(0), dv.getUint32(4)); const o = new Uint8Array(8); const ov = new DataView(o.buffer); ov.setUint32(0, l); ov.setUint32(4, r); return o; }; return { size: 8, enc: io(bfEnc), dec: io(bfDec) }; };

// ---------- bcrypt ----------
const BC64 = "./ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
function bcEnc(b, len) { let o = ""; let i = 0; while (i < len) { let c1 = b[i++]; o += BC64[c1 >> 2]; c1 = (c1 & 3) << 4; if (i >= len) { o += BC64[c1]; break; } let c2 = b[i++]; c1 |= c2 >> 4; o += BC64[c1]; c1 = (c2 & 15) << 2; if (i >= len) { o += BC64[c1]; break; } c2 = b[i++]; c1 |= c2 >> 6; o += BC64[c1] + BC64[c2 & 63]; } return o; }
function bcDec(s, maxLen) { const v = [...s].map((c) => BC64.indexOf(c)); const out = []; for (let i = 0; i < v.length && out.length < maxLen; i += 4) { const [a, b, c, d] = [v[i], v[i + 1], v[i + 2] ?? -1, v[i + 3] ?? -1]; out.push(((a << 2) | (b >> 4)) & 255); if (c < 0 || out.length >= maxLen) break; out.push((((b & 15) << 4) | (c >> 2)) & 255); if (d < 0 || out.length >= maxLen) break; out.push((((c & 3) << 6) | d) & 255); } return new Uint8Array(out); }
export function bcrypt(password, cost, salt, minor = "b") {
  if (cost < 4 || cost > 31) throw new Error("Cost must be 4–31"); if (cost > 16) throw new Error("Cost above 16 is too slow to run in the browser");
  let key = utf8(password); if (key.length > 72) key = key.subarray(0, 72); key = new Uint8Array([...key, 0]);
  BF_INIT ??= blowfishInit(); const st = { P: BF_INIT.P.slice(), S: BF_INIT.S.map((s) => s.slice()) };
  // EksBlowfishSetup
  const kp = { i: 0 }; for (let i = 0; i < 18; i++) st.P[i] = (st.P[i] ^ stream32(key, kp)) >>> 0;
  let L = 0, R = 0; const sp = { i: 0 }; for (let i = 0; i < 18; i += 2) { L ^= stream32(salt, sp); R ^= stream32(salt, sp); [L, R] = bfEnc(st, L, R); st.P[i] = L; st.P[i + 1] = R; }
  for (let b = 0; b < 4; b++) for (let i = 0; i < 256; i += 2) { L ^= stream32(salt, sp); R ^= stream32(salt, sp); [L, R] = bfEnc(st, L, R); st.S[b][i] = L; st.S[b][i + 1] = R; }
  for (let r = 0; r < 2 ** cost; r++) { bfExpand0(st, key); bfExpand0(st, salt); }
  const ctext = [0x4f727068, 0x65616e42, 0x65686f6c, 0x64657253, 0x63727944, 0x6f756274];
  for (let i = 0; i < 64; i++) for (let j = 0; j < 6; j += 2) [ctext[j], ctext[j + 1]] = bfEnc(st, ctext[j], ctext[j + 1]);
  const out = new Uint8Array(24); const dv = new DataView(out.buffer); ctext.forEach((w, i) => dv.setUint32(i * 4, w >>> 0));
  return `$2${minor}$${String(cost).padStart(2, "0")}$${bcEnc(salt, 16)}${bcEnc(out, 23)}`;
}
export function bcryptParse(h) { const m = String(h).trim().match(/^\$2([abxy]?)\$(\d\d)\$([./A-Za-z0-9]{22})([./A-Za-z0-9]{31})$/); if (!m) throw new Error("Not a bcrypt hash ($2a$/$2b$/$2y$, cost, 53 characters)"); return { minor: m[1] || "", cost: +m[2], salt: bcDec(m[3], 16), saltText: m[3], hash: m[4] }; }

// ---------- DES / 3DES ----------
const PC1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36, 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4];
const PC2 = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32];
const SHIFTS = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];
const IP = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7];
const FP = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25];
const EXP = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29, 30, 31, 32, 1];
const PERM = [16, 7, 20, 21, 29, 12, 28, 17, 1, 15, 23, 26, 5, 18, 31, 10, 2, 8, 24, 14, 32, 27, 3, 9, 19, 13, 30, 6, 22, 11, 4, 25];
const SBOX = [
  [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13],
  [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9],
  [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12],
  [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14],
  [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3],
  [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13],
  [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12],
  [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11],
];
const toBits = (b) => Array.from({ length: b.length * 8 }, (_, i) => (b[i >> 3] >> (7 - (i & 7))) & 1);
const fromBits = (bits) => { const o = new Uint8Array(bits.length / 8); bits.forEach((x, i) => (o[i >> 3] |= x << (7 - (i & 7)))); return o; };
function desSubkeys(key8) { const k = toBits(key8); let cd = PC1.map((p) => k[p - 1]); const out = []; for (const s of SHIFTS) { const c = cd.slice(0, 28), d = cd.slice(28); cd = [...c.slice(s), ...c.slice(0, s), ...d.slice(s), ...d.slice(0, s)]; out.push(PC2.map((p) => cd[p - 1])); } return out; }
function desBlock(blk, subkeys) { const b = toBits(blk); let lr = IP.map((p) => b[p - 1]); let L = lr.slice(0, 32), R = lr.slice(32);
  for (const k of subkeys) { const e = EXP.map((p) => R[p - 1]).map((x, i) => x ^ k[i]); const s = []; for (let j = 0; j < 8; j++) { const c = e.slice(j * 6, j * 6 + 6); const v = SBOX[j][((c[0] << 1) | c[5]) * 16 + ((c[1] << 3) | (c[2] << 2) | (c[3] << 1) | c[4])]; s.push((v >> 3) & 1, (v >> 2) & 1, (v >> 1) & 1, v & 1); } const f = PERM.map((p) => s[p - 1]); [L, R] = [R, L.map((x, i) => x ^ f[i])]; }
  const pre = [...R, ...L]; return fromBits(FP.map((p) => pre[p - 1])); }
const desCipher = (key) => { if (key.length !== 8) throw new Error("DES key must be 8 bytes"); const ks = desSubkeys(key); const rev = ks.slice().reverse(); return { size: 8, enc: (b) => desBlock(b, ks), dec: (b) => desBlock(b, rev) }; };
const tdesCipher = (key) => { if (key.length !== 16 && key.length !== 24) throw new Error("Triple DES key must be 16 or 24 bytes"); const k1 = desSubkeys(key.subarray(0, 8)), k2 = desSubkeys(key.subarray(8, 16)), k3 = desSubkeys(key.length === 24 ? key.subarray(16, 24) : key.subarray(0, 8)); const r = (x) => x.slice().reverse();
  return { size: 8, enc: (b) => desBlock(desBlock(desBlock(b, k1), r(k2)), k3), dec: (b) => desBlock(desBlock(desBlock(b, r(k3)), k2), r(k1)) }; };
export const desEncryptBlock = (key8, blk) => desBlock(blk, desSubkeys(key8));

// ---------- RC6-32/20/b ----------
const rotl = (x, n) => ((x << (n & 31)) | (x >>> ((32 - n) & 31))) >>> 0; const rotr = (x, n) => ((x >>> (n & 31)) | (x << ((32 - n) & 31))) >>> 0;
const rc6Cipher = (key) => { if (![16, 24, 32].includes(key.length)) throw new Error("RC6 key must be 16, 24 or 32 bytes"); const r = 20, t = 2 * r + 4; const c = Math.max(1, key.length / 4); const L = Array.from({ length: c }, (_, i) => new DataView(key.buffer, key.byteOffset).getUint32(i * 4, true));
  const S = [0xb7e15163]; for (let i = 1; i < t; i++) S[i] = (S[i - 1] + 0x9e3779b9) >>> 0; let A = 0, B = 0, i = 0, j = 0; for (let s = 0; s < 3 * Math.max(t, c); s++) { A = S[i] = rotl((S[i] + A + B) >>> 0, 3); B = L[j] = rotl((L[j] + A + B) >>> 0, (A + B) >>> 0); i = (i + 1) % t; j = (j + 1) % c; }
  const mul = (a, b) => Math.imul(a, b) >>> 0;
  const rd = (b) => { const d = new DataView(b.buffer, b.byteOffset, 16); return [0, 4, 8, 12].map((o) => d.getUint32(o, true)); }; const wr = (w) => { const o = new Uint8Array(16), d = new DataView(o.buffer); w.forEach((x, k) => d.setUint32(k * 4, x >>> 0, true)); return o; };
  return { size: 16,
    enc: (blk) => { let [a, b, cc, d] = rd(blk); b = (b + S[0]) >>> 0; d = (d + S[1]) >>> 0; for (let k = 1; k <= r; k++) { const tt = rotl(mul(b, (2 * b + 1) >>> 0), 5), u = rotl(mul(d, (2 * d + 1) >>> 0), 5); a = (rotl((a ^ tt) >>> 0, u) + S[2 * k]) >>> 0; cc = (rotl((cc ^ u) >>> 0, tt) + S[2 * k + 1]) >>> 0; [a, b, cc, d] = [b, cc, d, a]; } a = (a + S[2 * r + 2]) >>> 0; cc = (cc + S[2 * r + 3]) >>> 0; return wr([a, b, cc, d]); },
    dec: (blk) => { let [a, b, cc, d] = rd(blk); cc = (cc - S[2 * r + 3]) >>> 0; a = (a - S[2 * r + 2]) >>> 0; for (let k = r; k >= 1; k--) { [a, b, cc, d] = [d, a, b, cc]; const u = rotl(mul(d, (2 * d + 1) >>> 0), 5), tt = rotl(mul(b, (2 * b + 1) >>> 0), 5); cc = (rotr((cc - S[2 * k + 1]) >>> 0, tt) ^ u) >>> 0; a = (rotr((a - S[2 * k]) >>> 0, u) ^ tt) >>> 0; } d = (d - S[1]) >>> 0; b = (b - S[0]) >>> 0; return wr([a, b, cc, d]); } }; };

// ---------- PRESENT-80/128 ----------
const PS = [0xc, 0x5, 0x6, 0xb, 0x9, 0x0, 0xa, 0xd, 0x3, 0xe, 0xf, 0x8, 0x4, 0x7, 0x1, 0x2]; const PSI = PS.map((_, i) => PS.indexOf(i));
const presentCipher = (key) => { if (key.length !== 10 && key.length !== 16) throw new Error("PRESENT key must be 10 (80-bit) or 16 (128-bit) bytes"); let K = 0n; for (const b of key) K = (K << 8n) | BigInt(b); const kb = BigInt(key.length * 8); const KM = (1n << kb) - 1n; const rk = [];
  for (let i = 1; i <= 32; i++) { rk.push(K >> (kb - 64n)); K = ((K << 61n) | (K >> (kb - 61n))) & KM; if (kb === 80n) { K = (BigInt(PS[Number(K >> 76n)]) << 76n) | (K & ((1n << 76n) - 1n)); K ^= BigInt(i) << 15n; } else { K = (BigInt(PS[Number(K >> 124n)]) << 124n) | (BigInt(PS[Number((K >> 120n) & 15n)]) << 120n) | (K & ((1n << 120n) - 1n)); K ^= BigInt(i) << 62n; } }
  const sub = (s, box) => { let o = 0n; for (let i = 0n; i < 16n; i++) o |= BigInt(box[Number((s >> (4n * i)) & 15n)]) << (4n * i); return o; };
  const perm = (s) => { let o = 0n; for (let i = 0n; i < 64n; i++) if ((s >> i) & 1n) o |= 1n << (i === 63n ? 63n : (16n * i) % 63n); return o; };
  const permInv = (s) => { let o = 0n; for (let i = 0n; i < 64n; i++) { const p = i === 63n ? 63n : (16n * i) % 63n; if ((s >> p) & 1n) o |= 1n << i; } return o; };
  const toB = (blk) => blk.reduce((a, b) => (a << 8n) | BigInt(b), 0n); const fromB = (s) => Uint8Array.from({ length: 8 }, (_, i) => Number((s >> BigInt(8 * (7 - i))) & 255n));
  return { size: 8, enc: (blk) => { let s = toB(blk); for (let i = 0; i < 31; i++) s = perm(sub(s ^ rk[i], PS)); return fromB(s ^ rk[31]); }, dec: (blk) => { let s = toB(blk) ^ rk[31]; for (let i = 30; i >= 0; i--) s = sub(permInv(s), PSI) ^ rk[i]; return fromB(s); } }; };

// ---------- modes ----------
const pkcs7 = (b, n) => { const p = n - (b.length % n); return new Uint8Array([...b, ...new Array(p).fill(p)]); };
const unpad = (b, n) => { const p = b[b.length - 1]; if (!p || p > n || b.subarray(b.length - p).some((x) => x !== p)) throw new Error("Bad padding — wrong key, IV or mode"); return b.subarray(0, b.length - p); };
function crypt(cipher, data, mode, iv, decrypt, padding) {
  const n = cipher.size; const xor = (a, b) => a.map((x, i) => x ^ b[i]);
  if (["CBC", "CFB", "OFB", "CTR"].includes(mode) && iv.length !== n) throw new Error(`IV must be ${n} bytes for ${mode}`);
  if (mode === "ECB" || mode === "CBC") {
    if (!decrypt && padding === "PKCS#7") data = pkcs7(data, n); else if (!decrypt && padding === "Zero" && data.length % n) data = new Uint8Array([...data, ...new Array(n - (data.length % n)).fill(0)]);
    if (data.length % n) throw new Error(`Input must be a multiple of ${n} bytes (or enable padding)`);
    const out = new Uint8Array(data.length); let prev = iv;
    for (let o = 0; o < data.length; o += n) { const blk = data.slice(o, o + n);
      if (mode === "ECB") out.set(decrypt ? cipher.dec(blk) : cipher.enc(blk), o);
      else if (decrypt) { out.set(xor(cipher.dec(blk), prev), o); prev = blk; } else { prev = cipher.enc(xor(blk, prev)); out.set(prev, o); } }
    return decrypt && padding === "PKCS#7" ? unpad(out, n) : out;
  }
  const out = new Uint8Array(data.length); let reg = iv.slice();
  for (let o = 0; o < data.length; o += n) { let ks; if (mode === "CTR") { ks = cipher.enc(reg); for (let k = n - 1; k >= 0; k--) { reg[k] = (reg[k] + 1) & 255; if (reg[k]) break; } } else if (mode === "OFB") { reg = cipher.enc(reg); ks = reg; } else { ks = cipher.enc(reg); }
    const chunk = data.subarray(o, o + n); const res = chunk.map((x, i) => x ^ ks[i]); out.set(res, o); if (mode === "CFB") { reg = new Uint8Array(n); reg.set(decrypt ? chunk : res); } }
  return out;
}
const decIn = (i, e) => (e === "Hex" ? hexToBytes(i) : e === "Base64" ? base64ToBytes(i) : utf8(i));
const encOut = (b, e) => (e === "Base64" ? bytesToBase64(b) : e === "Raw" ? fromUtf8(b) : bytesToHex(b));
const blockOp = (name, mk, decrypt, def = {}) => ({ name, run: (i, a) => encOut(crypt(mk(parseBytes(a.key, a.keyEncoding)), decIn(i, a.inputEncoding), a.mode, a.mode === "ECB" ? new Uint8Array(0) : hexToBytes(a.iv), decrypt, a.padding), a.output),
  args: [opt("key", "Key", "text", { default: def.key || "" }), select("keyEncoding", "Key format", ["hex", "utf8", "base64"]), opt("iv", "IV (hex)", "text", { default: def.iv || "0000000000000000" }), select("mode", "Mode", ["CBC", "ECB", "CTR", "OFB", "CFB"]), select("padding", "Padding", ["PKCS#7", "None", "Zero"]),
    select("inputEncoding", "Input format", decrypt ? ["Hex", "Base64", "Raw"] : ["Raw", "Hex", "Base64"]), select("output", "Output format", decrypt ? ["Raw", "Hex", "Base64"] : ["Hex", "Base64", "Raw"])] });

// ---------- Rabbit (RFC 4503) ----------
function rabbit(key, iv) {
  if (key.length !== 16) throw new Error("Rabbit key must be 16 bytes"); if (iv.length && iv.length !== 8) throw new Error("Rabbit IV must be 8 bytes (or empty)");
  const A = [0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3, 0x34d34d34, 0x4d34d34d, 0xd34d34d3]; const X = new Array(8), C = new Array(8); let b = 0;
  const g = (u, v) => { const x = BigInt((u + v) >>> 0); const sq = x * x; return Number((sq ^ (sq >> 32n)) & 0xffffffffn); };
  const next = () => { for (let j = 0; j < 8; j++) { const t = C[j] + A[j] + b; b = t > 0xffffffff ? 1 : 0; C[j] = t >>> 0; } const G = X.map((x, j) => g(x, C[j]));
    X[0] = (G[0] + rotl(G[7], 16) + rotl(G[6], 16)) >>> 0; X[1] = (G[1] + rotl(G[0], 8) + G[7]) >>> 0; X[2] = (G[2] + rotl(G[1], 16) + rotl(G[0], 16)) >>> 0; X[3] = (G[3] + rotl(G[2], 8) + G[1]) >>> 0;
    X[4] = (G[4] + rotl(G[3], 16) + rotl(G[2], 16)) >>> 0; X[5] = (G[5] + rotl(G[4], 8) + G[3]) >>> 0; X[6] = (G[6] + rotl(G[5], 16) + rotl(G[4], 16)) >>> 0; X[7] = (G[7] + rotl(G[6], 8) + G[5]) >>> 0; };
  const kd = new DataView(key.buffer, key.byteOffset); const k = [0, 1, 2, 3, 4, 5, 6, 7].map((i) => kd.getUint16(i * 2, true));
  for (let j = 0; j < 8; j++) { if (j % 2 === 0) { X[j] = ((k[(j + 1) % 8] << 16) | k[j]) >>> 0; C[j] = ((k[(j + 4) % 8] << 16) | k[(j + 5) % 8]) >>> 0; } else { X[j] = ((k[(j + 5) % 8] << 16) | k[(j + 4) % 8]) >>> 0; C[j] = ((k[j] << 16) | k[(j + 1) % 8]) >>> 0; } }
  for (let i = 0; i < 4; i++) next(); for (let j = 0; j < 8; j++) C[j] = (C[j] ^ X[(j + 4) % 8]) >>> 0;
  if (iv.length) { const d = new DataView(iv.buffer, iv.byteOffset); const i0 = d.getUint32(0, true), i2 = d.getUint32(4, true); const i1 = ((i2 & 0xffff0000) | (i0 >>> 16)) >>> 0, i3 = ((i2 << 16) | (i0 & 0xffff)) >>> 0;
    C[0] ^= i0; C[1] ^= i1; C[2] ^= i2; C[3] ^= i3; C[4] ^= i0; C[5] ^= i1; C[6] ^= i2; C[7] ^= i3; for (let j = 0; j < 8; j++) C[j] >>>= 0; for (let i = 0; i < 4; i++) next(); }
  return () => { next(); const s = [X[0] ^ (X[5] >>> 16) ^ (X[3] << 16), X[2] ^ (X[7] >>> 16) ^ (X[5] << 16), X[4] ^ (X[1] >>> 16) ^ (X[7] << 16), X[6] ^ (X[3] >>> 16) ^ (X[1] << 16)]; const o = new Uint8Array(16), d = new DataView(o.buffer); s.forEach((w, i) => d.setUint32(i * 4, w >>> 0, true)); return o; };
}

export const ops = {
  "des-encrypt": blockOp("DES Encrypt", desCipher, false, { key: "0123456789abcdef" }), "des-decrypt": blockOp("DES Decrypt", desCipher, true, { key: "0123456789abcdef" }),
  "3des-encrypt": blockOp("Triple DES Encrypt", tdesCipher, false, { key: "0123456789abcdeffedcba98765432100123456789abcdef" }), "3des-decrypt": blockOp("Triple DES Decrypt", tdesCipher, true, { key: "0123456789abcdeffedcba98765432100123456789abcdef" }),
  "blowfish-encrypt": blockOp("Blowfish Encrypt", blowfishCipher, false, { key: "0123456789abcdef" }), "blowfish-decrypt": blockOp("Blowfish Decrypt", blowfishCipher, true, { key: "0123456789abcdef" }),
  "rc6-encrypt": blockOp("RC6 Encrypt", rc6Cipher, false, { key: "000102030405060708090a0b0c0d0e0f", iv: "00000000000000000000000000000000" }), "rc6-decrypt": blockOp("RC6 Decrypt", rc6Cipher, true, { key: "000102030405060708090a0b0c0d0e0f", iv: "00000000000000000000000000000000" }),
  "present-encrypt": blockOp("PRESENT Encrypt", presentCipher, false, { key: "00000000000000000000" }), "present-decrypt": blockOp("PRESENT Decrypt", presentCipher, true, { key: "00000000000000000000" }),
  rabbit: { name: "Rabbit", run: (i, a) => { const ks = rabbit(parseBytes(a.key, a.keyEncoding), hexToBytes(a.iv || "")); const d = decIn(i, a.inputEncoding); const out = new Uint8Array(d.length); let blk; for (let k = 0; k < d.length; k++) { if (k % 16 === 0) blk = ks(); out[k] = d[k] ^ blk[k % 16]; } return encOut(out, a.output); },
    args: [opt("key", "Key (16 bytes)", "text", { default: "00000000000000000000000000000000" }), select("keyEncoding", "Key format", ["hex", "utf8", "base64"]), opt("iv", "IV (8 bytes hex, optional)", "text"), select("inputEncoding", "Input format", ["Raw", "Hex", "Base64"]), select("output", "Output format", ["Hex", "Base64", "Raw"])] },
  "evp-key": { name: "Derive EVP key (OpenSSL)", run: async (i, a) => { const salt = hexToBytes(a.salt || ""); const need = Number(a.keyLen) + Number(a.ivLen); let prev = new Uint8Array(0); const out = []; const H = async (b) => (a.hash === "MD5" ? md5(b) : new Uint8Array(await crypto.subtle.digest(a.hash, b)));
    while (out.length < need) { let d = await H(new Uint8Array([...prev, ...utf8(i), ...salt])); for (let k = 1; k < Number(a.iterations); k++) d = await H(d); out.push(...d); prev = d; }
    const b = new Uint8Array(out); return `Key: ${bytesToHex(b.subarray(0, Number(a.keyLen)))}\nIV:  ${bytesToHex(b.subarray(Number(a.keyLen), need))}`; },
    args: [opt("salt", "Salt (hex, 8 bytes)", "text", { default: "0102030405060708" }), select("hash", "Digest", ["MD5", "SHA-256", "SHA-1"]), opt("keyLen", "Key length (bytes)", "number", { default: 32 }), opt("ivLen", "IV length (bytes)", "number", { default: 16 }), opt("iterations", "Iterations", "number", { default: 1 })], placeholder: "Passphrase" },
  "bcrypt-hash": { name: "Bcrypt", run: (i, a) => bcrypt(String(i), Number(a.cost), crypto.getRandomValues(new Uint8Array(16))), args: [opt("cost", "Cost (rounds = 2^cost)", "number", { default: 10 })], placeholder: "Password" },
  "bcrypt-compare": { name: "Bcrypt compare", run: (i, a) => { const p = bcryptParse(a.hash); return bcrypt(String(i), p.cost, p.salt, p.minor || "a").slice(7) === String(a.hash).trim().slice(7) ? "✓ Password MATCHES the hash" : "✗ Password does NOT match"; }, args: [opt("hash", "Bcrypt hash", "text", { default: "" })], placeholder: "Password" },
  "bcrypt-parse": { name: "Bcrypt parse", run: (i) => { const p = bcryptParse(i); return `Algorithm: $2${p.minor}$ (${({ a: "original OpenBSD", b: "OpenBSD 2014 fix", y: "PHP crypt_blowfish fix", x: "crypt_blowfish buggy" })[p.minor] || "legacy"})\nCost: ${p.cost} (${(2 ** p.cost).toLocaleString()} rounds)\nSalt: ${p.saltText} (hex ${bytesToHex(p.salt)})\nHash: ${p.hash}`; }, placeholder: "$2b$10$..." },
};
export { blowfishCipher, desCipher, tdesCipher, rc6Cipher, presentCipher, crypt, rabbit };
