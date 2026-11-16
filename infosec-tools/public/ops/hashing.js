import { utf8, hexToBytes, bytesToHex, bytesToBase64, parseBytes, select, opt } from "./util.js";

// MD5 (RFC 1321). WebCrypto does not provide it.
export function md5(bytes) {
  const K = new Uint32Array(64), S = [7, 12, 17, 22, 5, 9, 14, 20, 4, 11, 16, 23, 6, 10, 15, 21];
  for (let i = 0; i < 64; i++) K[i] = Math.floor(Math.abs(Math.sin(i + 1)) * 2 ** 32) >>> 0;
  const len = bytes.length, padLen = ((len + 8) >>> 6 << 6) + 64;
  const m = new Uint8Array(padLen); m.set(bytes); m[len] = 0x80;
  const dv = new DataView(m.buffer);
  dv.setUint32(padLen - 8, (len * 8) >>> 0, true); dv.setUint32(padLen - 4, Math.floor(len / 0x20000000), true);
  let a0 = 0x67452301, b0 = 0xefcdab89, c0 = 0x98badcfe, d0 = 0x10325476;
  for (let off = 0; off < padLen; off += 64) {
    let A = a0, B = b0, C = c0, D = d0;
    for (let i = 0; i < 64; i++) {
      let F, g;
      if (i < 16) { F = (B & C) | (~B & D); g = i; }
      else if (i < 32) { F = (D & B) | (~D & C); g = (5 * i + 1) % 16; }
      else if (i < 48) { F = B ^ C ^ D; g = (3 * i + 5) % 16; }
      else { F = C ^ (B | ~D); g = (7 * i) % 16; }
      F = (F + A + K[i] + dv.getUint32(off + g * 4, true)) >>> 0;
      A = D; D = C; C = B;
      const s = S[(i >> 4) * 4 + (i & 3)];
      B = (B + ((F << s) | (F >>> (32 - s)))) >>> 0;
    }
    a0 = (a0 + A) >>> 0; b0 = (b0 + B) >>> 0; c0 = (c0 + C) >>> 0; d0 = (d0 + D) >>> 0;
  }
  const out = new Uint8Array(16), ov = new DataView(out.buffer);
  [a0, b0, c0, d0].forEach((v, i) => ov.setUint32(i * 4, v, true));
  return out;
}

let crcTable;
export function crc32(bytes) {
  if (!crcTable) { crcTable = new Uint32Array(256); for (let n = 0; n < 256; n++) { let c = n; for (let k = 0; k < 8; k++) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1; crcTable[n] = c >>> 0; } }
  let crc = 0xffffffff;
  for (const b of bytes) crc = crcTable[(crc ^ b) & 0xff] ^ (crc >>> 8);
  return (crc ^ 0xffffffff) >>> 0;
}

function adler32(bytes) { let a = 1, b = 0; for (const x of bytes) { a = (a + x) % 65521; b = (b + a) % 65521; } return ((b << 16) | a) >>> 0; }
function fnv1a32(bytes) { let h = 0x811c9dc5; for (const x of bytes) { h ^= x; h = Math.imul(h, 0x01000193) >>> 0; } return h >>> 0; }

const WEB = { "SHA-1": "SHA-1", "SHA-256": "SHA-256", "SHA-384": "SHA-384", "SHA-512": "SHA-512" };
export async function digest(alg, bytes) {
  if (alg === "MD5") return md5(bytes);
  return new Uint8Array(await crypto.subtle.digest(WEB[alg], bytes));
}

const fmt = (bytes, f) => (f === "Base64" ? bytesToBase64(bytes) : f === "HEX (upper)" ? bytesToHex(bytes).toUpperCase() : bytesToHex(bytes));
const inputBytes = (i, enc) => (enc === "hex" ? hexToBytes(i) : utf8(i));
const formatOpt = select("format", "Output format", ["hex", "HEX (upper)", "Base64"]);
const inputOpt = select("inputEncoding", "Input format", ["utf8", "hex"]);
const hashOp = (alg) => ({ name: alg, run: async (i, a) => fmt(await digest(alg, inputBytes(i, a.inputEncoding)), a.format), args: [formatOpt, inputOpt] });

export const ops = {
  md5: hashOp("MD5"), sha1: hashOp("SHA-1"), sha256: hashOp("SHA-256"), sha384: hashOp("SHA-384"), sha512: hashOp("SHA-512"),
  "hash-all": { name: "Hash text (all algorithms)", run: async (i, a) => {
    const b = inputBytes(i, a.inputEncoding); const rows = [];
    for (const alg of ["MD5", "SHA-1", "SHA-256", "SHA-384", "SHA-512"]) rows.push(`${alg.padEnd(8)} ${fmt(await digest(alg, b), a.format)}`);
    rows.push(`CRC32    ${crc32(b).toString(16).padStart(8, "0")}`); rows.push(`Adler32  ${adler32(b).toString(16).padStart(8, "0")}`);
    return rows.join("\n"); }, args: [formatOpt, inputOpt] },
  hmac: { name: "HMAC", run: async (i, a) => {
    const key = await crypto.subtle.importKey("raw", parseBytes(a.key, a.keyEncoding), { name: "HMAC", hash: a.hash }, false, ["sign"]);
    return fmt(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(i))), a.format);
  }, args: [opt("key", "Key", "text", { default: "secret" }), select("keyEncoding", "Key format", ["utf8", "hex", "base64"]), select("hash", "Hash", ["SHA-256", "SHA-1", "SHA-384", "SHA-512"]), formatOpt] },
  crc32: { name: "CRC-32 Checksum", run: (i, a) => crc32(inputBytes(i, a.inputEncoding)).toString(16).padStart(8, "0"), args: [inputOpt] },
  adler32: { name: "Adler-32 Checksum", run: (i, a) => adler32(inputBytes(i, a.inputEncoding)).toString(16).padStart(8, "0"), args: [inputOpt] },
  fnv1a: { name: "FNV-1a (32-bit)", run: (i) => fnv1a32(utf8(i)).toString(16).padStart(8, "0") },
  "luhn-check": { name: "Luhn Checksum", run: null },
  "hash-identify": { name: "Analyse / Identify Hash", run: (i) => {
    const h = String(i).trim(); const n = h.length; const hex = /^[0-9a-f]+$/i.test(h); const out = [];
    if (/^\$2[abxy]\$\d\d\$/.test(h)) out.push("bcrypt");
    if (/^\$argon2(id|i|d)\$/.test(h)) out.push("Argon2");
    if (/^\$6\$/.test(h)) out.push("SHA-512 crypt"); if (/^\$5\$/.test(h)) out.push("SHA-256 crypt"); if (/^\$1\$/.test(h)) out.push("MD5 crypt");
    if (hex) { const m = { 8: "CRC32 / Adler32 / FNV-32", 32: "MD5 / NTLM / MD4", 40: "SHA-1 / RIPEMD-160", 56: "SHA-224 / SHA3-224", 64: "SHA-256 / SHA3-256 / BLAKE2s", 96: "SHA-384 / SHA3-384", 128: "SHA-512 / SHA3-512 / Whirlpool / BLAKE2b" }; if (m[n]) out.push(m[n]); }
    return out.length ? `Length ${n}${hex ? " hex" : ""} — likely: ${out.join("; ")}` : `Length ${n}: no common hash format matched`;
  } },
};

ops["luhn-check"].run = (i) => {
  const d = String(i).replace(/\D/g, ""); if (d.length < 2) throw new Error("Enter at least two digits");
  const sum = (s) => { let t = 0; for (let k = 0; k < s.length; k++) { let n = +s[s.length - 1 - k]; if (k % 2) { n *= 2; if (n > 9) n -= 9; } t += n; } return t; };
  if (sum(d) % 10 === 0) return "Valid Luhn checksum";
  const body = d.slice(0, -1); const check = (10 - (sum(body + "0") % 10)) % 10;
  return `Invalid — the check digit should be ${check}`;
};
