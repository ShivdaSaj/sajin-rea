// QR Code encoder (ISO/IEC 18004): numeric / alphanumeric / byte modes, versions 1–40,
// ECC L/M/Q/H, automatic mask selection. Renders SVG. Used by the QR tools.
import { utf8, bytesToBase64, select, opt } from "./util.js";

const ECC = { L: 0, M: 1, Q: 2, H: 3 }; const FORMAT_BITS = [1, 0, 3, 2];
const ECC_PER_BLOCK = [
  [-1, 7, 10, 15, 20, 26, 18, 20, 24, 30, 18, 20, 24, 26, 30, 22, 24, 28, 30, 28, 28, 28, 28, 30, 30, 26, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 10, 16, 26, 18, 24, 16, 18, 22, 22, 26, 30, 22, 22, 24, 24, 28, 28, 26, 26, 26, 26, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28, 28],
  [-1, 13, 22, 18, 26, 18, 24, 18, 22, 20, 24, 28, 26, 24, 20, 30, 24, 28, 28, 26, 30, 28, 30, 30, 30, 30, 28, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
  [-1, 17, 28, 22, 16, 22, 28, 26, 26, 24, 28, 24, 28, 22, 24, 24, 30, 28, 28, 26, 28, 30, 24, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30, 30],
];
const NUM_BLOCKS = [
  [-1, 1, 1, 1, 1, 1, 2, 2, 2, 2, 4, 4, 4, 4, 4, 6, 6, 6, 6, 7, 8, 8, 9, 9, 10, 12, 12, 12, 13, 14, 15, 16, 17, 18, 19, 19, 20, 21, 22, 24, 25],
  [-1, 1, 1, 1, 2, 2, 4, 4, 4, 5, 5, 5, 8, 9, 9, 10, 10, 11, 13, 14, 16, 17, 17, 18, 20, 21, 23, 25, 26, 28, 29, 31, 33, 35, 37, 38, 40, 43, 45, 47, 49],
  [-1, 1, 1, 2, 2, 4, 4, 6, 6, 8, 8, 8, 10, 12, 16, 12, 17, 16, 18, 21, 20, 23, 23, 25, 27, 29, 34, 34, 35, 38, 40, 43, 45, 48, 51, 53, 56, 59, 62, 65, 68],
  [-1, 1, 1, 2, 4, 4, 4, 5, 6, 8, 8, 11, 11, 16, 16, 18, 16, 19, 21, 25, 25, 25, 34, 30, 32, 35, 37, 40, 42, 45, 48, 51, 54, 57, 60, 63, 66, 70, 74, 77, 81],
];
const rawModules = (v) => { let r = (16 * v + 128) * v + 64; if (v >= 2) { const n = Math.floor(v / 7) + 2; r -= (25 * n - 10) * n - 55; if (v >= 7) r -= 36; } return r; };
const dataCodewords = (v, e) => Math.floor(rawModules(v) / 8) - ECC_PER_BLOCK[e][v] * NUM_BLOCKS[e][v];
function alignPositions(v) { if (v === 1) return []; const n = Math.floor(v / 7) + 2; const size = v * 4 + 17; const step = v === 32 ? 26 : Math.ceil((v * 4 + 4) / (n * 2 - 2)) * 2; const r = [6]; for (let pos = size - 7; r.length < n; pos -= step) r.splice(1, 0, pos); return r; }

// GF(256) Reed–Solomon with polynomial 0x11D
const gfMul = (x, y) => { let z = 0; for (let i = 7; i >= 0; i--) { z = (z << 1) ^ ((z >>> 7) * 0x11d); z ^= ((y >>> i) & 1) * x; } return z & 255; };
function rsDivisor(deg) { const r = new Array(deg).fill(0); r[deg - 1] = 1; let root = 1; for (let i = 0; i < deg; i++) { for (let j = 0; j < r.length; j++) { r[j] = gfMul(r[j], root); if (j + 1 < r.length) r[j] ^= r[j + 1]; } root = gfMul(root, 2); } return r; }
function rsRemainder(data, div) { const r = new Array(div.length).fill(0); for (const b of data) { const f = b ^ r.shift(); r.push(0); div.forEach((c, i) => (r[i] ^= gfMul(c, f))); } return r; }

const ALNUM = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";
function segmentFor(text) {
  if (/^\d*$/.test(text)) { const bits = []; for (let i = 0; i < text.length; i += 3) { const ch = text.substr(i, 3); push(bits, +ch, ch.length * 3 + 1); } return { mode: 1, count: text.length, bits, ccBits: [10, 12, 14] }; }
  if ([...text].every((c) => ALNUM.includes(c))) { const bits = []; for (let i = 0; i + 1 < text.length; i += 2) push(bits, ALNUM.indexOf(text[i]) * 45 + ALNUM.indexOf(text[i + 1]), 11); if (text.length % 2) push(bits, ALNUM.indexOf(text.at(-1)), 6); return { mode: 2, count: text.length, bits, ccBits: [9, 11, 13] }; }
  const b = utf8(text); const bits = []; for (const x of b) push(bits, x, 8); return { mode: 4, count: b.length, bits, ccBits: [8, 16, 16] };
}
function push(arr, val, len) { for (let i = len - 1; i >= 0; i--) arr.push((val >>> i) & 1); }

export function qrEncode(text, eccName = "M", minVersion = 1, boostEcc = true) {
  let e = ECC[eccName]; const seg = segmentFor(String(text)); let version, used;
  for (version = minVersion; ; version++) { if (version > 40) throw new Error("Data too long for a QR code (max ~2,950 bytes at level L)"); const cc = seg.ccBits[version < 10 ? 0 : version < 27 ? 1 : 2]; used = 4 + cc + seg.bits.length; if (seg.count < 2 ** cc && used <= dataCodewords(version, e) * 8) break; }
  if (boostEcc) for (const ne of [ECC.M, ECC.Q, ECC.H]) if (ne > e && used <= dataCodewords(version, ne) * 8) e = ne;
  const cap = dataCodewords(version, e) * 8; const bits = []; push(bits, seg.mode, 4); push(bits, seg.count, seg.ccBits[version < 10 ? 0 : version < 27 ? 1 : 2]); bits.push(...seg.bits);
  push(bits, 0, Math.min(4, cap - bits.length)); push(bits, 0, (8 - (bits.length % 8)) % 8); for (let pad = 0xec; bits.length < cap; pad ^= 0xec ^ 0x11) push(bits, pad, 8);
  const data = []; for (let i = 0; i < bits.length; i += 8) data.push(parseInt(bits.slice(i, i + 8).join(""), 2));
  // split into blocks, add ECC, interleave
  const nb = NUM_BLOCKS[e][version], eccLen = ECC_PER_BLOCK[e][version], raw = Math.floor(rawModules(version) / 8); const shortBlocks = nb - (raw % nb), shortLen = Math.floor(raw / nb);
  const div = rsDivisor(eccLen); const blocks = []; for (let i = 0, k = 0; i < nb; i++) { const dat = data.slice(k, k + shortLen - eccLen + (i < shortBlocks ? 0 : 1)); k += dat.length; const ecc = rsRemainder(dat, div); if (i < shortBlocks) dat.push(0); blocks.push(dat.concat(ecc)); }
  const codewords = []; for (let i = 0; i < blocks[0].length; i++) blocks.forEach((b, j) => { if (i !== shortLen - eccLen || j >= shortBlocks) codewords.push(b[i]); });
  // matrix
  const size = version * 4 + 17; const M = Array.from({ length: size }, () => new Array(size).fill(false)); const F = Array.from({ length: size }, () => new Array(size).fill(false));
  const set = (x, y, d) => { M[y][x] = d; F[y][x] = true; };
  for (let i = 0; i < size; i++) { set(6, i, i % 2 === 0); set(i, 6, i % 2 === 0); }
  const finder = (cx, cy) => { for (let dy = -4; dy <= 4; dy++) for (let dx = -4; dx <= 4; dx++) { const d = Math.max(Math.abs(dx), Math.abs(dy)); const x = cx + dx, y = cy + dy; if (x >= 0 && x < size && y >= 0 && y < size) set(x, y, d !== 2 && d !== 4); } };
  finder(3, 3); finder(size - 4, 3); finder(3, size - 4);
  const al = alignPositions(version); for (let i = 0; i < al.length; i++) for (let j = 0; j < al.length; j++) { if ((i === 0 && j === 0) || (i === 0 && j === al.length - 1) || (i === al.length - 1 && j === 0)) continue; for (let dy = -2; dy <= 2; dy++) for (let dx = -2; dx <= 2; dx++) set(al[i] + dx, al[j] + dy, Math.max(Math.abs(dx), Math.abs(dy)) !== 1); }
  const drawFormat = (mask) => { const d = (FORMAT_BITS[e] << 3) | mask; let r = d; for (let i = 0; i < 10; i++) r = (r << 1) ^ ((r >>> 9) * 0x537); const b = ((d << 10) | r) ^ 0x5412; const bit = (i) => ((b >>> i) & 1) !== 0;
    for (let i = 0; i <= 5; i++) set(8, i, bit(i)); set(8, 7, bit(6)); set(8, 8, bit(7)); set(7, 8, bit(8)); for (let i = 9; i < 15; i++) set(14 - i, 8, bit(i));
    for (let i = 0; i < 8; i++) set(size - 1 - i, 8, bit(i)); for (let i = 8; i < 15; i++) set(8, size - 15 + i, bit(i)); set(8, size - 8, true); };
  drawFormat(0);
  if (version >= 7) { let r = version; for (let i = 0; i < 12; i++) r = (r << 1) ^ ((r >>> 11) * 0x1f25); const b = (version << 12) | r; for (let i = 0; i < 18; i++) { const bit = ((b >>> i) & 1) !== 0; const a = size - 11 + (i % 3), c = Math.floor(i / 3); set(a, c, bit); set(c, a, bit); } }
  // data placement (zigzag)
  let k = 0; for (let right = size - 1; right >= 1; right -= 2) { if (right === 6) right = 5; for (let vert = 0; vert < size; vert++) for (let j = 0; j < 2; j++) { const x = right - j; const up = ((right + 1) & 2) === 0; const y = up ? size - 1 - vert : vert; if (!F[y][x] && k < codewords.length * 8) { M[y][x] = ((codewords[k >>> 3] >>> (7 - (k & 7))) & 1) !== 0; k++; } } }
  const MASKS = [(x, y) => (x + y) % 2 === 0, (x, y) => y % 2 === 0, (x) => x % 3 === 0, (x, y) => (x + y) % 3 === 0, (x, y) => (Math.floor(x / 3) + Math.floor(y / 2)) % 2 === 0, (x, y) => ((x * y) % 2) + ((x * y) % 3) === 0, (x, y) => (((x * y) % 2) + ((x * y) % 3)) % 2 === 0, (x, y) => (((x + y) % 2) + ((x * y) % 3)) % 2 === 0];
  const applyMask = (m) => { for (let y = 0; y < size; y++) for (let x = 0; x < size; x++) if (!F[y][x] && MASKS[m](x, y)) M[y][x] = !M[y][x]; };
  const penalty = () => { let p = 0; const lines = (get) => { for (let a = 0; a < size; a++) { let run = 1; for (let b = 1; b <= size; b++) { if (b < size && get(a, b) === get(a, b - 1)) run++; else { if (run >= 5) p += run - 2; run = 1; } }
      const seq = Array.from({ length: size }, (_, b) => get(a, b)); const s = seq.map((x) => (x ? 1 : 0)).join(""); for (const pat of ["10111010000", "00001011101"]) { let i = -1; while ((i = s.indexOf(pat, i + 1)) >= 0) p += 40; } } };
    lines((a, b) => M[a][b]); lines((a, b) => M[b][a]);
    for (let y = 0; y < size - 1; y++) for (let x = 0; x < size - 1; x++) { const c = M[y][x]; if (c === M[y][x + 1] && c === M[y + 1][x] && c === M[y + 1][x + 1]) p += 3; }
    let dark = 0; M.forEach((r) => r.forEach((c) => (dark += c ? 1 : 0))); const total = size * size; p += Math.max(0, Math.ceil(Math.abs(dark * 20 - total * 10) / total) - 1) * 10; return p; };
  let best = 0, bestP = Infinity; for (let m = 0; m < 8; m++) { applyMask(m); drawFormat(m); const p = penalty(); if (p < bestP) { bestP = p; best = m; } applyMask(m); }
  applyMask(best); drawFormat(best);
  return { size, modules: M, version, ecc: Object.keys(ECC)[e], mask: best };
}
export function qrSvg(qr, { scale = 8, border = 4, fg = "#000000", bg = "#ffffff" } = {}) {
  const n = qr.size + border * 2; let path = ""; qr.modules.forEach((row, y) => row.forEach((c, x) => { if (c) path += `M${x + border},${y + border}h1v1h-1z`; }));
  return `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${n} ${n}" width="${n * scale}" height="${n * scale}" shape-rendering="crispEdges"><rect width="100%" height="100%" fill="${bg}"/><path d="${path}" fill="${fg}"/></svg>`;
}
const hexColor = (c, d) => (/^#[0-9a-f]{3,8}$/i.test(String(c).trim()) ? String(c).trim() : d);
function qrResult(text, a) {
  const qr = qrEncode(text, a.ecc || "M"); const svg = qrSvg(qr, { scale: Math.max(1, Math.min(Number(a.scale) || 8, 40)), border: Math.max(0, Math.min(Number(a.border ?? 4), 20)), fg: hexColor(a.fg, "#000000"), bg: hexColor(a.bg, "#ffffff") });
  return { text: `Version ${qr.version} (${qr.size}×${qr.size} modules), error correction ${qr.ecc}, mask ${qr.mask}`, image: `data:image/svg+xml;base64,${bytesToBase64(utf8(svg))}`, download: { name: "qrcode.svg", data: utf8(svg), mime: "image/svg+xml" } };
}
const styleArgs = [select("ecc", "Error correction", ["M", "L", "Q", "H"]), opt("scale", "Pixels per module", "number", { default: 8 }), opt("border", "Quiet zone (modules)", "number", { default: 4 }), opt("fg", "Foreground", "text", { default: "#000000" }), opt("bg", "Background", "text", { default: "#ffffff" })];
const wifiEsc = (s) => String(s).replace(/([\\;,:"])/g, "\\$1");

export const ops = {
  "qr-generate": { name: "Generate QR Code", run: (i, a) => qrResult(String(i), a), args: styleArgs, placeholder: "Text or URL to encode" },
  "wifi-qr": { name: "WiFi QR Code Generator", input: false, run: (_, a) => { if (!a.ssid) throw new Error("Enter the network name (SSID)"); const t = `WIFI:T:${a.security === "None" ? "nopass" : a.security};S:${wifiEsc(a.ssid)};${a.security === "None" ? "" : `P:${wifiEsc(a.password)};`}${a.hidden ? "H:true;" : ""};`; const r = qrResult(t, a); r.text = `${r.text}\nPayload: ${t.replace(/P:[^;]*;/, "P:••••;")}`; return r; },
    args: [opt("ssid", "Network name (SSID)", "text", { default: "" }), select("security", "Security", ["WPA", "WEP", "None"]), opt("password", "Password", "text"), opt("hidden", "Hidden network", "checkbox"), ...styleArgs] },
};
