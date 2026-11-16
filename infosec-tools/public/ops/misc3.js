// Phase 3 utilities: float, Bech32, Base92, Base64 offsets, text encodings, TLV, MIME words, BSON,
// XPath/CSS selectors, RAKE, code beautify/minify, Magic, Enigma, BIP39, cheat sheets, misc.
import { utf8, fromUtf8, hexToBytes, bytesToHex, bytesToBase64, base64ToBytes, lines, select, opt } from "./util.js";
import { registry as _r } from "./_registry-ref.js";

// ---------- IEEE 754 ----------
function toFloat(i, a) { const nums = String(i).trim().split(/[\s,]+/).filter(Boolean).map(Number); const w = a.size === "Double (64-bit)" ? 8 : 4; return nums.map((n) => { const b = new Uint8Array(w); const dv = new DataView(b.buffer); w === 8 ? dv.setFloat64(0, n, a.endian === "Little-endian") : dv.setFloat32(0, n, a.endian === "Little-endian"); return bytesToHex(b); }).join(" "); }
function fromFloat(i, a) { const b = hexToBytes(i); const w = a.size === "Double (64-bit)" ? 8 : 4; if (b.length % w) throw new Error(`Need a multiple of ${w} bytes`); const dv = new DataView(b.buffer); const out = []; for (let o = 0; o < b.length; o += w) out.push(w === 8 ? dv.getFloat64(o, a.endian === "Little-endian") : +dv.getFloat32(o, a.endian === "Little-endian").toPrecision(9)); return out.join(" "); }
const floatArgs = [select("size", "Size", ["Float (32-bit)", "Double (64-bit)"]), select("endian", "Byte order", ["Big-endian", "Little-endian"])];

// ---------- Bech32 / Bech32m (BIP-173 / BIP-350) ----------
const B32C = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"; const GEN = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
const polymod = (v) => { let c = 1; for (const x of v) { const top = c >> 25; c = ((c & 0x1ffffff) << 5) ^ x; for (let i = 0; i < 5; i++) if ((top >> i) & 1) c ^= GEN[i]; } return c >>> 0; };
const hrpExpand = (h) => [...[...h].map((c) => c.charCodeAt(0) >> 5), 0, ...[...h].map((c) => c.charCodeAt(0) & 31)];
const convertBits = (data, from, to, pad) => { let acc = 0, bits = 0; const out = []; const maxv = (1 << to) - 1; for (const v of data) { acc = (acc << from) | v; bits += from; while (bits >= to) { bits -= to; out.push((acc >> bits) & maxv); } } if (pad && bits) out.push((acc << (to - bits)) & maxv); else if (!pad && (bits >= from || ((acc << (to - bits)) & maxv))) throw new Error("Invalid padding in Bech32 data"); return out; };
function bech32Encode(hrp, bytes, m) { const data = convertBits(bytes, 8, 5, true); const C = m ? 0x2bc830a3 : 1; const pm = polymod([...hrpExpand(hrp), ...data, 0, 0, 0, 0, 0, 0]) ^ C; const chk = Array.from({ length: 6 }, (_, i) => (pm >> (5 * (5 - i))) & 31); return `${hrp}1${[...data, ...chk].map((d) => B32C[d]).join("")}`; }
function bech32Decode(s) { const str = String(s).trim(); if (str !== str.toLowerCase() && str !== str.toUpperCase()) throw new Error("Mixed case is not allowed in Bech32"); const t = str.toLowerCase(); const p = t.lastIndexOf("1"); if (p < 1 || p + 7 > t.length) throw new Error("Not a Bech32 string (missing separator '1' or checksum)");
  const hrp = t.slice(0, p); const data = [...t.slice(p + 1)].map((c) => { const k = B32C.indexOf(c); if (k < 0) throw new Error(`Invalid Bech32 character "${c}"`); return k; }); const pm = polymod([...hrpExpand(hrp), ...data]); const variant = pm === 1 ? "Bech32" : pm === 0x2bc830a3 ? "Bech32m" : null; if (!variant) throw new Error("Checksum is invalid");
  const payload = data.slice(0, -6); let bytes = null; try { bytes = new Uint8Array(convertBits(payload, 5, 8, false)); } catch { /* not byte-aligned */ }
  const segwit = (hrp === "bc" || hrp === "tb" || hrp === "bcrt") && payload.length ? `\nSegWit v${payload[0]} program: ${bytesToHex(new Uint8Array(convertBits(payload.slice(1), 5, 8, false)))}` : "";
  return `HRP: ${hrp}\nVariant: ${variant}\nData (5-bit): ${payload.join(",")}\nData (bytes): ${bytes ? bytesToHex(bytes) : "(not byte-aligned)"}${segwit}`; }

// ---------- Base92 ----------
const b92c = (n) => (n === 0 ? "!" : n <= 61 ? String.fromCharCode(n + 34) : String.fromCharCode(n + 35));
const b92o = (c) => (c === "!" ? 0 : c <= "_" ? c.charCodeAt(0) - 34 : c.charCodeAt(0) - 35);
function base92Encode(b) { if (!b.length) return "~"; let bits = ""; for (const x of b) bits += x.toString(2).padStart(8, "0"); let o = ""; while (bits.length >= 13) { const n = parseInt(bits.slice(0, 13), 2); o += b92c(Math.floor(n / 91)) + b92c(n % 91); bits = bits.slice(13); } if (bits.length) { if (bits.length < 7) o += b92c(parseInt(bits.padEnd(6, "0"), 2)); else { const n = parseInt(bits.padEnd(13, "0"), 2); o += b92c(Math.floor(n / 91)) + b92c(n % 91); } } return o; }
function base92Decode(s) { s = String(s).trim(); if (s === "~") return new Uint8Array(); let bits = ""; let i = 0; for (; i + 1 < s.length; i += 2) bits += (b92o(s[i]) * 91 + b92o(s[i + 1])).toString(2).padStart(13, "0"); if (i < s.length) bits += b92o(s[i]).toString(2).padStart(6, "0"); const out = []; for (let k = 0; k + 8 <= bits.length; k += 8) out.push(parseInt(bits.slice(k, k + 8), 2)); return new Uint8Array(out); }

// ---------- text encodings ----------
const CHARSETS = ["utf-8", "utf-16le", "utf-16be", "windows-1252", "iso-8859-1", "iso-8859-2", "iso-8859-5", "iso-8859-7", "iso-8859-15", "windows-1250", "windows-1251", "windows-1256", "koi8-r", "ibm866", "macintosh", "shift_jis", "euc-jp", "iso-2022-jp", "gbk", "gb18030", "big5", "euc-kr"];
const singleByteMaps = new Map();
function encodeText(s, cs) { if (cs === "utf-8") return utf8(s); if (cs === "utf-16le" || cs === "utf-16be") { const o = []; for (let k = 0; k < s.length; k++) { const c = s.charCodeAt(k); o.push(...(cs === "utf-16le" ? [c & 255, c >> 8] : [c >> 8, c & 255])); } return new Uint8Array(o); }
  let m = singleByteMaps.get(cs); if (!m) { let dec; try { dec = new TextDecoder(cs); } catch { throw new Error(`Unknown charset ${cs}`); } m = new Map(); for (let b = 0; b < 256; b++) { const ch = dec.decode(new Uint8Array([b])); if (ch.length === 1 && ch !== "�") m.set(ch, b); } if (m.size < 200) throw new Error(`${cs} is a multi-byte charset — only decoding is supported for it`); singleByteMaps.set(cs, m); }
  return new Uint8Array([...s].map((c) => { const b = m.get(c); if (b === undefined) throw new Error(`"${c}" cannot be represented in ${cs}`); return b; })); }
const decodeText = (b, cs) => new TextDecoder(cs, { fatal: false }).decode(b);

// ---------- BSON ----------
function bsonEncode(obj) { const out = []; const i32 = (n) => out.push(n & 255, (n >> 8) & 255, (n >> 16) & 255, (n >>> 24) & 255); const cstr = (s) => out.push(...utf8(s), 0);
  const doc = (o, isArr) => { const start = out.length; out.push(0, 0, 0, 0); for (const [k, v] of Object.entries(o)) { const key = isArr ? String(k) : k;
      if (v === null) { out.push(0x0a); cstr(key); } else if (typeof v === "boolean") { out.push(0x08); cstr(key); out.push(v ? 1 : 0); } else if (typeof v === "number" && Number.isInteger(v) && v >= -(2 ** 31) && v < 2 ** 31) { out.push(0x10); cstr(key); i32(v); }
      else if (typeof v === "number") { out.push(0x01); cstr(key); const b = new Uint8Array(8); new DataView(b.buffer).setFloat64(0, v, true); out.push(...b); } else if (typeof v === "string") { out.push(0x02); cstr(key); const b = utf8(v); i32(b.length + 1); out.push(...b, 0); }
      else if (Array.isArray(v)) { out.push(0x04); cstr(key); doc(v, true); } else { out.push(0x03); cstr(key); doc(v, false); } }
    out.push(0); const len = out.length - start; out[start] = len & 255; out[start + 1] = (len >> 8) & 255; out[start + 2] = (len >> 16) & 255; out[start + 3] = (len >>> 24) & 255; };
  doc(obj, Array.isArray(obj)); return new Uint8Array(out); }
function bsonDecode(b) { const dv = new DataView(b.buffer, b.byteOffset, b.byteLength); const cstr = (o) => { let e = o; while (b[e]) e++; return [fromUtf8(b.subarray(o, e)), e + 1]; };
  const doc = (o, isArr) => { const len = dv.getInt32(o, true); const end = o + len - 1; let p = o + 4; const res = isArr ? [] : {};
    while (p < end) { const t = b[p++]; const [k, q] = cstr(p); p = q; let v;
      switch (t) { case 0x01: v = dv.getFloat64(p, true); p += 8; break; case 0x02: { const n = dv.getInt32(p, true); v = fromUtf8(b.subarray(p + 4, p + 3 + n)); p += 4 + n; break; } case 0x03: case 0x04: { v = doc(p, t === 0x04); p += dv.getInt32(p, true); break; }
        case 0x05: { const n = dv.getInt32(p, true); v = { $binary: bytesToBase64(b.subarray(p + 5, p + 5 + n)), subtype: b[p + 4] }; p += 5 + n; break; } case 0x07: v = { $oid: bytesToHex(b.subarray(p, p + 12)) }; p += 12; break; case 0x08: v = !!b[p++]; break;
        case 0x09: v = { $date: new Date(Number(dv.getBigInt64(p, true))).toISOString() }; p += 8; break; case 0x0a: v = null; break; case 0x10: v = dv.getInt32(p, true); p += 4; break; case 0x11: v = { $timestamp: dv.getBigUint64(p, true).toString() }; p += 8; break; case 0x12: v = { $numberLong: dv.getBigInt64(p, true).toString() }; p += 8; break;
        default: throw new Error(`Unsupported BSON type 0x${t.toString(16)}`); } if (isArr) res.push(v); else res[k] = v; } return res; };
  return doc(0, false); }

// ---------- RAKE ----------
const STOP = new Set("a about above after again against all am an and any are as at be because been before being below between both but by can could did do does doing down during each few for from further had has have having he her here hers herself him himself his how i if in into is it its itself just me more most my myself no nor not now of off on once only or other our ours ourselves out over own same she should so some such than that the their theirs them themselves then there these they this those through to too under until up very was we were what when where which while who whom why will with would you your yours yourself yourselves".split(" "));
function rake(text) { const phrases = []; for (const sent of String(text).toLowerCase().split(/[.!?,;:\t\n"()\[\]{}]+/)) { let cur = []; for (const w of sent.split(/\s+/)) { const ww = w.replace(/[^a-z0-9'-]/g, ""); if (!ww || STOP.has(ww)) { if (cur.length) phrases.push(cur); cur = []; } else cur.push(ww); } if (cur.length) phrases.push(cur); }
  const freq = {}, deg = {}; for (const p of phrases) for (const w of p) { freq[w] = (freq[w] || 0) + 1; deg[w] = (deg[w] || 0) + p.length; } const score = (p) => p.reduce((s, w) => s + deg[w] / freq[w], 0);
  const seen = new Map(); for (const p of phrases) { const k = p.join(" "); seen.set(k, score(p)); } return [...seen].sort((a, b) => b[1] - a[1]); }

// ---------- code tidy ----------
function genericBeautify(code, indent = "  ") { let depth = 0; const out = []; const toks = String(code).replace(/\r/g, "").split("\n").map((l) => l.trim()).filter((l, k, arr) => l || (arr[k - 1] && arr[k - 1].trim()));
  for (let l of toks) { const opens = (l.match(/[{[(]/g) || []).length, closes = (l.match(/[}\])]/g) || []).length; const leadClose = /^[}\])]/.test(l) ? 1 : 0; depth = Math.max(0, depth - leadClose); out.push(indent.repeat(depth) + l); depth = Math.max(0, depth + opens - closes + leadClose); } return out.join("\n"); }
function jsMinify(src) { let out = "", i = 0; const s = String(src); let lastSig = "";
  while (i < s.length) { const c = s[i], n = s[i + 1];
    if (c === "/" && n === "/") { while (i < s.length && s[i] !== "\n") i++; continue; } if (c === "/" && n === "*") { const e = s.indexOf("*/", i + 2); i = e < 0 ? s.length : e + 2; continue; }
    if (c === '"' || c === "'" || c === "`") { let j = i + 1; while (j < s.length && s[j] !== c) { if (s[j] === "\\") j++; j++; } out += s.slice(i, j + 1); i = j + 1; lastSig = c; continue; }
    if (c === "/" && /[(,=:[!&|?{};+\-*%<>~^]$|^$|return$|typeof$/.test(out.trimEnd() || "")) { let j = i + 1, cls = false; while (j < s.length && (s[j] !== "/" || cls)) { if (s[j] === "\\") j++; else if (s[j] === "[") cls = true; else if (s[j] === "]") cls = false; j++; } j++; while (/[a-z]/i.test(s[j] || "")) j++; out += s.slice(i, j); i = j; continue; }
    if (/\s/.test(c)) { let j = i; let nl = false; while (j < s.length && /\s/.test(s[j])) { if (s[j] === "\n") nl = true; j++; } const prev = out.at(-1) || "", next = s[j] || "";
      // keep a newline wherever automatic semicolon insertion could apply (e.g. "return⏎x"), else the minimum separator
      if (nl && /[\w$)\]'"`]/.test(prev) && /[\w$([{'"`+\-!~]/.test(next)) out += "\n"; else if (/[\w$]/.test(prev) && /[\w$]/.test(next)) out += " "; else if ((prev === "+" && next === "+") || (prev === "-" && next === "-")) out += " "; i = j; continue; }
    out += c; lastSig = c; i++; } void lastSig; return out.trim(); }

// ---------- Magic ----------
async function magic(input, depth) { const R = _r(); const tries = ["base64-decode", "hex-decode", "url-decode", "base32-decode", "binary-decode", "decimal-decode", "octal-decode", "html-decode", "rot13", "rot47", "base58-decode", "base85-decode", "quoted-printable-decode", "unicode-unescape", "morse-decode", "base45-decode", "charcode-decode", "gunzip", "zlib-inflate", "raw-inflate"];
  const score = (s) => { if (!s) return -1; let p = 0, letters = 0, words = (s.match(/\b(the|and|is|in|to|of|a|for|http|www|com|password|flag|key|user)\b/gi) || []).length; for (const ch of s) { const k = ch.charCodeAt(0); if ((k >= 32 && k < 127) || k === 10 || k === 13 || k === 9) p++; if (/[a-z]/i.test(ch)) letters++; } return (p / s.length) * 2 + letters / s.length + Math.min(words, 10) * 0.2 - (s.includes("�") ? 2 : 0); };
  const results = []; const seen = new Set();
  const walk = async (text, path, d) => { for (const k of tries) { const op = R[k]; if (!op) continue; let out; try { const a = Object.fromEntries((op.args || []).map((x) => [x.name, x.default ?? (x.options ? x.options[0] : "")])); out = String(await op.run(text, a)); } catch { continue; } if (!out || out === text || seen.has(out) || out.length < 1) continue; seen.add(out);
      const sc = score(out); const np = [...path, op.name]; if (sc > score(text) + 0.15) results.push({ path: np, out, sc }); if (d > 1 && sc > 1.5) await walk(out, np, d - 1); } };
  await walk(String(input), [], depth); return results.sort((a, b) => b.sc - a.sc || a.path.length - b.path.length).slice(0, 12); }

// ---------- Enigma (Wehrmacht/Kriegsmarine I, M3) ----------
const ROTORS = { I: ["EKMFLGDQVZNTOWYHXUSPAIBRCJ", "Q"], II: ["AJDKSIRUXBLHWTMCQGZNPYFVOE", "E"], III: ["BDFHJLCPRTXVZNYEIWGAKMUSQO", "V"], IV: ["ESOVPZJAYQUIRHXLNFTGKDCMWB", "J"], V: ["VZBRGITYUPSDNHLXAWMJQOFECK", "Z"], VI: ["JPGVOUMFYQBENHZRDKASXLICTW", "ZM"], VII: ["NZJHGRCXMYSWBOUFAIVLPEKQDT", "ZM"], VIII: ["FKQHTLXOCBJSPDZRAMEWNIUYGV", "ZM"] };
const REFLECTORS = { B: "YRUHQSLDPXNGOKMIEBFZCWVJAT", C: "FVPJIAOYEDRZXWGCTKUQSBNMHL" };
function enigma(text, a) { const names = [a.left, a.middle, a.right]; const rot = names.map((n) => ROTORS[n]); const ring = String(a.rings || "AAA").toUpperCase().padEnd(3, "A").split("").map((c) => c.charCodeAt(0) - 65); let pos = String(a.positions || "AAA").toUpperCase().padEnd(3, "A").split("").map((c) => c.charCodeAt(0) - 65);
  const plug = {}; for (const pair of String(a.plugboard || "").toUpperCase().split(/\s+/).filter(Boolean)) { if (!/^[A-Z]{2}$/.test(pair) || plug[pair[0]] || plug[pair[1]]) throw new Error(`Bad plugboard pair "${pair}"`); plug[pair[0]] = pair[1]; plug[pair[1]] = pair[0]; }
  const fwd = (r, c, p, rg) => (rot[r][0].charCodeAt((c + p - rg + 26) % 26) - 65 - p + rg + 26) % 26; const back = (r, c, p, rg) => (rot[r][0].indexOf(String.fromCharCode(((c + p - rg + 26) % 26) + 65)) - p + rg + 26) % 26; const notch = (r) => rot[r][1].includes(String.fromCharCode(pos[r] + 65));
  let out = ""; for (const ch0 of String(text).toUpperCase()) { if (!/[A-Z]/.test(ch0)) { if (a.keepOther) out += ch0; continue; }
    if (notch(1)) { pos[0] = (pos[0] + 1) % 26; pos[1] = (pos[1] + 1) % 26; } else if (notch(2)) pos[1] = (pos[1] + 1) % 26; pos[2] = (pos[2] + 1) % 26;
    let c = (plug[ch0] || ch0).charCodeAt(0) - 65; for (const r of [2, 1, 0]) c = fwd(r, c, pos[r], ring[r]); c = REFLECTORS[a.reflector].charCodeAt(c) - 65; for (const r of [0, 1, 2]) c = back(r, c, pos[r], ring[r]); const o = String.fromCharCode(c + 65); out += plug[o] || o; }
  return `${out}\n\nFinal rotor positions: ${pos.map((p) => String.fromCharCode(p + 65)).join("")}`; }

// ---------- BIP39 ----------
let WORDS; async function words() { if (WORDS) return WORDS; let txt; if (typeof window !== "undefined" && typeof fetch !== "undefined" && typeof location !== "undefined") txt = await (await fetch("/data/bip39-english.txt")).text(); else { const fs = await import("node:fs"); txt = fs.readFileSync(new URL("../data/bip39-english.txt", import.meta.url), "utf8"); } WORDS = txt.trim().split(/\s+/); if (WORDS.length !== 2048) throw new Error("BIP39 wordlist failed to load"); return WORDS; }
async function entropyToMnemonic(ent) { const W = await words(); const h = new Uint8Array(await crypto.subtle.digest("SHA-256", ent)); let bits = [...ent].map((b) => b.toString(2).padStart(8, "0")).join("") + [...h].map((b) => b.toString(2).padStart(8, "0")).join("").slice(0, ent.length / 4); return bits.match(/.{11}/g).map((x) => W[parseInt(x, 2)]).join(" "); }
async function mnemonicToEntropy(m) { const W = await words(); const ws = String(m).trim().toLowerCase().split(/\s+/); if (![12, 15, 18, 21, 24].includes(ws.length)) throw new Error(`A BIP39 phrase has 12, 15, 18, 21 or 24 words (got ${ws.length})`); const bits = ws.map((w) => { const k = W.indexOf(w); if (k < 0) throw new Error(`"${w}" is not in the BIP39 English wordlist`); return k.toString(2).padStart(11, "0"); }).join("");
  const cs = ws.length / 3, entBits = bits.slice(0, bits.length - cs); const ent = new Uint8Array(entBits.match(/.{8}/g).map((x) => parseInt(x, 2))); const h = new Uint8Array(await crypto.subtle.digest("SHA-256", ent)); const want = [...h].map((b) => b.toString(2).padStart(8, "0")).join("").slice(0, cs); return { ent, ok: want === bits.slice(-cs) }; }
async function bip39Seed(m, pass) { const k = await crypto.subtle.importKey("raw", utf8(String(m).normalize("NFKD")), "PBKDF2", false, ["deriveBits"]); return new Uint8Array(await crypto.subtle.deriveBits({ name: "PBKDF2", salt: utf8(`mnemonic${pass || ""}`.normalize("NFKD")), iterations: 2048, hash: "SHA-512" }, k, 512)); }

const sheet = (text) => (i) => { const q = String(i || "").trim().toLowerCase(); if (!q) return text.trim(); const out = text.trim().split("\n").filter((l) => l.toLowerCase().includes(q)); return out.length ? out.join("\n") : `No lines match "${i}"`; };
const GIT = `
SETUP     git config --global user.name "Name" · git config --global user.email you@example.com
START     git init · git clone <url> · git clone --depth 1 <url>
STAGE     git status · git add <file> · git add -p (interactive hunks) · git restore --staged <file>
COMMIT    git commit -m "msg" · git commit --amend (fix last commit; don't amend pushed commits)
BRANCH    git switch -c feature · git switch main · git branch -d feature · git branch -a
MERGE     git merge feature · git rebase main (replay your commits on main) · git cherry-pick <sha>
REMOTE    git fetch · git pull --rebase · git push -u origin feature · git push --force-with-lease
UNDO      git restore <file> (discard changes) · git revert <sha> (safe undo) · git reset --soft HEAD~1 (uncommit, keep changes)
RECOVER   git reflog (find lost commits) · git switch -c rescue <sha>
STASH     git stash · git stash list · git stash pop · git stash -u (include untracked)
INSPECT   git log --oneline --graph --all · git show <sha> · git diff --staged · git blame <file>
SEARCH    git grep "text" · git log -S "text" (pickaxe) · git bisect start/good/bad
TAGS      git tag -a v1.0 -m "release" · git push --tags
CLEAN     git clean -nd (preview) · git clean -fd (delete untracked)
SECRETS   leaked a secret? rotate it first, then rewrite history (git filter-repo) and force-push`;
const REGEX = `
.        any character except newline        \\d  digit   \\w  word char   \\s  whitespace   (\\D \\W \\S = negated)
^  $     start / end of line (with m flag)    \\b  word boundary
[abc]    one of a, b, c   [^abc] none of      [a-z0-9] ranges
*  +  ?  0+, 1+, 0 or 1 (greedy)              *? +? ??  lazy versions
{3} {2,} {2,5}  exact / at least / between
( )      capturing group     (?: )  non-capturing     (?<name> ) named group     \\1 \\k<name> backreference
a|b      alternation
(?= ) (?! )   lookahead / negative lookahead    (?<= ) (?<! )  lookbehind / negative lookbehind
flags    g global · i ignore case · m multiline · s dotall · u unicode · y sticky
EXAMPLES
email    ^[\\w.+-]+@[\\w-]+(\\.[\\w-]+)+$
IPv4     \\b(?:(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\.){3}(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)\\b
date     \\d{4}-(0[1-9]|1[0-2])-(0[1-9]|[12]\\d|3[01])
hex      ^#?([0-9a-f]{3}|[0-9a-f]{6})$    (with i flag)
UUID     [0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}
Try patterns with the Regular Expression Tester tool.`;

export const ops = {
  "to-float": { name: "To Float", run: toFloat, args: floatArgs, placeholder: "3.14159 -2.5 1e10" },
  "from-float": { name: "From Float", run: fromFloat, args: floatArgs, placeholder: "40490fd0" },
  "bech32-encode": { name: "To Bech32", run: (i, a) => bech32Encode(a.hrp.toLowerCase(), a.inputEncoding === "Hex" ? hexToBytes(i) : utf8(i), a.variant === "Bech32m"), args: [opt("hrp", "Human-readable part", "text", { default: "bc" }), select("variant", "Variant", ["Bech32", "Bech32m"]), select("inputEncoding", "Input", ["Hex", "Text"])] },
  "bech32-decode": { name: "From Bech32", run: (i) => bech32Decode(i), placeholder: "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4" },
  "base92-encode": { name: "To Base92", run: (i) => base92Encode(utf8(i)) },
  "base92-decode": { name: "From Base92", run: (i) => fromUtf8(base92Decode(i)) },
  "base64-offsets": { name: "Show Base64 offsets", run: (i) => { const b = utf8(i); if (!b.length) throw new Error("Enter text");
    return [0, 1, 2].map((off) => { const enc = bytesToBase64(new Uint8Array([...new Array(off).fill(0), ...b])); const total = off + b.length; const start = [0, 2, 3][off]; const end = total % 3 ? Math.floor(total / 3) * 4 + (total % 3 === 1 ? 1 : 2) : enc.length; return `Offset ${off}: ${enc}\n  stable: ${enc.slice(start, end)}`; }).join("\n\n")
      + "\n\nGrep base64-encoded data for any of the stable strings to find this text at every alignment."; } },
  "encode-text": { name: "Encode text", run: (i, a) => { const b = encodeText(String(i), a.charset); return a.output === "Base64" ? bytesToBase64(b) : bytesToHex(b); }, args: [select("charset", "Charset", ["utf-16le", "utf-16be", "utf-8", "windows-1252", "iso-8859-1", "iso-8859-2", "iso-8859-5", "iso-8859-7", "iso-8859-15", "windows-1250", "windows-1251", "koi8-r", "ibm866", "macintosh"]), select("output", "Output", ["Hex", "Base64"])] },
  "decode-text": { name: "Decode text", run: (i, a) => decodeText(a.inputEncoding === "Base64" ? base64ToBytes(i) : hexToBytes(i), a.charset), args: [select("charset", "Charset", CHARSETS), select("inputEncoding", "Input", ["Hex", "Base64"])], placeholder: "Hex bytes, e.g. 48 00 69 00" },
  "text-encoding-brute": { name: "Text Encoding Brute Force", run: (i, a) => { const b = a.inputEncoding === "Base64" ? base64ToBytes(i) : hexToBytes(i); return CHARSETS.map((cs) => { let t; try { t = decodeText(b, cs); } catch { return null; } const bad = (t.match(/�/g) || []).length; return `${cs.padEnd(14)} ${bad ? `(${bad} invalid) ` : ""}${t.slice(0, 120).replace(/\n/g, "⏎")}`; }).filter(Boolean).join("\n"); }, args: [select("inputEncoding", "Input", ["Hex", "Base64"])] },
  "parse-tlv": { name: "Parse TLV", run: (i, a) => { const b = hexToBytes(i); const ts = Number(a.tagSize), ls = Number(a.lenSize); const rd = (o, n) => { let v = 0; for (let k = 0; k < n; k++) v = v * 256 + b[o + k]; return v; }; const out = []; let o = 0;
    while (o + ts + ls <= b.length) { const t = rd(o, ts), l = rd(o + ts, ls); const v = b.subarray(o + ts + ls, o + ts + ls + l); out.push(`tag 0x${t.toString(16).padStart(ts * 2, "0")} (${t})  len ${l}  ${bytesToHex(v)}${/^[\x20-\x7e]+$/.test(fromUtf8(v)) ? `  "${fromUtf8(v)}"` : ""}`); o += ts + ls + l; if (out.length > 5000) break; }
    if (o !== b.length) out.push(`(${b.length - o} trailing bytes)`); return out.join("\n"); }, args: [select("tagSize", "Tag size (bytes)", ["1", "2", "4"]), select("lenSize", "Length size (bytes)", ["1", "2", "4"])] },
  "mime-decode": { name: "MIME Decoding", run: (i) => String(i).replace(/=\?([^?]+)\?([BbQq])\?([^?]*)\?=(\s+(?==\?))?/g, (_, cs, enc, txt) => { const bytes = enc.toUpperCase() === "B" ? base64ToBytes(txt) : Uint8Array.from(txt.replace(/_/g, " ").replace(/=([0-9A-F]{2})/gi, (m, h) => String.fromCharCode(parseInt(h, 16))), (c) => c.charCodeAt(0)); try { return new TextDecoder(cs.toLowerCase()).decode(bytes); } catch { return fromUtf8(bytes); } }), placeholder: "Subject: =?UTF-8?B?SGVsbG8gV29ybGQg8J+Riw==?=" },
  "fuzzy-match": { name: "Fuzzy Match", run: (i, a) => { const q = String(a.search).toLowerCase(); if (!q) throw new Error("Enter a search pattern"); const scored = lines(i).filter(Boolean).map((l) => { const s = l.toLowerCase(); let k = 0, score = 0, last = -2, marks = ""; for (let p = 0; p < s.length && k < q.length; p++) { if (s[p] === q[k]) { score += p === last + 1 ? 3 : 1; if (p === 0 || /\W/.test(s[p - 1])) score += 2; last = p; marks += "^"; k++; } else marks += " "; } return k === q.length ? [score - s.length * 0.01, l, marks] : null; }).filter(Boolean).sort((x, y) => y[0] - x[0]);
    return scored.map(([sc, l, m]) => `${sc.toFixed(1).padStart(6)}  ${l}\n        ${m}`).join("\n") || "No matches"; }, args: [opt("search", "Pattern", "text", { default: "" })] },
  "offset-checker": { name: "Offset checker", run: (i) => { const ls = lines(i).filter(Boolean); if (ls.length < 2) throw new Error("Enter two or more samples, one per line"); const n = Math.max(...ls.map((l) => l.length)); const mark = Array.from({ length: n }, (_, k) => (ls.every((l) => l[k] !== undefined && l[k] === ls[0][k]) ? "^" : " ")).join("");
    return `${ls.join("\n")}\n${mark}\n\n${(mark.match(/\^/g) || []).length} aligned matching position(s) marked with ^`; } },
  sleep: { name: "Sleep", run: async (i, a) => { await new Promise((r) => setTimeout(r, Math.min(Math.max(0, Number(a.ms) || 0), 10000))); return String(i); }, args: [opt("ms", "Milliseconds (max 10000)", "number", { default: 500 })] },
  "show-on-map": { name: "Show on map", run: (i) => { const v = (String(i).match(/-?\d+(\.\d+)?/g) || []).map(Number); if (v.length < 2 || Math.abs(v[0]) > 90 || Math.abs(v[1]) > 180) throw new Error("Enter latitude, longitude in decimal degrees"); const [la, lo] = v; return `Latitude ${la}, longitude ${lo}\n\nOpenStreetMap: https://www.openstreetmap.org/?mlat=${la}&mlon=${lo}#map=15/${la}/${lo}\nGoogle Maps:   https://www.google.com/maps?q=${la},${lo}`; }, placeholder: "51.5007, -0.1246" },
  xpath: { name: "XPath expression", run: (i, a) => { if (typeof DOMParser === "undefined") throw new Error("XPath needs a browser"); const doc = new DOMParser().parseFromString(String(i), a.type === "HTML" ? "text/html" : "application/xml"); if (doc.querySelector("parsererror")) throw new Error("Input is not well-formed XML"); const r = doc.evaluate(a.query, doc, null, XPathResult.ANY_TYPE, null);
    if (r.resultType <= 3) return String(r.resultType === 1 ? r.numberValue : r.resultType === 2 ? r.stringValue : r.booleanValue); const out = []; for (let n = r.iterateNext(); n; n = r.iterateNext()) out.push(n.nodeType === 1 ? new XMLSerializer().serializeToString(n) : n.textContent); return out.join("\n") || "No matches"; },
    args: [opt("query", "XPath", "text", { default: "//title" }), select("type", "Document type", ["XML", "HTML"])] },
  "css-selector": { name: "CSS selector", run: (i, a) => { if (typeof DOMParser === "undefined") throw new Error("CSS selectors need a browser"); const doc = new DOMParser().parseFromString(String(i), "text/html"); const els = [...doc.querySelectorAll(a.selector)]; return els.length ? els.map((e) => (a.output === "Text" ? e.textContent.trim() : a.output === "Attribute" ? e.getAttribute(a.attr) ?? "" : e.outerHTML)).join("\n") : "No matches"; },
    args: [opt("selector", "Selector", "text", { default: "a[href]" }), select("output", "Output", ["Outer HTML", "Text", "Attribute"]), opt("attr", "Attribute name", "text", { default: "href" })] },
  rake: { name: "RAKE keyword extraction", run: (i, a) => rake(i).slice(0, Number(a.top) || 20).map(([p, s]) => `${s.toFixed(2).padStart(7)}  ${p}`).join("\n") || "No keywords", args: [opt("top", "Show top N", "number", { default: 20 })] },
  "code-beautify": { name: "Generic Code Beautify", run: (i, a) => genericBeautify(i, a.indent === "Tab" ? "\t" : " ".repeat(Number(a.indent))), args: [select("indent", "Indent", ["2", "4", "Tab"])] },
  "js-minify": { name: "JavaScript Minify", run: (i) => jsMinify(i) },
  "bson-serialise": { name: "BSON serialise", run: (i) => bytesToHex(bsonEncode(JSON.parse(i))), placeholder: '{"hello":"world","n":42}' },
  "bson-deserialise": { name: "BSON deserialise", run: (i) => { const s = String(i).trim(); return JSON.stringify(bsonDecode(/^[0-9a-f\s]+$/i.test(s) ? hexToBytes(s) : base64ToBytes(s)), null, 2); }, placeholder: "Hex or base64" },
  magic: { name: "Magic (auto-decode)", run: async (i, a) => { const r = await magic(i, Number(a.depth)); return r.length ? r.map((x, k) => `#${k + 1}  ${x.path.join(" → ")}\n    ${x.out.slice(0, 300).replace(/\n/g, "⏎")}`).join("\n\n") : "No decoding produced more readable output"; }, args: [select("depth", "Search depth", ["2", "1", "3"])] },
  comment: { name: "Comment", run: (i) => String(i), placeholder: "Pass-through: use as a note step in a recipe" },
  enigma: { name: "Enigma", run: (i, a) => enigma(i, a), args: [select("left", "Left rotor", Object.keys(ROTORS), "I"), select("middle", "Middle rotor", Object.keys(ROTORS), "II"), select("right", "Right rotor", Object.keys(ROTORS), "III"), select("reflector", "Reflector", ["B", "C"]), opt("rings", "Ring settings", "text", { default: "AAA" }), opt("positions", "Start positions", "text", { default: "AAA" }), opt("plugboard", "Plugboard pairs", "text", { default: "" }), opt("keepOther", "Keep non-letters", "checkbox")] },
  numberwang: { name: "Numberwang", run: (i) => { const n = parseFloat(i); if (isNaN(n)) return "That's not even a number."; const h = [...String(i)].reduce((a, c) => (a * 31 + c.charCodeAt(0)) >>> 0, 7); return h % 4 === 0 ? "That's Numberwang! 🎉" : h % 11 === 0 ? "That's WangerNumb! Let's rotate the board!" : "Sorry, that's not Numberwang."; } },
  "bip39-generate": { name: "BIP39 Passphrase Generator", input: false, run: async (_, a) => { const n = { "12 words": 16, "15 words": 20, "18 words": 24, "21 words": 28, "24 words": 32 }[a.words]; const ent = crypto.getRandomValues(new Uint8Array(n)); const m = await entropyToMnemonic(ent); return `${m}\n\nEntropy: ${bytesToHex(ent)}\n\n⚠ Generated in your browser. Anyone who sees this phrase controls any wallet derived from it.`; }, args: [select("words", "Length", ["12 words", "24 words", "15 words", "18 words", "21 words"])] },
  "bip39-check": { name: "BIP39 Mnemonic Validator / Seed", run: async (i, a) => { const { ent, ok } = await mnemonicToEntropy(i); const seed = await bip39Seed(String(i).trim().toLowerCase().split(/\s+/).join(" "), a.passphrase); return `Checksum: ${ok ? "✓ valid" : "✗ INVALID — a word is wrong or out of order"}\nEntropy: ${bytesToHex(ent)}\nSeed (BIP39, PBKDF2-SHA512 ×2048): ${bytesToHex(seed)}`; }, args: [opt("passphrase", "Optional passphrase (25th word)", "text")], placeholder: "abandon abandon … about" },
  "bip39-from-entropy": { name: "BIP39 Mnemonic from Entropy", run: async (i) => { const e = hexToBytes(i); if (![16, 20, 24, 28, 32].includes(e.length)) throw new Error("Entropy must be 16, 20, 24, 28 or 32 bytes (hex)"); return entropyToMnemonic(e); }, placeholder: "00000000000000000000000000000000" },
  "git-memo": { name: "Git Cheat Sheet", run: sheet(GIT), allowEmpty: true, placeholder: "Filter (optional)" },
  "regex-memo": { name: "Regex Cheat Sheet", run: sheet(REGEX), allowEmpty: true, placeholder: "Filter (optional)" },
  "base64-file": { name: "Base64 File Converter", input: "file", run: (f, a) => { if (a.direction === "Base64 → file") { const s = new TextDecoder().decode(f.bytes).trim().replace(/^data:[^,]*,/, ""); const b = base64ToBytes(s); return { text: `Decoded ${b.length.toLocaleString()} bytes`, download: { name: "decoded.bin", data: b } }; } const b64 = bytesToBase64(f.bytes); return `${b64.length > 200000 ? b64.slice(0, 200000) + "…(truncated in view; use Copy for all)" : b64}\n\nData URI prefix: data:${f.type || "application/octet-stream"};base64,`; },
    args: [select("direction", "Direction", ["File → Base64", "Base64 → file"])] },
};
export { bech32Encode, bech32Decode, base92Encode, base92Decode, bsonEncode, bsonDecode, enigma, entropyToMnemonic, mnemonicToEntropy, bip39Seed, jsMinify };
