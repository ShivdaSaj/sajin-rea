import { utf8, fromUtf8, hexToBytes, bytesToHex, bytesToBase64, base64ToBytes, parseBytes, select, opt } from "./util.js";

const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
function base32Encode(bytes) {
  let bits = 0, value = 0, out = "";
  for (const b of bytes) {
    value = (value << 8) | b; bits += 8;
    while (bits >= 5) { out += B32[(value >>> (bits - 5)) & 31]; bits -= 5; }
  }
  if (bits > 0) out += B32[(value << (5 - bits)) & 31];
  while (out.length % 8) out += "=";
  return out;
}
function base32Decode(s) {
  const clean = String(s).toUpperCase().replace(/[=\s]/g, "");
  let bits = 0, value = 0; const out = [];
  for (const c of clean) {
    const i = B32.indexOf(c); if (i < 0) throw new Error(`Invalid Base32 character "${c}"`);
    value = (value << 5) | i; bits += 5;
    if (bits >= 8) { out.push((value >>> (bits - 8)) & 255); bits -= 8; }
  }
  return new Uint8Array(out);
}

const B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58Encode(bytes) {
  let n = 0n; for (const b of bytes) n = n * 256n + BigInt(b);
  let out = ""; while (n > 0n) { out = B58[Number(n % 58n)] + out; n /= 58n; }
  for (const b of bytes) { if (b !== 0) break; out = "1" + out; }
  return out;
}
function base58Decode(s) {
  let n = 0n;
  for (const c of String(s).trim()) { const i = B58.indexOf(c); if (i < 0) throw new Error(`Invalid Base58 character "${c}"`); n = n * 58n + BigInt(i); }
  const out = []; while (n > 0n) { out.unshift(Number(n % 256n)); n /= 256n; }
  for (const c of String(s).trim()) { if (c !== "1") break; out.unshift(0); }
  return new Uint8Array(out);
}

const MORSE = { A: ".-", B: "-...", C: "-.-.", D: "-..", E: ".", F: "..-.", G: "--.", H: "....", I: "..", J: ".---", K: "-.-", L: ".-..", M: "--", N: "-.", O: "---", P: ".--.", Q: "--.-", R: ".-.", S: "...", T: "-", U: "..-", V: "...-", W: ".--", X: "-..-", Y: "-.--", Z: "--..", 0: "-----", 1: ".----", 2: "..---", 3: "...--", 4: "....-", 5: ".....", 6: "-....", 7: "--...", 8: "---..", 9: "----.", ".": ".-.-.-", ",": "--..--", "?": "..--..", "'": ".----.", "!": "-.-.--", "/": "-..-.", "(": "-.--.", ")": "-.--.-", "&": ".-...", ":": "---...", ";": "-.-.-.", "=": "-...-", "+": ".-.-.", "-": "-....-", _: "..--.-", '"': ".-..-.", $: "...-..-", "@": ".--.-." };
const MORSE_REV = Object.fromEntries(Object.entries(MORSE).map(([k, v]) => [v, k]));

const HTML_ENT = { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" };
const NAMED = { amp: "&", lt: "<", gt: ">", quot: '"', apos: "'", nbsp: " ", copy: "©", reg: "®", euro: "€", pound: "£" };

const rotChar = (c, n) => {
  const code = c.charCodeAt(0);
  if (code >= 65 && code <= 90) return String.fromCharCode(((code - 65 + n) % 26 + 26) % 26 + 65);
  if (code >= 97 && code <= 122) return String.fromCharCode(((code - 97 + n) % 26 + 26) % 26 + 97);
  return c;
};

const radixEncode = (radix, pad) => (input, a) =>
  Array.from(utf8(input), (b) => b.toString(radix).padStart(pad, "0")).join(a.delimiter === "None" ? "" : delim(a.delimiter));
const radixDecode = (radix, width) => (input) => {
  const parts = String(input).trim().match(new RegExp(`[0-9a-z]{1,${width}}`, "gi")) || [];
  return fromUtf8(Uint8Array.from(parts.map((p) => parseInt(p, radix))));
};
const delim = (d) => ({ Space: " ", Comma: ",", Newline: "\n", Colon: ":", None: "" }[d] ?? " ");
const delimiterOpt = select("delimiter", "Delimiter", ["Space", "Comma", "Colon", "Newline", "None"]);

function vigenere(input, key, decrypt) {
  const k = String(key).toLowerCase().replace(/[^a-z]/g, "");
  if (!k) throw new Error("Key must contain letters");
  let j = 0;
  return String(input).replace(/[a-z]/gi, (c) => { const shift = k.charCodeAt(j++ % k.length) - 97; return rotChar(c, decrypt ? -shift : shift); });
}

export const ops = {
  "base64-encode": { name: "To Base64", run: (i, a) => { const s = bytesToBase64(utf8(i)); return a.urlSafe ? s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "") : s; }, args: [opt("urlSafe", "URL-safe alphabet", "checkbox")] },
  "base64-decode": { name: "From Base64", run: (i) => fromUtf8(base64ToBytes(i)) },
  "base32-encode": { name: "To Base32", run: (i) => base32Encode(utf8(i)) },
  "base32-decode": { name: "From Base32", run: (i) => fromUtf8(base32Decode(i)) },
  "base58-encode": { name: "To Base58", run: (i) => base58Encode(utf8(i)) },
  "base58-decode": { name: "From Base58", run: (i) => fromUtf8(base58Decode(i)) },
  "hex-encode": { name: "To Hex", run: radixEncode(16, 2), args: [delimiterOpt] },
  "hex-decode": { name: "From Hex", run: (i) => fromUtf8(hexToBytes(i)) },
  "binary-encode": { name: "To Binary", run: radixEncode(2, 8), args: [delimiterOpt] },
  "binary-decode": { name: "From Binary", run: (i) => fromUtf8(Uint8Array.from((String(i).replace(/[^01]/g, "").match(/.{8}/g) || []).map((b) => parseInt(b, 2)))) },
  "octal-encode": { name: "To Octal", run: radixEncode(8, 3), args: [delimiterOpt] },
  "octal-decode": { name: "From Octal", run: radixDecode(8, 3) },
  "decimal-encode": { name: "To Decimal (bytes)", run: radixEncode(10, 0), args: [delimiterOpt] },
  "decimal-decode": { name: "From Decimal (bytes)", run: (i) => fromUtf8(Uint8Array.from((String(i).match(/\d+/g) || []).map(Number))) },
  "charcode-encode": { name: "To Charcode", run: (i, a) => Array.from(String(i), (c) => c.codePointAt(0).toString(Number(a.base))).join(" "), args: [select("base", "Base", ["16", "10", "8", "2"])] },
  "charcode-decode": { name: "From Charcode", run: (i, a) => (String(i).match(/[0-9a-f]+/gi) || []).map((x) => String.fromCodePoint(parseInt(x, Number(a.base)))).join(""), args: [select("base", "Base", ["16", "10", "8", "2"])] },
  "url-encode": { name: "URL Encode", run: (i, a) => (a.all ? Array.from(utf8(i), (b) => "%" + b.toString(16).toUpperCase().padStart(2, "0")).join("") : encodeURIComponent(i)), args: [opt("all", "Encode every character", "checkbox")] },
  "url-decode": { name: "URL Decode", run: (i) => decodeURIComponent(String(i).replace(/\+/g, " ")) },
  "html-encode": { name: "HTML Entity Encode", run: (i, a) => String(i).replace(a.all ? /[^\w\s]/g : /[&<>"']/g, (c) => HTML_ENT[c] || `&#${c.codePointAt(0)};`), args: [opt("all", "Encode all non-alphanumerics", "checkbox")] },
  "html-decode": { name: "HTML Entity Decode", run: (i) => String(i).replace(/&(#x[0-9a-f]+|#\d+|[a-z]+);/gi, (m, e) => e[0] === "#" ? String.fromCodePoint(e[1].toLowerCase() === "x" ? parseInt(e.slice(2), 16) : parseInt(e.slice(1), 10)) : NAMED[e.toLowerCase()] ?? m) },
  "unicode-escape": { name: "Escape Unicode / String", run: (i) => Array.from(String(i), (c) => { const cp = c.codePointAt(0); return cp < 128 && cp >= 32 && c !== "\\" ? c : cp > 0xffff ? `\\u{${cp.toString(16)}}` : `\\u${cp.toString(16).padStart(4, "0")}`; }).join("") },
  "unicode-unescape": { name: "Unescape Unicode / String", run: (i) => String(i).replace(/\\u\{([0-9a-f]+)\}|\\u([0-9a-f]{4})|\\x([0-9a-f]{2})|\\n|\\t|\\r|\\\\/gi, (m, a, b, c) => a || b || c ? String.fromCodePoint(parseInt(a || b || c, 16)) : { "\\n": "\n", "\\t": "\t", "\\r": "\r", "\\\\": "\\" }[m]) },
  "quoted-printable-encode": { name: "To Quoted Printable", run: (i) => Array.from(utf8(i), (b) => (b >= 33 && b <= 126 && b !== 61) || b === 32 ? String.fromCharCode(b) : b === 10 ? "\n" : "=" + b.toString(16).toUpperCase().padStart(2, "0")).join("") },
  "quoted-printable-decode": { name: "From Quoted Printable", run: (i) => fromUtf8(Uint8Array.from(String(i).replace(/=\r?\n/g, "").replace(/=([0-9A-F]{2})|[\s\S]/gi, (m, h) => String.fromCharCode(h ? parseInt(h, 16) : m.charCodeAt(0) & 255)), (c) => c.charCodeAt(0))) },
  "rot13": { name: "ROT13 / Caesar", run: (i, a) => String(i).replace(/[a-z]/gi, (c) => rotChar(c, Number(a.amount) || 13)), args: [opt("amount", "Shift", "number", { default: 13 })] },
  "rot47": { name: "ROT47", run: (i) => String(i).replace(/[!-~]/g, (c) => String.fromCharCode(33 + ((c.charCodeAt(0) + 14) % 94))) },
  "atbash": { name: "Atbash Cipher", run: (i) => String(i).replace(/[a-z]/gi, (c) => { const base = c <= "Z" ? 65 : 97; return String.fromCharCode(25 - (c.charCodeAt(0) - base) + base); }) },
  "vigenere-encode": { name: "Vigenère Encode", run: (i, a) => vigenere(i, a.key, false), args: [opt("key", "Key", "text", { default: "secret" })] },
  "vigenere-decode": { name: "Vigenère Decode", run: (i, a) => vigenere(i, a.key, true), args: [opt("key", "Key", "text", { default: "secret" })] },
  "affine-encode": { name: "Affine Cipher Encode", run: (i, a) => String(i).replace(/[a-z]/gi, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((Number(a.a) * (c.charCodeAt(0) - b) + Number(a.b)) % 26 + 26) % 26 + b); }), args: [opt("a", "a", "number", { default: 5 }), opt("b", "b", "number", { default: 8 })] },
  "affine-decode": { name: "Affine Cipher Decode", run: (i, a) => { const A = Number(a.a); let inv = 0; for (let x = 1; x < 26; x++) if ((A * x) % 26 === 1) inv = x; if (!inv) throw new Error("a must be coprime with 26"); return String(i).replace(/[a-z]/gi, (c) => { const b = c <= "Z" ? 65 : 97; return String.fromCharCode(((inv * (c.charCodeAt(0) - b - Number(a.b))) % 26 + 26) % 26 + b); }); }, args: [opt("a", "a", "number", { default: 5 }), opt("b", "b", "number", { default: 8 })] },
  "morse-encode": { name: "To Morse Code", run: (i) => String(i).toUpperCase().split(/\s+/).map((w) => Array.from(w, (c) => MORSE[c] ?? "").filter(Boolean).join(" ")).join(" / ") },
  "morse-decode": { name: "From Morse Code", run: (i) => String(i).trim().split(/\s*\/\s*|\s{3,}/).map((w) => w.split(/\s+/).map((c) => MORSE_REV[c] ?? "").join("")).join(" ") },
  "a1z26-encode": { name: "A1Z26 Cipher Encode", run: (i) => String(i).toUpperCase().split(/\s+/).map((w) => Array.from(w.replace(/[^A-Z]/g, ""), (c) => c.charCodeAt(0) - 64).join("-")).join(" ") },
  "a1z26-decode": { name: "A1Z26 Cipher Decode", run: (i) => String(i).trim().split(/\s+/).map((w) => w.split(/\D+/).filter(Boolean).map((n) => String.fromCharCode(64 + Number(n))).join("")).join(" ") },
  "bacon-encode": { name: "Bacon Cipher Encode", run: (i) => Array.from(String(i).toUpperCase().replace(/[^A-Z]/g, ""), (c) => (c.charCodeAt(0) - 65).toString(2).padStart(5, "0").replace(/0/g, "A").replace(/1/g, "B")).join(" ") },
  "bacon-decode": { name: "Bacon Cipher Decode", run: (i) => (String(i).toUpperCase().replace(/[^AB]/g, "").match(/.{5}/g) || []).map((g) => String.fromCharCode(65 + parseInt(g.replace(/A/g, "0").replace(/B/g, "1"), 2))).join("") },
  "nato-alphabet": { name: "Text to NATO Alphabet", run: (i) => Array.from(String(i).toUpperCase(), (c) => NATO[c] ?? (c === " " ? "/" : c)).join(" ") },
  "xor": { name: "XOR", run: (i, a) => { const key = parseBytes(a.key, a.keyEncoding); if (!key.length) throw new Error("Key is empty"); const data = a.inputEncoding === "hex" ? hexToBytes(i) : utf8(i); const out = data.map((b, j) => b ^ key[j % key.length]); return a.output === "Text" ? fromUtf8(out) : bytesToHex(out); },
    args: [opt("key", "Key", "text", { default: "key" }), select("keyEncoding", "Key format", ["utf8", "hex", "base64"]), select("inputEncoding", "Input format", ["utf8", "hex"]), select("output", "Output", ["Hex", "Text"])] },
  "reverse": { name: "Reverse", run: (i, a) => (a.by === "Line" ? String(i).split("\n").reverse().join("\n") : Array.from(String(i)).reverse().join("")), args: [select("by", "By", ["Character", "Line"])] },
  "punycode-encode": { name: "To Punycode (IDN)", run: (i) => String(i).trim().split(/\s+/).map((d) => new URL("http://" + d).hostname).join("\n") },
  "byte-length": { name: "Byte & Character Count", run: (i) => `${utf8(i).length} bytes, ${Array.from(String(i)).length} characters` },
};

const NATO = { A: "Alfa", B: "Bravo", C: "Charlie", D: "Delta", E: "Echo", F: "Foxtrot", G: "Golf", H: "Hotel", I: "India", J: "Juliett", K: "Kilo", L: "Lima", M: "Mike", N: "November", O: "Oscar", P: "Papa", Q: "Quebec", R: "Romeo", S: "Sierra", T: "Tango", U: "Uniform", V: "Victor", W: "Whiskey", X: "X-ray", Y: "Yankee", Z: "Zulu", 0: "Zero", 1: "One", 2: "Two", 3: "Three", 4: "Four", 5: "Five", 6: "Six", 7: "Seven", 8: "Eight", 9: "Nine" };
