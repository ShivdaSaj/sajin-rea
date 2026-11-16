import { utf8, fromUtf8, hexToBytes, bytesToHex, bytesToBase64, base64ToBytes, parseBytes, select, opt } from "./util.js";

const rand = (n) => crypto.getRandomValues(new Uint8Array(n));
function randInt(max) { // unbiased integer in [0, max)
  const lim = Math.floor(0x100000000 / max) * max; const buf = new Uint32Array(1);
  do crypto.getRandomValues(buf); while (buf[0] >= lim);
  return buf[0] % max;
}

function uuidv4() { const b = rand(16); b[6] = (b[6] & 0x0f) | 0x40; b[8] = (b[8] & 0x3f) | 0x80; const h = bytesToHex(b); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; }
function uuidv7() { const b = rand(16); const ts = BigInt(Date.now()); for (let i = 0; i < 6; i++) b[i] = Number((ts >> BigInt(8 * (5 - i))) & 0xffn); b[6] = (b[6] & 0x0f) | 0x70; b[8] = (b[8] & 0x3f) | 0x80; const h = bytesToHex(b); return `${h.slice(0, 8)}-${h.slice(8, 12)}-${h.slice(12, 16)}-${h.slice(16, 20)}-${h.slice(20)}`; }
const CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";
function ulid() { let t = Date.now(), time = ""; for (let i = 0; i < 10; i++) { time = CROCKFORD[t % 32] + time; t = Math.floor(t / 32); } let r = ""; for (let i = 0; i < 16; i++) r += CROCKFORD[randInt(32)]; return time + r; }

const b64url = (b) => bytesToBase64(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const decodeJwtPart = (p) => JSON.parse(fromUtf8(base64ToBytes(p)));

async function aesKey(a, usage) {
  const mode = a.mode === "GCM" ? "AES-GCM" : a.mode === "CTR" ? "AES-CTR" : "AES-CBC";
  if (a.keyFormat === "passphrase") {
    const base = await crypto.subtle.importKey("raw", utf8(a.key), "PBKDF2", false, ["deriveKey"]);
    return crypto.subtle.deriveKey({ name: "PBKDF2", salt: parseBytes(a.salt || "", "utf8"), iterations: Number(a.iterations) || 100000, hash: "SHA-256" }, base, { name: mode, length: Number(a.bits) }, false, [usage]);
  }
  return crypto.subtle.importKey("raw", parseBytes(a.key, a.keyFormat), mode, false, [usage]);
}
const aesParams = (a, iv) => a.mode === "GCM" ? { name: "AES-GCM", iv } : a.mode === "CTR" ? { name: "AES-CTR", counter: iv, length: 64 } : { name: "AES-CBC", iv };
const aesArgs = [select("mode", "Mode", ["GCM", "CBC", "CTR"]), opt("key", "Key / passphrase", "text", { default: "" }), select("keyFormat", "Key format", ["passphrase", "hex", "base64", "utf8"]),
  opt("iv", "IV (hex; blank = random on encrypt)", "text"), opt("salt", "PBKDF2 salt (passphrase mode)", "text", { default: "infosec-tools" }), opt("iterations", "PBKDF2 iterations", "number", { default: 100000 }), select("bits", "Key size (passphrase mode)", ["256", "192", "128"])];

function strength(pw) {
  let pool = 0; if (/[a-z]/.test(pw)) pool += 26; if (/[A-Z]/.test(pw)) pool += 26; if (/\d/.test(pw)) pool += 10; if (/[^a-zA-Z0-9]/.test(pw)) pool += 33;
  const bits = pw.length * Math.log2(pool || 1); const guesses = 2 ** bits / 2; const perSec = 1e10;
  const secs = guesses / perSec;
  const human = secs < 1 ? "instantly" : secs < 3600 ? `${Math.round(secs / 60)} minutes` : secs < 86400 * 365 ? `${Math.round(secs / 86400)} days` : secs < 3.15e16 ? `${(secs / 31536000).toExponential(1)} years` : "longer than the age of the universe";
  const score = bits < 28 ? "Very weak" : bits < 36 ? "Weak" : bits < 60 ? "Reasonable" : bits < 128 ? "Strong" : "Very strong";
  return `Length: ${pw.length}\nCharacter pool: ${pool}\nEntropy: ${bits.toFixed(1)} bits\nRating: ${score}\nBrute-force time at 10^10 guesses/s: ${human}`;
}

export const ops = {
  "uuid": { name: "Generate UUID", input: false, run: (_, a) => Array.from({ length: Math.min(Number(a.count) || 1, 500) }, () => (a.version === "v7" ? uuidv7() : uuidv4())).join("\n"), args: [select("version", "Version", ["v4", "v7"]), opt("count", "How many", "number", { default: 5 })] },
  "ulid": { name: "Generate ULID", input: false, run: (_, a) => Array.from({ length: Math.min(Number(a.count) || 1, 500) }, ulid).join("\n"), args: [opt("count", "How many", "number", { default: 5 })] },
  "token": { name: "Token / Password Generator", input: false, run: (_, a) => {
    let chars = ""; if (a.lower) chars += "abcdefghijklmnopqrstuvwxyz"; if (a.upper) chars += "ABCDEFGHIJKLMNOPQRSTUVWXYZ"; if (a.digits) chars += "0123456789"; if (a.symbols) chars += "!@#$%^&*()-_=+[]{};:,.<>/?~";
    if (!chars) throw new Error("Select at least one character set");
    const len = Math.min(Math.max(Number(a.length) || 32, 1), 1024);
    return Array.from({ length: Math.min(Number(a.count) || 1, 100) }, () => Array.from({ length: len }, () => chars[randInt(chars.length)]).join("")).join("\n");
  }, args: [opt("length", "Length", "number", { default: 32 }), opt("count", "How many", "number", { default: 5 }), opt("lower", "Lowercase", "checkbox", { default: true }), opt("upper", "Uppercase", "checkbox", { default: true }), opt("digits", "Digits", "checkbox", { default: true }), opt("symbols", "Symbols", "checkbox", { default: false })] },
  "random-bytes": { name: "Random Bytes", input: false, run: (_, a) => { const b = rand(Math.min(Number(a.length) || 32, 4096)); return a.format === "Base64" ? bytesToBase64(b) : bytesToHex(b); }, args: [opt("length", "Bytes", "number", { default: 32 }), select("format", "Format", ["Hex", "Base64"])] },
  "random-number": { name: "Random Number Generator", input: false, run: (_, a) => { const lo = Math.ceil(Number(a.min)), hi = Math.floor(Number(a.max)); if (!(hi >= lo)) throw new Error("max must be ≥ min"); return Array.from({ length: Math.min(Number(a.count) || 1, 1000) }, () => lo + randInt(hi - lo + 1)).join("\n"); }, args: [opt("min", "Min", "number", { default: 1 }), opt("max", "Max", "number", { default: 100 }), opt("count", "How many", "number", { default: 10 })] },
  "password-strength": { name: "Password Strength Analyser", run: (i) => strength(String(i)) },
  "jwt-decode": { name: "JWT Decode", run: (i) => {
    const parts = String(i).trim().split("."); if (parts.length < 2) throw new Error("A JWT has at least two dot-separated parts");
    const header = decodeJwtPart(parts[0]), payload = decodeJwtPart(parts[1]);
    const notes = []; for (const k of ["iat", "nbf", "exp"]) if (typeof payload[k] === "number") notes.push(`${k}: ${new Date(payload[k] * 1000).toISOString()}${k === "exp" && payload.exp * 1000 < Date.now() ? " (expired)" : ""}`);
    return `Header:\n${JSON.stringify(header, null, 2)}\n\nPayload:\n${JSON.stringify(payload, null, 2)}${notes.length ? "\n\nTimes:\n" + notes.join("\n") : ""}\n\nSignature (not verified): ${parts[2] || "(none)"}`;
  } },
  "jwt-sign": { name: "JWT Sign (HS256)", run: async (i, a) => {
    const payload = JSON.parse(i || "{}"); const head = b64url(utf8(JSON.stringify({ alg: "HS256", typ: "JWT" }))), body = b64url(utf8(JSON.stringify(payload)));
    const key = await crypto.subtle.importKey("raw", utf8(a.secret), { name: "HMAC", hash: "SHA-256" }, false, ["sign"]);
    return `${head}.${body}.${b64url(new Uint8Array(await crypto.subtle.sign("HMAC", key, utf8(`${head}.${body}`))))}`;
  }, args: [opt("secret", "Secret", "text", { default: "secret" })], placeholder: '{"sub":"1234567890","name":"Alice"}' },
  "jwt-verify": { name: "JWT Verify (HS256)", run: async (i, a) => {
    const [h, p, s] = String(i).trim().split("."); const key = await crypto.subtle.importKey("raw", utf8(a.secret), { name: "HMAC", hash: "SHA-256" }, false, ["verify"]);
    const ok = await crypto.subtle.verify("HMAC", key, base64ToBytes(s || ""), utf8(`${h}.${p}`));
    return ok ? "Signature VALID for the given secret" : "Signature INVALID for the given secret";
  }, args: [opt("secret", "Secret", "text", { default: "secret" })] },
  "basic-auth": { name: "Basic Auth Header Generator", input: false, run: (_, a) => `Authorization: Basic ${bytesToBase64(utf8(`${a.user}:${a.pass}`))}`, args: [opt("user", "Username", "text", { default: "admin" }), opt("pass", "Password", "text", { default: "" })] },
  "aes-encrypt": { name: "AES Encrypt", run: async (i, a) => {
    const ivLen = a.mode === "GCM" ? 12 : 16; const iv = a.iv ? hexToBytes(a.iv) : rand(ivLen);
    const ct = new Uint8Array(await crypto.subtle.encrypt(aesParams(a, iv), await aesKey(a, "encrypt"), utf8(i)));
    return `IV (hex): ${bytesToHex(iv)}\nCiphertext (base64): ${bytesToBase64(ct)}\nCiphertext (hex): ${bytesToHex(ct)}`;
  }, args: aesArgs },
  "aes-decrypt": { name: "AES Decrypt", run: async (i, a) => {
    if (!a.iv) throw new Error("IV is required to decrypt");
    const data = /^[0-9a-f\s]+$/i.test(i) ? hexToBytes(i) : base64ToBytes(i);
    try { return fromUtf8(new Uint8Array(await crypto.subtle.decrypt(aesParams(a, hexToBytes(a.iv)), await aesKey(a, "decrypt"), data))); }
    catch { throw new Error("Decryption failed — wrong key, IV, mode or corrupted ciphertext"); }
  }, args: aesArgs, placeholder: "Ciphertext as base64 or hex" },
  "pbkdf2": { name: "Derive PBKDF2 Key", run: async (i, a) => {
    const base = await crypto.subtle.importKey("raw", utf8(i), "PBKDF2", false, ["deriveBits"]);
    const bits = await crypto.subtle.deriveBits({ name: "PBKDF2", salt: utf8(a.salt), iterations: Number(a.iterations) || 1, hash: a.hash }, base, Number(a.bits));
    return bytesToHex(new Uint8Array(bits));
  }, args: [opt("salt", "Salt", "text", { default: "salt" }), opt("iterations", "Iterations", "number", { default: 100000 }), select("hash", "Hash", ["SHA-256", "SHA-1", "SHA-512"]), select("bits", "Key length (bits)", ["256", "128", "512"])], placeholder: "Passphrase" },
  "rsa-keygen": { name: "RSA Key Pair Generator", input: false, run: async (_, a) => {
    const kp = await crypto.subtle.generateKey({ name: "RSA-OAEP", modulusLength: Number(a.bits), publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-256" }, true, ["encrypt", "decrypt"]);
    const pem = (label, buf) => `-----BEGIN ${label}-----\n${bytesToBase64(new Uint8Array(buf)).match(/.{1,64}/g).join("\n")}\n-----END ${label}-----`;
    return `${pem("PUBLIC KEY", await crypto.subtle.exportKey("spki", kp.publicKey))}\n\n${pem("PRIVATE KEY", await crypto.subtle.exportKey("pkcs8", kp.privateKey))}`;
  }, args: [select("bits", "Modulus length", ["2048", "3072", "4096"])] },
  "otp": { name: "TOTP Code Generator", input: false, run: async (_, a) => {
    const B32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"; let bits = 0, v = 0; const key = [];
    for (const c of String(a.secret).toUpperCase().replace(/[=\s]/g, "")) { const i = B32.indexOf(c); if (i < 0) throw new Error("Secret must be Base32"); v = (v << 5) | i; bits += 5; if (bits >= 8) { key.push((v >>> (bits - 8)) & 255); bits -= 8; } }
    const counter = Math.floor(Date.now() / 1000 / 30); const msg = new Uint8Array(8); new DataView(msg.buffer).setUint32(4, counter);
    const k = await crypto.subtle.importKey("raw", new Uint8Array(key), { name: "HMAC", hash: "SHA-1" }, false, ["sign"]);
    const h = new Uint8Array(await crypto.subtle.sign("HMAC", k, msg)); const o = h[19] & 15;
    const code = (((h[o] & 127) << 24) | (h[o + 1] << 16) | (h[o + 2] << 8) | h[o + 3]) % 1e6;
    return `${String(code).padStart(6, "0")}  (valid for ${30 - (Math.floor(Date.now() / 1000) % 30)}s)`;
  }, args: [opt("secret", "Base32 secret", "text", { default: "JBSWY3DPEHPK3PXP" })] },
};
