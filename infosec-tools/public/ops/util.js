// Shared byte/string helpers used by every op module. Pure JS: runs in browsers and Node.
export const te = new TextEncoder();
export const td = new TextDecoder("utf-8", { fatal: false });

export const utf8 = (s) => te.encode(String(s ?? ""));
export const fromUtf8 = (b) => td.decode(b);

export function hexToBytes(hex) {
  const clean = String(hex).replace(/0x/gi, "").replace(/[^0-9a-f]/gi, "");
  if (clean.length % 2) throw new Error("Hex input has an odd number of digits");
  const out = new Uint8Array(clean.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(clean.substr(i * 2, 2), 16);
  return out;
}

export const bytesToHex = (b, sep = "") =>
  Array.from(b, (x) => x.toString(16).padStart(2, "0")).join(sep);

export function lines(s) {
  return String(s ?? "").split(/\r?\n/);
}

// Parse a key/IV given as hex, base64 or UTF-8 text.
export function parseBytes(value, encoding) {
  if (encoding === "hex") return hexToBytes(value);
  if (encoding === "base64") return Uint8Array.from(atob(String(value).replace(/\s/g, "")), (c) => c.charCodeAt(0));
  return utf8(value);
}

export function bytesToBase64(b) {
  let s = "";
  for (let i = 0; i < b.length; i += 0x8000) s += String.fromCharCode(...b.subarray(i, i + 0x8000));
  return btoa(s);
}

export function base64ToBytes(s) {
  const clean = String(s).replace(/\s/g, "").replace(/-/g, "+").replace(/_/g, "/");
  const padded = clean + "===".slice((clean.length + 3) % 4);
  return Uint8Array.from(atob(padded), (c) => c.charCodeAt(0));
}

export const opt = (name, label, type = "text", extra = {}) => ({ name, label, type, ...extra });
export const select = (name, label, options, def) => ({ name, label, type: "select", options, default: def ?? options[0] });
