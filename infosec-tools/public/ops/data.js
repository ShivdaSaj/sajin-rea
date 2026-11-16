import { lines, utf8, select, opt } from "./util.js";

function parseCsv(text, sep) {
  const rows = []; let row = [], field = "", q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; continue; }
    if (c === '"') q = true; else if (c === sep) { row.push(field); field = ""; }
    else if (c === "\n" || c === "\r") { if (c === "\r" && text[i + 1] === "\n") i++; row.push(field); rows.push(row); row = []; field = ""; }
    else field += c;
  }
  if (field || row.length) { row.push(field); rows.push(row); }
  return rows.filter((r) => r.some((f) => f !== ""));
}
const csvCell = (v, sep) => { const s = v == null ? "" : typeof v === "object" ? JSON.stringify(v) : String(v); return /["\n\r]/.test(s) || s.includes(sep) ? `"${s.replace(/"/g, '""')}"` : s; };

function toYaml(v, ind = "") {
  if (v === null) return "null";
  if (Array.isArray(v)) return v.length ? v.map((x) => `\n${ind}- ${typeof x === "object" && x !== null ? toYaml(x, ind + "  ").trimStart() : toYaml(x, ind + "  ")}`).join("") : "[]";
  if (typeof v === "object") { const e = Object.entries(v); return e.length ? e.map(([k, x]) => `\n${ind}${/^[\w.-]+$/.test(k) ? k : JSON.stringify(k)}:${typeof x === "object" && x !== null && Object.keys(x).length ? toYaml(x, ind + "  ") : " " + toYaml(x, ind + "  ")}`).join("") : "{}"; }
  if (typeof v === "string") return /^[\w./@ -]*$/.test(v) && v.trim() === v && v && !/^(true|false|null|yes|no|~|[\d.+-]+)$/i.test(v) ? v : JSON.stringify(v);
  return String(v);
}

function xmlFormat(xml, indent = "  ") {
  let depth = 0;
  return String(xml).replace(/>\s*</g, "><").replace(/</g, "\n<").split("\n").filter((l) => l.trim()).map((l) => {
    if (/^<\//.test(l)) depth = Math.max(depth - 1, 0);
    const out = indent.repeat(depth) + l;
    if (/^<[^!?/][^>]*[^/]>/.test(l) && !/<\/[^>]+>$/.test(l)) depth++;
    return out;
  }).join("\n");
}

const RE = {
  urls: /\b(?:https?|ftp):\/\/[^\s<>"'`]+/gi,
  emails: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g,
  ipv4: /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g,
  ipv6: /(?<![:\w])(?:[0-9a-f]{1,4}:){2,7}(?::|[0-9a-f]{1,4})(?![:\w])|(?<![:\w])::(?:[0-9a-f]{1,4}:){0,6}[0-9a-f]{1,4}(?![:\w])/gi,
  domains: /\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b/gi,
  mac: /\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b/gi,
  hashes: /\b(?:[a-f0-9]{128}|[a-f0-9]{96}|[a-f0-9]{64}|[a-f0-9]{40}|[a-f0-9]{32})\b/gi,
  "file paths": /(?:[A-Za-z]:\\[^\s"'<>|]+|(?<![\w.])\/(?:[\w.-]+\/)+[\w.-]+)/g,
  dates: /\b\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}(?::\d{2})?)?\b|\b\d{1,2}\/\d{1,2}\/\d{2,4}\b/g,
  "credit cards": /\b(?:\d[ -]?){13,19}\b/g,
};
const extract = (kind) => ({ name: `Extract ${kind}`, run: (i, a) => { let m = String(i).match(RE[kind]) || []; if (a.unique) m = [...new Set(m)]; if (a.sort) m.sort(); return a.count ? `${m.length} found\n${m.join("\n")}` : m.join("\n"); }, args: [opt("unique", "Unique only", "checkbox", { default: true }), opt("sort", "Sort", "checkbox"), opt("count", "Show count", "checkbox", { default: true })] });

const ROMAN = [[1000, "M"], [900, "CM"], [500, "D"], [400, "CD"], [100, "C"], [90, "XC"], [50, "L"], [40, "XL"], [10, "X"], [9, "IX"], [5, "V"], [4, "IV"], [1, "I"]];
function parseColor(s) {
  s = String(s).trim().toLowerCase(); let m;
  if ((m = s.match(/^#?([0-9a-f]{3,8})$/))) { let h = m[1]; if (h.length <= 4) h = [...h].map((c) => c + c).join(""); return { r: parseInt(h.slice(0, 2), 16), g: parseInt(h.slice(2, 4), 16), b: parseInt(h.slice(4, 6), 16), a: h.length === 8 ? parseInt(h.slice(6), 16) / 255 : 1 }; }
  if ((m = s.match(/^rgba?\(\s*(\d+)[\s,]+(\d+)[\s,]+(\d+)(?:[\s,/]+([\d.]+))?\s*\)$/))) return { r: +m[1], g: +m[2], b: +m[3], a: m[4] ? +m[4] : 1 };
  if ((m = s.match(/^hsla?\(\s*([\d.]+)[\s,]+([\d.]+)%[\s,]+([\d.]+)%(?:[\s,/]+([\d.]+))?\s*\)$/))) { const h = +m[1] / 360, sat = +m[2] / 100, l = +m[3] / 100; const f = (n) => { const k = (n + h * 12) % 12, a2 = sat * Math.min(l, 1 - l); return Math.round(255 * (l - a2 * Math.max(-1, Math.min(k - 3, 9 - k, 1)))); }; return { r: f(0), g: f(8), b: f(4), a: m[4] ? +m[4] : 1 }; }
  throw new Error("Use #hex, rgb(...) or hsl(...)");
}
function rgbToHsl({ r, g, b }) { r /= 255; g /= 255; b /= 255; const mx = Math.max(r, g, b), mn = Math.min(r, g, b), l = (mx + mn) / 2; let h = 0, s = 0; if (mx !== mn) { const d = mx - mn; s = l > 0.5 ? d / (2 - mx - mn) : d / (mx + mn); h = mx === r ? (g - b) / d + (g < b ? 6 : 0) : mx === g ? (b - r) / d + 2 : (r - g) / d + 4; h *= 60; } return [Math.round(h), Math.round(s * 100), Math.round(l * 100)]; }

const PERMS = ["---", "--x", "-w-", "-wx", "r--", "r-x", "rw-", "rwx"];
const UNITS = { B: 1, KB: 1e3, MB: 1e6, GB: 1e9, TB: 1e12, KiB: 1024, MiB: 1024 ** 2, GiB: 1024 ** 3, TiB: 1024 ** 4 };

export const ops = {
  "json-format": { name: "JSON Prettify", run: (i, a) => JSON.stringify(JSON.parse(i), a.sortKeys ? (k, v) => (v && typeof v === "object" && !Array.isArray(v) ? Object.fromEntries(Object.entries(v).sort()) : v) : null, Number(a.indent) || 2), args: [select("indent", "Indent", ["2", "4", "1"]), opt("sortKeys", "Sort keys", "checkbox")] },
  "json-minify": { name: "JSON Minify", run: (i) => JSON.stringify(JSON.parse(i)) },
  "json-validate": { name: "JSON Validator", run: (i) => { try { const v = JSON.parse(i); return `Valid JSON (${Array.isArray(v) ? `array of ${v.length}` : typeof v})`; } catch (e) { return `Invalid JSON: ${e.message}`; } } },
  "json-to-csv": { name: "JSON to CSV", run: (i, a) => { let d = JSON.parse(i); if (!Array.isArray(d)) d = [d]; const sep = a.sep === "Tab" ? "\t" : a.sep === "Semicolon" ? ";" : ","; const cols = [...new Set(d.flatMap((r) => Object.keys(r ?? {})))]; return [cols.map((c) => csvCell(c, sep)).join(sep), ...d.map((r) => cols.map((c) => csvCell(r?.[c], sep)).join(sep))].join("\n"); }, args: [select("sep", "Separator", ["Comma", "Semicolon", "Tab"])] },
  "csv-to-json": { name: "CSV to JSON", run: (i, a) => { const sep = a.sep === "Tab" ? "\t" : a.sep === "Semicolon" ? ";" : ","; const rows = parseCsv(String(i), sep); if (!a.header) return JSON.stringify(rows, null, 2); const [h, ...rest] = rows; return JSON.stringify(rest.map((r) => Object.fromEntries(h.map((k, j) => [k, r[j] ?? ""]))), null, 2); }, args: [select("sep", "Separator", ["Comma", "Semicolon", "Tab"]), opt("header", "First row is header", "checkbox", { default: true })] },
  "json-to-yaml": { name: "JSON to YAML", run: (i) => toYaml(JSON.parse(i)).replace(/^\n/, "") },
  "json-to-xml": { name: "JSON to XML", run: (i) => { const esc = (s) => String(s).replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;"); const w = (k, v, ind) => Array.isArray(v) ? v.map((x) => w(k, x, ind)).join("\n") : v && typeof v === "object" ? `${ind}<${k}>\n${Object.entries(v).map(([kk, vv]) => w(kk.replace(/[^\w.-]/g, "_"), vv, ind + "  ")).join("\n")}\n${ind}</${k}>` : `${ind}<${k}>${esc(v)}</${k}>`; return `<?xml version="1.0" encoding="UTF-8"?>\n${w("root", JSON.parse(i), "")}`; } },
  "xml-format": { name: "XML Prettify", run: (i) => xmlFormat(i) },
  "html-strip": { name: "Strip HTML Tags", run: (i) => String(i).replace(/<script[\s\S]*?<\/script>|<style[\s\S]*?<\/style>/gi, "").replace(/<[^>]+>/g, "").replace(/\n\s*\n+/g, "\n\n").trim() },
  "url-parse": { name: "URL Parser", run: (i) => { const u = new URL(String(i).trim()); const q = [...u.searchParams].map(([k, v]) => `  ${k} = ${v}`).join("\n");
    return `Protocol: ${u.protocol}\nUsername: ${u.username}\nPassword: ${u.password}\nHostname: ${u.hostname}\nPort: ${u.port || "(default)"}\nPath: ${u.pathname}\nQuery: ${u.search}\n${q}\nFragment: ${u.hash}\nOrigin: ${u.origin}`; } },
  "query-to-json": { name: "Query String to JSON", run: (i) => { const p = new URLSearchParams(String(i).replace(/^[^?]*\?/, "")); const o = {}; for (const [k, v] of p) o[k] = k in o ? [].concat(o[k], v) : v; return JSON.stringify(o, null, 2); } },
  "defang-url": { name: "Defang URL / IP", run: (i) => String(i).replace(/https?:\/\//gi, (m) => m.replace(/t/gi, "x").replace("://", "[://]")).replace(/\./g, "[.]") },
  "fang-url": { name: "Fang URL / IP", run: (i) => String(i).replace(/\[\.\]|\(\.\)|\{\.\}/g, ".").replace(/\[:\/\/\]/g, "://").replace(/hxxp/gi, "http").replace(/\[@\]/g, "@") },
  ...Object.fromEntries(Object.keys(RE).map((k) => [`extract-${k.replace(/\s/g, "-")}`, extract(k)])),
  "unix-timestamp": { name: "Unix Timestamp Converter", run: (i) => { const s = String(i).trim(); const now = Date.now(); let d;
    if (!s) d = new Date(now); else if (/^-?\d+(\.\d+)?$/.test(s)) { const n = Number(s); d = new Date(Math.abs(n) > 1e11 ? n : n * 1000); } else d = new Date(s);
    if (isNaN(d)) throw new Error("Could not parse date or timestamp");
    return `Unix (s): ${Math.floor(d / 1000)}\nUnix (ms): ${+d}\nISO 8601: ${d.toISOString()}\nUTC: ${d.toUTCString()}\nLocal: ${d.toString()}\nRelative: ${rel(d - now)}`; }, placeholder: "1700000000 or 2026-01-01T00:00:00Z (blank = now)" },
  "date-diff": { name: "Date Difference", run: (i, a) => { const x = new Date(String(i).trim()), y = new Date(String(a.other).trim()); if (isNaN(x) || isNaN(y)) throw new Error("Enter two valid dates"); const ms = Math.abs(y - x); return `${(ms / 864e5).toFixed(2)} days\n${(ms / 36e5).toFixed(2)} hours\n${(ms / 6e4).toFixed(0)} minutes\n${(ms / 1e3).toFixed(0)} seconds`; }, args: [opt("other", "Second date", "text", { default: "2027-01-01" })], placeholder: "2026-01-01" },
  "base-convert": { name: "Integer Base Converter", run: (i, a) => { const s = String(i).trim().toLowerCase().replace(/^0[xbo]/, ""); const from = Number(a.from); let n = 0n; for (const c of s) { const d = parseInt(c, 36); if (isNaN(d) || d >= from) throw new Error(`"${c}" is not a base-${from} digit`); n = n * BigInt(from) + BigInt(d); }
    return [2, 8, 10, 16, 32, 36].map((b) => `Base ${String(b).padEnd(3)} ${n.toString(b)}`).join("\n"); }, args: [select("from", "Input base", ["10", "16", "2", "8", "32", "36"])] },
  "roman": { name: "Roman Numeral Converter", run: (i) => { const s = String(i).trim().toUpperCase(); if (/^\d+$/.test(s)) { let n = +s; if (n < 1 || n > 3999) throw new Error("1–3999 only"); let r = ""; for (const [v, sym] of ROMAN) while (n >= v) { r += sym; n -= v; } return r; }
    const map = { I: 1, V: 5, X: 10, L: 50, C: 100, D: 500, M: 1000 }; let t = 0; for (let k = 0; k < s.length; k++) { const v = map[s[k]]; if (!v) throw new Error("Invalid numeral"); t += v < (map[s[k + 1]] || 0) ? -v : v; } return String(t); } },
  "temperature": { name: "Temperature Converter", run: (i, a) => { const v = parseFloat(i); if (isNaN(v)) throw new Error("Enter a number"); const c = { C: v, F: (v - 32) * 5 / 9, K: v - 273.15, R: (v - 491.67) * 5 / 9 }[a.from]; return `Celsius: ${c.toFixed(2)} °C\nFahrenheit: ${(c * 9 / 5 + 32).toFixed(2)} °F\nKelvin: ${(c + 273.15).toFixed(2)} K\nRankine: ${((c + 273.15) * 9 / 5).toFixed(2)} °R`; }, args: [select("from", "From", ["C", "F", "K", "R"])] },
  "percentage": { name: "Percentage Calculator", input: false, run: (_, a) => { const x = Number(a.x), y = Number(a.y); return `${x}% of ${y} = ${(x / 100) * y}\n${x} is ${((x / y) * 100).toFixed(4)}% of ${y}\nChange from ${x} to ${y}: ${(((y - x) / x) * 100).toFixed(4)}%`; }, args: [opt("x", "X", "number", { default: 20 }), opt("y", "Y", "number", { default: 150 })] },
  "byte-convert": { name: "Data Size Converter", run: (i, a) => { const v = parseFloat(i); if (isNaN(v)) throw new Error("Enter a number"); const bytes = v * UNITS[a.unit]; return Object.entries(UNITS).map(([u, f]) => `${u.padEnd(4)} ${+(bytes / f).toPrecision(10)}`).join("\n") + `\nbits ${bytes * 8}`; }, args: [select("unit", "Unit", Object.keys(UNITS), "MB")] },
  "color-convert": { name: "Color Converter", run: (i) => { const c = parseColor(i); const [h, s, l] = rgbToHsl(c); const hex = "#" + [c.r, c.g, c.b].map((x) => x.toString(16).padStart(2, "0")).join("");
    return `HEX: ${hex}\nRGB: rgb(${c.r}, ${c.g}, ${c.b})\nRGBA: rgba(${c.r}, ${c.g}, ${c.b}, ${c.a})\nHSL: hsl(${h}, ${s}%, ${l}%)\nDecimal: ${(c.r << 16) | (c.g << 8) | c.b}`; }, preview: "color" },
  "chmod": { name: "Chmod Calculator", run: (i) => { const s = String(i).trim();
    if (/^[0-7]{3,4}$/.test(s)) { const d = s.slice(-3); return `Octal: ${s}\nSymbolic: ${[...d].map((x) => PERMS[+x]).join("")}\nCommand: chmod ${s} file`; }
    const m = s.replace(/^[-dl]/, ""); if (!/^[rwx-]{9}$/.test(m)) throw new Error("Enter octal (755) or symbolic (rwxr-xr-x)");
    const oct = m.match(/.{3}/g).map((t) => PERMS.indexOf(t)).join(""); return `Octal: ${oct}\nSymbolic: ${m}\nCommand: chmod ${oct} file`; }, placeholder: "755 or rwxr-xr-x" },
  "entropy": { name: "Shannon Entropy", run: (i) => { const b = utf8(i); if (!b.length) return "0 bits/byte"; const f = new Array(256).fill(0); for (const x of b) f[x]++; let e = 0; for (const c of f) if (c) { const p = c / b.length; e -= p * Math.log2(p); }
    return `${e.toFixed(4)} bits per byte (max 8)\n${e > 7.5 ? "Very high — likely encrypted or compressed" : e > 6 ? "High — possibly encoded/compressed" : e > 4 ? "Typical of text" : "Low — repetitive data"}`; } },
  "frequency-analysis": { name: "Character Frequency", run: (i) => { const f = new Map(); for (const c of String(i)) f.set(c, (f.get(c) || 0) + 1); const n = Array.from(String(i)).length || 1; return [...f].sort((a, b) => b[1] - a[1]).map(([c, k]) => `${JSON.stringify(c).padEnd(6)} ${String(k).padStart(6)}  ${((k / n) * 100).toFixed(2)}%`).join("\n"); } },
  "list-convert": { name: "List Converter", run: (i, a) => { let items = lines(i).map((x) => x.trim()).filter(Boolean); if (a.unique) items = [...new Set(items)]; if (a.sort) items.sort(); const w = (x) => `${a.prefix}${a.quote === "None" ? x : a.quote === "Double" ? `"${x}"` : `'${x}'`}${a.suffix}`; return items.map(w).join(a.joiner.replace(/\\n/g, "\n")); },
    args: [opt("joiner", "Join with", "text", { default: ", " }), select("quote", "Quote items", ["None", "Double", "Single"]), opt("prefix", "Prefix", "text"), opt("suffix", "Suffix", "text"), opt("unique", "Unique", "checkbox"), opt("sort", "Sort", "checkbox")] },
  "user-agent": { name: "User-Agent Parser", run: (i) => { const ua = String(i); const pick = (re) => (ua.match(re) || [])[1];
    const browser = pick(/(Edg|OPR|Firefox|Chrome|Safari|MSIE|Trident)\/?\s*([\d.]+)?/) ? ua.match(/(Edg|OPR|Firefox|Chrome|Safari|MSIE|Trident)\/?\s*([\d.]+)?/).slice(1).join(" ") : "Unknown";
    const os = /Windows NT ([\d.]+)/.test(ua) ? `Windows NT ${pick(/Windows NT ([\d.]+)/)}` : /Android ([\d.]+)/.test(ua) ? `Android ${pick(/Android ([\d.]+)/)}` : /iPhone OS ([\d_]+)/.test(ua) ? `iOS ${pick(/iPhone OS ([\d_]+)/).replace(/_/g, ".")}` : /Mac OS X ([\d_]+)/.test(ua) ? `macOS ${pick(/Mac OS X ([\d_]+)/).replace(/_/g, ".")}` : /Linux/.test(ua) ? "Linux" : "Unknown";
    return `Browser: ${browser.replace("Edg", "Edge").replace("OPR", "Opera")}\nOS: ${os}\nDevice: ${/Mobile|iPhone|Android/.test(ua) ? "Mobile" : /iPad|Tablet/.test(ua) ? "Tablet" : "Desktop"}\nEngine: ${/Gecko\/\d/.test(ua) ? "Gecko" : /AppleWebKit/.test(ua) ? "WebKit/Blink" : /Trident/.test(ua) ? "Trident" : "Unknown"}\nBot: ${/bot|crawl|spider|slurp/i.test(ua) ? "Yes" : "No"}`; }, placeholder: "Mozilla/5.0 (Windows NT 10.0; Win64; x64) ..." },
};
function rel(ms) { const s = Math.round(ms / 1000), a = Math.abs(s); const [v, u] = a < 60 ? [a, "seconds"] : a < 3600 ? [Math.round(a / 60), "minutes"] : a < 86400 ? [Math.round(a / 3600), "hours"] : a < 2592000 ? [Math.round(a / 86400), "days"] : a < 31536000 ? [Math.round(a / 2592000), "months"] : [Math.round(a / 31536000), "years"]; return s === 0 ? "now" : s < 0 ? `${v} ${u} ago` : `in ${v} ${u}`; }
