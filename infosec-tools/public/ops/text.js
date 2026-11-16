import { lines, select, opt } from "./util.js";

const words = (s) => String(s).replace(/([a-z0-9])([A-Z])/g, "$1 $2").replace(/[_\-./]+/g, " ").trim().split(/\s+/).filter(Boolean);
const cap = (w) => w.charAt(0).toUpperCase() + w.slice(1).toLowerCase();
const CASES = {
  "lowercase": (s) => s.toLowerCase(), "UPPERCASE": (s) => s.toUpperCase(),
  "Title Case": (s) => s.replace(/\w\S*/g, cap), "Sentence case": (s) => s.toLowerCase().replace(/(^\s*\w|[.!?]\s+\w)/g, (m) => m.toUpperCase()),
  "camelCase": (s) => words(s).map((w, i) => (i ? cap(w) : w.toLowerCase())).join(""), "PascalCase": (s) => words(s).map(cap).join(""),
  "snake_case": (s) => words(s).map((w) => w.toLowerCase()).join("_"), "CONSTANT_CASE": (s) => words(s).map((w) => w.toUpperCase()).join("_"),
  "kebab-case": (s) => words(s).map((w) => w.toLowerCase()).join("-"), "dot.case": (s) => words(s).map((w) => w.toLowerCase()).join("."),
  "path/case": (s) => words(s).map((w) => w.toLowerCase()).join("/"), "aLtErNaTiNg": (s) => Array.from(s, (c, i) => (i % 2 ? c.toUpperCase() : c.toLowerCase())).join(""),
};
const LOREM = "lorem ipsum dolor sit amet consectetur adipiscing elit sed do eiusmod tempor incididunt ut labore et dolore magna aliqua ut enim ad minim veniam quis nostrud exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat duis aute irure dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur excepteur sint occaecat cupidatat non proident sunt in culpa qui officia deserunt mollit anim id est laborum".split(" ");

function lineDiff(a, b) {
  const A = lines(a), B = lines(b), n = A.length, m = B.length;
  const dp = Array.from({ length: n + 1 }, () => new Uint32Array(m + 1));
  for (let i = n - 1; i >= 0; i--) for (let j = m - 1; j >= 0; j--) dp[i][j] = A[i] === B[j] ? dp[i + 1][j + 1] + 1 : Math.max(dp[i + 1][j], dp[i][j + 1]);
  const out = []; let i = 0, j = 0;
  while (i < n && j < m) { if (A[i] === B[j]) { out.push("  " + A[i]); i++; j++; } else if (dp[i + 1][j] >= dp[i][j + 1]) out.push("- " + A[i++]); else out.push("+ " + B[j++]); }
  while (i < n) out.push("- " + A[i++]); while (j < m) out.push("+ " + B[j++]);
  return out.join("\n");
}

export const ops = {
  "case-convert": { name: "Case Converter", run: (i, a) => (a.case === "All" ? Object.entries(CASES).map(([k, f]) => `${k.padEnd(14)} ${f(String(i))}`).join("\n") : CASES[a.case](String(i))), args: [select("case", "Case", ["All", ...Object.keys(CASES)])] },
  "text-stats": { name: "Text Statistics", run: (i) => { const s = String(i); const w = s.trim() ? s.trim().split(/\s+/).length : 0;
    return `Characters: ${Array.from(s).length}\nCharacters (no spaces): ${s.replace(/\s/g, "").length}\nWords: ${w}\nLines: ${s ? lines(s).length : 0}\nSentences: ${(s.match(/[.!?]+(\s|$)/g) || []).length}\nParagraphs: ${s.split(/\n\s*\n/).filter((p) => p.trim()).length}\nBytes (UTF-8): ${new TextEncoder().encode(s).length}\nReading time: ~${Math.max(1, Math.round(w / 230))} min`; } },
  "sort-lines": { name: "Sort Lines", run: (i, a) => { let l = lines(i); if (a.unique) l = [...new Set(l)]; l.sort(a.order === "Numeric" ? (x, y) => parseFloat(x) - parseFloat(y) : a.order === "Length" ? (x, y) => x.length - y.length : (x, y) => x.localeCompare(y, undefined, { sensitivity: a.caseInsensitive ? "base" : "variant" })); if (a.reverse) l.reverse(); return l.join("\n"); },
    args: [select("order", "Order", ["Alphabetical", "Numeric", "Length"]), opt("reverse", "Reverse", "checkbox"), opt("unique", "Remove duplicates", "checkbox"), opt("caseInsensitive", "Case-insensitive", "checkbox")] },
  "unique-lines": { name: "Unique Lines", run: (i, a) => { const seen = new Map(); for (const l of lines(i)) seen.set(l, (seen.get(l) || 0) + 1); return a.counts ? [...seen].map(([l, c]) => `${String(c).padStart(5)}  ${l}`).join("\n") : [...seen.keys()].join("\n"); }, args: [opt("counts", "Show counts", "checkbox")] },
  "remove-whitespace": { name: "Remove Whitespace", run: (i, a) => { let s = String(i); if (a.mode === "All") return s.replace(/\s+/g, ""); if (a.mode === "Trim lines") return lines(s).map((l) => l.trim()).join("\n"); if (a.mode === "Empty lines") return lines(s).filter((l) => l.trim()).join("\n"); return s.replace(/[ \t]+/g, " ").trim(); }, args: [select("mode", "Remove", ["Collapse spaces", "All", "Trim lines", "Empty lines"])] },
  "find-replace": { name: "Find / Replace", run: (i, a) => { const re = a.regex ? new RegExp(a.find, a.flags || "g") : new RegExp(a.find.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "g" + (a.flags?.includes("i") ? "i" : "")); return String(i).replace(re, a.replace); },
    args: [opt("find", "Find", "text"), opt("replace", "Replace with", "text"), opt("regex", "Regular expression", "checkbox"), opt("flags", "Flags", "text", { default: "g" })] },
  "regex-tester": { name: "Regular Expression Tester", run: (i, a) => { const re = new RegExp(a.pattern, (a.flags || "").includes("g") ? a.flags : (a.flags || "") + "g"); const out = [];
    for (const m of String(i).matchAll(re)) { out.push(`#${out.length + 1} @${m.index}: ${JSON.stringify(m[0])}${m.length > 1 ? "  groups: " + JSON.stringify(m.slice(1)) : ""}${m.groups ? "  named: " + JSON.stringify(m.groups) : ""}`); if (out.length >= 1000) break; }
    return out.length ? `${out.length} match(es)\n` + out.join("\n") : "No matches"; }, args: [opt("pattern", "Pattern", "text", { default: "\\b\\w+@\\w+\\.\\w+\\b" }), opt("flags", "Flags", "text", { default: "gi" })] },
  "count-occurrences": { name: "Count Occurrences", run: (i, a) => { if (!a.search) throw new Error("Enter a search string"); return `${String(i).split(a.search).length - 1} occurrence(s) of ${JSON.stringify(a.search)}`; }, args: [opt("search", "Search for", "text")] },
  "word-frequency": { name: "Word Frequency", run: (i) => { const f = new Map(); for (const w of String(i).toLowerCase().match(/[\p{L}\p{N}']+/gu) || []) f.set(w, (f.get(w) || 0) + 1); return [...f].sort((a, b) => b[1] - a[1]).slice(0, 200).map(([w, c]) => `${String(c).padStart(6)}  ${w}`).join("\n"); } },
  "lorem-ipsum": { name: "Lorem Ipsum Generator", input: false, run: (_, a) => Array.from({ length: Math.min(Number(a.paragraphs) || 1, 50) }, (_, p) => { const n = Number(a.sentences) || 4; return Array.from({ length: n }, (_, s) => { const len = 8 + ((p * 7 + s * 5) % 9); const ws = Array.from({ length: len }, (_, k) => LOREM[(p * 31 + s * 17 + k * 7) % LOREM.length]); ws[0] = cap(ws[0]); return ws.join(" ") + "."; }).join(" "); }).join("\n\n"),
    args: [opt("paragraphs", "Paragraphs", "number", { default: 3 }), opt("sentences", "Sentences per paragraph", "number", { default: 4 })] },
  "slugify": { name: "Slugify String", run: (i) => String(i).normalize("NFKD").replace(/[̀-ͯ]/g, "").toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "") },
  "text-diff": { name: "Text Diff", run: (i, a) => lineDiff(i, a.other), args: [opt("other", "Compare with (second text)", "textarea")] },
  "string-obfuscate": { name: "String Obfuscator", run: (i, a) => { const s = String(i); const keep = Number(a.keep) || 4; return s.length <= keep ? "*".repeat(s.length) : s.slice(0, keep) + "*".repeat(Math.max(0, s.length - keep)); }, args: [opt("keep", "Keep first N characters", "number", { default: 4 })] },
  "numeronym": { name: "Numeronym Generator", run: (i) => String(i).split(/\s+/).map((w) => (w.length > 3 ? `${w[0]}${w.length - 2}${w.at(-1)}` : w)).join(" ") },
  "add-line-numbers": { name: "Add Line Numbers", run: (i) => { const l = lines(i); const w = String(l.length).length; return l.map((x, k) => `${String(k + 1).padStart(w)}  ${x}`).join("\n"); } },
  "remove-line-numbers": { name: "Remove Line Numbers", run: (i) => lines(i).map((l) => l.replace(/^\s*\d+[\s.:)|-]*/, "")).join("\n") },
  "head-tail": { name: "Head / Tail", run: (i, a) => { const l = lines(i), n = Number(a.n) || 10; return (a.which === "Tail" ? l.slice(-n) : l.slice(0, n)).join("\n"); }, args: [select("which", "Take", ["Head", "Tail"]), opt("n", "Lines", "number", { default: 10 })] },
  "split-join": { name: "Split / Join", run: (i, a) => String(i).split(a.split.replace(/\\n/g, "\n").replace(/\\t/g, "\t")).join(a.join.replace(/\\n/g, "\n").replace(/\\t/g, "\t")), args: [opt("split", "Split on", "text", { default: "," }), opt("join", "Join with", "text", { default: "\\n" })] },
  "emoji-escape": { name: "Unicode Code Points", run: (i) => Array.from(String(i), (c) => `${JSON.stringify(c)}  U+${c.codePointAt(0).toString(16).toUpperCase().padStart(4, "0")}`).join("\n") },
  "markdown-to-html": { name: "Markdown to HTML", run: (i) => { const esc = (s) => s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
    return lines(i).map((l) => { const h = l.match(/^(#{1,6})\s+(.*)/); if (h) return `<h${h[1].length}>${esc(h[2])}</h${h[1].length}>`; if (/^\s*[-*]\s+/.test(l)) return `<li>${esc(l.replace(/^\s*[-*]\s+/, ""))}</li>`; return l.trim() ? `<p>${esc(l)}</p>` : ""; }).join("\n").replace(/\*\*(.+?)\*\*/g, "<strong>$1</strong>").replace(/`([^`]+)`/g, "<code>$1</code>").replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2">$1</a>'); } },
};
