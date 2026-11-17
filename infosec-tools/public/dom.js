// Tiny DOM helpers. All text goes through textContent, never innerHTML, so catalog
// content and tool output can't inject markup.
export function h(tag, attrs = {}, ...children) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === undefined || v === null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "value") el.value = v;
    else if (k === "checked") el.checked = !!v;
    else el.setAttribute(k, v === true ? "" : String(v));
  }
  for (const c of children.flat(Infinity)) if (c !== null && c !== undefined && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
export const $ = (sel, root = document) => root.querySelector(sel);
export const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
export function toast(msg, err = false) {
  let t = $("#toast"); if (!t) { t = h("div", { id: "toast", class: "toast", role: "status", "aria-live": "polite" }); document.body.append(t); }
  t.textContent = msg; t.classList.toggle("err", !!err); t.classList.add("show");
  clearTimeout(toast.t); toast.t = setTimeout(() => t.classList.remove("show"), err ? 3600 : 2000);
}
export function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
export const store = { get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } }, set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } } };
// The server renders the admin-chosen theme into <html data-theme data-default-theme>; theme.js re-applies the
// visitor's own light/dark choice before paint. The toggle flips between light and dark (or back to the default).
export function initTheme(btn) {
  const d = document.documentElement; const def = d.dataset.defaultTheme || "dark";
  const modeOf = (t) => (["light", "paper"].includes(t) ? "light" : "dark");
  btn?.addEventListener("click", () => {
    const next = d.dataset.mode === "dark" ? "light" : "dark"; const theme = modeOf(def) === next ? def : next;
    d.dataset.theme = theme; d.dataset.mode = next; try { localStorage.setItem("it-mode", next); } catch { /* ignore */ }
  });
}
// replaceChildren() stringifies null/arrays; mount() flattens and drops empties first.
export function mount(el, ...kids) { el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false)); }
export const hue = (s) => { let x = 0; for (const c of String(s)) x = (x * 31 + c.charCodeAt(0)) % 360; return x; };
export const initials = (n) => String(n).replace(/[^A-Za-z0-9 ]/g, " ").trim().split(/\s+/).slice(0, 2).map((w) => w[0]).join("").toUpperCase() || "?";
