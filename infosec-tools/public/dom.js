// Tiny DOM helpers. All text goes through textContent — never innerHTML — so catalog
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
export function toast(msg, err = false) { const t = h("div", { class: "toast" + (err ? " err" : ""), role: "status" }, msg); document.body.append(t); setTimeout(() => t.remove(), 3200); }
export function debounce(fn, ms) { let t; return (...a) => { clearTimeout(t); t = setTimeout(() => fn(...a), ms); }; }
export const store = { get(k, d) { try { const v = localStorage.getItem(k); return v === null ? d : JSON.parse(v); } catch { return d; } }, set(k, v) { try { localStorage.setItem(k, JSON.stringify(v)); } catch { /* storage unavailable */ } } };
export function initTheme(btn) {
  const apply = (t) => { document.documentElement.dataset.theme = t; store.set("theme", t); };
  apply(store.get("theme", matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
  btn?.addEventListener("click", () => apply(document.documentElement.dataset.theme === "light" ? "dark" : "light"));
}
// replaceChildren() stringifies null/arrays; mount() flattens and drops empties first.
export function mount(el, ...kids) { el.replaceChildren(...kids.flat(Infinity).filter((k) => k !== null && k !== undefined && k !== false)); }
