// Infosec Tools admin: site settings, toolkits, their categories and tools, backups. Same design as the portal.
import { h, $, $$, toast, initTheme, mount, hue, initials } from "./dom.js";
import { icon, ICON_NAMES } from "./icons.js";
import { registry } from "./ops/index.js";
import { renderRunner, argField, defaults, SERVER_ARGS } from "./runner.js";

const main = $("#main");
let catalog = null, serverOps = {}, themes = ["dark", "light"], dirty = false;
const ui = { section: "overview", kit: 0, tab: "tools", q: "", cat: "", shown: 200 };

const api = async (path, opts = {}) => {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-Requested-With": "infosec-tools", ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j;
};
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) || "item";
const topCat = (c) => String(c || "General").split(" · ")[0];
const subCat = (c) => String(c || "").split(" · ").slice(1).join(" · ");
const plural = (n, w, p = w + "s") => `${n} ${n === 1 ? w : p}`;
const uniqueId = (base, taken) => { let id = slug(base), i = 2; while (taken.has(id)) id = `${slug(base)}-${i++}`; return id; };
const kitStyle = (k) => `--accent:${k.accent || "#22d3ee"}`;
addEventListener("beforeunload", (e) => { if (dirty) { e.preventDefault(); e.returnValue = ""; } });
function markDirty() { dirty = true; drawTop(); }

// ---------- boot / auth ----------
async function boot() {
  initTheme($("#themeToggle"));
  const st = await api("/api/admin/status");
  if (!st.enabled) { drawTop(); return mount(main, h("div", { class: "wrap" }, h("div", { class: "login-card panel" }, h("span", { class: "cat-ico" }, icon("lock", 24)), h("h1", {}, "Admin is disabled"), h("p", { class: "muted" }, "Set the ADMIN_PASSWORD environment variable on the server and restart it.")))); }
  if (!st.authenticated) return login();
  [catalog, serverOps] = await Promise.all([api("/api/admin/catalog"), api("/api/admin/server-ops")]);
  themes = (await api("/api/admin/meta").catch(() => ({}))).themes || themes;
  dirty = false; draw();
}
function login() {
  drawTop();
  const pw = h("input", { type: "password", autocomplete: "current-password", placeholder: "Admin password", "aria-label": "Admin password", required: true });
  const err = h("p", { class: "form-error", role: "alert" });
  const go = async (e) => { e.preventDefault(); err.textContent = ""; btn.disabled = true;
    try { await api("/api/admin/login", { method: "POST", body: JSON.stringify({ password: pw.value }) }); await boot(); } catch (x) { err.textContent = x.message; btn.disabled = false; pw.select(); } };
  const btn = h("button", { class: "btn primary", type: "submit" }, "Sign in ", icon("arrow", 16));
  mount(main, h("div", { class: "wrap" }, h("form", { class: "login-card panel", onsubmit: go },
    h("span", { class: "cat-ico" }, icon("shield", 24)), h("span", { class: "kicker" }, "Admin"), h("h1", {}, "Sign in"),
    h("p", { class: "muted" }, "Manage the toolkits, categories and tools of the site."), pw, err, btn)));
  pw.focus();
}
async function logout() { if (dirty && !confirm("Discard unsaved changes and sign out?")) return; await api("/api/admin/logout", { method: "POST" }).catch(() => {}); dirty = false; catalog = null; login(); }

async function save() {
  if (!dirty) return;
  const btn = $("#saveBtn"); if (btn) btn.disabled = true;
  try {
    const clean = structuredClone(catalog); for (const t of clean.tabs) delete t._new;
    await api("/api/admin/catalog", { method: "PUT", body: JSON.stringify(clean) });
    const keepKit = catalog.tabs[ui.kit]?.id;
    catalog = await api("/api/admin/catalog"); dirty = false;
    ui.kit = Math.max(0, catalog.tabs.findIndex((t) => t.id === keepKit));
    toast("Saved. The live site is updated."); draw();
  } catch (e) { toast(e.message, true); if (btn) btn.disabled = false; }
}
document.addEventListener("keydown", (e) => { if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "s" && catalog) { e.preventDefault(); save(); } if (e.key === "Escape") closeDrawer(); });
document.addEventListener("click", (e) => { if (e.target.closest("[data-close]")) closeDrawer(); });

// ---------- chrome ----------
function drawTop() {
  mount($("#topActions"), catalog ? [
    h("span", { class: `save-state${dirty ? " dirty" : ""}` }, dirty ? "Unsaved changes" : "All changes saved"),
    h("a", { class: "btn sm", href: "/", target: "_blank", rel: "noopener" }, icon("external", 15), "View site"),
    h("button", { class: "btn sm primary", id: "saveBtn", type: "button", disabled: !dirty, onclick: save, title: "Save (Ctrl+S)" }, icon("check", 15), "Save"),
    h("button", { class: "icon-btn", type: "button", "aria-label": "Sign out", title: "Sign out", onclick: logout }, icon("logout", 17))] : []);
}
function go(section, kit = ui.kit, tab = ui.tab) { ui.section = section; ui.kit = kit; ui.tab = tab; ui.q = ""; ui.cat = ""; ui.shown = 200; draw(); scrollTo({ top: 0 }); }
function draw() {
  drawTop();
  const kits = catalog.tabs;
  const side = h("aside", { class: "sidebar", "aria-label": "Admin sections" },
    h("h5", {}, "Site"),
    h("ul", { class: "side-list" },
      h("li", {}, h("button", { type: "button", class: ui.section === "overview" ? "on" : "", onclick: () => go("overview") }, icon("grid", 16), "Overview")),
      h("li", {}, h("button", { type: "button", class: ui.section === "site" ? "on" : "", onclick: () => go("site") }, icon("settings", 16), "Site settings"))),
    h("h5", {}, "Toolkits"),
    h("ul", { class: "side-list" }, kits.map((k, i) => h("li", {}, h("button", { type: "button", style: kitStyle(k), class: ui.section === "kit" && ui.kit === i ? "on" : "", onclick: () => go("kit", i, ui.tab) },
      icon(k.icon || "toolbox", 16), h("span", { class: "side-name" }, k.name || "(unnamed)"), k.visible === false ? icon("eyeOff", 14) : null, h("span", { class: "n" }, k.tools.length)))),
      h("li", {}, h("button", { type: "button", class: "add", onclick: addKit }, icon("plus", 16), "New toolkit"))),
    h("h5", {}, "Maintenance"),
    h("ul", { class: "side-list" }, h("li", {}, h("button", { type: "button", class: ui.section === "backups" ? "on" : "", onclick: () => go("backups") }, icon("history", 16), "Backups & import"))));
  const body = h("section", { class: "admin-body" });
  if (ui.section === "site") drawSite(body);
  else if (ui.section === "kit" && kits[ui.kit]) drawKit(body, kits[ui.kit]);
  else if (ui.section === "backups") drawBackups(body);
  else drawOverview(body);
  mount(main, h("div", { class: "wrap" }, h("div", { class: "admin-layout" }, side, body)));
}

// ---------- form helpers ----------
const field = (label, input, opts = {}) => h("div", { class: `field${opts.full ? " full" : ""}` }, h("label", {}, label), input, opts.help ? h("small", { class: "help" }, opts.help) : null);
function textIn(obj, key, opts = {}) {
  const el = h(opts.multiline ? "textarea" : "input", { type: opts.type || "text", rows: opts.rows || 3, placeholder: opts.placeholder || "", value: opts.multiline ? undefined : obj[key] ?? "", maxlength: opts.max, disabled: opts.disabled,
    oninput: (e) => { obj[key] = e.target.value; opts.onchange?.(e.target.value); markDirty(); } }, opts.multiline ? obj[key] ?? "" : null);
  return el;
}
function iconPicker(obj, key = "icon") {
  const prev = h("span", { class: "cat-ico sm" }, icon(obj[key] || "sparkle", 16));
  const sel = h("select", { class: "sel", onchange: (e) => { obj[key] = e.target.value; prev.replaceChildren(icon(e.target.value, 16)); markDirty(); } }, ICON_NAMES.map((n) => h("option", { value: n, selected: n === obj[key] }, n)));
  return h("div", { class: "icon-pick" }, prev, sel);
}
function colorIn(obj, key, allowBlank = false) {
  const hex = h("input", { type: "text", value: obj[key] || "", placeholder: allowBlank ? "theme default" : "#22d3ee", maxlength: 7, class: "hex",
    oninput: (e) => { const v = e.target.value.trim(); if (!v && allowBlank) { obj[key] = ""; markDirty(); } else if (/^#[0-9a-f]{6}$/i.test(v)) { obj[key] = v; pick.value = v; markDirty(); } } });
  const pick = h("input", { type: "color", value: obj[key] || "#22d3ee", "aria-label": "Pick colour", oninput: (e) => { obj[key] = e.target.value; hex.value = e.target.value; markDirty(); } });
  return h("div", { class: "color-in" }, pick, hex, allowBlank ? h("button", { class: "btn sm", type: "button", onclick: () => { obj[key] = ""; hex.value = ""; markDirty(); } }, "Default") : null);
}
const checkIn = (obj, key, label) => h("label", { class: "field check" }, h("input", { type: "checkbox", checked: obj[key] !== false, onchange: (e) => { obj[key] = e.target.checked; markDirty(); } }), h("span", {}, label));
const avatar = (t, k) => h("span", { class: "avatar", style: `--h:${hue(topCat(t.category) + k.id)}` }, initials(t.name));
const head = (kicker, title, text, actions, k) => h("div", { class: "cat-banner admin-head", style: k ? kitStyle(k) : "" }, h("span", { class: "cat-ico" }, icon(k?.icon || "settings", 28)),
  h("div", { style: "flex:1;min-width:220px" }, h("span", { class: "kicker" }, kicker), h("h1", {}, title), text ? h("p", {}, text) : null), actions ? h("div", { class: "actions" }, actions) : null);

// ---------- overview ----------
function drawOverview(body) {
  const tools = catalog.tabs.flatMap((k) => k.tools);
  const cats = catalog.tabs.reduce((n, k) => n + new Set(k.tools.map((t) => topCat(t.category))).size, 0);
  mount(body, head("Admin", "Overview", `Last saved ${catalog.updatedAt ? new Date(catalog.updatedAt).toLocaleString() : "never (seed catalog)"}.`),
    h("div", { class: "stats admin-stats" },
      [["Tools", tools.length, "var(--accent)"], ["Toolkits", catalog.tabs.length, "var(--accent-2)"], ["Categories", cats, "var(--accent-3)"], ["Hidden tools", tools.filter((t) => t.visible === false).length, "var(--danger)"],
        ["Featured", tools.filter((t) => t.featured).length, "var(--warn)"], ["Live checks", tools.filter((t) => t.native?.mode === "server").length, "var(--warn)"]]
        .map(([l, n, c]) => h("div", { class: "stat", style: `--c:${c}` }, h("b", {}, n), h("span", {}, l)))),
    h("div", { class: "section-head", style: "margin:32px 0 16px" }, h("div", {}, h("span", { class: "kicker" }, "Toolkits"), h("h2", {}, "Manage a toolkit"))),
    h("div", { class: "kits two" }, catalog.tabs.map((k, i) => h("div", { class: "kit", style: `--c1:${k.accent};--c2:var(--accent-2);${kitStyle(k)}` },
      h("div", { class: "kit-head" }, h("span", { class: "cat-ico" }, icon(k.icon || "toolbox", 22)), h("div", {}, h("h3", {}, k.name), h("span", { class: "result-count" }, `${plural(k.tools.length, "tool")} · ${plural(new Set(k.tools.map((t) => topCat(t.category))).size, "category", "categories")}${k.visible === false ? " · hidden" : ""}`))),
      h("p", { class: "scenario" }, k.tagline || k.description || "No description yet."),
      h("div", { class: "actions" }, h("button", { class: "btn primary", type: "button", onclick: () => go("kit", i, "tools") }, icon("list", 16), "Tools"),
        h("button", { class: "btn", type: "button", onclick: () => go("kit", i, "categories") }, icon("layers", 16), "Categories"),
        h("button", { class: "btn", type: "button", onclick: () => go("kit", i, "details") }, icon("pen", 16), "Details"))))),
    h("div", { class: "actions", style: "margin-top:16px" }, h("button", { class: "btn", type: "button", onclick: addKit }, icon("plus", 16), "New toolkit")));
}

// ---------- site settings ----------
function drawSite(body) {
  catalog.site = catalog.site || {}; const s = catalog.site;
  const preview = h("div", { class: "hero-preview" });
  const drawPreview = () => mount(preview, h("span", { class: "eyebrow" }, h("span", { class: "dot" }), s.eyebrow || ""), h("h2", {}, `${s.heading || ""} `, h("span", { class: "grad" }, s.highlight || ""), ` ${s.headingEnd || ""}`),
    h("p", {}, String(s.lead || "").replace(/\{(\w+)\}/g, (_, k) => ({ tools: catalog.tabs.reduce((n, t) => n + t.tools.length, 0), toolkits: catalog.tabs.length }[k] ?? `{${k}}`))));
  const t = (key, opts) => textIn(s, key, { ...opts, onchange: drawPreview });
  mount(body, head("Site", "Site settings", "Branding, the home page hero, the footer and the colour theme."),
    h("div", { class: "panel form-panel" }, h("h3", {}, icon("sparkle", 18), "Branding"),
      h("div", { class: "form-grid" }, field("Site title", t("title", { max: 80 }), { help: "Used in the browser tab." }), field("Brand (plain part)", t("brandPrefix", { max: 40 })), field("Brand (gradient part)", t("brandSuffix", { max: 40 })))),
    h("div", { class: "panel form-panel" }, h("h3", {}, icon("home", 18), "Home page hero"),
      h("div", { class: "form-grid" }, field("Eyebrow", t("eyebrow", { max: 80 })), field("Heading", t("heading", { max: 80 })), field("Highlighted words", t("highlight", { max: 80 })), field("Heading end", t("headingEnd", { max: 80 })),
        field("Lead paragraph", t("lead", { multiline: true, max: 400 }), { full: true, help: "Placeholders: {tools} {toolkits} {categories} {live} {browser}" })),
      h("div", { class: "hero-preview-wrap" }, h("small", { class: "help" }, "Preview"), preview)),
    h("div", { class: "panel form-panel" }, h("h3", {}, icon("file", 18), "Footer"), field("About text", t("footer", { multiline: true, max: 600 }), { full: true })),
    h("div", { class: "panel form-panel" }, h("h3", {}, icon("eye", 18), "Theme"),
      h("div", { class: "theme-grid", role: "radiogroup", "aria-label": "Default theme" }, themes.map((th) => h("button", { type: "button", role: "radio", "aria-checked": String((s.theme || "dark") === th), class: `theme-swatch${(s.theme || "dark") === th ? " on" : ""}`, "data-theme": th,
        onclick: () => { s.theme = th; markDirty(); $$(".theme-swatch").forEach((b) => { b.classList.toggle("on", b.dataset.theme === th); b.setAttribute("aria-checked", String(b.dataset.theme === th)); }); } },
        h("span", { class: "sw" }, h("i", { class: "a" }), h("i", { class: "b" }), h("i", { class: "c" })), th))),
      h("small", { class: "help" }, "The default for visitors; they can still switch between light and dark."),
      h("div", { class: "form-grid", style: "margin-top:16px" }, field("Accent colour", colorIn(s, "accent", true)), field("Second accent", colorIn(s, "accent2", true)))));
  drawPreview();
}

// ---------- toolkits ----------
function addKit() {
  const taken = new Set(catalog.tabs.map((t) => t.id));
  catalog.tabs.push({ id: uniqueId("new-toolkit", taken), name: "New toolkit", tagline: "", description: "", icon: "toolbox", accent: "#22d3ee", source: "", sourceUrl: "", visible: true, categories: [{ name: "General", icon: "sparkle", description: "" }], tools: [], _new: true });
  markDirty(); go("kit", catalog.tabs.length - 1, "details"); toast("Toolkit added. Fill in the details, add tools, then Save.");
}
function drawKit(body, k) {
  const i = catalog.tabs.indexOf(k);
  const move = (d) => { const j = i + d; if (j < 0 || j >= catalog.tabs.length) return; [catalog.tabs[i], catalog.tabs[j]] = [catalog.tabs[j], catalog.tabs[i]]; markDirty(); go("kit", j); };
  const del = () => { if (!confirm(`Delete the toolkit "${k.name}" and its ${plural(k.tools.length, "tool")}? You can restore it from a backup after saving.`)) return; catalog.tabs.splice(i, 1); markDirty(); go("overview"); };
  const tabs = [["tools", "list", `Tools (${k.tools.length})`], ["categories", "layers", `Categories (${new Set(k.tools.map((t) => topCat(t.category))).size || (k.categories || []).length})`], ["details", "pen", "Details"]];
  const content = h("div");
  mount(body, head(`Toolkit ${i + 1} of ${catalog.tabs.length}`, k.name || "(unnamed)", k.tagline, [
    h("a", { class: "btn sm", href: `/#/toolkits/${k.id}`, target: "_blank", rel: "noopener" }, icon("external", 15), "View"),
    h("button", { class: "icon-btn sm", type: "button", title: "Move up", "aria-label": "Move toolkit up", disabled: i === 0, onclick: () => move(-1) }, icon("arrowUp", 15)),
    h("button", { class: "icon-btn sm", type: "button", title: "Move down", "aria-label": "Move toolkit down", disabled: i === catalog.tabs.length - 1, onclick: () => move(1) }, icon("arrowDown", 15)),
    h("button", { class: "icon-btn sm danger", type: "button", title: "Delete toolkit", "aria-label": "Delete toolkit", onclick: del }, icon("trash", 15))], k),
    h("div", { class: "kit-tabs admin-tabs", role: "tablist", style: kitStyle(k) }, tabs.map(([id, ic, label]) => h("button", { type: "button", role: "tab", "aria-selected": String(ui.tab === id), class: ui.tab === id ? "on" : "",
      onclick: () => { ui.tab = id; draw(); } }, h("span", { class: "kt-ico" }, icon(ic, 16)), h("span", { class: "kt-name" }, label)))), content);
  if (ui.tab === "categories") drawCategories(content, k); else if (ui.tab === "details") drawDetails(content, k); else drawTools(content, k);
}

function drawDetails(box, k) {
  const idIn = h("input", { type: "text", value: k.id, disabled: !k._new, oninput: (e) => { k.id = slug(e.target.value); markDirty(); } });
  mount(box, h("div", { class: "panel form-panel" }, h("div", { class: "form-grid" },
    field("Name", textIn(k, "name", { max: 80, onchange: () => drawTop() })),
    field("ID (used in links)", idIn, { help: k._new ? "Letters, digits and dashes. Can't be changed after saving." : "Fixed: changing it would break saved links." }),
    field("Tagline", textIn(k, "tagline", { max: 200 }), { full: true, help: "One line shown on cards and in search." }),
    field("Description", textIn(k, "description", { multiline: true, max: 1000 }), { full: true }),
    field("Icon", iconPicker(k)), field("Accent colour", colorIn(k, "accent")),
    field("Source name", textIn(k, "source", { max: 60, placeholder: "e.g. cyberchef" }), { help: "Recipe builder appears for the toolkit whose source is cyberchef." }),
    field("Original instance URL", textIn(k, "sourceUrl", { type: "url", max: 500, placeholder: "https://…" })),
    checkIn(k, "visible", "Visible on the site"))));
}

function catList(k) { // categories in display order, including ones only referenced by tools
  k.categories = Array.isArray(k.categories) ? k.categories : [];
  for (const n of new Set(k.tools.map((t) => topCat(t.category)))) if (!k.categories.some((c) => c.name === n)) k.categories.push({ name: n, icon: "sparkle", description: "" });
  return k.categories;
}
function drawCategories(box, k) {
  const cats = catList(k);
  const count = (c) => k.tools.filter((t) => topCat(t.category) === c.name).length;
  const rename = (c, next) => { next = next.trim().replace(/\s*·\s*/g, " "); if (!next || next === c.name) return; if (cats.some((x) => x !== c && x.name === next)) { toast(`A category named "${next}" already exists`, true); draw(); return; }
    for (const t of k.tools) if (topCat(t.category) === c.name) t.category = [next, subCat(t.category)].filter(Boolean).join(" · ");
    c.name = next; markDirty(); draw(); };
  const rows = cats.map((c, i) => {
    const n = count(c);
    const moveTo = h("select", { class: "sel sm", "aria-label": `Move tools of ${c.name} to`, onchange: (e) => { const to = e.target.value; if (!to) return; for (const t of k.tools) if (topCat(t.category) === c.name) t.category = [to, subCat(t.category)].filter(Boolean).join(" · "); markDirty(); toast(`Moved ${plural(n, "tool")} to ${to}`); draw(); } },
      h("option", { value: "" }, "Move tools to…"), cats.filter((x) => x !== c).map((x) => h("option", { value: x.name }, x.name)));
    return h("div", { class: "cat-row" },
      h("div", { class: "cat-order" }, h("button", { class: "icon-btn sm", type: "button", "aria-label": "Move up", disabled: !i, onclick: () => { [cats[i - 1], cats[i]] = [cats[i], cats[i - 1]]; markDirty(); draw(); } }, icon("arrowUp", 14)),
        h("button", { class: "icon-btn sm", type: "button", "aria-label": "Move down", disabled: i === cats.length - 1, onclick: () => { [cats[i + 1], cats[i]] = [cats[i], cats[i + 1]]; markDirty(); draw(); } }, icon("arrowDown", 14))),
      iconPicker(c),
      h("div", { class: "cat-text" }, h("input", { type: "text", value: c.name, "aria-label": "Category name", maxlength: 120, onchange: (e) => rename(c, e.target.value) }),
        h("input", { type: "text", value: c.description || "", placeholder: "Short description shown on the category card", "aria-label": "Category description", maxlength: 400, oninput: (e) => { c.description = e.target.value; markDirty(); } })),
      h("div", { class: "cat-meta" }, h("button", { class: "btn sm", type: "button", onclick: () => { ui.tab = "tools"; ui.cat = c.name; draw(); } }, plural(n, "tool")), n ? moveTo : null,
        h("button", { class: "icon-btn sm danger", type: "button", "aria-label": `Delete ${c.name}`, title: n ? "Move or delete its tools first" : "Delete category", disabled: n > 0, onclick: () => { cats.splice(i, 1); markDirty(); draw(); } }, icon("trash", 14))));
  });
  const newName = h("input", { type: "text", placeholder: "New category name", "aria-label": "New category name", maxlength: 120 });
  const add = () => { const v = newName.value.trim().replace(/\s*·\s*/g, " "); if (!v) return; if (cats.some((c) => c.name === v)) return toast("That category already exists", true); cats.push({ name: v, icon: "sparkle", description: "" }); markDirty(); draw(); };
  newName.addEventListener("keydown", (e) => { if (e.key === "Enter") add(); });
  mount(box, h("div", { class: "panel form-panel" }, h("p", { class: "help", style: "margin:0 0 6px" }, "Categories group the tools of this toolkit into cards on the home page and toolkit page. Renaming a category updates all of its tools. Empty categories are hidden on the site."),
    rows.length ? rows : h("p", { class: "muted" }, "No categories yet."),
    h("div", { class: "add-row" }, newName, h("button", { class: "btn primary", type: "button", onclick: add }, icon("plus", 16), "Add category"))));
}

function drawTools(box, k) {
  const cats = catList(k);
  const results = h("div"); const count = h("div", { class: "result-count" });
  const render = () => {
    const ql = ui.q.toLowerCase();
    const list = k.tools.filter((t) => (!ui.cat || topCat(t.category) === ui.cat) && (!ql || `${t.name} ${t.id} ${t.description} ${t.native?.op || ""}`.toLowerCase().includes(ql)));
    count.textContent = `${plural(list.length, "tool")}${ui.cat ? ` in ${ui.cat}` : ""}${ui.q ? ` matching “${ui.q}”` : ""}`;
    const shown = list.slice(0, ui.shown);
    mount(results, list.length ? h("div", { class: "admin-table", role: "table", "aria-label": `${k.name} tools` },
      h("div", { class: "at-row at-head", role: "row" }, ["Tool", "Category", "Runs", "Visible", "Featured", ""].map((x) => h("span", { role: "columnheader" }, x))),
      shown.map((t) => h("div", { class: `at-row${t.visible === false ? " is-hidden" : ""}`, role: "row" },
        h("span", { class: "at-tool", role: "cell" }, avatar(t, k), h("span", { style: "min-width:0" }, h("b", {}, t.name), h("small", { class: "mono" }, t.id))),
        h("span", { role: "cell", class: "at-cat" }, t.category),
        h("span", { role: "cell" }, t.native ? h("span", { class: `status ${t.native.mode === "server" ? "st-live" : "st-browser"}`, title: t.native.op }, t.native.mode === "server" ? "Live" : "Browser") : h("span", { class: "status st-link" }, "Link")),
        h("span", { role: "cell" }, h("label", { class: "switch", title: "Visible on the site" }, h("input", { type: "checkbox", checked: t.visible !== false, "aria-label": `Visible: ${t.name}`, onchange: (e) => { t.visible = e.target.checked; markDirty(); e.target.closest(".at-row").classList.toggle("is-hidden", !t.visible); } }), h("i", {}))),
        h("span", { role: "cell" }, h("button", { type: "button", class: `star-btn${t.featured ? " on" : ""}`, "aria-pressed": String(!!t.featured), "aria-label": `Featured: ${t.name}`, onclick: (e) => { t.featured = !t.featured; markDirty(); e.currentTarget.classList.toggle("on", t.featured); e.currentTarget.setAttribute("aria-pressed", String(t.featured)); } }, icon("star", 16))),
        h("span", { role: "cell", class: "at-actions" }, h("button", { class: "btn sm", type: "button", onclick: () => editTool(k, t) }, icon("pen", 14), "Edit"),
          h("button", { class: "icon-btn sm danger", type: "button", "aria-label": `Delete ${t.name}`, onclick: () => { if (confirm(`Delete "${t.name}" from ${k.name}?`)) { k.tools.splice(k.tools.indexOf(t), 1); markDirty(); render(); } } }, icon("trash", 14))))),
      list.length > shown.length ? h("div", { class: "at-more" }, h("button", { class: "btn", type: "button", onclick: () => { ui.shown += 300; render(); } }, `Show more (${list.length - shown.length} left)`)) : null)
      : h("div", { class: "empty" }, icon("search", 36), h("b", {}, k.tools.length ? "No tools match" : "No tools yet"), h("p", {}, k.tools.length ? "Clear the filter or pick another category." : "Add the first tool to this toolkit."),
        h("button", { class: "btn primary", type: "button", onclick: () => editTool(k, null) }, icon("plus", 16), "Add tool")));
  };
  const catSel = h("select", { class: "sel", "aria-label": "Category filter", onchange: (e) => { ui.cat = e.target.value; ui.shown = 200; render(); } }, h("option", { value: "" }, "All categories"), cats.map((c) => h("option", { value: c.name, selected: c.name === ui.cat }, c.name)));
  const q = h("input", { type: "search", value: ui.q, placeholder: `Filter ${k.tools.length} tools…`, "aria-label": "Filter tools" });
  let tmr; q.addEventListener("input", (e) => { clearTimeout(tmr); tmr = setTimeout(() => { ui.q = e.target.value.trim(); ui.shown = 200; render(); }, 120); });
  mount(box, h("div", { class: "toolbar" }, h("label", { class: "filter-input" }, icon("search", 18), q), catSel, h("button", { class: "btn primary", type: "button", onclick: () => editTool(k, null) }, icon("plus", 16), "Add tool")), count, results);
  render();
}

// ---------- tool editor (drawer) ----------
function closeDrawer() { const d = $("#drawer"); if (!d || d.hidden) return; d.hidden = true; document.body.style.overflow = ""; mount($("#drawerPanel")); }
function editTool(kit, tool) {
  const isNew = !tool; let target = kit;
  const t = tool ? structuredClone(tool) : { id: "", name: "", description: "", category: ui.cat || catList(kit)[0]?.name || "General", keywords: [], native: null, external: "", visible: true, featured: false };
  let top = topCat(t.category), sub = subCat(t.category);
  const opts = { client: Object.entries(registry).map(([key, v]) => ({ key, name: v.name || key })).sort((a, b) => a.name.localeCompare(b.name)), server: Object.entries(serverOps).map(([key, name]) => ({ key, name })).sort((a, b) => a.name.localeCompare(b.name)) };
  const presetBox = h("div"); const preview = h("div", { class: "runner" });
  const opSpecs = () => (!t.native ? [] : t.native.mode === "server" ? SERVER_ARGS[t.native.op] || [] : registry[t.native.op]?.args || []);
  const drawPreset = () => {
    const specs = opSpecs(); t.native && (t.native.preset = t.native.preset || {});
    mount(presetBox, !t.native ? h("p", { class: "help" }, "Pick an implementation to set preset options.") : !specs.length ? h("p", { class: "help" }, "This operation has no options.")
      : [h("div", { class: "args" }, specs.map((s) => argField(s, defaults(specs, t.native.preset)[s.name], (v) => { t.native.preset[s.name] = v; }))),
        h("button", { class: "btn sm", type: "button", onclick: () => { t.native.preset = {}; drawPreset(); } }, icon("history", 14), "Reset to defaults")]);
  };
  const opFilter = h("input", { type: "search", placeholder: "Filter operations…", "aria-label": "Filter operations" });
  const opSel = h("select", { class: "sel", size: 8, "aria-label": "Implementation" });
  const opLabel = h("div", { class: "op-current" });
  const showCurrent = () => mount(opLabel, t.native ? [h("span", { class: `status ${t.native.mode === "server" ? "st-live" : "st-browser"}` }, t.native.mode === "server" ? "Live" : "Browser"), h("b", {}, (t.native.mode === "server" ? serverOps[t.native.op] : registry[t.native.op]?.name) || t.native.op), h("code", {}, t.native.op)]
    : h("span", { class: "muted" }, "No implementation: the tool will be a link."));
  const fillOps = () => { const ql = opFilter.value.trim().toLowerCase(); const m = (o) => !ql || `${o.name} ${o.key}`.toLowerCase().includes(ql); const cur = t.native ? `${t.native.mode}:${t.native.op}` : "";
    mount(opSel, h("option", { value: "" }, "— None (link only) —"),
      h("optgroup", { label: "Browser (runs locally)" }, opts.client.filter(m).map((o) => h("option", { value: `client:${o.key}`, selected: cur === `client:${o.key}` }, `${o.name}  ·  ${o.key}`))),
      h("optgroup", { label: "Live (runs on the server)" }, opts.server.filter(m).map((o) => h("option", { value: `server:${o.key}`, selected: cur === `server:${o.key}` }, `${o.name}  ·  ${o.key}`)))); };
  opFilter.addEventListener("input", fillOps);
  opSel.addEventListener("change", () => { const v = opSel.value; if (!v) t.native = null; else { const [mode, op] = v.split(":"); t.native = { op, mode, preset: {} }; if (!t.name.trim()) { t.name = (mode === "server" ? serverOps[op] : registry[op]?.name) || op; nameIn.value = t.name; } } showCurrent(); drawPreset(); });
  const nameIn = h("input", { type: "text", value: t.name, maxlength: 120, oninput: (e) => (t.name = e.target.value) });
  const idIn = h("input", { type: "text", value: t.id, disabled: !isNew, placeholder: "auto from name", oninput: (e) => (t.id = e.target.value) });
  const catSel = (k) => h("select", { class: "sel", onchange: (e) => (top = e.target.value) }, catList(k).map((c) => h("option", { value: c.name, selected: c.name === top }, c.name)));
  let catBox = h("div", {}, catSel(kit));
  const kitSel = h("select", { class: "sel", onchange: (e) => { target = catalog.tabs[+e.target.value]; if (!catList(target).some((c) => c.name === top)) top = catList(target)[0]?.name || "General"; catBox.replaceChildren(catSel(target)); } },
    catalog.tabs.map((k, i) => h("option", { value: i, selected: k === kit }, k.name)));
  const kw = h("input", { type: "text", value: (t.keywords || []).join(", "), placeholder: "comma, separated" });
  const apply = () => {
    if (!t.name.trim()) return toast("Name is required", true);
    t.external = (t.external || "").trim(); if (t.external && !/^https?:\/\//i.test(t.external)) return toast("Link must start with http:// or https://", true);
    if (!t.native && !t.external) return toast("Pick an implementation or add a link", true);
    const taken = new Set(target.tools.filter((x) => x !== tool).map((x) => x.id));
    if (isNew) t.id = t.id.trim() ? slug(t.id) : uniqueId(t.name, taken);
    if (taken.has(t.id)) return toast(`The id "${t.id}" is already used in ${target.name}`, true);
    t.category = [top, sub.trim().replace(/\s*·\s*/g, " ")].filter(Boolean).join(" · ");
    t.keywords = kw.value.split(",").map((x) => x.trim()).filter(Boolean).slice(0, 30);
    if (t.native) { const specs = opSpecs(); const d = defaults(specs); const p = Object.fromEntries(Object.entries(t.native.preset || {}).filter(([n, v]) => specs.some((s) => s.name === n) && String(v) !== String(d[n]))); t.native.preset = Object.keys(p).length ? p : undefined; }
    if (tool) { const idx = kit.tools.indexOf(tool); kit.tools.splice(idx, 1); if (target === kit) kit.tools.splice(idx, 0, t); else target.tools.unshift(t); }
    else target.tools.unshift(t);
    markDirty(); closeDrawer(); draw(); toast(isNew ? `Added "${t.name}" to ${target.name}` : target !== kit ? `Moved "${t.name}" to ${target.name}` : `Updated "${t.name}"`);
  };
  const panel = $("#drawerPanel");
  mount(panel, h("button", { class: "icon-btn drawer-close", type: "button", "data-close": "", "aria-label": "Close" }, icon("close", 18)),
    h("div", { class: "tool-hero", style: kitStyle(kit) }, h("span", { class: "cat-ico" }, icon(isNew ? "plus" : "pen", 24)), h("div", {}, h("span", { class: "kicker" }, kit.name), h("h2", { id: "drawerTitle" }, isNew ? "Add a tool" : `Edit ${tool.name}`))),
    h("div", { class: "form-grid" },
      field("Name", nameIn), field("ID (used in links)", idIn, { help: isNew ? "Leave blank to generate from the name." : "Fixed after creation." }),
      field("Description", h("textarea", { rows: 3, maxlength: 2000, oninput: (e) => (t.description = e.target.value) }, t.description || ""), { full: true }),
      field("Toolkit", kitSel), field("Category", catBox),
      field("Sub-category (optional)", h("input", { type: "text", value: sub, maxlength: 60, placeholder: "e.g. Record Generators", oninput: (e) => (sub = e.target.value) })),
      field("Keywords", kw, { help: "Help search find this tool." })),
    h("div", { class: "rpanel" }, h("div", { class: "rhead" }, h("span", { class: "rtitle" }, icon("cpu", 15), "Implementation")), opLabel, h("label", { class: "filter-input" }, icon("search", 18), opFilter), opSel,
      h("div", { class: "rhead" }, h("span", { class: "rtitle" }, icon("settings", 15), "Preset options")), presetBox),
    h("div", { class: "form-grid" }, field("Link (optional)", h("input", { type: "url", value: t.external || "", placeholder: "https://… (the original tool, or the only target if there's no implementation)", oninput: (e) => (t.external = e.target.value) }), { full: true }),
      h("label", { class: "field check" }, h("input", { type: "checkbox", checked: t.visible !== false, onchange: (e) => (t.visible = e.target.checked) }), h("span", {}, "Visible on the site")),
      h("label", { class: "field check" }, h("input", { type: "checkbox", checked: !!t.featured, onchange: (e) => (t.featured = e.target.checked) }), h("span", {}, "Featured on the home page"))),
    h("div", { class: "actions" }, h("button", { class: "btn primary", type: "button", onclick: apply }, icon("check", 16), isNew ? "Add tool" : "Apply"),
      h("button", { class: "btn", type: "button", onclick: () => { t.category = [top, sub].filter(Boolean).join(" · "); renderRunner(preview, structuredClone(t)); preview.scrollIntoView({ behavior: "smooth", block: "nearest" }); } }, icon("play", 16), "Preview"),
      h("button", { class: "btn", type: "button", onclick: closeDrawer }, "Cancel"), h("span", { class: "spacer" }), h("small", { class: "help" }, "Changes go live when you press Save.")),
    preview);
  fillOps(); showCurrent(); drawPreset();
  $("#drawer").hidden = false; document.body.style.overflow = "hidden"; panel.scrollTop = 0; nameIn.focus();
}

// ---------- backups ----------
async function drawBackups(body) {
  const list = h("div", { class: "backup-list" }, h("p", { class: "muted" }, "Loading backups…"));
  const fileIn = h("input", { type: "file", accept: "application/json,.json", hidden: true, onchange: async (e) => {
    const f = e.target.files[0]; if (!f) return;
    try { const c = JSON.parse(await f.text()); if (!Array.isArray(c.tabs)) throw new Error("Not a catalog: no tabs array"); catalog = { ...catalog, ...c, seedGeneratedAt: catalog.seedGeneratedAt, seedIds: catalog.seedIds, seedNative: catalog.seedNative }; markDirty(); toast("Imported. Review it, then press Save."); go("overview"); }
    catch (x) { toast(`Import failed: ${x.message}`, true); } } });
  const exportJson = () => { const url = URL.createObjectURL(new Blob([JSON.stringify(catalog, null, 1)], { type: "application/json" })); const a = h("a", { href: url, download: `infosec-tools-catalog-${new Date().toISOString().slice(0, 10)}.json` }); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 2000); };
  mount(body, head("Maintenance", "Backups & import", "Every save keeps a backup (the latest 50). Restoring or resetting also takes a backup first."),
    h("div", { class: "split two" },
      h("div", { class: "panel" }, h("h3", {}, icon("download", 18), "Export & import"), h("p", { class: "muted" }, "Download the whole catalog as JSON, or load one back in. An import only takes effect when you press Save."),
        h("div", { class: "actions" }, h("button", { class: "btn", type: "button", onclick: exportJson }, icon("download", 16), "Export JSON"), h("button", { class: "btn", type: "button", onclick: () => fileIn.click() }, icon("upload", 16), "Import JSON"), fileIn)),
      h("div", { class: "panel" }, h("h3", {}, icon("history", 18), "Reset"), h("p", { class: "muted" }, "Replace everything with the catalog this release shipped with: 4 toolkits and 700 tools. Your current catalog is backed up first."),
        h("div", { class: "actions" }, h("button", { class: "btn danger", type: "button", onclick: async () => { if (!confirm("Reset the catalog to the shipped seed? Your current catalog is backed up first.")) return; try { await api("/api/admin/reset", { method: "POST" }); catalog = await api("/api/admin/catalog"); dirty = false; toast("Reset to the seed catalog"); go("overview"); } catch (x) { toast(x.message, true); } } }, icon("history", 16), "Reset to seed")))),
    h("div", { class: "panel", style: "margin-top:16px" }, h("h3", {}, icon("archive", 18), "Backups"), list));
  try {
    const files = await api("/api/admin/backups");
    mount(list, files.length ? files.map((f) => { const m = f.match(/^catalog-(\d{4}-\d\d-\d\d)T(\d\d)-(\d\d)-(\d\d)/); const when = m ? `${m[1]} ${m[2]}:${m[3]}:${m[4]} UTC` : f; const tag = f.match(/-(pre-[\w-]+)\.json$/)?.[1];
      return h("div", { class: "backup-row" }, icon("file", 16), h("span", { class: "mono" }, when), tag ? h("span", { class: "tag" }, tag.replace(/-/g, " ")) : null, h("span", { class: "spacer" }),
        h("button", { class: "btn sm", type: "button", onclick: async () => { if (dirty && !confirm("Discard unsaved changes?")) return; if (!confirm(`Restore the backup from ${when}?`)) return;
          try { await api("/api/admin/restore", { method: "POST", body: JSON.stringify({ file: f }) }); catalog = await api("/api/admin/catalog"); dirty = false; toast("Backup restored"); go("overview"); } catch (x) { toast(x.message, true); } } }, icon("history", 14), "Restore")); })
      : h("p", { class: "muted" }, "No backups yet. One is written every time you save."));
  } catch (e) { mount(list, h("p", { class: "form-error" }, e.message)); }
}

boot().catch((e) => mount(main, h("div", { class: "wrap" }, h("div", { class: "empty", style: "margin:60px 0" }, h("b", {}, "Could not load the admin panel"), h("p", {}, e.message)))));
