import { h, $, toast, initTheme, mount } from "./dom.js";
import { registry } from "./ops/index.js";

const view = $("#view");
let catalog = null, serverOps = {}, dirty = false, tabIdx = 0, filter = "";
const api = async (path, opts = {}) => {
  const r = await fetch(path, { ...opts, headers: { "Content-Type": "application/json", "X-Requested-With": "infosec-tools", ...(opts.headers || {}) } });
  const j = await r.json().catch(() => ({})); if (!r.ok) throw new Error(j.error || `HTTP ${r.status}`); return j;
};
const markDirty = () => { dirty = true; $("#save-state") && ($("#save-state").textContent = "Unsaved changes"); };
addEventListener("beforeunload", (e) => { if (dirty) { e.preventDefault(); e.returnValue = ""; } });
const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "").slice(0, 60) || "item";

async function boot() {
  initTheme($("#theme-toggle"));
  const st = await api("/api/admin/status");
  if (!st.enabled) return mount(view, h("div", { class: "notice" }, h("h1", {}, "Admin is disabled"), h("p", {}, "Set the ADMIN_PASSWORD environment variable on the server and restart it.")));
  if (!st.authenticated) return login();
  [catalog, serverOps] = await Promise.all([api("/api/admin/catalog"), api("/api/admin/server-ops")]);
  draw();
}

function login() {
  const pw = h("input", { type: "password", autocomplete: "current-password", placeholder: "Admin password", "aria-label": "Admin password" });
  const err = h("p", { class: "small", style: "color:var(--danger);min-height:1.5em" });
  const go = async (e) => { e.preventDefault(); err.textContent = ""; try { await api("/api/admin/login", { method: "POST", body: JSON.stringify({ password: pw.value }) }); boot(); } catch (x) { err.textContent = x.message; } };
  mount(view, h("form", { class: "panel", style: "max-width:380px;margin:60px auto", onsubmit: go }, h("h1", {}, "Sign in"), h("p", { class: "muted" }, "Manage tabs and tools of Infosec Tools."), pw, err, h("button", { class: "btn primary", type: "submit" }, "Sign in")));
  pw.focus();
}

async function save() {
  try { const r = await api("/api/admin/catalog", { method: "PUT", body: JSON.stringify(catalog) }); catalog.updatedAt = r.updatedAt; dirty = false; toast("Saved — the live site is updated"); draw(); }
  catch (e) { toast(e.message, true); }
}

function field(label, input, cls = "") { return h("div", { class: "field " + cls }, h("label", {}, label), input); }
function text(obj, key, attrs = {}) { return h(attrs.multiline ? "textarea" : "input", { type: "text", value: obj[key] ?? "", rows: attrs.multiline ? 3 : undefined, style: attrs.multiline ? "min-height:70px;font-family:inherit" : undefined, oninput: (e) => { obj[key] = e.target.value; markDirty(); }, ...attrs.extra }, attrs.multiline ? obj[key] ?? "" : null); }

function opPicker(tool) {
  const clientOps = Object.entries(registry).map(([k, v]) => [k, v.name]).sort((a, b) => a[1].localeCompare(b[1]));
  const cur = tool.native ? `${tool.native.mode}:${tool.native.op}` : "";
  const sel = h("select", { onchange: (e) => { const v = e.target.value; if (!v) tool.native = null; else { const [mode, op] = v.split(":"); tool.native = { op, mode }; } markDirty(); } },
    h("option", { value: "" }, "— None: link to the original —"),
    h("optgroup", { label: "Native (runs in browser)" }, clientOps.map(([k, n]) => h("option", { value: `client:${k}`, selected: cur === `client:${k}` }, `${n}  (${k})`))),
    h("optgroup", { label: "Live (runs on server)" }, Object.entries(serverOps).map(([k, n]) => h("option", { value: `server:${k}`, selected: cur === `server:${k}` }, `${n}  (${k})`))));
  return sel;
}

function editTool(tab, tool, isNew = false) {
  const t = structuredClone(tool); const back = h("div", { class: "modal-back", onclick: (e) => { if (e.target === back) back.remove(); } });
  const presetInput = h("input", { type: "text", value: t.native?.preset ? new URLSearchParams(t.native.preset).toString() : "", placeholder: "e.g. case=UPPERCASE" });
  const kw = h("input", { type: "text", value: (t.keywords || []).join(", ") });
  const commit = () => {
    if (!t.name.trim()) return toast("Name is required", true);
    if (isNew) { t.id = slug(t.id || t.name); if (tab.tools.some((x) => x.id === t.id)) return toast("A tool with that id already exists in this tab", true); }
    if (t.external && !/^https?:\/\//i.test(t.external)) return toast("Link must start with http:// or https://", true);
    t.keywords = kw.value.split(",").map((x) => x.trim()).filter(Boolean);
    if (t.native) { const p = presetInput.value.trim(); t.native.preset = p ? Object.fromEntries(new URLSearchParams(p)) : undefined; }
    if (isNew) tab.tools.unshift(t); else Object.assign(tool, t);
    markDirty(); back.remove(); draw();
  };
  const cats = [...new Set(tab.tools.map((x) => x.category))];
  const catInput = h("input", { type: "text", value: t.category || "", list: "cat-list", oninput: (e) => { t.category = e.target.value; } });
  back.append(h("div", { class: "modal", role: "dialog", "aria-label": isNew ? "Add tool" : "Edit tool" },
    h("h2", { style: "margin-top:0" }, isNew ? `Add a tool to ${tab.name}` : `Edit: ${tool.name}`),
    h("div", { class: "form-grid" },
      field("Name", h("input", { type: "text", value: t.name, oninput: (e) => (t.name = e.target.value) })),
      isNew ? field("ID (URL slug, optional)", h("input", { type: "text", value: t.id || "", placeholder: "auto from name", oninput: (e) => (t.id = e.target.value) })) : field("ID", h("input", { type: "text", value: t.id, disabled: true })),
      field("Description", h("textarea", { rows: 3, style: "min-height:70px;font-family:inherit", oninput: (e) => (t.description = e.target.value) }, t.description || ""), "full"),
      field("Category", h("div", {}, catInput, h("datalist", { id: "cat-list" }, cats.map((c) => h("option", { value: c }))))),
      field("Keywords (comma separated)", kw),
      field("Native implementation", opPicker(t), "full"),
      field("Preset arguments for the native op (query-string form)", presetInput, "full"),
      field("Link to original / external tool", h("input", { type: "text", value: t.external || "", placeholder: "https://…", oninput: (e) => (t.external = e.target.value) }), "full"),
      h("div", { class: "field checkbox" }, h("input", { type: "checkbox", id: "f-vis", checked: t.visible !== false, onchange: (e) => (t.visible = e.target.checked) }), h("label", { for: "f-vis" }, "Visible on the site")),
      h("div", { class: "field checkbox" }, h("input", { type: "checkbox", id: "f-feat", checked: !!t.featured, onchange: (e) => (t.featured = e.target.checked) }), h("label", { for: "f-feat" }, "Featured on the landing page"))),
    h("div", { class: "row", style: "margin-top:18px" }, h("button", { class: "btn primary", type: "button", onclick: commit }, isNew ? "Add tool" : "Apply"), h("button", { class: "btn", type: "button", onclick: () => back.remove() }, "Cancel"),
      h("span", { class: "spacer" }), h("span", { class: "small muted" }, "Changes go live when you press Save."))));
  document.body.append(back);
}

function editTab(tab, isNew = false) {
  const t = structuredClone(tab); const back = h("div", { class: "modal-back", onclick: (e) => { if (e.target === back) back.remove(); } });
  const commit = () => { if (!t.name.trim()) return toast("Name is required", true);
    if (isNew) { t.id = slug(t.name); if (catalog.tabs.some((x) => x.id === t.id)) return toast("A tab with that name already exists", true); catalog.tabs.push(t); tabIdx = catalog.tabs.length - 1; } else Object.assign(tab, t);
    markDirty(); back.remove(); draw(); };
  back.append(h("div", { class: "modal" }, h("h2", { style: "margin-top:0" }, isNew ? "New tab" : `Edit tab: ${tab.name}`),
    h("div", { class: "form-grid" },
      field("Tab name", h("input", { type: "text", value: t.name, oninput: (e) => (t.name = e.target.value) })),
      field("Icon", h("select", { onchange: (e) => (t.icon = e.target.value) }, ["wrench", "flask", "radar", "network"].map((i) => h("option", { value: i, selected: t.icon === i }, i)))),
      field("Description", h("textarea", { rows: 3, style: "min-height:70px;font-family:inherit", oninput: (e) => (t.description = e.target.value) }, t.description || ""), "full"),
      field("Original instance URL", h("input", { type: "text", value: t.sourceUrl || "", placeholder: "https://…", oninput: (e) => (t.sourceUrl = e.target.value) }), "full"),
      h("div", { class: "field checkbox" }, h("input", { type: "checkbox", id: "t-vis", checked: t.visible !== false, onchange: (e) => (t.visible = e.target.checked) }), h("label", { for: "t-vis" }, "Visible on the site"))),
    h("div", { class: "row", style: "margin-top:18px" }, h("button", { class: "btn primary", type: "button", onclick: commit }, isNew ? "Create tab" : "Apply"), h("button", { class: "btn", type: "button", onclick: () => back.remove() }, "Cancel"))));
  document.body.append(back);
}

async function backups() {
  const list = await api("/api/admin/backups"); const back = h("div", { class: "modal-back", onclick: (e) => { if (e.target === back) back.remove(); } });
  back.append(h("div", { class: "modal" }, h("h2", { style: "margin-top:0" }, "Backups"), h("p", { class: "muted small" }, "A backup is taken automatically before every save (latest 50 kept)."),
    list.length ? h("table", {}, h("tbody", {}, list.map((f) => h("tr", {}, h("td", { class: "mono small" }, f), h("td", {}, h("button", { class: "btn", type: "button", onclick: async () => { if (!confirm(`Restore ${f}? Current catalog is backed up first.`)) return; await api("/api/admin/restore", { method: "POST", body: JSON.stringify({ file: f }) }); toast("Restored"); back.remove(); boot(); } }, "Restore")))))) : h("p", {}, "No backups yet."),
    h("div", { class: "row", style: "margin-top:16px" }, h("button", { class: "btn danger", type: "button", onclick: async () => { if (!confirm("Reset the catalog to the original REA-built seed? Current catalog is backed up first.")) return; await api("/api/admin/reset", { method: "POST", body: "{}" }); toast("Reset to seed"); back.remove(); boot(); } }, "Reset to original seed"),
      h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", onclick: () => back.remove() }, "Close"))));
  document.body.append(back);
}

function exportJson() { const a = h("a", { href: URL.createObjectURL(new Blob([JSON.stringify(catalog, null, 1)], { type: "application/json" })), download: `infosec-tools-catalog-${new Date().toISOString().slice(0, 10)}.json` }); a.click(); URL.revokeObjectURL(a.href); }
function importJson() { const inp = h("input", { type: "file", accept: "application/json,.json", onchange: async () => { try { const c = JSON.parse(await inp.files[0].text()); if (!Array.isArray(c.tabs)) throw new Error("File has no tabs array"); catalog = c; tabIdx = 0; markDirty(); draw(); toast("Imported — review and Save to publish"); } catch (e) { toast(`Import failed: ${e.message}`, true); } } }); inp.click(); }

function draw() {
  const tab = catalog.tabs[tabIdx] || catalog.tabs[0]; const all = catalog.tabs.reduce((n, t) => n + t.tools.length, 0);
  const ql = filter.toLowerCase();
  const rows = tab ? tab.tools.filter((t) => !ql || `${t.name} ${t.id} ${t.category}`.toLowerCase().includes(ql)) : [];
  mount(view, 
    h("section", { class: "banner" }, h("div", { style: "flex:1;min-width:260px" }, h("h1", {}, "Catalog editor"), h("p", { class: "lead" }, `${catalog.tabs.length} tabs · ${all} tools · last saved ${catalog.updatedAt ? new Date(catalog.updatedAt).toLocaleString() : "never"}`)),
      h("div", { class: "row" }, h("span", { id: "save-state", class: "small muted" }, dirty ? "Unsaved changes" : "All changes saved"), h("button", { class: "btn primary", type: "button", onclick: save }, "Save & publish"),
        h("button", { class: "btn", type: "button", onclick: backups }, "Backups"), h("button", { class: "btn", type: "button", onclick: exportJson }, "Export"), h("button", { class: "btn", type: "button", onclick: importJson }, "Import"),
        h("button", { class: "btn", type: "button", onclick: async () => { await api("/api/admin/logout", { method: "POST", body: "{}" }); location.reload(); } }, "Sign out"))),
    h("div", { class: "panel", style: "margin-bottom:16px" }, h("div", { class: "form-grid" },
      field("Site title", text(catalog, "title")), field("Landing page tagline (blank = default)", text(catalog, "tagline")))),
    h("nav", { class: "tabs", style: "border-radius:10px;margin-bottom:12px" }, catalog.tabs.map((t, i) => h("a", { href: "#", class: i === tabIdx ? "active" : "", onclick: (e) => { e.preventDefault(); tabIdx = i; draw(); } }, t.name, t.visible === false ? " (hidden)" : "", h("span", { class: "count" }, t.tools.length))),
      h("a", { href: "#", onclick: (e) => { e.preventDefault(); editTab({ id: "", name: "", description: "", icon: "wrench", source: "custom", sourceUrl: "", visible: true, tools: [] }, true); } }, "+ New tab")),
    tab ? h("div", { class: "panel" },
      h("div", { class: "toolbar" }, h("strong", {}, tab.name), h("button", { class: "btn", type: "button", onclick: () => editTab(tab) }, "Edit tab"),
        h("button", { class: "btn", type: "button", disabled: tabIdx === 0, onclick: () => { [catalog.tabs[tabIdx - 1], catalog.tabs[tabIdx]] = [catalog.tabs[tabIdx], catalog.tabs[tabIdx - 1]]; tabIdx--; markDirty(); draw(); } }, "← Move"),
        h("button", { class: "btn", type: "button", disabled: tabIdx === catalog.tabs.length - 1, onclick: () => { [catalog.tabs[tabIdx + 1], catalog.tabs[tabIdx]] = [catalog.tabs[tabIdx], catalog.tabs[tabIdx + 1]]; tabIdx++; markDirty(); draw(); } }, "Move →"),
        h("button", { class: "btn danger", type: "button", onclick: () => { if (confirm(`Delete the tab "${tab.name}" and its ${tab.tools.length} tools?`)) { catalog.tabs.splice(tabIdx, 1); tabIdx = 0; markDirty(); draw(); } } }, "Delete tab"),
        h("span", { class: "spacer" }), h("input", { type: "search", placeholder: "Filter tools…", value: filter, oninput: (e) => { filter = e.target.value; draw(); $("#tool-filter")?.focus(); }, id: "tool-filter" }),
        h("button", { class: "btn primary", type: "button", onclick: () => editTool(tab, { id: "", name: "", description: "", category: "General", keywords: [], native: null, external: "", visible: true }, true) }, "+ Add tool")),
      h("div", { style: "overflow-x:auto" }, h("table", {}, h("thead", {}, h("tr", {}, ["Tool", "Category", "Implementation", "Visible", ""].map((x) => h("th", {}, x)))),
        h("tbody", {}, rows.slice(0, 600).map((t) => h("tr", {},
          h("td", {}, h("strong", {}, t.name), h("div", { class: "small muted mono" }, t.id)),
          h("td", { class: "small" }, t.category),
          h("td", { class: "small" }, t.native ? h("span", { class: `badge ${t.native.mode === "server" ? "server" : "native"}` }, `${t.native.mode === "server" ? "LIVE" : "NATIVE"} · ${t.native.op}`) : h("span", { class: "badge external" }, "LINK")),
          h("td", {}, h("input", { type: "checkbox", checked: t.visible !== false, "aria-label": `Visible: ${t.name}`, onchange: (e) => { t.visible = e.target.checked; markDirty(); } })),
          h("td", { style: "white-space:nowrap" }, h("button", { class: "btn", type: "button", onclick: () => editTool(tab, t) }, "Edit"), " ",
            h("button", { class: "btn danger", type: "button", onclick: () => { if (confirm(`Remove "${t.name}"?`)) { tab.tools.splice(tab.tools.indexOf(t), 1); markDirty(); draw(); } } }, "✕"))))))),
      rows.length > 600 ? h("p", { class: "small muted" }, `Showing 600 of ${rows.length} — use the filter.`) : null) : h("p", {}, "No tabs. Create one."),
  );
}
boot().catch((e) => mount(view, h("div", { class: "notice" }, `Could not load admin: ${e.message}`)));
