import { h, $, toast, debounce, store, initTheme, mount } from "./dom.js";
import { registry } from "./ops/index.js";
import { renderLanding, icon, heroMeter } from "./landing.js";

// Arguments for server-side checks (the server ops take a target plus these).
const SERVER_ARGS = {
  "dns-lookup": [{ name: "type", label: "Record type", type: "select", options: ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR", "NAPTR"] }],
  "dns-propagation": [{ name: "type", label: "Record type", type: "select", options: ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] }],
  "dkim-check": [{ name: "selector", label: "Selector (blank = try common ones)", type: "text" }],
  "port-check": [{ name: "port", label: "Port", type: "number", default: 443 }],
};
const TARGET_HINT = { "reverse-dns": "IP address, e.g. 8.8.8.8", "ip-whois": "IP address or hostname", "asn-lookup": "AS number, e.g. AS13335", blocklists: "IPv4 address or hostname" };

let catalog = { tabs: [] };
const view = $("#view");
const visibleTools = (tab) => tab.tools;
const allTools = () => catalog.tabs.flatMap((t) => t.tools.map((x) => ({ ...x, tab: t })));

function badge(tool) {
  if (!tool.native) return h("span", { class: "badge external", title: "Not rebuilt yet — opens your existing instance" }, "LINK");
  return tool.native.mode === "server" ? h("span", { class: "badge server", title: "Runs on the Infosec Tools server" }, "LIVE") : h("span", { class: "badge native", title: "Runs natively in your browser" }, "NATIVE");
}
const toolHref = (tab, tool) => `#/${tab.id}/${encodeURIComponent(tool.id)}`;
function card(tab, tool, showTab = false) {
  return h("a", { class: `card k-${tool.native ? (tool.native.mode === "server" ? "live" : "native") : "link"}`, href: toolHref(tab, tool) },
    h("div", { class: "title" }, h("span", {}, tool.name), badge(tool)),
    h("div", { class: "desc" }, tool.description || ""),
    h("div", { class: "meta" }, showTab ? `${tab.name} · ${tool.category}` : tool.category));
}

function renderTabs(activeId) {
  const nav = $("#tabs"); nav.replaceChildren(
    h("a", { href: "#/", class: activeId ? "" : "active" }, "Overview"),
    ...catalog.tabs.map((t) => h("a", { href: `#/${t.id}`, class: t.id === activeId ? "active" : "" }, t.name, h("span", { class: "count" }, t.tools.length))));
}

function renderHome() {
  renderTabs(null);
  renderLanding(view, catalog, allTools, card);
}

function renderTab(tab, state = {}) {
  renderTabs(tab.id);
  const cats = [...new Map(visibleTools(tab).map((t) => [t.category, 0])).keys()];
  let cat = state.cat || "All", q = "", onlyNative = store.get("onlyNative", false);
  const grid = h("div", { class: "grid" }); const chips = h("div", { class: "chips" });
  const draw = () => {
    const ql = q.toLowerCase();
    const list = visibleTools(tab).filter((t) => (cat === "All" || t.category === cat) && (!onlyNative || t.native) && (!ql || `${t.name} ${t.description} ${t.keywords.join(" ")}`.toLowerCase().includes(ql)));
    mount(chips, ...["All", ...cats].map((c) => h("button", { class: "chip" + (c === cat ? " active" : ""), type: "button", onclick: () => { cat = c; draw(); } }, c, h("span", { class: "n" }, c === "All" ? tab.tools.length : tab.tools.filter((t) => t.category === c).length))));
    mount(grid, ...(list.length ? list.map((t) => card(tab, t)) : [h("div", { class: "empty" }, "No tools match.")]));
  };
  const nNative = tab.tools.filter((t) => t.native).length;
  mount(view, 
    h("section", { class: "banner", style: "flex-direction:column;align-items:stretch" },
      h("div", { class: "row", style: "gap:18px;align-items:center" }, h("span", { class: "spot-icon" }, icon(tab.icon)),
        h("div", { style: "flex:1;min-width:240px" }, h("h1", {}, tab.name), h("p", { class: "lead" }, tab.description)),
        h("div", { class: "banner-stats" }, h("div", { class: "stat" }, h("b", {}, tab.tools.length), h("span", {}, "tools")), h("div", { class: "stat" }, h("b", {}, nNative), h("span", {}, "run here")), h("div", { class: "stat" }, h("b", {}, cats.length), h("span", {}, "categories")))),
      heroMeter(tab.tools)),
    h("div", { class: "toolbar" },
      h("input", { type: "search", placeholder: `Filter ${tab.name}…`, oninput: (e) => { q = e.target.value; draw(); } }),
      h("label", { class: "row small" }, h("input", { type: "checkbox", checked: onlyNative, onchange: (e) => { onlyNative = e.target.checked; store.set("onlyNative", onlyNative); draw(); } }), "Native only"),
      tab.id === "cipher-lab" ? h("a", { class: "btn primary", href: "#/cipher-lab/~recipe" }, "Recipe builder") : null,
      h("span", { class: "spacer" }), tab.sourceUrl ? h("a", { class: "btn", href: tab.sourceUrl, target: "_blank", rel: "noopener" }, "Original instance ↗") : null),
    chips, grid);
  draw();
}

function argField(spec, value, onchange) {
  const id = "arg-" + spec.name + "-" + Math.random().toString(36).slice(2, 7);
  if (spec.type === "checkbox") return h("div", { class: "field checkbox" }, h("input", { id, type: "checkbox", checked: value, onchange: (e) => onchange(e.target.checked) }), h("label", { for: id }, spec.label));
  let input;
  if (spec.type === "select") input = h("select", { id, onchange: (e) => onchange(e.target.value) }, spec.options.map((o) => h("option", { value: o, selected: String(o) === String(value) }, o)));
  else if (spec.type === "textarea") input = h("textarea", { id, rows: 4, oninput: (e) => onchange(e.target.value) }, value ?? "");
  else input = h("input", { id, type: spec.type === "number" ? "number" : "text", value: value ?? "", oninput: (e) => onchange(e.target.value) });
  return h("div", { class: "field" }, h("label", { for: id }, spec.label), input);
}
const defaults = (specs, preset = {}) => Object.fromEntries((specs || []).map((s) => [s.name, preset[s.name] ?? s.default ?? (s.type === "checkbox" ? false : s.type === "select" ? s.options[0] : "")]));

async function runClient(op, input, args) { return String(await op.run(input, args)); }
async function runServer(opKey, target, args) {
  const r = await fetch(`/api/run/${opKey}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target, args }) });
  const j = await r.json().catch(() => ({ ok: false, error: `HTTP ${r.status}` }));
  if (!j.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return { text: j.text, data: j.data, ms: j.ms };
}

function renderTool(tab, tool) {
  renderTabs(tab.id);
  const recent = store.get("recent", []).filter((r) => !(r.tab === tab.id && r.id === tool.id)); recent.unshift({ tab: tab.id, id: tool.id }); store.set("recent", recent.slice(0, 8));
  const header = [h("div", { class: "crumbs" }, h("a", { href: "#/" }, "Home"), " / ", h("a", { href: `#/${tab.id}` }, tab.name), " / ", tool.category),
    h("section", { class: "banner" }, h("span", { class: "spot-icon" }, icon(tab.icon)),
      h("div", { style: "flex:1;min-width:240px" }, h("div", { class: "row" }, h("h1", {}, tool.name), badge(tool)), h("p", { class: "lead" }, tool.description || `${tool.category} tool`)))];
  const extLink = tool.external ? h("a", { class: "btn", href: tool.external, target: "_blank", rel: "noopener" }, "Open original ↗") : null;

  if (!tool.native) {
    mount(view, ...header, h("div", { class: "notice" },
      h("p", {}, "This tool hasn't been rebuilt natively in Infosec Tools yet — it's scheduled for a later phase."),
      h("p", { class: "muted small" }, "Until then, use it on your existing self-hosted instance:"), h("div", { class: "row" }, extLink)));
    return;
  }
  const out = h("pre", { class: "output", "aria-live": "polite" }); const status = h("span", { class: "small muted" });
  const copyBtn = h("button", { class: "btn", type: "button", onclick: () => navigator.clipboard.writeText(out.textContent).then(() => toast("Copied")) }, "Copy");
  const show = (text, err = false) => { out.textContent = text; out.classList.toggle("error", err); };

  if (tool.native.mode === "server") {
    const specs = SERVER_ARGS[tool.native.op] || []; const args = defaults(specs, tool.native.preset);
    const target = h("input", { type: "text", placeholder: TARGET_HINT[tool.native.op] || "Domain or URL, e.g. example.com", value: store.get("lastTarget", ""), "aria-label": "Target" });
    let data = null;
    const go = async () => { if (!target.value.trim()) return show("Enter a target first.", true); store.set("lastTarget", target.value.trim()); runBtn.disabled = true; status.textContent = "Running…"; show("");
      try { const r = await runServer(tool.native.op, target.value.trim(), args); data = r.data; show(r.text || "(no output)"); status.textContent = `Done in ${r.ms} ms`; } catch (e) { show(e.message, true); status.textContent = ""; } finally { runBtn.disabled = false; } };
    const runBtn = h("button", { class: "btn primary", type: "button", onclick: go }, "Run check");
    target.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
    mount(view, ...header,
      h("div", { class: "panel" }, h("label", {}, "Target"), h("div", { class: "row" }, h("div", { style: "flex:1;min-width:220px" }, target), runBtn),
        specs.length ? h("div", { class: "args", style: "margin-top:12px" }, specs.map((s) => argField(s, args[s.name], (v) => (args[s.name] = v)))) : null),
      h("div", { class: "panel", style: "margin-top:16px" }, h("div", { class: "row", style: "margin-bottom:8px" }, h("label", { style: "margin:0" }, "Result"), status, h("span", { class: "spacer" }), copyBtn,
        h("button", { class: "btn", type: "button", onclick: () => data && navigator.clipboard.writeText(JSON.stringify(data, null, 2)).then(() => toast("JSON copied")) }, "Copy JSON"), extLink), out));
    return;
  }

  const op = registry[tool.native.op];
  if (!op) { mount(view, ...header, h("div", { class: "notice" }, `Native op "${tool.native.op}" is missing from this build.`, extLink)); return; }
  const args = defaults(op.args, tool.native.preset);
  const needsInput = op.input !== false;
  const input = h("textarea", { rows: 10, placeholder: op.placeholder || "Input", spellcheck: "false", "aria-label": "Input" });
  const run = async () => { try { status.textContent = ""; const t0 = performance.now(); show(await runClient(op, input.value, args)); status.textContent = `${(performance.now() - t0).toFixed(1)} ms`; } catch (e) { show(e.message || String(e), true); } };
  const auto = debounce(run, 180); input.addEventListener("input", auto);
  const argPanel = op.args?.length ? h("div", { class: "args" }, op.args.map((s) => argField(s, args[s.name], (v) => { args[s.name] = v; auto(); }))) : null;
  mount(view, ...header,
    argPanel ? h("div", { class: "panel" }, h("label", {}, "Options"), argPanel) : null,
    h("div", { class: needsInput ? "tool-layout" : "" },
      needsInput ? h("div", { class: "panel" }, h("div", { class: "row", style: "margin-bottom:8px" }, h("label", { style: "margin:0" }, "Input"), h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", onclick: () => { input.value = ""; run(); } }, "Clear")), input) : null,
      h("div", { class: "panel", style: needsInput ? "" : "margin-top:16px" }, h("div", { class: "row", style: "margin-bottom:8px" }, h("label", { style: "margin:0" }, "Output"), status, h("span", { class: "spacer" }),
        h("button", { class: "btn" + (needsInput ? "" : " primary"), type: "button", onclick: run }, needsInput ? "Run" : "Generate"), copyBtn, extLink), out)));
  run();
}

// CyberChef-style recipe: chain native client ops, output of one feeds the next.
function renderRecipe(tab) {
  renderTabs(tab.id);
  const ops = tab.tools.filter((t) => t.native?.mode === "client" && registry[t.native.op]?.input !== false);
  let steps = store.get("recipe", []).filter((s) => registry[s.op]);
  const input = h("textarea", { rows: 10, placeholder: "Input", spellcheck: "false" }); input.value = store.get("recipeInput", "");
  const out = h("pre", { class: "output" }); const list = h("div");
  const picker = h("select", {}, h("option", { value: "" }, "Add an operation…"), ops.map((t) => h("option", { value: `${t.native.op}|${JSON.stringify(t.native.preset || {})}|${t.name}` }, t.name)));
  const run = debounce(async () => { store.set("recipe", steps); store.set("recipeInput", input.value); let v = input.value;
    try { for (const s of steps) v = String(await registry[s.op].run(v, s.args)); out.textContent = v; out.classList.remove("error"); } catch (e) { out.textContent = e.message; out.classList.add("error"); } }, 150);
  const draw = () => { mount(list, ...(steps.length ? steps.map((s, i) => h("div", { class: "recipe-step" },
    h("div", {}, h("strong", {}, `${i + 1}. ${s.name}`), registry[s.op].args?.length ? h("div", { class: "args" }, registry[s.op].args.map((a) => argField(a, s.args[a.name], (v) => { s.args[a.name] = v; run(); }))) : null),
    h("div", { class: "row" }, h("button", { class: "btn", type: "button", title: "Move up", onclick: () => { if (i) { [steps[i - 1], steps[i]] = [steps[i], steps[i - 1]]; draw(); run(); } } }, "↑"),
      h("button", { class: "btn danger", type: "button", title: "Remove", onclick: () => { steps.splice(i, 1); draw(); run(); } }, "✕")))) : [h("p", { class: "muted" }, "Add operations to build a recipe — each step's output feeds the next.")])); };
  picker.addEventListener("change", () => { if (!picker.value) return; const [op, preset, name] = picker.value.split("|"); steps.push({ op, name, args: defaults(registry[op].args, JSON.parse(preset)) }); picker.value = ""; draw(); run(); });
  input.addEventListener("input", run);
  mount(view, h("div", { class: "crumbs" }, h("a", { href: "#/" }, "Home"), " / ", h("a", { href: `#/${tab.id}` }, tab.name), " / Recipe builder"),
    h("section", { class: "banner" }, h("span", { class: "spot-icon" }, icon("flask")), h("div", { style: "flex:1" }, h("h1", {}, "Recipe builder"),
      h("p", { class: "lead" }, `Chain any of ${ops.length} native operations — encoders, decoders, hashes, ciphers and text tools. Each step's output feeds the next, all locally in your browser.`))),
    h("div", { class: "tool-layout" }, h("div", { class: "panel" }, h("label", {}, "Recipe"), picker, h("div", { style: "margin-top:10px" }, list), h("button", { class: "btn danger", type: "button", onclick: () => { steps = []; draw(); run(); } }, "Clear recipe")),
      h("div", {}, h("div", { class: "panel" }, h("label", {}, "Input"), input), h("div", { class: "panel", style: "margin-top:16px" }, h("div", { class: "row", style: "margin-bottom:8px" }, h("label", { style: "margin:0" }, "Output"), h("span", { class: "spacer" }), h("button", { class: "btn", type: "button", onclick: () => navigator.clipboard.writeText(out.textContent).then(() => toast("Copied")) }, "Copy")), out))));
  draw(); run();
}

function renderSearch(q) {
  renderTabs(null); const ql = q.toLowerCase();
  const hits = allTools().filter((t) => `${t.name} ${t.description} ${t.keywords.join(" ")} ${t.category}`.toLowerCase().includes(ql))
    .sort((a, b) => (b.name.toLowerCase().includes(ql) - a.name.toLowerCase().includes(ql)) || (!!b.native - !!a.native));
  mount(view, h("section", { class: "banner" }, h("div", {}, h("h1", {}, `Search: “${q}”`), h("p", { class: "lead" }, `${hits.length} result(s) across all tabs`))), h("div", { class: "grid" }, hits.slice(0, 300).map((t) => card(t.tab, t, true))));
}

function route() {
  const [, tabId, toolId] = location.hash.replace(/^#/, "").split("/");
  const sq = new URLSearchParams(location.hash.split("?")[1] || "").get("q");
  if (tabId?.startsWith("search")) return renderSearch(sq || "");
  const tab = catalog.tabs.find((t) => t.id === tabId);
  if (!tab) return renderHome();
  if (!toolId) return renderTab(tab);
  if (toolId === "~recipe") return renderRecipe(tab);
  const tool = tab.tools.find((t) => t.id === decodeURIComponent(toolId));
  return tool ? renderTool(tab, tool) : renderTab(tab);
}

async function main() {
  initTheme($("#theme-toggle"));
  try { catalog = await (await fetch("/api/catalog")).json(); } catch { mount(view, h("div", { class: "notice" }, "Could not load the tool catalog.")); return; }
  document.title = catalog.title || "Infosec Tools"; $("#site-title").textContent = catalog.title || "Infosec Tools";
  const total = allTools().length; $("#footer-stats").textContent = `${total} tools · ${allTools().filter((t) => t.native).length} native · ${catalog.tabs.length} tabs`;
  const gs = $("#global-search");
  gs.addEventListener("input", debounce(() => { location.hash = gs.value.trim() ? `#/search?q=${encodeURIComponent(gs.value.trim())}` : "#/"; }, 200));
  document.addEventListener("keydown", (e) => { if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(document.activeElement.tagName)) { e.preventDefault(); gs.focus(); } });
  addEventListener("hashchange", () => { route(); if (!location.hash.startsWith("#/search")) window.scrollTo(0, 0); });
  route();
}
main();
