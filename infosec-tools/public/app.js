// Infosec Tools portal: four toolkits (IT, CyberChef, Web, Network) in the Forensics Atlas design.
import { h, $, $$, toast, store, initTheme, mount, hue, initials } from "./dom.js";
import { icon } from "./icons.js";
import { renderRunner, renderRecipe } from "./runner.js";

const main = $("#main");
const reduceMotion = matchMedia("(prefers-reduced-motion: reduce)").matches;
let CAT = { tabs: [] }, SITE = {}, KITS = [], TOOLS = [], BYKEY = {}, CATS = [];
let saved = new Set(store.get("it-saved", []));
let layout = store.get("it-view", "grid");

const slug = (s) => String(s).toLowerCase().replace(/[^a-z0-9]+/g, "-").replace(/^-|-$/g, "");
const topCat = (c) => String(c).split(" · ")[0];
const subCat = (c) => String(c).split(" · ").slice(1).join(" · ");
const isLive = (t) => t.native?.mode === "server";
const plural = (n, w) => `${n} ${w}${n === 1 ? "" : "s"}`;
const keyOf = (t) => `${t.kit.id}/${t.id}`;
const toolHref = (t) => `#/t/${t.kit.id}/${encodeURIComponent(t.id)}`;
const catHref = (c) => `#/explore/${c.kit.id}/${c.id}`;
const kitStyle = (k) => `--accent:${k.accent}`;

// ---------- data ----------
function index(catalog) {
  CAT = catalog; SITE = catalog.site || {}; KITS = []; TOOLS = []; BYKEY = {}; CATS = [];
  for (const tab of catalog.tabs) {
    const kit = { ...tab, cats: [], tools: [] };
    const meta = Object.fromEntries((tab.categories || []).map((c) => [c.name, c]));
    const order = [...(tab.categories || []).map((c) => c.name), ...tab.tools.map((t) => topCat(t.category))];
    for (const name of new Set(order)) {
      const tools = tab.tools.filter((t) => topCat(t.category) === name); if (!tools.length) continue;
      const c = { id: slug(name), name, icon: meta[name]?.icon || "sparkle", description: meta[name]?.description || "", kit, tools: [] };
      kit.cats.push(c); CATS.push(c);
    }
    for (const t0 of tab.tools) {
      const c = kit.cats.find((x) => x.name === topCat(t0.category));
      const t = { ...t0, kit, cat: c, sub: subCat(t0.category) };
      c.tools.push(t); kit.tools.push(t); TOOLS.push(t); BYKEY[keyOf(t)] = t;
    }
    KITS.push(kit);
  }
}
const kitById = (id) => KITS.find((k) => k.id === id);
const stats = () => ({ tools: TOOLS.length, toolkits: KITS.length, categories: CATS.length, live: TOOLS.filter(isLive).length, browser: TOOLS.filter((t) => !isLive(t)).length });
const fill = (s) => String(s || "").replace(/\{(tools|toolkits|categories|live|browser)\}/g, (_, k) => stats()[k]);

function score(t, q) {
  if (!q) return 1;
  const n = t.name.toLowerCase(), d = `${t.description} ${t.category} ${t.kit.name} ${(t.keywords || []).join(" ")} ${t.native?.op || ""}`.toLowerCase();
  let s = 0;
  for (const w of q.toLowerCase().split(/\s+/).filter(Boolean)) { if (n === w) s += 100; else if (n.startsWith(w)) s += 60; else if (n.includes(w)) s += 40; else if (d.includes(w)) s += 12; else return 0; }
  return s + (t.featured ? 6 : 0);
}
function highlight(text, q) {
  const terms = String(q || "").trim().split(/\s+/).filter((x) => x.length > 1).map((x) => x.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"));
  if (!terms.length) return [text];
  return String(text).split(new RegExp(`(${terms.join("|")})`, "gi")).map((part, i) => (i % 2 ? h("mark", {}, part) : part));
}

// ---------- shared pieces ----------
const avatar = (t) => h("span", { class: "avatar", style: `--h:${hue(t.cat.name + t.kit.id)}` }, initials(t.name));
const statusPill = (t) => (isLive(t) ? h("span", { class: "status st-live", title: "Runs live on the Infosec Tools server" }, "Live") : h("span", { class: "status st-browser", title: "Runs entirely in your browser" }, "Browser"));
const saveBtn = (t) => { const on = saved.has(keyOf(t)); return h("button", { class: `save-btn${on ? " on" : ""}`, type: "button", "data-save": keyOf(t), "aria-pressed": String(on), "aria-label": `${on ? "Remove from saved" : "Save"} ${t.name}` }, icon("bookmark", 16)); };
function toolCard(t, q = "", i = 0) {
  return h("article", { class: `tool${t.featured ? " recommended" : ""}`, "data-tool": keyOf(t), tabindex: "0", style: `animation-delay:${Math.min(i, 20) * 18}ms`, "aria-label": t.name },
    h("div", { class: "tool-head" }, avatar(t), h("div", { style: "min-width:0" }, h("h3", {}, highlight(t.name, q)), h("div", { class: "host" }, `${t.kit.name} · ${t.native?.op || "link"}`))),
    h("p", {}, highlight(t.description || `${t.category} tool`, q)),
    h("div", { class: "tool-foot" }, statusPill(t), h("span", { class: "tag" }, t.sub || t.cat.name), saveBtn(t)));
}
const mini = (t, extra) => h("button", { class: "mini", type: "button", "data-tool": keyOf(t) }, avatar(t), h("span", { style: "min-width:0" }, h("b", {}, t.name), h("small", {}, t.description || t.category)), extra);
function catCard(c, i = 0) {
  const max = Math.max(...c.kit.cats.map((x) => x.tools.length)); const live = c.tools.filter(isLive).length, br = c.tools.length - live;
  return h("a", { class: "cat-card reveal", href: catHref(c), style: `${kitStyle(c.kit)};transition-delay:${Math.min(i, 12) * 30}ms` },
    h("div", { class: "cat-top" }, h("span", { class: "cat-ico" }, icon(c.icon, 22)), h("span", { class: "count" }, c.tools.length)),
    h("h3", {}, c.name), h("p", {}, c.description || `${c.kit.name} tools`),
    h("div", { class: "bar" }, h("i", { style: `width:${Math.max(6, (c.tools.length / max) * 100)}%` })),
    h("div", { class: "meta-row" }, br ? h("span", { class: "tag tg-browser" }, `${br} browser`) : null, live ? h("span", { class: "tag tg-live" }, `${live} live`) : null,
      c.tools.some((t) => t.featured) ? h("span", { class: "tag", style: "color:var(--warn)" }, "★ Picks") : null));
}
const empty = (ico, title, text, action) => h("div", { class: "empty", style: "grid-column:1/-1" }, icon(ico, 40), h("b", {}, title), h("p", {}, text), action);
const sectionHead = (kicker, title, text, action) => h("div", { class: "section-head reveal" }, h("div", {}, h("span", { class: "kicker" }, kicker), h("h2", {}, title), text ? h("p", {}, text) : null), action);
function kitTabs(active) {
  return h("div", { class: "kit-tabs", role: "tablist", "aria-label": "Toolkits" }, KITS.map((k) => h("a", { href: `#/toolkits/${k.id}`, role: "tab", "aria-selected": String(k.id === active), class: k.id === active ? "on" : "", style: kitStyle(k) },
    h("span", { class: "kt-ico" }, icon(k.icon, 18)), h("span", { class: "kt-name" }, k.name), h("span", { class: "kt-n" }, k.tools.length))));
}

// ---------- views ----------
function viewHome() {
  const s = stats();
  const blipItems = [...KITS.map((k) => ({ label: k.name.replace(" Toolkit", ""), href: `#/toolkits/${k.id}`, color: k.accent })), { label: "Recipes", href: "#/recipe", color: "var(--accent-2)" }, { label: "Live checks", href: `#/explore?mode=live`, color: "var(--warn)" }];
  const blips = blipItems.map((b, i) => { const a = (i / blipItems.length) * Math.PI * 2 - Math.PI / 2, r = 44; return h("a", { class: "blip", href: b.href, style: `left:${50 + r * Math.cos(a)}%;top:${50 + r * Math.sin(a)}%;--bc:${b.color}` }, h("i", {}), b.label); });
  const popular = [["cyberchef-toolkit", "hashing"], ["it-toolkit", "crypto"], ["web-toolkit", "tls-certificates"], ["network-toolkit", "subnetting"], ["network-toolkit", "dns-tools"]].map(([k, c]) => CATS.find((x) => x.kit.id === k && x.id === c)).filter(Boolean);
  const heroSearch = h("form", { class: "hero-search", role: "search", onsubmit: (e) => { e.preventDefault(); const q = new FormData(e.target).get("q").trim(); location.hash = `#/explore${q ? "?q=" + encodeURIComponent(q) : ""}`; } },
    icon("search", 20), h("input", { name: "q", type: "search", placeholder: "Try “base64”, “subnet”, “TLS”, “JWT”…", "aria-label": "Search tools" }), h("button", { type: "submit" }, "Search"));
  const STEPS = [
    { id: "Find", icon: "search", short: "Search or browse", text: `Press Ctrl K to search ${s.tools} tools, or browse ${s.toolkits} toolkits and ${s.categories} categories.`, chips: KITS.map((k) => ({ label: k.name, href: `#/toolkits/${k.id}`, ico: k.icon, n: k.tools.length })) },
    { id: "Input", icon: "file", short: "Type, paste or drop", text: "Type or paste text, or drop a file. File tools also accept pasted hex or Base64 and turn it into bytes.", chips: pickCats(["cyberchef-toolkit/forensics", "cyberchef-toolkit/compression", "cyberchef-toolkit/multimedia"]) },
    { id: "Run local", icon: "cpu", short: "In your browser", text: `${s.browser} tools run entirely in your browser. Nothing you type leaves the page.`, chips: pickCats(["cyberchef-toolkit/hashing", "cyberchef-toolkit/encryption-encoding", "it-toolkit/crypto", "network-toolkit/subnetting"]) },
    { id: "Run live", icon: "bolt", short: "From the server", text: `${s.live} live checks query DNS, TLS and HTTP from the server. Every request goes through an SSRF guard that refuses private and internal addresses.`, chips: pickCats(["web-toolkit/dns-domain", "web-toolkit/tls-certificates", "web-toolkit/http-security", "network-toolkit/lookups"]) },
    { id: "Chain", icon: "chain", short: "Build recipes", text: "Chain CyberChef operations into a recipe: each step's output feeds the next, and the recipe is remembered in this browser.", chips: [{ label: "Open the recipe builder", href: "#/recipe", ico: "chain" }] },
    { id: "Save", icon: "bookmark", short: "Keep a shortlist", text: "Bookmark the tools you use most and export your shortlist as Markdown for your team.", chips: [{ label: "Saved tools", href: "#/saved", ico: "bookmark", n: saved.size }] },
  ];
  const detail = h("div", { class: "phase-detail reveal" });
  const renderStep = (st) => mount(detail, h("div", {}, h("span", { class: "kicker" }, `Step ${STEPS.indexOf(st) + 1} of ${STEPS.length}`), h("h4", {}, st.id), h("p", {}, st.text)),
    h("div", { class: "chips" }, st.chips.map((c) => h("a", { class: "chip", href: c.href }, icon(c.ico || "sparkle", 14), c.label, c.n !== undefined ? h("span", { class: "n" }, c.n) : null))));
  const steps = STEPS.map((st, i) => h("button", { class: `phase${i === 2 ? " on" : ""}`, type: "button", role: "tab", "aria-selected": String(i === 2),
    onclick: (e) => { $$(".phase").forEach((x) => { x.classList.toggle("on", x === e.currentTarget); x.setAttribute("aria-selected", String(x === e.currentTarget)); }); renderStep(st); } },
    h("span", { class: "node" }, icon(st.icon, 26), h("span", { class: "num" }, `0${i + 1}`)), h("b", {}, st.id), h("small", {}, st.short)));
  renderStep(STEPS[2]);
  const picks = TOOLS.filter((t) => t.featured);
  const prov = CAT.provenance;
  mount(main,
    h("section", { class: "hero" }, h("div", { class: "wrap" },
      h("div", { class: "hero-grid" },
        h("div", {}, SITE.eyebrow ? h("span", { class: "eyebrow" }, h("span", { class: "dot" }), SITE.eyebrow) : null,
          h("h1", {}, `${SITE.heading || ""} `, SITE.highlight ? h("span", { class: "grad" }, SITE.highlight) : null, ` ${SITE.headingEnd || ""}`),
          SITE.lead ? h("p", { class: "lead" }, fill(SITE.lead)) : null, heroSearch,
          h("div", { class: "quick-tags" }, h("span", {}, "Popular:"), popular.map((c) => h("a", { class: "chip", href: catHref(c) }, icon(c.icon, 14), c.name)))),
        h("div", { class: "scanner", "aria-hidden": "true" }, h("div", { class: "ring" }), h("div", { class: "ring r2" }), h("div", { class: "ring r3" }), h("div", { class: "sweep" }),
          h("div", { class: "core" }, h("div", {}, h("b", { "data-count": s.tools }, "0"), h("small", {}, "tools ready"))), blips)),
      h("div", { class: "stats" },
        h("div", { class: "stat reveal", style: "--c:var(--accent)" }, h("b", { "data-count": s.tools }, "0"), h("span", {}, "Tools you can run")),
        h("div", { class: "stat reveal", style: "--c:var(--accent-2)" }, h("b", { "data-count": s.toolkits }, "0"), h("span", {}, "Toolkits")),
        h("div", { class: "stat reveal", style: "--c:var(--accent-3)" }, h("b", { "data-count": s.categories }, "0"), h("span", {}, "Categories")),
        h("div", { class: "stat reveal", style: "--c:var(--warn)" }, h("b", { "data-count": s.live }, "0"), h("span", {}, "Live server checks"))))),

    h("section", { class: "section" }, h("div", { class: "wrap" },
      sectionHead("Choose your toolkit", "Four toolkits, one workbench", "Each toolkit groups related tools by category. Pick one to start, or search across all of them.",
        h("a", { class: "btn", href: "#/toolkits" }, "All toolkits ", icon("arrow", 16))),
      h("div", { class: "audience four" }, KITS.map((k) => h("div", { class: "aud-card reveal", style: `--c:${k.accent};${kitStyle(k)}` },
        h("span", { class: "badge-ico" }, icon(k.icon, 26)), h("h3", {}, k.name), h("p", {}, k.tagline || k.description),
        h("ul", {}, [...k.cats].sort((a, b) => b.tools.length - a.tools.length).slice(0, 3).map((c) => h("li", {}, icon("check", 16), `${c.name}: ${plural(c.tools.length, "tool")}`))),
        h("div", { class: "actions" }, h("a", { class: "btn primary", href: `#/toolkits/${k.id}` }, `Open ${k.name} `, icon("arrow", 16)),
          h("span", { class: "result-count" }, `${k.tools.length} tools · ${k.cats.length} categories`))))))),

    h("section", { class: "section" }, h("div", { class: "wrap" },
      sectionHead("How it works", "From input to answer in seconds", "Select a step to see what happens and where to start."),
      h("div", { class: "lifecycle six reveal", role: "tablist" }, steps), detail)),

    KITS.map((k, i) => h("section", { class: "section", style: "padding-top:24px" }, h("div", { class: "wrap" },
      sectionHead(`Toolkit 0${i + 1}`, k.name, k.tagline || k.description, h("a", { class: "btn", href: `#/toolkits/${k.id}`, style: kitStyle(k) }, "Open toolkit ", icon("arrow", 16))),
      h("div", { class: "cat-grid" }, k.cats.map(catCard))))),

    picks.length ? h("section", { class: "section" }, h("div", { class: "wrap" },
      sectionHead("★ Recommended", "Good places to start", "Popular tools from each toolkit, picked by the site admin."),
      h("div", { class: "tool-grid" }, picks.map((t, i) => toolCard(t, "", i))))) : null,

    prov ? h("section", { class: "section" }, h("div", { class: "wrap" },
      sectionHead("Built with REA", "How this catalog was made", "Each source site was mirrored and analysed statically with REA. The tools were then rebuilt natively; tools that couldn't be rebuilt were left out."),
      h("div", { class: "glossary" }, Object.entries(prov.sites || {}).map(([src, v]) => { const k = KITS.find((x) => x.source === src);
        return h("div", { class: "term reveal", style: k ? kitStyle(k) : "" }, h("b", {}, k ? k.name : v.label), h("p", {}, `${v.label}: ${v.tools} tools analysed, ${k ? k.tools.length : 0} rebuilt here. REA analysis ${v.rea?.status || "n/a"}; tool registry read from ${String(v.registry || "").split(" ")[0]}.`)); })))) : null);
  countUp();
}
function pickCats(keys) { return keys.map((k) => { const [kit, c] = k.split("/"); return CATS.find((x) => x.kit.id === kit && x.id === c); }).filter(Boolean).map((c) => ({ label: c.name, href: catHref(c), ico: c.icon, n: c.tools.length })); }

function viewToolkits() {
  mount(main, h("div", { class: "wrap" }, h("section", { class: "section" },
    sectionHead("Toolkits", "Four toolkits, one workbench", "Every tool belongs to one of four toolkits, each organised into categories. Open a toolkit to see its categories and tools."),
    kitTabs(null),
    h("div", { class: "kits two" }, KITS.map((k) => h("div", { class: "kit reveal", style: `--c1:${k.accent};--c2:var(--accent-2);${kitStyle(k)}` },
      h("div", { class: "kit-head" }, h("span", { class: "cat-ico" }, icon(k.icon, 22)), h("div", {}, h("h3", {}, k.name), h("span", { class: "result-count" }, `${k.tools.length} tools · ${k.cats.length} categories`))),
      h("p", { class: "scenario" }, k.description),
      h("ol", {}, k.cats.map((c) => h("li", {}, h("a", { class: "mini", href: catHref(c) }, h("span", { class: "cat-ico sm" }, icon(c.icon, 16)), h("span", { style: "min-width:0" }, h("b", {}, c.name), h("small", {}, c.description)), h("em", {}, c.tools.length))))),
      h("div", { class: "actions" }, h("a", { class: "btn primary", href: `#/toolkits/${k.id}` }, "Open toolkit ", icon("arrow", 16)),
        k.source === "cyberchef" ? h("a", { class: "btn", href: "#/recipe" }, icon("chain", 16), "Recipe builder") : null)))))));
}

function toolGrid(list, q, grouped) {
  const box = h("div", { class: `tool-grid ${layout}`, id: "results" }); let last = null, i = 0; const kids = [];
  for (const t of list) {
    if (grouped && t.category !== last) { kids.push(h("div", { class: "subgroup-title" }, grouped === "kit" ? `${t.kit.name} · ${t.category}` : t.category)); last = t.category; }
    kids.push(toolCard(t, q, i++));
  }
  mount(box, kids); return box;
}
function layoutSeg() {
  return h("div", { class: "seg", role: "group", "aria-label": "Layout" }, ["grid", "list"].map((v) => h("button", { type: "button", "data-view": v, class: layout === v ? "on" : "", "aria-label": `${v} view`,
    onclick: () => { layout = v; store.set("it-view", v); $$("[data-view]").forEach((x) => x.classList.toggle("on", x.dataset.view === v)); $$(".tool-grid#results").forEach((g) => (g.className = `tool-grid ${v}`)); } }, icon(v, 16))));
}

function viewKit(k) {
  let q = "";
  const results = h("div"); const count = h("div", { class: "result-count" });
  const draw = () => { const list = k.tools.map((t) => ({ t, s: score(t, q) })).filter((x) => x.s > 0); if (q) list.sort((a, b) => b.s - a.s);
    count.textContent = `${plural(list.length, "tool")}${q ? ` for “${q}”` : ""}`;
    mount(results, list.length ? toolGrid(list.map((x) => x.t), q, !q && "cat") : empty("search", "No matches", "Try a broader term.")); };
  const live = k.tools.filter(isLive).length;
  mount(main, h("div", { class: "wrap" }, h("section", { class: "section", style: "padding-top:36px" },
    kitTabs(k.id),
    h("div", { class: "cat-banner kit-banner", style: kitStyle(k) }, h("span", { class: "cat-ico" }, icon(k.icon, 30)),
      h("div", { style: "flex:1;min-width:240px" }, h("span", { class: "kicker" }, "Toolkit"), h("h1", {}, k.name), h("p", {}, k.description),
        h("div", { class: "meta-row", style: "margin-top:10px" }, h("span", { class: "tag" }, plural(k.tools.length, "tool")), h("span", { class: "tag" }, plural(k.cats.length, "category").replace("categorys", "categories")),
          k.tools.length - live ? h("span", { class: "tag tg-browser" }, `${k.tools.length - live} in browser`) : null, live ? h("span", { class: "tag tg-live" }, `${live} live`) : null)),
      h("div", { class: "actions" }, k.source === "cyberchef" ? h("a", { class: "btn primary", href: "#/recipe" }, icon("chain", 16), "Recipe builder") : null,
        h("a", { class: "btn", href: `#/explore/${k.id}` }, icon("search", 16), "Explore"))),
    h("div", { class: "section-head", style: "margin-top:40px" }, h("div", {}, h("span", { class: "kicker" }, "Categories"), h("h2", {}, `${k.name} categories`))),
    h("div", { class: "cat-grid" }, k.cats.map(catCard)),
    h("div", { class: "section-head", style: "margin-top:48px" }, h("div", {}, h("span", { class: "kicker" }, "All tools"), h("h2", {}, `Every tool in ${k.name}`))),
    h("div", { class: "toolbar" }, h("label", { class: "filter-input" }, icon("search", 18), h("input", { type: "search", placeholder: `Filter ${k.name}…`, "aria-label": `Filter ${k.name}`, oninput: (e) => { q = e.target.value.trim(); draw(); } })), layoutSeg()),
    count, results)));
  draw();
}

function viewExplore(kitId, catId, params) {
  const kit = kitById(kitId); const cat = kit && catId ? kit.cats.find((c) => c.id === catId) : null;
  const st = { q: params.get("q") || "", mode: params.get("mode") || "all", sort: params.get("sort") || "relevance" };
  const results = h("div"); const count = h("div", { class: "result-count" });
  const sync = () => { const p = new URLSearchParams(); if (st.q) p.set("q", st.q); if (st.mode !== "all") p.set("mode", st.mode); if (st.sort !== "relevance") p.set("sort", st.sort);
    history.replaceState(null, "", `#/explore${kit ? "/" + kit.id : ""}${cat ? "/" + cat.id : ""}${p.toString() ? "?" + p : ""}`); closeDrawer.back = location.hash; };
  const draw = () => {
    let list = (cat ? cat.tools : kit ? kit.tools : TOOLS).map((t) => ({ t, s: score(t, st.q) })).filter((x) => x.s > 0)
      .filter((x) => st.mode === "all" || (st.mode === "live" ? isLive(x.t) : !isLive(x.t)));
    if (st.sort === "az") list.sort((a, b) => a.t.name.localeCompare(b.t.name)); else if (st.q) list.sort((a, b) => b.s - a.s);
    count.textContent = `${plural(list.length, "result")}${st.q ? ` for “${st.q}”` : ""}`;
    mount(results, list.length ? toolGrid(list.map((x) => x.t), st.q, !st.q && st.sort === "relevance" && (kit ? "cat" : "kit"))
      : empty("search", "No matches", "Try a broader term or clear the filters.", h("a", { class: "btn", href: "#/explore" }, "Clear filters")));
  };
  const nav = (k, c) => { const p = new URLSearchParams(); if (st.q) p.set("q", st.q); if (st.mode !== "all") p.set("mode", st.mode); location.hash = `#/explore${k ? "/" + k : ""}${c ? "/" + c : ""}${p.toString() ? "?" + p : ""}`; };
  const side = h("ul", { class: "side-list cats" },
    h("li", {}, h("button", { type: "button", class: !kit ? "on" : "", onclick: () => nav() }, icon("grid", 16), "All toolkits", h("span", { class: "n" }, TOOLS.length))),
    KITS.map((k) => [h("li", {}, h("button", { type: "button", class: `kit-btn${kit === k && !cat ? " on" : ""}`, style: kitStyle(k), onclick: () => nav(k.id) }, icon(k.icon, 16), k.name, h("span", { class: "n" }, k.tools.length))),
      kit === k ? k.cats.map((c) => h("li", {}, h("button", { type: "button", class: `sub${cat === c ? " on" : ""}`, style: kitStyle(k), onclick: () => nav(k.id, c.id) }, icon(c.icon, 16), c.name, h("span", { class: "n" }, c.tools.length)))) : null]));
  const banner = cat ? h("div", { class: "cat-banner", style: kitStyle(kit) }, h("span", { class: "cat-ico" }, icon(cat.icon, 28)), h("div", {}, h("span", { class: "kicker" }, kit.name), h("h1", {}, cat.name), h("p", {}, cat.description),
      h("div", { class: "meta-row", style: "margin-top:10px" }, h("span", { class: "tag" }, plural(cat.tools.length, "tool")), [...new Set(cat.tools.map((t) => t.sub).filter(Boolean))].length ? h("span", { class: "tag" }, `${[...new Set(cat.tools.map((t) => t.sub).filter(Boolean))].length} sub-categories`) : null)))
    : kit ? h("div", { class: "cat-banner", style: kitStyle(kit) }, h("span", { class: "cat-ico" }, icon(kit.icon, 28)), h("div", {}, h("span", { class: "kicker" }, "Toolkit"), h("h1", {}, kit.name), h("p", {}, kit.tagline || kit.description)))
    : h("div", { class: "cat-banner" }, h("span", { class: "cat-ico" }, icon("search", 28)), h("div", {}, h("h1", {}, "Explore every tool"), h("p", {}, `Search and filter all ${TOOLS.length} tools across the four toolkits.`)));
  const qInput = h("input", { id: "q", type: "search", value: st.q, placeholder: "Filter by name, description or keyword…", "aria-label": "Filter results" });
  let tmr; qInput.addEventListener("input", (e) => { clearTimeout(tmr); tmr = setTimeout(() => { st.q = e.target.value.trim(); draw(); sync(); }, 120); });
  const sortSel = h("select", { class: "sel", "aria-label": "Sort", onchange: (e) => { st.sort = e.target.value; draw(); sync(); } }, [["relevance", "Sort: Relevance"], ["az", "Sort: A → Z"]].map(([v, l]) => h("option", { value: v, selected: st.sort === v }, l)));
  const modeChips = h("div", { class: "filter-chips" }, [["all", "Any"], ["browser", "Browser"], ["live", "Live"]].map(([v, l]) => h("button", { type: "button", class: `chip${st.mode === v ? " on" : ""}`, "data-runs": v,
    onclick: () => { st.mode = v; $$("[data-runs]", modeChips).forEach((x) => x.classList.toggle("on", x.dataset.runs === v)); draw(); sync(); } }, l)));
  mount(main, h("div", { class: "wrap" }, h("div", { class: "explore" },
    h("aside", { class: "sidebar", "aria-label": "Filters" }, h("h5", {}, "Toolkits"), side, h("h5", {}, "Runs in"), modeChips,
      h("h5", {}, "Legend"), h("div", { class: "legend", style: "flex-direction:column;align-items:start;gap:8px" }, h("span", { class: "status st-browser" }, "Browser: runs on your device"), h("span", { class: "status st-live" }, "Live: runs on the server"))),
    h("section", {}, h("div", { class: "results-head" }, banner, h("div", { class: "toolbar" }, h("label", { class: "filter-input" }, icon("search", 18), qInput), sortSel, layoutSeg()), count), results))));
  draw();
  $(".side-list .on")?.scrollIntoView({ block: "nearest", inline: "center" });
  if (st.q && !kit) qInput.focus();
}

function viewSaved() {
  const list = TOOLS.filter((t) => saved.has(keyOf(t)));
  mount(main, h("div", { class: "wrap" }, h("section", { class: "section" },
    h("div", { class: "section-head" }, h("div", {}, h("span", { class: "kicker" }, "Your shortlist"), h("h2", {}, "Saved tools"), h("p", {}, "Stored in this browser only. Copy it as Markdown to share with your team.")),
      list.length ? h("div", { class: "actions" },
        h("button", { class: "btn", type: "button", onclick: () => navigator.clipboard.writeText(list.map((t) => `- [${t.name}](${location.origin}/${toolHref(t)}) - ${t.kit.name}: ${t.description}`).join("\n")).then(() => toast("Copied Markdown to clipboard"), () => toast("Clipboard not available", true)) }, icon("copy", 16), "Copy as Markdown"),
        h("button", { class: "btn", type: "button", onclick: () => { saved.clear(); persistSaved(); viewSaved(); } }, icon("close", 16), "Clear")) : null),
    list.length ? h("div", { class: "tool-grid" }, list.map((t, i) => toolCard(t, "", i))) : empty("bookmark", "Nothing saved yet", "Use the bookmark button on any tool to build a personal shortlist.", h("a", { class: "btn primary", href: "#/explore" }, "Browse tools")))));
}

// Tool details + runner. Used by the drawer (quick view) and the full tool page.
function toolBody(t, full) {
  const runnerBox = h("div", { class: "runner" }); renderRunner(runnerBox, t);
  const related = t.cat.tools.filter((x) => x !== t).sort((a, b) => (b.sub === t.sub) - (a.sub === t.sub)).slice(0, 6);
  const recent = store.get("it-recent", []).filter((k) => k !== keyOf(t)); recent.unshift(keyOf(t)); store.set("it-recent", recent.slice(0, 10));
  return [
    h("div", { class: "tool-hero", style: kitStyle(t.kit) }, avatar(t), h("div", { style: "min-width:0;flex:1" }, h("span", { class: "kicker" }, `${t.kit.name} · ${t.cat.name}`), h(full ? "h1" : "h2", { id: "drawerTitle" }, t.name))),
    t.description ? h("p", { class: "desc" }, t.description) : null,
    h("div", { class: "badges" }, statusPill(t), h("span", { class: "tag" }, t.category), t.featured ? h("span", { class: "tag", style: "color:var(--warn)" }, "★ Recommended") : null),
    runnerBox,
    h("dl", { class: "kv" }, h("dt", {}, "Toolkit"), h("dd", {}, h("a", { href: `#/toolkits/${t.kit.id}` }, t.kit.name)),
      h("dt", {}, "Category"), h("dd", {}, h("a", { href: catHref(t.cat) }, t.cat.name), t.sub ? ` · ${t.sub}` : ""),
      h("dt", {}, "Runs"), h("dd", {}, isLive(t) ? "Live on the Infosec Tools server (SSRF-guarded)" : "In your browser; input never leaves this page"),
      t.native ? [h("dt", {}, "Operation"), h("dd", { class: "mono" }, t.native.op)] : null,
      t.keywords?.length ? [h("dt", {}, "Keywords"), h("dd", {}, t.keywords.slice(0, 12).join(", "))] : null),
    h("div", { class: "actions" },
      full ? null : h("a", { class: "btn primary", href: `#/tool/${t.kit.id}/${encodeURIComponent(t.id)}` }, "Open full page ", icon("external", 16)),
      h("button", { class: "btn", type: "button", id: "dSave", onclick: (e) => { toggleSave(keyOf(t)); e.currentTarget.lastChild.textContent = saved.has(keyOf(t)) ? "Saved" : "Save"; } }, icon("bookmark", 16), h("span", {}, saved.has(keyOf(t)) ? "Saved" : "Save")),
      h("button", { class: "btn", type: "button", onclick: () => navigator.clipboard.writeText(`${location.origin}/${toolHref(t)}`).then(() => toast("Link copied"), () => toast("Clipboard not available", true)) }, icon("link", 16), "Copy link"),
      t.external ? h("a", { class: "btn", href: t.external, target: "_blank", rel: "noopener", title: "The same tool on the original self-hosted instance" }, "Original ", icon("external", 16)) : null),
    related.length ? h("div", { class: "related" }, h("h4", {}, `More in ${t.cat.name}`), h("div", { class: "mini-list" }, related.map((r) => mini(r)))) : null,
  ];
}
function openTool(t) {
  const panel = $("#drawerPanel");
  mount(panel, h("button", { class: "icon-btn drawer-close", type: "button", "data-close": "", "aria-label": "Close" }, icon("close", 18)), toolBody(t, false));
  const d = $("#drawer"); const wasHidden = d.hidden; d.hidden = false; document.body.style.overflow = "hidden"; panel.scrollTop = 0;
  if (wasHidden) openTool.prev = document.activeElement;
  $(".drawer-close").focus();
  document.title = `${t.name} · ${SITE.title || "Infosec Tools"}`;
}
function closeDrawer() {
  const d = $("#drawer"); if (d.hidden) return; d.hidden = true; document.body.style.overflow = ""; mount($("#drawerPanel"));
  if (location.hash.startsWith("#/t/")) history.replaceState(null, "", closeDrawer.back || "#/explore");
  openTool.prev?.focus?.();
}
function viewTool(t) {
  mount(main, h("div", { class: "wrap tool-page" }, h("nav", { class: "crumbs", "aria-label": "Breadcrumb" }, h("a", { href: "#/" }, "Home"), " / ", h("a", { href: `#/toolkits/${t.kit.id}` }, t.kit.name), " / ", h("a", { href: catHref(t.cat) }, t.cat.name)),
    h("section", { class: "panel tool-panel" }, toolBody(t, true))));
}

// ---------- saving ----------
function persistSaved() { store.set("it-saved", [...saved]); $("#savedCount").textContent = saved.size; }
function toggleSave(k) {
  saved.has(k) ? saved.delete(k) : saved.add(k); persistSaved();
  $$(`[data-save="${CSS.escape(k)}"]`).forEach((b) => { b.classList.toggle("on", saved.has(k)); b.setAttribute("aria-pressed", String(saved.has(k))); });
  toast(saved.has(k) ? `Saved ${BYKEY[k].name}` : `Removed ${BYKEY[k].name}`);
}

// ---------- command palette ----------
let palSel = 0, palList = [];
function openPalette(q = "") { const p = $("#palette"); p.hidden = false; const inp = $("#paletteInput"); inp.value = q; palSel = 0; renderPalette(); inp.focus(); document.body.style.overflow = "hidden"; }
function closePalette() { $("#palette").hidden = true; if ($("#drawer").hidden) document.body.style.overflow = ""; }
function palRow(i, lead, title, sub, right) { return h("li", { role: "option", "data-i": i, "aria-selected": String(i === palSel), onclick: () => choosePalette(i), onmousemove: () => { if (palSel !== i) { palSel = i; markPal(); } } }, lead, h("div", { style: "min-width:0" }, h("b", {}, title), h("small", {}, sub)), h("span", { class: "cat" }, right)); }
const icoBox = (n, k) => h("span", { class: "cat-ico", style: `width:32px;height:32px;border-radius:9px;${k ? kitStyle(k) : ""}` }, icon(n, 16));
function renderPalette() {
  const q = $("#paletteInput").value.trim(); const box = $("#paletteResults");
  if (!q) {
    const recent = store.get("it-recent", []).map((k) => BYKEY[k]).filter(Boolean).slice(0, 5);
    palList = [...KITS.map((k) => ({ type: "kit", k })), ...recent.map((t) => ({ type: "tool", t }))];
    mount(box, h("li", { class: "pal-head", role: "presentation" }, "Toolkits"), KITS.map((k, i) => palRow(i, icoBox(k.icon, k), k.name, k.tagline, `${k.tools.length} tools`)),
      recent.length ? h("li", { class: "pal-head", role: "presentation" }, "Recently used") : null, recent.map((t, j) => palRow(KITS.length + j, avatar(t), t.name, t.description, t.kit.name)));
    return;
  }
  const ql = q.toLowerCase();
  const kits = KITS.filter((k) => k.name.toLowerCase().includes(ql)).map((k) => ({ type: "kit", k }));
  const cats = CATS.filter((c) => c.name.toLowerCase().includes(ql)).slice(0, 6).map((c) => ({ type: "cat", c }));
  const tools = TOOLS.map((t) => ({ t, s: score(t, q) })).filter((x) => x.s > 0).sort((a, b) => b.s - a.s).slice(0, 30).map((x) => ({ type: "tool", t: x.t }));
  palList = [...kits, ...cats, ...tools]; if (palSel >= palList.length) palSel = 0;
  mount(box, palList.length ? palList.map((x, i) => x.type === "kit" ? palRow(i, icoBox(x.k.icon, x.k), highlight(x.k.name, q), x.k.tagline, "toolkit")
    : x.type === "cat" ? palRow(i, icoBox(x.c.icon, x.c.kit), highlight(x.c.name, q), `${x.c.kit.name} · ${plural(x.c.tools.length, "tool")}`, "category")
    : palRow(i, avatar(x.t), highlight(x.t.name, q), highlight(x.t.description || x.t.category, q), x.t.kit.name.replace(" Toolkit", "")))
    : h("li", { class: "pal-head", role: "presentation" }, "No results. Press Enter to search everything."));
}
const markPal = () => $$("#paletteResults [data-i]").forEach((li) => li.setAttribute("aria-selected", String(+li.dataset.i === palSel)));
function choosePalette(i) {
  const x = palList[i]; const q = $("#paletteInput").value.trim(); closePalette();
  if (!x) { location.hash = `#/explore?q=${encodeURIComponent(q)}`; return; }
  if (x.type === "kit") location.hash = `#/toolkits/${x.k.id}`; else if (x.type === "cat") location.hash = catHref(x.c); else location.hash = toolHref(x.t);
}

// ---------- background canvas & effects (as on Forensics Atlas) ----------
function background() {
  const cv = $("#bg"), ctx = cv.getContext("2d"); let w, hh, pts = [], raf; const dpr = Math.min(devicePixelRatio || 1, 2);
  const resize = () => { w = innerWidth; hh = innerHeight; cv.width = w * dpr; cv.height = hh * dpr; ctx.setTransform(dpr, 0, 0, dpr, 0, 0); const n = Math.min(70, Math.floor((w * hh) / 22000));
    pts = Array.from({ length: n }, () => ({ x: Math.random() * w, y: Math.random() * hh, vx: (Math.random() - 0.5) * 0.25, vy: (Math.random() - 0.5) * 0.25, r: Math.random() * 1.6 + 0.6 })); };
  const col = () => getComputedStyle(document.documentElement).getPropertyValue("--accent").trim() || "#22d3ee"; let c = col();
  new MutationObserver(() => { c = col(); if (reduceMotion) draw(); }).observe(document.documentElement, { attributes: true, attributeFilter: ["data-theme", "data-mode"] });
  const draw = () => {
    ctx.clearRect(0, 0, w, hh);
    if (!reduceMotion) for (const p of pts) { p.x += p.vx; p.y += p.vy; if (p.x < 0 || p.x > w) p.vx *= -1; if (p.y < 0 || p.y > hh) p.vy *= -1; }
    ctx.strokeStyle = c; ctx.fillStyle = c;
    for (let i = 0; i < pts.length; i++) for (let j = i + 1; j < pts.length; j++) { const a = pts[i], b = pts[j], d = Math.hypot(a.x - b.x, a.y - b.y); if (d < 140) { ctx.globalAlpha = (1 - d / 140) * 0.18; ctx.beginPath(); ctx.moveTo(a.x, a.y); ctx.lineTo(b.x, b.y); ctx.stroke(); } }
    for (const p of pts) { ctx.globalAlpha = 0.5; ctx.beginPath(); ctx.arc(p.x, p.y, p.r, 0, 6.3); ctx.fill(); }
    ctx.globalAlpha = 1; if (!reduceMotion && !document.hidden) raf = requestAnimationFrame(draw);
  };
  resize(); draw();
  addEventListener("resize", () => { resize(); if (reduceMotion) draw(); });
  document.addEventListener("visibilitychange", () => { if (!document.hidden && !reduceMotion) { cancelAnimationFrame(raf); draw(); } });
}
function countUp() {
  $$("[data-count]").forEach((el) => { const to = +el.dataset.count; if (reduceMotion) { el.textContent = to; return; }
    const t0 = performance.now(); const step = (t) => { const k = Math.min(1, (t - t0) / 1200); el.textContent = Math.round(to * (1 - Math.pow(1 - k, 3))); if (k < 1) requestAnimationFrame(step); }; requestAnimationFrame(step); });
}
let io;
function reveal() {
  io?.disconnect();
  if (!("IntersectionObserver" in window)) { $$(".reveal").forEach((el) => el.classList.add("in")); return; }
  io = new IntersectionObserver((es) => es.forEach((e) => { if (e.isIntersecting) { e.target.classList.add("in"); io.unobserve(e.target); } }), { rootMargin: "0px 0px -40px 0px" });
  $$(".reveal").forEach((el) => io.observe(el));
}

// ---------- router ----------
function route() {
  const [path, qs] = location.hash.replace(/^#/, "").split("?"); const parts = path.split("/").filter(Boolean).map(decodeURIComponent); const params = new URLSearchParams(qs || "");
  const [page, a, b] = parts;
  const navKey = page === "t" || page === "tool" ? "explore" : page === "toolkits" ? "toolkits" : page || "home";
  $$(".nav a").forEach((x) => x.classList.toggle("active", x.dataset.nav === navKey));
  $("#nav").classList.remove("open"); $("#menuBtn").setAttribute("aria-expanded", "false");
  if (page === "t") {
    const t = BYKEY[`${a}/${b}`];
    if (t) { if (!main.children.length) { viewExplore(t.kit.id, t.cat.id, new URLSearchParams()); closeDrawer.back = catHref(t.cat); reveal(); } openTool(t); return; }
  }
  closeDrawer.back = location.hash; closeDrawer();
  let title = "";
  if (page === "toolkits" && kitById(a)) { viewKit(kitById(a)); title = kitById(a).name; }
  else if (page === "toolkits") { viewToolkits(); title = "Toolkits"; }
  else if (page === "explore") { viewExplore(a, b, params); const k = kitById(a); title = (k && k.cats.find((c) => c.id === b)?.name) || k?.name || "Explore"; }
  else if (page === "tool" && BYKEY[`${a}/${b}`]) { const t = BYKEY[`${a}/${b}`]; viewTool(t); title = t.name; }
  else if (page === "recipe") { renderRecipe(main, KITS.find((k) => k.source === "cyberchef") || KITS[0]); title = "Recipe builder"; }
  else if (page === "saved") { viewSaved(); title = "Saved"; }
  else viewHome();
  document.title = title ? `${title} · ${SITE.title || "Infosec Tools"}` : `${SITE.title || "Infosec Tools"} · Security & engineering toolkits`;
  window.scrollTo({ top: 0, behavior: "instant" }); main.focus({ preventScroll: true });
  reveal();
}

function bind() {
  document.addEventListener("click", (e) => {
    const s = e.target.closest("[data-save]"); if (s) { e.stopPropagation(); e.preventDefault(); toggleSave(s.dataset.save); return; }
    if (e.target.closest("[data-close]")) { closeDrawer(); return; }
    const t = e.target.closest("[data-tool]"); if (t && BYKEY[t.dataset.tool]) location.hash = toolHref(BYKEY[t.dataset.tool]);
  });
  document.addEventListener("keydown", (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === "k") { e.preventDefault(); $("#palette").hidden ? openPalette() : closePalette(); return; }
    if (e.key === "/" && !/input|textarea|select/i.test(document.activeElement.tagName)) { e.preventDefault(); openPalette(); return; }
    if (e.key === "Escape") { if (!$("#palette").hidden) closePalette(); else closeDrawer(); return; }
    if (e.key === "Enter" && document.activeElement.matches(".tool[data-tool]")) location.hash = toolHref(BYKEY[document.activeElement.dataset.tool]);
    if (!$("#palette").hidden) {
      if (e.key === "ArrowDown") { e.preventDefault(); palSel = Math.min(palList.length - 1, palSel + 1); markPal(); $(`#paletteResults [data-i="${palSel}"]`)?.scrollIntoView({ block: "nearest" }); }
      if (e.key === "ArrowUp") { e.preventDefault(); palSel = Math.max(0, palSel - 1); markPal(); $(`#paletteResults [data-i="${palSel}"]`)?.scrollIntoView({ block: "nearest" }); }
      if (e.key === "Enter") { e.preventDefault(); choosePalette(palSel); }
    }
  });
  $("#paletteInput").addEventListener("input", () => { palSel = 0; renderPalette(); });
  $("#palette").addEventListener("click", (e) => { if (e.target.id === "palette") closePalette(); });
  $("#openSearch").addEventListener("click", () => openPalette());
  $("#menuBtn").addEventListener("click", () => { const n = $("#nav"); n.classList.toggle("open"); $("#menuBtn").setAttribute("aria-expanded", String(n.classList.contains("open"))); });
  addEventListener("scroll", () => $("#topbar").classList.toggle("scrolled", scrollY > 8), { passive: true });
  document.addEventListener("pointermove", (e) => { const c = e.target.closest?.(".cat-card"); if (c) { const r = c.getBoundingClientRect(); c.style.setProperty("--mx", `${e.clientX - r.left}px`); c.style.setProperty("--my", `${e.clientY - r.top}px`); } }, { passive: true });
  addEventListener("hashchange", route);
}

function brand(el) { mount(el, SITE.brandPrefix || "Infosec", h("b", {}, SITE.brandSuffix || "Tools")); }
async function boot() {
  initTheme($("#themeToggle")); bind(); background();
  try { index(await (await fetch("/api/catalog", { cache: "no-cache" })).json()); }
  catch { mount(main, h("div", { class: "wrap" }, empty("close", "Could not load the tool catalog", "Please refresh the page."))); return; }
  brand($("#brandText")); brand($("#footerBrand"));
  $("#footerAbout").textContent = SITE.footer || "";
  const s = stats();
  mount($("#footerMeta"), h("div", {}, `${s.tools} tools · ${s.categories} categories · ${s.toolkits} toolkits`),
    CAT.updatedAt ? h("div", {}, `Catalog updated ${new Date(CAT.updatedAt).toISOString().slice(0, 10)}`) : null,
    h("div", {}, "Press ", h("kbd", {}, "Ctrl K"), " or ", h("kbd", {}, "/"), " to search"), h("div", {}, h("a", { href: "/admin" }, "Admin")));
  persistSaved(); route();
}
boot();
