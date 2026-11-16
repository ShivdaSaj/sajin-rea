// Landing page: hero meter, rebuild progress by tab, per-tab category charts,
// REA provenance, and a compact map of the whole catalog. Charts are inline SVG.
import { h, store, mount } from "./dom.js";

const SVG = "http://www.w3.org/2000/svg";
function s(tag, attrs = {}, ...kids) { const el = document.createElementNS(SVG, tag); for (const [k, v] of Object.entries(attrs)) if (v !== undefined) el.setAttribute(k, v); for (const c of kids.flat()) if (c != null) el.append(c instanceof Node ? c : document.createTextNode(String(c))); return el; }

const STATUS = [
  { key: "native", label: "Native (in browser)", cls: "seg-native", test: (t) => t.native?.mode === "client" },
  { key: "live", label: "Live (server check)", cls: "seg-live", test: (t) => t.native?.mode === "server" },
  { key: "link", label: "Link to original (planned)", cls: "seg-link", test: (t) => !t.native },
];
const ICONS = {
  wrench: "M14.7 6.3a4 4 0 0 0-5.4 5.4L3 18l3 3 6.3-6.3a4 4 0 0 0 5.4-5.4l-2.5 2.5-2.4-.6-.6-2.4 2.5-2.5z",
  flask: "M9 3h6M10 3v6L4.5 18.5A2 2 0 0 0 6.2 21h11.6a2 2 0 0 0 1.7-2.5L14 9V3M7 15h10",
  radar: "M12 12 19 5M21 12a9 9 0 1 1-9-9M17 12a5 5 0 1 1-5-5M12 12h.01",
  network: "M12 3v6M5 21v-4h14v4M12 9v8M5 13h14M3 3h18v6H3z",
};
export const icon = (name) => s("svg", { viewBox: "0 0 24 24", width: 22, height: 22, fill: "none", stroke: "currentColor", "stroke-width": 1.8, "stroke-linecap": "round", "stroke-linejoin": "round", "aria-hidden": "true" }, s("path", { d: ICONS[name] || ICONS.wrench }));
const counts = (tools) => Object.fromEntries(STATUS.map((x) => [x.key, tools.filter(x.test).length]));
const topCat = (c) => c.split(" · ")[0];

// One shared tooltip for every chart.
let tip;
function tooltip() { if (!tip) { tip = h("div", { class: "viz-tip", role: "tooltip" }); document.body.append(tip); } return tip; }
function bindTip(el, lines) {
  const show = (e) => { const t = tooltip(); t.replaceChildren(...lines.map((l, i) => h(i ? "div" : "strong", {}, l))); t.style.opacity = 1; move(e); };
  const move = (e) => { const t = tooltip(); const x = Math.min(e.clientX + 14, innerWidth - t.offsetWidth - 8); t.style.left = x + "px"; t.style.top = e.clientY + 14 + "px"; };
  el.addEventListener("pointerenter", show); el.addEventListener("pointermove", move); el.addEventListener("pointerleave", () => (tooltip().style.opacity = 0));
  el.setAttribute("tabindex", "0"); el.addEventListener("focus", (e) => { const r = el.getBoundingClientRect(); show({ clientX: r.left + r.width / 2, clientY: r.top }); }); el.addEventListener("blur", () => (tooltip().style.opacity = 0));
}

function legend() { return h("div", { class: "viz-legend" }, STATUS.map((x) => h("span", {}, h("i", { class: `swatch ${x.cls}` }), x.label))); }

// Stacked horizontal bar: segments with 2px surface gaps, rounded data-ends.
function stackBar(c, total, max, width, height, label) {
  const g = s("g"); let x = 0; const parts = STATUS.filter((st) => c[st.key] > 0);
  parts.forEach((st, i) => { const w = Math.max((c[st.key] / max) * width - (i < parts.length - 1 ? 2 : 0), 1);
    const r = s("rect", { x, y: 0, width: w, height, rx: 4, class: st.cls }); bindTip(r, [label, `${st.label}: ${c[st.key]}`, `${((c[st.key] / total) * 100).toFixed(1)}% of ${total}`]); g.append(r); x += w + 2; });
  return g;
}

export function heroMeter(all) {
  const c = counts(all), total = all.length; const W = 1000, H = 18;
  return h("div", { class: "hero-meter" },
    h("div", { class: "row small muted", style: "justify-content:space-between;margin-bottom:6px" }, h("span", {}, "Rebuild coverage across all tabs"), h("span", {}, `${(((c.native + c.live) / total) * 100).toFixed(0)}% running here`)),
    s("svg", { viewBox: `0 0 ${W} ${H}`, preserveAspectRatio: "none", class: "meter-svg", role: "img", "aria-label": `${c.native} native, ${c.live} live, ${c.link} link-only of ${total} tools` }, stackBar(c, total, total, W, H, "All tools")), legend());
}

function progressChart(tabs) {
  const rows = tabs.map((t) => ({ t, c: counts(t.tools), n: t.tools.length })); const max = Math.max(...rows.map((r) => r.n));
  const W = 760, LW = 140, RH = 26, GAP = 18, PAD = 44, H = rows.length * (RH + GAP); const plot = W - LW - PAD;
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "viz", role: "img", "aria-label": "Tools per tab by rebuild status" });
  const ticks = [0, 0.25, 0.5, 0.75, 1].map((f) => Math.round(max * f));
  for (const v of ticks) { const x = LW + (v / max) * plot; svg.append(s("line", { x1: x, x2: x, y1: 0, y2: H - GAP / 2, class: "grid" })); }
  rows.forEach(({ t, c, n }, i) => { const y = i * (RH + GAP);
    const a = s("a", { href: `#/${t.id}` }, s("text", { x: LW - 10, y: y + RH / 2 + 5, "text-anchor": "end", class: "lbl" }, t.name)); svg.append(a);
    const g = stackBar(c, n, max, plot, RH, t.name); g.setAttribute("transform", `translate(${LW},${y})`); svg.append(g);
    svg.append(s("text", { x: LW + (n / max) * plot + 8, y: y + RH / 2 + 5, class: "val" }, n)); });
  const table = h("details", { class: "viz-table" }, h("summary", {}, "Show as table"), h("table", {}, h("thead", {}, h("tr", {}, h("th", {}, "Tab"), STATUS.map((x) => h("th", {}, x.label)), h("th", {}, "Total"))),
    h("tbody", {}, rows.map(({ t, c, n }) => h("tr", {}, h("td", {}, t.name), STATUS.map((x) => h("td", {}, c[x.key])), h("td", {}, n))))));
  return h("div", { class: "panel viz-panel" }, h("div", { class: "viz-head" }, h("h3", {}, "Rebuild progress by tab"), legend()), svg, table);
}

function categoryChart(tab) {
  const m = new Map(); for (const t of tab.tools) m.set(topCat(t.category), (m.get(topCat(t.category)) || 0) + 1);
  const rows = [...m].sort((a, b) => b[1] - a[1]); const shown = rows.slice(0, 7); const rest = rows.slice(7).reduce((n, r) => n + r[1], 0); if (rest) shown.push([`Other (${rows.length - 7})`, rest]);
  const max = Math.max(...shown.map((r) => r[1])); const W = 360, LW = 132, RH = 14, GAP = 8, H = shown.length * (RH + GAP); const plot = W - LW - 34;
  const svg = s("svg", { viewBox: `0 0 ${W} ${H}`, class: "viz cat-viz", role: "img", "aria-label": `${tab.name} tools by category` });
  shown.forEach(([name, n], i) => { const y = i * (RH + GAP); const label = name.length > 20 ? name.slice(0, 19) + "…" : name;
    svg.append(s("text", { x: LW - 8, y: y + RH - 3, "text-anchor": "end", class: "lbl small" }, label));
    const r = s("rect", { x: LW, y, width: Math.max((n / max) * plot, 2), height: RH, rx: 4, class: "seg-cat" }); bindTip(r, [name, `${n} tool${n > 1 ? "s" : ""}`]); svg.append(r);
    svg.append(s("text", { x: LW + (n / max) * plot + 6, y: y + RH - 3, class: "val small" }, n)); });
  return svg;
}

function tabSpotlight(tab, site) {
  const c = counts(tab.tools); const quick = tab.tools.filter((t) => t.native).slice(0, 4);
  return h("article", { class: "spot" },
    h("header", {}, h("span", { class: "spot-icon" }, icon(tab.icon)), h("div", {}, h("h3", {}, h("a", { href: `#/${tab.id}` }, tab.name)), h("div", { class: "small muted" }, `Rebuilt from ${site?.label || tab.source}`))),
    h("p", {}, tab.description),
    h("div", { class: "spot-stats" }, h("div", {}, h("b", {}, tab.tools.length), h("span", {}, "tools")), h("div", {}, h("b", {}, new Set(tab.tools.map((t) => topCat(t.category))).size), h("span", {}, "categories")),
      h("div", {}, h("b", {}, c.native + c.live), h("span", {}, "run here"))),
    categoryChart(tab),
    h("div", { class: "spot-quick" }, quick.map((t) => h("a", { href: `#/${tab.id}/${encodeURIComponent(t.id)}`, class: "chip" }, t.name))),
    h("a", { class: "btn primary", href: `#/${tab.id}` }, `Open ${tab.name} →`));
}

function pipeline() {
  const steps = [["Mirror", "Fetched each site's HTML and JavaScript bundles over HTTPS"], ["REA analysis", "Static JavaScript application graph and route analysis; no target code executed"], ["Registry extraction", "Read each app's own tool registry: names, categories and descriptions"], ["Catalog", "789 tools grouped into four tabs, editable from the admin panel"], ["Native rebuild", "Tools reimplemented here in phases; the rest link to your instances"]];
  return h("ol", { class: "pipeline" }, steps.map(([t, d], i) => h("li", {}, h("span", { class: "step-n" }, i + 1), h("strong", {}, t), h("span", { class: "small muted" }, d))));
}

function provenanceTable(prov, tabs) {
  if (!prov?.sites) return null;
  return h("div", { class: "panel", style: "overflow-x:auto" }, h("table", { class: "prov" },
    h("thead", {}, h("tr", {}, ["Source site", "Became tab", "Files mirrored", "Tools found", "Categories", "REA analysis", "Evidence"].map((x) => h("th", {}, x)))),
    h("tbody", {}, Object.entries(prov.sites).map(([k, v]) => { const tab = tabs.find((t) => t.source === k);
      return h("tr", {}, h("td", {}, h("a", { href: v.url, target: "_blank", rel: "noopener" }, v.label || k)), h("td", {}, tab ? h("a", { href: `#/${tab.id}` }, tab.name) : "—"),
        h("td", {}, `${v.mirroredFiles ?? "?"} (${v.mirroredBytes ? (v.mirroredBytes / 1e6).toFixed(1) + " MB" : "?"})`), h("td", {}, v.tools), h("td", {}, v.categories ?? "—"),
        h("td", {}, h("span", { class: `pill ${v.rea.status === "complete" ? "ok" : "partial"}` }, v.rea.status === "complete" ? "✓ Complete" : "◐ Partial"), v.rea.status !== "complete" ? h("div", { class: "small muted" }, "Hit the 300 s per-bundle limit; inventory came from the route registry") : null),
        h("td", { class: "mono small" }, v.rea.application_evidence_id ? v.rea.application_evidence_id.slice(0, 18) + "…" : "partial bundle"));
    }))), h("p", { class: "small muted", style: "margin:10px 0 0" }, `Analysed with REA ${prov.reaVersion || ""} on ${prov.generated}. ${prov.method}`));
}

const MARK = { native: "●", live: "◆", link: "○" };
function catalogMap(tabs) {
  const status = (t) => (t.native ? t.native.mode === "server" ? "live" : "native" : "link");
  const body = h("div", { class: "map" }); let q = "", only = "all";
  const draw = () => { const ql = q.toLowerCase(); let shown = 0;
    mount(body, ...tabs.map((tab, ti) => { const groups = new Map();
      for (const t of tab.tools) { if (only !== "all" && status(t) !== only) continue; if (ql && !`${t.name} ${t.category} ${t.keywords.join(" ")}`.toLowerCase().includes(ql)) continue; const c = topCat(t.category); if (!groups.has(c)) groups.set(c, []); groups.get(c).push(t); }
      const n = [...groups.values()].reduce((a, g) => a + g.length, 0); shown += n; if (!n) return null;
      return h("details", { class: "map-tab", open: ql || only !== "all" || ti === 0 ? true : undefined },
        h("summary", {}, h("span", { class: "spot-icon sm" }, icon(tab.icon)), h("strong", {}, tab.name), h("span", { class: "muted small" }, `${n} tools · ${groups.size} categories`), h("a", { href: `#/${tab.id}`, class: "small", onclick: (e) => e.stopPropagation() }, "Open tab →")),
        h("div", { class: "map-cats" }, [...groups].map(([c, list]) => h("section", {}, h("h4", {}, h("a", { href: `#/${tab.id}` }, c), h("span", { class: "muted" }, ` ${list.length}`)),
          h("ul", {}, list.map((t) => h("li", {}, h("a", { href: `#/${tab.id}/${encodeURIComponent(t.id)}`, title: t.description || t.name, class: `m-${status(t)}` }, h("i", { "aria-hidden": "true" }, MARK[status(t)]), t.name))))))));
    }).filter(Boolean), shown ? [] : [h("p", { class: "empty" }, "Nothing matches.")]); };
  const filters = h("div", { class: "toolbar" }, h("input", { type: "search", placeholder: "Filter the catalog map…", oninput: (e) => { q = e.target.value; draw(); } }),
    h("div", { class: "chips", style: "margin:0" }, [["all", "All"], ["native", "● Native"], ["live", "◆ Live"], ["link", "○ Link"]].map(([k, l]) => h("button", { type: "button", class: "chip" + (k === only ? " active" : ""), onclick: (e) => { only = k; e.target.parentElement.querySelectorAll(".chip").forEach((b) => b.classList.remove("active")); e.target.classList.add("active"); draw(); } }, l))));
  draw();
  return h("div", {}, filters, body);
}

export function renderLanding(view, catalog, allTools, card) {
  const all = allTools(); const c = counts(all); const prov = catalog.provenance;
  const recent = store.get("recent", []).map((r) => all.find((t) => t.tab.id === r.tab && t.id === r.id)).filter(Boolean);
  const featured = all.filter((t) => t.featured);
  mount(view, 
    h("section", { class: "hero" },
      h("div", { class: "hero-copy" },
        h("span", { class: "eyebrow" }, "Security · Network · Developer toolkit"),
        h("h1", {}, catalog.title || "Infosec Tools"),
        h("p", { class: "lead" }, catalog.tagline || "Four self-hosted toolkits, reverse-engineered with REA and rebuilt as one fast, private workspace. Browser tools run locally; live checks run on this server."),
        h("div", { class: "row" }, h("a", { class: "btn primary", href: `#/${catalog.tabs[0]?.id || ""}` }, "Start exploring"), h("a", { class: "btn", href: "#catalog-map", onclick: (e) => { e.preventDefault(); document.getElementById("catalog-map")?.scrollIntoView({ behavior: "smooth" }); } }, "Browse the catalog map"))),
      h("div", { class: "hero-stats" },
        [[all.length, "tools catalogued"], [c.native, "native in-browser"], [c.live, "live server checks"], [catalog.tabs.length, "tabbed utilities"]].map(([n, l]) => h("div", { class: "stat" }, h("b", {}, n.toLocaleString()), h("span", {}, l)))),
      heroMeter(all)),
    featured.length || recent.length ? h("section", {}, h("h2", {}, recent.length ? "Pick up where you left off" : "Featured"), h("div", { class: "grid" }, (recent.length ? recent : featured).slice(0, 8).map((t) => card(t.tab, t, true)))) : null,
    h("section", {}, h("h2", {}, "The four toolkits"), h("p", { class: "lead" }, "Each tab is rebuilt from one of your self-hosted sites. The charts show what REA found in each one."),
      h("div", { class: "spots" }, catalog.tabs.map((t) => tabSpotlight(t, prov?.sites?.[t.source])))),
    h("section", {}, progressChart(catalog.tabs)),
    h("section", {}, h("h2", {}, "How this catalog was built"), pipeline(), provenanceTable(prov, catalog.tabs)),
    h("section", { id: "catalog-map" }, h("h2", {}, "Catalog map"), h("p", { class: "lead" }, "Every tool in short, grouped by tab and category. Each entry opens that tool in its tab."),
      h("div", { class: "row small muted", style: "margin-bottom:10px;gap:16px" }, h("span", { class: "m-native" }, "● native"), h("span", { class: "m-live" }, "◆ live check"), h("span", { class: "m-link" }, "○ links to original (planned)")), catalogMap(catalog.tabs)),
  );
}
