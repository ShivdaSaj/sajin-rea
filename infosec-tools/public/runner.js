// Tool runner (client ops run in the browser, server ops call /api/run) and the recipe builder.
import { h, toast, debounce, store, mount } from "./dom.js";
import { icon } from "./icons.js";
import { registry } from "./ops/index.js";

// Arguments for server-side checks (the server ops take a target plus these).
export const SERVER_ARGS = {
  "dns-lookup": [{ name: "type", label: "Record type", type: "select", options: ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA", "SRV", "PTR", "NAPTR"] }],
  "dns-propagation": [{ name: "type", label: "Record type", type: "select", options: ["A", "AAAA", "MX", "NS", "TXT", "CNAME"] }],
  "dkim-check": [{ name: "selector", label: "Selector (blank = try common ones)", type: "text" }],
  "port-check": [{ name: "port", label: "Port", type: "number", default: 443 }],
  "cors-check": [{ name: "origin", label: "Origin to test", type: "text", default: "https://example.org" }],
  "http-request": [{ name: "method", label: "Method", type: "select", options: ["GET", "HEAD", "OPTIONS"] }, { name: "headers", label: "Request headers (one per line)", type: "textarea", default: "Accept: */*" }],
  "dns-trace": [{ name: "type", label: "Record type", type: "select", options: ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"] }],
};
const TARGET_HINT = { "reverse-dns": "IP address, e.g. 8.8.8.8", "ip-whois": "IP address or hostname", "asn-lookup": "AS number, e.g. AS13335", blocklists: "IPv4 address or hostname", "bgp-lookup": "IP, prefix or hostname, e.g. 1.1.1.0/24", "mail-tls": "Mail domain or MX host, e.g. example.com", "spf-flatten": "Domain, e.g. example.com", "cors-check": "URL of the API or page to test", "http-request": "https://example.com/path", "axfr-test": "Domain, e.g. zonetransfer.me" };

let uid = 0;
export function argField(spec, value, onchange) {
  const id = `arg-${spec.name}-${++uid}`;
  if (spec.type === "checkbox") return h("label", { class: "field check", for: id }, h("input", { id, type: "checkbox", checked: value, onchange: (e) => onchange(e.target.checked) }), h("span", {}, spec.label));
  let input;
  if (spec.type === "select") input = h("select", { id, class: "sel", onchange: (e) => onchange(e.target.value) }, spec.options.map((o) => h("option", { value: o, selected: String(o) === String(value) }, o)));
  else if (spec.type === "textarea") input = h("textarea", { id, rows: 3, oninput: (e) => onchange(e.target.value) }, value ?? "");
  else input = h("input", { id, type: spec.type === "number" ? "number" : "text", value: value ?? "", oninput: (e) => onchange(e.target.value) });
  return h("div", { class: "field" }, h("label", { for: id }, spec.label), input);
}
// Presets are stored as strings by the server, so coerce them back to the argument's type.
const coerce = (s, v) => (s.type === "checkbox" ? v === true || v === "true" : v);
export const defaults = (specs, preset = {}) => Object.fromEntries((specs || []).map((s) => [s.name, preset?.[s.name] !== undefined ? coerce(s, preset[s.name]) : s.default ?? (s.type === "checkbox" ? false : s.type === "select" ? s.options[0] : "")]));

async function runServer(opKey, target, args) {
  const r = await fetch(`/api/run/${opKey}`, { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ target, args }) });
  const j = await r.json().catch(() => ({ ok: false, error: `HTTP ${r.status}` }));
  if (!j.ok) throw new Error(j.error || `HTTP ${r.status}`);
  return j;
}
const panel = (title, ico, actions, ...body) => h("section", { class: "rpanel" }, h("div", { class: "rhead" }, h("span", { class: "rtitle" }, icon(ico, 15), title), h("span", { class: "spacer" }), actions), ...body);
const copy = (text, what = "Copied") => navigator.clipboard.writeText(text).then(() => toast(what), () => toast("Clipboard not available", true));

// Renders the runner for one tool into `box`. Returns nothing; everything is wired up inside.
export function renderRunner(box, tool) {
  const out = h("pre", { class: "output", "aria-live": "polite" });
  const status = h("span", { class: "rstatus" });
  const media = h("div", { class: "media-out" });
  const show = (text, err = false) => { out.textContent = text; out.classList.toggle("error", err); };
  const copyBtn = h("button", { class: "btn sm", type: "button", onclick: () => copy(out.textContent) }, icon("copy", 15), "Copy");

  if (!tool.native) {
    mount(box, h("div", { class: "empty" }, icon("external", 36), h("b", {}, "External tool"), h("p", {}, "This entry links to another site."),
      tool.external ? h("a", { class: "btn primary", href: tool.external, target: "_blank", rel: "noopener" }, "Open ", icon("external", 15)) : null));
    return;
  }

  if (tool.native.mode === "server") {
    const specs = SERVER_ARGS[tool.native.op] || []; const args = defaults(specs, tool.native.preset);
    const target = h("input", { type: "text", class: "target", placeholder: TARGET_HINT[tool.native.op] || "Domain or URL, e.g. example.com", value: store.get("lastTarget", ""), "aria-label": "Target", spellcheck: "false" });
    let data = null;
    const go = async () => {
      if (!target.value.trim()) { show("Enter a target first.", true); target.focus(); return; }
      store.set("lastTarget", target.value.trim()); runBtn.disabled = true; status.textContent = "Running…"; status.className = "rstatus busy"; show("");
      try { const r = await runServer(tool.native.op, target.value.trim(), args); data = r.data; show(r.text || "(no output)"); status.textContent = `Done in ${r.ms} ms`; status.className = "rstatus ok"; }
      catch (e) { show(e.message, true); status.textContent = "Failed"; status.className = "rstatus bad"; } finally { runBtn.disabled = false; }
    };
    const runBtn = h("button", { class: "btn primary", type: "button", onclick: go }, icon("bolt", 16), "Run check");
    target.addEventListener("keydown", (e) => { if (e.key === "Enter") go(); });
    show("Enter a domain, URL or IP and press Run check. The check runs live from the Infosec Tools server.");
    mount(box,
      panel("Target", "target", null, h("div", { class: "target-row" }, h("label", { class: "filter-input" }, icon("globe", 18), target), runBtn),
        specs.length ? h("div", { class: "args" }, specs.map((s) => argField(s, args[s.name], (v) => (args[s.name] = v)))) : null),
      panel("Result", "list", [status, copyBtn, h("button", { class: "btn sm", type: "button", onclick: () => (data ? copy(JSON.stringify(data, null, 2), "JSON copied") : toast("Run the check first", true)) }, icon("code", 15), "JSON")], out));
    return;
  }

  const op = registry[tool.native.op];
  if (!op) { mount(box, h("div", { class: "empty" }, h("b", {}, `Operation "${tool.native.op}" is missing from this build.`))); return; }
  const args = defaults(op.args, tool.native.preset);
  const fileMode = op.input === "file" || op.input === "image";
  const needsInput = op.input !== false;
  const input = h("textarea", { class: "code", rows: fileMode ? 4 : 12, placeholder: fileMode ? "…or paste data here" : op.placeholder || "Type or paste input", spellcheck: "false", "aria-label": "Input" });
  let file = null; // { bytes, name, type }
  const pasteEnc = h("select", { class: "sel sm", "aria-label": "Pasted data format", onchange: () => auto() }, ["Text", "Hex", "Base64"].map((o) => h("option", { value: o }, o)));
  const fileInfo = h("small", {}, "No file chosen");
  const picker = h("input", { type: "file", accept: op.input === "image" ? "image/*" : op.accept || "", hidden: true, onchange: (e) => e.target.files[0] && loadFile(e.target.files[0]) });
  async function loadFile(f) { file = { bytes: new Uint8Array(await f.arrayBuffer()), name: f.name, type: f.type }; fileInfo.textContent = `${f.name} · ${f.size.toLocaleString()} bytes`; input.value = ""; run(); }
  function pastedBytes() { const v = input.value.trim(); if (pasteEnc.value === "Hex") return Uint8Array.from((v.replace(/[^0-9a-f]/gi, "").match(/../g) || []).map((x) => parseInt(x, 16))); if (pasteEnc.value === "Base64") return Uint8Array.from(atob(v.replace(/\s/g, "")), (c) => c.charCodeAt(0)); return new TextEncoder().encode(input.value); }
  const fileInput = async () => (input.value.trim() ? { bytes: pastedBytes(), name: "pasted.bin", type: "" } : file);
  function showRich(r) {
    media.replaceChildren(); if (typeof r === "string" || r === undefined || r === null) { show(String(r ?? "")); return; }
    show(r.text ?? ""); if (!r.text) out.textContent = r.image ? "" : "(no text output)";
    if (r.image) { const src = typeof r.image === "string" ? r.image : URL.createObjectURL(r.image); media.append(h("img", { src, alt: "Output image", class: "out-img" })); }
    if (r.download) { const blob = r.download.data instanceof Blob ? r.download.data : new Blob([r.download.data], { type: r.download.mime || "application/octet-stream" }); const url = URL.createObjectURL(blob);
      media.append(h("a", { class: "btn primary", href: url, download: r.download.name || "output.bin" }, icon("download", 16), `Download ${r.download.name || "file"} (${blob.size.toLocaleString()} bytes)`)); }
  }
  const idle = (msg) => { out.classList.remove("error"); out.textContent = msg; media.replaceChildren(); status.textContent = ""; status.className = "rstatus"; };
  const run = async () => {
    try {
      let value = input.value;
      if (fileMode) { value = await fileInput(); if (!value) return idle(op.input === "image" ? "Choose or drop an image to see the result." : "Choose or drop a file, or paste data, to see the result."); }
      else if (needsInput && !input.value.trim() && !op.allowEmpty) return idle("Enter input to see the result.");
      const t0 = performance.now(); showRich(await op.run(value, args)); status.textContent = `${(performance.now() - t0).toFixed(1)} ms`; status.className = "rstatus ok";
    } catch (e) { media.replaceChildren(); show(e.message || String(e), true); status.textContent = "Error"; status.className = "rstatus bad"; }
  };
  const auto = debounce(run, 180); input.addEventListener("input", auto);
  const drop = fileMode ? h("div", { class: "dropzone", tabindex: "0", role: "button", "aria-label": "Choose a file",
    onclick: () => picker.click(), onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); picker.click(); } },
    ondragover: (e) => { e.preventDefault(); e.currentTarget.classList.add("over"); }, ondragleave: (e) => e.currentTarget.classList.remove("over"),
    ondrop: (e) => { e.preventDefault(); e.currentTarget.classList.remove("over"); const f = e.dataTransfer.files[0]; if (f) loadFile(f); } },
    icon("upload", 26), h("b", {}, op.input === "image" ? "Drop an image or click to choose" : "Drop a file or click to choose"), fileInfo, picker) : null;
  const optionsPanel = op.args?.length ? panel("Options", "settings", null, h("div", { class: "args" }, op.args.map((s) => argField(s, args[s.name], (v) => { args[s.name] = v; auto(); })))) : null;
  const inputPanel = needsInput ? panel("Input", "file", [fileMode ? pasteEnc : null,
    h("button", { class: "btn sm", type: "button", onclick: () => { input.value = ""; file = null; fileInfo.textContent = "No file chosen"; run(); } }, icon("close", 15), "Clear")], drop, input) : null;
  const outputPanel = panel("Output", "list", [status, h("button", { class: "btn sm" + (needsInput ? "" : " primary"), type: "button", onclick: run }, icon(needsInput ? "play" : "sparkle", 15), needsInput ? "Run" : "Generate"), copyBtn], media, out);
  mount(box, optionsPanel, h("div", { class: needsInput ? "io-grid" : "" }, inputPanel, outputPanel));
  run();
}

// CyberChef-style recipe: chain native text ops; each step's output feeds the next.
export function renderRecipe(main, kit) {
  const ops = (kit?.tools || []).filter((t) => t.native?.mode === "client" && registry[t.native.op] && registry[t.native.op].input === undefined);
  let steps = store.get("recipe", []).filter((s) => registry[s.op]);
  const input = h("textarea", { class: "code", rows: 12, placeholder: "Input", spellcheck: "false", "aria-label": "Recipe input" }); input.value = store.get("recipeInput", "");
  const out = h("pre", { class: "output", "aria-live": "polite" }); const list = h("ol", { class: "recipe-steps" }); const status = h("span", { class: "rstatus" });
  let q = ""; const opList = h("div", { class: "op-list" });
  const run = debounce(async () => {
    store.set("recipe", steps); store.set("recipeInput", input.value); let v = input.value; const t0 = performance.now();
    try { for (const s of steps) v = String(await registry[s.op].run(v, s.args)); out.textContent = v || (steps.length ? "(empty output)" : ""); out.classList.remove("error"); status.textContent = `${steps.length} step${steps.length === 1 ? "" : "s"} · ${(performance.now() - t0).toFixed(1)} ms`; status.className = "rstatus ok"; }
    catch (e) { out.textContent = e.message; out.classList.add("error"); status.textContent = "Error"; status.className = "rstatus bad"; }
  }, 150);
  const add = (t) => { steps.push({ op: t.native.op, name: t.name, args: defaults(registry[t.native.op].args, t.native.preset) }); draw(); run(); };
  const drawOps = () => { const ql = q.toLowerCase(); const hits = ops.filter((t) => !ql || `${t.name} ${t.category}`.toLowerCase().includes(ql)).slice(0, 120);
    mount(opList, hits.length ? hits.map((t) => h("button", { class: "op-item", type: "button", onclick: () => add(t), title: t.description }, h("b", {}, t.name), h("small", {}, t.category), icon("plus", 14))) : h("p", { class: "muted" }, "No operations match.")); };
  const draw = () => mount(list, steps.length ? steps.map((s, i) => h("li", { class: "recipe-step" },
    h("div", { class: "rs-head" }, h("span", { class: "rs-n" }, i + 1), h("b", {}, s.name), h("span", { class: "spacer" }),
      h("button", { class: "icon-btn sm", type: "button", title: "Move up", "aria-label": `Move ${s.name} up`, disabled: !i, onclick: () => { [steps[i - 1], steps[i]] = [steps[i], steps[i - 1]]; draw(); run(); } }, icon("arrowUp", 15)),
      h("button", { class: "icon-btn sm", type: "button", title: "Move down", "aria-label": `Move ${s.name} down`, disabled: i === steps.length - 1, onclick: () => { [steps[i + 1], steps[i]] = [steps[i], steps[i + 1]]; draw(); run(); } }, icon("arrowDown", 15)),
      h("button", { class: "icon-btn sm danger", type: "button", title: "Remove", "aria-label": `Remove ${s.name}`, onclick: () => { steps.splice(i, 1); draw(); run(); } }, icon("close", 15))),
    registry[s.op].args?.length ? h("div", { class: "args" }, registry[s.op].args.map((a) => argField(a, s.args[a.name], (v) => { s.args[a.name] = v; run(); }))) : null))
    : h("li", { class: "recipe-empty" }, icon("chain", 28), h("b", {}, "Your recipe is empty"), h("span", {}, "Pick operations on the left. Each step's output feeds the next, all in your browser.")));
  input.addEventListener("input", run);
  mount(main, h("div", { class: "wrap" }, h("section", { class: "section", style: "padding-top:36px" },
    h("div", { class: "cat-banner", style: "--accent:" + (kit?.accent || "var(--accent)") }, h("span", { class: "cat-ico" }, icon("chain", 28)),
      h("div", { style: "flex:1" }, h("span", { class: "kicker" }, kit ? kit.name : "Recipes"), h("h1", {}, "Recipe builder"),
        h("p", {}, `Chain any of ${ops.length} operations: encoders, decoders, hashes, ciphers and text tools. Each step's output feeds the next, and nothing leaves your browser.`))),
    h("div", { class: "recipe-layout" },
      h("aside", { class: "rpanel" }, h("div", { class: "rhead" }, h("span", { class: "rtitle" }, icon("list", 15), "Operations"), h("span", { class: "spacer" }), h("small", { class: "muted" }, ops.length)),
        h("label", { class: "filter-input" }, icon("search", 18), h("input", { type: "search", placeholder: "Find an operation…", "aria-label": "Find an operation", oninput: (e) => { q = e.target.value; drawOps(); } })), opList),
      h("section", { class: "rpanel" }, h("div", { class: "rhead" }, h("span", { class: "rtitle" }, icon("chain", 15), "Recipe"), h("span", { class: "spacer" }),
        h("button", { class: "btn sm", type: "button", onclick: () => { steps = []; draw(); run(); } }, icon("trash", 15), "Clear")), list),
      h("div", { class: "recipe-io" },
        panel("Input", "file", h("button", { class: "btn sm", type: "button", onclick: () => { input.value = ""; run(); } }, icon("close", 15), "Clear"), input),
        panel("Output", "list", [status, h("button", { class: "btn sm", type: "button", onclick: () => copy(out.textContent) }, icon("copy", 15), "Copy")], out))))));
  drawOps(); draw(); run();
}
