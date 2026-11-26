"use strict";
// Megallen console. Event text is untrusted (it can come from the inbox file): everything is built with h()/put(),
// which only ever create text nodes. Never use innerHTML with event data.

// Colours come from the design tokens in style.css (design (1).md §1); JS never hard-codes hex.
const css = (n) => getComputedStyle(document.documentElement).getPropertyValue(n).trim();
const V = {  // verdict -> plain name, description, colour, plotly symbol (shape = second channel besides colour)
  UNKNOWN_ANOMALY: ["Possible zero-day", "Unusual and matches no known attack", css("--v-zeroday"), "triangle-up"],
  KNOWN_ATTACK: ["Known attack", "Matches one attack type the model was trained on", css("--v-known"), "diamond"],
  UNCERTAIN_REVIEW: ["Unclear", "Not unusual, but no single class fits clearly", css("--v-review"), "square"],
  DEGRADED_REVIEW: ["Model problem", "A model was unavailable, so it was not called normal", css("--v-invalid"), "x"],
  PROCESSING_ERROR: ["Bad record", "Failed input checks, so no model ran on it", css("--v-invalid"), "cross"],
  NORMAL: ["Normal", "Looks like normal traffic", css("--v-normal"), "circle"],
};
const ORDER = Object.keys(V);
const STATUS = { new: "Not reviewed", investigating: "Investigating", escalated: "Escalated", resolved: "Resolved", false_positive: "False alarm" };
const ACTIONS = [["investigating", "Mark investigating"], ["escalated", "Escalate"], ["resolved", "Mark resolved"],
                 ["false_positive", "Mark false alarm"], ["new", "Reset to not reviewed"]];
const RULES = [  // plain-words version of the decision table (architecture.md 6.4); index + 1 = server rule id
  ["No", "Exactly one attack class", "KNOWN_ATTACK"],
  ["Yes", "Exactly one attack class", "KNOWN_ATTACK", "flagged as a possible new variant"],
  ["No", "Only normal", "NORMAL"],
  ["Yes", "Only normal", "UNKNOWN_ANOMALY"],
  ["Yes", "None, or several", "UNKNOWN_ANOMALY"],
  ["No", "None, or several", "UNCERTAIN_REVIEW"],
  ["Any", "Input broken or a model failed", "PROCESSING_ERROR", "or Model problem; never Normal"],
];
const INK2 = css("--text-2"), INK3 = css("--text-3"), GRID = css("--line"), AXIS = css("--line-strong"), LIME = css("--lime");
const FONT = "Inter, system-ui, sans-serif", MONO = "JetBrains Mono, Consolas, monospace";

const S = { events: [], byId: new Map(), state: null, sel: null, rows: [], view: "monitor", feedSrc: "live", seenFeed: new Set(),
            filterV: new Set(["UNKNOWN_ANOMALY"]), es: null, lastId: 0, expCache: new Map(), model: null };
const $ = (q) => document.querySelector(q);

function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k === "style") el.style.cssText = v;
    else if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const c of kids.flat(3)) if (c != null && c !== false) el.append(c instanceof Node ? c : document.createTextNode(String(c)));
  return el;
}
const put = (el, ...kids) => el.replaceChildren(...kids.flat(3).filter((k) => k != null && k !== false).map((k) => (k instanceof Node ? k : document.createTextNode(String(k)))));
const dot = (c) => h("span", { class: "dot", style: `background:${c}` });
const vname = (v) => V[v][0];
const pill = (v) => h("span", { class: "pill", style: `color:${V[v][2]};background:${V[v][2]}24` }, dot(V[v][2]), vname(v));  // 24 hex = 14% soft fill
const fmt = (x, d = 3) => (x == null || Number.isNaN(x) ? "—" : Number(x).toFixed(d));
const int = (x) => (x ?? 0).toLocaleString();
const pct = (x, d = 1) => (x == null ? "—" : `${(100 * x).toFixed(d)}%`);
const num = (x) => (x == null ? "—" : Math.abs(x) >= 1000 ? Math.round(x).toLocaleString() : +Number(x).toPrecision(3));
const time = (t) => new Date(t * 1000).toLocaleTimeString([], { hour12: false });
const mask = (ip) => (!ip ? "" : $("#mask").checked && /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip.split(".").slice(0, 2).join(".") + ".*.*" : ip);
const cap = (s) => (s ? s[0].toUpperCase() + s.slice(1) : "");
// Words instead of raw scores. Thresholds are relative to the calibrated alert line.
const level = (score) => { const t = S.state?.threshold; if (score == null) return "Not checked"; if (t == null) return fmt(score);
  return score > t + 0.08 ? "Very unusual" : score > t ? "Unusual" : score > t - 0.05 ? "Borderline" : "Looks normal"; };
const urgency = (e) => (e.priority == null ? "—" : e.priority >= 80 ? "High" : e.priority >= 55 ? "Medium" : "Low");
const origin = (e) => e.scenario || (e.source === "replay" ? "Test replay" : "Sent by you");
// Short "what was sent" label for the table: Zero-day · satan, Attack · smurf, Normal, Test replay.
const sentLabel = (e) => { if (e.source !== "live") return e.src ? `Test replay · ${mask(e.src)}` : "Test replay";
  const sc = e.scenario || "", m = /^(zero-day|attack): (\S+)/.exec(sc);
  return m ? `${m[1] === "zero-day" ? "Zero-day" : "Attack"} · ${m[2]}` : sc.startsWith("normal") ? "Normal" : sc.startsWith("synthetic") ? "Unusual (test)"
    : sc.startsWith("malformed") ? "Broken record" : cap(sc.split(" (")[0]) || "Sent by you"; };
const srcTag = (e) => h("span", { class: `tag ${e.source}` }, e.source === "live" ? "Sent by you" : "Replay");
const store = { get: (k) => { try { return localStorage.getItem(k); } catch { return null; } },
                set: (k, v) => { try { localStorage.setItem(k, v); } catch { /* private mode: fine */ } } };

async function api(path, body) {
  const r = await fetch(path, body ? { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(body) } : {});
  if (!r.ok) throw new Error(`${r.status} ${await r.text()}`);
  return r.json();
}
function toast(title, sub, kind = "alert", onclick) {
  const t = h("div", { class: `toast ${kind}`, role: "status", onclick: () => { onclick && onclick(); t.remove(); } }, h("b", {}, title), h("span", { class: "muted small" }, sub));
  $("#toasts").append(t);
  setTimeout(() => t.remove(), 5000);
  while ($("#toasts").children.length > 4) $("#toasts").firstChild.remove();
}

// ---------------- plots ----------------
const base = (extra = {}) => ({
  paper_bgcolor: "rgba(0,0,0,0)", plot_bgcolor: "rgba(0,0,0,0)", font: { color: INK2, size: 12, family: FONT },
  margin: { l: 52, r: 14, t: 10, b: 36 }, showlegend: true,
  legend: { orientation: "h", x: 0, xanchor: "left", y: 1.12, font: { color: INK2, size: 12 }, bgcolor: "rgba(0,0,0,0)" },
  xaxis: { showgrid: false, linecolor: AXIS, tickcolor: AXIS, zeroline: false, tickfont: { family: MONO, size: 11, color: INK3 } },
  yaxis: { gridcolor: GRID, gridwidth: 1, linecolor: AXIS, zeroline: false, tickfont: { family: MONO, size: 11, color: INK3 } },
  hoverlabel: { bgcolor: css("--surface-3"), bordercolor: AXIS, font: { family: FONT, size: 12, color: css("--text") } }, ...extra });
const cfg = { displaylogo: false, responsive: true, modeBarButtonsToRemove: ["lasso2d", "select2d", "autoScale2d", "toImage"] };

// ---------------- stream ----------------
function connect() {
  S.es?.close();
  S.es = new EventSource(`/api/stream?since=${S.lastId}`);
  S.es.onopen = () => { $("#conn").textContent = "Live"; $("#conn").className = "conn ok"; };
  S.es.onerror = () => { $("#conn").textContent = "Reconnecting…"; $("#conn").className = "conn bad"; };
  S.es.onmessage = (m) => {
    const { events, state } = JSON.parse(m.data);
    if (S.state && state.bundle !== S.state.bundle) resetLocal();
    S.state = state;
    if (events.length) {
      for (const e of events) { if (S.byId.has(e.id)) { Object.assign(S.byId.get(e.id), e); continue; } S.events.push(e); S.byId.set(e.id, e); }
      S.lastId = events[events.length - 1].id;
      if (S.events.length > 20000) for (const e of S.events.splice(0, S.events.length - 20000)) S.byId.delete(e.id);
      const zd = events.filter((e) => e.verdict === "UNKNOWN_ANOMALY" && e.source === "live");
      if (zd.length) {
        toast(`${zd.length} possible zero-day${zd.length > 1 ? "s" : ""} detected`, `${origin(zd[0])} · click to see why`, "alert", () => openEvent(zd[0].id));
        stepDone(2);
      }
    }
    renderTop();
    if (S.view === "monitor") renderMonitor(events.length > 0);
    if (S.view === "alerts" && $("#autoref").checked && events.length) loadAlerts();
  };
}
function resetLocal() { S.events = []; S.byId.clear(); S.seenFeed.clear(); S.sel = null; S.lastId = 0; S.expCache.clear(); S.model = null; }

function renderTop() {
  const st = S.state; if (!st) return;
  const sel = $("#bundle");
  if (sel.options.length !== st.bundles.length)
    put(sel, st.bundles.map((b) => h("option", { value: b }, bundleName(b))));
  sel.value = st.bundle;
  const r = st.replay;
  $("#play").textContent = r.running ? "Pause test traffic" : r.cursor >= r.total ? "Test traffic finished" : r.cursor ? "Resume test traffic" : "Play test traffic";
  $("#play").disabled = !r.running && r.cursor >= r.total;
  $("#prog").style.width = `${(100 * r.cursor) / r.total}%`;
  $("#progtxt").textContent = r.cursor ? `${int(r.cursor)} of ${int(r.total)} connections played` : "Not started";
  if (r.cursor) stepDone(1);
  const n = st.status.new; $("#newcount").textContent = int(n); $("#newcount").className = n ? "count" : "count zero";
  put($("#ctx"), "Hidden from training: ", h("b", {}, st.holdout), ` · alert line ${fmt(st.threshold)}`);
  $("#sim-zd").textContent = `${st.holdout} attacks, hidden from training`;
  if (st.mismatch && st.mismatch.length && S.warned !== st.mismatch.join()) {
    S.warned = st.mismatch.join();
    toast("Traffic was sent for a different model", `inject.py used ${st.mismatch.map(bundleName).join(", ")}; the console uses ${bundleName(st.bundle)}. Its "zero-day" and "known" labels may not match. Add --experiment ${st.bundle}`, "info");
  }
  const ds = { nsl_kdd: "NSL-KDD", cic_ids2017: "CIC-IDS2017" }[st.dataset] || st.dataset;
  const era = st.dataset === "nsl_kdd" ? "recorded on a simulated military network in 1998 (DARPA / MIT Lincoln Lab)" : "recorded on a test network in 2017 (Canadian Institute for Cybersecurity)";
  if (S.stripFor !== st.bundle) {
    S.stripFor = st.bundle;
    put($("#datastrip"), h("span", {}, h("b", {}, "Data: "), `the ${ds} test set, ${int(st.replay.total)} real network connections ${era}. Not a live network.`),
      h("span", {}, h("b", {}, "Zero-day: "), "this model never saw any ", h("code", {}, st.holdout), " attacks, so that traffic plays the role of a brand-new attack."),
      h("button", { class: "btn ghost", onclick: openHelp }, "How does this work?"));
    put($("#help-data"), `From the public ${ds} research dataset: ${int(st.replay.total)} network connections ${era}, each summarised into ${ds === "NSL-KDD" ? 41 : "about 80"} measurements (bytes sent, connection length, failed logins and so on) and labelled normal or attack. The models trained on a separate part of the dataset. "Play test traffic" streams the unseen part through them. "Send zero-day attack" sends ${st.holdout} connections, a type removed from training on purpose.`);
  }
}

// ---------------- intro ----------------
function openHelp() {
  put($("#help-verdicts"), ORDER.flatMap((v) => [h("dt", {}, pill(v)), h("dd", {}, V[v][1])]));
  $("#helpdlg").showModal();
}
function stepDone(i) { document.querySelector(`#intro .steps li:nth-child(${i})`)?.classList.add("done"); }
function newestZeroDay() {
  for (let i = S.events.length - 1; i >= 0; i--) if (S.events[i].verdict === "UNKNOWN_ANOMALY" && S.events[i].source === "live") return S.events[i];
  for (let i = S.events.length - 1; i >= 0; i--) if (S.events[i].verdict === "UNKNOWN_ANOMALY") return S.events[i];
  return null;
}

// ---------------- monitor ----------------
function kpi(l, v, s, color, opts = {}) {
  return h("div", { class: `kpi${opts.alert ? " alert" : ""}${opts.onclick ? " click" : ""}`, onclick: opts.onclick, tabindex: opts.onclick ? "0" : null,
    role: opts.onclick ? "button" : null, title: opts.title, style: color ? `--k:${color}` : null },
    h("div", { class: "l" }, l), h("div", { class: "v" }, v), h("div", { class: "s" }, s));
}
const filterTo = (verdicts) => () => { S.filterV = new Set(verdicts); chipsInit(); $("#sfilter").value = ""; show("alerts"); };
let lastPlot = 0;
function renderMonitor(changed) {
  const st = S.state; if (!st) return;
  const c = st.counts, unclear = c.UNCERTAIN_REVIEW + c.DEGRADED_REVIEW + c.PROCESSING_ERROR;
  put($("#kpis"),
    kpi("Connections checked", int(st.total), st.eps >= 1 ? `${st.eps.toFixed(0)} per second right now` : "Press Play test traffic to start"),
    kpi("Possible zero-days", int(c.UNKNOWN_ANOMALY), "Unusual and unlike any known attack", V.UNKNOWN_ANOMALY[2], { alert: c.UNKNOWN_ANOMALY > 0, onclick: filterTo(["UNKNOWN_ANOMALY"]), title: "Show these in Alerts" }),
    kpi("Known attacks", int(c.KNOWN_ATTACK), "Recognised attack types", V.KNOWN_ATTACK[2], { onclick: filterTo(["KNOWN_ATTACK"]), title: "Show these in Alerts" }),
    kpi("Needs a look", int(unclear), "The system was not sure", V.UNCERTAIN_REVIEW[2], { onclick: filterTo(["UNCERTAIN_REVIEW", "DEGRADED_REVIEW", "PROCESSING_ERROR"]), title: "Show these in Alerts" }));
  renderFeed();
  const now = performance.now();
  if (!changed && now - lastPlot < 4000) return;
  lastPlot = now;
  plotStream(); renderMix(); renderDrift();
}
// Simple bar row: label, filled track, value. Used instead of complex charts.
function barRow(label, sub, frac, color, value, onclick, showDot = true) {
  return h("div", { class: `brow${onclick ? " click" : ""}`, onclick, role: onclick ? "button" : null, tabindex: onclick ? "0" : null },
    h("div", { class: "blabel" }, showDot && color && dot(color), h("span", {}, label, sub && h("small", {}, sub))),
    h("div", { class: "btrack" }, h("i", { style: `width:${Math.max(0, Math.min(1, frac)) * 100}%;background:${color || LIME}` })),
    h("div", { class: "bval" }, value));
}
// One line per verdict group; each has its own dash so colour is never the only cue (§6). Zero-day is drawn last, on top.
const SERIES = [
  ["NORMAL", "Normal", { dash: "longdash", width: 1.75, opacity: 0.7 }],
  ["UNCERTAIN_REVIEW", "Needs a look", { dash: "dash", width: 2.5 }],
  ["KNOWN_ATTACK", "Known attacks", { dash: "dot", width: 2.5 }],
  ["UNKNOWN_ANOMALY", "Possible zero-days", { dash: "solid", width: 3, fill: "tozeroy" }],
];
function plotStream() {
  const B = 10, N = 18, now = Date.now() / 1000, t0 = Math.floor(now / B) * B - (N - 1) * B;
  const xs = Array.from({ length: N }, (_, i) => new Date((t0 + i * B) * 1000));
  const group = (v) => (v === "DEGRADED_REVIEW" || v === "PROCESSING_ERROR" ? "UNCERTAIN_REVIEW" : v);
  const ys = Object.fromEntries(SERIES.map(([v]) => [v, new Array(N).fill(0)]));
  for (const e of S.events) if (e.t >= t0) ys[group(e.verdict)][Math.min(N - 1, Math.floor((e.t - t0) / B))]++;  // no early exit: order is not guaranteed
  const traces = SERIES.map(([v, name, st]) => ({ type: "scatter", mode: "lines", name: `${name}: ${ys[v][N - 1]} in the last 10 s`, x: xs, y: ys[v],
    line: { color: V[v][2], width: st.width, dash: st.dash, shape: "spline", smoothing: 0.6 }, opacity: st.opacity ?? 1,
    fill: st.fill || "none", fillcolor: st.fill ? `${V[v][2]}24` : undefined, hovertemplate: `${name}: %{y}<extra></extra>` }));
  const alerts = ["UNKNOWN_ANOMALY", "KNOWN_ATTACK", "UNCERTAIN_REVIEW"].reduce((a, v) => a + ys[v].reduce((x, y) => x + y, 0), 0);
  const narrow = matchMedia("(max-width: 720px)").matches;
  const lay = base({ height: narrow ? 280 : 340, hovermode: "x unified", margin: { l: 44, r: 16, t: 28, b: 36 },
    legend: { ...base().legend, y: narrow ? -0.2 : 1.12, yanchor: narrow ? "top" : "bottom" },
    xaxis: { ...base().xaxis, type: "date", tickformat: "%H:%M", nticks: 4,
      showspikes: true, spikemode: "across", spikethickness: 1, spikecolor: AXIS, spikedash: "solid" },
    yaxis: { ...base().yaxis, rangemode: "tozero", nticks: 4 } });
  if (!alerts) lay.annotations = [{ xref: "paper", yref: "paper", x: 0.5, y: 0.5, showarrow: false, text: "No alerts in the last 3 minutes", font: { color: INK2, size: 14 } }];
  Plotly.react("chart-stream", traces, lay, { displayModeBar: false, responsive: true });
}
function renderMix() {
  const c = S.state.counts, total = Object.values(c).reduce((a, b) => a + b, 0);
  const groups = [["Possible zero-days", "UNKNOWN_ANOMALY", c.UNKNOWN_ANOMALY, ["UNKNOWN_ANOMALY"]],
    ["Known attacks", "KNOWN_ATTACK", c.KNOWN_ATTACK, ["KNOWN_ATTACK"]],
    ["Unclear", "UNCERTAIN_REVIEW", c.UNCERTAIN_REVIEW + c.DEGRADED_REVIEW + c.PROCESSING_ERROR, ["UNCERTAIN_REVIEW", "DEGRADED_REVIEW", "PROCESSING_ERROR"]],
    ["Normal", "NORMAL", c.NORMAL, null]];
  if (!total) { put($("#mix"), h("div", { class: "empty" }, "Nothing checked yet. Start the replay or send traffic.")); return; }
  put($("#mix"), groups.map(([name, v, n, vs]) => barRow(name, null, n / total, V[v][2],
    [int(n), h("small", {}, pct(n / total, 0))], vs ? filterTo(vs) : null)));
}
// 3-step meter: how big a change is, shown as filled segments instead of a number.
const meter = (n, col) => h("span", { class: "meter", "aria-hidden": "true" }, [1, 2, 3].map((i) => h("i", { style: i <= n ? `background:${col}` : "" })));
function renderDrift() {
  const d = S.state.drift, f = d.features || {}, ks = Object.keys(f).slice(0, 3);
  const ANSWER = {
    stable: [1, V.NORMAL[2], "No, it looks like the training traffic", "The model is seeing the kind of traffic it learned from, so its verdicts can be trusted as usual."],
    moderate_shift: [2, css("--warn"), "A little different", "Some parts of the traffic have changed. Verdicts still work, but keep an eye on them."],
    significant_shift: [3, css("--warn"), "Yes, quite different", "The model is seeing traffic unlike what it learned from, so it may make more mistakes. Double-check its alerts."],
    insufficient_batch: [0, INK2, "Not sure yet", "We need at least 500 connections before we can compare."],
  };
  const [lvl, col, answer, why] = ANSWER[d.status];
  const change = (v) => (v >= 0.25 ? [3, LIME, "Big change"] : v >= 0.1 ? [2, LIME, "Some change"] : [1, LIME, "Small change"]);  // single-hue: drift is not a verdict
  put($("#drift"), h("div", { class: "shift" },
    h("div", { class: "shift-main" },
      h("div", { class: "shift-q" }, "Does recent traffic look different from what the model learned on?"),
      h("div", { class: "shift-a", style: `color:${col}` }, meter(lvl, col), answer),
      h("p", { class: "shift-why" }, why),
      h("p", { class: "shift-foot" }, "Just a heads-up: this never changes a verdict.")),
    ks.length > 0 && h("div", { class: "shift-side" },
      h("div", { class: "shift-q" }, "What changed most"),
      h("ul", { class: "shift-list" }, ks.map((k) => { const [n, c, word] = change(f[k]);
        return h("li", {}, h("span", { class: "shift-name" }, cap(d.described?.[k] || k)), h("span", { class: "shift-lvl", style: `color:${c}` }, meter(n, c), word)); })))));
}
function renderFeed() {
  const zd = S.events.filter((e) => e.verdict === "UNKNOWN_ANOMALY" && (S.feedSrc === "all" || e.source === "live")).slice(-60).reverse();
  if (!zd.length) {
    put($("#feed"), h("li", { class: "empty" }, h("b", {}, S.feedSrc === "live" ? "No zero-days sent yet" : "No possible zero-days yet"),
      "Send attack traffic the model has never seen and watch it get flagged.",
      h("div", {}, h("button", { class: "btn danger", onclick: () => inject("zero-day") }, "Send zero-day attack"))));
    return;
  }
  put($("#feed"), zd.map((e) => {
    const fresh = !S.seenFeed.has(e.id); S.seenFeed.add(e.id);
    return h("li", { class: `item${fresh ? " fresh" : ""}`, tabindex: "0", role: "button", onclick: () => openEvent(e.id),
      onkeydown: (ev) => ev.key === "Enter" && openEvent(e.id), title: "See why it was flagged" },
      h("span", { class: "sc" }, srcTag(e), e.scenario || `Flow ${e.id}`), h("span", { class: "pr" }, `${urgency(e)} urgency`),
      h("span", { class: "sub" }, [time(e.t), level(e.score), mask(e.src) && `from ${mask(e.src)}`, e.incident && "part of a burst from one host"].filter(Boolean).join(" · ")),
      e.flow && h("span", { class: "sub mono" }, flowLine(e.flow)));
  }));
}
// ---------------- alerts ----------------
function chipsInit() {
  put($("#vfilter"), ORDER.map((v) => h("button", { class: `chip${S.filterV.has(v) ? " on" : ""}`, "aria-pressed": String(S.filterV.has(v)), title: V[v][1],
    style: `--cs:${V[v][2]}24;--cb:${V[v][2]}73`,
    onclick: (ev) => { S.filterV.has(v) ? S.filterV.delete(v) : S.filterV.add(v); ev.currentTarget.classList.toggle("on"); ev.currentTarget.setAttribute("aria-pressed", String(S.filterV.has(v))); loadAlerts(); } },
    dot(V[v][2]), vname(v))));
}
let alertsBusy = false;
async function loadAlerts() {
  if (alertsBusy) return; alertsBusy = true;
  try {
    const qs = new URLSearchParams({ verdict: [...S.filterV].join(","), status: $("#sfilter").value, source: $("#ofilter").value, q: $("#search").value, limit: 500 });
    S.rows = S.filterV.size ? await api(`/api/events?${qs}`) : [];
    renderTable();
  } catch (e) { console.error(e); } finally { alertsBusy = false; }
}
function renderTable() {
  const empty = $("#tbl-empty");
  if (S.rows.length) empty.style.display = "none";
  else {
    empty.style.display = "block";
    const any = S.state && S.state.total;
    put(empty, h("b", {}, any ? "No alerts match these filters" : "No alerts yet"),
      any ? "Try turning on more verdicts or clearing the search." : "Start the test replay or send a zero-day attack.",
      h("div", {}, any ? h("button", { class: "btn", onclick: () => { S.filterV = new Set(ORDER); chipsInit(); $("#ofilter").value = ""; $("#sfilter").value = ""; $("#search").value = ""; loadAlerts(); } }, "Show all flows")
        : h("button", { class: "btn danger", onclick: () => inject("zero-day") }, "Send zero-day attack")));
  }
  put($("#tbl tbody"), S.rows.map((e) => h("tr", { class: e.id === S.sel ? "sel" : "", "data-id": e.id, onclick: () => select(e.id) },
    h("td", { class: "num" }, e.id), h("td", { class: "mono" }, time(e.t)), h("td", {}, pill(e.verdict)),
    h("td", {}, e.candidate ? h("b", {}, e.candidate) : e.set && e.set.length ? e.set.map((c) => h("span", { class: "setchip" }, c)) : h("span", { class: "muted" }, e.set ? "Nothing fits" : "—")),
    h("td", { class: "small" }, flowLine(e.flow)),
    h("td", { class: "lvl" }, level(e.score), h("small", {}, fmt(e.score))),
    h("td", {}, h("span", { class: "pbar" }, h("i", { style: `width:${e.priority ?? 0}%` })), urgency(e)),
    h("td", { class: "src", title: origin(e) }, sentLabel(e)),
    h("td", {}, e.status ? h("span", { class: `status ${e.status}` }, STATUS[e.status]) : h("span", { class: "muted" }, "—")))));
}

const bytes = (b) => (b == null ? "—" : b >= 1e6 ? `${(b / 1e6).toFixed(1)} MB` : b >= 1e3 ? `${(b / 1e3).toFixed(1)} KB` : `${Math.round(b)} B`);
const secs = (s) => (s == null ? "—" : s >= 60 ? `${(s / 60).toFixed(1)} min` : s >= 1 ? `${s.toFixed(1)} s` : `${Math.round(s * 1000)} ms`);
function flowLine(f) {
  if (!f) return h("span", { class: "muted" }, "—");
  return [f.protocol || (f.port != null ? `port ${f.port}` : null), secs(f.duration_s), f.packets != null ? `${num(f.packets)} pkts` : null, bytes(f.bytes)]
    .filter(Boolean).join(" · ");
}
function flowFacts(f) {
  if (!f) return h("div", { class: "muted small" }, "No flow features are available for this record.");
  const rows = [["Protocol", f.protocol || "not recorded in this dataset"], ["Service", f.service], ["Destination port", f.port], ["Connection end", f.flag],
    ["Duration", secs(f.duration_s)],
    ["Packets", f.packets == null ? "not recorded in this dataset" : `${num(f.packets)} (${num(f.packets_out)} out / ${num(f.packets_back)} back)`],
    ["Bytes", f.bytes == null ? "—" : `${bytes(f.bytes)} (${bytes(f.bytes_out)} out / ${bytes(f.bytes_back)} back)`]]
    .filter(([, v]) => v != null && v !== "");
  return h("div", { class: "kv" }, rows.flatMap(([k, v]) => [h("span", {}, k), h("span", { class: "mono" }, String(v))]));
}

function gauge(score, thr, color) {
  const lo = Math.min(-0.25, score ?? 0, thr ?? 0) - 0.02, hi = Math.max(0.25, score ?? 0, thr ?? 0) + 0.02;
  const pos = (x) => `${(100 * (x - lo)) / (hi - lo)}%`;
  return h("div", {},
    h("div", { class: "gauge", style: `--t:${pos(thr ?? hi)};--s:${pos(score ?? lo)};--c:${color}` },
      score != null && h("i", { title: `score ${fmt(score)}` }), thr != null && h("div", { class: "line" }, h("span", {}, `alert line ${fmt(thr)}`))),
    h("div", { class: "gauge-l" }, h("span", {}, "like normal traffic"), score != null && h("span", {}, "score ", h("b", {}, fmt(score))), h("span", {}, "unlike normal traffic")));
}
function sectionT(title, sub) { return h("div", { class: "sec-t" }, title, sub && h("small", {}, sub)); }

async function select(id) {
  S.sel = id;
  document.querySelectorAll("#tbl tbody tr").forEach((tr) => tr.classList.toggle("sel", +tr.dataset.id === id));
  document.querySelector(`#tbl tr[data-id="${id}"]`)?.scrollIntoView({ block: "nearest" });
  const pane = $("#detail");
  put(pane, h("div", { class: "skeleton", style: "width:40%;height:28px" }), h("div", { class: "skeleton" }), h("div", { class: "skeleton", style: "width:80%" }));
  let d;
  try { d = await api(`/api/events/${id}`); } catch { put(pane, h("div", { class: "empty" }, h("b", {}, "This flow is no longer kept"), "Only the newest 40,000 flows are kept in memory.")); return; }
  if (S.sel !== id) return;
  const e = d.event, col = V[e.verdict][2];
  const scores = Object.entries(d.scores).filter(([, p]) => p != null).sort((a, b) => b[1] - a[1]);
  const fits = scores.filter(([c, p]) => p >= (d.pass_marks[c] ?? 2)).map(([c]) => c);
  const unusual = e.novelty;
  const note = h("textarea", { placeholder: "Note for the audit log (optional). Notes never change the model.", maxlength: 500, "aria-label": "Review note" });
  const xbox = h("div", {}, h("div", { class: "skeleton" }), h("div", { class: "skeleton", style: "width:70%" }), h("div", { class: "skeleton", style: "width:85%" }));

  pane.style.setProperty("--vc", col);
  put(pane,
    h("div", { class: "d-head" }, h("span", { class: "vbig", style: `color:${col}` }, vname(e.verdict)),
      h("span", { class: "muted" }, `Flow ${e.id}`), e.status && h("span", { class: `status ${e.status}` }, STATUS[e.status])),
    h("div", { class: "d-sub" }, V[e.verdict][1], " · ", origin(e), e.src ? ` · ${mask(e.src)}` : "", e.incident ? " · part of an incident" : ""),
    h("div", { class: "sec-t", style: "margin-top:14px" }, "Flow features"),
    flowFacts(e.flow),
    h("div", { class: "sec-t", style: "margin-top:14px" }, "In short"),
    decisionPath(e, fits, scores.length > 0, col),
    h("p", { class: "d-sum" }, d.summary),
    e.conflict && h("div", { class: "warn" }, "Mixed signals: the classifier recognises a known attack, but the traffic is also unlike normal traffic. It may be a new variant of that attack, so escalate it."),
    e.error && h("div", { class: "warn" }, `Input check failed: ${e.error}`),

    h("div", { class: "sec" }, sectionT("The checks in detail", "two models, then a fixed rule"),
      h("div", { class: "step" },
        h("div", { class: "step-h" }, h("b", {}, "1. Is it unusual?"),
          unusual == null ? h("span", { class: "ans mid" }, "Not checked") : h("span", { class: `ans ${unusual ? "yes" : "no"}` }, unusual ? "Yes" : "No")),
        gauge(e.score, d.threshold, col),
        h("div", { class: "muted small" }, unusual == null ? "The unusual-traffic detector did not run on this flow."
          : `Unusualness ${fmt(e.score)} is ${unusual ? "above" : "below"} the alert line ${fmt(d.threshold)}. The detector learned only from normal traffic, so a high score means "unlike anything normal".`)),
      h("div", { class: "step" },
        h("div", { class: "step-h" }, h("b", {}, "2. Does it match a known attack?"),
          !scores.length ? h("span", { class: "ans mid" }, "Not checked")
            : fits.length === 1 && fits[0] !== "BENIGN" ? h("span", { class: "ans yes" }, `Yes: ${fits[0]}`)
            : fits.length === 1 ? h("span", { class: "ans no" }, "Only normal fits")
            : fits.length ? h("span", { class: "ans mid" }, "Several fit") : h("span", { class: "ans mid" }, "No class fits")),
        scores.length ? scores.map(([c, p]) => {
          const ok = p >= d.pass_marks[c];
          return h("div", { class: "crow" }, h("span", {}, c),
            h("div", { class: "cbar", title: `score ${pct(p)} · bar ${pct(d.pass_marks[c])}` }, h("i", { class: ok ? "fit" : "", style: `width:${100 * p}%${ok ? `;background:${c === "BENIGN" ? V.NORMAL[2] : V.KNOWN_ATTACK[2]}` : ""}` }), h("b", { style: `left:${100 * d.pass_marks[c]}%` })),
            h("span", { class: `fitlbl ${ok ? "yes" : "no"}` }, `${pct(p, 0)} · ${ok ? "fits" : "doesn't fit"}`));
        }) : h("div", { class: "muted small" }, "The attack classifier did not run on this flow."),
        scores.length > 0 && h("div", { class: "muted small", style: "margin-top:6px" }, "Bar = the classifier's score. White tick = the confidence bar that class must reach, set from held-back labelled data.")),
      h("div", { class: "step" },
        h("div", { class: "step-h" }, h("b", {}, "3. Which rule decided"), h("span", { class: "ans mid" }, `Rule ${d.rule} of 7`)),
        h("div", { class: "small" }, ruleSentence(d.rule)),
        h("details", {}, h("summary", {}, "See all 7 rules"), rulesTable(d.rule)))),

    h("div", { class: "sec" }, sectionT("What made it unusual", "compared with normal traffic, not proof of cause"), xbox),

    h("div", { class: "sec" }, sectionT("Your review", "saved to the audit log; never retrains the model"),
      h("div", { class: "actions" }, ACTIONS.map(([k, lab]) => h("button", { class: `btn${e.status === k ? " on" : ""}`, onclick: () => setStatus(id, k, note.value) }, lab))), note),
    h("details", {}, h("summary", {}, "Technical details (JSON)"), h("pre", {}, JSON.stringify(d.contract, null, 2))));

  try {
    let x = S.expCache.get(id);
    if (!x) { x = await api(`/api/events/${id}/explain`); S.expCache.set(id, x); }
    if (S.sel === id) put(xbox, explanation(x, e));
  } catch (err) { if (S.sel === id) put(xbox, h("div", { class: "muted" }, "The explanation could not be computed for this flow.")); }
}
function decisionPath(e, fits, classified, col) {
  const u = e.novelty, known = fits.length === 1 && fits[0] !== "BENIGN" ? fits[0] : null;
  return h("div", { class: "path" },
    h("div", { class: `q ${u == null ? "mid" : u ? "yes" : "no"}` }, h("small", {}, "Unlike normal traffic?"), h("b", {}, u == null ? "Not checked" : u ? "Yes" : "No")),
    h("span", { class: "arrow", "aria-hidden": "true" }, "+"),
    h("div", { class: `q ${!classified ? "mid" : known ? "yes" : "no"}` }, h("small", {}, "Matches a known attack?"),
      h("b", {}, !classified ? "Not checked" : known ? `Yes, ${known}` : fits.length === 1 ? "No, looks normal" : fits.length ? "Unsure" : "No")),
    h("span", { class: "arrow", "aria-hidden": "true" }, "="),
    h("div", { class: "res", style: `color:${col};border-color:${col}77;background:${col}14` }, h("small", {}, "Verdict"), h("b", {}, vname(e.verdict))));
}
function ruleSentence(r) {
  const [u, f, v, extra] = RULES[r - 1];
  return r === 7 ? "The input was broken or a model failed, so the system refused to call it normal."
    : `Unusual: ${u.toLowerCase()}. Known classes that fit: ${f.toLowerCase()}. So the verdict is ${vname(v)}${extra ? ` (${extra})` : ""}.`;
}
function rulesTable(hit) {
  return h("table", { class: "rules" },
    h("tr", {}, h("th", {}, "#"), h("th", {}, "Unusual?"), h("th", {}, "Known classes that fit"), h("th", {}, "Verdict")),
    RULES.map(([u, f, v, extra], i) => h("tr", { class: hit === i + 1 ? "hit" : "" }, h("td", {}, i + 1), h("td", {}, u), h("td", {}, f),
      h("td", {}, pill(v), extra && h("div", { class: "muted small" }, extra)))));
}
function explanation(x, e) {
  const out = [];
  const dev = x.baseline_deviation || [];
  if (dev.length) out.push(h("div", { class: "reason" }, dev.map((b) => h("div", { class: "rcard" },
    h("div", { class: "rt" }, h("div", {}, h("b", {}, cap(b.description)), h("div", { class: "fname" }, b.feature)),
      b.relative_deviation >= 1 && h("span", { class: "xtag" }, b.relative_deviation >= 10 ? "Far from normal" : b.relative_deviation >= 3 ? "Well outside normal" : "Outside normal")),
    h("div", { class: "rv" }, "Value ", h("strong", {}, num(b.value)), `. Normal traffic is usually around ${num(b.benign_median)}, and 95% is at or below ${num(b.benign_p95)}.`)))));
  else out.push(h("div", { class: "muted" }, "No feature comparison is available for this flow."));

  const s = x.shap || {};
  out.push(h("div", { class: "sec" }, sectionT("What the classifier relied on", s.top_features ? `pushes towards or away from "${s.explained_class}"` : "")));
  if (s.top_features && s.top_features.length) {
    const mx = Math.max(...s.top_features.map((t) => Math.abs(t.contribution))) || 1;
    out.push(h("div", {}, s.top_features.map((t) => {
      const w = (50 * Math.abs(t.contribution)) / mx, towards = t.contribution > 0;
      return h("div", { class: "shaprow" },
        h("div", { class: "sd" }, cap(t.description), h("small", {}, `${t.feature} = ${t.value}`)),
        h("div", { title: `contribution ${t.contribution.toFixed(4)}` },
          h("div", { class: "sbar" }, h("i", { style: `${towards ? "left:50%" : `left:${50 - w}%`};width:${w}%;background:${towards ? LIME : INK3}` })),
          h("div", { class: "muted small", style: "text-align:center;margin-top:4px" }, towards ? `Pushes towards ${s.explained_class}` : "Pushes away")));
    })), h("div", { class: "muted small", style: "margin-top:6px" }, "TreeSHAP of the attack classifier: how much each value moved its score. It shows what the model used, not what caused the traffic."));
  } else out.push(h("div", { class: "muted" }, `Not available: ${s.reason || "the classifier did not run"}.`));

  out.push(h("div", { class: "sec" }, sectionT("Suggested next step"), h("div", { class: "hint" }, x.defensive_action || "No action suggested.")));
  if (x.explanation_latency_ms != null) out.push(h("div", { class: "muted small", style: "margin-top:6px" }, `Explained in ${x.explanation_latency_ms.toFixed(0)} ms`));
  return out;
}
async function setStatus(id, status, note) {
  try {
    const e = await api(`/api/events/${id}/triage`, { status, note });
    const row = S.rows.find((r) => r.id === id); if (row) row.status = e.status;
    const ev = S.byId.get(id); if (ev) ev.status = e.status;
    renderTable(); select(id);
    toast(`Flow ${id}: ${STATUS[status].toLowerCase()}`, "Saved to the audit log", "info");
  } catch (err) { toast("Could not save the review", String(err), "info"); }
}
function openEvent(id) {
  const e = S.byId.get(id);
  if (e && !S.filterV.has(e.verdict)) { S.filterV.add(e.verdict); chipsInit(); }
  $("#sfilter").value = ""; $("#search").value = ""; $("#ofilter").value = e?.source || "";
  stepDone(3);
  show("alerts"); loadAlerts().then(() => select(id));
}
async function inject(sc, extra = {}) {
  try {
    const r = await api("/api/inject", { scenario: sc, count: Math.min(500, Math.max(1, +$("#simcount").value || 25)), rate: 10, ...extra });
    const parts = Object.entries(r.breakdown || {}).map(([k, n]) => `${n} ${k}`).join(" · ");
    toast(`Sending ${r.queued} flows`, parts || r.scenario, "info");
  } catch (e) { toast("Could not send traffic", String(e).replace(/^Error: \d+ /, ""), "info"); }
}
// What to expect for each kind of attack, in plain words.
const EXPECT = {
  known: [V.KNOWN_ATTACK[2], "Known to the model. Expect: Known attack."],
  hidden: [V.UNKNOWN_ANOMALY[2], "Hidden from training. Expect: Possible zero-day."],
  rare: [V.UNKNOWN_ANOMALY[2], "A family the model never trained on. Expect: Possible zero-day or Unclear."],
  new: [V.UNCERTAIN_REVIEW[2], "A new type in a known family. It may be recognised, flagged as unusual, or missed."],
};
async function loadAttackTypes() {
  try {
    const r = await api("/api/attack-types");
    const fams = [...new Set(r.types.map((t) => t.family))];
    const short = { known: "known", hidden: "hidden: zero-day", rare: "rare, never trained", new: "new type" };
    S.atypes = new Map(r.types.map((t) => [t.type, t]));
    r.types.forEach((t) => S.atypes.set(t.type, t));
    fams.forEach((f) => S.atypes.set(f, { type: f, family: f, status: r.types.find((t) => t.family === f).status === "hidden" ? "hidden"
      : r.types.find((t) => t.family === f).status === "rare" ? "rare" : "known", family_all: true }));
    put($("#atype"), fams.map((f) => h("optgroup", { label: `${f} attacks` },
      h("option", { value: f }, `Any ${f} attack`),
      r.types.filter((t) => t.family === f).map((t) => h("option", { value: t.type }, `${t.type} · ${short[t.status]} (${int(t.count)})`)))));
    const keep = S.atypeSel && S.atypes.has(S.atypeSel) ? S.atypeSel : r.types.find((t) => t.status === "known")?.type;
    if (keep) $("#atype").value = keep;
    noteAttack();
  } catch (e) { put($("#atype-note"), "Attack list unavailable."); }
}
function noteAttack() {
  const t = S.atypes?.get($("#atype").value); if (!t) return;
  S.atypeSel = t.type;
  const [col, txt] = EXPECT[t.status];
  put($("#atype-note"), dot(col), txt);
  $("#mix-sub").textContent = `70% normal · 15% zero-day · 15% ${t.family_all ? `${t.type} attacks` : t.type}, shuffled`;
}

// ---------------- how it decides ----------------
async function loadHow() {
  const m = S.model || (S.model = await api("/api/model"));
  const bars = Object.entries(m.classes_cal);
  put($("#pipe"),
    h("div", { class: "pnode" }, h("div", { class: "pn" }, "Step 1"), h("b", {}, "Input check"),
      h("p", {}, `Each flow must have all ${m.n_features} expected values with the right types. Broken records stop here as "Bad record".`)),
    h("div", { class: "pnode duo gate" }, h("div", { class: "pn" }, "Step 2 · two detectors"),
      h("div", {}, h("b", {}, "Unusual-traffic detector"), h("p", {}, "An Isolation Forest trained only on normal traffic. It scores how unlike normal a flow is."),
        h("div", { class: "pv" }, `Alert line ${fmt(m.threshold)}: about ${pct(m.target_fpr, 0)} of normal flows cross it (set on ${int(m.n_anom_cal)} normal flows).`)),
      h("div", {}, h("b", {}, "Attack classifier"), h("p", {}, `A gradient-boosted tree classifier that knows ${m.classes.join(", ")}.`),
        h("div", { class: "pv" }, "Each class has its own confidence bar. A class fits only if its score reaches the bar."))),
    h("div", { class: "pnode" }, h("div", { class: "pn" }, "Step 3"), h("b", {}, "Decision rules"), h("p", {}, "Seven fixed rules combine both answers. No model output can turn a failure into Normal.")),
    h("div", { class: "pnode" }, h("div", { class: "pn" }, "Step 4"), h("b", {}, "Verdict"),
      h("div", { class: "pv" }, ORDER.slice(0, 3).concat("NORMAL").map((v) => h("div", {}, pill(v))))),
    h("div", { class: "pnode" }, h("div", { class: "pn" }, "Step 5"), h("b", {}, "Urgency and explanation"),
      h("p", {}, "Urgency (0-100) sorts the alert list; it never changes the verdict. Every alert explains which check and rule decided it.")));
  put($("#rules"), [...rulesTable(0).childNodes]);
  put($("#passmarks"), h("tr", {}, h("th", {}, "Class"), h("th", {}, "Confidence bar"), h("th", {}, "Set on"), h("th", {}, "")),
    bars.map(([c, b]) => h("tr", {}, h("td", {}, h("b", {}, c)), h("td", { class: "num" }, pct(b.pass_mark)), h("td", { class: "num" }, `${int(b.n)} flows`),
      h("td", { class: "muted small" }, b.fallback ? "Too few examples: always fits" : b.pass_mark < 0.9 ? "Lower bar: less certain class" : ""))));
  put($("#passnote"), `${m.holdout} attacks were removed from training and calibration, so they act as a zero-day this model has never seen.`,
    m.rare.length ? ` ${m.rare.join(", ")} had too few examples to learn reliably and is treated the same way.` : "");
  const imp = m.importance.slice(0, 8), top = imp[0]?.importance || 1;
  put($("#imp"), imp.map((f) => barRow(cap(f.description), f.feature, f.importance / top, LIME, pct(f.importance, 1), null, false)),
    h("p", { class: "muted small" }, "Longer bar = the classifier uses this feature more often to separate attack types."));
  const G = [["Zero-day", "An attack type the model has never seen. Here: a type removed from training on purpose."],
    ["Unusualness score", "How unlike normal traffic a flow is. Higher means less normal."],
    ["Alert line", `The unusualness level that triggers an alert (${fmt(m.threshold)}). Set so about ${pct(m.target_fpr, 0)} of normal flows cross it.`],
    ["Known attack", "A flow that clearly fits exactly one attack type the classifier learned."],
    ["Fits / confidence bar", "A class fits a flow when the classifier's score for it reaches that class's bar."],
    ["Unclear", "Not unusual, but no single class fits. A person should look."],
    ["Urgency", "A 0-100 score for sorting the alert list. It is a heuristic, not a probability."],
    ["Incident", "Three or more alerts from the same host within 30 seconds, grouped. No alert is hidden."],
    ["Traffic shift", "How far recent traffic has moved from the training data. A warning only."],
    ["False alarm", "Your review that an alert was not a real attack. Saved for audit; never retrains the model."],
    ["Held-out family", `The attack type kept out of training for this model: ${m.holdout}.`]];
  put($("#gloss"), G.flatMap(([t, d]) => [h("dt", {}, t), h("dd", {}, d)]));
}
const wrap = (s, n) => { const out = []; let line = ""; for (const w of s.split(" ")) { if ((line + " " + w).trim().length > n && line) { out.push(line); line = w; } else line = (line + " " + w).trim(); } out.push(line); return out.slice(0, 2).join("<br>") + (out.length > 2 ? "…" : ""); };
const bundleName = (b) => { const [ds, exp] = b.split("/"); const m = /^lofo-(.+?)-(grouped|random)(-noport)?$/.exec(exp || "");
  const d = { nsl_kdd: "NSL-KDD", cic_ids2017: "CIC-IDS2017" }[ds] || ds;
  if (!m) return `${d} · ${exp}`;
  const FAM = { dos: "DoS", ddos: "DDoS", probe: "Probe", r2l: "R2L", u2r: "U2R", portscan: "PortScan", bot: "Bot", webattack: "WebAttack", bruteforce: "BruteForce" };
  const fam = FAM[m[1]] || m[1].replace(/^./, (c) => c.toUpperCase());
  return `${d} · hides ${fam}${m[2] === "random" ? " · random split (audit)" : ""}${m[3] ? " · no port" : ""}`; };

// ---------------- model results ----------------
async function loadEval() {
  const m = await api("/api/metrics");
  const cols = [["Model", (r) => bundleName(r.bundle)], ["Hidden attack", (r) => r.holdout],
    ["Hidden attack flagged", (r) => pct(r.alert_recall)], ["Hidden attack over alert line", (r) => pct(r.novelty_recall)],
    ["Zero-day alerts that were real", (r) => pct(r.unknown_precision)], ["Normal flows alerted", (r) => pct(r.auto_alert_fpr)],
    ["Normal flows sent to review", (r) => pct(r.review_rate)], ["Known-class accuracy (macro F1)", (r) => fmt(r.macro_f1)], ["Flows per second", (r) => int(Math.round(r.flows_per_s))]];
  put($("#exp thead"), h("tr", {}, cols.map((c) => h("th", {}, c[0]))));
  // Best value per metric column (lower is better for the "Normal flows ..." burden columns).
  const val = (c, r) => parseFloat(String(c[1](r)).replace(/,/g, ""));
  const best = cols.map((c, i) => { if (i < 2) return null; const vs = m.experiments.map((r) => val(c, r)).filter(Number.isFinite);
    return vs.length ? (c[0].startsWith("Normal flows") ? Math.min(...vs) : Math.max(...vs)) : null; });
  put($("#exp tbody"), m.experiments.map((r) => h("tr", { class: r.bundle === m.current.bundle ? "sel" : "", onclick: () => switchBundle(r.bundle), title: "Use this model in the console" },
    cols.map((c, i) => h("td", { class: i > 1 ? `num${val(c, r) === best[i] ? " best" : ""}` : "" }, c[1](r))))));
  const cur = m.current, lofo = cur.lofo, b = cur.benign;
  put($("#eval-kpis"),
    kpi("Hidden attack", lofo.holdout_family, `${int(lofo.n)} test flows, never seen in training`),
    kpi("Flagged", pct(lofo.system_alert_recall?.rate), "Hidden-attack flows not called normal", V.UNKNOWN_ANOMALY[2]),
    kpi("Over the alert line", pct(lofo.novelty_gate_recall?.rate), "Hidden-attack flows the detector caught"),
    kpi("Zero-day alerts that were real", pct(lofo.unknown_anomaly_precision?.rate), "Possible zero-days that were the hidden attack"),
    kpi("Normal flows alerted", pct(b.auto_alert_fpr?.rate), `Target for the alert line: ${pct(b.target_fpr, 0)}`, V.NORMAL[2]),
    kpi("Normal flows to review", pct(b.benign_review_rate?.rate), "Work created for a person"),
    kpi("Confidence-bar coverage", pct(cur.conformal?.empirical_coverage), `Target ${pct(cur.conformal?.target_coverage, 0)}; test data differs from training`));
  const pc = cur.per_class || {};
  put($("#recog"), cur.confusion ? cur.confusion.labels.map((c) => { const r = pc[c]?.recall ?? 0;
    return barRow(c === "BENIGN" ? "Normal traffic" : c, `${int(pc[c]?.support)} test flows`, r, r >= 0.8 ? V.NORMAL[2] : r >= 0.5 ? V.UNCERTAIN_REVIEW[2] : V.UNKNOWN_ANOMALY[2], pct(r, 0), null, false); }) : "—",
    h("p", { class: "muted small" }, "Cyan 80% or more · violet 50-80% · red below 50%."));
  const vbl = cur.verdicts_by_label;
  const OUT = [["Alerted", V.UNKNOWN_ANOMALY[2], ["UNKNOWN_ANOMALY", "KNOWN_ATTACK"]], ["Sent to review", V.UNCERTAIN_REVIEW[2], ["UNCERTAIN_REVIEW", "DEGRADED_REVIEW", "PROCESSING_ERROR"]], ["Called normal", V.NORMAL[2], ["NORMAL"]]];
  put($("#outcome"), h("div", { class: "legend" }, OUT.map(([n, col]) => h("span", {}, dot(col), n))),
    Object.keys(vbl).sort((a, b) => (a === "BENIGN") - (b === "BENIGN")).map((lab) => {
      const tot = Object.values(vbl[lab]).reduce((a, b) => a + b, 0) || 1;
      const parts = OUT.map(([n, col, vs]) => [n, col, vs.reduce((a, v) => a + (vbl[lab][v] || 0), 0) / tot]);
      const name = lab === "BENIGN" ? "Normal" : lab + (lab === cur.lofo.holdout_family ? " (hidden)" : (cur.rare && lab in cur.rare) ? " (rare)" : "");
      return h("div", { class: "orow" }, h("b", {}, name), h("div", { class: "stack", title: parts.map(([n, , f]) => `${n} ${pct(f, 0)}`).join(" · ") },
        parts.filter(([, , f]) => f > 0).map(([n, col, f]) => h("i", { style: `width:${f * 100}%;background:${col}` }, f >= 0.08 ? pct(f, 0) : ""))));
    }),
    h("p", { class: "muted small" }, "For attack types, more red is better. For normal traffic, more cyan is better."));
  const plain = { holdout_absent_from_train_validation_conf_cal: "The hidden attack never appears in training or calibration data",
    anom_cal_benign_only: "The alert line was set on normal traffic only", partitions_disjoint: "No flow is used in two data splits",
    anom_cal_conf_cal_row_overlap: "The two calibration sets share no flows" };
  put($("#leak"), Object.entries(cur.leakage.checks).map(([k, v]) => {
    const ok = v === true || v === 0;
    return h("li", {}, h("span", { class: ok ? "ok" : "bad", "aria-label": ok ? "passed" : "failed" }, ok ? "✓" : "✗"), plain[k] || k.replaceAll("_", " "));
  }), cur.leakage.limitations && h("li", {}, h("span", { class: "muted" }, "ⓘ"), h("span", { class: "muted" }, cur.leakage.limitations)));
  const p = cur.performance;
  put($("#perf"), [["Flows per second", int(Math.round(p.throughput_flows_per_s))], ["Time per batch", `${fmt(p.batch_latency_ms_median, 0)} ms for ${int(p.batch_size)} flows`],
    ["Time per flow", `${fmt(p.per_flow_latency_ms, 2)} ms`], ["Time per explanation", `${fmt(p.explanation_latency_ms_mean, 0)} ms (not included above)`],
    ["Processor", p.hardware || "—"]].flatMap(([k, v]) => [h("span", {}, k), h("span", {}, v)]));
}

// ---------------- navigation ----------------
function show(view) {
  S.view = view;
  document.querySelectorAll(".tabs button").forEach((b) => { b.classList.toggle("on", b.dataset.view === view); b.setAttribute("aria-selected", String(b.dataset.view === view)); });
  document.querySelectorAll(".view").forEach((v) => v.classList.toggle("on", v.id === `view-${view}`));
  if (view === "alerts") { loadAlerts(); if (!S.sel) put($("#detail"), h("div", { class: "empty" }, h("b", {}, "Pick an alert"), "Select a row to see why the system flagged it.")); }
  if (view === "eval") loadEval().catch((e) => toast("Could not load results", String(e), "info"));
  if (view === "how") loadHow().catch((e) => toast("Could not load the model", String(e), "info"));
  if (view === "monitor") { lastPlot = 0; renderMonitor(true); }
  requestAnimationFrame(() => document.querySelectorAll(`#view-${view} .js-plotly-plot`).forEach((g) => Plotly.Plots.resize(g)));
}
async function switchBundle(b) {
  if (S.state && b === S.state.bundle) return;
  $("#conn").textContent = "Loading model…"; resetLocal();
  await api("/api/bundle", { bundle: b }); connect(); loadAttackTypes();
  if (S.view === "eval") loadEval(); if (S.view === "how") loadHow();
}

// ---------------- tooltips ----------------
function tipShow(el) {
  const t = $("#tip"); t.textContent = el.dataset.tip; t.hidden = false;
  const r = el.getBoundingClientRect(), w = t.offsetWidth, hh = t.offsetHeight;
  t.style.left = `${Math.max(8, Math.min(window.innerWidth - w - 8, r.left + r.width / 2 - w / 2))}px`;
  t.style.top = `${r.bottom + 8 + hh > window.innerHeight ? r.top - hh - 8 : r.bottom + 8}px`;
}
const tipHide = () => { $("#tip").hidden = true; };

document.addEventListener("DOMContentLoaded", () => {
  document.querySelectorAll(".tabs button").forEach((b) => b.addEventListener("click", () => show(b.dataset.view)));
  $("#bundle").addEventListener("change", (e) => switchBundle(e.target.value));
  const toggleReplay = () => api("/api/replay", { action: S.state?.replay.running ? "pause" : "start", rate: +$("#rate").value });
  $("#play").addEventListener("click", toggleReplay);
  $("#rate").addEventListener("change", () => api("/api/replay", { action: S.state?.replay.running ? "start" : "pause", rate: +$("#rate").value }));
  $("#reset").addEventListener("click", async () => { resetLocal(); await api("/api/replay", { action: "reset" }); connect(); });
  $("#mask").addEventListener("change", () => { renderFeed(); renderTable(); if (S.sel) select(S.sel); });
  document.querySelectorAll(".sim-btn[data-sc]").forEach((b) => b.addEventListener("click", () => inject(b.dataset.sc)));
  $("#atype").addEventListener("change", noteAttack);
  $("#send-attack").addEventListener("click", () => inject("attack", { attack: $("#atype").value }));
  $("#send-mix").addEventListener("click", () => inject("mix", { attack: $("#atype").value }));
  loadAttackTypes();
  document.querySelectorAll("#feedsrc button").forEach((b) => b.addEventListener("click", () => {
    S.feedSrc = b.dataset.src; document.querySelectorAll("#feedsrc button").forEach((x) => x.classList.toggle("on", x === b)); renderFeed(); }));
  ["#sfilter", "#ofilter"].forEach((q) => $(q).addEventListener("change", loadAlerts));
  let st; $("#search").addEventListener("input", () => { clearTimeout(st); st = setTimeout(loadAlerts, 250); });

  if (store.get("megallen.introHidden") === "1") $("#intro").hidden = true;
  $("#intro-close").addEventListener("click", () => { $("#intro").hidden = true; store.set("megallen.introHidden", "1"); });
  document.querySelectorAll("#intro [data-act]").forEach((b) => b.addEventListener("click", () => {
    if (b.dataset.act === "start" && !S.state?.replay.running) toggleReplay();
    if (b.dataset.act === "zeroday") inject("zero-day");
    if (b.dataset.act === "open") { const z = newestZeroDay(); z ? openEvent(z.id) : toast("No possible zero-days yet", "Send a zero-day attack first", "info"); }
  }));

  document.addEventListener("mouseover", (e) => { const el = e.target.closest?.(".info[data-tip]"); if (el) tipShow(el); });
  document.addEventListener("mouseout", (e) => { if (e.target.closest?.(".info[data-tip]")) tipHide(); });
  document.addEventListener("focusin", (e) => { if (e.target.matches?.(".info[data-tip]")) tipShow(e.target); });
  document.addEventListener("focusout", (e) => { if (e.target.matches?.(".info[data-tip]")) tipHide(); });

  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") tipHide();
    if (e.target.matches("input, textarea, select")) { if (e.key === "Escape") e.target.blur(); return; }
    if ((e.key === "Enter" || e.key === " ") && e.target.matches(".kpi.click, .qrow")) { e.preventDefault(); e.target.click(); return; }
    if (e.key === "/") { e.preventDefault(); show("alerts"); $("#search").focus(); return; }
    if (S.view !== "alerts" || !S.rows.length) return;
    const i = S.rows.findIndex((r) => r.id === S.sel);
    if (e.key === "j") select(S.rows[Math.min(S.rows.length - 1, i + 1)].id);
    if (e.key === "k") select(S.rows[Math.max(0, i - 1)].id);
    const k = { i: "investigating", e: "escalated", r: "resolved", f: "false_positive" }[e.key];
    if (k && S.sel) setStatus(S.sel, k, "");
  });
  window.__errs = [];  // read by the headless screenshot check
  window.addEventListener("error", (e) => window.__errs.push(e.message));
  window.addEventListener("unhandledrejection", (e) => window.__errs.push(String(e.reason)));
  // The stream only replays the newest events, so fetch earlier zero-days you sent (feed survives a page reload).
  api("/api/events?verdict=UNKNOWN_ANOMALY&source=live&limit=200").then((rows) => {
    for (const e of rows) if (!S.byId.has(e.id)) { S.events.push(e); S.byId.set(e.id, e); }
    S.events.sort((a, b) => a.id - b.id); renderFeed();
  }).catch(() => {});
  $("#help").addEventListener("click", openHelp);
  $("#help-close").addEventListener("click", () => $("#helpdlg").close());
  $("#helpdlg").addEventListener("click", (ev) => { if (ev.target.id === "helpdlg") $("#helpdlg").close(); });
  chipsInit(); connect();
});
