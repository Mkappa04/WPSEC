// Dashboard di wpsec. Regola: i dati (che possono venire dal sito analizzato) entrano nel
// DOM solo come testo (textContent), mai come HTML.
"use strict";

// ------------------------------------------------------------ vocabolario
const FINDING = {
  confirmed: ["Confermato", "bad"], not_present: ["Non rilevato", "ok"],
  inconclusive: ["Da verificare", "warn"], false_positive: ["Falso positivo", "neutral"],
  not_applicable: ["Non applicabile", "neutral"], error: ["Errore", "err"], info: ["Contesto", "neutral"],
  candidate: ["Da validare", "warn"], not_detected: ["Da validare", "warn"],
};
const SCAN = {
  completed: ["Completata", "done"], running: ["In corso", "live"], pending: ["In avvio", "live"],
  failed: ["Fallita", "err"], cancelled: ["Annullata", "neutral"],
};
const OUTCOME = {
  new: ["Nuovo", "new"], resolved: ["Risolto", "resolved"], still_open: ["Ancora presente", "open"],
  unchanged: ["Invariato", "neutral"], not_comparable: ["Non confrontabile", "warn"], info: ["Contesto", "neutral"],
};
const AGENT = { pending: ["In attesa", "neutral"], running: ["In corso", "live"], completed: ["Completato", "done"],
  failed: ["Fallito", "err"], skipped: ["Saltato", "neutral"] };
const SEV = { critical: "Critica", high: "Alta", medium: "Media", low: "Bassa", info: "Info" };
const SEV_ORDER = ["critical", "high", "medium", "low", "info"];
const CONFIDENCE = { high: "alta", medium: "media", low: "bassa" };

let pollTimer = null;
let routeSeq = 0;
let firstRoute = true;   // al primo caricamento il focus resta all'inizio (link "Vai al contenuto")

// ------------------------------------------------------------ DOM
function el(tag, attrs = {}, ...children) {
  const svg = ["svg", "g", "line", "path", "circle", "text", "rect", "title"].includes(tag);
  const n = svg ? document.createElementNS("http://www.w3.org/2000/svg", tag) : document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.setAttribute("class", v);
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, "");
    else n.setAttribute(k, String(v));
  }
  append(n, children);
  return n;
}
function append(n, children) {
  for (const c of children) {
    if (c === null || c === undefined || c === false) continue;
    if (Array.isArray(c)) append(n, c);
    else n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
}
const view = () => document.getElementById("view");
function show(...nodes) { const v = view(); v.replaceChildren(); append(v, nodes); }
const mono = (t, cls = "") => el("span", { class: `mono ${cls}` }, t);
const st = ([text, cls]) => el("span", { class: `st ${cls}` }, text);
const findingSt = (s) => st(FINDING[s] || [s, "neutral"]);
const scanSt = (r) => st(r.live ? SCAN.running : SCAN[r.status] || [r.status, "neutral"]);
const link = (href, text, attrs = {}) => el("a", { href, ...attrs }, text);

function fmtDate(s, withSeconds = true) {
  if (!s) return "-";
  const d = new Date(s);
  const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getDate())}/${p(d.getMonth() + 1)}/${d.getFullYear()} ${p(d.getHours())}:${p(d.getMinutes())}` +
    (withSeconds ? `:${p(d.getSeconds())}` : "");
}
const shortDate = (s) => { const d = new Date(s); const p = (n) => String(n).padStart(2, "0");
  return `${p(d.getDate())}/${p(d.getMonth() + 1)} ${p(d.getHours())}:${p(d.getMinutes())}`; };
const siteName = (target) => target.replace(/^https?:\/\//, "").replace(/\/$/, "");
const shortId = (id) => id;
const enc = encodeURIComponent;

function sevText(sev) {
  const parts = SEV_ORDER.filter((k) => k !== "info" && sev && sev[k]).map((k) => `${SEV[k]} ${sev[k]}`);
  return parts.length ? el("span", { class: "sev" }, parts.join(", ")) : el("span", { class: "dim" }, "nessuno");
}

// ------------------------------------------------------------ API
class ApiError extends Error {
  constructor(message, status, path) { super(message); this.status = status; this.path = path; }
}
async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {} };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  let r;
  try { r = await fetch(path, init); } catch {
    throw new ApiError("Il server della dashboard non risponde. Controlla che `python main.py serve` sia ancora in esecuzione.", 0, path);
  }
  if (r.status === 204) return null;
  const data = await r.json().catch(() => null);
  if (!r.ok) {
    let d = data && data.detail;
    if (Array.isArray(d)) d = d.map((e) => `${(e.loc || []).slice(1).join(".")}: ${e.msg}`).join("; ");
    throw new ApiError(d || `Il server ha risposto con l'errore HTTP ${r.status}.`, r.status, path);
  }
  return data;
}

// ------------------------------------------------------------ stati della pagina
function contextBar({ crumbs = [], title, meta = [], tabs = null }) {
  return el("header", { class: "context" },
    crumbs.length ? el("nav", { "aria-label": "Percorso" }, el("ol", { class: "crumbs" },
      crumbs.map(([text, href]) => el("li", {}, href ? link(href, text) : el("span", { "aria-current": "page" }, text))))) : null,
    el("h1", {}, title),
    meta.length ? el("dl", { class: "meta" }, meta.filter(Boolean).map(([k, v]) => el("div", {}, el("dt", {}, k), el("dd", {}, v)))) : null,
    tabs);
}
function loading(text) { return el("p", { class: "loading", role: "status" }, text); }
function emptyState(title, text, ...actions) {
  return el("section", { class: "panel state" }, el("h2", {}, title), el("p", {}, text),
    actions.length ? el("div", { class: "actions" }, actions) : null);
}
function errorState(err, retry) {
  const notFound = err.status === 404;
  return el("section", { class: "panel state error", role: "alert" },
    el("h2", {}, notFound ? "Record non trovato" : "Dati non disponibili"),
    el("p", {}, err.message),
    err.path ? el("p", { class: "mono" }, `${err.status ? `HTTP ${err.status} · ` : ""}${err.path}`) : null,
    el("div", { class: "actions" },
      retry ? el("button", { class: "quiet", onclick: retry }, "Riprova") : null,
      link("#/scans", "Torna allo storico")));
}
function notice(text, kind = "") { return el("div", { class: `notice ${kind}`, role: "status" }, text); }

// ------------------------------------------------------------ dati comuni
async function loadScans(limit = 500) { return api(`/api/scans?limit=${limit}`); }
function bySite(rows) {
  const m = new Map();
  for (const r of rows) { if (!m.has(r.target)) m.set(r.target, []); m.get(r.target).push(r); }
  return m;   // ogni elenco resta dal più recente
}
const completed = (rows) => rows.filter((r) => r.status === "completed" && !r.live);
function previousCompleted(rows, r) {
  return completed(rows).find((x) => x.target === r.target && x.started_at < r.started_at) || null;
}

// ------------------------------------------------------------ panoramica
async function viewOverview() {
  const rows = await loadScans();
  const ctx = contextBar({ title: "Panoramica", meta: rows.length ? [
    ["Siti", mono(String(bySite(rows).size))], ["Scansioni", mono(String(rows.length))],
    ["In corso", mono(String(rows.filter((r) => r.live).length))],
    ["Ultima attività", mono(fmtDate(rows[0].started_at))]] : [] });
  if (!rows.length) {
    return show(ctx, emptyState("Nessuna scansione registrata",
      "Registra un'autorizzazione per il sito (o per il laboratorio locale), poi avvia la prima scansione.",
      link("#/new", "Nuova scansione", { class: "button" }), link("#/auth", "Autorizzazioni")));
  }
  const sites = [...bySite(rows).entries()];
  const table = el("table", { class: "stack" },
    el("thead", {}, el("tr", {}, ["Sito", "Ultima scansione", "Stato", "Confermati", "Gravità", "Azioni"]
      .map((h, i) => el("th", { class: i === 3 ? "num" : null, scope: "col" }, h)))),
    el("tbody", {}, sites.map(([target, list]) => {
      const last = list[0];
      const done = completed(list);
      const prev = done[0] && done[0].id === last.id ? done[1] : done[0];
      let delta = null;
      if (last.status === "completed" && prev) {
        const d = last.confirmed - prev.confirmed;
        delta = el("span", { class: "sub" }, d === 0 ? "come la precedente" : `${d > 0 ? "+" : "−"}${Math.abs(d)} dalla precedente`);
      }
      return el("tr", {},
        el("td", { class: "wide" }, link(`#/scans?target=${enc(target)}`, siteName(target), { class: "site" }),
          el("span", { class: "sub" }, `${list.length} ${list.length === 1 ? "scansione" : "scansioni"}`)),
        el("td", { "data-label": "Ultima scansione" }, mono(fmtDate(last.started_at, false)),
          last.label ? el("span", { class: "sub" }, last.label) : null),
        el("td", { "data-label": "Stato" }, scanSt(last)),
        el("td", { class: "num", "data-label": "Confermati" }, mono(String(last.confirmed)), delta),
        el("td", { "data-label": "Gravità" }, sevText(last.severity)),
        el("td", { class: "wide" }, el("div", { class: "actions" },
          link(`#/scan/${enc(last.id)}`, "Apri l'ultima"),
          done.length >= 2 ? link(`#/compare?before=${enc(done[1].id)}&after=${enc(done[0].id)}`, "Confronta le ultime due") : null,
          done.length >= 2 ? link(`#/trend?target=${enc(target)}`, "Andamento") : null)));
    })));
  show(ctx, el("div", { class: "panel" }, table));
}

// ------------------------------------------------------------ storico
async function viewScans(q) {
  const all = await loadScans();
  const targets = [...bySite(all).keys()];
  const target = q.get("target") || "";
  const rows = target ? all.filter((r) => r.target === target) : all;
  const filter = el("select", { id: "f-target", onchange: (e) => {
    location.hash = e.target.value ? `#/scans?target=${enc(e.target.value)}` : "#/scans"; } },
  el("option", { value: "" }, `Tutti i siti (${targets.length})`),
  targets.map((t) => el("option", { value: t, selected: t === target }, siteName(t))));
  const ctx = contextBar({
    crumbs: target ? [["Storico", "#/scans"], [siteName(target)]] : [],
    title: target ? `Storico di ${siteName(target)}` : "Storico",
    meta: [["Scansioni", mono(String(rows.length))],
      target ? ["Completate", mono(String(completed(rows).length))] : null] });
  if (!all.length) {
    return show(ctx, emptyState("Lo storico è vuoto", "Le scansioni avviate compaiono qui, dalla più recente.",
      link("#/new", "Nuova scansione", { class: "button" })));
  }
  const table = el("table", { class: "stack" },
    el("thead", {}, el("tr", {}, ["Sito", "Data", "Stato", "Confermati", "Da verificare", "Gravità", "Azioni"]
      .map((h, i) => el("th", { scope: "col", class: [3, 4].includes(i) ? "num" : null }, h)))),
    el("tbody", {}, rows.map((r) => {
      const prev = previousCompleted(all, r);
      return el("tr", {},
        el("td", { class: "wide" }, link(`#/scan/${enc(r.id)}`, siteName(r.target), { class: "site" }),
          el("span", { class: "sub" }, r.label ? `${r.label} · ` : "", mono(shortId(r.id)),
            r.source !== "v4" ? " · importata dalla v3" : "")),
        el("td", { "data-label": "Data" }, mono(fmtDate(r.started_at))),
        el("td", { "data-label": "Stato" }, scanSt(r)),
        el("td", { class: "num", "data-label": "Confermati" }, mono(String(r.confirmed))),
        el("td", { class: "num", "data-label": "Da verificare" }, mono(String(r.inconclusive))),
        el("td", { "data-label": "Gravità" }, sevText(r.severity)),
        el("td", { class: "wide" }, el("div", { class: "actions" },
          link(`#/scan/${enc(r.id)}`, "Dettaglio"),
          r.live ? null : link(`#/scan/${enc(r.id)}/report`, "Report"),
          r.status === "completed" && prev ? link(`#/compare?before=${enc(prev.id)}&after=${enc(r.id)}`, "Confronta con la precedente") : null)));
    })));
  show(ctx, el("div", { class: "toolbar" }, el("label", { class: "field", for: "f-target" }, "Sito", filter)),
    rows.length ? el("div", { class: "panel" }, table)
      : emptyState("Nessuna scansione per questo sito", "Scegli un altro sito o mostra tutto lo storico.", link("#/scans", "Mostra tutto")));
}

// ------------------------------------------------------------ dettaglio
const TABS = [["", "Riepilogo"], ["findings", "Rilievi"], ["agents", "Agenti"], ["report", "Report"]];

function scanContext(s, tab) {
  const base = `#/scan/${enc(s.id)}`;
  const confirmedN = s.findings.filter((f) => f.status === "confirmed").length;
  return contextBar({
    crumbs: [["Storico", "#/scans"], [siteName(s.target), `#/scans?target=${enc(s.target)}`], [s.id]],
    title: siteName(s.target),
    meta: [["ID", mono(s.id)], ["Avviata", mono(fmtDate(s.started_at))],
      s.options.label ? ["Etichetta", s.options.label] : null,
      ["Stato", scanSt(s)], ["IA", s.model_used ? mono(s.model_used) : "non usata"],
      s.source !== "v4" ? ["Origine", "importata dalla v3"] : null],
    tabs: el("nav", { class: "tabs", "aria-label": "Sezioni della scansione" }, TABS.map(([t, label]) =>
      el("a", { href: t ? `${base}/${t}` : base, "aria-current": t === tab ? "page" : null },
        label, t === "findings" ? el("span", { class: "dim" }, ` ${confirmedN}`) : null))),
  });
}

function evidenceBlock(ev) {
  if (!ev) return null;
  return el("div", { class: "evidence" },
    el("div", { class: "line" },
      el("span", {}, ev.method), el("span", { class: "url" }, ev.url),
      el("span", {}, ev.error ? `errore: ${ev.error}` : `HTTP ${ev.status_code}`),
      el("span", { class: "dim" }, `${Math.round((ev.elapsed_s || 0) * 1000)} ms`),
      el("span", { class: "dim" }, fmtDate(ev.timestamp)),
      ev.redirect_blocked ? el("span", {}, `redirect bloccato: ${ev.redirect_blocked}`) : null),
    ev.excerpt ? el("pre", {}, ev.excerpt) : null);
}

function findingItem(f, evidence, open = false) {
  const evs = (f.evidence_ids || []).map((id) => evidence.get(id)).filter(Boolean);
  const r = f.remediation;
  const facts = [["Controllo", mono(f.check_id)], ["Percorso", mono(f.path)],
    ["Confidenza", CONFIDENCE[f.confidence] || f.confidence], f.cwe ? ["CWE", mono(f.cwe)] : null,
    f.priority ? ["Priorità", mono(f.priority)] : null, f.impact ? ["Impatto", f.impact] : null,
    f.likelihood ? ["Probabilità", f.likelihood] : null].filter(Boolean);
  return el("details", { class: "finding", id: `f-${f.id}`, open },
    el("summary", {},
      el("span", { class: "ttl" }, f.title, el("span", { class: "sub" }, f.summary)),
      el("span", { class: "right" }, f.severity && f.status === "confirmed" ? el("span", { class: "sev" }, `${SEV[f.severity]} `) : null,
        findingSt(f.status))),
    el("div", { class: "body" },
      el("dl", { class: "facts" }, facts.map(([k, v]) => [el("dt", {}, k), el("dd", {}, v)])),
      evs.length ? [el("h3", {}, `Evidenze (${evs.length})`), evs.map(evidenceBlock)]
        : el("p", { class: "dim" }, "Nessuna richiesta collegata a questo esito."),
      (f.ai_notes || []).map((n) => el("div", { class: "ai" },
        el("span", { class: "who" }, `Nota dell'IA locale · ${n.model}`, n.suggested_priority ? ` · priorità suggerita ${n.suggested_priority}` : ""),
        n.text)),
      r ? el("details", { class: "sub" }, el("summary", {}, `Correzione: ${r.title}`),
        el("p", {}, r.summary),
        [["WordPress", r.wordpress], ["Apache", r.apache], ["Nginx", r.nginx], ["Verifica", r.verification]]
          .filter(([, t]) => t).map(([l, t]) => [el("h3", {}, l), el("pre", {}, t)]),
        r.risks ? el("p", {}, el("b", {}, "Rischi: "), r.risks) : null) : null,
      (f.history || []).length ? el("details", { class: "sub" }, el("summary", {}, "Cronologia dello stato"),
        el("ul", { class: "plain" }, f.history.map((c) =>
          el("li", {}, mono(`${c.from_status || "—"} → ${c.to_status}`), ` ${c.agent}: ${c.reason}`)))) : null));
}

function reportPanel(s) {
  const base = `/api/scans/${enc(s.id)}/report`;
  if (s.live) return notice("I report si generano a scansione conclusa.");
  const fmt = (ext, title, text, actions) => el("div", {},
    el("h3", {}, title, " ", el("span", { class: "ext" }, `.${ext}`)), el("p", {}, text), el("div", { class: "actions" }, actions));
  const dl = (href, text) => link(href, text, { download: "" });
  return el("div", { class: "panel formats" },
    fmt("html", "Report HTML", "Da leggere nel browser; si apre in una nuova scheda, senza script.", [
      link(`${base}.html`, "Apri il report", { target: "_blank", rel: "noopener", class: "button" }),
      link(`${base}.html?anonymize=true`, "Versione anonimizzata", { target: "_blank", rel: "noopener" })]),
    fmt("pdf", "PDF", "Per l'archivio o da consegnare al titolare del sito.", [
      dl(`${base}.pdf`, "Scarica"), dl(`${base}.pdf?anonymize=true`, "Scarica anonimizzato")]),
    fmt("md", "Markdown", "Per la documentazione o la tesi.", [
      dl(`${base}.md`, "Scarica"), dl(`${base}.md?anonymize=true`, "Scarica anonimizzato")]),
    fmt("json", "JSON", "Risultato completo, con evidenze e cronologia degli stati.", [dl(`${base}.json`, "Scarica")]));
}

async function viewScan(id, tab, q, first = true) {
  const s = await api(`/api/scans/${enc(id)}`);
  const evidence = new Map((s.evidence || []).map((e) => [e.id, e]));
  const by = (...st) => s.findings.filter((f) => st.includes(f.status));
  const confirmed = by("confirmed").sort((a, b) => SEV_ORDER.indexOf(a.severity) - SEV_ORDER.indexOf(b.severity));
  const parts = [scanContext(s, tab)];
  if (s.error) parts.push(notice(s.error, "error"));
  if (s.live) {
    const done = s.agents.filter((a) => !["pending", "running"].includes(a.state)).length;
    const bar = el("div"); bar.style.width = `${s.agents.length ? (100 * done) / s.agents.length : 0}%`;
    parts.push(el("div", { class: "panel pad" },
      el("div", { class: "toolbar" }, el("span", { class: "grow" }, `Agenti completati: ${done} di ${s.agents.length}`),
        el("button", { class: "danger", onclick: async (e) => {
          e.target.disabled = true;
          try { await api(`/api/scans/${enc(id)}/cancel`, { method: "POST" }); } catch (err) { alert(err.message); }
        } }, "Annulla la scansione")),
      el("div", { class: "progress", role: "progressbar", "aria-valuemin": 0, "aria-valuemax": s.agents.length, "aria-valuenow": done }, bar)));
  }

  if (tab === "") {
    const sev = {}; confirmed.forEach((f) => { sev[f.severity] = (sev[f.severity] || 0) + 1; });
    parts.push(el("div", { class: "readout" },
      [["Confermati", confirmed.length, confirmed.length ? "bad" : s.live ? "" : "ok"],
        ["Critica o alta", (sev.critical || 0) + (sev.high || 0), ""], ["Media", sev.medium || 0, ""], ["Bassa", sev.low || 0, ""],
        ["Da verificare", by("inconclusive", "candidate", "not_detected").length, by("inconclusive").length ? "warn" : ""],
        ["Controlli superati", by("not_present").length, ""]]
        .map(([k, v, cls]) => el("div", {}, el("span", { class: `v ${cls}` }, v), el("span", { class: "k" }, k)))));
    const left = el("section", {}, el("h2", {}, "Problemi confermati ", el("span", { class: "count" }, `(${confirmed.length})`)),
      confirmed.length ? el("div", { class: "panel" }, el("table", { class: "stack" },
        el("thead", {}, el("tr", {}, ["Problema", "Gravità", "Evidenze"].map((h) => el("th", { scope: "col" }, h)))),
        el("tbody", {}, confirmed.map((f) => el("tr", {},
          el("td", { class: "wide" }, link(`#/scan/${enc(s.id)}/findings?open=${enc(f.id)}`, f.title), el("span", { class: "sub mono" }, f.path)),
          el("td", { "data-label": "Gravità" }, SEV[f.severity] || "-", f.priority ? el("span", { class: "sub mono" }, f.priority) : null),
          el("td", { "data-label": "Evidenze" }, mono(String((f.evidence_ids || []).length))))))))
        : el("p", { class: "muted" }, s.live ? "In attesa della validazione delle evidenze." : "Nessun problema confermato dai controlli eseguiti."));
    const lims = (s.stats || {}).limitations || [];
    const right = el("section", {},
      el("h2", {}, "Sintesi"),
      s.executive_summary ? (s.executive_summary_ai
        ? el("div", { class: "ai" }, el("span", { class: "who" }, `Scritta dall'IA locale · ${s.model_used}`), s.executive_summary)
        : el("p", {}, s.executive_summary)) : el("p", { class: "dim" }, "Sintesi non disponibile."),
      lims.length ? [el("h2", {}, "Limiti dell'analisi"), el("ul", { class: "plain muted" }, lims.map((l) => el("li", {}, l)))] : null,
      s.live ? null : el("p", {}, link(`#/scan/${enc(s.id)}/report`, "Apri o scarica il report")));
    parts.push(el("div", { class: "split" }, left, right));
  } else if (tab === "findings") {
    const want = q.get("open");
    const groups = [["Confermati", ["confirmed"], true], ["Da verificare manualmente", ["inconclusive", "candidate", "not_detected"], true],
      ["Errori", ["error"], true], ["Falsi positivi scartati", ["false_positive"], false],
      ["Controlli superati", ["not_present"], false], ["Contesto e non applicabili", ["info", "not_applicable"], false]];
    for (const [title, sts, openGroup] of groups) {
      const list = sts[0] === "confirmed" ? confirmed : by(...sts);
      if (!list.length) continue;
      const hasWanted = list.some((f) => f.id === want);
      parts.push(el("details", { class: "panel group", open: openGroup || hasWanted },
        el("summary", {}, title, " ", el("span", { class: "count" }, `(${list.length})`)),
        list.map((f) => findingItem(f, evidence, f.id === want))));
    }
    if (!s.findings.length) parts.push(emptyState("Nessun rilievo", s.live ? "I rilievi compaiono man mano che gli agenti terminano." : "La scansione non ha prodotto risultati."));
  } else if (tab === "agents") {
    parts.push(el("div", { class: "panel" }, el("table", { class: "stack" },
      el("thead", {}, el("tr", {}, ["Agente", "Stato", "Durata", "Richieste", "Esito"].map((h, i) =>
        el("th", { scope: "col", class: [2, 3].includes(i) ? "num" : null }, h)))),
      el("tbody", {}, s.agents.map((a) => el("tr", {},
        el("td", { class: "wide" }, a.display_name, a.uses_ai ? el("span", { class: "sub" }, "usa l'IA locale") : null),
        el("td", { "data-label": "Stato" }, st(AGENT[a.state] || [a.state, "neutral"])),
        el("td", { class: "num", "data-label": "Durata" }, mono(`${a.duration_s.toFixed(2)} s`)),
        el("td", { class: "num", "data-label": "Richieste" }, mono(String(a.requests))),
        el("td", { class: "wide" }, a.message || a.error || "")))))));
    const http = (s.stats || {}).http;
    if (http) parts.push(el("p", { class: "muted" }, `Richieste HTTP: ${http.requests}, dalla cache: ${http.cache_hits}, bloccate dal perimetro: ${http.blocked}, errori: ${http.errors}.`));
  } else if (tab === "report") {
    parts.push(reportPanel(s));
  }
  show(...parts);
  if (first && q.get("open")) {
    const n = document.getElementById(`f-${q.get("open")}`);
    if (n) { n.scrollIntoView({ block: "start" }); n.querySelector("summary").focus({ preventScroll: true }); }
  }
  if (s.live) pollTimer = setTimeout(() => guarded(() => viewScan(id, tab, q, false)), 1000);
}

// ------------------------------------------------------------ confronto
function scanOption(r, selected) {
  return el("option", { value: r.id, selected: r.id === selected },
    `${fmtDate(r.started_at, false)}${r.label ? ` · ${r.label}` : ""} · ${r.confirmed} confermati${r.source !== "v4" ? " · v3" : ""}`);
}
function scanSelect(id, rows, selected) {
  return el("select", { id, name: id }, [...bySite(rows).entries()].map(([t, list]) =>
    el("optgroup", { label: siteName(t) }, list.map((r) => scanOption(r, selected)))));
}

async function viewCompare(q) {
  const rows = completed(await loadScans());
  let before = q.get("before"), after = q.get("after");
  const ctxBase = { crumbs: [], title: "Confronto prima/dopo" };
  if (rows.length < 2) {
    return show(contextBar(ctxBase), emptyState("Servono due scansioni completate",
      "Il confronto mette a fianco due scansioni dello stesso sito, per esempio prima e dopo una correzione.",
      link("#/new", "Nuova scansione", { class: "button" })));
  }
  if (!before || !after) {   // proposta: le ultime due dello stesso sito
    const pair = [...bySite(rows).values()].find((l) => l.length >= 2);
    after = after || (pair ? pair[0].id : rows[0].id);
    before = before || (pair ? pair[1].id : rows[1].id);
  }
  const rb = rows.find((r) => r.id === before), ra = rows.find((r) => r.id === after);
  const selB = scanSelect("before", rows, before), selA = scanSelect("after", rows, after);
  const side = (tag, sel, r, forId) => el("div", { class: "side" },
    el("label", { for: forId }, tag), sel,
    r ? el("div", { class: "chosen" }, el("b", {}, siteName(r.target)), " ", mono(r.id, "dim"),
      el("div", { class: "muted" }, mono(fmtDate(r.started_at)), r.label ? ` · ${r.label}` : "", ` · ${r.confirmed} confermati`))
      : el("div", { class: "chosen dim" }, "Scansione non completata o inesistente."));
  const form = el("form", { class: "panel", onsubmit: (e) => {
    e.preventDefault();
    location.hash = `#/compare?before=${enc(selB.value)}&after=${enc(selA.value)}`;
  } },
  el("div", { class: "pair" }, side("Prima", selB, rb, "before"), el("div", { class: "arrow", "aria-hidden": "true" }, "→"), side("Dopo", selA, ra, "after")),
  el("div", { class: "pad", style: null }, el("div", { class: "actions" },
    el("button", { type: "submit" }, "Confronta"),
    el("button", { type: "button", class: "quiet", onclick: () => {
      location.hash = `#/compare?before=${enc(selA.value)}&after=${enc(selB.value)}`; } }, "Inverti"))));
  const ctx = contextBar({ crumbs: rb && ra ? [["Confronto", "#/compare"], [siteName(ra.target)]] : [],
    title: rb && ra ? `Confronto di ${siteName(ra.target)}` : ctxBase.title,
    meta: rb && ra ? [["Prima", mono(`${fmtDate(rb.started_at, false)}${rb.label ? ` (${rb.label})` : ""}`)],
      ["Dopo", mono(`${fmtDate(ra.started_at, false)}${ra.label ? ` (${ra.label})` : ""}`)]] : [] });
  const out = el("div", {}, loading("Confronto in corso"));
  show(ctx, form, out);
  if (before === after) { out.replaceChildren(notice("Hai scelto la stessa scansione due volte: scegline due diverse.", "error")); return; }
  let c;
  try { c = await api(`/api/compare?before=${enc(before)}&after=${enc(after)}`); } catch (e) {
    out.replaceChildren(errorState(e, () => route())); return;
  }
  const order = ["new", "resolved", "still_open", "not_comparable", "unchanged"];
  const rowsOf = (k) => c.rows.filter((r) => r.outcome === k);
  const warnings = [...c.warnings];
  if (rb && ra && rb.target !== ra.target) warnings.unshift(`Le due scansioni riguardano siti diversi (${siteName(rb.target)} e ${siteName(ra.target)}): il confronto ha poco senso.`);
  if (rb && ra && rb.started_at > ra.started_at) warnings.unshift("La scansione «Prima» è più recente di «Dopo»: usa Inverti se l'ordine è sbagliato.");
  const table = el("table", { class: "stack" },
    el("thead", {}, el("tr", {}, ["Controllo", "Esito", "Prima → Dopo", "Motivo"].map((h) => el("th", { scope: "col" }, h)))),
    el("tbody", {}, order.filter((k) => k !== "unchanged").flatMap(rowsOf).map((r) => el("tr", { class: `row-${OUTCOME[r.outcome][1]}` },
      el("td", { class: "wide" }, el("b", {}, r.title), el("span", { class: "sub mono" }, r.key)),
      el("td", { "data-label": "Esito" }, st(OUTCOME[r.outcome])),
      el("td", { class: "arrowcell", "data-label": "Prima → Dopo" }, (FINDING[r.before] || ["—"])[0], " ",
        el("span", { class: "to", "aria-label": "diventa" }, "→"), " ", (FINDING[r.after] || ["—"])[0]),
      el("td", { class: "wide muted" }, r.reason)))));
  const unchanged = rowsOf("unchanged");
  out.replaceChildren(...[
    warnings.map((w) => notice(w)),
    el("p", { class: "outcomes", "aria-label": "Riepilogo del confronto" }, order.map((k) =>
      el("span", {}, el("b", {}, String(c.counts[k] || 0)), st(OUTCOME[k])))),
    c.rows.some((r) => !["info", "unchanged"].includes(r.outcome)) ? el("div", { class: "panel" }, table)
      : emptyState("Nessuna differenza", "I due risultati coincidono: nessun problema nuovo, risolto o ancora presente."),
    unchanged.length ? el("details", { class: "panel group" }, el("summary", {}, "Assenti in entrambe ", el("span", { class: "count" }, `(${unchanged.length})`)),
      el("ul", { class: "plain pad" }, unchanged.map((r) => el("li", {}, r.title)))) : null,
    el("p", { class: "actions", style: null },
      link(`/api/compare?before=${enc(before)}&after=${enc(after)}&format=md`, "Scarica il confronto in Markdown", { download: `confronto-${before}-${after}.md` }),
      link(`/api/compare?before=${enc(before)}&after=${enc(after)}&format=md&anonymize=true`, "Versione anonimizzata", { download: `confronto-${before}-${after}-anon.md` }),
      link(`#/scan/${enc(after)}`, "Dettaglio della scansione «Dopo»")),
  ].flat().filter(Boolean));
}

// ------------------------------------------------------------ andamento
function trendChart(points) {
  // larghezza reale del pannello: i testi restano a 11px anche su schermi stretti
  const W = Math.min(900, Math.max(280, view().clientWidth - 66)), H = W < 500 ? 200 : 240;
  const L = 36, R = 40, T = 16, B = 46;
  const max = Math.max(1, ...points.map((p) => p.value));
  const step = max <= 5 ? 1 : max <= 12 ? 2 : Math.ceil(max / 6);
  const top = Math.ceil(max / step) * step;
  const x = (i) => L + (points.length === 1 ? (W - L - R) / 2 : (i * (W - L - R)) / (points.length - 1));
  const y = (v) => T + (H - T - B) * (1 - v / top);
  const ticks = []; for (let v = 0; v <= top; v += step) ticks.push(v);
  let d = "";   // a gradini: il valore resta valido fino alla scansione successiva
  points.forEach((p, i) => { d += i === 0 ? `M${x(i)},${y(p.value)}` : `H${x(i)}V${y(p.value)}`; });
  const wrap = el("div", { class: "chart" });
  const tip = el("div", { class: "tip", hidden: true, role: "status" });
  const showTip = (i) => {
    const p = points[i]; const box = wrap.getBoundingClientRect(); const svgBox = svg.getBoundingClientRect();
    tip.textContent = `${fmtDate(p.date, false)}${p.label ? ` · ${p.label}` : ""}: ${p.value} confermati`;
    tip.style.left = `${svgBox.left - box.left + (x(i) / W) * svgBox.width}px`;
    tip.style.top = `${svgBox.top - box.top + (y(p.value) / H) * svgBox.height}px`;
    tip.hidden = false;
  };
  const labelEvery = Math.ceil(points.length / Math.max(2, Math.floor((W - L - R) / 96)));
  const svg = el("svg", { viewBox: `0 0 ${W} ${H}`, role: "img",
    "aria-label": `Problemi confermati per scansione, da ${points[0].value} a ${points[points.length - 1].value}` },
  el("g", { class: "grid" }, ticks.map((v) => el("line", { x1: L, x2: W - R, y1: y(v), y2: y(v) }))),
  el("g", { class: "axis" },
    ticks.map((v) => el("text", { x: L - 8, y: y(v) + 4, "text-anchor": "end" }, v)),
    points.map((p, i) => (i % labelEvery === 0 || i === points.length - 1)
      ? el("text", { x: x(i), y: H - B + 18, "text-anchor": "middle" }, shortDate(p.date)) : null),
    points.map((p, i) => (p.label && (i % labelEvery === 0 || i === points.length - 1))
      ? el("text", { x: x(i), y: H - B + 32, "text-anchor": "middle", class: "unit" }, p.label) : null)),
  el("path", { class: "series", d }),
  points.map((p, i) => [
    el("rect", { class: "hit", x: x(i) - 14, y: T, width: 28, height: H - T - B, tabindex: 0,
      "aria-label": `${fmtDate(p.date, false)}${p.label ? `, ${p.label}` : ""}: ${p.value} confermati`,
      onmouseenter: () => showTip(i), onfocus: () => showTip(i), onmouseleave: () => { tip.hidden = true; },
      onblur: () => { tip.hidden = true; }, onclick: () => { location.hash = `#/scan/${enc(p.id)}`; },
      onkeydown: (e) => { if (e.key === "Enter") location.hash = `#/scan/${enc(p.id)}`; } }),
    el("circle", { class: "dot", cx: x(i), cy: y(p.value), r: 4 })]));
  wrap.append(el("p", { class: "muted", style: null }, "Problemi confermati per scansione (numero). Asse orizzontale: scansioni completate in ordine di data, a distanza uguale."), svg, tip);
  return wrap;
}

async function viewTrend(q) {
  const all = await loadScans();
  const sites = [...bySite(completed(all)).entries()];
  let target = q.get("target");
  if (!target && sites.length) target = (sites.find(([, l]) => l.length >= 2) || sites[0])[0];
  const sel = el("select", { id: "t-target", onchange: (e) => { location.hash = `#/trend?target=${enc(e.target.value)}`; } },
    sites.map(([t, l]) => el("option", { value: t, selected: t === target }, `${siteName(t)} (${l.length})`)));
  const ctx = contextBar({ crumbs: target ? [["Andamento", "#/trend"], [siteName(target)]] : [],
    title: target ? `Andamento di ${siteName(target)}` : "Andamento" });
  if (!sites.length) {
    return show(ctx, emptyState("Nessuna scansione completata", "L'andamento si costruisce dalle scansioni completate di uno stesso sito.",
      link("#/new", "Nuova scansione", { class: "button" })));
  }
  const scans = completed(all).filter((r) => r.target === target).reverse();   // dalla più vecchia
  const toolbar = el("div", { class: "toolbar" }, el("label", { class: "field", for: "t-target" }, "Sito", sel));
  if (scans.length < 2) {
    return show(ctx, toolbar, emptyState("Dati insufficienti per un andamento",
      `Per ${siteName(target)} c'è ${scans.length} scansione completata: ne servono almeno due per vedere come cambiano i problemi.`,
      scans[0] ? link(`#/scan/${enc(scans[0].id)}`, "Apri la scansione") : null, link("#/new", "Nuova scansione")));
  }
  const ids = new Set(scans.map((r) => r.id));
  const host = scans[0].host;
  let issues = [];
  try { issues = (await api(`/api/timeline?host=${enc(host)}`)); } catch (e) { issues = null; }
  const points = scans.map((r) => ({ id: r.id, date: r.started_at, label: r.label, value: r.confirmed }));
  ctx.querySelector(".meta")?.remove();
  ctx.append(el("dl", { class: "meta" }, [["Periodo", mono(`${fmtDate(scans[0].started_at, false)} – ${fmtDate(scans[scans.length - 1].started_at, false)}`)],
    ["Scansioni", mono(String(scans.length))], ["Unità", "problemi confermati"]].map(([k, v]) => el("div", {}, el("dt", {}, k), el("dd", {}, v)))));
  const parts = [ctx, toolbar, el("div", { class: "panel" }, trendChart(points))];
  if (issues === null) parts.push(notice("Il dettaglio per problema non è disponibile (errore dell'API /api/timeline).", "error"));
  else {
    const rows = issues.map((it) => ({ ...it, history: it.history.filter((h) => ids.has(h.scan_id)) }))
      .filter((it) => it.history.some((h) => h.status === "confirmed"));
    const cols = scans.map((r, i) => ({ r, i }));
    parts.push(el("h2", {}, "Problemi nel tempo ", el("span", { class: "count" }, `(${rows.length})`)),
      el("div", { class: "panel", style: null }, el("div", { style: null, class: "scroll-x" }, el("table", { class: "matrix" },
        el("thead", {}, el("tr", {}, el("th", { scope: "col" }, "Problema"),
          cols.map(({ r, i }) => el("th", { scope: "col", class: "cell", title: fmtDate(r.started_at) }, link(`#/scan/${enc(r.id)}`, `S${i + 1}`, { "aria-label": `Scansione ${i + 1} del ${fmtDate(r.started_at, false)}` }))))),
        el("tbody", {}, rows.map((it) => el("tr", {},
          el("td", {}, it.title, el("span", { class: "sub mono" }, it.path)),
          cols.map(({ r }) => {
            const h = it.history.find((x) => x.scan_id === r.id);
            const [text, cls] = h ? FINDING[h.status] || [h.status, "neutral"] : ["Non eseguito", "neutral"];
            return el("td", { class: "cell", title: text }, el("span", { class: `st ${cls}` }, el("span", { class: "sr" }, text)));
          }))))))),
      el("p", { class: "muted legend" }, el("span", {}, "S1, S2… sono le scansioni nell'ordine del grafico."),
        st(FINDING.confirmed), st(FINDING.not_present), st(FINDING.inconclusive), st(["Altro", "neutral"])));
  }
  show(...parts);
}

// ------------------------------------------------------------ nuova scansione
function formData(form) {
  const out = {};
  for (const [k, v] of new FormData(form).entries()) out[k] = typeof v === "string" ? v.trim() : v;
  form.querySelectorAll("input[type=checkbox]").forEach((c) => { out[c.name] = c.checked; });
  return out;
}
const field = (label, input, hint) => el("label", { class: "field" }, label, input, hint ? el("span", { class: "dim" }, hint) : null);

async function viewNew() {
  const [auths, models] = await Promise.all([api("/api/authorizations?only_valid=true"),
    api("/api/models").catch(() => ({ available: false, models: [] }))]);
  const ctx = contextBar({ title: "Nuova scansione" });
  if (!auths.length) {
    return show(ctx, emptyState("Nessuna autorizzazione valida",
      "Ogni scansione richiede un'autorizzazione in corso di validità per il sito: registrala prima di avviare.",
      link("#/auth", "Registra un'autorizzazione", { class: "button" })));
  }
  const target = el("input", { name: "target_url", required: true, value: auths[0].target_url, class: "mono" });
  const authSel = el("select", { name: "authorization_id",
    onchange: (e) => { target.value = auths.find((a) => a.id === e.target.value).target_url; } },
  auths.map((a) => el("option", { value: a.id },
    `${siteName(a.target_url)} · ${a.kind === "lab" ? "laboratorio" : "sito reale"} · fino al ${fmtDate(a.valid_until, false)}`)));
  const modelSel = el("select", { name: "model" },
    el("option", { value: "" }, models.available ? `Predefinito (${models.default})` : "Ollama non raggiungibile"),
    (models.models || []).map((m) => el("option", { value: m }, m)));
  const out = el("div");
  const form = el("form", { class: "panel grid", onsubmit: async (ev) => {
    ev.preventDefault();
    const btn = form.querySelector("button[type=submit]"); btn.disabled = true;
    const d = formData(form);
    const body = { authorization_id: d.authorization_id, target_url: d.target_url,
      options: { label: d.label, model: d.model, use_ai: d.use_ai, force_wordpress: d.force_wordpress,
        planner: d.planner, burp: d.burp } };
    try {
      const r = await api("/api/scans", { method: "POST", body });
      location.hash = `#/scan/${enc(r.id)}`;
    } catch (e) { btn.disabled = false; out.replaceChildren(notice(e.message, "error")); }
  } },
  field("Autorizzazione", authSel),
  field("Indirizzo da analizzare", target, "Deve rientrare nel perimetro dell'autorizzazione."),
  field("Etichetta", el("input", { name: "label", maxlength: 60, placeholder: "prima, dopo…" }), "Facoltativa; aiuta nei confronti."),
  field("Modello IA", modelSel),
  field("Ordine dei controlli", el("select", { name: "planner" },
    el("option", { value: "deterministic" }, "Fisso (consigliato)"),
    el("option", { value: "llm" }, "Scelto dall'IA (sperimentale)"))),
  field("Proxy Burp", el("input", { name: "burp", placeholder: "127.0.0.1:8080", class: "mono" }), "Facoltativo."),
  el("div", { class: "form-foot" },
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "use_ai", checked: models.available }), "Usa l'IA locale per spiegazioni e sintesi"),
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "force_wordpress" }), "Esegui i controlli WordPress anche se non viene rilevato")),
  el("div", { class: "form-foot" }, el("button", { type: "submit" }, "Avvia la scansione"),
    el("span", { class: "muted" }, "Solo richieste in lettura dal registro chiuso delle sonde; nessun login né exploit.")));
  show(ctx, out, form);
}

// ------------------------------------------------------------ autorizzazioni
async function viewAuth() {
  const auths = await api("/api/authorizations");
  const out = el("div");
  const now = new Date();
  const ctx = contextBar({ title: "Autorizzazioni", meta: [["Registrate", mono(String(auths.length))],
    ["Valide", mono(String(auths.filter((a) => !a.revoked && new Date(a.valid_from) <= now && now <= new Date(a.valid_until)).length))]] });
  const list = el("div", { class: "panel" }, el("table", { class: "stack" },
    el("thead", {}, el("tr", {}, ["Sito", "Tipo", "Autorizzata da", "Validità", "Stato", "Azioni"].map((x) => el("th", { scope: "col" }, x)))),
    el("tbody", {}, auths.map((a) => {
      const valid = !a.revoked && new Date(a.valid_from) <= now && now <= new Date(a.valid_until);
      return el("tr", {},
        el("td", { class: "wide" }, el("span", { class: "site" }, siteName(a.target_url)),
          el("span", { class: "sub" }, mono(a.id), a.scope.length > 1 ? ` · altre ${a.scope.length - 1} origini` : "")),
        el("td", { "data-label": "Tipo" }, a.kind === "lab" ? "Laboratorio" : "Sito reale"),
        el("td", { "data-label": "Autorizzata da" }, a.authorizer_name, el("span", { class: "sub" }, a.authorizer_role)),
        el("td", { "data-label": "Validità" }, mono(fmtDate(a.valid_from, false)), el("span", { class: "sub" }, "fino al ", mono(fmtDate(a.valid_until, false)))),
        el("td", { "data-label": "Stato" }, a.revoked ? st(["Revocata", "err"]) : valid ? st(["Valida", "done"]) : st(["Scaduta", "neutral"])),
        el("td", { class: "wide" }, a.revoked ? null : el("button", { class: "danger", onclick: async () => {
          if (!confirm(`Revocare l'autorizzazione per ${a.target_url}?`)) return;
          try { await api(`/api/authorizations/${enc(a.id)}/revoke`, { method: "POST" }); route(); } catch (e) { out.replaceChildren(notice(e.message, "error")); }
        } }, "Revoca")));
    }))));
  const form = el("form", { class: "panel grid", onsubmit: async (ev) => {
    ev.preventDefault();
    const d = formData(form);
    const body = { kind: d.kind, target_url: d.target_url, authorizer_name: d.authorizer_name,
      authorizer_role: d.authorizer_role, operator: d.operator, document_ref: d.document_ref,
      document_sha256: d.document_sha256, days: d.days ? Number(d.days) : null, notes: d.notes,
      extra_scope: d.extra_scope ? d.extra_scope.split(/[\s,]+/).filter(Boolean) : [] };
    try { await api("/api/authorizations", { method: "POST", body }); route(); } catch (e) { out.replaceChildren(notice(e.message, "error")); }
  } },
  field("Tipo", el("select", { name: "kind" },
    el("option", { value: "engagement" }, "Sito reale (autorizzazione scritta)"),
    el("option", { value: "lab" }, "Laboratorio locale (127.0.0.1)"))),
  field("Sito", el("input", { name: "target_url", required: true, placeholder: "https://www.esempio.it", class: "mono" })),
  field("Altre origini nel perimetro", el("input", { name: "extra_scope", placeholder: "https://esempio.it", class: "mono" }), "Separate da spazi."),
  field("Autorizzata da", el("input", { name: "authorizer_name", required: true })),
  field("Ruolo di chi autorizza", el("input", { name: "authorizer_role", required: true, placeholder: "Titolare del sito" })),
  field("Operatore", el("input", { name: "operator", required: true })),
  field("Documento firmato", el("input", { name: "document_ref" }), "Obbligatorio per i siti reali."),
  field("SHA-256 del documento", el("input", { name: "document_sha256", maxlength: 64, class: "mono" }), "Facoltativo."),
  field("Durata in giorni", el("input", { name: "days", type: "number", min: 1, max: 365, value: 7 })),
  field("Note", el("input", { name: "notes" })),
  el("div", { class: "form-foot" }, el("button", { type: "submit" }, "Registra l'autorizzazione")));
  show(ctx, out, auths.length ? list : emptyState("Nessuna autorizzazione registrata", "Registra la prima con il modulo qui sotto."),
    el("h2", {}, "Nuova autorizzazione"), form);
}

// ------------------------------------------------------------ router
function parseHash() {
  const raw = location.hash.replace(/^#\/?/, "");
  const [path, query = ""] = raw.split("?");
  const parts = path.split("/").filter(Boolean).map(decodeURIComponent);
  return { parts, q: new URLSearchParams(query) };
}

async function guarded(fn) {
  try { await fn(); } catch (e) {
    const err = e instanceof ApiError ? e : new ApiError(`Errore inatteso nella dashboard: ${e.message}`, 0, "");
    show(contextBar({ title: "Impossibile mostrare la pagina" }), errorState(err, () => route()));
    console.error(e);
  }
}

async function route() {
  clearTimeout(pollTimer);
  const seq = ++routeSeq;
  const { parts, q } = parseHash();
  const name = parts[0] || "overview";
  const navName = name === "scan" ? "scans" : name;
  document.querySelectorAll(".rail nav a").forEach((a) => {
    const on = a.dataset.route === navName;
    a.classList.toggle("active", on);
    if (on) a.setAttribute("aria-current", "page"); else a.removeAttribute("aria-current");
  });
  const v = view();
  v.replaceChildren(loading("Caricamento"));
  await guarded(async () => {
    if (name === "scan" && parts[1]) await viewScan(parts[1], parts[2] || "", q);
    else if (name === "scans") await viewScans(q);
    else if (name === "compare") await viewCompare(q);
    else if (name === "trend") await viewTrend(q);
    else if (name === "new") await viewNew();
    else if (name === "auth") await viewAuth();
    else await viewOverview();
  });
  if (seq !== routeSeq) return;
  const h1 = v.querySelector("h1");
  document.title = h1 ? `${h1.textContent} · wpsec` : "wpsec";
  if (!q.get("open")) { window.scrollTo(0, 0); if (!firstRoute) v.focus({ preventScroll: true }); }
  firstRoute = false;
}

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", async () => {
  route();
  try { document.getElementById("version").textContent = `v${(await api("/api/health")).version}`; } catch { /* facoltativo */ }
});
