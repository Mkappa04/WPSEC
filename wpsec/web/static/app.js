// Dashboard di wpsec. Regola: i dati (che possono venire dal sito analizzato) entrano nel
// DOM solo come testo (textContent), mai come HTML.
"use strict";

const STATUS_IT = {
  confirmed: "Confermato", false_positive: "Falso positivo", not_present: "Non rilevato",
  inconclusive: "Inconcludente", not_applicable: "Non applicabile", error: "Errore",
  info: "Informativo", candidate: "Da validare", not_detected: "Da validare",
};
const SEV_IT = { critical: "Critica", high: "Alta", medium: "Media", low: "Bassa", info: "Info" };
const AGENT_IT = { pending: "in attesa", running: "in corso", completed: "completato",
  failed: "fallito", skipped: "saltato" };
const OUTCOME_IT = { resolved: "RISOLTO", still_open: "ANCORA APERTO", new: "NUOVO PROBLEMA",
  unchanged: "INVARIATO", not_comparable: "NON CONFRONTABILE", info: "INFO" };

let pollTimer = null;

// ------------------------------------------------------------ utilità DOM
function el(tag, attrs = {}, ...children) {
  const n = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v === null || v === undefined || v === false) continue;
    if (k === "class") n.className = v;
    else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
    else if (v === true) n.setAttribute(k, "");
    else n.setAttribute(k, String(v));
  }
  for (const c of children.flat()) {
    if (c === null || c === undefined || c === false) continue;
    n.append(c instanceof Node ? c : document.createTextNode(String(c)));
  }
  return n;
}
const badge = (text, cls) => el("span", { class: `badge ${cls}` }, text);
const view = () => document.getElementById("view");
function show(...nodes) { view().replaceChildren(...nodes); }
function msg(text, kind = "error") { return el("div", { class: `msg ${kind}`, role: "status" }, text); }
const fmtDate = (s) => (s ? new Date(s).toLocaleString("it-IT") : "-");

async function api(path, opts = {}) {
  const init = { method: opts.method || "GET", headers: {} };
  if (opts.body !== undefined) {
    init.headers["Content-Type"] = "application/json";
    init.body = JSON.stringify(opts.body);
  }
  const r = await fetch(path, init);
  if (r.status === 204) return null;
  const data = await r.json().catch(() => ({}));
  if (!r.ok) {
    let d = data.detail;
    if (Array.isArray(d)) d = d.map((e) => `${(e.loc || []).slice(1).join(".")}: ${e.msg}`).join("; ");
    throw new Error(d || `HTTP ${r.status}`);
  }
  return data;
}

function formData(form) {
  const out = {};
  for (const [k, v] of new FormData(form).entries()) out[k] = typeof v === "string" ? v.trim() : v;
  form.querySelectorAll("input[type=checkbox]").forEach((c) => { out[c.name] = c.checked; });
  return out;
}

// ------------------------------------------------------------ elenco scansioni
async function viewScans() {
  const rows = await api("/api/scans?limit=100");
  const table = el("table", {},
    el("tr", {}, ["Data", "Sito", "Etichetta", "Stato", "Confermati", "Inconcludenti", "Gravità"]
      .map((h) => el("th", {}, h))),
    rows.map((r) => el("tr", { class: "click", onclick: () => (location.hash = `#/scan/${r.id}`) },
      el("td", {}, fmtDate(r.started_at)),
      el("td", {}, r.target),
      el("td", {}, r.label || ""),
      el("td", {}, r.live ? badge("in corso", "ag-running") : r.status,
        r.source !== "v4" ? el("span", { class: "muted" }, " (v3)") : null),
      el("td", {}, r.confirmed),
      el("td", {}, r.inconclusive),
      el("td", {}, Object.entries(r.severity).filter(([, n]) => n)
        .map(([s, n]) => badge(`${SEV_IT[s]} ${n}`, `s-${s}`)))
    )));
  show(el("h1", {}, "Scansioni"),
    rows.length ? el("div", { class: "card table-wrap" }, table)
      : el("p", { class: "muted" }, "Nessuna scansione. Crea un'autorizzazione e avvia una scansione."));
}

// ------------------------------------------------------------ nuova scansione
async function viewNew() {
  const [auths, models] = await Promise.all([api("/api/authorizations?only_valid=true"),
    api("/api/models").catch(() => ({ available: false, models: [] }))]);
  if (!auths.length) {
    show(el("h1", {}, "Nuova scansione"),
      msg("Nessuna autorizzazione valida: registrane una prima di scansionare.", "error"),
      el("a", { href: "#/auth" }, "Vai alle autorizzazioni"));
    return;
  }
  const target = el("input", { name: "target_url", required: true, value: auths[0].target_url });
  const authSel = el("select", { name: "authorization_id",
    onchange: (e) => { target.value = auths.find((a) => a.id === e.target.value).target_url; } },
  auths.map((a) => el("option", { value: a.id },
    `${a.target_url} — ${a.kind === "lab" ? "laboratorio" : "sito reale"} (fino al ${fmtDate(a.valid_until)})`)));
  const modelSel = el("select", { name: "model" },
    el("option", { value: "" }, models.available ? `predefinito (${models.default})` : "Ollama non disponibile"),
    (models.models || []).map((m) => el("option", { value: m }, m)));
  const out = el("div");
  const form = el("form", { class: "card", onsubmit: async (ev) => {
    ev.preventDefault();
    const d = formData(form);
    const body = { authorization_id: d.authorization_id, target_url: d.target_url,
      options: { label: d.label, model: d.model, use_ai: d.use_ai, force_wordpress: d.force_wordpress,
        planner: d.planner, burp: d.burp } };
    try {
      const r = await api("/api/scans", { method: "POST", body });
      location.hash = `#/scan/${r.id}`;
    } catch (e) { out.replaceChildren(msg(e.message)); }
  } },
  el("div", { class: "grid" },
    el("label", {}, "Autorizzazione", authSel),
    el("label", {}, "Target (deve essere nel perimetro)", target),
    el("label", {}, "Etichetta (es. prima, dopo)", el("input", { name: "label", maxlength: 60 })),
    el("label", {}, "Modello IA", modelSel),
    el("label", {}, "Pianificatore", el("select", { name: "planner" },
      el("option", { value: "deterministic" }, "deterministico (consigliato)"),
      el("option", { value: "llm" }, "LLM (sperimentale, solo ordine)"))),
    el("label", {}, "Proxy Burp (host:porta, facoltativo)", el("input", { name: "burp", placeholder: "127.0.0.1:8080" }))),
  el("div", { class: "row" },
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "use_ai", checked: models.available }), "Usa l'IA locale"),
    el("label", { class: "check" }, el("input", { type: "checkbox", name: "force_wordpress" }), "Forza i controlli WordPress")),
  el("p", { class: "muted" }, "Solo richieste in lettura dal registro chiuso delle sonde; nessun login né exploit."),
  el("button", { type: "submit" }, "Avvia scansione"));
  show(el("h1", {}, "Nuova scansione"), form, out);
}

// ------------------------------------------------------------ dettaglio scansione
function findingCard(f) {
  const body = [
    el("p", {}, f.summary),
    el("p", { class: "muted" }, `Percorso: ${f.path} · confidenza ${f.confidence}`,
      f.cwe ? ` · ${f.cwe}` : "", f.priority ? ` · ${f.priority}` : ""),
  ];
  if (f.impact) body.push(el("p", {}, el("b", {}, "Impatto: "), f.impact));
  if (f.likelihood) body.push(el("p", {}, el("b", {}, "Probabilità: "), f.likelihood));
  for (const n of f.ai_notes || []) {
    body.push(el("div", { class: "ai" }, el("div", { class: "tag" },
      `IA (${n.model}, ${n.purpose})`, n.suggested_priority ? ` — priorità suggerita: ${n.suggested_priority}` : ""),
    n.text));
  }
  if (f.remediation) {
    const r = f.remediation;
    body.push(el("details", {}, el("summary", {}, `Correzione: ${r.title}`),
      el("p", {}, r.summary),
      [["WordPress", r.wordpress], ["Apache", r.apache], ["Nginx", r.nginx], ["Verifica", r.verification]]
        .filter(([, t]) => t).map(([l, t]) => [el("b", {}, l), el("pre", {}, t)]),
      r.risks ? el("p", {}, el("b", {}, "Rischi: "), r.risks) : null));
  }
  const h = f.history || [];
  if (h.length) {
    body.push(el("details", {}, el("summary", {}, "Storia dello stato"),
      el("ul", {}, h.map((c) => el("li", {}, `${c.from_status || "—"} → ${c.to_status} (${c.agent}): ${c.reason}`)))));
  }
  return el("div", { class: "card" },
    el("div", { class: "row" }, el("b", {}, f.title),
      f.severity ? badge(SEV_IT[f.severity], `s-${f.severity}`) : null,
      badge(STATUS_IT[f.status] || f.status, `st-${f.status}`)),
    body);
}

function findingTable(list) {
  return el("div", { class: "table-wrap" }, el("table", {},
    el("tr", {}, ["Controllo", "Esito", "Dettaglio"].map((x) => el("th", {}, x))),
    list.map((f) => el("tr", {}, el("td", {}, f.title),
      el("td", {}, badge(STATUS_IT[f.status] || f.status, `st-${f.status}`)),
      el("td", {}, f.summary)))));
}

async function viewScan(id) {
  let s;
  try { s = await api(`/api/scans/${encodeURIComponent(id)}`); } catch (e) {
    show(msg(e.message));
    if (/avvio/.test(e.message)) pollTimer = setTimeout(() => viewScan(id), 800);
    return;
  }
  const done = s.agents.filter((a) => !["pending", "running"].includes(a.state)).length;
  const bar = el("div"); bar.style.width = `${s.agents.length ? (100 * done) / s.agents.length : 0}%`;
  const by = (st) => s.findings.filter((f) => st.includes(f.status));
  const confirmed = by(["confirmed"]);
  const header = el("div", {},
    el("h1", {}, `Scansione di ${s.target}`),
    el("p", { class: "muted" }, `${fmtDate(s.started_at)} · ${s.status}`,
      s.options.label ? ` · ${s.options.label}` : "", s.model_used ? ` · IA: ${s.model_used}` : " · senza IA",
      ` · ${s.network_mode}`, s.source !== "v4" ? " · importata dalla v3" : ""),
    s.error ? msg(s.error) : null);
  const actions = el("div", { class: "row" });
  if (s.live) {
    actions.append(el("button", { class: "danger", onclick: async () => {
      try { await api(`/api/scans/${id}/cancel`, { method: "POST" }); } catch (e) { alert(e.message); }
    } }, "Annulla scansione"));
  } else {
    for (const f of ["html", "pdf", "md", "json"]) {
      actions.append(el("a", { href: `/api/scans/${id}/report.${f}`, target: "_blank", rel: "noopener" }, `Report ${f.toUpperCase()}`));
    }
    actions.append(el("a", { href: `/api/scans/${id}/report.pdf?anonymize=true` }, "PDF anonimizzato"));
  }
  const agents = el("div", { class: "card" }, el("div", { class: "progress" }, bar),
    el("div", { class: "table-wrap" }, el("table", {},
      el("tr", {}, ["Agente", "Stato", "Durata", "Richieste", "Esito"].map((x) => el("th", {}, x))),
      s.agents.map((a) => el("tr", {}, el("td", {}, a.display_name, a.uses_ai ? " (IA)" : ""),
        el("td", { class: `ag-${a.state}` }, AGENT_IT[a.state] || a.state),
        el("td", {}, `${a.duration_s.toFixed(2)}s`), el("td", {}, a.requests),
        el("td", {}, a.message || a.error || ""))))));
  const sev = {}; confirmed.forEach((f) => { sev[f.severity] = (sev[f.severity] || 0) + 1; });
  const tiles = el("div", { class: "tiles" },
    ["critical", "high", "medium", "low"].map((k) => el("div", { class: "tile" }, el("b", { class: `s-${k}` }, sev[k] || 0), SEV_IT[k])),
    el("div", { class: "tile" }, el("b", { class: "st-inconclusive" }, by(["inconclusive"]).length), "Inconcludenti"));
  const parts = [header, actions, agents, tiles];
  if (s.executive_summary) {
    parts.push(el("h2", {}, "Sintesi"), s.executive_summary_ai
      ? el("div", { class: "ai" }, el("div", { class: "tag" }, `IA locale (${s.model_used})`), s.executive_summary)
      : el("p", {}, s.executive_summary));
  }
  const lims = (s.stats || {}).limitations || [];
  if (lims.length) parts.push(el("h2", {}, "Limiti dell'analisi"), el("ul", {}, lims.map((l) => el("li", {}, l))));
  parts.push(el("h2", {}, `Problemi confermati (${confirmed.length})`),
    confirmed.length ? confirmed.map(findingCard) : el("p", { class: "muted" }, s.live ? "In attesa della validazione…" : "Nessuno."));
  const groups = [["Da verificare manualmente", ["inconclusive", "candidate", "not_detected"]],
    ["Falsi positivi scartati", ["false_positive"]], ["Errori", ["error"]],
    ["Controlli superati", ["not_present"]], ["Contesto", ["info", "not_applicable"]]];
  for (const [title, st] of groups) {
    const list = by(st);
    if (list.length) parts.push(el("details", { class: "card", open: st[0] === "inconclusive" },
      el("summary", {}, `${title} (${list.length})`), findingTable(list)));
  }
  show(...parts);
  if (s.live) pollTimer = setTimeout(() => viewScan(id), 1000);
}

// ------------------------------------------------------------ autorizzazioni
async function viewAuth() {
  const auths = await api("/api/authorizations");
  const out = el("div");
  const now = new Date();
  const list = el("div", { class: "card table-wrap" }, el("table", {},
    el("tr", {}, ["Target", "Tipo", "Autorizzata da", "Validità", "Stato", ""].map((x) => el("th", {}, x))),
    auths.map((a) => {
      const valid = !a.revoked && new Date(a.valid_from) <= now && now <= new Date(a.valid_until);
      return el("tr", {}, el("td", {}, a.target_url, el("div", { class: "muted" }, a.scope.length > 1 ? `+${a.scope.length - 1} origini` : "")),
        el("td", {}, a.kind === "lab" ? "laboratorio" : "sito reale"),
        el("td", {}, `${a.authorizer_name} (${a.authorizer_role})`, el("div", { class: "muted" }, a.document_ref)),
        el("td", {}, `${fmtDate(a.valid_from)} → ${fmtDate(a.valid_until)}`),
        el("td", {}, a.revoked ? badge("revocata", "st-error") : valid ? badge("valida", "st-not_present") : badge("non valida", "st-info")),
        el("td", {}, a.revoked ? "" : el("button", { class: "danger", onclick: async () => {
          if (!confirm(`Revocare l'autorizzazione per ${a.target_url}?`)) return;
          try { await api(`/api/authorizations/${a.id}/revoke`, { method: "POST" }); viewAuth(); } catch (e) { out.replaceChildren(msg(e.message)); }
        } }, "Revoca")));
    })));
  const form = el("form", { class: "card", onsubmit: async (ev) => {
    ev.preventDefault();
    const d = formData(form);
    const body = { kind: d.kind, target_url: d.target_url, authorizer_name: d.authorizer_name,
      authorizer_role: d.authorizer_role, operator: d.operator, document_ref: d.document_ref,
      document_sha256: d.document_sha256, days: d.days ? Number(d.days) : null, notes: d.notes,
      extra_scope: d.extra_scope ? d.extra_scope.split(/[\s,]+/).filter(Boolean) : [] };
    try { await api("/api/authorizations", { method: "POST", body }); viewAuth(); } catch (e) { out.replaceChildren(msg(e.message)); }
  } },
  el("div", { class: "grid" },
    el("label", {}, "Tipo", el("select", { name: "kind" },
      el("option", { value: "engagement" }, "Sito reale (autorizzazione scritta)"),
      el("option", { value: "lab" }, "Laboratorio locale (127.0.0.1)"))),
    el("label", {}, "Target", el("input", { name: "target_url", required: true, placeholder: "https://www.esempio.it" })),
    el("label", {}, "Altre origini nel perimetro", el("input", { name: "extra_scope", placeholder: "https://esempio.it http://esempio.it" })),
    el("label", {}, "Autorizzata da", el("input", { name: "authorizer_name", required: true })),
    el("label", {}, "Ruolo di chi autorizza", el("input", { name: "authorizer_role", required: true, placeholder: "Titolare del sito" })),
    el("label", {}, "Operatore", el("input", { name: "operator", required: true })),
    el("label", {}, "Riferimento al documento firmato", el("input", { name: "document_ref" })),
    el("label", {}, "SHA-256 del documento (facoltativo)", el("input", { name: "document_sha256", maxlength: 64 })),
    el("label", {}, "Durata in giorni", el("input", { name: "days", type: "number", min: 1, max: 365, value: 7 })),
    el("label", {}, "Note", el("input", { name: "notes" }))),
  el("button", { type: "submit" }, "Registra autorizzazione"));
  show(el("h1", {}, "Autorizzazioni"), out, form, el("h2", {}, "Registrate"),
    auths.length ? list : el("p", { class: "muted" }, "Nessuna autorizzazione registrata."));
}

// ------------------------------------------------------------ confronto
async function viewCompare() {
  const scans = (await api("/api/scans?limit=200")).filter((s) => s.status === "completed");
  const opt = (s) => el("option", { value: s.id }, `${fmtDate(s.started_at)} — ${s.target}${s.label ? ` (${s.label})` : ""}${s.source !== "v4" ? " [v3]" : ""}`);
  const before = el("select", { name: "before" }, scans.map(opt));
  const after = el("select", { name: "after" }, scans.map(opt));
  if (scans.length > 1) before.selectedIndex = 1;
  const out = el("div");
  const form = el("form", { class: "card row", onsubmit: async (ev) => {
    ev.preventDefault();
    try {
      const c = await api(`/api/compare?before=${encodeURIComponent(before.value)}&after=${encodeURIComponent(after.value)}`);
      out.replaceChildren(
        ...c.warnings.map((w) => msg(w, "error")),
        el("div", { class: "tiles" }, ["resolved", "still_open", "new", "not_comparable"].map((k) =>
          el("div", { class: "tile" }, el("b", { class: `o-${k}` }, c.counts[k]), OUTCOME_IT[k]))),
        el("div", { class: "card table-wrap" }, el("table", {},
          el("tr", {}, ["Controllo", "Prima", "Dopo", "Esito", "Motivo"].map((x) => el("th", {}, x))),
          c.rows.filter((r) => r.outcome !== "info").map((r) => el("tr", {}, el("td", {}, r.title),
            el("td", {}, STATUS_IT[r.before] || "-"), el("td", {}, STATUS_IT[r.after] || "-"),
            el("td", { class: `o-${r.outcome}` }, OUTCOME_IT[r.outcome]), el("td", {}, r.reason))))),
        el("a", { href: `/api/compare?before=${encodeURIComponent(before.value)}&after=${encodeURIComponent(after.value)}&format=md`, target: "_blank", rel: "noopener" }, "Scarica in Markdown"));
    } catch (e) { out.replaceChildren(msg(e.message)); }
  } },
  el("label", {}, "Prima", before), el("label", {}, "Dopo", after),
  el("button", { type: "submit" }, "Confronta"));
  show(el("h1", {}, "Confronto prima/dopo"),
    scans.length < 2 ? el("p", { class: "muted" }, "Servono almeno due scansioni completate dello stesso sito.") : form, out);
}

// ------------------------------------------------------------ router
async function route() {
  clearTimeout(pollTimer);
  const [, name = "scans", arg] = location.hash.split("/");
  document.querySelectorAll("nav a").forEach((a) => a.classList.toggle("active", a.dataset.route === name));
  try {
    if (name === "scan" && arg) await viewScan(decodeURIComponent(arg));
    else if (name === "new") await viewNew();
    else if (name === "auth") await viewAuth();
    else if (name === "compare") await viewCompare();
    else await viewScans();
  } catch (e) { show(msg(e.message)); }
}

window.addEventListener("hashchange", route);
window.addEventListener("DOMContentLoaded", async () => {
  route();
  try { document.getElementById("version").textContent = `v${(await api("/api/health")).version}`; } catch { /* facoltativo */ }
});
