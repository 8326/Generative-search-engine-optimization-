/* SiteCheck AI — results dashboard */
const $ = (id) => document.getElementById(id);
const HISTORY_KEY = "sitecheck_history";
const target = new URLSearchParams(location.search).get("url");
let data = null, filter = "issues";

function el(tag, cls, text) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (text !== undefined) e.textContent = text;   // textContent only: page data is untrusted
  return e;
}
const scoreColor = (s) => (s >= 80 ? "var(--ok)" : s >= 50 ? "var(--warn)" : "var(--bad)");
const fmt = (v) => (v === null || v === undefined ? "n/a" : v);
const STAGES = ["Validating URL and resolving DNS", "Fetching the page", "Parsing the HTML",
                "Checking robots.txt and sitemap", "Calculating the score"];

/* ---------- run ---------- */
async function run() {
  if (!target) { location.href = "index.html"; return; }
  $("report").hidden = true; $("errorBox").hidden = true; $("loading").hidden = false;
  $("loadUrl").textContent = target;
  const ol = $("stages"); ol.replaceChildren(...STAGES.map((s) => el("li", "", s)));
  let i = 0;
  const mark = () => [...ol.children].forEach((li, n) => (li.className = n < i ? "done" : n === i ? "now" : ""));
  mark();
  const timer = setInterval(() => { if (i < STAGES.length - 1) { i++; mark(); } }, 1800);
  try {
    data = await analyzeUrl(target);
    clearInterval(timer); i = STAGES.length; mark();
    render(data); saveHistory(data);
  } catch (e) {
    clearInterval(timer);
    $("loading").hidden = true; $("errorBox").hidden = false; $("errorMsg").textContent = e.message;
  }
}

/* ---------- render ---------- */
function render(d) {
  $("loading").hidden = true; $("report").hidden = false;
  document.title = "SEO Report: " + d.title;
  $("pTitle").textContent = d.title;
  const a = $("pUrl"); a.textContent = d.url; a.href = d.url;
  $("pMeta").textContent = "HTTP " + d.status + " · Analyzed " + new Date(d.timestamp).toLocaleString() +
    (d.truncated ? " · Page was larger than the size limit; only the first part was analyzed." : "");

  const s = d.scores, C = 2 * Math.PI * 54, ring = $("ring");
  ring.style.strokeDasharray = C; ring.style.strokeDashoffset = C;
  ring.style.stroke = scoreColor(s.overall);
  requestAnimationFrame(() => (ring.style.strokeDashoffset = C * (1 - (s.overall || 0) / 100)));
  $("ringNum").textContent = fmt(s.overall); $("ringNum").style.color = scoreColor(s.overall);
  $("ringWrap").setAttribute("aria-label", "SEO health score " + s.overall + " out of 100");
  $("sTech").textContent = fmt(s.technical); $("sPage").textContent = fmt(s.onpage); $("sCont").textContent = fmt(s.content);
  $("cPass").textContent = d.counts.pass; $("cWarn").textContent = d.counts.warn;
  $("cFail").textContent = d.counts.fail; $("cUnv").textContent = d.counts.unverified;

  const pr = $("priorities"); pr.replaceChildren();
  const top = d.checks.filter((c) => c.status === "fail" || c.status === "warn").slice(0, 5);
  if (!top.length) pr.append(el("li", "", "No failed checks or warnings. Nice work!"));
  top.forEach((c) => pr.append(el("li", "", c.title + ": " + c.detected)));

  const f = d.facts, box = $("facts"); box.replaceChildren();
  [["HTTP status", d.status], ["Internal links", f.internal_links], ["External links", f.external_links],
   ["Images", f.images + " (" + f.images_missing_alt + " missing alt)"],
   ["Structured data", f.structured_types.length ? f.structured_types.join(", ") : "None detected"],
   ["Word count", f.word_count], ["Redirects followed", d.redirects]].forEach(([k, v]) => {
    const c = el("div", "card fact"); c.append(el("span", "muted small", k), el("b", "", String(v))); box.append(c);
  });

  $("howNote").textContent = d.method.note;
  $("weights").replaceChildren(...Object.entries(d.method.weights).map(([k, v]) => el("li", "", k.replace(/_/g, " ") + ": " + v)));
  renderChecks();
  if (window.lucide) lucide.createIcons();
}

const LABEL = { pass: "Passed", warn: "Warning", fail: "Failed", unverified: "Not verified" };
function visible(c) {
  return { issues: c.status !== "pass", high: c.severity === "high" && c.status !== "pass",
           warn: c.status === "warn", pass: c.status === "pass", unverified: c.status === "unverified" }[filter];
}
function renderChecks() {
  const box = $("checks"); box.replaceChildren();
  const list = data.checks.filter(visible);
  if (!list.length) box.append(el("p", "muted", "Nothing to show for this filter."));
  list.forEach((c) => {
    const d = el("details", "chk " + c.status);
    d.open = c.status === "fail";
    const sm = el("summary");
    sm.append(el("span", "pill " + c.status, LABEL[c.status]), el("span", "ttl", c.title),
              el("span", "sev " + c.severity, c.severity));
    d.append(sm);
    const body = el("div", "cbody");
    const row = (h, t) => { const p = el("p"); p.append(el("b", "", h + " "), document.createTextNode(t)); body.append(p); };
    row("Detected:", c.detected);
    row("Why it matters:", c.why);
    if (c.fix) row("How to fix:", c.fix);
    if (c.example) { const pre = el("pre"); pre.append(el("code", "", c.example)); body.append(pre); }
    d.append(body); box.append(d);
  });
}
$("filters").addEventListener("click", (e) => {
  const b = e.target.closest("button"); if (!b) return;
  filter = b.dataset.f;
  [...$("filters").children].forEach((x) => x.classList.toggle("on", x === b));
  renderChecks();
});

/* ---------- history & export ---------- */
function saveHistory(d) {
  try {
    const h = (JSON.parse(localStorage.getItem(HISTORY_KEY)) || []).filter((x) => x.url !== d.requested_url);
    h.unshift({ url: d.requested_url, title: d.title, score: d.scores.overall, timestamp: d.timestamp });
    localStorage.setItem(HISTORY_KEY, JSON.stringify(h.slice(0, 10)));
  } catch {}
}
function download(name, text, type) {
  const a = document.createElement("a");
  a.href = URL.createObjectURL(new Blob([text], { type }));
  a.download = name; a.click(); URL.revokeObjectURL(a.href);
}
const slug = () => new URL(data.url).hostname.replace(/\W+/g, "-");
$("jsonBtn").onclick = () => download("sitecheck-" + slug() + ".json", JSON.stringify(data, null, 2), "application/json");
$("csvBtn").onclick = () => {
  const q = (v) => '"' + String(v).replace(/"/g, '""') + '"';
  const rows = [["id", "category", "status", "severity", "title", "detected", "fix"]].concat(
    data.checks.map((c) => [c.id, c.category, c.status, c.severity, c.title, c.detected, c.fix]));
  download("sitecheck-" + slug() + ".csv", rows.map((r) => r.map(q).join(",")).join("\n"), "text/csv");
};
$("printBtn").onclick = () => { document.querySelectorAll("details.chk").forEach((d) => (d.open = true)); window.print(); };
$("reBtn").onclick = run;
$("retryBtn").onclick = run;

run();
if (window.lucide) lucide.createIcons();
