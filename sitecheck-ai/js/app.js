/* SiteCheck AI — landing page logic */
const API_BASE = window.SITECHECK_API || (location.port === "8000" ? "" : "http://localhost:8000"); // same origin when served by the backend
const HISTORY_KEY = "sitecheck_history";

const $ = (id) => document.getElementById(id);
const form = $("analyzeForm"), input = $("urlInput"), errBox = $("urlError");

/* ---------- URL validation (client-side; the server re-validates everything) ---------- */
function normalizeUrl(raw) {
  let v = raw.trim();
  if (!v) throw new Error("Enter a website URL to analyze.");
  if (/\s/.test(v)) throw new Error("The URL can't contain spaces.");
  if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(v)) {
    if (/^[a-z][a-z0-9+.-]*:/i.test(v) && !/^[^/]+:\d+/.test(v))
      throw new Error("Only http:// and https:// URLs are supported.");
    v = "https://" + v;
  }
  let u;
  try { u = new URL(v); } catch { throw new Error("That doesn't look like a valid URL. Try https://example.com"); }
  if (!["http:", "https:"].includes(u.protocol)) throw new Error("Only http:// and https:// URLs are supported.");
  if (u.username || u.password) throw new Error("URLs with embedded credentials are not allowed.");
  const h = u.hostname.toLowerCase();
  if (h === "localhost" || h.endsWith(".localhost") || h.endsWith(".local") || h.endsWith(".internal"))
    throw new Error("Local and internal addresses can't be analyzed. Use a public website.");
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h) || h.includes(":"))
    throw new Error("Please use a domain name rather than an IP address.");
  if (!h.includes(".")) throw new Error("Enter a full domain name, like example.com.");
  return u.href;
}

function showError(msg) {
  errBox.textContent = msg;
  errBox.hidden = false;
  input.setAttribute("aria-invalid", "true");
}
function clearError() { errBox.hidden = true; input.removeAttribute("aria-invalid"); }

form.addEventListener("submit", (e) => {
  e.preventDefault();
  clearError();
  try {
    const url = normalizeUrl(input.value);
    $("analyzeBtn").disabled = true;
    // results.html runs the real analysis through the backend
    location.href = "results.html?url=" + encodeURIComponent(url);
  } catch (err) {
    showError(err.message);
    input.focus();
  }
});
input.addEventListener("input", clearError);
$("exampleBtn").addEventListener("click", () => { input.value = "https://example.com"; clearError(); input.focus(); });

/* ---------- Backend status ---------- */
async function checkBackend() {
  const el = $("apiStatus");
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 4000);
    const res = await fetch(API_BASE + "/api/health", { signal: ctrl.signal });
    clearTimeout(t);
    if (!res.ok) throw new Error();
    el.textContent = "Backend online"; el.className = "status on";
  } catch {
    el.textContent = "Backend offline"; el.className = "status off";
    el.title = "Start the FastAPI server (see README) to run analyses.";
  }
}

/* ---------- History (written by results.js, read here) ---------- */
function loadHistory() {
  try { return JSON.parse(localStorage.getItem(HISTORY_KEY)) || []; } catch { return []; }
}
function scoreClass(s) { return s >= 80 ? "good" : s >= 50 ? "mid" : "low"; }

function renderHistory() {
  const items = loadHistory();
  $("historySection").hidden = items.length === 0;
  const list = $("historyList");
  list.replaceChildren();
  items.forEach((it) => {
    const li = document.createElement("li");
    const a = document.createElement("a");
    a.href = "results.html?url=" + encodeURIComponent(it.url);
    const u = document.createElement("span"); u.className = "h-url"; u.textContent = it.title || it.url;
    const m = document.createElement("span"); m.className = "h-meta";
    m.textContent = it.url + " · " + new Date(it.timestamp).toLocaleString();
    a.append(u, m);
    const b = document.createElement("span");
    b.className = "badge " + scoreClass(it.score); b.textContent = it.score;
    b.setAttribute("aria-label", "Score " + it.score + " out of 100");
    li.append(a, b);
    list.append(li);
  });
  if (window.lucide) lucide.createIcons();
}

$("clearHistory").addEventListener("click", () => {
  if (confirm("Clear all recent analyses? This can't be undone.")) {
    try { localStorage.removeItem(HISTORY_KEY); } catch {}
    renderHistory();
  }
});

/* ---------- Init ---------- */
$("year").textContent = new Date().getFullYear();
renderHistory();
checkBackend();
if (window.lucide) lucide.createIcons();
