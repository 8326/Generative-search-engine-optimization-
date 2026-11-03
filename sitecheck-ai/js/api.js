/* SiteCheck AI — backend client */
const API_BASE = window.SITECHECK_API || (location.port === "8000" ? "" : "http://localhost:8000"); // same origin when served by the backend

async function analyzeUrl(url) {
  let res;
  try {
    res = await fetch(API_BASE + "/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
  } catch {
    throw new Error("Can't reach the SiteCheck backend. Start it with: uvicorn main:app --port 8000 (see README).");
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(typeof data.detail === "string" ? data.detail : "Analysis failed (HTTP " + res.status + ").");
  return data;
}
