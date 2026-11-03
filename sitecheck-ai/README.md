# SiteCheck AI — Website SEO Analyzer

Analyzes one public page and reports technical, on-page and content SEO findings, a transparent score and fix recommendations. It does **not** measure rankings, traffic, backlinks, Core Web Vitals or real indexing status.

## Quick start
- **Windows:** double-click `run.bat`
- **macOS/Linux:** `./run.sh`

It creates a virtual environment, installs dependencies, starts the server and opens http://localhost:8000.

## Manual run
```bash
cd backend
python -m venv .venv
.venv\Scripts\activate          # macOS/Linux: source .venv/bin/activate
pip install -r requirements.txt
uvicorn main:app --port 8000
```
Open **http://localhost:8000** — the backend serves the frontend too, so one command is enough.
(Live Server on port 5500 also works while the backend runs on 8000.)

## Structure
```
sitecheck-ai/
├── index.html, results.html
├── css/style.css
├── js/app.js (landing), api.js (backend client), results.js (dashboard)
└── backend/main.py, requirements.txt
```

## Scoring
Each check has a weight in `WEIGHTS` (top of `backend/main.py`). Pass = full weight, warning = half, fail = zero.
Score = points earned / weight of verifiable checks. Checks that couldn't be verified (e.g. no sitemap at a guessed URL) are excluded, never counted as failures. Technical, on-page and content scores use the same formula per category.

## Security
http/https only, ports 80/443/8080/8443, every DNS result must be a public IP, the connection is made to the validated IP (anti DNS-rebinding), manual redirects each re-validated (max 5), 5s connect / 10s read timeouts, 2 MB size cap, 10 requests/minute/IP, proxies ignored.

## Not measured
Rankings, organic traffic, backlinks, Core Web Vitals, real indexing. JavaScript-rendered content isn't seen (only server-delivered HTML is analyzed).
