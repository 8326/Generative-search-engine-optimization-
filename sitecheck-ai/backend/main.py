"""SiteCheck AI backend: SSRF-safe, single-page SEO analyzer.
Run:  uvicorn main:app --port 8000   then open http://localhost:8000"""
import ipaddress, json, re, socket, time
from collections import defaultdict, deque
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from urllib3.util import connection as u3conn

# ---------------- settings ----------------
MAX_BYTES, TIMEOUT, MAX_REDIRECTS = 2_000_000, (5, 10), 5
RATE_LIMIT, RATE_WINDOW = 10, 60          # requests per IP per window (seconds)
ALLOWED_PORTS = {80, 443, 8080, 8443}
UA = "SiteCheckAI/1.0 (SEO audit tool)"
# Configurable check weights. Score = weighted share of points earned (pass=1, warn=0.5, fail=0).
# Checks that could not be verified are excluded, never counted as failures.
WEIGHTS = {"http_status": 10, "https": 8, "canonical": 5, "robots_meta": 8, "viewport": 6, "lang": 3,
           "robots_txt": 3, "sitemap": 3, "internal_links": 4,
           "title": 10, "meta_description": 8, "h1": 6, "heading_order": 3, "open_graph": 3,
           "structured_data": 4, "image_alt": 5,
           "word_count": 8, "readability": 4, "heading_quality": 5, "link_text": 4,
           "title_quality": 4, "desc_quality": 3}
POINTS = {"pass": 1.0, "warn": 0.5, "fail": 0.0}

# ---------------- SSRF protection ----------------
class Blocked(Exception):
    pass

def check_ip(raw):
    ip = ipaddress.ip_address(raw.split("%")[0])
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    if not ip.is_global or ip.is_multicast:
        raise Blocked("That address points to a private or internal network and can't be analyzed.")
    return str(ip)

def safe_ips(host, port):
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror:
        raise Blocked("The domain name could not be resolved.")
    ips = list(dict.fromkeys(check_ip(i[4][0]) for i in infos))  # every result must be public
    if not ips:
        raise Blocked("The domain name could not be resolved.")
    return ips

# DNS-rebinding defence: resolve, validate AND connect inside one function, so the IP that was
# checked is the IP that is used. (TLS/SNI still uses the original hostname.)
_orig_cc = u3conn.create_connection
def _safe_create_connection(address, *a, **kw):
    host, port = address
    last = None
    for ip in safe_ips(host.strip("[]"), port):
        try:
            return _orig_cc((ip, port), *a, **kw)
        except OSError as e:
            last = e
    raise last or OSError("connection failed")
u3conn.create_connection = _safe_create_connection

def validate_url(url):
    p = urlparse(url)
    if p.scheme not in ("http", "https"):
        raise Blocked("Only http:// and https:// URLs are allowed.")
    if not p.hostname:
        raise Blocked("The URL has no hostname.")
    if p.username or p.password:
        raise Blocked("URLs with embedded credentials are not allowed.")
    try:
        port = p.port or (443 if p.scheme == "https" else 80)
    except ValueError:
        raise Blocked("The URL has an invalid port.")
    if port not in ALLOWED_PORTS:
        raise Blocked("Only ports 80, 443, 8080 and 8443 are allowed.")
    h = p.hostname.lower()
    if h == "localhost" or h.endswith((".localhost", ".local", ".internal")):
        raise Blocked("Local and internal addresses can't be analyzed.")
    safe_ips(h, port)

def fetch(url, max_bytes=MAX_BYTES):
    """GET with manual redirects (every hop validated), timeouts and a size cap."""
    s = requests.Session()
    s.trust_env = False                      # ignore proxy env vars
    hops = 0
    for _ in range(MAX_REDIRECTS + 1):
        validate_url(url)
        r = s.get(url, headers={"User-Agent": UA, "Accept": "text/html,application/xhtml+xml,*/*;q=0.8"},
                  timeout=TIMEOUT, allow_redirects=False, stream=True)
        loc = r.headers.get("location")
        if r.status_code in (301, 302, 303, 307, 308) and loc:
            url = urljoin(url, loc); hops += 1; r.close(); continue
        body, truncated = b"", False
        for chunk in r.iter_content(16384):
            body += chunk
            if len(body) > max_bytes:
                body, truncated = body[:max_bytes], True
                break
        r.close()
        return {"url": url, "status": r.status_code, "headers": r.headers, "body": body,
                "redirects": hops, "truncated": truncated}
    raise Blocked("Too many redirects.")

def probe(url, max_bytes=200_000):
    try:
        return fetch(url, max_bytes)
    except Exception:
        return None

# ---------------- helpers ----------------
def syllables(w):
    n = len(re.findall(r"[aeiouy]+", w.lower()))
    return max(n - 1 if w.lower().endswith("e") and n > 1 else n, 1)

def blocks_all(txt):
    ua = False
    for ln in txt.splitlines():
        ln = ln.split("#")[0].strip().lower()
        if ln.startswith("user-agent:"):
            ua = ln.split(":", 1)[1].strip() == "*"
        elif ua and ln.replace(" ", "") == "disallow:/":
            return True
    return False

GENERIC_LINKS = {"click here", "here", "read more", "more", "learn more", "link", "this link", "details", "click"}
GENERIC_TITLES = {"home", "homepage", "untitled", "index", "welcome", "document", "new page"}

# ---------------- page parsing ----------------
def parse_page(page):
    soup = BeautifulSoup(page["body"], "html.parser")
    final = page["url"]
    host = urlparse(final).netloc.lower().removeprefix("www.")
    metas = {(m.get("name") or m.get("property") or "").lower(): (m.get("content") or "").strip()
             for m in soup.find_all("meta")}
    canon = next((l.get("href", "") for l in soup.find_all("link", href=True)
                  if "canonical" in [x.lower() for x in (l.get("rel") or [])]), None)
    heads = [(int(h.name[1]), h.get_text(" ", strip=True)) for h in soup.find_all(re.compile(r"^h[1-6]$"))]
    internal, external, generic = 0, 0, []
    for a in soup.find_all("a", href=True):
        href = a["href"].strip()
        if href.startswith(("#", "javascript:", "mailto:", "tel:")):
            continue
        p = urlparse(urljoin(final, href))
        if p.scheme not in ("http", "https"):
            continue
        if p.netloc.lower().removeprefix("www.") == host:
            internal += 1
        else:
            external += 1
        txt = (a.get_text(" ", strip=True) or a.get("aria-label") or "").strip().lower()
        if txt in GENERIC_LINKS:
            generic.append(txt)
    imgs = soup.find_all("img")
    no_alt = [i.get("src", "(no src)")[:80] for i in imgs if i.get("alt") is None]
    types, bad_ld = [], 0
    for sc in soup.find_all("script", type=lambda t: t and "ld+json" in t.lower()):
        try:
            d = json.loads(sc.string or "")
            for it in (d if isinstance(d, list) else d.get("@graph", [d])):
                if isinstance(it, dict) and it.get("@type"):
                    types.append(str(it["@type"]))
        except Exception:
            bad_ld += 1
    microdata = len(soup.find_all(attrs={"itemscope": True}))
    for s in soup(["script", "style", "noscript", "template"]):
        s.decompose()
    text = soup.get_text(" ", strip=True)
    words = re.findall(r"[A-Za-z0-9']+", text)
    return {
        "title": soup.title.get_text(strip=True) if soup.title else "", "desc": metas.get("description"),
        "canonical": canon, "robots": metas.get("robots", ""), "viewport": metas.get("viewport"),
        "lang": (soup.html.get("lang") if soup.html else None), "metas": metas, "headings": heads,
        "internal": internal, "external": external, "generic_links": generic,
        "images": len(imgs), "no_alt": no_alt, "ld_types": types, "bad_ld": bad_ld, "microdata": microdata,
        "text": text, "words": len(words), "wordlist": words,
    }

# ---------------- checks ----------------
def run_checks(f, page, robots, sitemap):
    C = []
    def add(i, cat, title, st, sev, det, why, fix, ex=""):
        C.append({"id": i, "category": cat, "title": title, "status": st, "severity": sev,
                  "weight": WEIGHTS[i], "detected": det, "why": why, "fix": fix,
                  "example": ex if st in ("warn", "fail") else ""})
    T, P, N = "technical", "onpage", "content"
    s, final = page["status"], page["url"]
    # --- technical ---
    add("http_status", T, "Page accessibility (HTTP status)", "pass" if s < 400 else "fail", "high",
        f"Final status {s}" + (f" after {page['redirects']} redirect(s)." if page["redirects"] else "."),
        "Search engines can only index pages that respond successfully.",
        "Make the page return 200 for crawlers and fix server errors or blocks.")
    https = final.startswith("https://")
    add("https", T, "HTTPS", "pass" if https else "fail", "high",
        "Page is served over HTTPS." if https else "Page is served over plain HTTP.",
        "HTTPS protects visitors and is a lightweight ranking signal; browsers warn on HTTP pages.",
        "Install a TLS certificate and 301-redirect all HTTP URLs to HTTPS.")
    c = f["canonical"]
    add("canonical", T, "Canonical URL", "pass" if c else "warn", "medium",
        f"Canonical: {c}" if c else "No canonical link found.",
        "A canonical tells search engines which URL is the preferred version when duplicates exist.",
        "Add a self-referencing canonical to the head.", f'<link rel="canonical" href="{final}">')
    xrt = page["headers"].get("x-robots-tag", "")
    noidx = "noindex" in f["robots"].lower() or "noindex" in xrt.lower()
    add("robots_meta", T, "Robots directives", "fail" if noidx else "pass", "high",
        "A noindex directive was found." if noidx else
        (f"Robots meta: {f['robots']}" if f["robots"] else "No blocking robots directives found."),
        "A noindex directive asks search engines to keep this page out of results.",
        "Remove noindex (meta tag or X-Robots-Tag header) if the page should appear in search.",
        '<meta name="robots" content="index, follow">')
    add("viewport", T, "Viewport meta tag", "pass" if f["viewport"] else "fail", "medium",
        f"Viewport: {f['viewport']}" if f["viewport"] else "No viewport meta tag.",
        "Without it, mobile browsers render a desktop-width page, hurting mobile usability.",
        "Add a viewport meta tag.", '<meta name="viewport" content="width=device-width, initial-scale=1">')
    add("lang", T, "HTML language attribute", "pass" if f["lang"] else "warn", "low",
        f"lang=\"{f['lang']}\"" if f["lang"] else "The <html> tag has no lang attribute.",
        "Helps search engines and screen readers pick the right language.",
        "Set lang on the html element.", '<html lang="en">')
    rs = robots["state"]
    if rs == "found":
        blocked = blocks_all(robots["text"])
        add("robots_txt", T, "robots.txt", "fail" if blocked else "pass", "high" if blocked else "low",
            "robots.txt disallows all crawlers (Disallow: /)." if blocked else "robots.txt found.",
            "robots.txt controls which paths crawlers may fetch.",
            "Remove 'Disallow: /' for User-agent: * unless the site should be hidden.",
            "User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml")
    elif rs == "missing":
        add("robots_txt", T, "robots.txt", "warn", "low", "robots.txt returned 404 (confirmed missing).",
            "Not required, but it's the standard place to declare your sitemap and crawl rules.",
            "Create /robots.txt.", "User-agent: *\nAllow: /\nSitemap: https://example.com/sitemap.xml")
    else:
        add("robots_txt", T, "robots.txt", "unverified", "low", "robots.txt could not be fetched (error or timeout).",
            "Status unknown, so this check is excluded from the score.", "Re-run the analysis later.")
    sm = sitemap
    if sm["state"] == "found":
        add("sitemap", T, "XML sitemap", "pass", "low", f"Sitemap reachable at {sm['url']}.",
            "Sitemaps help crawlers discover URLs.", "")
    elif sm["state"] == "declared_unreachable":
        add("sitemap", T, "XML sitemap", "warn", "low", "robots.txt declares a sitemap that couldn't be fetched.",
            "A broken sitemap URL wastes the discovery hint.", "Fix the Sitemap: URL in robots.txt.")
    else:
        add("sitemap", T, "XML sitemap", "unverified", "low",
            "No sitemap found at the robots.txt entry or /sitemap.xml. It may exist elsewhere (sitemap index, CMS path), so this is not counted as a failure.",
            "Absence at a guessed URL doesn't prove there is no sitemap.",
            "If you have none, generate one and reference it in robots.txt.")
    add("internal_links", T, "Internal links", "pass" if f["internal"] else "warn", "medium",
        f"{f['internal']} internal and {f['external']} external links.",
        "Internal links help crawlers discover pages and spread relevance.",
        "Link to related pages on your site with descriptive anchor text.",
        '<a href="/guides/seo-basics">SEO basics guide</a>')
    # --- on-page ---
    t, tl = f["title"], len(f["title"])
    if not t:
        st, det = "fail", "No <title> tag."
    elif 30 <= tl <= 60:
        st, det = "pass", f"Title is {tl} characters: {t}"
    else:
        st, det = "warn", f"Title is {tl} characters ({'short' if tl < 30 else 'may be truncated in results'}): {t}"
    add("title", P, "Page title", st, "high" if st == "fail" else "medium", det,
        "The title is a primary signal for what the page is about and is often shown as the result headline.",
        "Write a unique, descriptive title of about 30-60 characters.",
        "<title>Handmade Leather Wallets | Brand Name</title>")
    d = f["desc"]
    if d is None or not d:
        st, det = "fail", "No meta description."
    elif 70 <= len(d) <= 160:
        st, det = "pass", f"Description is {len(d)} characters."
    else:
        st, det = "warn", f"Description is {len(d)} characters (aim for 70-160)."
    add("meta_description", P, "Meta description", st, "medium" if st == "fail" else "low", det,
        "A useful description can help searchers understand the page, although search engines may write their own snippet.",
        "Add a unique, relevant meta description to the head.",
        '<meta name="description" content="A concise summary of this page\'s content.">')
    h1 = [h for h in f["headings"] if h[0] == 1]
    st = "pass" if len(h1) == 1 else ("fail" if not h1 else "warn")
    add("h1", P, "H1 heading", st, "medium" if st == "fail" else "low",
        f"{len(h1)} H1 heading(s)" + (f": {h1[0][1]}" if h1 else "."),
        "The H1 states the main topic for users and search engines.",
        "Use one clear H1 that matches the page's topic.", "<h1>Handmade Leather Wallets</h1>")
    levels = [h[0] for h in f["headings"]]
    skips = [(a, b) for a, b in zip(levels, levels[1:]) if b > a + 1]
    add("heading_order", P, "Heading hierarchy", "warn" if skips else "pass", "low",
        f"Skipped levels, e.g. H{skips[0][0]} followed by H{skips[0][1]}." if skips else "No skipped heading levels.",
        "A logical outline helps accessibility and content understanding.",
        "Don't jump levels (H2 then H4); nest headings in order.")
    og = [k for k in ("og:title", "og:description", "og:image") if f["metas"].get(k)]
    add("open_graph", P, "Open Graph metadata", "pass" if len(og) == 3 else "warn", "low",
        f"Found: {', '.join(og) or 'none'}.", "Controls how the page looks when shared on social platforms.",
        "Add the three core Open Graph tags.",
        '<meta property="og:title" content="Page title">\n<meta property="og:description" content="Short summary">\n<meta property="og:image" content="https://example.com/image.jpg">')
    has_sd = bool(f["ld_types"]) or f["microdata"] > 0
    add("structured_data", P, "Structured data", "pass" if has_sd else "warn", "low",
        (f"JSON-LD types: {', '.join(f['ld_types'])}" if f["ld_types"] else f"{f['microdata']} microdata item(s).")
        if has_sd else "No structured data detected in the page HTML.",
        "Structured data can make a page eligible for rich results; it isn't a direct ranking factor.",
        "Add JSON-LD that matches the page type.",
        '<script type="application/ld+json">\n{"@context":"https://schema.org","@type":"Article","headline":"Title"}\n</script>')
    n, m = f["images"], len(f["no_alt"])
    st = "pass" if m == 0 else ("warn" if m / n <= 0.2 else "fail")
    add("image_alt", P, "Image alt text", st, "medium",
        f"{m} of {n} images have no alt attribute." if n else "No <img> elements found.",
        "Alt text describes images to screen readers and search engines (alt=\"\" is fine for decorative images).",
        "Add descriptive alt text to meaningful images.", '<img src="wallet.jpg" alt="Brown leather bifold wallet">')
    # --- content ---
    w = f["words"]
    st = "pass" if w >= 300 else ("warn" if w >= 100 else "fail")
    add("word_count", N, "Visible text length", st, "medium", f"{w} words in the server-delivered HTML"
        + ("; content added by JavaScript is not seen." if w < 100 else "."),
        "Very thin pages often give search engines too little to understand.",
        "Cover the topic fully for your audience (word count alone isn't a ranking factor).")
    lang = (f["lang"] or "en").lower()
    if w < 100 or not lang.startswith("en"):
        add("readability", N, "Readability", "unverified", "low",
            "Needs 100+ words of English text; not verified.", "Flesch scoring is English-only.", "")
    else:
        sents = max(1, len(re.findall(r"[.!?]+", f["text"][:20000])))
        wl = f["wordlist"][:3000]
        fre = 206.835 - 1.015 * (len(wl) / sents) - 84.6 * (sum(map(syllables, wl)) / len(wl))
        st = "pass" if fre >= 50 else ("warn" if fre >= 30 else "fail")
        add("readability", N, "Readability (Flesch)", st, "low", f"Flesch Reading Ease: {fre:.0f} (higher is easier).",
            "Text that's easy to scan keeps visitors engaged.", "Use shorter sentences and plainer words.")
    empty = sum(1 for h in f["headings"] if not h[1])
    seen, dup = set(), set()
    for h in f["headings"]:
        k = h[1].lower()
        if k and k in seen: dup.add(h[1])
        seen.add(k)
    st = "warn" if (empty or dup) else "pass"
    add("heading_quality", N, "Empty or repeated headings", st, "low",
        f"{empty} empty and {len(dup)} repeated heading(s)" + (f": {', '.join(list(dup)[:3])}" if dup else "")
        if st == "warn" else "No empty or repeated headings.",
        "Empty or duplicate headings dilute page structure.", "Remove empty headings and make repeated ones unique.")
    g = f["generic_links"]
    add("link_text", N, "Descriptive link text", "warn" if g else "pass", "low",
        f"{len(g)} link(s) use generic text such as \"{g[0]}\"." if g else "No generic link text found.",
        "Anchor text tells users and crawlers what the destination is about.",
        "Replace generic text with a description of the target.",
        '<a href="/pricing">View pricing plans</a>  <!-- instead of "click here" -->')
    gen = (not t) or t.lower() in GENERIC_TITLES or len(t.split()) < 2
    add("title_quality", N, "Descriptive title", "warn" if gen else "pass", "medium",
        f"Title \"{t}\" looks generic or very short." if gen else "Title has descriptive wording.",
        "A vague title gives searchers little reason to click.", "Include the page's main topic and brand.")
    weak = d is not None and d != "" and (d.strip().lower() == t.strip().lower() or len(d.split()) < 5)
    add("desc_quality", N, "Content description quality", "warn" if weak else ("pass" if d else "warn"), "low",
        "Description repeats the title or is very short." if weak else ("Description looks distinct." if d else "No description to evaluate."),
        "A distinct description adds information beyond the title.", "Write a unique summary of the page.")
    return C

def score(checks):
    def pct(cs):
        v = [c for c in cs if c["status"] in POINTS]
        tw = sum(c["weight"] for c in v)
        return round(100 * sum(c["weight"] * POINTS[c["status"]] for c in v) / tw) if tw else None
    by = lambda k: [c for c in checks if c["category"] == k]
    return {"overall": pct(checks), "technical": pct(by("technical")),
            "onpage": pct(by("onpage")), "content": pct(by("content"))}

# ---------------- API ----------------
hits = defaultdict(deque)
def rate_limit(ip):
    now, q = time.time(), hits[ip]
    while q and now - q[0] > RATE_WINDOW:
        q.popleft()
    if len(q) >= RATE_LIMIT:
        raise HTTPException(429, f"Too many requests. Try again in a minute (limit {RATE_LIMIT}/{RATE_WINDOW}s).")
    q.append(now)

app = FastAPI(title="SiteCheck AI")
app.add_middleware(CORSMiddleware, allow_origin_regex=r"https?://(localhost|127\.0\.0\.1)(:\d+)?",
                   allow_methods=["GET", "POST"], allow_headers=["Content-Type"])

class Req(BaseModel):
    url: str

@app.get("/api/health")
def health():
    return {"ok": True}

@app.post("/api/analyze")
def analyze(req: Req, request: Request):
    rate_limit(request.client.host if request.client else "?")
    url = req.url.strip()
    if "://" not in url:
        url = "https://" + url
    try:
        validate_url(url)
        page = fetch(url)
    except Blocked as e:
        raise HTTPException(400, str(e))
    except requests.exceptions.SSLError:
        raise HTTPException(502, "The site's SSL certificate could not be verified.")
    except requests.exceptions.Timeout:
        raise HTTPException(504, "The website took too long to respond.")
    except requests.exceptions.RequestException:
        raise HTTPException(502, "The website could not be reached.")
    ctype = page["headers"].get("content-type", "").lower()
    if ctype and "html" not in ctype and "xml" not in ctype:
        raise HTTPException(422, f"That URL returned {ctype.split(';')[0]}, not an HTML page.")
    f = parse_page(page)
    u = urlparse(page["url"]); origin = f"{u.scheme}://{u.netloc}"
    r = probe(origin + "/robots.txt")
    robots = {"state": "error", "text": ""}
    if r and r["status"] == 200:
        robots = {"state": "found", "text": r["body"].decode("utf-8", "replace")}
    elif r and r["status"] in (404, 410):
        robots["state"] = "missing"
    declared = re.findall(r"(?im)^\s*sitemap:\s*(\S+)", robots["text"])[:3]
    sitemap = {"state": "unknown", "url": ""}
    for cand in declared + [origin + "/sitemap.xml"]:
        sr = probe(cand, 50_000)
        if sr and sr["status"] == 200:
            sitemap = {"state": "found", "url": cand}
            break
    if sitemap["state"] == "unknown" and declared:
        sitemap["state"] = "declared_unreachable"
    checks = run_checks(f, page, robots, sitemap)
    order = {"high": 0, "medium": 1, "low": 2}
    counts = {k: sum(c["status"] == k for c in checks) for k in ("pass", "warn", "fail", "unverified")}
    return {
        "url": page["url"], "requested_url": url, "title": f["title"] or page["url"],
        "timestamp": datetime.now(timezone.utc).isoformat(), "status": page["status"],
        "redirects": page["redirects"], "truncated": page["truncated"],
        "scores": score(checks), "counts": counts,
        "checks": sorted(checks, key=lambda c: (c["status"] == "pass", order[c["severity"]])),
        "facts": {"internal_links": f["internal"], "external_links": f["external"], "images": f["images"],
                  "images_missing_alt": len(f["no_alt"]), "missing_alt_examples": f["no_alt"][:5],
                  "structured_types": f["ld_types"], "word_count": f["words"],
                  "headings": [{"level": l, "text": t} for l, t in f["headings"][:40]]},
        "method": {"weights": WEIGHTS, "points": POINTS,
                   "note": "Weighted share of points earned. Unverified checks are excluded. "
                           "This is an independent on-page estimate, not a Google metric; it does not measure "
                           "rankings, traffic, Core Web Vitals, backlinks or indexing."},
    }

# ---------------- serve the frontend from the same server ----------------
ROOT = Path(__file__).resolve().parent.parent
for name in ("index.html", "results.html"):
    app.add_api_route("/" + name, (lambda n=name: FileResponse(ROOT / n)), methods=["GET"], include_in_schema=False)
app.add_api_route("/", lambda: FileResponse(ROOT / "index.html"), methods=["GET"], include_in_schema=False)
app.mount("/css", StaticFiles(directory=ROOT / "css"), name="css")
app.mount("/js", StaticFiles(directory=ROOT / "js"), name="js")
