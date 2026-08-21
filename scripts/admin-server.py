#!/usr/bin/env python3
import base64
import json
import os
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse


LOG_PATH = Path(os.getenv("TRAFFIC_LOG", "/var/log/nginx/lulucybtc_access.json"))
ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
PORT = int(os.getenv("ADMIN_PORT", "18082"))

STATIC_SUFFIXES = (
    ".css",
    ".js",
    ".map",
    ".png",
    ".jpg",
    ".jpeg",
    ".gif",
    ".svg",
    ".ico",
    ".webp",
    ".woff",
    ".woff2",
)

COUNTRY_POINTS = {
    "US": ("United States", 38, -97),
    "CA": ("Canada", 56, -106),
    "MX": ("Mexico", 23, -102),
    "BR": ("Brazil", -10, -55),
    "AR": ("Argentina", -34, -64),
    "CL": ("Chile", -30, -71),
    "CO": ("Colombia", 4, -74),
    "PE": ("Peru", -10, -76),
    "GB": ("United Kingdom", 54, -2),
    "IE": ("Ireland", 53, -8),
    "FR": ("France", 46, 2),
    "DE": ("Germany", 51, 10),
    "NL": ("Netherlands", 52, 5),
    "BE": ("Belgium", 51, 4),
    "ES": ("Spain", 40, -4),
    "PT": ("Portugal", 39, -8),
    "IT": ("Italy", 42, 12),
    "CH": ("Switzerland", 47, 8),
    "AT": ("Austria", 47, 14),
    "SE": ("Sweden", 62, 15),
    "NO": ("Norway", 61, 8),
    "FI": ("Finland", 64, 26),
    "DK": ("Denmark", 56, 10),
    "PL": ("Poland", 52, 19),
    "CZ": ("Czechia", 50, 15),
    "TR": ("Turkey", 39, 35),
    "RU": ("Russia", 61, 105),
    "UA": ("Ukraine", 49, 32),
    "AE": ("United Arab Emirates", 24, 54),
    "SA": ("Saudi Arabia", 24, 45),
    "IL": ("Israel", 31, 35),
    "IN": ("India", 22, 79),
    "PK": ("Pakistan", 30, 70),
    "BD": ("Bangladesh", 24, 90),
    "CN": ("China", 35, 103),
    "HK": ("Hong Kong", 22, 114),
    "TW": ("Taiwan", 24, 121),
    "JP": ("Japan", 37, 138),
    "KR": ("South Korea", 36, 128),
    "SG": ("Singapore", 1, 104),
    "MY": ("Malaysia", 4, 102),
    "TH": ("Thailand", 15, 101),
    "VN": ("Vietnam", 16, 108),
    "PH": ("Philippines", 13, 122),
    "ID": ("Indonesia", -2, 118),
    "AU": ("Australia", -25, 133),
    "NZ": ("New Zealand", -41, 174),
    "ZA": ("South Africa", -29, 24),
    "EG": ("Egypt", 27, 30),
    "NG": ("Nigeria", 9, 8),
    "KE": ("Kenya", 0, 38),
}


def parse_time(value):
    if not value:
        return None
    try:
        clean = value.replace("Z", "+0000")
        if clean[-3] == ":" and clean[-6] in ("+", "-"):
            clean = clean[:-3] + clean[-2:]
        for fmt in ("%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%dT%H:%M:%S.%f%z"):
            try:
                return datetime.strptime(clean, fmt)
            except ValueError:
                pass
        return None
    except ValueError:
        return None


def visitor_ip(row):
    return row.get("cf_connecting_ip") or row.get("remote_addr") or "-"


def row_time(row):
    return parse_time(row.get("time"))


def country_label(code):
    code = (code or "-").upper()
    if code in ("-", "XX", "T1"):
        return "Unknown"
    return COUNTRY_POINTS.get(code, (code, 0, 0))[0]


def map_point(code):
    code = (code or "-").upper()
    item = COUNTRY_POINTS.get(code)
    if not item:
        return None
    _, lat, lon = item
    return {
        "x": (lon + 180) / 360 * 100,
        "y": (90 - lat) / 180 * 100,
    }


def safe_float(value):
    try:
        return float(value or 0)
    except (TypeError, ValueError):
        return 0.0


def load_rows(hours=24, include_assets=False):
    cutoff = datetime.now(timezone.utc) - timedelta(hours=hours)
    rows = []
    if not LOG_PATH.exists():
        return rows
    with LOG_PATH.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            ts = parse_time(row.get("time"))
            if ts and ts < cutoff:
                continue
            uri = row.get("uri") or "/"
            if not include_assets and (uri.startswith("/api/") or uri == "/ws" or uri.endswith(STATIC_SUFFIXES)):
                continue
            rows.append(row)
    return rows


def summarize(rows):
    host_counts = Counter()
    path_counts = Counter()
    country_counts = Counter()
    ua_counts = Counter()
    status_counts = Counter()
    unique_ips = set()
    host_unique = defaultdict(set)
    total_time = 0.0
    slow = []
    ip_seen = {}

    for row in rows:
        host = row.get("host") or "-"
        uri = row.get("uri") or "/"
        ip = visitor_ip(row)
        status = str(row.get("status") or "-")
        country = row.get("cf_country") or "-"
        ua = row.get("user_agent") or "-"
        request_time = safe_float(row.get("request_time"))
        key = f"{host}{uri}"

        host_counts[host] += 1
        path_counts[key] += 1
        country_counts[country] += 1
        ua_counts[ua[:120]] += 1
        status_counts[status] += 1
        unique_ips.add(ip)
        host_unique[host].add(ip)
        total_time += request_time
        slow.append((request_time, host, uri, status))
        seen = ip_seen.setdefault(
            ip,
            {
                "ip": ip,
                "views": 0,
                "country": country,
                "countryLabel": country_label(country),
                "lastSeen": "",
                "hosts": Counter(),
            },
        )
        seen["views"] += 1
        seen["hosts"][host] += 1
        ts = row.get("time") or ""
        if ts > seen["lastSeen"]:
            seen["lastSeen"] = ts

    slow.sort(reverse=True)
    countries = []
    total_views = len(rows)
    for code, views in country_counts.most_common(30):
        point = map_point(code)
        countries.append(
            {
                "country": code,
                "label": country_label(code),
                "views": views,
                "share": views / total_views if total_views else 0,
                "x": point["x"] if point else None,
                "y": point["y"] if point else None,
            }
        )

    ips = sorted(ip_seen.values(), key=lambda item: (item["views"], item["lastSeen"]), reverse=True)
    return {
        "totalViews": len(rows),
        "uniqueVisitors": len(unique_ips),
        "avgRequestTime": total_time / len(rows) if rows else 0,
        "hosts": [
            {"host": host, "views": views, "uniqueVisitors": len(host_unique[host])}
            for host, views in host_counts.most_common()
        ],
        "paths": [{"path": path, "views": views} for path, views in path_counts.most_common(30)],
        "countries": countries,
        "ips": [
            {
                "ip": item["ip"],
                "views": item["views"],
                "country": item["country"],
                "countryLabel": item["countryLabel"],
                "lastSeen": item["lastSeen"],
                "topHost": item["hosts"].most_common(1)[0][0] if item["hosts"] else "-",
            }
            for item in ips[:50]
        ],
        "statuses": [{"status": k, "views": v} for k, v in status_counts.most_common()],
        "userAgents": [{"userAgent": k, "views": v} for k, v in ua_counts.most_common(15)],
        "slowRequests": [
            {"time": t, "host": host, "path": uri, "status": status} for t, host, uri, status in slow[:15]
        ],
    }


def rows_since(rows, now, hours):
    cutoff = now - timedelta(hours=hours)
    filtered = []
    for row in rows:
        ts = row_time(row)
        if ts and ts >= cutoff:
            filtered.append(row)
    return filtered


def window_summary(rows):
    now = datetime.now().astimezone()
    today = []
    for row in rows:
        ts = row_time(row)
        if ts and ts.astimezone(now.tzinfo).date() == now.date():
            today.append(row)
    windows = [
        ("today", "今日", today),
        ("days7", "7 天", rows_since(rows, now, 168)),
        ("days30", "30 天", rows_since(rows, now, 720)),
    ]
    payload = {}
    for key, label, scoped in windows:
        payload[key] = {
            "label": label,
            "views": len(scoped),
            "uniqueVisitors": len({visitor_ip(row) for row in scoped}),
        }

    daily = []
    for offset in range(29, -1, -1):
        day = (now - timedelta(days=offset)).date()
        day_rows = []
        for row in rows:
            ts = row_time(row)
            if ts and ts.astimezone(now.tzinfo).date() == day:
                day_rows.append(row)
        daily.append(
            {
                "date": day.isoformat(),
                "views": len(day_rows),
                "uniqueVisitors": len({visitor_ip(row) for row in day_rows}),
            }
        )
    payload["daily"] = daily
    return payload


def page():
    return """<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LULUCYBTC Admin</title>
  <style>
    :root{color-scheme:dark;--bg:#081016;--panel:#101b23;--line:rgba(255,255,255,.12);--text:#eef7f4;--muted:#9eb5b1;--green:#43d389;--cyan:#3fc7e8;--warn:#f4bf4f}
    *{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
    main{width:min(1280px,calc(100% - 28px));margin:0 auto;padding:28px 0 46px}.top{display:flex;align-items:end;justify-content:space-between;gap:16px;margin-bottom:18px}
    h1{margin:0;font-size:2rem}p{margin:6px 0 0;color:var(--muted)}select,label{color:var(--muted)}select{height:38px;border:1px solid var(--line);border-radius:8px;background:#0c151d;color:var(--text);padding:0 10px}
    .grid{display:grid;grid-template-columns:repeat(6,minmax(0,1fr));gap:12px}.card,.panel{border:1px solid var(--line);border-radius:8px;background:var(--panel)}.card{padding:16px}.card span{color:var(--muted);font-size:.86rem}.card strong{display:block;margin-top:8px;font-size:1.55rem}
    .panels{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}.panel{overflow:hidden}.panel.wide{grid-column:1/-1}.panel h2{margin:0;padding:13px 15px;border-bottom:1px solid var(--line);font-size:1rem}.rows{display:grid}.row{display:grid;grid-template-columns:1fr auto auto;gap:12px;padding:11px 15px;border-bottom:1px solid rgba(255,255,255,.07);align-items:center}.row:last-child{border-bottom:0}.row small{color:var(--muted);overflow-wrap:anywhere}.pill{color:var(--cyan);font-weight:800}.warn{color:var(--warn)}
    .map-wrap{position:relative;min-height:340px;padding:18px;background:linear-gradient(180deg,rgba(20,37,48,.62),rgba(8,16,22,.3))}.world{width:100%;height:320px;border:1px solid rgba(255,255,255,.08);border-radius:8px;background:radial-gradient(circle at 50% 50%,rgba(63,199,232,.1),transparent 30rem)}.map-dot{position:absolute;border-radius:999px;background:var(--green);box-shadow:0 0 0 6px rgba(67,211,137,.16);transform:translate(-50%,-50%)}.map-empty{position:absolute;inset:0;display:grid;place-items:center;color:var(--muted);pointer-events:none}.bars{display:grid;gap:8px;padding:14px 15px}.bar{display:grid;grid-template-columns:140px 1fr 70px;gap:12px;align-items:center}.bar-track{height:9px;border-radius:999px;background:rgba(255,255,255,.08);overflow:hidden}.bar-fill{height:100%;border-radius:999px;background:linear-gradient(90deg,var(--green),var(--cyan))}
    .daily{display:grid;grid-template-columns:repeat(30,1fr);gap:4px;align-items:end;min-height:160px;padding:16px}.day{min-height:6px;border-radius:4px 4px 0 0;background:linear-gradient(180deg,var(--cyan),rgba(63,199,232,.35))}
    @media(max-width:1100px){.grid{grid-template-columns:repeat(3,minmax(0,1fr))}}@media(max-width:900px){.grid,.panels{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}.bar{grid-template-columns:1fr}.daily{grid-template-columns:repeat(15,1fr)}}
  </style>
</head>
<body>
  <main>
    <section class="top">
      <div><h1>LULUCYBTC Admin</h1><p>访问量、来源和响应速度统计</p></div>
      <label>时间范围 <select id="hours"><option value="24">24 小时</option><option value="72">3 天</option><option value="168">7 天</option><option value="720">30 天</option></select></label>
    </section>
    <section class="grid">
      <div class="card"><span>今日访问</span><strong id="todayViews">-</strong></div>
      <div class="card"><span>7 天访问</span><strong id="days7Views">-</strong></div>
      <div class="card"><span>30 天访问</span><strong id="days30Views">-</strong></div>
      <div class="card"><span>当前范围访问</span><strong id="views">-</strong></div>
      <div class="card"><span>独立访客 IP</span><strong id="unique">-</strong></div>
      <div class="card"><span>平均响应</span><strong id="avg">-</strong></div>
    </section>
    <section class="panels">
      <div class="panel wide"><h2>全球 IP 分布图</h2><div class="map-wrap"><svg class="world" viewBox="0 0 100 50" preserveAspectRatio="none" aria-hidden="true"><path d="M8 15h84M8 25h84M8 35h84M20 6v38M40 6v38M60 6v38M80 6v38" stroke="rgba(255,255,255,.08)" stroke-width=".35"/><path d="M14 14c8-6 20-7 30-3 8 3 15 2 25-1 8-2 15 1 20 6-5 4-13 5-24 4-8-1-17 1-27 4-9 3-18 2-24-1zM18 30c9-4 18-3 29-1 12 3 22 2 35-3 3 8-5 14-20 15-12 1-20-4-31-2-7 1-12-2-13-9z" fill="rgba(255,255,255,.055)"/></svg><div id="mapDots"></div><div class="map-empty" id="mapEmpty">暂无国家分布数据</div></div><div class="bars" id="countryBars"></div></div>
      <div class="panel wide"><h2>近 30 天每日访问量</h2><div class="daily" id="daily"></div></div>
      <div class="panel"><h2>域名访问</h2><div class="rows" id="hosts"></div></div>
      <div class="panel"><h2>热门页面</h2><div class="rows" id="paths"></div></div>
      <div class="panel"><h2>国家/地区</h2><div class="rows" id="countries"></div></div>
      <div class="panel"><h2>访客 IP</h2><div class="rows" id="ips"></div></div>
      <div class="panel"><h2>状态码</h2><div class="rows" id="statuses"></div></div>
      <div class="panel"><h2>慢请求</h2><div class="rows" id="slow"></div></div>
      <div class="panel"><h2>浏览器 / 系统</h2><div class="rows" id="ua"></div></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const esc = (value) => String(value ?? "").replace(/[&<>"']/g, (char) => ({"&":"&amp;","<":"&lt;",">":"&gt;","\"":"&quot;","'":"&#39;"}[char]));
    const row = (a,b,c="") => `<div class="row"><small>${esc(a)}</small><b class="pill">${esc(b)}</b><small>${esc(c)}</small></div>`;
    function renderMap(countries){
      const points = countries.filter((x) => Number.isFinite(x.x) && Number.isFinite(x.y));
      $("mapEmpty").style.display = points.length ? "none" : "grid";
      $("mapDots").innerHTML = points.map((x) => {
        const size = Math.max(10, Math.min(30, 10 + x.share * 90));
        return `<span class="map-dot" title="${esc(x.label)} ${x.views}" style="left:${x.x}%;top:${x.y}%;width:${size}px;height:${size}px"></span>`;
      }).join("");
      const max = Math.max(1, ...countries.map((x) => x.views));
      $("countryBars").innerHTML = countries.slice(0, 10).map((x) => `
        <div class="bar"><small>${esc(x.label)} (${esc(x.country)})</small><div class="bar-track"><div class="bar-fill" style="width:${Math.max(4, x.views / max * 100)}%"></div></div><b class="pill">${esc(x.views)}</b></div>
      `).join("") || row("暂无数据","-");
    }
    function renderDaily(items){
      const max = Math.max(1, ...items.map((x) => x.views));
      $("daily").innerHTML = items.map((x) => {
        const height = Math.max(6, Math.round(x.views / max * 145));
        return `<span class="day" title="${esc(x.date)}: ${esc(x.views)}" style="height:${height}px"></span>`;
      }).join("");
    }
    async function load(){
      const hours = $("hours").value;
      const res = await fetch(`/api/summary?hours=${hours}`);
      const data = await res.json();
      $("todayViews").textContent = data.windows.today.views;
      $("days7Views").textContent = data.windows.days7.views;
      $("days30Views").textContent = data.windows.days30.views;
      $("views").textContent = data.totalViews;
      $("unique").textContent = data.uniqueVisitors;
      $("avg").textContent = `${data.avgRequestTime.toFixed(3)}s`;
      $("hosts").innerHTML = data.hosts.map(x => row(x.host, x.views, `${x.uniqueVisitors} IP`)).join("") || row("暂无数据","-");
      $("paths").innerHTML = data.paths.map(x => row(x.path, x.views)).join("") || row("暂无数据","-");
      $("countries").innerHTML = data.countries.map(x => row(`${x.label} (${x.country})`, x.views, `${(x.share * 100).toFixed(1)}%`)).join("") || row("暂无数据","-");
      $("ips").innerHTML = data.ips.map(x => row(x.ip, x.views, `${x.countryLabel} · ${x.topHost}`)).join("") || row("暂无数据","-");
      $("statuses").innerHTML = data.statuses.map(x => row(x.status, x.views)).join("") || row("暂无数据","-");
      $("slow").innerHTML = data.slowRequests.map(x => row(`${x.host}${x.path}`, `${x.time.toFixed(3)}s`, x.status)).join("") || row("暂无数据","-");
      $("ua").innerHTML = data.userAgents.map(x => row(x.userAgent, x.views)).join("") || row("暂无数据","-");
      renderMap(data.countries);
      renderDaily(data.windows.daily);
    }
    $("hours").addEventListener("change", load);
    load();
    setInterval(load, 30000);
  </script>
</body>
</html>"""


class Handler(BaseHTTPRequestHandler):
    def check_auth(self):
        if not ADMIN_PASSWORD:
            return False
        header = self.headers.get("Authorization", "")
        if not header.startswith("Basic "):
            return False
        try:
            decoded = base64.b64decode(header.split(" ", 1)[1]).decode("utf-8")
        except Exception:
            return False
        user, _, password = decoded.partition(":")
        return user == ADMIN_USER and password == ADMIN_PASSWORD

    def require_auth(self):
        self.send_response(401)
        self.send_header("WWW-Authenticate", 'Basic realm="LULUCYBTC Admin"')
        self.end_headers()

    def do_GET(self):
        if not self.check_auth():
            self.require_auth()
            return
        parsed = urlparse(self.path)
        if parsed.path == "/api/summary":
            qs = parse_qs(parsed.query)
            hours = int(qs.get("hours", ["24"])[0])
            include_assets = qs.get("all", ["0"])[0] == "1"
            rows = load_rows(hours=max(hours, 720), include_assets=include_assets)
            payload = summarize(rows_since(rows, datetime.now(timezone.utc), hours))
            payload["windows"] = window_summary(rows)
            body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = page().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format, *args):
        return


class ThreadingHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    server = ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    print(f"LULUCYBTC Admin listening on http://127.0.0.1:{PORT}")
    server.serve_forever()
