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


def parse_time(value):
    if not value:
        return None
    try:
        clean = value.replace("Z", "+0000")
        if clean[-3] == ":" and clean[-6] in ("+", "-"):
            clean = clean[:-3] + clean[-2:]
        return datetime.strptime(clean, "%Y-%m-%dT%H:%M:%S%z")
    except ValueError:
        return None


def visitor_ip(row):
    return row.get("cf_connecting_ip") or row.get("remote_addr") or "-"


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

    for row in rows:
        host = row.get("host") or "-"
        uri = row.get("uri") or "/"
        ip = visitor_ip(row)
        status = str(row.get("status") or "-")
        country = row.get("cf_country") or "-"
        ua = row.get("user_agent") or "-"
        request_time = float(row.get("request_time") or 0)
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

    slow.sort(reverse=True)
    return {
        "totalViews": len(rows),
        "uniqueVisitors": len(unique_ips),
        "avgRequestTime": total_time / len(rows) if rows else 0,
        "hosts": [
            {"host": host, "views": views, "uniqueVisitors": len(host_unique[host])}
            for host, views in host_counts.most_common()
        ],
        "paths": [{"path": path, "views": views} for path, views in path_counts.most_common(30)],
        "countries": [{"country": k, "views": v} for k, v in country_counts.most_common(20)],
        "statuses": [{"status": k, "views": v} for k, v in status_counts.most_common()],
        "userAgents": [{"userAgent": k, "views": v} for k, v in ua_counts.most_common(15)],
        "slowRequests": [
            {"time": t, "host": host, "path": uri, "status": status} for t, host, uri, status in slow[:15]
        ],
    }


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
    .grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px}.card,.panel{border:1px solid var(--line);border-radius:8px;background:var(--panel)}.card{padding:16px}.card span{color:var(--muted);font-size:.86rem}.card strong{display:block;margin-top:8px;font-size:1.6rem}
    .panels{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-top:12px}.panel{overflow:hidden}.panel h2{margin:0;padding:13px 15px;border-bottom:1px solid var(--line);font-size:1rem}.rows{display:grid}.row{display:grid;grid-template-columns:1fr auto auto;gap:12px;padding:11px 15px;border-bottom:1px solid rgba(255,255,255,.07);align-items:center}.row:last-child{border-bottom:0}.row small{color:var(--muted);overflow-wrap:anywhere}.pill{color:var(--cyan);font-weight:800}.warn{color:var(--warn)}
    @media(max-width:900px){.grid,.panels{grid-template-columns:1fr}.top{align-items:flex-start;flex-direction:column}}
  </style>
</head>
<body>
  <main>
    <section class="top">
      <div><h1>LULUCYBTC Admin</h1><p>访问量、来源和响应速度统计</p></div>
      <label>时间范围 <select id="hours"><option value="24">24 小时</option><option value="72">3 天</option><option value="168">7 天</option><option value="720">30 天</option></select></label>
    </section>
    <section class="grid">
      <div class="card"><span>访问量</span><strong id="views">-</strong></div>
      <div class="card"><span>独立访客 IP</span><strong id="unique">-</strong></div>
      <div class="card"><span>平均响应</span><strong id="avg">-</strong></div>
      <div class="card"><span>日志文件</span><strong id="log">active</strong></div>
    </section>
    <section class="panels">
      <div class="panel"><h2>域名访问</h2><div class="rows" id="hosts"></div></div>
      <div class="panel"><h2>热门页面</h2><div class="rows" id="paths"></div></div>
      <div class="panel"><h2>国家/地区</h2><div class="rows" id="countries"></div></div>
      <div class="panel"><h2>状态码</h2><div class="rows" id="statuses"></div></div>
      <div class="panel"><h2>慢请求</h2><div class="rows" id="slow"></div></div>
      <div class="panel"><h2>浏览器 / 系统</h2><div class="rows" id="ua"></div></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const row = (a,b,c="") => `<div class="row"><small>${a}</small><b class="pill">${b}</b><small>${c}</small></div>`;
    async function load(){
      const hours = $("hours").value;
      const res = await fetch(`/api/summary?hours=${hours}`);
      const data = await res.json();
      $("views").textContent = data.totalViews;
      $("unique").textContent = data.uniqueVisitors;
      $("avg").textContent = `${data.avgRequestTime.toFixed(3)}s`;
      $("hosts").innerHTML = data.hosts.map(x => row(x.host, x.views, `${x.uniqueVisitors} IP`)).join("") || row("暂无数据","-");
      $("paths").innerHTML = data.paths.map(x => row(x.path, x.views)).join("") || row("暂无数据","-");
      $("countries").innerHTML = data.countries.map(x => row(x.country, x.views)).join("") || row("暂无数据","-");
      $("statuses").innerHTML = data.statuses.map(x => row(x.status, x.views)).join("") || row("暂无数据","-");
      $("slow").innerHTML = data.slowRequests.map(x => row(`${x.host}${x.path}`, `${x.time.toFixed(3)}s`, x.status)).join("") || row("暂无数据","-");
      $("ua").innerHTML = data.userAgents.map(x => row(x.userAgent, x.views)).join("") || row("暂无数据","-");
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
            payload = summarize(load_rows(hours=hours, include_assets=include_assets))
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
