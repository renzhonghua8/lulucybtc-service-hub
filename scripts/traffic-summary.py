#!/usr/bin/env python3
import argparse
import json
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path


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
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None


def visitor_ip(row):
    return row.get("cf_connecting_ip") or row.get("remote_addr") or "-"


def main():
    parser = argparse.ArgumentParser(description="Summarize LULUCYBTC Nginx JSON traffic logs.")
    parser.add_argument("--log", default="/var/log/nginx/lulucybtc_access.json")
    parser.add_argument("--hours", type=int, default=24)
    parser.add_argument("--all", action="store_true", help="Include static assets and API calls.")
    parser.add_argument("--limit", type=int, default=30)
    args = parser.parse_args()

    path = Path(args.log)
    if not path.exists():
        raise SystemExit(f"Log file not found: {path}")

    cutoff = datetime.now(timezone.utc) - timedelta(hours=args.hours)
    stats = defaultdict(lambda: {"views": 0, "ips": set(), "time": 0.0, "errors": 0})

    with path.open("r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            ts = parse_time(row.get("time"))
            if ts and ts < cutoff:
                continue

            uri = row.get("uri") or "/"
            if not args.all and (uri.startswith("/api/") or uri == "/ws" or uri.endswith(STATIC_SUFFIXES)):
                continue

            key = (row.get("host") or "-", uri)
            stats[key]["views"] += 1
            stats[key]["ips"].add(visitor_ip(row))
            stats[key]["time"] += float(row.get("request_time") or 0)
            if int(row.get("status") or 0) >= 400:
                stats[key]["errors"] += 1

    rows = []
    for (host, uri), item in stats.items():
        views = item["views"]
        rows.append(
            {
                "host": host,
                "uri": uri,
                "views": views,
                "unique_ips": len(item["ips"]),
                "avg_time": item["time"] / views if views else 0,
                "errors": item["errors"],
            }
        )

    rows.sort(key=lambda item: item["views"], reverse=True)
    print(f"Traffic summary: last {args.hours}h")
    print(f"{'views':>8} {'unique':>8} {'avg_s':>8} {'errors':>8}  host path")
    for row in rows[: args.limit]:
        print(
            f"{row['views']:>8} {row['unique_ips']:>8} {row['avg_time']:>8.3f} "
            f"{row['errors']:>8}  {row['host']} {row['uri']}"
        )


if __name__ == "__main__":
    main()
