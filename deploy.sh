#!/usr/bin/env bash
set -euo pipefail

APP_NAME="lulucybtc-service-hub"
WEB_ROOT="/var/www/lulucybtc"
NGINX_CONF="/etc/nginx/conf.d/lulucybtc.conf"
ADMIN_SERVICE="/etc/systemd/system/lulucybtc-admin.service"
ADMIN_ENV="/etc/lulucybtc-admin.env"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Please run as root: sudo ./deploy.sh"
  exit 1
fi

echo "====== ${APP_NAME} deploy ======"

install_nginx() {
  if command -v nginx >/dev/null 2>&1; then
    return
  fi

  if command -v apt-get >/dev/null 2>&1; then
    apt-get update
    apt-get install -y nginx
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y nginx
  elif command -v yum >/dev/null 2>&1; then
    yum install -y epel-release || true
    yum install -y nginx
  else
    echo "Unsupported system: please install nginx first."
    exit 1
  fi
}

enable_nginx() {
  systemctl enable nginx >/dev/null 2>&1 || true
  systemctl restart nginx
}

install_nginx

mkdir -p "${WEB_ROOT}"
cp "${PROJECT_DIR}/index.html" "${WEB_ROOT}/index.html"
cp "${PROJECT_DIR}/monitor-unavailable.html" "${WEB_ROOT}/monitor-unavailable.html"
mkdir -p "${WEB_ROOT}/assets"
cp -R "${PROJECT_DIR}/assets/." "${WEB_ROOT}/assets/"

cp "${PROJECT_DIR}/nginx/lulucybtc.conf" "${NGINX_CONF}"
cp "${PROJECT_DIR}/scripts/traffic-summary.py" "/usr/local/bin/lulucybtc-traffic-summary"
chmod +x "/usr/local/bin/lulucybtc-traffic-summary"
cp "${PROJECT_DIR}/scripts/admin-server.py" "/usr/local/bin/lulucybtc-admin-server"
chmod +x "/usr/local/bin/lulucybtc-admin-server"

if [[ ! -f "${ADMIN_ENV}" ]]; then
  ADMIN_PASSWORD="$(python3 - <<'PY'
import secrets
print(secrets.token_urlsafe(18))
PY
)"
  cat > "${ADMIN_ENV}" <<ENV
ADMIN_USER=admin
ADMIN_PASSWORD=${ADMIN_PASSWORD}
ADMIN_PORT=18082
TRAFFIC_LOG=/var/log/nginx/lulucybtc_access.json
ENV
  chmod 600 "${ADMIN_ENV}"
fi

cat > "${ADMIN_SERVICE}" <<SERVICE
[Unit]
Description=LULUCYBTC admin traffic dashboard
After=network.target nginx.service

[Service]
Type=simple
EnvironmentFile=${ADMIN_ENV}
ExecStart=/usr/local/bin/lulucybtc-admin-server
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
SERVICE

systemctl daemon-reload
systemctl enable lulucybtc-admin >/dev/null 2>&1 || true
systemctl restart lulucybtc-admin

cat > /etc/logrotate.d/lulucybtc <<'LOGROTATE'
/var/log/nginx/lulucybtc_access.json {
    daily
    rotate 30
    missingok
    notifempty
    compress
    sharedscripts
    postrotate
        /bin/systemctl reload nginx >/dev/null 2>&1 || true
    endscript
}
LOGROTATE

nginx -t
enable_nginx

echo "Done."
echo "Open: http://lulucybtc.com"
echo "Main: http://main.lulucybtc.com -> 127.0.0.1:4173"
echo "Trade: http://trade.lulucybtc.com -> original 43.167.14.143 default port 80 page"
echo "AltTrend: http://alttrend.lulucybtc.com -> 127.0.0.1:38621"
echo "Traffic log: /var/log/nginx/lulucybtc_access.json"
echo "Traffic summary: lulucybtc-traffic-summary"
echo "Admin: http://admin.lulucybtc.com -> 127.0.0.1:18082"
echo "Admin credentials file: /etc/lulucybtc-admin.env"
echo
echo "HTTPS next step after DNS points to this server:"
echo "  certbot --nginx -d lulucybtc.com -d www.lulucybtc.com -d main.lulucybtc.com -d bscchain.lulucybtc.com -d solchain.lulucybtc.com -d trade.lulucybtc.com -d live.lulucybtc.com -d admin.lulucybtc.com -d alttrend.lulucybtc.com"
