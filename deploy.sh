#!/usr/bin/env bash
set -euo pipefail

APP_NAME="lulucybtc-service-hub"
WEB_ROOT="/var/www/lulucybtc"
NGINX_CONF="/etc/nginx/conf.d/lulucybtc.conf"
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

nginx -t
enable_nginx

echo "Done."
echo "Open: http://lulucybtc.com"
echo
echo "HTTPS next step after DNS points to this server:"
echo "  certbot --nginx -d lulucybtc.com -d www.lulucybtc.com -d main.lulucybtc.com -d bscchain.lulucybtc.com -d solchain.lulucybtc.com -d trade.lulucybtc.com -d monitor.lulucybtc.com"
