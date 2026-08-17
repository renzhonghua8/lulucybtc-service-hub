# LULUCYBTC Service Hub

LULUCYBTC 根域名中转页和 Nginx 反向代理配置。

## 服务映射

| 域名 | 目标服务 |
| --- | --- |
| `lulucybtc.com` / `www.lulucybtc.com` | 静态中转页 |
| `main.lulucybtc.com` | `127.0.0.1:8080` |
| `bscchain.lulucybtc.com` | `127.0.0.1:18080` |
| `solchain.lulucybtc.com` | `127.0.0.1:5174` |
| `trade.lulucybtc.com` | `127.0.0.1:4173` |
| `monitor2.lulucybtc.com` | `127.0.0.1:8000` |

## 服务器部署

```bash
cd /opt
git clone https://github.com/renzhonghua8/lulucybtc-service-hub.git
cd lulucybtc-service-hub
chmod +x deploy.sh
sudo ./deploy.sh
```

## DNS 解析

把下面所有记录都解析到服务器公网 IP：

```text
lulucybtc.com
www.lulucybtc.com
main.lulucybtc.com
bscchain.lulucybtc.com
solchain.lulucybtc.com
trade.lulucybtc.com
monitor2.lulucybtc.com
```

## HTTPS

DNS 生效后，在服务器安装 Certbot：

Ubuntu / Debian:

```bash
sudo apt-get update
sudo apt-get install -y certbot python3-certbot-nginx
```

CentOS / Rocky / AlmaLinux:

```bash
sudo yum install -y epel-release
sudo yum install -y certbot python3-certbot-nginx
```

申请证书：

```bash
sudo certbot --nginx \
  -d lulucybtc.com \
  -d www.lulucybtc.com \
  -d main.lulucybtc.com \
  -d bscchain.lulucybtc.com \
  -d solchain.lulucybtc.com \
  -d trade.lulucybtc.com \
  -d monitor2.lulucybtc.com
```

## 安全建议

`trade.lulucybtc.com` 和 `monitor2.lulucybtc.com` 建议增加访问保护。优先考虑 Cloudflare Access；也可以用 Nginx Basic Auth。
