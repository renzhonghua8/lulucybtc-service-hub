# LULUCYBTC Service Hub

LULUCYBTC 根域名中转页和 Nginx 反向代理配置。

## 服务映射

| 域名 | 目标服务 |
| --- | --- |
| `lulucybtc.com` / `www.lulucybtc.com` | 静态中转页 |
| `main.lulucybtc.com` | 暂时复用 Service Hub 静态目录 `/var/www/lulucybtc` |
| `bscchain.lulucybtc.com` | `127.0.0.1:18080` |
| `solchain.lulucybtc.com` | 前端 `127.0.0.1:5174`，API `127.0.0.1:8787/api/` |
| `trade.lulucybtc.com` | `127.0.0.1:4173` |
| `monitor.lulucybtc.com` | `127.0.0.1:8000` |

## 服务器部署

```bash
cd /opt
git clone https://github.com/renzhonghua8/lulucybtc-service-hub.git
cd lulucybtc-service-hub
chmod +x deploy.sh
sudo ./deploy.sh
```

## Solchain API 请求

前端不要直接请求带端口的地址：

```text
http://solchain.lulucybtc.com:8787/api/snapshot
```

请改成同域名相对路径：

```text
/api/snapshot
```

Nginx 会自动把它转发到服务器本机：

```text
127.0.0.1:8787/api/snapshot
```

如果浏览器网络面板里还看到它请求：

```text
http://solchain.lulucybtc.com:8787/api/snapshot
```

说明 Solchain 前端包还没有改成相对 API 地址。需要在 Solchain 前端项目里把 API 基础地址改成 `/api`，重新构建并部署前端。

## 服务自检

Cloudflare 502 表示 DNS 已经到服务器了，但 Nginx 反代的本机端口没有正常响应。部署后在服务器上检查：

```bash
curl -I http://127.0.0.1:5174
curl -I http://127.0.0.1:8787/api/snapshot
curl -I http://127.0.0.1:8000
```

如果 `monitor.lulucybtc.com` 还是 502，重点检查 `8000` 端口服务是否正在运行，并确认它监听在 `127.0.0.1:8000` 或 `0.0.0.0:8000`。

## DNS 解析

把下面所有记录都解析到服务器公网 IP：

```text
lulucybtc.com
www.lulucybtc.com
main.lulucybtc.com
bscchain.lulucybtc.com
solchain.lulucybtc.com
trade.lulucybtc.com
monitor.lulucybtc.com
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
  -d monitor.lulucybtc.com
```

## 安全建议

`trade.lulucybtc.com` 和 `monitor.lulucybtc.com` 建议增加访问保护。优先考虑 Cloudflare Access；也可以用 Nginx Basic Auth。
