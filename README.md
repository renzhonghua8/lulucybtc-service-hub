# LULUCYBTC Service Hub

LULUCYBTC 根域名中转页和 Nginx 反向代理配置。

## 服务映射

| 域名 | 目标服务 |
| --- | --- |
| `lulucybtc.com` / `www.lulucybtc.com` | 静态中转页 |
| `main.lulucybtc.com` | `127.0.0.1:4173` |
| `bscchain.lulucybtc.com` | `127.0.0.1:18080` |
| `solchain.lulucybtc.com` | 前端 `127.0.0.1:5174`，API `127.0.0.1:8787/api/`，WebSocket `127.0.0.1:8787/ws` |
| `trade.lulucybtc.com` | 原 `43.167.14.143` 默认 80 页面 |
| `monitor.lulucybtc.com` | `127.0.0.1:8000`，异常时显示本地降级页 |
| `admin.lulucybtc.com` | 访问统计后台 `127.0.0.1:18082` |
| `alttrend.lulucybtc.com` | AltTrend 服务 `127.0.0.1:38621` |

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
curl -I http://127.0.0.1:4173
curl -I -H 'Host: 43.167.14.143' http://127.0.0.1
curl -I http://127.0.0.1:8000
```

如果 `monitor.lulucybtc.com` 还是 502，重点检查 `8000` 端口服务是否正在运行，并确认它监听在 `127.0.0.1:8000` 或 `0.0.0.0:8000`。

## 访问量统计

Nginx 会统一记录 JSON 访问日志：

```text
/var/log/nginx/lulucybtc_access.json
```

可以记录：

- 访问时间
- 访问域名和路径
- HTTP 方法、状态码、返回大小
- 请求耗时和上游服务耗时
- Cloudflare 传来的真实来访 IP、国家代码
- Referer 来源页面
- User-Agent 浏览器/系统信息

不会记录 Cookie、请求体、密码或表单内容。

查看最近 24 小时页面访问量：

```bash
sudo lulucybtc-traffic-summary
```

查看最近 7 天，并包含 API 和静态资源：

```bash
sudo lulucybtc-traffic-summary --hours 168 --all
```

## 访问统计后台

后台域名：

```text
admin.lulucybtc.com
```

内部端口：

```text
127.0.0.1:18082
```

首次部署会自动生成账号密码，保存在服务器：

```bash
sudo cat /etc/lulucybtc-admin.env
```

修改密码：

```bash
sudo vim /etc/lulucybtc-admin.env
sudo systemctl restart lulucybtc-admin
```

后台页面可以查看：

- 今日访问量
- 7 天访问量
- 30 天访问量
- 近 30 天每日访问趋势
- 独立访客 IP 和访问次数
- IP 国家/地区分布图
- 各域名访问量、热门路径、状态码、慢请求和浏览器信息

国家/地区统计优先使用 Cloudflare 请求头 `CF-IPCountry`。如果域名没有走 Cloudflare 代理，国家/地区可能显示为 `Unknown`，但 IP 和访问次数仍会记录。

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
admin.lulucybtc.com
alttrend.lulucybtc.com
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
  -d monitor.lulucybtc.com \
  -d admin.lulucybtc.com \
  -d alttrend.lulucybtc.com
```

## 安全建议

`trade.lulucybtc.com` 和 `monitor.lulucybtc.com` 建议增加访问保护。优先考虑 Cloudflare Access；也可以用 Nginx Basic Auth。
