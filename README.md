# CF-Workers-DoH

基于 Cloudflare Workers 的 DNS-over-HTTPS (DoH) 解析服务，支持智能 ECS (EDNS Client Subnet) 自适应、CNAME 递归追踪、IP 地理位置查询等功能。

## 功能特性

- **DoH 代理/服务器** — 兼容标准 DNS-over-HTTPS 协议 (RFC 8484)，支持 JSON 和 DNS message 格式
- **智能 ECS 自适应** — 根据客户端 IP 自动计算最优 EDNS Client Subnet 参数
  - IPv4: /24 掩码
  - IPv6: 默认 /64，针对中国电信 (`240e`) / 中国联通 (`2408`) 使用 /56 精细化
- **CNAME 递归追踪** — 自动递归解析 CNAME 目标，同时查询 A 和 AAAA 记录
- **NS 防污染** — NS 查询不携带 ECS 参数，返回最权威的结果
- **IP 地理位置查询** — 通过 `/ip-info` 接口查询 IP 归属地、AS 信息
- **Web 管理界面** — 内置可视化 DNS 查询页面，支持多 DoH 服务器切换
- **反向代理** — 可通过环境变量配置为 URL 反向代理

## 部署

### 1. Cloudflare Workers 部署

1. 登录 [Cloudflare Dashboard](https://dash.cloudflare.com/)
2. 进入 **Workers & Pages** → 创建 Worker
3. 将 `worker.js` 的内容粘贴到编辑器中
4. 保存并部署

### 2. Wrangler CLI 部署

```bash
# 安装 wrangler
npm install -g wrangler

# 登录
wrangler login

# 部署
wrangler deploy worker.js
```

## 环境变量

| 变量名 | 说明 | 示例 |
|--------|------|------|
| `DOH` | 上游 DoH 服务器地址 | `dns.alidns.com` 或 `https://dns.google/resolve` |
| `PATH` | DoH 服务路径 | `my-dns-query` |
| `TOKEN` | IP 查询接口的访问令牌（也可作为 PATH 回退值） | `my-secret-token` |
| `URL302` | 设置后请求将 302 重定向到该地址 | `https://example.com` |
| `URL` | 设置后作为反向代理目标；值为 `nginx` 时返回 nginx 欢迎页 | `https://example.com` |

### 配置示例

```
# 使用阿里 DoH 作为上游
DOH=dns.alidns.com

# 自定义 DoH 路径（访问 https://your-worker.dev/my-dns 触发 DoH 服务）
PATH=my-dns

# 保护 IP 查询接口（需携带 ?token=xxx 参数）
TOKEN=my-secret-key
```

## 使用方法

### DoH 查询（JSON 格式）

```bash
# 标准 DoH JSON 查询
curl "https://your-worker.dev/dns-query?name=example.com&type=A"

# 使用本服务的高级 ECS 查询
curl "https://your-worker.dev/?doh=https://dns.alidns.com/resolve&domain=example.com"
```

### DoH 查询（DNS message 格式）

```bash
curl -H "Accept: application/dns-message" \
  "https://your-worker.dev/dns-query?name=example.com&type=A"
```

### POST 方式查询

```bash
curl -X POST \
  -H "Content-Type: application/dns-message" \
  --data-binary @query.dns \
  "https://your-worker.dev/dns-query"
```

### IP 地理位置查询

```bash
# 查询指定 IP
curl "https://your-worker.dev/ip-info?ip=8.8.8.8&token=your-token"

# 查询客户端自身 IP
curl "https://your-worker.dev/ip-info?token=your-token"
```

### 高级 ECS 查询参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `doh` | 上游 DoH 服务器 URL | `https://dns.google/resolve` |
| `domain` 或 `name` | 待解析域名 | `www.google.com` |
| `ecs` | 自定义 ECS IP（可选，默认使用客户端 IP） | `1.2.3.4` |

## 上游 DoH 服务器推荐

| 服务商 | 地址 | 特点 |
|--------|------|------|
| Google | `dns.google` | 全球覆盖，支持完整 ECS |
| 阿里 DNS | `dns.alidns.com` | 国内优化，ECS 友好 |
| Cloudflare | `cloudflare-dns.com` | 速度快，隐私保护 |
| 腾讯 DNS | `sm2.doh.pub` | 国内优化 |
| AdGuard | `dns.adguard-dns.com` | 广告过滤 |

## 项目结构

```
├── worker.js      # Cloudflare Worker 主脚本
├── LICENSE         # Apache License 2.0
└── README.md       # 项目文档
```

## 许可证

[Apache License 2.0](LICENSE)
