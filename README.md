# ip-lookup

查询 IP 的类型（家宽 / 移动 / 机房 / CDN / 教育 / 企业 / 政府）、用途标记（Tor、VPN、代理、iCloud 专用代理、爬虫、公共服务、任播）、原生或广播、纯净度评分，以及地理位置、ASN、路由、注册信息等基础资料。

在线体验：<https://ip.llkan.com>

```
curl ip.llkan.com              # 查询自己的出口 IP，纯文本
curl ip.llkan.com/8.8.8.8      # 查询指定 IP
curl ip.llkan.com/json/8.8.8.8 # 完整 JSON
```

## 工作方式

每次查询会汇总三类数据，再由打分规则得出结论。网页上会列出每一条判断依据，并在地图上标出定位点和精度范围；各数据源的响应状态和耗时只在 API 结果的 `sources` 字段里提供。

- **离线数据**：服务端每天检查一次更新（带 ETag 的条件请求，没变就不重新下载），查询时直接读取本地文件，耗时在毫秒级。
  - 地理库：Merged-IP（合并了 GeoLite2、IPinfo Lite 和 DB-IP）、DB-IP Lite、ip2region。
  - AS 分类：bgp.tools 的 AS 分类和标签。
  - IP 名单：Tor 出口、iCloud 专用代理、VPN 与机房网段、公开代理、各云厂商官方网段、搜索引擎爬虫、Spamhaus DROP、FireHOL、IPsum 等，共 60 多份。
- **在线接口**：只使用免费额度，每个接口都设了配额、超时和缓存。
  - 地理与网络类型：ip-api、ipwho.is、ip.sb、ipapi.is、ipinfo、ipapi.co、IP2Location.io、纯真、百度。
  - 风险评估：proxycheck、ipyou、GreyNoise。
  - 开放端口：Shodan InternetDB。
  - 同 IP 域名：HackerTarget。
  - 注册与路由：RDAP、RIPEstat（路由可见度、RPKI、RIR 统计）、PeeringDB。
- **DNS 查询**：反向解析并做正反解校验（FCrDNS），通过 Team Cymru 查 ASN，另查 12 个 DNSBL 黑名单。

页面打开时，浏览器还会通过 ipify、Cloudflare trace、WebRTC 等方式探测访客的其他出口地址，并检测 DNS 出口。

## 判定规则

- **类型**：每个数据源给出带权重的证据，同一数据源对同一结论只计一次，按总分最高者定类型。
  - CDN 节点在多数数据源里被标成机房，所以 CDN 先和机房合并比较，胜出后再按 CDN 证据细分。
- **用途标记**：一个强证据（例如命中 Tor 官方出口列表），或两个互相印证的中等证据，就会打上标记。
- **原生 / 广播**：比较 RIR 登记国家和地理定位国家，两者一致为原生 IP，不一致为广播 IP。
- **纯净度**：从 100 分开始扣分，扣分项包括 Tor/代理/VPN、机房、滥用记录、DNSBL 命中和第三方风险分。
  - 分档：≥95 极度纯净，≥80 纯净，≥50 良好，≥25 中性，其余为可疑。

这些结论来自公开数据的统计推断，只能作为参考。各数据源本身也有误判，页面会把原始证据全部列出，便于自行核对。

## API

| 路径 | 说明 |
| --- | --- |
| `GET /api/lookup?ip=&mode=full\|fast` | 不传 `ip` 时查询访客自己。`fast` 只用离线数据（<50ms），`full` 会加上在线接口和 DNS（最长约 10 秒） |
| `GET /json`、`GET /json/{ip}` | 等同于 `mode=full` |
| `GET /api/ip` | 返回访客 IP |
| `GET /api/sources` | 返回各数据集的条目数、更新时间，以及在线接口的配额使用情况 |
| `GET /`、`GET /{ip}` | 浏览器访问返回网页，curl、wget、HTTPie 返回纯文本 |

查询别人的 IP 时，每个客户端（IPv6 按 /64 计）每分钟最多 20 次 full 查询。查询自己不受这个限制。

## 部署

需要 Go 1.27 以上。离线数据约 320MB，放在 `DATA_DIR` 里，运行时内存大约 50 到 150MB。

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ip-lookup ./cmd/ip-lookup
useradd --system --no-create-home --shell /usr/sbin/nologin iplookup
install -D -m 755 ip-lookup /opt/ip-lookup/ip-lookup
install -m 600 deploy/ip-lookup.env.example /etc/ip-lookup.env
install -m 644 deploy/ip-lookup.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now ip-lookup
```

服务首次启动时，会在后台用几分钟下载全部数据集。数据还没就绪时也能查询，只是缺少的数据会显示为空。nginx 配置可以参考 `deploy/nginx.conf.example`。环境变量的说明见 `deploy/ip-lookup.env.example`；可选的 API key 填进去后，对应的数据源会改用付费额度。

## 数据来源与许可

本项目代码采用 MIT 许可。数据不随代码分发，由服务端从各来源下载，使用时请遵守原始许可：

- GeoLite2、IPinfo Lite（经 Merged-IP 合并）：CC BY-SA 4.0。DB-IP Lite：CC BY 4.0，页面已按要求署名。
- ip2region：Apache-2.0。lord-alfred/ipranges：CC0。axpwx/IP-Data、monosans/proxy-list：MIT。stamparm/ipsum：Unlicense。proxifly/free-proxy-list：GPL-3.0。
- X4BNet/lists_vpn、FireHOL、bgp.tools、Spamhaus DROP、各云厂商网段：按各自网站的使用条款。
- 地图：Leaflet 1.9.4（BSD-2-Clause，随代码放在 `web/static/vendor/leaflet/`），底图来自 OpenStreetMap（ODbL），页面带有署名。
- ip-api.com 的免费接口仅限非商业用途，商业部署需要购买它的 Pro 版，或者从 `internal/sources/all.go` 中移除这个数据源。
