# ip-lookup

IP 查询服务。网页集中显示 IP 地址和纯净度；API 与 curl 纯文本还提供类型（家宽 / 移动 / 机房 / CDN / 教育 / 企业 / 政府）、用途标记（Tor、VPN、代理、iCloud 专用代理、爬虫、公共服务、任播）、原生或广播，以及地理位置、ASN、路由、注册信息等基础资料。

部署后通过自己的域名访问；以下命令以 `ip.example.com` 为例。

```
curl ip.example.com              # 查询自己的出口 IP，纯文本
curl ip.example.com/8.8.8.8      # 查询指定 IP
curl ip.example.com/json/8.8.8.8 # 完整 JSON
```

## 工作方式

首页只展示 IP 地址和纯净度，支持输入其他 IP、查我的 IP、复制地址。Go 在首屏直接输出 IP，不等待在线评分；随后发起 `full` 查询取得纯净度。等待结果时不显示预设的 100 分，查询失败时保留 IP，并将纯净度显示为“未知”。来源与许可默认收在小型“数据说明”折叠入口。

地理、网络、地图、多源对照、判定依据、连接探测明细和扣分项不在首页展示。后端的类型判断、地理与网络资料、风险分析和评分规则保持完整，API 与 curl 纯文本继续提供详细结果；各数据源的响应状态和耗时在 API 结果的 `sources` 字段里。首页不加载连接检测脚本或地图，也不自动发起浏览器端的第三方请求与 STUN 探测。

服务端每次查询会汇总三类数据，再由打分规则得出结论：

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

## 连接检测研究

`web/static/connection.js` 与 `web/connection.test.cjs` 保留独立的连接检测逻辑和测试，涵盖多目标出口、随机 DNS / ECS、WebRTC / STUN、TCP 系统特征和浏览器环境。当前首页不加载或运行该模块，“查我的 IP”也不会触发这些探测；连接观测不参与 IP 纯净度评分。

模块的研究思路参考 [egress-observatory](https://github.com/BlackSlience-Reaper/egress-observatory) 的多目标观测与连接证据分离，以及 [whoprobe](https://github.com/zzusec/whoprobe) 的目标站点矩阵、随机 DNS 与 WebRTC 状态区分，代码在本项目独立实现。若单独运行，第三方会看到访客请求它们时的出口 IP；失败或未返回数据只能表示未知，不能证明没有泄露、网络安全或服务已解锁。第三方推断和系统差异只是线索，耗时也不是链路 ping 延迟。

## 判定规则

- **类型**：每个数据源给出带权重的证据，同一数据源对同一结论只计一次，按总分最高者定类型。
  - CDN 节点在多数数据源里被标成机房，所以 CDN 先和机房合并比较，胜出后再按 CDN 证据细分。
- **用途标记**：一个强证据（例如命中 Tor 官方出口列表），或两个互相印证的中等证据，就会打上标记。
- **原生 / 广播**：比较 RIR 登记国家和地理定位国家，两者一致为原生 IP，不一致为广播 IP。
- **纯净度**：从 100 分开始扣分，扣分项包括 Tor/代理/VPN、机房、滥用记录、DNSBL 命中和第三方风险分。
  - 分档：≥95 极度纯净，≥80 纯净，≥50 良好，≥25 中性，其余为可疑。

这些结论来自公开数据的统计推断，只能作为参考。各数据源本身也有误判，类型判定依据、扣分项及其余原始数据可从 API 与 curl 纯文本获取，便于自行核对。

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

## 验证

```sh
go test ./...
node --test web/connection.test.cjs
node --test web/app.ui.test.cjs
```

浏览器测试需要已安装的 Playwright 与 Chromium；支持通过 `CHROMIUM_PATH` 指定浏览器，不自动下载依赖。首页测试使用合成数据验证首屏 IP、纯净度等待与失败状态、查询与复制操作、第三方探测不自动运行及 393px 手机布局。独立连接模块另用合成响应验证观测与判定逻辑；测试夹具不保证真实第三方接口可达。

## 数据来源与许可

本项目代码采用 MIT 许可。数据不随代码分发，由服务端从各来源下载，使用时请遵守原始许可：

- GeoLite2、IPinfo Lite（经 Merged-IP 合并）：CC BY-SA 4.0。DB-IP Lite：CC BY 4.0，页面已按要求署名。
- ip2region：Apache-2.0。lord-alfred/ipranges：CC0。axpwx/IP-Data、monosans/proxy-list：MIT。stamparm/ipsum：Unlicense。proxifly/free-proxy-list：GPL-3.0。
- X4BNet/lists_vpn、FireHOL、bgp.tools、Spamhaus DROP、各云厂商网段：按各自网站的使用条款。
- 保留的地图依赖：Leaflet 1.9.4（BSD-2-Clause，随代码放在 `web/static/vendor/leaflet/`）；OpenStreetMap 数据采用 ODbL。当前首页不加载地图或请求底图，后续若启用 OpenStreetMap 底图，须保留贡献者署名。
- ip-api.com 的免费接口仅限非商业用途，商业部署需要购买它的 Pro 版，或者从 `internal/sources/all.go` 中移除这个数据源。
