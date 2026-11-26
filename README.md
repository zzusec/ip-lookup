# ip-lookup

查询 IP 的类型（家宽 / 移动 / 机房 / CDN / 教育 / 企业 / 政府）、用途标记（Tor、VPN、代理、iCloud 专用代理、商业租赁网段、爬虫、公共服务、任播）、原生或广播、纯净度评分、**人机流量探测及比例分布**，以及同网段邻居信誉、伪家宽流量方向核验、地理位置、ASN、路由、注册信息等资料。

部署后通过自己的域名访问；以下命令以 `ip.example.com` 为例。

```
curl ip.example.com              # 查询自己的出口 IP（含人机流量与当前客户端探测），纯文本
curl ip.example.com/8.8.8.8      # 查询指定 IP
curl ip.example.com/json/8.8.8.8 # 完整 JSON
```

## 工作方式

页面上半部分保留 IP 类型摘要：IP 地址、ASN、AS 域名、IP 范围、位置、原生或广播、IP 属性及置信度、人机流量摘要与纯净度；中间展示**人机流量与多维检测**卡片；下方保留地理位置、位置地图和网络资料。手机上 IP 与评分圆环并排放在首屏，较长的网络资料排在下方。支持输入其他 IP、查我的 IP、复制地址。

Go 在首屏直接输出 IP，不等待在线评分，页面响应使用 `Cache-Control: private, no-store`。浏览器并发发起 `fast` 与 `full` 查询，先用快速查询呈现离线基础资料，再以完整结果更新。纯净度等待 `full` 结果，不先显示预设的 100 分；完整查询失败时保留 IP 和已经取得的基础资料，并将纯净度显示为未知（页面文案为“未能评估”）。

点击评分区的“评分详情”可查看本次 IP、扣分明细、原始风险读数和实际计分值、深度审计与流量信号、DNSBL 返回码与错误，以及来源状态和观察说明。详情按需打开，可关闭或按 Escape 返回；切换查询会关闭并清空旧详情。API 与 curl 纯文本继续提供详细结果；各数据源的响应状态和耗时在 API 结果的 `sources` 字段里。

首页默认不自动加载 `connection.js` 连接检测脚本，不自动执行 STUN 或向 ChatGPT、Claude 等目标发起连接探测。仅当用户主动点击「实测当前连接与 443 伪装」按钮时，才按需运行服务端 `:443` 证书回探与浏览器多目标出口/DNS/WebRTC 探针。有效经纬度可用时，地图按需加载本站提供的 Leaflet 组件，并请求 OpenStreetMap 图块；地图仍会产生浏览器端的第三方请求，署名保留在地图控件中。

服务端每次查询会汇总四类检测能力，再由打分与流量评估规则得出结论：

- **离线数据与网段连带审计**：服务端每天检查一次更新（带 ETag 的条件请求，没变就不重新下载），查询时直接读取本地文件，耗时在毫秒级。
  - 地理库：Merged-IP（合并了 GeoLite2、IPinfo Lite 和 DB-IP）、DB-IP Lite、ip2region。
  - AS 分类：bgp.tools 的 AS 分类和标签。
  - IP 名单：Tor 出口、iCloud 专用代理、VPN 与机房网段、公开代理、各云厂商官方网段、搜索引擎爬虫、Spamhaus DROP、FireHOL Level 1、IPsum、blocklist.de 爆破源、CINS Army 恶意扫描、GreenSnow、StopForumSpam 近 7 天垃圾源等，共 60 多份。
  - 同段邻居信誉密度：对所有已加载的滥用、公开代理、VPN 与 Tor 离线名单做区间并集去重，统计目标地址所在 `/24`（IPv4，共 256 地址）或 `/48`（IPv6）内的风险命中密度，识别“单 IP 未上榜但所在 C 段高度污染”的连坐风险。
- **在线接口**：使用匿名接口或已配置账户的额度，各接口设有超时和缓存，并按来源限制请求量。
  - 地理与网络类型：ip-api、ipwho.is、ip.sb、ipapi.is、ipinfo、IPinfo Blackbox v3、ipapi.co、IP2Location.io、纯真、百度。
  - 风险与威胁行为：proxycheck、ipyou、IPQuery、GreyNoise、StopForumSpam（垃圾注册/表单提交频次）、SANS DShield（蜜罐捕获扫描包与目标数）、AlienVault OTX（威胁脉冲，含基础设施白名单过滤）、Tor Onionoo（精确 Tor 出口/中继昵称及同网段节点）。
  - 可选 ipdata.co：直接查询目标 IP 的地理、ASN / Company 类型及 Tor、VPN、代理、中继、机房和滥用信号。只有显式安全相关布尔值或合法的 `trust_score` 才计入信誉覆盖。
  - 可选 Cloudflare Radar（`CF_RADAR_TOKEN`）：按自治系统（ASN）拉取近 7 天真实观测的 HTTP **真人 vs 自动化机器人流量占比**及**桌面端 vs 移动端流量分布**（按 ASN 缓存 12 小时）。未配置 Token 时，自动回退到基于多源行为与网络特征的信号推算模式，并在界面与 JSON `traffic.mode` 中明确区分。
  - 开放端口与同 IP 域名：Shodan InternetDB、HackerTarget。
  - 注册、路由、ASN 规模与租赁/伪家宽审计：RDAP（含 `autnum` 自治系统注册日期与企业注册主体）、RIPEstat（宣告前缀去重 IPv4 地址总量、路由可见度、RPKI、RIR 统计）、PeeringDB（预估带宽与互联规模）。自动识别 IPXO、InterLIR、Cloud Innovation、LARUS、Heficed 等商业地址租赁平台，并结合 PeeringDB 入出向流量比（`Heavy Outbound` / `Mostly Outbound`）核验“声称家庭宽带但呈现机房出向特征”的伪家宽网段。
- **DNS 查询**：反向解析并做正反解校验（FCrDNS），通过 Team Cymru 查 ASN，另查 14 个 DNSBL 黑名单（含 SpamCop、Barracuda、UCEPROTECT、DroneBL、blocklist.de、Mailspike、dan.me.uk Tor 等）。
- **实时人机特征与按需连接探测**：
  - 查询访客自身 IP 时，服务端实时核验本次 HTTP 握手的 `User-Agent`、`Sec-Fetch-*` 安全上下文、`Sec-CH-UA*` 客户端提示与系统一致性、语言压缩协商及正向代理透传头，结合浏览器端零外联环境检测（`navigator.webdriver`、自动化注入钩子、语言栈、无头视口特征）给出当前连接的真人 / 自动化特征比例。
  - 用户点击「实测当前连接与 443 伪装」后，服务端仅针对访客自身公网出口 IP 执行只读 `:443` TCP/TLS 握手，识别非大厂自治系统借用 Microsoft / Apple / Yahoo / Google / Cloudflare 等官网域名证书的 **VLESS-Reality / ShadowTLS 伪装节点**；同时浏览器按需加载 `web/static/connection.js` 并发检测双栈出口、Cloudflare / ChatGPT / Claude / 国内目标分流、DNS / EDNS 子网、WebRTC / STUN 候选与 TCP 系统指纹。

## 判定规则

- **类型**：每个数据源给出带权重的证据，同一数据源对同一结论只计一次，按总分最高者定类型。
  - CDN 节点在多数数据源里被标成机房，所以 CDN 先和机房合并比较，胜出后再按 CDN 证据细分。
- **用途标记**：一个强证据（例如命中 Tor 官方出口列表或商业地址租赁商），或两个互相印证的中等证据，就会打上标记。
- **原生 / 广播**：比较 RIR 登记国家和地理定位国家，两者一致为原生 IP，不一致为广播 IP。
- **人机流量分布（`traffic`）**：
  - `mode = "radar"`：来自 Cloudflare Radar 对该自治系统近 7 天 HTTP 请求的实测统计（`human_pct` / `bot_pct` 及可选 `desktop_pct` / `mobile_pct`）。
  - `mode = "estimated"`：未配置 `CF_RADAR_TOKEN` 或该 ASN 无采样记录时，综合网络类型基线、PeeringDB 入出向流量比、爬虫/Tor/代理标记、StopForumSpam 垃圾提交、DShield 扫描包、OTX 脉冲及同 `/24` 脏邻居密度推算机器流量倾向，并列出命中的 `bot_signals`。
- **纯净度与语义色严格对应**：从 100 分开始扣分，扣分项包括 Tor/代理/VPN、机房、滥用记录、商业租赁网段、伪家宽流量冲突、同 `/24` 高密度风险邻居、DNSBL 命中和第三方风险分。
  - 分档与颜色对应：90–100 极度纯净（深翠绿）、78–89 纯净（健康绿）、55–77 一般（琥珀橙黄，提示存在机房或共享风险特征）、30–54 风险偏高（深橙红）、0–29 可疑（警示红），首屏同时提供 0–100 连续光谱刻度尺。
  - 场景评估：结合网络类型、原生性、地区可用性、黑名单与人机流量占比，对 TikTok、社媒运营、AI 应用及免盾浏览提供 10 分制参考评级。
  - ipdata 的 `threat.scores.trust_score` 越高越可信，以 `100 - trust_score` 转为风险读数；IPQuery 低基线读数（`<15`）与 ipyou 极低风险区间（`<20`）保留 `risk[].value` 原始读数并以 `effective_value: 0` 避免正常宽带误扣分。

评分包含 `score.data_status`（`complete` / `limited` / `unavailable`）与 `score.coverage`（`received` 为有效信誉源数，`total` 为本轮请求涉及的相关信誉源数）。只有实际返回、类型正确的安全相关布尔值或 0–100 风险读数（含 0）才计为有效信誉数据；地理或 ASN 数据、HTTP 200、空事件记录、DNSBL 子查询错误均不当作安全证据。`unavailable` 下的数值基线并非实测结果，网页和 curl 在此时显示未知（页面使用“未能评估 / 数据不足”）。

风险计分保留原始读数，并区分来源语义：GreyNoise 的 `unknown` 只表示观察到扫描、尚未判定恶意或安全，不生成固定风险 50，也不算有效的干净信誉检查；`benign` 不因良性活动生成风险 10；`malicious` 仍保留风险 90 和滥用证据。参见 [GreyNoise 分类说明](https://docs.greynoise.io/docs/understanding-greynoise-classifications) 与 [ipyou 风控值说明](https://ipyou.net/zh/wiki/ip-risk-score)。

## API

| 路径 | 说明 |
| --- | --- |
| `GET /api/lookup?ip=&mode=full\|fast` | 不传 `ip` 时查询访客自己（自动附带 `traffic.request_probe`）。`fast` 只用离线数据（<50ms），`full` 会加上在线接口和 DNS（最长约 10 秒） |
| `GET /json`、`GET /json/{ip}` | 等同于 `mode=full` |
| `GET /api/probe` | 对访客自身连接执行实时 HTTP 人机特征核验与公网出口 `:443` TLS / Reality 借证伪装探查（每客户端限流并带缓存，不接受第三方目标 IP） |
| `GET /api/ip` | 返回访客 IP |
| `GET /api/sources` | 返回各数据集的条目数、更新时间，以及在线接口的配额使用情况 |
| `GET /`、`GET /{ip}` | 浏览器访问返回网页，curl、wget、HTTPie 返回纯文本 |

查询别人的 IP 时，每个客户端（IPv6 按 /64 计）每分钟最多 20 次 full 查询。查询自己不受这个限制。

## 部署

需要 Go 1.27 以上。离线数据约 330MB，放在 `DATA_DIR` 里，运行时内存大约 50 到 150MB。

```sh
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o ip-lookup ./cmd/ip-lookup
useradd --system --no-create-home --shell /usr/sbin/nologin iplookup
install -D -m 755 ip-lookup /opt/ip-lookup/ip-lookup
install -m 600 deploy/ip-lookup.env.example /etc/ip-lookup.env
install -m 644 deploy/ip-lookup.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now ip-lookup
```

服务首次启动时，会在后台用几分钟下载全部数据集。数据还没就绪时也能查询，只是缺少的数据会显示为空。nginx 配置可以参考 `deploy/nginx.conf.example`。环境变量说明见 `deploy/ip-lookup.env.example`：

- `CF_RADAR_TOKEN`（可选）：具有 `Account -> Cloudflare Radar -> Read` 只读权限的 Cloudflare API Token，配置后启用自治系统近 7 天实测人机流量与桌面/移动设备占比。
- `IPDATA_API_KEY`（可选）：保存在服务端私有环境文件中，按精确 IP 缓存 24 小时并自限每天 100 次请求。

## 验证

```sh
go test ./...
node --test web/connection.test.cjs
CHROMIUM_PATH="/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" node --test web/app.ui.test.cjs
```

浏览器测试需要已安装的 Playwright 与 Chromium / Chrome；支持通过 `CHROMIUM_PATH` 指定浏览器，不自动下载依赖。首页测试使用合成数据验证首屏 IP、摘要与人机流量及多维审计、地理及网络资料、纯净度等待、失败及数据可用性状态、查询与复制操作、按需主动探测与 `:443` Reality 伪装核验、地图按需加载、评分详情及 393px / 390px 手机首屏布局。

## 数据来源与许可

本项目代码采用 MIT 许可。数据不随代码分发，由服务端从各来源下载，使用时请遵守原始许可：

- GeoLite2、IPinfo Lite（经 Merged-IP 合并）：CC BY-SA 4.0。DB-IP Lite：CC BY 4.0。
- ip2region：Apache-2.0。lord-alfred/ipranges：CC0。axpwx/IP-Data、monosans/proxy-list：MIT。stamparm/ipsum：Unlicense。proxifly/free-proxy-list：GPL-3.0。
- X4BNet/lists_vpn、FireHOL（含 blocklist.de / CINS Army / GreenSnow / StopForumSpam 子集）、bgp.tools、Spamhaus DROP、各云厂商网段：按各自网站的使用条款。
- 地图：Leaflet 1.9.4（BSD-2-Clause，随代码放在 `web/static/vendor/leaflet/`），底图来自 OpenStreetMap（ODbL）。
- ip-api.com 的免费接口仅限非商业用途，商业部署需要购买它的 Pro 版，或者从 `internal/sources/all.go` 中移除这个数据源。
