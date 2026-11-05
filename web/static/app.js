'use strict';
const $ = s => document.querySelector(s);
const bootIP = $('#ipAddress')?.textContent || '';
const out = $('#out'), statusEl = $('#status'), form = $('#q'), input = $('#qi'), qerr = $('#qerr');
const scoreDialog = $('#scoreDetails'), scoreDetailsBody = $('#scoreDetailsBody');
let scoreDetailsOpener = null;

const HUE = {residential: 150, mobile: 195, hosting: 28, cdn: 265, business: 215, education: 175, government: 330,
  tor: 4, vpn: 4, proxy: 4, abuser: 4, abuse: 4, crawler: 45, icloud_relay: 210, public_service: 190, anycast: 240, satellite: 280, org: 215};
const CONF = {high: ['高', 3], medium: ['中', 2], low: ['低', 1]};
const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
let zhRegion;
try { zhRegion = new Intl.DisplayNames(['zh-CN'], {type: 'region', style: 'short'}); } catch {}

// All API strings reach the DOM through createElement/append (text nodes), never innerHTML.
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === 'class') el.className = v;
    else if (k === 'style') for (const p in v) el.style.setProperty(p, v[p]);
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (k === 'href') { const u = safeURL(v); if (u) el.setAttribute('href', u); }
    else el.setAttribute(k, v === true ? '' : v);
  }
  for (const c of kids.flat(9)) if (c != null && c !== false && c !== '') el.append(c);
  return el;
}
// Only same-site IP paths and absolute http(s) URLs become links.
function safeURL(v) {
  v = String(v);
  if (/^\/[0-9A-Za-z.:]*$/.test(v)) return v;
  try { const u = new URL(v); return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null; } catch { return null; }
}
const ext = (href, text = href) => safeURL(href) ? h('a', {href, target: '_blank', rel: 'noopener noreferrer'}, text) : text;
const has = v => Array.isArray(v) ? v.some(has) : typeof v === 'string' ? v.trim() !== '' : v != null && v !== false && v !== 0;
const clamp = v => Math.max(0, Math.min(100, Number(v) || 0));
const scoreHue = v => v >= 95 ? 152 : v >= 80 ? 140 : v >= 50 ? 85 : v >= 25 ? 38 : 4;
const mono = v => has(v) ? h('span', {class: 'mono'}, v) : null;
const tag = (text, hue) => h('span', {class: hue == null ? 'tag' : 'tag hue', style: hue == null ? null : {'--h': hue}}, text);
const tags = (arr, fn = x => tag(String(x))) => arr?.length ? h('div', {class: 'tags'}, arr.map(fn)) : null;
const flag = cc => /^[a-z]{2}$/i.test(cc || '') ? String.fromCodePoint(...[...cc.toUpperCase()].map(c => 127397 + c.charCodeAt(0))) : '';
function ccName(c) {
  if (!/^[a-z]{2}$/i.test(c || '')) return c || '';
  c = c.toUpperCase();
  let n = '';
  try { n = zhRegion?.of(c) || ''; } catch {}
  return `${flag(c)} ${n && n !== c ? n + ' ' : ''}${c}`;
}
const zhName = cc => { try { return zhRegion?.of(cc) || cc; } catch { return cc; } };
// One spelling per country, flag and Chinese name, whatever language the source answered in.
const countryOf = s => /^[a-z]{2}$/i.test(s.country_code || '') ? `${flag(s.country_code)} ${zhName(s.country_code.toUpperCase())}` : s.country || '';
const bi = (zh, en, code) => (zh || en) ? (zh || en) + (zh && en && en !== zh ? ' ' + en : '') + (code ? `（${code}）` : '') : code || '';
const fmtTime = s => { const d = new Date(s); return isNaN(d) ? s : d.toLocaleString('zh-CN', {dateStyle: 'short', timeStyle: 'short'}); };

function isV6(s) {
  if (!s.includes(':') || !/^[0-9a-f:.]+$/i.test(s)) return false;
  if (s.includes('.') && !/:(\d+\.){3}\d+$/.test(s)) return false;
  const halves = s.split('::');
  if (halves.length > 2) return false;
  let groups = halves.flatMap(p => p ? p.split(':') : []), n = groups.length;
  if (groups[n - 1]?.includes('.')) { if (!V4.test(groups.pop())) return false; n++; }
  if (!groups.every(g => /^[0-9a-f]{1,4}$/i.test(g))) return false;
  return halves.length === 2 ? n <= 7 : n === 8;
}
function normIP(s) {
  s = String(s || '').trim().replace(/^\[(.*)\]$/, '$1').replace(/^([0-9a-f:.]*:[0-9a-f:.]*)%[\w.-]+$/i, '$1');
  return V4.test(s) ? s : isV6(s) ? s.toLowerCase() : '';
}

const kv = rows => {
  rows = rows.filter(r => r && has(r[1]));
  return rows.length ? h('dl', {class: 'kv'}, rows.map(([k, v]) => [h('dt', null, k), h('dd', null, v)])) : null;
};
const card = (title, ...kids) => h('section', {class: 'card'}, h('h2', null, title), kids);
const empty = text => h('p', {class: 'empty'}, text);
const spinner = () => h('span', {class: 'spin', 'aria-hidden': 'true'});

// Runs fn(signal) with its own timeout; also aborts when parent aborts.
async function timed(ms, fn, parent) {
  const c = new AbortController(), stop = () => c.abort();
  const t = setTimeout(stop, ms);
  parent?.addEventListener('abort', stop);
  try { return await fn(c.signal); } finally { clearTimeout(t); parent?.removeEventListener('abort', stop); }
}
async function getJSON(url, signal) {
  const r = await fetch(url, {signal, headers: {accept: 'application/json'}});
  let body = null;
  try { body = await r.json(); } catch {}
  if (!r.ok) {
    const e = new Error(body?.error || `HTTP ${r.status}`);
    e.status = r.status;
    e.retry = body?.retry_after || Number(r.headers.get('retry-after')) || 0;
    throw e;
  }
  if (!body) throw new Error('响应不是有效的 JSON');
  return body;
}
const errText = e => e.name === 'AbortError' ? '请求超时'
  : e.status === 429 ? '查询太频繁，' + (e.retry ? `请 ${e.retry} 秒后再试` : '请稍后再试')
  : e instanceof TypeError ? '无法连接服务器' : e.message;
const LEVEL = v => v >= 95 ? '极度纯净' : v >= 80 ? '纯净' : v >= 50 ? '良好' : v >= 25 ? '中性' : '可疑';

async function copy(text, btn) {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch {
    const ta = h('textarea', {style: {position: 'fixed', opacity: '0'}});
    ta.value = text; document.body.append(ta); ta.select();
    try { ok = document.execCommand('copy'); } catch {}
    ta.remove();
  }
  btn.textContent = ok ? '已复制' : '复制失败';
  setTimeout(() => { btn.textContent = '复制'; }, 1500);
}
const ipHead = r => h('div', {class: 'v-ip'},
  h('h1', {id: 'ipAddress', class: 'mono'}, String(r.ip).match(/[^:]+:*|:+/g)?.flatMap(part => [part, h('wbr')])),
  h('button', {id: 'copy', type: 'button', class: 'btn sm', disabled: !normIP(r.ip), 'aria-label': '复制 IP 地址', onclick: e => copy(r.ip, e.currentTarget)}, '复制'),
  r.version ? tag('IPv' + r.version) : null);

function verdictCard(r, pending, failed = false) {
  const v = r.verdict || {}, conf = CONF[v.confidence], hue = HUE[v.type], n = r.network || {};
  const identity = h('div', {class: 'summary-identity'}, ipHead(r),
    h('p', {class: 'v-label'}, r.bogon ? '私网或保留地址' : v.label || v.type_label || (pending && !failed ? '识别中…' : '未知')),
    r.bogon ? h('p', null, r.bogon) : null);
  const body = h('div', {class: 'summary-body'}, kv([
    ['ASN', n.asn && [ext('https://bgp.tools/as/' + n.asn, 'AS' + n.asn), n.as_name ? ' – ' + n.as_name : '']],
    ['AS 域名', n.as_domain],
    ['IP 范围', mono(n.net_range || n.bgp_prefix || n.prefix)],
    ['位置', places(r)],
    ['IP 来源', nativeLine(r.native || {})],
    ['IP 属性', h('div', {class: 'tags'},
      v.type_label ? tag(v.type_label, hue) : null,
      (v.usage_labels || []).map((l, i) => tag(l, HUE[v.usage?.[i]] ?? 4)),
      conf ? h('span', {class: 'conf c' + conf[1]}, '置信度', h('i'), h('i'), h('i'), ' ' + conf[0]) : null)],
  ]), h('p', {class: 'meta'},
    h('span', null, r.mode === 'full' ? '完整查询' : '快速查询（仅离线库）'),
    r.queried_at ? h('span', null, '查询于 ' + fmtTime(r.queried_at)) : null,
    r.elapsed_ms != null ? h('span', null, `耗时 ${r.elapsed_ms} ms`) : null));
  return h('section', {id: 'result', 'aria-busy': String(Boolean(pending && !failed && !r.bogon)),
    class: hue == null ? 'card verdict' : 'card verdict hue', style: hue == null ? null : {'--h': hue}},
    identity, scoreBox(r, r.bogon ? 'bogon' : failed ? 'error' : pending ? 'pending' : ''), body);
}

// Where the main databases place the address, one line each; ip2region only
// for China, where it is the most precise and elsewhere often vague.
const PLACE_SRC = ['Merged-IP', 'ip2region', 'DB-IP City Lite', 'IP2Location.io', 'ipinfo.io', 'ip-api.com'];
function places(r) {
  const list = r.geo_sources || [], cn = (r.geo?.country_code || '').toUpperCase() === 'CN';
  const rows = PLACE_SRC.filter(n => cn || n !== 'ip2region').map(n => list.find(s => s.source === n))
    .filter(s => s && has([s.country, s.country_code]));
  return rows.length ? h('div', {class: 'locs'}, rows.map(s => h('div', null, h('span', {class: 'mut'}, s.source),
    h('span', null, [countryOf(s), s.region, s.city !== s.region && s.city].filter(has).join(', '))))) : null;
}

// A successful request can still lack reputation evidence. Keep that distinct
// from a measured clean result, and keep offline scores out of the pending UI.
function scoreBox(r, state) {
  const s = r.score || {};
  const waiting = state === 'pending', unavailable = s.data_status === 'unavailable';
  const unknown = waiting || state === 'error' || state === 'bogon' || unavailable;
  const v = unknown ? 0 : clamp(s.value), level = waiting ? '评估中…' : state === 'error' || unavailable ? '未能评估'
    : state === 'bogon' ? '不适用' : s.level || LEVEL(v);
  const coverage = s.coverage;
  const coverageText = coverage && Number.isInteger(coverage.received) && Number.isInteger(coverage.total)
    && coverage.received >= 0 && coverage.total > 0 && coverage.received <= coverage.total
    ? ` · ${coverage.received}/${coverage.total} 信誉源` : '';
  const quality = {complete: '数据较充分', limited: '数据有限', unavailable: '数据不足'}[s.data_status];
  return h('div', {id: 'score', class: 'score', 'aria-live': 'polite'},
    h('div', {class: unknown ? 'ring wait' : 'ring', style: {'--v': v, '--h': unknown ? 200 : scoreHue(v)}, role: 'img',
      'aria-label': unknown ? level : `纯净度 ${v} 分，${level}`},
      h('b', {id: 'scoreValue'}, unknown ? '—' : String(v)), h('span', {id: 'scoreLevel'}, level)),
    h('span', {class: 'mut'}, '纯净度 ', h('span', {id: 'scoreTotal', hidden: state === 'bogon'}, '/100')),
    !state && quality ? h('span', {class: 'score-data mut', title: '只统计实际返回安全字段或风险读数的信誉源；数据返回不代表安全保证。'}, quality + coverageText) : null,
    h('button', {id: 'scoreDetailsToggle', type: 'button', class: 'btn score-details-toggle', disabled: state === 'pending' || !r.mode,
      'aria-haspopup': 'dialog', 'aria-controls': 'scoreDetails', onclick: e => showScoreDetails(r, e.currentTarget)}, '评分详情'));
}

const SOURCE_STATUS = {ok: '已返回', empty: '无记录', error: '查询失败', timeout: '超时', quota: '配额不足', skipped: '未执行'};
function clearScoreDetails() {
  scoreDetailsOpener = null;
  if (scoreDialog.open) scoreDialog.close();
  scoreDetailsBody.replaceChildren();
}
function showScoreDetails(r, opener) {
  const s = r.score || {}, unknown = r.bogon || s.data_status === 'unavailable' || r.mode !== 'full';
  const factors = Array.isArray(s.factors) ? s.factors : [];
  const risks = Array.isArray(r.risk) ? r.risk : [];
  const dnsbl = Array.isArray(r.dnsbl) ? r.dnsbl : [];
  const sources = Array.isArray(r.sources) ? r.sources : [];
  const section = (title, ...children) => h('section', {class: 'score-detail-section'}, h('h3', null, title), children);
  const rows = items => h('ul', {class: 'score-detail-list'}, items);
  const signed = n => n > 0 ? '+' + n : String(n);
  const info = kv([
    ['本次 IP', mono(r.ip)],
    ['检测时间', r.queried_at ? fmtTime(r.queried_at) : '未提供'],
    ['纯净度', unknown ? '未能评估' : String(s.value) + ' / 100 · ' + (s.level || LEVEL(s.value))],
    ['数据状态', {complete: '数据较充分', limited: '数据有限', unavailable: '数据不足'}[s.data_status] || (r.mode === 'full' ? '完整查询' : '仅离线数据')],
  ]);
  const factorList = factors.length ? rows(factors.map(f => h('li', null,
    h('div', {class: 'score-detail-row'}, h('span', null, f.name), h('b', null, signed(f.delta) + ' 分')),
    f.detail ? h('p', {class: 'mut'}, f.detail) : null)))
    : empty(unknown ? '缺少有效数据，不能将基准 100 分当作已验证纯净。' : '本次没有达到扣分条件的项目。');
  const riskList = risks.length ? rows(risks.map(x => {
    const effective = Number.isInteger(x.effective_value) ? x.effective_value : x.value;
    return h('li', null, h('div', {class: 'score-detail-row'}, h('b', null, x.source),
      h('span', null, '原始风险 ' + x.value + ' / 100 → 计分 ' + effective + ' / 100')),
      x.detail ? h('p', {class: 'mut'}, x.detail) : null,
      x.scoring_note ? h('p', {class: 'mut'}, x.scoring_note) : null);
  })) : empty('没有返回可计分的风险读数；未知观察不补成风险分。');
  const dnsList = dnsbl.length ? rows(dnsbl.map(x => h('li', null,
    h('div', {class: 'score-detail-row'}, h('b', {class: 'mono'}, x.zone), h('span', null, x.error ? '未能确认' : x.listed ? '命中' : '未命中')),
    x.answer ? h('p', {class: 'mut'}, '返回码：', mono(x.answer)) : null,
    x.error ? h('p', {class: 'mut'}, '错误：' + x.error) : null))) : empty('本次未执行 DNSBL 检查或此地址类型不适用。');
  const sourceList = sources.length ? rows(sources.map(x => h('li', null,
    h('div', {class: 'score-detail-row'}, h('b', null, x.name), h('span', null, SOURCE_STATUS[x.status] || x.status || '未知')),
    h('p', {class: 'mut'}, [x.cached ? '缓存命中' : '', Number.isFinite(x.ms) ? x.ms + ' ms' : '',
      x.reputation === true ? '返回有效信誉字段' : ''].filter(Boolean).join(' · ')),
    x.note ? h('p', {class: 'mut'}, x.note) : null,
    x.error ? h('p', {class: 'mut'}, '错误：' + x.error) : null))) : empty('本次没有来源明细。');
  const countedRisk = risks.map(x => Number.isInteger(x.effective_value) && x.effective_value >= 0 && x.effective_value <= 100 ? x.effective_value : x.value)
    .filter(x => Number.isInteger(x) && x >= 0 && x <= 100);
  const meanRisk = countedRisk.length ? Math.floor(countedRisk.reduce((sum, x) => sum + x, 0) / countedRisk.length) : null;
  const formula = meanRisk == null ? null : h('p', {class: 'mut'},
    `本次计分风险均值 ${meanRisk}；均值除以 4 向下取整，额外扣 ${Math.floor(meanRisk / 4)} 分。代理、类型和 DNSBL 等项目另计。`);
  scoreDetailsBody.replaceChildren(info,
    section('扣分明细', h('p', {class: 'mut'}, '从 100 分开始扣减，结果限制在 0–100；未知或未完成的检测不显示虚构分数。'), factorList),
    section('第三方风险数据', h('p', {class: 'mut'}, '风险值标准化到 0–100，越高表示风险越高。原始读数和实际计分值分别保留；信任分按相反方向归一化。'), formula, riskList),
    section('DNSBL 检查', dnsList), section('本次检测来源', sourceList));
  scoreDetailsOpener = opener;
  scoreDialog.showModal();
}
$('#scoreDetailsClose').addEventListener('click', () => scoreDialog.close());
scoreDialog.addEventListener('close', () => { if (scoreDetailsOpener?.isConnected) scoreDetailsOpener.focus(); });

function nativeLine(n) {
  const reg = n.registered_country, geo = n.geo_country;
  if (!has([n.label, reg, geo])) return null;
  const diff = reg && geo && reg.toUpperCase() !== geo.toUpperCase() ? 'diff' : null;
  return h('div', {class: 'tags'},
    tag(n.label || '未知', {native: 150, broadcast: 28}[n.status] ?? null),
    reg || geo ? h('span', {class: 'cmp'},
      h('span', null, '注册国 ', h('b', {class: diff}, ccName(reg) || '未知')),
      h('span', null, '定位国 ', h('b', {class: diff}, ccName(geo) || '未知'))) : null,
    n.registry ? h('span', {class: 'mut'}, n.registry) : null,
    n.status === 'unknown' && n.detail ? h('span', {class: 'mut'}, n.detail) : null);
}

function geoCard(g) {
  const lat = Number(g.lat) || 0, lon = Number(g.lon) || 0;
  return card('地理位置', kv([
    ['洲', bi(g.continent, '', g.continent_code)],
    ['国家', has([g.country, g.country_en, g.country_code]) && `${g.flag || flag(g.country_code)} ${bi(g.country, g.country_en, g.country_code)}`.trim()],
    ['地区', bi(g.region, g.region_en, g.region_code)],
    ['城市', bi(g.city, g.city_en)],
    ['区县', g.district],
    ['邮编', g.postal],
    ['经纬度', (lat || lon) && ext(`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=10/${lat}/${lon}`, `${lat}, ${lon}`)],
    ['精度', g.accuracy_km && `约 ${g.accuracy_km} km`],
    ['时区', g.time_zone],
    ['UTC 偏移', g.utc_offset],
    ['货币', g.currency],
    ['电话区号', g.calling_code],
    ['欧盟成员', g.is_eu && '是'],
  ]) || empty('没有地理信息'));
}

// The map card is kept while the location stays the same, so the full result
// replacing the fast one does not reload the map.
let mapView = null, leaflet = null;
function mapCard(g) {
  const lat = Number(g.lat), lon = Number(g.lon), acc = Number(g.accuracy_km) || 0, key = [lat, lon, acc].join();
  if (!(Math.abs(lat) <= 90 && Math.abs(lon) <= 180) || !lat && !lon) return dropMap();
  if (mapView?.key !== key) {
    dropMap();
    const box = h('div', {class: 'map'});
    mapView = {key, lat, lon, acc, box, el: h('section', {class: 'card mapcard'},
      h('h2', null, '位置地图', acc ? h('small', null, `圆圈为约 ${acc} km 的定位精度`) : null), box)};
  }
  return mapView.el;
}
function dropMap() { mapView?.map?.remove(); mapView = null; return null; }

// Leaflet is fetched only when a map is shown, after the results are on screen.
function loadLeaflet() {
  const load = (tag, props) => new Promise((resolve, reject) => document.head.append(Object.assign(document.createElement(tag), props,
    {onload: resolve, onerror: () => reject(new Error('无法下载地图组件'))})));
  return leaflet ||= Promise.all([load('link', {rel: 'stylesheet', href: '/static/vendor/leaflet/leaflet.css?v=1.9.4'}),
    load('script', {src: '/static/vendor/leaflet/leaflet.js?v=1.9.4'})])
    .then(() => window.L || Promise.reject(new Error('地图组件无效')), e => { leaflet = null; throw e; });
}
async function mountMap() {
  const v = mapView;
  if (!v?.el.isConnected || v.loading) return;
  if (v.map) return void v.map.invalidateSize();
  v.loading = true;
  try {
    const L = await loadLeaflet();
    if (v !== mapView || !v.el.isConnected) return;
    const at = [v.lat, v.lon], color = getComputedStyle(v.box).getPropertyValue('--acc').trim() || '#0a6e8a';
    v.box.replaceChildren();
    const m = v.map = L.map(v.box, {scrollWheelZoom: false, dragging: !L.Browser.mobile});
    if (v.acc) {
      m.fitBounds(L.latLng(at).toBounds(v.acc * 2000), {maxZoom: 12, padding: [16, 16]});
      L.circle(at, {radius: v.acc * 1000, color, weight: 1, fillOpacity: .1}).addTo(m);
    } else m.setView(at, 10);
    // Tiles send the site origin as Referer, which the OSM tile policy requires;
    // the page itself sends none, so the queried address is not exposed.
    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19, referrerPolicy: 'strict-origin-when-cross-origin',
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors'}).addTo(m);
    L.circleMarker(at, {radius: 6, color, weight: 2, fillColor: color, fillOpacity: .9}).addTo(m);
  } catch (e) {
    v.box.replaceChildren(empty('地图加载失败：' + e.message));
  } finally { v.loading = false; }
}

function netCard(n) {
  const p = n.peeringdb || {};
  return card('网络', kv([
    ['ASN', n.asn && ext('https://bgp.tools/as/' + n.asn, 'AS' + n.asn)],
    ['AS 名称', n.as_name],
    ['AS 域名', n.as_domain],
    ['AS 国家', ccName(n.as_country)],
    ['组织', n.org],
    ['ISP', n.isp],
    ['前缀', mono(n.prefix)],
    ['BGP 前缀', mono(n.bgp_prefix)],
    ['网络名称', n.net_name],
    ['地址范围', mono(n.net_range)],
    ['注册机构', n.registry],
    ['分配日期', n.allocated],
    ['反向解析', n.rdns?.length && [n.rdns.map(d => h('div', {class: 'mono'}, d)),
      n.fcrdns === true ? tag('FCrDNS 通过', 150) : n.fcrdns === false ? tag('FCrDNS 未通过') : tag('来自第三方，未校验')]],
    ['用途类型', n.usage_type],
    ['RPKI', n.rpki],
    ['可见性', n.visibility],
    ['滥用联系', n.abuse],
    ['AS 分类', n.as_class],
    ['AS 标签', tags(n.as_tags)],
    ['同 IP 域名', n.domains?.length && h('div', {class: 'vlist'}, tags(n.domains))],
  ]) || empty('没有网络信息'),
  has(Object.values(p)) ? [h('h3', null, 'PeeringDB'), kv([
    ['名称', p.name], ['网络类型', p.info_type], ['流量', p.info_traffic], ['覆盖范围', p.info_scope],
    ['流量比例', p.info_ratio], ['网站', p.website && ext(p.website)], ['IRR AS-SET', mono(p.irr_as_set)],
    ['互联政策', p.policy], ['IX 数量', p.ix_count], ['机房数量', p.fac_count]])] : null);
}

let seq = 0, ctl = null;
function setStatus(cls, ...kids) { statusEl.className = 'status' + (cls ? ' ' + cls : ''); statusEl.replaceChildren(...kids); }

function render(r, pending = false, failed = false) {
  const parts = [verdictCard(r, pending, failed)];
  if (r.mode && !r.bogon) {
    const geo = geoCard(r.geo || {}), network = netCard(r.network || {});
    geo.classList.add('geo-card'); network.classList.add('net-card'); network.id = 'network';
    parts.push(h('div', {class: 'grid2'}, h('div', {class: 'col'}, geo, mapCard(r.geo || {})), network));
  } else dropMap();
  out.replaceChildren(...parts);
  out.classList.remove('stale');
  mountMap();
}

// Basic offline information can arrive first; only a full report supplies the score.
async function lookup(ip, initialIP = '') {
  clearScoreDetails();
  const my = ++seq, c = new AbortController();
  ctl?.abort(); ctl = c;
  input.value = ip; clearErr();
  document.title = (ip ? ip + ' - ' : '') + 'IP 类型查询';
  const known = normIP(ip || initialIP);
  const placeholder = {ip: known || '获取中…', version: known ? known.includes(':') ? 6 : 4 : 0, verdict: {}};
  render(placeholder, true);
  setStatus('', spinner(), '正在查询…');
  const run = (mode, ms) => timed(ms, signal => getJSON('/api/lookup?' + new URLSearchParams(ip ? {ip, mode} : {mode}), signal), c.signal);
  let basic = null, fullSettled = false;
  const fastReq = run('fast', 15000).then(r => {
    if (!normIP(r.ip)) throw new Error('服务器未返回有效 IP');
    basic = r;
    if (my === seq && !fullSettled) {
      render(r, true);
      setStatus('', spinner(), '正在评估纯净度…');
    }
    return r;
  });
  fastReq.catch(() => {}); // The full report may still succeed if this request fails.
  try {
    const r = await run('full', 25000);
    fullSettled = true;
    if (my !== seq) return;
    if (!normIP(r.ip)) throw new Error('服务器未返回有效 IP');
    if (!r.bogon && (typeof r.score?.value !== 'number' || !Number.isFinite(r.score.value) || r.score.value < 0 || r.score.value > 100))
      throw new Error('纯净度结果暂不可用');
    render(r);
    setStatus();
  } catch (e) {
    fullSettled = true;
    if (my !== seq) return;
    if (!basic) { try { basic = await fastReq; } catch {} }
    if (my !== seq) return;
    const fallback = basic || (known ? placeholder : {...placeholder, ip: '暂未获取到 IP'});
    render(fallback, true, true);
    setStatus('warn', `纯净度评估失败：${errText(e)}。请点击“查我的 IP”或重新查询。`);
  }
}

function clearErr() { input.removeAttribute('aria-invalid'); qerr.hidden = true; }
function showErr(t) { input.setAttribute('aria-invalid', 'true'); qerr.textContent = t; qerr.hidden = false; }
function go(ip) {
  if (location.pathname !== '/' + ip) history.pushState(null, '', '/' + ip);
  lookup(ip);
}
function route(init) {
  let raw = '';
  try { raw = decodeURIComponent(location.pathname.slice(1)).replace(/\/+$/, ''); } catch {}
  const ip = normIP(raw);
  lookup(ip, init ? bootIP : '');
  if (init && raw && !ip) { history.replaceState(null, '', '/'); showErr(`“${raw}”不是有效的 IP 地址，下面是你自己的 IP`); }
}
form.addEventListener('submit', e => {
  e.preventDefault();
  const v = input.value.trim(), ip = normIP(v);
  if (ip) return go(ip);
  showErr(v ? `“${v}”不是有效的 IPv4 或 IPv6 地址` : '请输入要查询的 IP 地址');
  input.focus();
});
input.addEventListener('input', clearErr);
$('#me').addEventListener('click', () => go(''));
document.addEventListener('click', e => {
  const a = e.target.closest?.('a[data-nav]');
  if (!a || e.button || e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;
  e.preventDefault();
  go(normIP(a.getAttribute('href').slice(1)));
  scrollTo({top: 0});
});
addEventListener('popstate', () => route(false));

route(true);
