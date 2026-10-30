'use strict';
const $ = s => document.querySelector(s);
const out = $('#out'), statusEl = $('#status'), form = $('#q'), input = $('#qi'), qerr = $('#qerr');

const KIND = {residential: '家庭宽带', mobile: '移动网络', hosting: '机房', cdn: 'CDN', business: '企业', education: '教育网', government: '政府', unknown: '未知',
  tor: 'Tor 出口', vpn: 'VPN', proxy: '代理', icloud_relay: 'iCloud 专用代理', crawler: '爬虫', public_service: '公共服务', abuser: '滥用记录', abuse: '滥用记录',
  anycast: '任播', satellite: '卫星网络', org: '知名机构', as_tag: 'AS 标签'};
const HUE = {residential: 150, mobile: 195, hosting: 28, cdn: 265, business: 215, education: 175, government: 330,
  tor: 4, vpn: 4, proxy: 4, abuser: 4, abuse: 4, crawler: 45, icloud_relay: 210, public_service: 190, anycast: 240, satellite: 280, org: 215};
const CONF = {high: ['高', 3], medium: ['中', 2], low: ['低', 1]};
const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
let zhRegion, enRegion;
try { zhRegion = new Intl.DisplayNames(['zh-CN'], {type: 'region', style: 'short'}); enRegion = new Intl.DisplayNames(['en'], {type: 'region'}); } catch {}

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
const signed = n => (n > 0 ? '+' : '') + n;
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
const enName = cc => { try { return /^[a-z]{2}$/i.test(cc || '') && enRegion?.of(cc.toUpperCase()) || ''; } catch { return ''; } };
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
const td = (c, cls) => h('td', {class: cls}, c);
const tr = (cells, cls) => h('tr', {class: cls}, cells.map(c => c?.tagName === 'TD' ? c : td(c)));
const table = (head, rows) => h('div', {class: 'tw'}, h('table', null,
  h('thead', null, h('tr', null, head.map(x => x?.tagName === 'TH' ? x : h('th', null, x)))), h('tbody', null, rows)));
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
const ipHead = r => h('div', {class: 'v-ip'}, mono(r.ip),
  h('button', {type: 'button', class: 'btn sm', onclick: e => copy(r.ip, e.currentTarget)}, '复制'),
  r.version ? tag('IPv' + r.version) : null);

function verdictCard(r, pending) {
  const v = r.verdict || {}, conf = CONF[v.confidence], hue = HUE[v.type], n = r.network || {};
  return h('section', {class: hue == null ? 'card verdict' : 'card verdict hue', style: hue == null ? null : {'--h': hue}},
    h('div', null,
      ipHead(r),
      h('p', {class: 'v-label'}, v.label || v.type_label || '未知'),
      kv([
        ['ASN', n.asn && [ext('https://bgp.tools/as/' + n.asn, 'AS' + n.asn), n.as_name ? ' – ' + n.as_name : '']],
        ['AS 域名', n.as_domain],
        ['IP 范围', mono(n.net_range || n.bgp_prefix || n.prefix)],
        ['位置', places(r)],
        ['IP 来源', nativeLine(r.native || {})],
        ['IP 属性', h('div', {class: 'tags'},
          v.type_label ? tag(v.type_label, hue) : null,
          (v.usage_labels || []).map((l, i) => tag(l, HUE[v.usage?.[i]] ?? 4)),
          conf ? h('span', {class: 'conf c' + conf[1]}, '置信度', h('i'), h('i'), h('i'), ' ' + conf[0]) : null)],
      ]),
      h('p', {class: 'meta'},
        h('span', null, r.mode === 'full' ? '完整查询' : '快速查询（仅离线库）'),
        r.queried_at ? h('span', null, '查询于 ' + fmtTime(r.queried_at)) : null,
        r.elapsed_ms != null ? h('span', null, `耗时 ${r.elapsed_ms} ms`) : null)),
    scoreBox(r.score || {}, pending ? 'pending' : r.mode === 'fast' ? 'offline' : ''));
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

// state is 'pending' while the full lookup runs, so no number is shown that
// the online checks would change, and 'offline' when only the offline
// databases answered.
function scoreBox(s, state) {
  if (state === 'pending') return h('div', {class: 'score'},
    h('div', {class: 'ring wait', style: {'--v': 0, '--h': 200}, role: 'img', 'aria-label': '纯净度评估中'}, spinner(), h('span', null, '评估中')),
    h('span', {class: 'mut'}, '等待在线数据源和 DNS'));
  const v = clamp(s.value), level = s.level || LEVEL(v);
  return h('div', {class: 'score'},
    h('div', {class: 'ring', style: {'--v': v, '--h': scoreHue(v)}, role: 'img', 'aria-label': `纯净度 ${v} 分，${level}`},
      h('b', null, String(v)), h('span', null, level)),
    h('span', {class: 'mut'}, state === 'offline' ? '仅依据离线库，未含在线风险检查' : '纯净度（满分 100）'),
    s.factors?.length ? h('ul', {class: 'factors'}, s.factors.map(f => h('li', null, h('span', null, f.name),
      h('b', {class: f.delta > 0 ? 'pos' : f.delta < 0 ? 'neg' : 'mut'}, signed(f.delta))))) : null);
}

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

function evidenceCard(ev) {
  if (!ev?.length) return null;
  return card('判定依据',
    table(['依据', h('th', {class: 'num'}, '权重'), '来源', '说明'], ev.map(e => tr([
      tag(KIND[e.kind] || e.kind, HUE[e.kind] ?? null), td(h('span', {class: e.weight < 0 ? 'w n' : 'w'}, signed(e.weight)), 'num'),
      e.source, td(e.detail, 'wr')]))));
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

function sameCountry(a, b) {
  const n = s => String(s).toLowerCase().replace(/^the\s+/, '').trim();
  a = n(a); b = n(b);
  return a === b || a.startsWith(b + ' ') || b.startsWith(a + ' ');
}

function geoSrcCard(r) {
  const list = r.geo_sources || [], g = r.geo || {};
  if (!list.length) return r.mode === 'full' ? card('多源地理对照', empty('没有来源返回地理信息')) : null;
  const differs = s => s.country_code && g.country_code ? s.country_code.toUpperCase() !== g.country_code.toUpperCase()
    : !!s.country && has([g.country, g.country_en]) && ![g.country, g.country_en].some(c => c && sameCountry(c, s.country));
  let diff = 0;
  const rows = list.map(s => {
    const d = differs(s); diff += d;
    const who = s.isp && s.org && s.isp !== s.org ? `${s.isp} / ${s.org}` : s.isp || s.org;
    // A source that answered with a line of text only keeps it across the place columns.
    const place = has([s.country, s.country_code, s.region, s.city]) ? [countryOf(s), s.region, s.city]
      : [h('td', {colspan: 3, class: 'wr'}, s.text)];
    return tr([s.source, ...place, td(who, 'wr'), s.asn ? 'AS' + s.asn : '', s.type], d ? 'hl' : null);
  });
  return card(['多源地理对照', diff ? h('small', null, '高亮行的国家与主结果不一致') : null],
    table(['来源', '国家', '地区', '城市', 'ISP / 组织', 'ASN', '类型'], rows));
}
let enToCC;
function ccFromEN(name) {
  if (!enToCC) {
    enToCC = {};
    for (let i = 0; i < 676; i++) {
      const c = String.fromCharCode(65 + (i / 26 | 0), 65 + i % 26), n = enName(c);
      let canon = c;
      try { canon = Intl.getCanonicalLocales('und-' + c)[0].slice(4); } catch {}
      if (n && n !== c && canon === c) enToCC[n.toLowerCase()] = c;
    }
  }
  const k = String(name || '').toLowerCase().replace(/^the\s+/, '').trim();
  return k ? enToCC[k] || Object.entries(enToCC).find(([n]) => sameCountry(n, k))?.[1] || '' : '';
}
const ver = ip => ip.includes(':') ? 6 : 4;
function isPublic(ip) {
  if (ver(ip) === 6) return /^[23]/.test(ip);
  const [a, b] = ip.split('.').map(Number);
  return !(a === 0 || a === 10 || a === 127 || a >= 224 || (a === 100 && b >= 64 && b < 128) || (a === 169 && b === 254)
    || (a === 172 && b >= 16 && b < 32) || (a === 192 && b === 168) || (a === 198 && (b === 18 || b === 19)));
}
// IPv6 addresses from the same /64 count as the same host (privacy addresses rotate).
function v6net(ip) {
  const [a, b = ''] = ip.split('::'), A = a ? a.split(':') : [], B = b ? b.split(':') : [];
  return [...A, ...Array(Math.max(0, 8 - A.length - B.length)).fill('0'), ...B].slice(0, 4).map(x => parseInt(x, 16)).join(':');
}
const inSet = (ip, set) => set.includes(ip) || ver(ip) === 6 && set.some(x => ver(x) === 6 && v6net(x) === v6net(ip));
const ipLine = (ip, ...extra) => h('div', {class: 'ipl'}, mono(ip), extra.filter(Boolean).map(x => h('span', {class: 'mut'}, x)),
  h('a', {class: 'btn sm', href: '/' + ip, 'data-nav': true}, '查询'));

function webrtcIPs() {
  return new Promise((resolve, reject) => {
    const found = new Map();
    let pc;
    try {
      pc = new RTCPeerConnection({iceServers: [{urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478']}]});
    } catch (e) { return reject(e); }
    const done = () => { clearTimeout(t); try { pc.close(); } catch {} resolve(found); };
    const t = setTimeout(done, 3000);
    pc.onicecandidate = e => {
      if (!e.candidate) return done();
      const p = e.candidate.candidate.split(' '), type = e.candidate.type || p[7], ip = normIP(e.candidate.address || p[4]);
      if (ip && (type === 'srflx' || type === 'host') && !found.has(ip)) found.set(ip, type);
    };
    pc.createDataChannel('probe');
    pc.createOffer().then(o => pc.setLocalDescription(o)).catch(done);
  });
}
function connPanel() {
  const L = [['v4', 'IPv4'], ['v6', 'IPv6'], ['pref', '优先协议'], ['cf', 'Cloudflare 视角'], ['cn', '国内出口'], ['dns', 'DNS 出口'], ['rtc', 'WebRTC']];
  const rows = {}, res = {}, hints = h('ul', {class: 'hints', 'aria-live': 'polite'});
  const el = card(['我的连接', h('small', null, '由浏览器直接请求第三方接口检测')],
    h('dl', {class: 'kv fit'}, L.map(([k, t]) => [h('dt', null, t), rows[k] = h('dd', null, h('span', {class: 'mut'}, '检测中…'))])), hints);
  let result = null, pending = L.length;
  const set = (k, ...c) => rows[k].replaceChildren(...c.flat().filter(Boolean));
  const muted = t => h('span', {class: 'mut'}, t);
  const j = url => timed(6000, s => getJSON(url, s));
  const ipOf = o => { const ip = normIP(o?.ip); if (!ip) throw new Error('无效 IP'); return ip; };
  const probe = (k, fn, show, fail = () => set(k, muted('不可用'))) =>
    fn().then(v => { res[k] = v; show(v); }, fail).finally(() => { pending--; update(); });

  probe('v4', () => j('https://api4.ipify.org?format=json').then(ipOf), ip => set('v4', ipLine(ip)));
  probe('v6', () => j('https://api6.ipify.org?format=json').then(ipOf), ip => set('v6', ipLine(ip)), () => set('v6', muted('无 IPv6')));
  probe('pref', () => j('https://api64.ipify.org?format=json').then(ipOf), ip => set('pref', ipLine(ip, ver(ip) === 6 ? 'IPv6 优先' : 'IPv4 优先')));
  probe('cf', async () => {
    const text = await timed(6000, async s => { const r = await fetch('https://1.1.1.1/cdn-cgi/trace', {signal: s}); if (!r.ok) throw new Error(r.status); return r.text(); });
    const o = {};
    for (const line of text.split('\n')) { const i = line.indexOf('='); if (i > 0) o[line.slice(0, i)] = line.slice(i + 1).trim(); }
    o.ip = ipOf(o);
    return o;
  }, o => set('cf', ipLine(o.ip, o.loc && ccName(o.loc), o.colo && '节点 ' + o.colo, o.warp && 'WARP ' + o.warp)));
  probe('cn', async () => {
    try {
      const o = await j('https://myip.ipip.net/json');
      if (o.ret !== 'ok') throw new Error(o.ret);
      return {ip: ipOf(o.data), loc: (o.data.location || []).filter(x => typeof x === 'string' && x).join(' ')};
    } catch { return {ip: ipOf(await j('https://api.ipify.cn/?format=json'))}; }
  }, o => set('cn', ipLine(o.ip, o.loc)));
  probe('dns', async () => {
    const o = await j('https://edns.ip-api.com/json'), e = o.edns;
    return {ip: ipOf(o.dns), geo: String(o.dns.geo || ''), edns: (e && typeof e === 'object' ? [e.ip, e.geo] : [e]).filter(x => typeof x === 'string' && x).join(' ')};
  }, o => set('dns', ipLine(o.ip, o.geo), o.edns && h('div', {class: 'mut'}, 'EDNS 客户端子网：' + o.edns)));
  probe('rtc', webrtcIPs, m => set('rtc', m.size ? [...m].map(([ip, t]) => ipLine(ip, t === 'srflx' ? 'STUN 映射地址' : '本机地址')) : muted('未获取到 IP')));

  function update() {
    if (pending) return;
    const r = result && !result.bogon ? result : {}, out = [];
    const foreign = [res.v4, res.v6, res.pref, res.cf?.ip].filter(Boolean), cn = res.cn?.ip;
    const others = cn ? [...new Set(foreign.filter(x => ver(x) === ver(cn) && !inSet(x, [cn])))] : [];
    if (others.length) out.push(`分流：国内直连、国外走代理（国内出口 ${cn}，国外出口 ${others.join('、')}）`);
    const exits = [...foreign, r.ip].filter(Boolean);
    const leaks = res.rtc && exits.length ? [...res.rtc.keys()].filter(ip => isPublic(ip) && !inSet(ip, exits)) : [];
    if (leaks.length) out.push(`WebRTC 可能泄露真实 IP：${leaks.join('、')}` + (cn && leaks.some(ip => inSet(ip, [cn])) ? '（与国内直连出口相同）' : ''));
    const dcc = res.dns?.geo && ccFromEN(res.dns.geo.split(' - ')[0]), icc = (r.geo?.country_code || res.cf?.loc || '').toUpperCase();
    if (dcc && dcc !== 'ZZ' && /^[A-Z]{2}$/.test(icc) && dcc !== icc)
      out.push(`DNS 出口位于${zhName(dcc)}，与 IP 所在国家（${zhName(icc)}）不一致，可能存在 DNS 泄露`);
    hints.replaceChildren(...out.map(t => h('li', null, t)));
  }
  return {el, setResult(r) { result = r; update(); }};
}
let conn = null, seq = 0, ctl = null;
function setStatus(cls, ...kids) { statusEl.className = 'status' + (cls ? ' ' + cls : ''); statusEl.replaceChildren(...kids); }

function render(r, pending) {
  const parts = r.bogon
    ? [h('section', {class: 'card verdict bogon'}, ipHead(r), h('p', {class: 'v-label'}, '私网或保留地址'), h('p', null, r.bogon))]
    : [verdictCard(r, pending), h('div', {class: 'grid2'}, h('div', {class: 'col'}, geoCard(r.geo || {}), mapCard(r.geo || {})),
      netCard(r.network || {})), geoSrcCard(r), evidenceCard(r.verdict?.evidence)];
  if (conn) { parts.push(conn.el); conn.setResult(r); }
  out.replaceChildren(...parts.filter(Boolean));
  out.classList.remove('stale');
  mountMap();
}

// fast (offline only) and full start together. fast is shown first with the
// score held back until full replaces it; a newer lookup cancels older ones.
async function lookup(ip) {
  const my = ++seq, c = new AbortController();
  ctl?.abort(); ctl = c;
  input.value = ip; clearErr();
  document.title = (ip ? ip + ' - ' : '') + 'IP 类型查询';
  conn = null;
  const run = (mode, ms) => timed(ms, s => getJSON('/api/lookup?' + new URLSearchParams(ip ? {ip, mode} : {mode}), s), c.signal);
  out.classList.add('stale');
  setStatus('', spinner(), '正在查询…');
  const fastReq = run('fast', 15000);
  let full = null;
  const fullReq = run('full', 25000).then(v => (full = v));
  fullReq.catch(() => {}); // awaited below once fast is on screen
  let r;
  try { r = await fastReq; } catch (e) {
    if (my !== seq) return;
    c.abort();
    if (!ip) conn = connPanel();
    out.replaceChildren(h('section', {class: 'card errbox'}, h('h2', null, '查询失败'), h('p', null, errText(e))), ...(conn ? [conn.el] : []));
    out.classList.remove('stale');
    return setStatus();
  }
  if (my !== seq) return;
  if (!ip && !r.bogon) conn = connPanel();
  if (r.bogon) { render(r); return setStatus(); }
  if (!full) {
    render(r, true);
    setStatus('', spinner(), '正在查询在线数据源和 DNS，最长约 10 秒…');
  }
  try { await fullReq; } catch (e) {
    if (my !== seq) return;
    render(r);
    return setStatus('warn', `完整查询失败：${errText(e)}。下面是仅查离线库的快速结果。`);
  }
  if (my !== seq) return;
  render(full);
  setStatus();
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
  lookup(ip);
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
