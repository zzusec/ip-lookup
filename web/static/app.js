'use strict';
const $ = s => document.querySelector(s);
const bootIP = $('#ipAddress')?.textContent || '';
const out = $('#out'), statusEl = $('#status'), form = $('#q'), input = $('#qi'), qerr = $('#qerr');
const scoreDialog = $('#scoreDetails'), scoreDetailsBody = $('#scoreDetailsBody');
const riskTab = $('#riskTab');
let scoreDetailsOpener = null;

function siblingWhoHref(host) {
  host = String(host || '').trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  return /^ip\.[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host) && !/^ip\.(\d+\.){3}\d+$/.test(host) ? `https://who.${host.slice(3)}/` : '';
}
const derivedWhoHref = siblingWhoHref(location.hostname);
if (riskTab && derivedWhoHref) riskTab.href = derivedWhoHref;
const footerWhoWrap = $('#footerWhoWrap'), footerWhoLink = $('#footerWhoLink');
if (footerWhoWrap && footerWhoLink && derivedWhoHref) {
  footerWhoLink.href = derivedWhoHref;
  footerWhoWrap.hidden = false;
}
$('#backTopBtn')?.addEventListener('click', () => {
  try { scrollTo({top: 0, behavior: 'smooth'}); } catch { scrollTo(0, 0); }
});

const TYPE_TONE = {
  residential: 'good', mobile: 'good', education: 'info', business: 'info',
  government: 'info', cdn: 'info', hosting: 'warn', unknown: 'neutral',
};
const USAGE_TONE = {
  tor: 'bad', vpn: 'bad', proxy: 'bad', abuser: 'bad', abuse: 'bad',
  leased: 'warn', crawler: 'warn', icloud_relay: 'info', public_service: 'info',
  anycast: 'info', satellite: 'info',
};
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
function safeURL(v) {
  v = String(v);
  if (/^\/[0-9A-Za-z.:/-]*$/.test(v)) return v;
  try { const u = new URL(v); return u.protocol === 'http:' || u.protocol === 'https:' ? u.href : null; } catch { return null; }
}
const ext = (href, text = href) => safeURL(href) ? h('a', {href, target: '_blank', rel: 'noopener noreferrer'}, text) : text;
const has = v => Array.isArray(v) ? v.some(has) : typeof v === 'string' ? v.trim() !== '' : v != null && v !== false && v !== 0;
const clamp = v => Math.max(0, Math.min(100, Number(v) || 0));
const mono = v => has(v) ? h('span', {class: 'mono'}, v) : null;
const tag = (text, hue) => h('span', {class: hue == null ? 'tag' : 'tag hue', style: hue == null ? null : {'--h': hue}}, text);
const pill = (text, tone = 'neutral', title = '') => h('span', {class: 'pill tone-' + tone, title: title || null}, text);
const dot = (text, state = 'ok', title = '') => h('span', {class: 'dot-state ' + state, title: title || null}, text);
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
const countryOf = s => /^[a-z]{2}$/i.test(s.country_code || '') ? `${flag(s.country_code)} ${zhName(s.country_code.toUpperCase())}` : s.country || '';
const bi = (zh, en, code) => (zh || en) ? (zh || en) + (zh && en && en !== zh ? ' ' + en : '') + (code ? `（${code}）` : '') : code || '';
const fmtTime = s => { const d = new Date(s); return isNaN(d) ? s : d.toLocaleString('zh-CN', {dateStyle: 'short', timeStyle: 'short'}); };
const fmtInt = n => Number.isFinite(Number(n)) && Number(n) > 0 ? Number(n).toLocaleString('en-US') : '';
const fmtPct = v => {
  const n = Number(v);
  if (!Number.isFinite(n)) return '0%';
  const r = Math.round(n * 10) / 10;
  return (Number.isInteger(r) ? String(r) : r.toFixed(1)) + '%';
};
function fmtCPE(raw) {
  const s = String(raw || '').trim();
  const parts = s.startsWith('cpe:2.3:') ? s.slice(8).split(':') : s.startsWith('cpe:/') ? s.slice(5).split(':') : [];
  if (parts.length >= 3) {
    const prod = parts[2]?.replace(/_/g, ' ') || '';
    const ver = parts[3] && parts[3] !== '*' && parts[3] !== '-' ? ' ' + parts[3] : '';
    if (prod) return prod + ver;
  }
  return s;
}

function scoreTier(v, explicitTone, explicitLevel) {
  const n = clamp(v);
  const derived = n >= 90 ? ['极度纯净', 'excellent']
    : n >= 78 ? ['纯净', 'good']
    : n >= 55 ? ['一般', 'fair']
    : n >= 30 ? ['风险偏高', 'poor']
    : ['可疑', 'bad'];
  const validTones = new Set(['excellent', 'good', 'fair', 'poor', 'bad']);
  const tone = validTones.has(explicitTone) ? explicitTone : derived[1];
  const level = explicitLevel && explicitLevel !== '良好' && explicitLevel !== '中性' ? explicitLevel : derived[0];
  return {level, tone};
}

function trafficTier(humanPct, explicitTone, explicitLevel) {
  const hp = clamp(humanPct);
  const derived = hp >= 70 ? ['真人主导', 'good']
    : hp >= 45 ? ['人机混合', 'warn']
    : hp >= 20 ? ['机器偏多', 'poor']
    : ['高度自动化', 'bad'];
  const valid = new Set(['good', 'warn', 'poor', 'bad']);
  return {
    level: explicitLevel && explicitLevel !== '混合流量' && explicitLevel !== '机器偏高' ? explicitLevel : derived[0],
    tone: valid.has(explicitTone) ? explicitTone : derived[1],
  };
}

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
const richCard = (id, title, sub, action, ...kids) => h('section', {id: id || null, class: 'card'},
  h('div', {class: 'card-head'},
    h('div', {class: 'card-title-group'}, h('h2', null, title), sub ? h('p', {class: 'card-sub'}, sub) : null),
    action),
  kids);
const statTile = (k, v, sub = '', vCls = '') => h('div', {class: 'stat-tile'},
  h('span', {class: 'st-k'}, k),
  h('b', {class: 'st-v' + (vCls ? ' ' + vCls : '')}, v),
  sub ? h('span', {class: 'st-sub'}, sub) : null);
const empty = text => h('p', {class: 'empty'}, text);
const spinner = () => h('span', {class: 'spin', 'aria-hidden': 'true'});

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

async function copy(text, btn, resetLabel = '复制') {
  let ok = false;
  try { await navigator.clipboard.writeText(text); ok = true; } catch {
    const ta = h('textarea', {style: {position: 'fixed', opacity: '0'}});
    ta.value = text; document.body.append(ta); ta.select();
    try { ok = document.execCommand('copy'); } catch {}
    ta.remove();
  }
  btn.textContent = ok ? '已复制' : '复制失败';
  setTimeout(() => { btn.textContent = resetLabel; }, 1500);
}

const ipHead = r => h('div', {class: 'v-ip'},
  h('h1', {id: 'ipAddress', class: 'mono'}, String(r.ip).match(/[^:]+:*|:+/g)?.flatMap(part => [part, h('wbr')])),
  h('button', {id: 'copy', type: 'button', class: 'btn sm', disabled: !normIP(r.ip), 'aria-label': '复制 IP 地址', onclick: e => copy(r.ip, e.currentTarget)}, '复制'),
  r.version ? tag('IPv' + r.version) : null);

// Pick ONE best-matching location via multi-source consensus + localized CJK preference
const PLACE_WEIGHT = new Map([
  ['ip2region', 6], ['Merged-IP', 5], ['ip-api.com', 4],
  ['ipwho.is', 3], ['DB-IP City Lite', 3], ['ipinfo.io', 3], ['IP2Location.io', 3],
]);
const hasCJK = s => /[\u4e00-\u9fff]/.test(String(s || ''));
const normCityKey = s => String(s || '').trim().replace(/\s*[（(].*?[)）]\s*$/g, '').trim().toLowerCase();

function bestPlace(r) {
  const g = r.geo || {}, list = r.geo_sources || [];
  const cc = (g.country_code || '').toUpperCase();
  const cands = [];
  if (has([g.country, g.country_code, g.region, g.city])) {
    cands.push({
      country_code: g.country_code,
      country: g.country || g.country_en,
      region: g.region || g.region_en || '',
      city: g.city || g.city_en || '',
      weight: 5,
    });
  }
  for (const s of list) {
    const w = PLACE_WEIGHT.get(s.source);
    if (!w || (s.source === 'ip2region' && cc !== 'CN')) continue;
    if (cc && s.country_code && s.country_code.toUpperCase() !== cc) continue;
    if (!has([s.country, s.country_code])) continue;
    cands.push({
      country_code: s.country_code || cc,
      country: s.country || '',
      region: s.region || '',
      city: s.city || '',
      weight: w,
    });
  }
  if (!cands.length) return null;

  // Group candidates with city/region by normalized city (or region) so majority-agreed locations win
  const clusters = new Map();
  for (const c of cands) {
    const key = normCityKey(c.city) || (c.region ? 'reg:' + normCityKey(c.region) : '');
    if (!key) continue;
    if (!clusters.has(key)) clusters.set(key, []);
    clusters.get(key).push(c);
  }

  let chosen = cands[0];
  if (clusters.size > 0) {
    const scoreCand = c => c.weight + (hasCJK(c.region) || hasCJK(c.city) ? 4 : 0) + (c.region && c.city ? 2 : 0);
    let bestKey = '', bestVotes = -1, bestTop = -1;
    for (const [k, arr] of clusters) {
      const top = Math.max(...arr.map(scoreCand));
      if (arr.length > bestVotes || (arr.length === bestVotes && top > bestTop)) {
        bestKey = k; bestVotes = arr.length; bestTop = top;
      }
    }
    const winners = clusters.get(bestKey) || [];
    winners.sort((a, b) => scoreCand(b) - scoreCand(a));
    if (winners[0]) chosen = winners[0];
  }

  const cleanCity = String(chosen.city || '').replace(/\s*\([^)]*\)\s*$/, '').trim();
  const cleanReg = String(chosen.region || '').trim();
  const parts = [countryOf(chosen), cleanReg, cleanCity && cleanCity !== cleanReg ? cleanCity : ''].filter(has);
  return parts.length ? h('span', {class: 'best-loc'}, parts.join(', ')) : null;
}

function resolveTrafficModel(r, pending) {
  const tr = r.traffic || {};
  if (tr.mode === 'radar' || tr.mode === 'estimated') return tr;
  if (pending || r.bogon || r.mode !== 'full' || r.score?.data_status === 'unavailable') return null;
  const v = r.verdict || {}, f = r.flags || {};
  const baseBot = {residential: 8, mobile: 6, education: 15, government: 14, business: 18, cdn: 46, hosting: 66}[v.type] ?? 22;
  const extra = (f.is_crawler ? 40 : 0) + (f.is_tor ? 24 : f.is_proxy || f.is_vpn ? 16 : 0) + (f.is_abuser ? 18 : 0);
  const botPct = Math.min(96, Math.max(4, baseBot + extra));
  const humanPct = 100 - botPct;
  const tier = trafficTier(humanPct);
  return {
    mode: 'baseline',
    source: '网络类型基线推算',
    human_pct: humanPct,
    bot_pct: botPct,
    level: tier.level,
    tone: tier.tone,
    bot_signals: tr.bot_signals || [],
    request_probe: tr.request_probe || null,
  };
}

function verdictTrafficBox(r, state) {
  if (state === 'bogon') return null;
  const waiting = state === 'pending';
  const tm = resolveTrafficModel(r, waiting || state === 'error');
  if (!tm) {
    return h('div', {id: 'verdictTraffic', class: 'verdict-traffic'},
      h('div', {class: 'vt-head'},
        h('span', {class: 'vt-title'}, '人机流量'),
        h('span', {class: 'vt-src'}, waiting ? '评估中…' : '数据不足')),
      empty(waiting ? '正在计算自治系统人机流量分布…' : (r.traffic?.note || '暂无法估算人机比例')));
  }
  const hp = clamp(tm.human_pct), bp = clamp(tm.bot_pct);
  const tier = trafficTier(hp, tm.tone, tm.level);
  const srcText = tm.mode === 'radar'
    ? `Cloudflare Radar · ${tm.window || '7d'}`
    : (tm.source || '多源行为与网段特征推算');
  const hasDev = typeof tm.desktop_pct === 'number' && typeof tm.mobile_pct === 'number';
  return h('div', {id: 'verdictTraffic', class: 'verdict-traffic'},
    h('div', {class: 'vt-head'},
      h('span', {class: 'vt-title'}, '人机流量', pill(tier.level, tier.tone)),
      h('span', {class: 'vt-src'}, srcText)),
    h('div', {class: 'hb-bar', role: 'img', 'aria-label': `人类 ${fmtPct(hp)}，机器 ${fmtPct(bp)}`},
      hp > 0 ? h('span', {class: 'seg-h', style: {width: hp + '%'}}) : null,
      bp > 0 ? h('span', {class: 'seg-b', style: {width: bp + '%'}}) : null),
    h('div', {class: 'vt-foot mono'},
      h('span', {class: 'h-txt'}, '人类 ' + fmtPct(hp)),
      h('span', {class: 'b-txt'}, '机器 ' + fmtPct(bp))),
    hasDev ? [
      h('div', {class: 'hb-bar dev', role: 'img', 'aria-label': `桌面端 ${fmtPct(tm.desktop_pct)}，移动端 ${fmtPct(tm.mobile_pct)}`},
        h('span', {class: 'seg-h', style: {width: clamp(tm.desktop_pct) + '%'}}),
        h('span', {class: 'seg-b', style: {width: clamp(tm.mobile_pct) + '%'}})),
      h('div', {class: 'vt-dev-row mono'},
        h('span', null, '桌面端 ' + fmtPct(tm.desktop_pct)),
        h('span', null, '移动端 ' + fmtPct(tm.mobile_pct))),
    ] : null);
}

// Band 1: Top Summary Dossier (#result)
function verdictCard(r, pending, failed = false) {
  const v = r.verdict || {}, conf = CONF[v.confidence], n = r.network || {};
  const typeTone = TYPE_TONE[v.type] || 'neutral';
  const state = r.bogon ? 'bogon' : failed ? 'error' : pending ? 'pending' : '';
  const identity = h('div', {class: 'summary-identity'}, ipHead(r),
    h('p', {class: 'v-label'}, r.bogon ? '私网或保留地址' : v.label || v.type_label || (pending && !failed ? '识别中…' : '未知')),
    r.bogon ? h('p', null, r.bogon) : null);
  const body = h('div', {class: 'summary-body'},
    kv([
      ['ASN', n.asn && [ext('https://bgp.tools/as/' + n.asn, 'AS' + n.asn), n.as_name ? ' – ' + n.as_name : '']],
      ['AS 域名', n.as_domain],
      ['IP 范围', mono(n.net_range || n.bgp_prefix || n.prefix)],
      ['位置', bestPlace(r)],
      ['IP 来源', nativeLine(r.native || {})],
      ['IP 属性', h('div', {class: 'tags'},
        v.type_label ? pill(v.type_label, typeTone) : null,
        (v.usage_labels || []).map((l, i) => pill(l, USAGE_TONE[v.usage?.[i]] || 'bad')),
        conf ? h('span', {class: 'conf c' + conf[1]}, '置信度', h('i'), h('i'), h('i'), ' ' + conf[0]) : null)],
    ]),
    h('p', {class: 'meta'},
      h('span', null, r.mode === 'full' ? '完整查询' : '快速查询（仅离线库）'),
      r.queried_at ? h('span', null, '查询于 ' + fmtTime(r.queried_at)) : null,
      r.elapsed_ms != null ? h('span', null, `耗时 ${r.elapsed_ms} ms`) : null));
  return h('section', {id: 'result', 'aria-busy': String(Boolean(pending && !failed && !r.bogon)), class: 'card verdict'},
    identity,
    h('div', {class: 'verdict-side'}, scoreBox(r, state), verdictTrafficBox(r, state)),
    body);
}

function scoreBox(r, state) {
  const s = r.score || {};
  const waiting = state === 'pending', unavailable = s.data_status === 'unavailable';
  const unknown = waiting || state === 'error' || state === 'bogon' || unavailable;
  const v = unknown ? 0 : clamp(s.value);
  const tier = unknown ? {level: '', tone: 'unknown'} : scoreTier(v, s.tone, s.level);
  const level = waiting ? '评估中…' : state === 'error' || unavailable ? '未能评估'
    : state === 'bogon' ? '不适用' : tier.level;
  const coverage = s.coverage;
  const hasCoverage = coverage && Number.isInteger(coverage.received) && Number.isInteger(coverage.total)
    && coverage.received >= 0 && coverage.total > 0 && coverage.received <= coverage.total;
  const quality = {complete: '数据较充分', limited: '数据有限', unavailable: '数据不足'}[s.data_status];
  return h('div', {id: 'score', class: 'score', 'aria-live': 'polite'},
    h('div', {class: unknown ? 'ring wait' : 'ring', 'data-tone': unknown ? null : tier.tone,
      style: {'--v': v}, role: 'img',
      'aria-label': unknown ? level : `纯净度 ${v} 分，${level}`},
      h('b', {id: 'scoreValue'}, unknown ? '—' : String(v)), h('span', {id: 'scoreLevel'}, level)),
    h('div', {class: 'score-meta'},
      h('div', {class: 'score-line'},
        h('span', {class: 'mut'}, '纯净度 ', h('span', {id: 'scoreTotal', hidden: state === 'bogon'}, '/100'))),
      !state && quality ? h('div', {class: 'score-data', title: '只统计实际返回安全字段或风险读数的信誉源；数据返回不代表安全保证。'},
        h('span', {class: 'sd-item'}, quality),
        hasCoverage ? h('span', {class: 'sd-sep', 'aria-hidden': 'true'}, '·') : null,
        hasCoverage ? h('span', {class: 'sd-item'}, `${coverage.received}/${coverage.total} 信誉源`) : null) : null,
      h('button', {id: 'scoreDetailsToggle', type: 'button', class: 'btn score-details-toggle', disabled: state === 'pending' || !r.mode,
        'aria-haspopup': 'dialog', 'aria-controls': 'scoreDetails', onclick: e => showScoreDetails(r, e.currentTarget)}, '评分详情')));
}

function nativeLine(n) {
  const reg = n.registered_country, geo = n.geo_country;
  if (!has([n.label, reg, geo])) return null;
  const diff = reg && geo && reg.toUpperCase() !== geo.toUpperCase() ? 'diff' : null;
  const tone = n.status === 'native' ? 'good' : n.status === 'broadcast' ? 'warn' : 'neutral';
  return h('div', {class: 'tags'},
    pill(n.label || '未知', tone),
    reg || geo ? h('span', {class: 'cmp'},
      h('span', null, '注册国 ', h('b', {class: diff}, ccName(reg) || '未知')),
      h('span', null, '定位国 ', h('b', {class: diff}, ccName(geo) || '未知'))) : null,
    n.registry ? h('span', {class: 'mut'}, n.registry) : null,
    n.status === 'unknown' && n.detail ? h('span', {class: 'mut'}, n.detail) : null);
}

// Band 2: Left (4-Scenario Suitability Cards) + Right (Risk Matrix & Cross-Audit Notes)
function buildFallbackScenarios(r) {
  if (Array.isArray(r.audit?.scenarios) && r.audit.scenarios.length) return r.audit.scenarios;
  if (r.mode !== 'full' || r.score?.data_status === 'unavailable' || r.bogon) return [];
  const f = r.flags || {}, v = r.verdict || {}, isHost = Boolean(f.is_hosting || f.is_cdn || v.type === 'hosting' || v.type === 'cdn');
  const isBroad = r.native?.status === 'broadcast';
  const mk = (id, name, raw, detail) => {
    const s = Math.max(1, Math.min(10, raw));
    const tone = s >= 8 ? 'good' : s >= 6 ? 'warn' : s >= 4 ? 'poor' : 'bad';
    const status = s >= 8 ? '优质可用' : s >= 6 ? (id === 'ai' ? '可以尝试' : '可用') : s >= 4 ? '易受限' : '高风控 / 受限';
    return {id, name, score: s, max: 10, status, tone, detail};
  };
  const penalty = (f.is_tor ? 5 : f.is_proxy || f.is_vpn ? 3 : 0) + (f.is_abuser ? 3 : 0) + (isBroad ? 1 : 0);
  return [
    mk('tiktok', 'TikTok', (isHost ? 6 : 9) - penalty, isHost ? '机房/CDN 网段可正常连接，但自然推荐权重低于本地原生住宅宽带' : '原生终端接入网络，适合内容浏览与分区定位'),
    mk('social', '社媒运营', (isHost ? 6 : 9) - penalty, isHost ? '常规浏览可用，新注册或高频操作更容易触发二次验证' : '网络属性与信誉良好，适合常规社媒账号登录维护'),
    mk('ai', 'AI 应用', (isHost ? 7 : 9) - penalty, isHost ? '原生云/边缘网段通常可访问，严格平台偶发人机质询' : '定位地区与信誉满足主流大模型平台要求'),
    mk('shield', '免盾浏览', (isHost ? 7 : 9) - penalty, isHost ? '数据中心 ASN 初始人机信任分略低于普通家庭宽带' : '未见黑名单与异常扫描特征，日常访问较少弹盾'),
  ];
}

function buildScenarioCard(r, pending) {
  const scenarios = buildFallbackScenarios(r);
  const scenarioNames = {
    tiktok: 'TikTok · 短视频分发',
    social: '社媒运营 · 账号登录维护',
    ai: 'AI 应用 · 主流大模型访问',
    shield: '免盾浏览 · 验证码与邮局信誉',
  };
  const body = scenarios.length ? h('div', {class: 'scenario-stack'}, scenarios.map(sc => {
    const pts = Math.max(0, Math.min(10, Number(sc.score) || 0));
    const segs = Array.from({length: 10}, (_, i) => h('i', {class: i < pts ? 'on' : null}));
    return h('div', {class: 'sc-row-card'},
      h('div', {class: 'sc-row-top'},
        h('div', {class: 'sc-name-wrap'},
          h('b', null, scenarioNames[sc.id] || sc.name),
          pill(sc.status, sc.tone)),
        h('span', {class: 'sc-pts'}, `${pts} / ${sc.max || 10}`)),
      h('div', {class: 'sc-seg-bar', 'data-tone': sc.tone, role: 'img', 'aria-label': `${sc.name} ${pts}/10`}, segs),
      sc.detail ? h('p', {class: 'sc-desc'}, sc.detail) : null);
  })) : empty(pending ? '正在根据原生性、网络类型与信誉信号生成各业务场景评估…' : '信誉数据不足，暂无法生成场景可用性参考');

  return richCard(
    'scenarioCard',
    '业务场景可用性参考',
    '结合原生地区、机房/家宽属性与风控记录评估常见场景表现',
    null,
    body
  );
}

// Band 2: Left (Risk & Masquerade Verification) + Right (IP Blacklists & Dirty Neighbors)
function riskAndBlacklistRow(r, pending) {
  const f = r.flags || {}, a = r.audit || {}, act = a.activity || {};
  const torHit = Boolean(f.is_tor || act.tor_exit || act.tor_relay);
  const leaseHit = Boolean(f.is_leased || a.lease?.leased);
  const masqHit = Boolean(a.flow?.masquerade);
  const sigs = Array.isArray(r.traffic?.bot_signals) ? r.traffic.bot_signals : [];

  const riskSummary = a.risk_summary || (pending ? '评估中…' : (f.is_tor || f.is_abuser ? '发现明显威胁标记' : f.is_proxy || f.is_vpn || leaseHit ? '存在代理或租赁特征' : '未发现明显威胁'));
  const riskTone = a.risk_tone || (f.is_tor || f.is_abuser ? 'bad' : f.is_proxy || f.is_vpn || leaseHit ? 'warn' : 'good');
  const abuseLevel = a.abuse_level || (pending ? '评估中…' : (f.is_abuser ? '高风险' : '纯净'));
  const abuseTone = a.abuse_tone || (f.is_abuser ? 'bad' : 'good');
  const honeyStatus = a.honeypot_status || (pending ? '评估中…' : '纯净');
  const honeyTone = a.honeypot_tone || 'good';

  const trio = h('div', {class: 'audit-trio'},
    h('div', {class: 'trio-box'}, h('span', null, '威胁综述'), h('b', {class: pending ? 'mut' : 'tone-' + riskTone}, riskSummary)),
    h('div', {class: 'trio-box'}, h('span', null, '滥用评级'), h('b', {class: pending ? 'mut' : 'tone-' + abuseTone}, abuseLevel)),
    h('div', {class: 'trio-box'}, h('span', null, 'IP 黑名单状态'), h('b', {class: pending ? 'mut' : 'tone-' + honeyTone}, honeyStatus)));

  const checkCell = (name, hit, hitText, severity = 'bad', tip = '') => {
    if (pending) return h('div', {class: 'check-cell'}, h('span', {class: 'check-name'}, name), h('span', {class: 'mut'}, '…'));
    return h('div', {class: hit ? 'check-cell hit-' + severity : 'check-cell', title: tip || null},
      h('span', {class: 'check-name'}, name),
      hit ? dot(hitText, severity) : dot('未检测到', 'ok'));
  };

  const checkGrid = h('div', {class: 'check-grid'},
    checkCell('VPN 隧道', Boolean(f.is_vpn), '检测到', 'bad'),
    checkCell('代理 (Proxy)', Boolean(f.is_proxy), '检测到', 'bad'),
    checkCell('Tor 匿名节点', torHit, f.is_tor || act.tor_exit ? '出口节点' : '中继节点', 'bad'),
    checkCell('爬虫 / 机器人', Boolean(f.is_crawler), '检测到', 'warn'),
    checkCell('商业地址租赁', leaseHit, a.lease?.broker || '租赁网段', 'warn', a.lease?.detail || ''),
    checkCell('家宽流量核验', masqHit, '疑似伪家宽', 'bad', a.flow?.detail || ''));

  const specialFlags = [
    f.is_anycast ? tag('Anycast 任播节点', 195) : null,
    f.is_icloud_relay ? tag('iCloud 专用代理', 210) : null,
    f.is_satellite ? tag('卫星通信网段', 225) : null,
    f.is_public_service ? tag('公共基础设施', 180) : null,
  ].filter(Boolean);

  const leaseDetail = a.lease?.detail || (pending ? '正在核验商业 IP 租赁经纪商名录…' : '未命中已知商业 IP 租赁经纪商（IPXO / InterLIR / Cloud Innovation 等）');
  const flowDetail = a.flow?.detail || (pending ? '正在交叉比对自治系统流量方向…' : '未发现出向型服务器流量冒充家庭宽带的异常特征');

  const auditNotes = h('div', {class: 'audit-notes'},
    h('div', {class: 'audit-note-item'},
      h('span', {class: 'an-k'}, '商业租赁核验', leaseHit ? pill(a.lease?.broker || '命中租赁', 'warn') : null),
      h('span', {class: 'an-v'}, leaseDetail)),
    h('div', {class: 'audit-note-item'},
      h('span', {class: 'an-k'}, '流量方向交叉核验', masqHit ? pill('疑似伪家宽', 'bad') : null),
      h('span', {class: 'an-v'}, flowDetail)),
    sigs.length ? h('div', {class: 'audit-note-item'},
      h('span', {class: 'an-k'}, '观测到的自动化线索'),
      h('ul', {class: 'hb-signals'}, sigs.map(s => h('li', null, s)))) : null,
    specialFlags.length ? h('div', {class: 'tags'}, specialFlags) : null);

  const leftCard = richCard(
    'securityCard',
    '风险与技术核验',
    '识别匿名代理隧道、商业租赁重宣告网段与伪家宽特征',
    null,
    trio,
    checkGrid,
    auditNotes
  );

  // Right Card: IP Blacklists & Same-Subnet Dirty Neighbors
  const nb = a.neighbor;
  const subMask = r.version === 6 ? '/48' : '/24';
  const totalCells = 32;
  let dirtyCells = 0, dirtyCls = 'dirty-warn';
  if (nb && nb.flagged > 0) {
    const ratio = nb.total ? nb.flagged / nb.total : Math.min(1, nb.flagged / 32);
    dirtyCells = Math.max(1, Math.round(ratio * totalCells));
    if (nb.level === '高危脏段' || ratio >= 0.12) dirtyCls = 'dirty-bad';
  }
  const nbTone = !nb ? 'neutral' : nb.flagged === 0 ? 'good' : nb.level === '高危脏段' ? 'bad' : 'warn';
  const nbRightLabel = !nb ? (pending ? '扫描中…' : '离线库未加载')
    : nb.total ? `脏邻居 ${nb.flagged} / ${nb.total}` + (nb.density_pct ? ` (${fmtPct(nb.density_pct)})` : '')
    : `脏邻居 ${nb.flagged} 个子块`;

  const subnetBox = h('div', {class: 'subnet-box'},
    h('div', {class: 'subnet-head'},
      h('div', {class: 'tags'},
        h('b', null, `同段脏邻居 (${subMask})`),
        nb?.prefix ? mono(nb.prefix) : null),
      nb ? pill(nb.level || (nb.flagged === 0 ? '纯净网段' : '存在连带'), nbTone) : h('span', {class: 'mut'}, nbRightLabel)),
    h('div', {class: nb ? 'subnet-grid' : 'subnet-grid pending', role: 'img', 'aria-label': '同段脏邻居污染密度示意'},
      Array.from({length: totalCells}, (_, i) => h('i', {class: i < dirtyCells ? dirtyCls : null}))),
    h('div', {class: 'subnet-foot'},
      h('span', null, nb ? nbRightLabel : `按同 ${subMask} 网段统计黑名单与代理脏邻居数量`),
      nb?.lists_loaded ? h('span', null, `已比对 ${nb.lists_loaded} 份黑名单与代理库`) : null),
    nb?.categories?.length ? h('div', {class: 'tags', style: {'margin-top': '6px'}}, nb.categories.map(c => tag('脏邻居类型：' + c))) : null);

  const dnsblTotal = (r.dnsbl || []).length;
  const dnsblHits = (r.dnsbl || []).filter(d => d.listed).length;
  const blackHits = (r.lists || []).filter(l => ['abuse', 'tor', 'proxy', 'vpn'].includes(l.category)).map(l => l.label).filter(Boolean);
  const otherListHits = (r.lists || []).filter(l => !['abuse', 'tor', 'proxy', 'vpn'].includes(l.category)).map(l => l.label).filter(Boolean);
  const telemetry = h('div', {class: 'stat-strip four'},
    statTile('DNSBL 黑名单', pending ? '…' : `${dnsblHits} / ${dnsblTotal}`, dnsblHits > 0 ? '命中实时黑名单' : '实时联防未命中', dnsblHits > 0 ? 'bot mono' : 'mono'),
    statTile('离线黑名单库', pending ? '…' : `${blackHits.length} 命中`, blackHits.length > 0 ? '命中恶意/代理集' : '威胁名单未命中', blackHits.length > 0 ? 'bot mono' : 'mono'),
    statTile('垃圾表单记录', pending ? '…' : `${act.spam_reports || 0} 次`, act.spam_last_seen ? '最近 ' + act.spam_last_seen : 'StopForumSpam', act.spam_reports > 0 ? 'bot mono' : 'mono'),
    statTile('蜜罐捕获包', pending ? '…' : `${act.dshield_packets || 0} 包`, act.otx_pulses ? `OTX 脉冲 ${act.otx_pulses} 条` : (act.dshield_targets ? `涉及 ${act.dshield_targets} 目标` : 'DShield / OTX'), (act.dshield_packets > 0 || act.otx_pulses > 0) ? 'bot mono' : 'mono'));

  const openPorts = r.ports?.ports || [];
  const cpes = (r.ports?.cpes || []).map(fmtCPE).filter(Boolean);
  const vulns = r.ports?.vulns || [];
  const portTags = r.ports?.tags || [];

  const exposureBox = h('div', {class: 'exposure-box'}, kv([
    ['黑名单核验', pending ? h('span', {class: 'mut'}, '核验中…')
      : (blackHits.length || dnsblHits > 0)
        ? h('div', {class: 'tags'},
            dnsblHits > 0 ? pill(`DNSBL 命中 ${dnsblHits} 家`, 'bad') : null,
            blackHits.slice(0, 6).map(x => pill(x, 'bad')))
        : dot('未命中实时 DNSBL 与离线恶意黑名单', 'ok')],
    ['网段归属名录', otherListHits.length ? tags(otherListHits.slice(0, 5)) : null],
    ['公开暴露端口', openPorts.length
      ? tags(openPorts.slice(0, 14))
      : (pending ? h('span', {class: 'mut'}, '正在查询暴露端口…') : dot('未见常见公开暴露端口', 'ok'))],
    ['服务组件指纹', tags(cpes.slice(0, 6))],
    ['协议与主机标签', portTags.length ? tags(portTags, t => tag(t, 195)) : null],
    ['关联漏洞编号', vulns.length ? h('div', {class: 'tags'},
      pill(`关联 ${vulns.length} 项 CVE`, 'bad'),
      vulns.slice(0, 4).map(v => mono(v))) : null],
  ]));

  const detailAction = h('button', {
    type: 'button',
    class: 'btn sm',
    disabled: pending || !r.mode,
    onclick: e => showScoreDetails(r, e.currentTarget),
  }, '黑名单明细');

  const rightCard = richCard(
    'subnetCard',
    'IP 黑名单与同段脏邻居',
    '并发核查 14 家实时 DNSBL、60+ 离线黑名单库与同 C 段脏邻居污染比例',
    detailAction,
    subnetBox,
    telemetry,
    exposureBox
  );

  return h('div', {id: 'insightGrid', class: 'grid2'}, leftCard, rightCard);
}

// Bottom Band: On-Demand Live Probe & CLI / JSON Workbench (placed at the bottom of the page)
function buildWorkbenchSection(r, pending) {
  const cleanRow = (k, v) => has(v) ? h('div', {class: 'clean-row'}, h('span', {class: 'clean-k'}, k), h('div', {class: 'clean-v'}, v)) : null;

  let tz = '', rawPath = '';
  try { tz = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch {}
  try { rawPath = decodeURIComponent(location.pathname.slice(1)).replace(/\/+$/, ''); } catch {}
  const lang = navigator.language || (navigator.languages && navigator.languages[0]) || '';
  const explicitIP = normIP(rawPath);
  const cmdHost = location.port ? location.origin : location.hostname;
  const textCmd = `curl ${cmdHost}`;
  const jsonPath = explicitIP ? `/json/${explicitIP}` : '/json';
  const jsonCmd = `curl ${cmdHost}/json`;

  let visitorHandshake = null;
  if (r.traffic?.request_probe) {
    const rp = r.traffic.request_probe;
    const env = inspectBrowserClient();
    const autoPct = clamp(Math.round(rp.automation_share * 0.65 + env.autoPts * 0.35));
    const humanShare = 100 - autoPct;
    visitorHandshake = cleanRow('当前访客握手', autoPct >= 45
      ? pill(`脚本倾向 ${autoPct}% · ${rp.client_family || '客户端'}`, 'warn')
      : dot(`真人终端特征 ${humanShare}% · ${rp.client_family || '标准浏览器'}${rp.proto ? ' (' + rp.proto + ')' : ''}`, 'ok'));
  }

  const cliRow = (label, cmd) => h('div', {class: 'cli-row'},
    h('code', {class: 'cli-code', title: cmd}, cmd),
    h('button', {type: 'button', class: 'btn sm', 'aria-label': '复制' + label, onclick: e => copy(cmd, e.currentTarget)}, '复制'));

  const workbenchCard = richCard(
    'workbenchCard',
    '实时连通与终端接口',
    '按需实测当前浏览器出口分流、443 借证伪装，或通过终端拉取报告',
    null,
    h('div', {class: 'wb-split'},
      h('div', {class: 'wb-card-body'},
        visitorHandshake,
        h('ul', {class: 'wb-checklist'},
          h('li', null, '出口 TCP/443 证书与 Reality 借证核验'),
          h('li', null, 'Cloudflare / ChatGPT / Claude 分流对照'),
          h('li', null, 'DNS / EDNS 客户端子网区域比对'),
          h('li', null, 'WebRTC STUN 候选与协议栈指纹')),
        h('div', {class: 'wb-actions'},
          h('button', {
            id: 'deepProbeBtn',
            type: 'button',
            class: 'btn primary',
            disabled: pending,
            onclick: () => runInlineProbe(),
          }, activeProbeState?.running ? '正在实测…' : activeProbeState ? '重新实测连接与 443' : '开始连接与 443 实测'),
          (tz || lang) ? h('span', {class: 'mut mono', style: {'font-size': '12px'}},
            ['时区 ' + (tz || '未知'), lang ? '语言 ' + lang : ''].filter(Boolean).join(' · ')) : null)),
      h('div', {class: 'wb-cli-block'},
        h('div', {class: 'wb-cli-head'}, h('span', null, '终端命令与 JSON 接口'), ext(jsonPath, '查看原始 JSON')),
        cliRow('终端纯文本命令', textCmd),
        cliRow('JSON 接口命令', jsonCmd)))
  );

  return [
    workbenchCard,
    h('div', {id: 'probeInlineBody', class: 'probe-inline', 'aria-live': 'polite'}),
  ];
}

// Score Details Modal (#scoreDetails)
const SOURCE_STATUS = {ok: '已返回', empty: '无记录', error: '查询失败', timeout: '超时', quota: '配额不足', skipped: '未执行'};
function clearScoreDetails() {
  scoreDetailsOpener = null;
  if (scoreDialog.open) scoreDialog.close();
  scoreDetailsBody.replaceChildren();
}
function showScoreDetails(r, opener) {
  const s = r.score || {}, unknown = r.bogon || s.data_status === 'unavailable' || r.mode !== 'full';
  const tier = scoreTier(s.value, s.tone, s.level);
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
    ['纯净度', unknown ? '未能评估' : String(s.value) + ' / 100 · ' + tier.level],
    ['等级标准', '90–100 极度纯净（深绿） · 78–89 纯净（绿） · 55–77 一般（琥珀橙） · 30–54 风险偏高（橙红） · 0–29 可疑（红）'],
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

// Band 3: Geography + Map (Left) & Consolidated Network / ASN Profile (Right)
function geoCard(g) {
  const lat = Number(g.lat) || 0, lon = Number(g.lon) || 0;
  const geoTiles = [
    g.continent ? statTile('所属大洲', g.continent, g.continent_code || '地理分区') : null,
    g.time_zone ? statTile('标准时区', g.time_zone, g.utc_offset ? 'UTC ' + g.utc_offset : '区域时间', 'mono') : null,
    (g.currency || g.calling_code) ? statTile('货币与区号', [g.currency, g.calling_code].filter(Boolean).join(' · '), g.is_eu ? '欧盟成员地区' : '国际通信参数', 'mono') : null,
  ].filter(Boolean);
  const topTiles = geoTiles.length >= 2 ? h('div', {class: geoTiles.length === 2 ? 'stat-strip two' : 'stat-strip'}, geoTiles) : null;

  const list = kv([
    ['所属大洲', !topTiles && bi(g.continent, '', g.continent_code)],
    ['国家', has([g.country, g.country_en, g.country_code]) && `${g.flag || flag(g.country_code)} ${bi(g.country, g.country_en, g.country_code)}`.trim()],
    ['地区 / 省州', bi(g.region, g.region_en, g.region_code)],
    ['城市', bi(g.city, g.city_en)],
    ['区县', g.district],
    ['邮政编码', mono(g.postal)],
    ['经纬度坐标', (lat || lon) && ext(`https://www.openstreetmap.org/?mlat=${lat}&mlon=${lon}#map=10/${lat}/${lon}`, `${lat}, ${lon}`)],
    ['定位精度半径', g.accuracy_km && `约 ${g.accuracy_km} km`],
    ['时区', !topTiles && [g.time_zone, g.utc_offset && 'UTC ' + g.utc_offset].filter(Boolean).join(' · ')],
    ['欧盟成员', !topTiles && g.is_eu && '是'],
  ]);
  return card('地理位置', topTiles, list || empty('没有地理信息'));
}

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
    const at = [v.lat, v.lon], color = getComputedStyle(v.box).getPropertyValue('--acc').trim() || '#0b6b88';
    v.box.replaceChildren();
    const m = v.map = L.map(v.box, {scrollWheelZoom: false, dragging: !L.Browser.mobile});
    if (v.acc) {
      m.fitBounds(L.latLng(at).toBounds(v.acc * 2000), {maxZoom: 12, padding: [16, 16]});
      L.circle(at, {radius: v.acc * 1000, color, weight: 1, fillOpacity: .1}).addTo(m);
    } else m.setView(at, 10);
    L.tileLayer('https://tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19, referrerPolicy: 'strict-origin-when-cross-origin',
      attribution: '&copy; <a href="https://www.openstreetmap.org/copyright" target="_blank" rel="noopener noreferrer">OpenStreetMap</a> contributors'}).addTo(m);
    L.circleMarker(at, {radius: 6, color, weight: 2, fillColor: color, fillOpacity: .9}).addTo(m);
  } catch (e) {
    v.box.replaceChildren(empty('地图加载失败：' + e.message));
  } finally { v.loading = false; }
}

function netCard(n) {
  const p = n.peeringdb || {};
  const v4Total = fmtInt(n.as_ipv4_count);
  const hasPfx = Boolean(n.as_prefixes_v4 || n.as_prefixes_v6);
  const netTiles = [
    v4Total ? statTile('ASN IPv4 地址总量', v4Total, '宣告前缀并集去重规模', 'mono') : null,
    p.info_traffic ? statTile('预估骨干带宽', p.info_traffic, [p.info_scope, p.info_ratio].filter(Boolean).join(' · ') || 'PeeringDB 申报', 'mono') : null,
    (p.ix_count || p.fac_count)
      ? statTile('互联交换设施', `IX ${p.ix_count || 0} · 机房 ${p.fac_count || 0}`, p.policy ? '互联策略 ' + p.policy : 'BGP 互联节点', 'mono')
      : hasPfx ? statTile('宣告路由前缀', `v4 ${n.as_prefixes_v4 || 0} · v6 ${n.as_prefixes_v6 || 0}`, '全局路由表活跃前缀数', 'mono') : null,
  ].filter(Boolean);
  const scaleStrip = netTiles.length >= 2 ? h('div', {class: netTiles.length === 2 ? 'stat-strip two' : 'stat-strip'}, netTiles) : null;

  const rpkiRaw = String(n.rpki || '');
  const rpkiNode = !rpkiRaw ? null
    : rpkiRaw === '有效' || (/valid/i.test(rpkiRaw) && !/invalid/i.test(rpkiRaw)) ? dot('Valid（路由源验证有效）', 'ok')
    : /无效|invalid/i.test(rpkiRaw) ? pill('Invalid（' + rpkiRaw + '）', 'bad')
    : dot(rpkiRaw, 'info');

  const entity = n.registrant && n.registrant !== n.org ? `${n.registrant}${n.org ? ' / ' + n.org : ''}` : (n.org || n.registrant);

  const list = kv([
    ['ASN', n.asn && h('div', {class: 'tags'},
      ext('https://bgp.tools/as/' + n.asn, mono('AS' + n.asn)),
      ext('https://www.peeringdb.com/asn/' + n.asn, 'PeeringDB'),
      h('button', {type: 'button', class: 'btn sm', onclick: e => copy('AS' + n.asn, e.currentTarget, '复制 ASN')}, '复制 ASN'))],
    ['AS 名称', n.as_name],
    ['AS 自报类型', n.as_type_label || p.info_type || n.as_class],
    ['AS 注册日期', mono(n.as_created)],
    ['企业 / 主体', entity],
    ['运营服务商', n.isp && n.isp !== n.as_name ? n.isp : null],
    ['BGP 路由前缀', mono(n.bgp_prefix || n.prefix)],
    ['所属注册网段', n.prefix && n.bgp_prefix && n.prefix !== n.bgp_prefix ? mono(n.prefix) : null],
    ['网络名称', mono(n.net_name)],
    ['注册局与分配', [n.registry && n.registry.toUpperCase(), n.allocated].filter(Boolean).join(' · ')],
    ['RPKI 路由签名', rpkiNode],
    ['反向解析', n.rdns?.length && h('div', {class: 'tags'},
      n.rdns.map(d => mono(d)),
      n.fcrdns === true ? dot('FCrDNS 通过', 'ok') : n.fcrdns === false ? dot('FCrDNS 未过', 'warn') : null)],
    ['路由可见度', n.visibility],
    ['IRR 路由集', mono(p.irr_as_set)],
    ['滥用信誉 / 联系', [n.abuser_score, n.abuse].filter(Boolean).join(' · ')],
    ['AS 标签', tags(n.as_tags)],
    ['同 IP 关联域名', n.domains?.length && h('div', {class: 'vlist'}, tags(n.domains))],
  ]);

  return card('网络信息', scaleStrip, list || empty('没有网络信息'));
}

// Inline Active Connection & 443 Reality Probe Engine
let seq = 0, ctl = null, probeCtl = null, connModule = null, lastRendered = null, activeProbeState = null;

function clearActiveProbe() {
  probeCtl?.abort();
  probeCtl = null;
  activeProbeState = null;
  const inline = $('#probeInlineBody');
  if (inline) inline.replaceChildren();
}

function inspectBrowserClient() {
  const nav = window.navigator || {};
  const ua = String(nav.userAgent || '');
  const checks = [];
  let autoPts = 0;
  if (nav.webdriver === true) {
    autoPts += 65;
    checks.push({name: 'WebDriver 标识', status: 'bot', detail: 'navigator.webdriver 为 true（浏览器受自动化驱动控制）'});
  } else {
    checks.push({name: 'WebDriver 标识', status: 'pass', detail: '未检测到 WebDriver 自动化受控标记'});
  }
  const hooks = ['__playwright', '__pwInitScripts', '_phantom', 'callPhantom', '__nightmare', 'domAutomation']
    .filter(k => k in window);
  if (hooks.length) {
    autoPts += 55;
    checks.push({name: '注入钩子扫描', status: 'bot', detail: '检测到自动化运行时符号：' + hooks.join(', ')});
  }
  const langs = Array.isArray(nav.languages) ? nav.languages.filter(Boolean) : [];
  if (!langs.length) {
    autoPts += 20;
    checks.push({name: '浏览器语言栈', status: 'warn', detail: 'navigator.languages 为空'});
  } else {
    checks.push({name: '浏览器语言栈', status: 'pass', detail: '语言偏好正常（' + langs.slice(0, 3).join(', ') + '）'});
  }
  if (/HeadlessChrome|PhantomJS/i.test(ua)) {
    autoPts += 70;
    checks.push({name: '渲染引擎特征', status: 'bot', detail: 'User-Agent 携带无头渲染标识'});
  } else if (window.outerWidth === 0 && window.outerHeight === 0) {
    autoPts += 25;
    checks.push({name: '视口几何尺寸', status: 'warn', detail: 'outerWidth / outerHeight 为 0，常见于无窗口容器'});
  }
  return {autoPts: clamp(autoPts), checks};
}

function loadConnectionScript() {
  if (window.IPConnection) return Promise.resolve(window.IPConnection);
  const src = document.body?.dataset?.connection || '/static/connection.js';
  return connModule ||= new Promise((resolve, reject) => {
    const s = Object.assign(document.createElement('script'), {
      src,
      onload: () => window.IPConnection ? resolve(window.IPConnection) : reject(new Error('连接探测模块无效')),
      onerror: () => { connModule = null; reject(new Error('无法加载连接探测模块')); },
    });
    document.head.append(s);
  });
}

const CHECK_TONE = {pass: ['正常', 'good'], info: ['参考', 'info'], warn: ['留意', 'warn'], bot: ['自动化特征', 'bad']};

function renderProbeInline() {
  const box = $('#probeInlineBody');
  const btn = $('#deepProbeBtn');
  if (!box) return;
  const st = activeProbeState;
  if (!st) {
    box.replaceChildren();
    if (btn) btn.textContent = '开始连接与 443 实测';
    return;
  }
  if (btn) btn.textContent = st.running ? '正在实测…' : '重新实测连接与 443';

  const rows = items => h('ul', {class: 'score-detail-list'}, items);
  const panels = [];

  if (st.running) {
    panels.push(h('div', {class: 'probe-panel wide'},
      h('p', {class: 'status', style: {'margin-bottom': '0'}}, spinner(), '正在实测访客出口 443 证书、多目标分流路径与浏览器协议栈特征…')));
  }

  // 1. Exit 443 TLS / Reality Masquerade
  if (st.server?.tls443) {
    const t = st.server.tls443;
    const vTone = t.reality_suspect ? 'bad' : t.port_open ? 'warn' : 'good';
    const vText = t.reality_suspect ? '疑似 Reality 借证伪装'
      : t.verdict === 'closed' ? '443 未开放（常规终端特征）'
      : t.verdict === 'skipped' ? '未执行公网回探'
      : t.tls_active ? '开放 443 / TLS 服务' : '开放 443 非 TLS 端口';
    panels.push(h('div', {class: 'probe-panel'},
      h('h3', null, '访客出口 443 端口与证书核验'),
      kv([
        ['实测出口', mono(st.server.ip)],
        ['核验结论', h('div', {class: 'tags'}, pill(vText, vTone), t.rtt_ms ? h('span', {class: 'mut mono'}, `${t.rtt_ms} ms`) : null)],
        ['TLS 协议', t.tls_version],
        ['证书域名', (t.subject_cn || t.sans?.length) && mono([t.subject_cn, ...(t.sans || [])].filter((x, i, a) => x && a.indexOf(x) === i).slice(0, 5).join(', '))],
        ['签发机构', t.issuer && (t.issuer + (t.self_signed ? '（自签名）' : ''))],
        ['说明', t.detail],
      ])));
  } else if (st.serverError) {
    panels.push(h('div', {class: 'probe-panel'},
      h('h3', null, '访客出口 443 端口与证书核验'),
      empty('未能完成：' + st.serverError)));
  }

  // 2. Live HTTP + Browser Human/Automation Checks
  const reqProbe = st.server?.request_probe || lastRendered?.traffic?.request_probe;
  if (reqProbe) {
    const clientEnv = inspectBrowserClient();
    const combinedAuto = clamp(Math.round(reqProbe.automation_share * 0.65 + clientEnv.autoPts * 0.35));
    const combinedHuman = 100 - combinedAuto;
    const allChecks = [...(reqProbe.checks || []), ...clientEnv.checks];
    panels.push(h('div', {class: 'probe-panel'},
      h('h3', null, '当前访客实时人机特征核验'),
      h('div', {class: 'ratio-wrap'},
        h('div', {class: 'ratio-bar probe-split'},
          h('span', {class: 'seg seg-a', style: {width: combinedHuman + '%'}}),
          h('span', {class: 'seg seg-b', style: {width: combinedAuto + '%'}})),
        h('div', {class: 'ratio-legend mono'},
          h('span', null, `真人终端特征 ${combinedHuman}%`),
          h('span', null, `脚本 / 自动化特征 ${combinedAuto}%`))),
      rows(allChecks.map(c => {
        const [lbl, tone] = CHECK_TONE[c.status] || ['观察', 'neutral'];
        return h('li', null,
          h('div', {class: 'score-detail-row'}, h('b', null, c.name), pill(lbl, tone)),
          h('p', {class: 'mut'}, c.detail));
      }))));
  }

  // 3. Multi-target egress, DNS/EDNS, WebRTC & TCP OS stack
  if (st.conn?.probes?.length) {
    const summarizeProbe = p => {
      if (p.status === 'pending') return '探测中…';
      if (p.status !== 'ok' || !p.data) return p.error || '未返回';
      const d = p.data;
      if (p.id === 'rtc') return d.publicIPs?.length ? '公网候选 ' + d.publicIPs.join(', ') : (d.mdns ? '仅 mDNS 隐藏候选' : '未暴露公网候选');
      if (p.id === 'dns') return [d.ip, d.country, d.org, d.ecs?.subnet ? 'ECS ' + d.ecs.subnet : ''].filter(Boolean).join(' · ');
      if (p.id === 'tcp') return [d.os, d.relay === true ? '疑似中继栈' : d.relay === false ? '原生协议栈' : '', d.mismatch ? '与 UA 系统不一致' : ''].filter(Boolean).join(' · ');
      return [d.ip, d.loc, d.colo ? '节点 ' + d.colo : '', d.warp === 'on' ? 'WARP 开启' : ''].filter(Boolean).join(' · ');
    };
    panels.push(h('div', {class: 'probe-panel wide'},
      h('h3', null, '多目标分流出口、DNS / WebRTC 与协议栈观测'),
      kv(st.conn.probes.map(p => [p.label, h('span', {class: p.status === 'error' ? 'mut' : ''}, summarizeProbe(p))])),
      st.findings?.length ? rows(st.findings.map(fd => h('li', null,
        h('div', {class: 'score-detail-row'}, h('b', null, fd.title), pill(fd.level === 'warn' ? '差异提示' : '观测说明', fd.level === 'warn' ? 'warn' : 'info')),
        h('p', {class: 'mut'}, fd.detail)))) : null));
  } else if (st.connError) {
    panels.push(h('div', {class: 'probe-panel wide'},
      h('h3', null, '多目标分流出口、DNS / WebRTC 与协议栈观测'),
      empty('未能完成：' + st.connError)));
  }

  box.replaceChildren(...panels);
}

async function runInlineProbe() {
  if (activeProbeState?.running) return;
  probeCtl?.abort();
  const c = new AbortController();
  probeCtl = c;
  activeProbeState = {running: true, server: null, conn: null, findings: []};
  renderProbeInline();

  const serverTask = timed(8000, sig => getJSON('/api/probe', sig), c.signal)
    .then(data => { if (probeCtl === c) { activeProbeState.server = data; renderProbeInline(); } })
    .catch(e => { if (probeCtl === c && e.name !== 'AbortError') { activeProbeState.serverError = errText(e); renderProbeInline(); } });

  const connTask = loadConnectionScript()
    .then(mod => mod.collect({
      signal: c.signal,
      onUpdate: snap => {
        if (probeCtl !== c) return;
        activeProbeState.conn = snap;
        activeProbeState.findings = mod.analyze(snap, lastRendered);
        renderProbeInline();
      },
    }))
    .catch(e => { if (probeCtl === c && e.name !== 'AbortError') { activeProbeState.connError = errText(e); renderProbeInline(); } });

  await Promise.allSettled([serverTask, connTask]);
  if (probeCtl !== c) return;
  activeProbeState.running = false;
  renderProbeInline();
}

function setStatus(cls, ...kids) { statusEl.className = 'status' + (cls ? ' ' + cls : ''); statusEl.replaceChildren(...kids); }

function render(r, pending = false, failed = false) {
  lastRendered = r;
  const parts = [verdictCard(r, pending, failed)];
  if (r.mode && !r.bogon) {
    const busy = pending && !failed;
    parts.push(riskAndBlacklistRow(r, busy));
    parts.push(buildScenarioCard(r, busy));
    const geo = geoCard(r.geo || {}), network = netCard(r.network || {});
    geo.classList.add('geo-card'); network.classList.add('net-card'); network.id = 'network';
    parts.push(h('div', {id: 'infraGrid', class: 'grid2'}, h('div', {class: 'col'}, geo, mapCard(r.geo || {})), network));
    parts.push(...buildWorkbenchSection(r, busy));
  } else dropMap();
  out.replaceChildren(...parts);
  out.classList.remove('stale');
  if (activeProbeState) renderProbeInline();
  mountMap();
}

async function lookup(ip, initialIP = '') {
  clearScoreDetails();
  clearActiveProbe();
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
  fastReq.catch(() => {});
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
