'use strict';
const $ = s => document.querySelector(s);
const bootIP = $('#ipAddress')?.textContent || '';
const out = $('#out'), statusEl = $('#status'), form = $('#q'), input = $('#qi'), qerr = $('#qerr');
const scoreDialog = $('#scoreDetails'), scoreDetailsBody = $('#scoreDetailsBody');
const probeDialog = $('#probeDetails'), probeDetailsBody = $('#probeDetailsBody');
const riskTab = $('#riskTab');
let scoreDetailsOpener = null, probeDetailsOpener = null;

function siblingWhoHref(host) {
  host = String(host || '').trim().toLowerCase().replace(/:\d+$/, '').replace(/\.$/, '');
  return /^ip\.[a-z0-9-]+(\.[a-z0-9-]+)+$/.test(host) && !/^ip\.(\d+\.){3}\d+$/.test(host) ? `https://who.${host.slice(3)}/` : '';
}
const derivedWhoHref = siblingWhoHref(location.hostname);
if (riskTab && derivedWhoHref) riskTab.href = derivedWhoHref;

const TYPE_TONE = {
  residential: 'good', mobile: 'good', education: 'info', business: 'info',
  government: 'info', cdn: 'info', hosting: 'warn', unknown: 'neutral',
};
const USAGE_TONE = {
  tor: 'bad', vpn: 'bad', proxy: 'bad', abuser: 'bad', abuse: 'bad',
  leased: 'warn', crawler: 'warn', icloud_relay: 'info', public_service: 'info',
  anycast: 'info', satellite: 'info',
};
const VERDICT_BORDER_VAR = {
  residential: 'var(--c-good)', mobile: 'var(--c-good)', hosting: 'var(--c-fair)',
  cdn: 'var(--acc)', business: 'var(--acc)', education: 'var(--acc)', government: 'var(--acc)',
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
  if (/^\/[0-9A-Za-z.:]*$/.test(v)) return v;
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

// Tier 1: Top Summary Card (Identity + Purity Score Ring)
function verdictCard(r, pending, failed = false) {
  const v = r.verdict || {}, conf = CONF[v.confidence], borderColor = VERDICT_BORDER_VAR[v.type], n = r.network || {};
  const typeTone = TYPE_TONE[v.type] || 'neutral';
  const identity = h('div', {class: 'summary-identity'}, ipHead(r),
    h('p', {class: 'v-label'}, r.bogon ? '私网或保留地址' : v.label || v.type_label || (pending && !failed ? '识别中…' : '未知')),
    r.bogon ? h('p', null, r.bogon) : null);
  const body = h('div', {class: 'summary-body'},
    kv([
      ['ASN', n.asn && [ext('https://bgp.tools/as/' + n.asn, 'AS' + n.asn), n.as_name ? ' – ' + n.as_name : '']],
      ['AS 域名', n.as_domain],
      ['IP 范围', mono(n.net_range || n.bgp_prefix || n.prefix)],
      ['位置', places(r)],
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
  return h('section', {id: 'result', 'aria-busy': String(Boolean(pending && !failed && !r.bogon)),
    class: borderColor ? 'card verdict hue' : 'card verdict', style: borderColor ? {'--verdict-c': borderColor} : null},
    identity, scoreBox(r, r.bogon ? 'bogon' : failed ? 'error' : pending ? 'pending' : ''), body);
}

const PLACE_SRC = ['Merged-IP', 'ip2region', 'DB-IP City Lite', 'IP2Location.io', 'ipinfo.io', 'ip-api.com'];
function places(r) {
  const list = r.geo_sources || [], cn = (r.geo?.country_code || '').toUpperCase() === 'CN';
  const rows = PLACE_SRC.filter(n => cn || n !== 'ip2region').map(n => list.find(s => s.source === n))
    .filter(s => s && has([s.country, s.country_code]));
  return rows.length ? h('div', {class: 'locs'}, rows.map(s => h('div', null, h('span', {class: 'mut'}, s.source),
    h('span', null, [countryOf(s), s.region, s.city !== s.region && s.city].filter(has).join(', '))))) : null;
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
  const coverageText = coverage && Number.isInteger(coverage.received) && Number.isInteger(coverage.total)
    && coverage.received >= 0 && coverage.total > 0 && coverage.received <= coverage.total
    ? ` · ${coverage.received}/${coverage.total} 信誉源` : '';
  const quality = {complete: '数据较充分', limited: '数据有限', unavailable: '数据不足'}[s.data_status];
  return h('div', {id: 'score', class: 'score', 'aria-live': 'polite'},
    h('div', {class: unknown ? 'ring wait' : 'ring', 'data-tone': unknown ? null : tier.tone,
      style: {'--v': v}, role: 'img',
      'aria-label': unknown ? level : `纯净度 ${v} 分，${level}`},
      h('b', {id: 'scoreValue'}, unknown ? '—' : String(v)), h('span', {id: 'scoreLevel'}, level)),
    h('span', {class: 'mut'}, '纯净度 ', h('span', {id: 'scoreTotal', hidden: state === 'bogon'}, '/100')),
    !state && quality ? h('span', {class: 'score-data mut', title: '只统计实际返回安全字段或风险读数的信誉源；数据返回不代表安全保证。'}, quality + coverageText) : null,
    h('button', {id: 'scoreDetailsToggle', type: 'button', class: 'btn score-details-toggle', disabled: state === 'pending' || !r.mode,
      'aria-haspopup': 'dialog', 'aria-controls': 'scoreDetails', onclick: e => showScoreDetails(r, e.currentTarget)}, '评分详情'));
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

// Tier 2: Symmetrical 2-Column Insight Row (Left: Traffic & Scenarios, Right: Risk & Security Checks)
function buildFallbackScenarios(r) {
  if (Array.isArray(r.audit?.scenarios) && r.audit.scenarios.length) return r.audit.scenarios;
  if (r.mode !== 'full' || r.score?.data_status === 'unavailable' || r.bogon) return [];
  const f = r.flags || {}, v = r.verdict || {}, isHost = Boolean(f.is_hosting || f.is_cdn || v.type === 'hosting' || v.type === 'cdn');
  const isBroad = r.native?.status === 'broadcast';
  const mk = (id, name, raw, detail) => {
    const s = Math.max(1, Math.min(10, raw));
    const tone = s >= 8 ? 'good' : s >= 6 ? 'warn' : s >= 4 ? 'poor' : 'bad';
    const status = s >= 8 ? '优质可用' : s >= 6 ? (id === 'ai' ? '可以尝试' : '可用') : s >= 4 ? '易受限' : '高风控';
    return {id, name, score: s, max: 10, status, tone, detail};
  };
  const penalty = (f.is_tor ? 5 : f.is_proxy || f.is_vpn ? 3 : 0) + (f.is_abuser ? 3 : 0) + (isBroad ? 1 : 0);
  return [
    mk('tiktok', 'TikTok', (isHost ? 6 : 9) - penalty, '基于网络属性、原生性与信誉信号评估'),
    mk('social', '社媒运营', (isHost ? 6 : 9) - penalty, '基于住宅/机房属性与垃圾滥用记录评估'),
    mk('ai', 'AI 应用', (isHost ? 7 : 9) - penalty, '基于定位地区、机房标记与风控信号评估'),
    mk('shield', '免盾浏览', (isHost ? 7 : 9) - penalty, '基于黑名单命中与人机流量倾向评估'),
  ];
}

function insightRow(r, pending) {
  const tr = r.traffic || {}, f = r.flags || {}, a = r.audit || {}, n = r.network || {};
  const act = a.activity || {};
  const hasRatio = tr.mode === 'radar' || tr.mode === 'estimated';

  // Left Card: Human/Bot Traffic Ratio + 2x2 Scenarios
  let trafficBlock;
  if (hasRatio) {
    const hp = clamp(tr.human_pct), bp = clamp(tr.bot_pct);
    const tier = trafficTier(hp, tr.tone, tr.level);
    const srcText = tr.mode === 'radar' ? `Cloudflare Radar · 近 ${tr.window || '7d'} 实测` : '多源行为与网段特征推算';
    const hasDev = typeof tr.desktop_pct === 'number' && typeof tr.mobile_pct === 'number';
    const sigs = Array.isArray(tr.bot_signals) ? tr.bot_signals.slice(0, 3) : [];
    trafficBlock = h('div', {class: 'hb-block'},
      h('div', {class: 'hb-top'},
        pill(tier.level, tier.tone),
        h('span', {class: 'hb-src'}, srcText)),
      h('div', {class: 'hb-bar', role: 'img', 'aria-label': `人类 ${fmtPct(hp)}，机器 ${fmtPct(bp)}`},
        hp > 0 ? h('span', {class: 'seg-h', style: {width: hp + '%'}}) : null,
        bp > 0 ? h('span', {class: 'seg-b', style: {width: bp + '%'}}) : null),
      h('div', {class: 'hb-foot mono'},
        h('span', {class: 'h-txt'}, '人类 ' + fmtPct(hp)),
        h('span', {class: 'b-txt'}, '机器 ' + fmtPct(bp))),
      hasDev ? h('div', {class: 'hb-dev'},
        h('div', {class: 'hb-bar dev', role: 'img', 'aria-label': `桌面端 ${fmtPct(tr.desktop_pct)}，移动端 ${fmtPct(tr.mobile_pct)}`},
          h('span', {class: 'seg-h', style: {width: clamp(tr.desktop_pct) + '%'}}),
          h('span', {class: 'seg-b', style: {width: clamp(tr.mobile_pct) + '%'}})),
        h('div', {class: 'hb-dev-row mono'},
          h('span', null, '桌面端 ' + fmtPct(tr.desktop_pct)),
          h('span', null, '移动端 ' + fmtPct(tr.mobile_pct)))) : null,
      sigs.length ? h('ul', {class: 'hb-signals'}, sigs.map(s => h('li', null, s))) : null);
  } else {
    trafficBlock = h('div', {class: 'hb-block'},
      empty(pending ? '正在计算人机流量比例分布…' : (tr.note || '当前缺少足够的自治系统与信誉数据，暂无法估算人机比例')));
  }

  const scenarios = buildFallbackScenarios(r);
  const scenarioSection = scenarios.length ? [
    h('h3', null, '场景可用性参考'),
    h('div', {class: 'scenario-grid'}, scenarios.map(sc =>
      h('div', {class: 'sc-item', title: sc.detail || ''},
        h('div', {class: 'sc-gauge', 'data-tone': sc.tone, style: {'--pts': sc.score}}, String(sc.score)),
        h('div', {class: 'sc-meta'},
          h('b', null, sc.name),
          h('span', {class: 'tone-' + sc.tone}, sc.status))))),
  ] : (pending ? [h('h3', null, '场景可用性参考'), empty('等待完整检测结果…')] : null);

  const leftCard = h('section', {id: 'trafficCard', class: 'card'},
    h('div', {class: 'card-head'}, h('h2', null, '人机流量与场景参考')),
    trafficBlock,
    scenarioSection);

  // Right Card: Quiet-Baseline Risk & Security Verification
  const torHit = Boolean(f.is_tor || act.tor_exit || act.tor_relay);
  const leaseHit = Boolean(f.is_leased || a.lease?.leased);
  const masqHit = Boolean(a.flow?.masquerade);

  const checkCell = (name, hit, hitText, severity = 'bad', tip = '') => {
    if (pending) {
      return h('div', {class: 'check-cell'}, h('span', {class: 'check-name'}, name), h('span', {class: 'mut'}, '…'));
    }
    return h('div', {class: hit ? 'check-cell hit-' + severity : 'check-cell', title: tip || null},
      h('span', {class: 'check-name'}, name),
      hit ? dot(hitText, severity) : dot('未检测到', 'ok'));
  };

  const checkGrid = h('div', {class: 'check-grid'},
    checkCell('VPN', Boolean(f.is_vpn), '检测到', 'bad'),
    checkCell('代理 (Proxy)', Boolean(f.is_proxy), '检测到', 'bad'),
    checkCell('Tor 节点', torHit, f.is_tor || act.tor_exit ? '出口节点' : '中继节点', 'bad'),
    checkCell('爬虫 / 机器人', Boolean(f.is_crawler), '检测到', 'warn'),
    checkCell('商业地址租赁', leaseHit, a.lease?.broker || '租赁段', 'warn', a.lease?.detail || ''),
    checkCell('家宽流量核验', masqHit, '疑似伪家宽', 'bad', a.flow?.detail || ''));

  const dnsblTotal = (r.dnsbl || []).length;
  const dnsblHits = (r.dnsbl || []).filter(d => d.listed).length;
  const threatParts = [];
  if (dnsblHits > 0) threatParts.push(`DNSBL ${dnsblHits}/${dnsblTotal}`);
  if (act.spam_reports > 0) threatParts.push(`垃圾注册 ${act.spam_reports} 次`);
  if (act.dshield_packets > 0) threatParts.push(`DShield ${act.dshield_packets} 包`);
  if (act.otx_pulses > 0) threatParts.push(`OTX ${act.otx_pulses} 脉冲`);

  const blacklistVal = pending ? h('span', {class: 'mut'}, '检测中…')
    : threatParts.length ? pill(threatParts.join(' · '), dnsblHits >= 2 || act.spam_reports >= 5 ? 'bad' : 'warn')
    : dot(dnsblTotal > 0 ? `纯净（0/${dnsblTotal} DNSBL）` : '纯净（未见威胁记录）', 'ok');

  const nb = a.neighbor;
  const nbVal = !nb ? h('span', {class: 'mut'}, '离线库未就绪')
    : nb.flagged === 0 ? dot(`纯净网段（${nb.prefix}）`, 'ok')
    : pill(`${nb.level} · ${nb.total ? nb.flagged + '/' + nb.total : nb.flagged + ' 块'}`,
      nb.level === '高危脏段' ? 'bad' : 'warn', nb.prefix);

  const rpkiRaw = String(n.rpki || '');
  const rpkiVal = !rpkiRaw ? (r.mode === 'full' ? h('span', {class: 'mut'}, '未知') : h('span', {class: 'mut'}, '待查询'))
    : rpkiRaw === '有效' || (/valid/i.test(rpkiRaw) && !/invalid/i.test(rpkiRaw)) ? dot('Valid（有效）', 'ok')
    : /无效|invalid/i.test(rpkiRaw) ? pill('Invalid（' + rpkiRaw + '）', 'bad')
    : dot(rpkiRaw, 'info');

  const openPorts = r.ports?.ports || [];
  const portVal = openPorts.length
    ? [mono(openPorts.slice(0, 6).join(', ') + (openPorts.length > 6 ? ` 等 ${openPorts.length} 个` : '')),
      r.ports?.vulns?.length ? pill(`漏洞 ${r.ports.vulns.length}`, 'bad') : null]
    : (r.mode === 'full' ? dot('未见公开暴露端口', 'ok') : null);

  // Compact live visitor probe summary when server attached request_probe (self IP)
  let reqSummary = null;
  if (tr.request_probe) {
    const clientEnv = inspectBrowserClient();
    const combinedAuto = clamp(Math.round(tr.request_probe.automation_share * 0.65 + clientEnv.autoPts * 0.35));
    const combinedHuman = 100 - combinedAuto;
    reqSummary = combinedAuto >= 45
      ? pill(`自动化倾向 ${combinedAuto}%（${tr.request_probe.client_family || '客户端'}）`, 'warn')
      : dot(`真人终端特征 ${combinedHuman}%（${tr.request_probe.client_family || '浏览器'}）`, 'ok');
  }

  const cleanRow = (k, v) => has(v) ? h('div', {class: 'clean-row'}, h('span', {class: 'clean-k'}, k), h('div', {class: 'clean-v'}, v)) : null;

  const rightCard = h('section', {id: 'securityCard', class: 'card'},
    h('div', {class: 'card-head'},
      h('h2', null, '风险与技术核验'),
      h('button', {
        id: 'deepProbeBtn',
        type: 'button',
        class: 'btn probe-trigger',
        disabled: pending,
        'aria-haspopup': 'dialog',
        'aria-controls': 'probeDetails',
        onclick: e => openProbeDialog(e.currentTarget),
      }, '连接与 443 实测')),
    checkGrid,
    h('div', {class: 'clean-rows'},
      cleanRow('蜜罐 / 黑名单', blacklistVal),
      cleanRow('同段邻居 (/24)', nbVal),
      cleanRow('RPKI 路由签名', rpkiVal),
      cleanRow('公开暴露端口', portVal),
      cleanRow('当前访客特征', reqSummary)));

  return h('div', {id: 'insightGrid', class: 'grid2'}, leftCard, rightCard);
}

// Score Details Modal
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

// Active Probe & Visitor Human/Bot Inspection Modal (#probeDetails)
let seq = 0, ctl = null, probeCtl = null, connModule = null, lastRendered = null, activeProbeState = null;

function clearActiveProbe() {
  probeCtl?.abort();
  probeCtl = null;
  activeProbeState = null;
  probeDetailsOpener = null;
  if (probeDialog?.open) probeDialog.close();
  probeDetailsBody?.replaceChildren();
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

function renderProbeDialogBody() {
  if (!probeDetailsBody) return;
  const st = activeProbeState || {};
  const section = (title, ...children) => h('section', {class: 'score-detail-section'}, h('h3', null, title), children);
  const rows = items => h('ul', {class: 'score-detail-list'}, items);
  const parts = [];

  if (st.running) {
    parts.push(h('p', {class: 'status'}, spinner(), '正在实测当前连接出口、HTTP 握手与 443 证书特征…'));
  }

  // 1. Exit 443 TLS / Reality Masquerade
  if (st.server?.tls443) {
    const t = st.server.tls443;
    const vTone = t.reality_suspect ? 'bad' : t.port_open ? 'warn' : 'good';
    const vText = t.reality_suspect ? '疑似 Reality 借证伪装'
      : t.verdict === 'closed' ? '443 未开放（常规终端特征）'
      : t.verdict === 'skipped' ? '未执行公网回探'
      : t.tls_active ? '开放 443 / TLS 服务' : '开放 443 非 TLS 端口';
    parts.push(section('访客出口 443 端口与证书核验', kv([
      ['实测出口', mono(st.server.ip)],
      ['核验结论', h('div', {class: 'tags'}, pill(vText, vTone), t.rtt_ms ? h('span', {class: 'mut mono'}, `${t.rtt_ms} ms`) : null)],
      ['TLS 协议', t.tls_version],
      ['证书域名', (t.subject_cn || t.sans?.length) && mono([t.subject_cn, ...(t.sans || [])].filter((x, i, a) => x && a.indexOf(x) === i).slice(0, 5).join(', '))],
      ['签发机构', t.issuer && (t.issuer + (t.self_signed ? '（自签名）' : ''))],
      ['说明', t.detail],
    ])));
  } else if (st.serverError) {
    parts.push(section('访客出口 443 端口与证书核验', empty('未能完成：' + st.serverError)));
  }

  // 2. Live HTTP + Browser Human/Automation Checks
  const reqProbe = st.server?.request_probe || lastRendered?.traffic?.request_probe;
  if (reqProbe) {
    const clientEnv = inspectBrowserClient();
    const combinedAuto = clamp(Math.round(reqProbe.automation_share * 0.65 + clientEnv.autoPts * 0.35));
    const combinedHuman = 100 - combinedAuto;
    const allChecks = [...(reqProbe.checks || []), ...clientEnv.checks];
    parts.push(section('当前访客实时人机特征明细',
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
    parts.push(section('多目标出口、DNS / WebRTC 与协议栈观测',
      kv(st.conn.probes.map(p => [p.label, h('span', {class: p.status === 'error' ? 'mut' : ''}, summarizeProbe(p))])),
      st.findings?.length ? rows(st.findings.map(fd => h('li', null,
        h('div', {class: 'score-detail-row'}, h('b', null, fd.title), pill(fd.level === 'warn' ? '差异提示' : '观测说明', fd.level === 'warn' ? 'warn' : 'info')),
        h('p', {class: 'mut'}, fd.detail)))) : null));
  } else if (st.connError) {
    parts.push(section('多目标出口、DNS / WebRTC 与协议栈观测', empty('未能完成：' + st.connError)));
  }

  probeDetailsBody.replaceChildren(...parts);
}

async function openProbeDialog(opener) {
  probeDetailsOpener = opener;
  if (!probeDialog.open) probeDialog.showModal();
  if (activeProbeState?.running) return;
  probeCtl?.abort();
  const c = new AbortController();
  probeCtl = c;
  activeProbeState = {running: true, server: null, conn: null, findings: []};
  renderProbeDialogBody();

  const serverTask = timed(8000, sig => getJSON('/api/probe', sig), c.signal)
    .then(data => { if (probeCtl === c) { activeProbeState.server = data; renderProbeDialogBody(); } })
    .catch(e => { if (probeCtl === c && e.name !== 'AbortError') { activeProbeState.serverError = errText(e); renderProbeDialogBody(); } });

  const connTask = loadConnectionScript()
    .then(mod => mod.collect({
      signal: c.signal,
      onUpdate: snap => {
        if (probeCtl !== c) return;
        activeProbeState.conn = snap;
        activeProbeState.findings = mod.analyze(snap, lastRendered);
        renderProbeDialogBody();
      },
    }))
    .catch(e => { if (probeCtl === c && e.name !== 'AbortError') { activeProbeState.connError = errText(e); renderProbeDialogBody(); } });

  await Promise.allSettled([serverTask, connTask]);
  if (probeCtl !== c) return;
  activeProbeState.running = false;
  renderProbeDialogBody();
}
$('#probeDetailsClose')?.addEventListener('click', () => probeDialog.close());
probeDialog?.addEventListener('close', () => { if (probeDetailsOpener?.isConnected) probeDetailsOpener.focus(); });

// Tier 3: Geography + Map (Left) & Consolidated Network / ASN Profile (Right)
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
    const at = [v.lat, v.lon], color = getComputedStyle(v.box).getPropertyValue('--acc').trim() || '#0a6e8a';
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
  const scaleNode = v4Total ? [
    mono(v4Total),
    (n.as_prefixes_v4 || n.as_prefixes_v6) ? h('span', {class: 'mut'}, `（v4 前缀 ${n.as_prefixes_v4 || 0}${n.as_prefixes_v6 ? ' · v6 前缀 ' + n.as_prefixes_v6 : ''}）`) : null,
  ] : null;
  const bandwidthNode = (p.info_traffic || p.info_ratio)
    ? [p.info_traffic, p.info_traffic && p.info_ratio ? ' · ' : '', p.info_ratio].filter(Boolean).join('')
    : null;
  const entity = n.registrant && n.registrant !== n.org ? `${n.registrant}${n.org ? ' / ' + n.org : ''}` : (n.org || n.registrant);

  return card('网络', kv([
    ['ASN', n.asn && h('div', {class: 'tags'},
      ext('https://bgp.tools/as/' + n.asn, mono('AS' + n.asn)),
      h('button', {type: 'button', class: 'btn sm', onclick: e => copy('AS' + n.asn, e.currentTarget, '复制 ASN')}, '复制 ASN'))],
    ['AS 名称', n.as_name],
    ['AS 类型', n.as_type_label || p.info_type || n.as_class],
    ['IPv4 地址量', scaleNode],
    ['预估带宽', bandwidthNode],
    ['AS 注册日期', mono(n.as_created)],
    ['企业 / 主体', entity],
    ['ISP', n.isp && n.isp !== n.as_name ? n.isp : null],
    ['BGP 前缀', mono(n.bgp_prefix || n.prefix)],
    ['网络名称', n.net_name],
    ['注册机构', [n.registry && n.registry.toUpperCase(), n.allocated].filter(Boolean).join(' · ')],
    ['反向解析', n.rdns?.length && h('div', {class: 'tags'},
      n.rdns.map(d => mono(d)),
      n.fcrdns === true ? dot('FCrDNS 通过', 'ok') : n.fcrdns === false ? dot('FCrDNS 未过', 'warn') : null)],
    ['路由可见度', n.visibility],
    ['滥用评分', mono(n.abuser_score)],
    ['滥用联系', n.abuse],
    ['AS 标签', tags(n.as_tags)],
    ['互联设施', (p.ix_count || p.fac_count || p.policy) && [
      p.policy ? `政策 ${p.policy}` : '',
      p.ix_count ? `IX ${p.ix_count}` : '',
      p.fac_count ? `机房 ${p.fac_count}` : '',
    ].filter(Boolean).join(' · ')],
    ['同 IP 域名', n.domains?.length && h('div', {class: 'vlist'}, tags(n.domains))],
  ]) || empty('没有网络信息'));
}

function setStatus(cls, ...kids) { statusEl.className = 'status' + (cls ? ' ' + cls : ''); statusEl.replaceChildren(...kids); }

function render(r, pending = false, failed = false) {
  lastRendered = r;
  const parts = [verdictCard(r, pending, failed)];
  if (r.mode && !r.bogon) {
    parts.push(insightRow(r, pending && !failed));
    const geo = geoCard(r.geo || {}), network = netCard(r.network || {});
    geo.classList.add('geo-card'); network.classList.add('net-card'); network.id = 'network';
    parts.push(h('div', {class: 'grid2'}, h('div', {class: 'col'}, geo, mapCard(r.geo || {})), network));
  } else dropMap();
  out.replaceChildren(...parts);
  out.classList.remove('stale');
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
