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

// Type & usage semantic tones so labels and colors always match their risk/health meaning.
const TYPE_TONE = {
  residential: 'good', mobile: 'good', education: 'info', business: 'info',
  government: 'info', cdn: 'info', hosting: 'warn', unknown: 'neutral',
};
const USAGE_TONE = {
  tor: 'bad', vpn: 'bad', proxy: 'bad', abuser: 'bad', abuse: 'bad',
  leased: 'warn', crawler: 'warn', icloud_relay: 'info', public_service: 'info',
  anycast: 'info', satellite: 'info',
};
const TYPE_EN = {
  residential: 'ISP（家庭宽带）', mobile: 'Cellular（移动蜂窝）', hosting: 'Hosting（机房托管）',
  cdn: 'CDN（边缘网络）', business: 'Business（企业专线）', education: 'Education（教育科研）',
  government: 'Government（政府网络）', unknown: 'Unknown（未知类型）',
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

// Strict alignment between score value, text level, and semantic color tier:
// >=90 极度纯净(深翠绿), 78-89 纯净(健康绿), 55-77 一般(琥珀橙黄), 30-54 风险偏高(深橙红), <30 可疑(警示红).
function scoreTier(v, explicitTone, explicitLevel) {
  const n = clamp(v);
  const derived = n >= 90 ? ['极度纯净', 'excellent']
    : n >= 78 ? ['纯净', 'good']
    : n >= 55 ? ['一般', 'fair']
    : n >= 30 ? ['风险偏高', 'poor']
    : ['可疑', 'bad'];
  const validTones = new Set(['excellent', 'good', 'fair', 'poor', 'bad']);
  const tone = validTones.has(explicitTone) ? explicitTone : derived[1];
  // Never pair a legacy "良好"/"中性" label with a medium/low score; keep label & color consistent.
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

const neighborTone = level => ({'纯净网段': 'good', '轻度连带': 'warn', '中度污染': 'poor', '高危脏段': 'bad'}[level] || 'neutral');

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
const metricRows = rows => {
  rows = rows.filter(r => r && has(r[1]));
  return rows.length ? h('div', {class: 'metric-list'}, rows.map(([k, v, stack]) =>
    h('div', {class: 'metric-row'}, h('span', {class: 'metric-k'}, k), h('div', {class: stack ? 'metric-v stack' : 'metric-v'}, v)))) : null;
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

function ratioBar(leftPct, rightPct, leftLabel, rightLabel, kind = 'human-bot') {
  const lp = clamp(leftPct), rp = clamp(rightPct);
  const total = lp + rp || 100;
  const lw = Math.round((lp / total) * 1000) / 10;
  const rw = Math.max(0, Math.round((100 - lw) * 10) / 10);
  return h('div', {class: 'ratio-wrap'},
    h('div', {class: 'ratio-bar ' + kind, role: 'img', 'aria-label': `${leftLabel} ${fmtPct(lp)}，${rightLabel} ${fmtPct(rp)}`},
      lw > 0 ? h('span', {class: 'seg seg-a', style: {width: lw + '%'}}) : null,
      rw > 0 ? h('span', {class: 'seg seg-b', style: {width: rw + '%'}}) : null),
    h('div', {class: 'ratio-legend'},
      h('span', {class: 'leg-a'}, h('i'), `${leftLabel} `, h('b', {class: 'mono'}, fmtPct(lp))),
      h('span', {class: 'leg-b'}, h('i'), `${rightLabel} `, h('b', {class: 'mono'}, fmtPct(rp)))));
}

function inlineHumanBot(tr) {
  if (!tr || (tr.mode !== 'radar' && tr.mode !== 'estimated')) return null;
  const hp = clamp(tr.human_pct), bp = clamp(tr.bot_pct);
  const tier = trafficTier(hp, tr.tone, tr.level);
  const srcLabel = tr.mode === 'radar' ? 'Cloudflare Radar 7d' : '多源信号评估';
  return h('div', {class: 'hb-inline'},
    h('div', {class: 'hb-meter'},
      h('div', {class: 'hb-bar', role: 'img', 'aria-label': `人类 ${fmtPct(hp)}，机器 ${fmtPct(bp)}`},
        hp > 0 ? h('span', {class: 'seg-h', style: {width: hp + '%'}}) : null,
        bp > 0 ? h('span', {class: 'seg-b', style: {width: bp + '%'}}) : null),
      h('div', {class: 'hb-nums mono'},
        h('span', {class: 'h-txt'}, '人类 ' + fmtPct(hp)),
        h('span', {class: 'b-txt'}, '机器 ' + fmtPct(bp)))),
    pill(tier.level, tier.tone),
    tag(srcLabel));
}

const VERDICT_BORDER_VAR = {
  residential: 'var(--c-good)', mobile: 'var(--c-good)', hosting: 'var(--c-fair)',
  cdn: 'var(--acc)', business: 'var(--acc)', education: 'var(--acc)', government: 'var(--acc)',
};

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
  const auditRows = [];
  if (r.traffic && (r.traffic.mode === 'radar' || r.traffic.mode === 'estimated')) {
    auditRows.push(['人机流量分布', `人类 ${fmtPct(r.traffic.human_pct)} / 机器 ${fmtPct(r.traffic.bot_pct)}（${r.traffic.source || r.traffic.mode}）`]);
  }
  if (r.audit?.neighbor) {
    const nb = r.audit.neighbor;
    auditRows.push(['同段邻居信誉', nb.total ? `${nb.prefix} 内 ${nb.flagged}/${nb.total} (${fmtPct(nb.density_pct)}) · ${nb.level}` : `${nb.prefix} · ${nb.level}`]);
  }
  if (r.audit?.lease) {
    auditRows.push(['地址租赁核验', r.audit.lease.leased ? `${r.audit.lease.broker} 商业租赁网段` : '未见商业租赁商标记']);
  }
  if (r.audit?.flow?.detail) {
    auditRows.push(['流量方向审计', r.audit.flow.detail]);
  }
  scoreDetailsBody.replaceChildren(info,
    section('扣分明细', h('p', {class: 'mut'}, '从 100 分开始扣减，结果限制在 0–100；未知或未完成的检测不显示虚构分数。'), factorList),
    section('第三方风险数据', h('p', {class: 'mut'}, '风险值标准化到 0–100，越高表示风险越高。原始读数和实际计分值分别保留；信任分按相反方向归一化。'), formula, riskList),
    auditRows.length ? section('深度审计与流量信号', kv(auditRows)) : null,
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
  const tone = n.status === 'native' ? 'good' : n.status === 'broadcast' ? 'warn' : 'neutral';
  return h('div', {class: 'tags'},
    pill(n.label || '未知', tone),
    reg || geo ? h('span', {class: 'cmp'},
      h('span', null, '注册国 ', h('b', {class: diff}, ccName(reg) || '未知')),
      h('span', null, '定位国 ', h('b', {class: diff}, ccName(geo) || '未知'))) : null,
    n.registry ? h('span', {class: 'mut'}, n.registry) : null,
    n.status === 'unknown' && n.detail ? h('span', {class: 'mut'}, n.detail) : null);
}

// Compute fallback client-side scenarios when synthetic/fast fixtures omit audit.scenarios.
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

// Row 1: Usage Scenarios / Type + ASN / Operator (modelled on industrial IP cards)
function usageAndASNRow(r, pending) {
  const v = r.verdict || {}, f = r.flags || {}, n = r.network || {}, g = r.geo || {}, nat = r.native || {};
  const typeTone = TYPE_TONE[v.type] || 'neutral';
  const natTone = nat.status === 'native' ? 'good' : nat.status === 'broadcast' ? 'warn' : 'neutral';
  const countryDisplay = g.country_code ? `${g.flag || flag(g.country_code)} ${zhName(g.country_code.toUpperCase())}` : g.country || '';

  const badgeItems = [];
  if (v.type_label) badgeItems.push(pill(v.type_label + (v.type === 'hosting' ? ' IP' : ''), typeTone));
  for (let i = 0; i < (v.usage_labels || []).length; i++) {
    badgeItems.push(pill(v.usage_labels[i], USAGE_TONE[v.usage?.[i]] || 'bad'));
  }
  if (f.is_anycast && !(v.usage || []).includes('anycast')) badgeItems.push(pill('Anycast 任播', 'info'));

  const scenarios = buildFallbackScenarios(r);
  const scenarioNode = scenarios.length ? h('div', {class: 'scenario-list'}, scenarios.map(sc =>
    h('div', {class: 'sc-item', title: sc.detail || ''},
      h('div', {class: 'sc-gauge', 'data-tone': sc.tone, style: {'--pts': sc.score}}, String(sc.score)),
      h('div', {class: 'sc-meta'},
        h('b', null, sc.name),
        h('span', {class: 'tone-' + sc.tone}, sc.status))))) : (pending ? h('span', {class: 'mut'}, '评估中…') : null);

  const leftCard = card('使用场景 / 类型', metricRows([
    ['IP 原生性', has([countryDisplay, nat.label]) && [
      countryDisplay ? h('span', null, countryDisplay) : null,
      nat.label ? pill(nat.label, natTone, nat.detail || '') : null,
    ]],
    ['类型标记', badgeItems.length ? badgeItems : (pending ? h('span', {class: 'mut'}, '识别中…') : pill('未知', 'neutral'))],
    ['运营商类型', v.type && TYPE_EN[v.type] ? TYPE_EN[v.type] : n.usage_type],
    ['人机流量', r.traffic && (r.traffic.mode === 'radar' || r.traffic.mode === 'estimated')
      ? inlineHumanBot(r.traffic)
      : (pending ? h('span', {class: 'mut'}, '计算中…') : h('span', {class: 'mut'}, r.traffic?.note || '数据不足，暂未评估'))],
    ['场景评估', scenarioNode],
    ['服务商', n.isp || n.as_name || n.org],
  ]));

  const p = n.peeringdb || {};
  const asnType = n.as_type_label || (p.info_type ? p.info_type : n.as_class) || (v.type ? TYPE_EN[v.type] : '');
  const v4Total = fmtInt(n.as_ipv4_count);
  const pfxHint = (n.as_prefixes_v4 || n.as_prefixes_v6)
    ? h('span', {class: 'mut', style: {'font-size': '12px', 'font-weight': '400'}},
      `（v4 前缀 ${n.as_prefixes_v4 || 0}${n.as_prefixes_v6 ? ' · v6 前缀 ' + n.as_prefixes_v6 : ''}）`)
    : null;

  const rightCard = card('ASN / 运营商', metricRows([
    ['ASN', n.asn ? [
      ext('https://bgp.tools/as/' + n.asn, h('span', {class: 'mono'}, 'AS' + n.asn)),
      h('button', {type: 'button', class: 'btn sm', onclick: e => copy('AS' + n.asn, e.currentTarget, '复制 ASN')}, '复制 ASN'),
    ] : '未识别'],
    ['ASN 归属', n.as_name || n.org || n.isp],
    ['ASN 自报类型', asnType],
    ['ASN IPv4 总量', v4Total ? [h('span', {class: 'mono'}, v4Total), pfxHint] : (r.mode === 'full' ? h('span', {class: 'mut'}, '未公开统计') : null)],
    ['预估带宽', p.info_traffic || (p.info_ratio ? p.info_ratio : (r.mode === 'full' ? h('span', {class: 'mut'}, '未公开披露') : null))],
    ['ASN 注册日期', mono(n.as_created || n.allocated)],
    ['企业 / 注册主体', n.registrant || n.org || n.net_name],
  ]));

  return h('div', {id: 'profileGrid', class: 'grid2'}, leftCard, rightCard);
}

// Row 2: 3-column Technical Indicators + Threat Intelligence + Deep Risk Detection
function threatAndTechMatrix(r, pending) {
  const f = r.flags || {}, n = r.network || {}, a = r.audit || {}, nat = r.native || {};
  const running = Boolean(activeProbeState?.running);

  // 1. Technical Indicators
  const bogonBadge = r.bogon
    ? pill('是（保留地址）', 'bad')
    : nat.status === 'broadcast'
      ? pill('公网可达 · 广播宣告', 'warn')
      : pill('否（公网可达）', 'good');

  const rdnsDisplay = n.rdns?.length
    ? [mono(n.rdns[0]), n.fcrdns === true ? pill('FCrDNS ✓', 'good') : n.fcrdns === false ? pill('FCrDNS 未过', 'warn') : null]
    : (r.mode === 'full' ? h('span', {class: 'mut'}, '未配置 PTR') : h('span', {class: 'mut'}, '待查询'));

  const nb = a.neighbor;
  const nbDisplay = nb
    ? [pill(nb.level || '未知', neighborTone(nb.level)),
      h('span', {class: 'mut mono', style: {'font-size': '12px'}}, nb.total ? `${nb.flagged}/${nb.total}` : `${nb.flagged} 块`)]
    : h('span', {class: 'mut'}, '离线库未就绪');

  const openPorts = r.ports?.ports || [];
  const portBtn = h('button', {
    id: 'deepProbeBtn',
    type: 'button',
    class: 'probe-pill-btn',
    disabled: running || pending,
    onclick: () => runActiveProbe(),
  }, running ? [spinner(), '实测中…'] : activeProbeState ? '重新实测连接 / 443' : '检测常见端口 / 443');

  const techCard = card('技术指标', metricRows([
    ['Bogon / 广播', bogonBadge],
    ['反向 DNS', rdnsDisplay],
    ['同段邻居 (/24)', nbDisplay],
    ['路由可见度', n.visibility || (f.is_anycast ? pill('Anycast 任播', 'info') : null)],
    ['开放端口与链路', [
      openPorts.length ? pill(`Shodan 暴露 ${openPorts.length} 端口`, openPorts.length >= 5 ? 'warn' : 'info', openPorts.join(', ')) : null,
      portBtn,
    ]],
  ]));

  // 2. IP Intelligence (Threat Indicators)
  const dnsblHits = (r.dnsbl || []).filter(d => d.listed).length;
  const dnsblTotal = (r.dnsbl || []).length;
  const riskLabel = a.risk_summary || (f.is_tor || f.is_abuser || dnsblHits >= 2 ? '发现明显威胁标记'
    : f.is_proxy || f.is_vpn || f.is_leased ? '存在代理或租赁特征' : '未发现明显威胁');
  const riskTone = a.risk_tone || (f.is_tor || f.is_abuser || dnsblHits >= 2 ? 'bad'
    : f.is_proxy || f.is_vpn || f.is_leased ? 'warn' : 'good');

  const abuseLabel = a.abuse_level || (f.is_abuser ? '高风险' : dnsblHits > 0 ? '中等' : '纯净');
  const abuseTone = a.abuse_tone || (f.is_abuser ? 'bad' : dnsblHits > 0 ? 'warn' : 'good');

  const honeyLabel = a.honeypot_status || (dnsblHits > 0 ? `黑名单命中 (${dnsblHits}/${dnsblTotal})` : '纯净');
  const honeyTone = a.honeypot_tone || (dnsblHits >= 2 ? 'bad' : dnsblHits === 1 ? 'warn' : 'good');

  const rpkiRaw = String(n.rpki || '');
  const rpkiNode = !rpkiRaw ? (r.mode === 'full' ? pill('未知', 'neutral') : h('span', {class: 'mut'}, '待查询'))
    : rpkiRaw === '有效' || /valid/i.test(rpkiRaw) && !/invalid/i.test(rpkiRaw) ? pill('✓ Valid（有效）', 'good')
    : /无效|invalid/i.test(rpkiRaw) ? pill('✕ Invalid（' + rpkiRaw + '）', 'bad')
    : pill(rpkiRaw, 'warn');

  const intelCard = card('IP 情报（威胁指标）', metricRows([
    ['风险标记', pending ? h('span', {class: 'mut'}, '检测中…') : pill(riskLabel, riskTone)],
    ['滥用等级', pending ? h('span', {class: 'mut'}, '检测中…') : [
      pill(abuseLabel, abuseTone),
      n.abuser_score ? h('span', {class: 'mut mono', style: {'font-size': '11.5px'}}, n.abuser_score) : null,
    ]],
    ['蜜罐 / 黑名单', pending ? h('span', {class: 'mut'}, '检测中…') : [
      pill(honeyLabel, honeyTone),
      dnsblTotal > 0 && dnsblHits === 0 ? h('span', {class: 'mut mono', style: {'font-size': '11.5px'}}, `0/${dnsblTotal}`) : null,
    ]],
    ['RPKI 状态', rpkiNode],
    ['流量方向核验', a.flow?.masquerade ? pill('疑似伪家宽（出向异常）', 'bad', a.flow.detail)
      : a.flow?.ratio_label ? pill(a.flow.ratio_label, 'info') : null],
  ]));

  // 3. Deep Risk Detection
  const flagPill = (detected, hitLabel, hitTone = 'bad') =>
    pending ? h('span', {class: 'mut'}, '检测中…') : detected ? pill(hitLabel, hitTone) : pill('未检测到', 'good');

  const torHit = Boolean(f.is_tor || a.activity?.tor_exit || a.activity?.tor_relay);
  const torLabel = f.is_tor || a.activity?.tor_exit ? '检测到 Tor 出口' : '检测到 Tor 中继';
  const leaseOrMasq = Boolean(f.is_leased || a.lease?.leased || a.flow?.masquerade);
  const leaseLabel = a.flow?.masquerade ? '疑似伪家宽' : `商业租赁（${a.lease?.broker || 'Broker'}）`;

  const deepCard = card('风险深度检测', metricRows([
    ['VPN', flagPill(Boolean(f.is_vpn), '检测到 VPN', 'bad')],
    ['代理 (Proxy)', flagPill(Boolean(f.is_proxy), '检测到代理', 'bad')],
    ['Tor 节点', flagPill(torHit, torLabel, 'bad')],
    ['爬虫 / 机器人', flagPill(Boolean(f.is_crawler), '检测到爬虫 / 自动化', 'warn')],
    ['租赁 / 伪家宽', flagPill(leaseOrMasq, leaseLabel, a.flow?.masquerade ? 'bad' : 'warn')],
    ['隐私中继', flagPill(Boolean(f.is_icloud_relay), 'iCloud 专用代理', 'info')],
  ]));

  return h('div', {id: 'matrixGrid', class: 'grid3'}, techCard, intelCard, deepCard);
}

let seq = 0, ctl = null, probeCtl = null, connModule = null, lastRendered = null, activeProbeState = null;
function setStatus(cls, ...kids) { statusEl.className = 'status' + (cls ? ' ' + cls : ''); statusEl.replaceChildren(...kids); }

function clearActiveProbe() {
  probeCtl?.abort();
  probeCtl = null;
  activeProbeState = null;
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

async function runActiveProbe() {
  const r = lastRendered;
  if (!r || r.bogon || activeProbeState?.running) return;
  probeCtl?.abort();
  const c = new AbortController();
  probeCtl = c;
  activeProbeState = {running: true, ip: r.ip, server: null, conn: null, findings: [], error: ''};
  render(r);

  const serverTask = timed(8000, sig => getJSON('/api/probe', sig), c.signal)
    .then(data => { if (probeCtl === c) activeProbeState.server = data; })
    .catch(e => { if (probeCtl === c && e.name !== 'AbortError') activeProbeState.serverError = errText(e); });

  const connTask = loadConnectionScript()
    .then(mod => mod.collect({
      signal: c.signal,
      onUpdate: snap => {
        if (probeCtl !== c) return;
        activeProbeState.conn = snap;
        activeProbeState.findings = mod.analyze(snap, lastRendered);
        if (lastRendered) render(lastRendered);
      },
    }))
    .catch(e => { if (probeCtl === c && e.name !== 'AbortError') activeProbeState.connError = errText(e); });

  await Promise.allSettled([serverTask, connTask]);
  if (probeCtl !== c) return;
  activeProbeState.running = false;
  if (lastRendered) render(lastRendered);
}

const CHECK_TONE = {
  pass: ['正常', 'good'],
  info: ['参考', 'info'],
  warn: ['留意', 'warn'],
  bot: ['自动化特征', 'bad'],
};

function renderProbeChecks(checks) {
  if (!checks?.length) return null;
  return h('ul', {class: 'probe-checks'}, checks.map(c => {
    const [lbl, tone] = CHECK_TONE[c.status] || ['观察', 'neutral'];
    return h('li', null,
      h('div', {class: 'probe-head'}, h('b', null, c.name), pill(lbl, tone)),
      h('p', {class: 'mut'}, c.detail));
  }));
}

function renderActiveProbePanel(state) {
  if (!state) return null;
  const blocks = [];
  if (state.server?.tls443) {
    const t = state.server.tls443;
    const vTone = t.reality_suspect ? 'bad' : t.port_open ? 'warn' : 'good';
    const vText = t.reality_suspect ? '疑似 Reality 借证伪装'
      : t.verdict === 'closed' ? '443 未开放（常规终端特征）'
      : t.verdict === 'skipped' ? '未执行公网回探'
      : t.tls_active ? '开放 443 / TLS 服务' : '开放 443 非 TLS 端口';
    blocks.push(h('div', {class: 'probe-sub'},
      h('h3', null, '出口 443 端口与证书核验（访客出口 ', mono(state.server.ip), '）'),
      kv([
        ['结论', h('div', {class: 'tags'}, pill(vText, vTone), t.rtt_ms ? h('span', {class: 'mut mono'}, `${t.rtt_ms} ms`) : null)],
        ['TLS 协议', t.tls_version],
        ['证书域名', (t.subject_cn || t.sans?.length) && mono([t.subject_cn, ...(t.sans || [])].filter((x, i, a) => x && a.indexOf(x) === i).slice(0, 5).join(', '))],
        ['签发机构', t.issuer && (t.issuer + (t.self_signed ? '（自签名）' : ''))],
        ['伪装核对', t.detail],
      ])));
  } else if (state.serverError) {
    blocks.push(h('p', {class: 'mut'}, '服务端 443 回探未能完成：' + state.serverError));
  }

  if (state.conn?.probes?.length) {
    const summarizeProbe = p => {
      if (p.status === 'pending') return '探测中…';
      if (p.status !== 'ok' || !p.data) return p.error || '未返回';
      const d = p.data;
      if (p.id === 'rtc') {
        if (d.publicIPs?.length) return '公网候选 ' + d.publicIPs.join(', ');
        return d.mdns ? '仅 mDNS 隐藏候选' : '未暴露公网候选';
      }
      if (p.id === 'dns') {
        return [d.ip, d.country, d.org, d.ecs?.subnet ? 'ECS ' + d.ecs.subnet : ''].filter(Boolean).join(' · ');
      }
      if (p.id === 'tcp') {
        return [d.os, d.relay === true ? '疑似中继栈' : d.relay === false ? '原生协议栈' : '', d.mismatch ? '与 UA 系统不一致' : ''].filter(Boolean).join(' · ');
      }
      return [d.ip, d.loc, d.colo ? '节点 ' + d.colo : '', d.warp === 'on' ? 'WARP 开启' : ''].filter(Boolean).join(' · ');
    };
    blocks.push(h('div', {class: 'probe-sub'},
      h('h3', null, '多目标出口、DNS / WebRTC 与协议栈实测'),
      kv(state.conn.probes.map(p => [p.label, h('span', {class: p.status === 'error' ? 'mut' : ''}, summarizeProbe(p))])),
      state.findings?.length ? h('ul', {class: 'probe-checks'}, state.findings.map(fd => h('li', null,
        h('div', {class: 'probe-head'}, h('b', null, fd.title), pill(fd.level === 'warn' ? '差异提示' : '观测说明', fd.level === 'warn' ? 'warn' : 'info')),
        h('p', {class: 'mut'}, fd.detail)))) : null));
  } else if (state.connError) {
    blocks.push(h('p', {class: 'mut'}, '浏览器链路探针未能完成：' + state.connError));
  }
  return blocks.length ? h('div', {class: 'active-probe-panel'}, blocks) : null;
}

// Detailed Human-vs-Bot Breakdown & Live Probe Card
function trafficDetailsCard(r, pending) {
  const tr = r.traffic || {};
  const act = r.audit?.activity || {};
  const hasRatio = tr.mode === 'radar' || tr.mode === 'estimated';
  const reqProbe = activeProbeState?.server?.request_probe || tr.request_probe;
  const sigList = Array.isArray(tr.bot_signals) ? tr.bot_signals : [];
  const hasAct = act.spam_reports > 0 || act.dshield_packets > 0 || act.otx_pulses > 0 || act.tor_neighbors > 0;
  if (!hasRatio && !reqProbe && !activeProbeState && !hasAct && !r.audit?.lease?.leased) return null;

  const leftParts = [];
  if (hasRatio) {
    const tier = trafficTier(tr.human_pct, tr.tone, tr.level);
    const srcBadge = tr.mode === 'radar'
      ? pill(`Cloudflare Radar · 近 ${tr.window || '7d'} 实测`, 'info')
      : pill('多源行为与网段推算', 'neutral');
    leftParts.push(
      h('div', {class: 'tags traffic-badges'},
        pill(tier.level, tier.tone),
        srcBadge,
        tr.asn ? h('span', {class: 'mut mono'}, 'AS' + tr.asn) : null),
      ratioBar(tr.human_pct, tr.bot_pct, '人类交互流量', '机器 / 自动化流量', 'human-bot'));
    if (typeof tr.desktop_pct === 'number' && typeof tr.mobile_pct === 'number') {
      leftParts.push(
        h('h3', null, '终端设备流量分布'),
        ratioBar(tr.desktop_pct, tr.mobile_pct, '桌面端', '移动端', 'device-split'));
    }
    if (tr.note) leftParts.push(h('p', {class: 'mut traffic-note'}, tr.note));
  } else {
    leftParts.push(empty(pending ? '正在汇总人机流量比例分布…' : (tr.note || '缺少自治系统与信誉数据，暂未生成流量分布')));
  }

  if (sigList.length) {
    leftParts.push(h('h3', null, '观测到的自动化 / 机器人信号'),
      h('div', {class: 'tags'}, sigList.map(s => pill(s, 'warn'))));
  }

  const actBadges = [];
  if (act.spam_reports > 0) actBadges.push(pill(`StopForumSpam ${act.spam_reports} 次`, 'bad'));
  if (act.dshield_packets > 0) actBadges.push(pill(`DShield ${act.dshield_packets} 包 / ${act.dshield_targets || 0} 目标`, 'poor'));
  if (act.otx_pulses > 0) actBadges.push(pill(`OTX ${act.otx_pulses} 条脉冲`, 'warn'));
  if (act.tor_neighbors > 0) actBadges.push(pill(`同段 Tor 节点 ${act.tor_neighbors} 个`, 'warn'));
  if (r.audit?.lease?.leased && r.audit.lease.detail) {
    actBadges.push(pill(r.audit.lease.detail, 'warn'));
  }
  if (actBadges.length) {
    leftParts.push(h('h3', null, '专项情报观测明细'), h('div', {class: 'tags'}, actBadges));
  }

  const rightParts = [];
  if (reqProbe) {
    const clientEnv = inspectBrowserClient();
    const combinedAuto = clamp(Math.round(reqProbe.automation_share * 0.65 + clientEnv.autoPts * 0.35));
    const combinedHuman = 100 - combinedAuto;
    const pTone = combinedAuto >= 50 ? 'bad' : combinedAuto >= 25 ? 'warn' : 'good';
    const pLabel = combinedAuto >= 50 ? '疑似自动化环境' : combinedAuto >= 25 ? '部分自动化线索' : (reqProbe.label || '标准浏览器交互');
    rightParts.push(
      h('div', {class: 'probe-sub'},
        h('h3', null, '当前访客实时人机特征探测'),
        h('div', {class: 'tags traffic-badges'},
          pill(pLabel, pTone),
          reqProbe.client_family ? pill(reqProbe.client_family, 'neutral') : null,
          reqProbe.proto ? h('span', {class: 'mut mono'}, reqProbe.proto) : null),
        ratioBar(combinedHuman, combinedAuto, '真人终端特征', '脚本 / 自动化特征', 'probe-split'),
        renderProbeChecks([...(reqProbe.checks || []), ...clientEnv.checks])));
  }
  const activePanel = renderActiveProbePanel(activeProbeState);
  if (activePanel) rightParts.push(activePanel);
  if (!rightParts.length) {
    rightParts.push(empty('查询第三方 IP 时不将您本机的浏览器特征计入对方；点击上方「检测常见端口 / 443」可实测您当前的出口链路与 443 证书伪装。'));
  }

  return h('section', {id: 'trafficCard', class: 'card traffic-card'},
    h('div', {class: 'card-head'},
      h('h2', null, '人机流量详单与实时连接探测', h('small', null, '流量构成 · 自动化信号 · 访客握手与 443 伪装探针'))),
    h('div', {class: 'traffic-grid'},
      h('div', {class: 'traffic-col'}, h('h3', {class: 'col-title'}, '人机流量比例分布'), leftParts),
      h('div', {class: 'traffic-col'}, h('h3', {class: 'col-title'}, '实时人机与连接探针'), rightParts)));
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
      n.fcrdns === true ? pill('FCrDNS 通过', 'good') : n.fcrdns === false ? pill('FCrDNS 未通过', 'warn') : pill('来自第三方，未校验', 'neutral')]],
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

function render(r, pending = false, failed = false) {
  lastRendered = r;
  const parts = [verdictCard(r, pending, failed)];
  if (r.mode && !r.bogon) {
    parts.push(usageAndASNRow(r, pending && !failed));
    parts.push(threatAndTechMatrix(r, pending && !failed));
    const tCard = trafficDetailsCard(r, pending && !failed);
    if (tCard) parts.push(tCard);
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
