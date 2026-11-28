(() => {
  'use strict';

  const byId = id => document.getElementById(id);
  const numFmt = new Intl.NumberFormat('zh-CN');
  const bjClock = new Intl.DateTimeFormat('zh-CN', {
    timeZone: 'Asia/Shanghai',
    dateStyle: 'medium',
    timeStyle: 'short',
    hour12: false,
  });
  const dayMs = 86400000;
  const cnDate = ms => new Date(ms + 8 * 3600000).toISOString().slice(0, 10);
  const isoDay = ms => new Date(ms).toISOString().slice(0, 10);
  const stamp = raw => (typeof raw === 'string' && /^\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})$/.test(raw) ? Date.parse(raw) : NaN);
  const integer = v => Number.isSafeInteger(v) && v >= 0;
  const h = s => String(s == null ? '' : s).replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'}[c]));
  const fmtNum = v => (Number.isFinite(Number(v)) ? numFmt.format(Number(v)) : '0');

  const VIEW_TITLES = {
    dashboard: '概览',
    visits: '实时流量',
    analytics: '趋势分布',
    sources: '情报源',
    security: '安全访问',
  };

  const KIND_META = {
    view: ['网页访问', 'info'],
    self_lookup: ['本机查询', 'ok'],
    target_lookup: ['外部 IP 查询', 'warn'],
    cli: ['CLI / JSON', 'neutral'],
    probe: ['443 实测', 'info'],
    error: ['异常请求', 'bad'],
  };

  let generation = 0;
  let loggedIn = false;
  let overviewCache = null;
  let lastNow = Date.now();
  let navStack = [{view: 'dashboard', params: {}}];
  let analyticsSpan = 7;
  let analyticsType = 'line';
  let chartHidden = new Set();
  let chartGeom = null;
  let chartSeries = [];

  let visitsState = {
    page: 1,
    size: 20,
    total: 0,
    q: '',
    kind: '',
    from: '',
    to: '',
    today: false,
    err: false,
    sort: 'time',
    order: 'desc',
  };

  let dsFilter = {q: '', status: ''};

  const AUTO_REFRESH_MS = 10000;
  const BROWSE_IDLE_MS = 15000;
  let autoRefreshTimer = null;
  let arLeft = 10;
  let refreshing = false;
  let lastInteractAt = 0;

  function toast(msg, ok = true) {
    const el = document.createElement('div');
    el.className = 'toast' + (ok ? '' : ' bad');
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.classList.add('show'), 16);
    setTimeout(() => {
      el.classList.remove('show');
      setTimeout(() => el.remove(), 200);
    }, 2400);
  }

  function setBanner(msg, error = false) {
    const el = byId('inlineBanner');
    if (!msg) {
      el.hidden = true;
      el.textContent = '';
      return;
    }
    el.hidden = false;
    el.dataset.tone = error ? 'error' : 'info';
    el.textContent = msg;
  }

  async function api(path, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const urlKey = new URLSearchParams(location.search).get('k') || '';
      const headers = body === undefined ? {Accept: 'application/json'} : {'Content-Type': 'application/json', Accept: 'application/json'};
      if (urlKey) headers['X-Admin-Key'] = urlKey;
      const response = await fetch(`/admin/api/${path}`, {
        method: body === undefined ? 'GET' : 'POST',
        body: body === undefined ? undefined : JSON.stringify(body),
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        redirect: 'error',
        referrerPolicy: 'no-referrer',
        signal: controller.signal,
      });
      const fetched = Date.parse(response.headers.get('Date'));
      const now = Number.isFinite(fetched) ? fetched : Date.now();
      let data = null;
      const ct = response.headers.get('Content-Type') || '';
      if (response.status !== 204 && ct.includes('application/json')) {
        try { data = await response.json(); } catch { data = null; }
      }
      return {status: response.status, now, data};
    } finally {
      clearTimeout(timer);
    }
  }

  function parseUsageSeries(usage, now) {
    const fields = ['pageViews', 'lookups', 'errors'];
    if (!usage || usage.schema !== 1 || usage.site !== 'ip' || !Array.isArray(usage.days) || usage.days.length > 30) return null;
    const start = stamp(usage.startedAt);
    const updated = stamp(usage.updatedAt);
    if (!Number.isFinite(start) || !Number.isFinite(updated) || updated < start) return null;
    const today = cnDate(now);
    const since = cnDate(start);
    if (since > today) return null;
    const map = new Map();
    for (const row of usage.days) {
      const d = row?.date;
      if (typeof d !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(d) || !Number.isFinite(Date.parse(d)) || isoDay(Date.parse(d)) !== d ||
          d < since || d > today || map.has(d) || !fields.every(k => integer(row[k]))) {
        return null;
      }
      map.set(d, {
        date: d,
        pageViews: row.pageViews || 0,
        lookups: row.lookups || 0,
        errors: row.errors || 0,
        uv: integer(row.uv) ? row.uv : 0,
        cliLookups: integer(row.cliLookups) ? row.cliLookups : 0,
        targetLookups: integer(row.targetLookups) ? row.targetLookups : 0,
        probes: integer(row.probes) ? row.probes : 0,
      });
    }
    const end = Date.parse(today + 'T00:00:00Z');
    return Array.from({length: 30}, (_, idx) => {
      const date = isoDay(end - (29 - idx) * dayMs);
      if (date < since) return {date, covered: false, pageViews: 0, lookups: 0, errors: 0, uv: 0, cliLookups: 0, targetLookups: 0, probes: 0};
      return {covered: true, ...(map.get(date) || {date, pageViews: 0, lookups: 0, errors: 0, uv: 0, cliLookups: 0, targetLookups: 0, probes: 0})};
    });
  }

  function sumDays(series, count) {
    if (!series) return null;
    const slice = series.slice(-count).filter(r => r.covered);
    const acc = {pageViews: 0, lookups: 0, errors: 0, uv: 0, cliLookups: 0, targetLookups: 0, probes: 0};
    for (const r of slice) {
      acc.pageViews += r.pageViews;
      acc.lookups += r.lookups;
      acc.errors += r.errors;
      acc.uv += r.uv;
      acc.cliLookups += r.cliLookups;
      acc.targetLookups += r.targetLookups;
      acc.probes += r.probes;
    }
    return acc;
  }

  function deltaHtml(todayVal, yestVal) {
    const t = Number(todayVal) || 0;
    const y = Number(yestVal) || 0;
    const d = t - y;
    const tag = d > 0 ? `<span class="kpi-up">+${fmtNum(d)}</span>` : d < 0 ? `<span class="kpi-dn">${fmtNum(d)}</span>` : '<span class="kpi-dn">±0</span>';
    return `昨日 ${fmtNum(y)} (${tag})`;
  }

  function currentView() {
    return navStack.length ? navStack[navStack.length - 1].view : 'dashboard';
  }

  function closeModal() {
    const dlg = byId('ipDialog');
    if (dlg.open) dlg.close();
    paintAutoRefreshLabel();
  }

  function showLogin(msg = '') {
    loggedIn = false;
    overviewCache = null;
    stopAutoRefresh();
    closeModal();
    byId('bootNotice').hidden = true;
    byId('app').hidden = true;
    byId('view').replaceChildren();
    byId('loginHost').textContent = location.host || 'IP Lookup';
    byId('loginPage').hidden = false;
    byId('p').value = '';
    byId('loginErr').textContent = msg;
    byId('p').focus();
  }

  function updateHeaderBadges(sources) {
    const dsErr = Array.isArray(sources?.datasets) ? sources.datasets.filter(d => d?.status === 'error').length : 0;
    const onLim = Array.isArray(sources?.online) ? sources.online.filter(o => {
      const b = stamp(o?.blocked_until);
      return Number.isFinite(b) && b > lastNow;
    }).length : 0;
    const total = dsErr + onLim;
    const badge = byId('sourcesNavBadge');
    badge.textContent = String(total);
    badge.hidden = total === 0;
    const rb = byId('roleBadge');
    if (dsErr > 0) {
      rb.className = 'status-pill warn';
      rb.textContent = `${dsErr} 项离线库异常`;
    } else if (onLim > 0) {
      rb.className = 'status-pill warn';
      rb.textContent = `${onLim} 项接口限流`;
    } else {
      rb.className = 'status-pill ok';
      rb.textContent = '运行正常';
    }
  }

  function labelizeTables(root) {
    (root || byId('view')).querySelectorAll('table:not(.matrix)').forEach(table => {
      const heads = Array.from(table.querySelectorAll('thead th')).map(th => th.textContent.replace(/[▲▼↕\s]+$/g, '').trim());
      if (!heads.length) return;
      table.querySelectorAll('tbody tr').forEach(tr => {
        Array.from(tr.children).forEach((td, idx) => {
          if (td.hasAttribute('colspan') || td.dataset.label) return;
          if (heads[idx]) td.dataset.label = heads[idx];
        });
      });
    });
  }

  /* ---------- Views ---------- */

  function renderDashboardView() {
    const v = byId('view');
    const data = overviewCache;
    if (!data) {
      v.innerHTML = '<p class="mut">加载中…</p>';
      return;
    }
    const usage = data.usage;
    const series = parseUsageSeries(usage, lastNow);
    const live = data.live || {};
    const sources = data.sources || {};

    const todayRow = series ? series[series.length - 1] : {pageViews: 0, lookups: 0, errors: 0, uv: 0, cliLookups: 0, targetLookups: 0, probes: 0};
    const yestRow = series && series.length >= 2 ? series[series.length - 2] : {pageViews: 0, lookups: 0, errors: 0, uv: 0, cliLookups: 0, targetLookups: 0, probes: 0};
    const s1 = sumDays(series, 1) || todayRow;
    const s7 = sumDays(series, 7) || s1;
    const s30 = sumDays(series, 30) || s1;

    const todayUV = live.todayUv ?? todayRow.uv ?? 0;
    const yestUV = live.yestUv ?? yestRow.uv ?? 0;

    const onlineArr = Array.isArray(sources.online) ? sources.online : null;
    const dsArr = Array.isArray(sources.datasets) ? sources.datasets : null;
    const onlineLimited = onlineArr ? onlineArr.filter(o => { const b = stamp(o?.blocked_until); return Number.isFinite(b) && b > lastNow; }).length : 0;
    const onlineOk = onlineArr ? onlineArr.length - onlineLimited : 0;
    const dsOk = dsArr ? dsArr.filter(d => d?.status === 'ok').length : 0;
    const dsErr = dsArr ? dsArr.filter(d => d?.status === 'error').length : 0;
    const dsEntries = dsArr ? dsArr.reduce((sum, d) => sum + (integer(d?.entries) ? d.entries : 0), 0) : 0;
    const topRegion = Array.isArray(live.regions) && live.regions.length ? live.regions[0].name : '等待采样';

    const cell = (label, val, subHtml, navView, navParams, bad = false) => `
      <button type="button" class="kpi-cell" data-nav="${h(navView)}" data-params="${h(JSON.stringify(navParams || {}))}">
        <span class="kpi-lbl">${h(label)}</span>
        <span class="kpi-val ${bad ? 'bad' : ''}">${h(val)}</span>
        <span class="kpi-delta">${subHtml}</span>
      </button>`;

    let matrixHtml = '';
    if (!series) {
      const msg = usage == null ? '未采集访问统计。' : '访问统计不可用，不能按零流量计算。';
      matrixHtml = `<section class="sheet"><div class="sheet-head"><h2>时段请求矩阵</h2></div><p id="coverage" class="mut">${h(msg)}</p><table id="totals" hidden></table></section>`;
    } else {
      const since = cnDate(stamp(usage.startedAt));
      const anyTraffic = s30.pageViews + s30.lookups + s30.errors > 0;
      const emptyMsg = !anyTraffic ? (since >= series[0].date ? '接入以来未记录到流量。' : '近 30 天未记录到流量。') : '';
      matrixHtml = `
        <section class="sheet">
          <div class="sheet-head">
            <h2>时段请求矩阵</h2>
            <span id="coverage" class="sheet-sub">${h(emptyMsg)}自 ${h(since)} 起按 UTC+8 归日 · 磁盘仅存匿名计数</span>
          </div>
          <div class="table-wrap">
            <table class="matrix">
              <thead><tr><th>统计窗口</th><th class="num">独立访客</th><th class="num">页面访问</th><th class="num">成功查询</th><th class="num">CLI / JSON</th><th class="num">443 实测</th><th class="num">异常</th></tr></thead>
              <tbody id="totals">
                <tr><td><strong>今日</strong></td><td class="num"><strong>${fmtNum(todayUV)}</strong></td><td class="num"><strong>${fmtNum(s1.pageViews)}</strong></td><td class="num"><strong>${fmtNum(s1.lookups)}</strong></td><td class="num">${fmtNum(s1.cliLookups)}</td><td class="num">${fmtNum(s1.probes)}</td><td class="num">${fmtNum(s1.errors)}</td></tr>
                <tr><td>近 7 天</td><td class="num">${fmtNum(live.uv7d ?? s7.uv)}</td><td class="num">${fmtNum(s7.pageViews)}</td><td class="num">${fmtNum(s7.lookups)}</td><td class="num">${fmtNum(s7.cliLookups)}</td><td class="num">${fmtNum(s7.probes)}</td><td class="num">${fmtNum(s7.errors)}</td></tr>
                <tr><td>近 30 天</td><td class="num">${fmtNum(live.uv30d ?? s30.uv)}</td><td class="num">${fmtNum(s30.pageViews)}</td><td class="num">${fmtNum(s30.lookups)}</td><td class="num">${fmtNum(s30.cliLookups)}</td><td class="num">${fmtNum(s30.probes)}</td><td class="num">${fmtNum(s30.errors)}</td></tr>
              </tbody>
            </table>
          </div>
        </section>`;
    }

    v.innerHTML = `
      <section class="kpi-ledger" aria-label="今日实时指标">
        ${cell('今日独立访客', fmtNum(todayUV), deltaHtml(todayUV, yestUV), 'visits', {today: true})}
        ${cell('页面访问 (PV)', fmtNum(todayRow.pageViews), deltaHtml(todayRow.pageViews, yestRow.pageViews), 'visits', {today: true, kind: 'view'})}
        ${cell('成功查询', fmtNum(todayRow.lookups), deltaHtml(todayRow.lookups, yestRow.lookups), 'visits', {today: true})}
        ${cell('CLI / JSON 接口', fmtNum(todayRow.cliLookups), deltaHtml(todayRow.cliLookups, yestRow.cliLookups), 'visits', {today: true, kind: 'cli_json'})}
        ${cell('443 连通实测', fmtNum(todayRow.probes), deltaHtml(todayRow.probes, yestRow.probes), 'visits', {today: true, kind: 'probe'})}
        ${cell('异常与限流', fmtNum(todayRow.errors), deltaHtml(todayRow.errors, yestRow.errors), 'visits', {today: true, err: true}, todayRow.errors > 0)}
      </section>

      <div class="overview-grid">
        ${matrixHtml}
        <section class="sheet">
          <div class="sheet-head">
            <h2>情报引擎状态</h2>
            <span class="sheet-sub">点击条目进入明细</span>
          </div>
          <div class="engine-list">
            <div class="engine-row" data-nav="sources" data-params="{}">
              <div>
                <strong>在线信誉与路由接口</strong>
                <small>${onlineLimited > 0 ? `${onlineLimited} 个上游处于配额/速率冷却期` : '所有已注册上游配额正常'}</small>
              </div>
              <div class="engine-stat">${onlineArr ? `${onlineOk} / ${onlineArr.length}` : '—'}</div>
            </div>
            <div class="engine-row" data-nav="sources" data-params="{}">
              <div>
                <strong>离线 MMDB 与威胁网段库</strong>
                <small>${dsErr > 0 ? `${dsErr} 份离线库加载报错` : `已索引 ${fmtNum(dsEntries)} 条路由与黑名单记录`}</small>
              </div>
              <div class="engine-stat">${dsArr ? `${dsOk} / ${dsArr.length}` : '—'}</div>
            </div>
            <div class="engine-row" data-nav="visits" data-params='{"kind":"target_lookup"}'>
              <div>
                <strong>指定外部 IP 查询累计</strong>
                <small>近 30 天主动输入或路径查询非本机 IP</small>
              </div>
              <div class="engine-stat">${fmtNum(s30.targetLookups)}</div>
            </div>
            <div class="engine-row" data-nav="analytics" data-params='{"span":30}'>
              <div>
                <strong>实时采样来源地区</strong>
                <small>当前首位来源：${h(topRegion)}</small>
              </div>
              <div class="engine-stat">${fmtNum((live.regions || []).length)} 地区</div>
            </div>
          </div>
        </section>
      </div>`;
  }

  function renderVisitsShell() {
    const chips = [];
    if (visitsState.today) chips.push('今日');
    if (visitsState.err) chips.push('仅异常');
    if (visitsState.kind) {
      const km = {view: '网页访问', self_lookup: '本机查询', target_lookup: '外部 IP 查询', cli_json: 'CLI / JSON', probe: '443 实测', error: '异常请求'};
      chips.push(km[visitsState.kind] || visitsState.kind);
    }
    if (visitsState.from || visitsState.to) chips.push(`${visitsState.from || '不限'} ~ ${visitsState.to || '不限'}`);

    const chipHtml = chips.length
      ? `<span class="chip">${h(chips.join(' · '))} <button type="button" data-action="visits-reset" title="清除筛选">×</button></span>`
      : '';

    byId('view').innerHTML = `
      <section class="sheet">
        <div class="sheet-head">
          <h2>实时请求观测流 ${chipHtml}</h2>
          <span class="sheet-sub">仅驻留进程内存环形缓冲（最近 1,000 条），重启即清空，不写磁盘</span>
        </div>
        <div class="toolbar">
          <input id="vSearch" placeholder="检索 IP / 国家地区 / ASN / 客户端" value="${h(visitsState.q)}">
          <select id="vKind" aria-label="请求类型">
            <option value="">全部类型</option>
            <option value="view" ${visitsState.kind === 'view' ? 'selected' : ''}>网页访问</option>
            <option value="self_lookup" ${visitsState.kind === 'self_lookup' ? 'selected' : ''}>本机查询</option>
            <option value="target_lookup" ${visitsState.kind === 'target_lookup' ? 'selected' : ''}>外部 IP 查询</option>
            <option value="cli_json" ${visitsState.kind === 'cli_json' ? 'selected' : ''}>CLI / JSON</option>
            <option value="probe" ${visitsState.kind === 'probe' ? 'selected' : ''}>443 实测</option>
            <option value="error" ${visitsState.kind === 'error' ? 'selected' : ''}>异常请求</option>
          </select>
          <input type="date" id="vFrom" aria-label="开始日期" value="${h(visitsState.from)}">
          <input type="date" id="vTo" aria-label="结束日期" value="${h(visitsState.to)}">
          <button type="button" class="btn sm ${visitsState.today ? 'active' : ''}" data-action="visits-toggle-today">今日</button>
          <button type="button" class="btn sm ${visitsState.err ? 'active' : ''}" data-action="visits-toggle-err">仅异常</button>
          <button type="button" class="btn sm primary" data-action="visits-search">检索</button>
          <button type="button" class="btn sm" data-action="visits-reset">重置</button>
        </div>
        <div id="visitsTable"><p class="mut">加载中…</p></div>
        <div id="visitsPager"></div>
      </section>`;
    void loadVisitsData();
  }

  async function loadVisitsData() {
    const box = byId('visitsTable');
    if (!box) return;
    const qs = new URLSearchParams({
      page: String(visitsState.page),
      size: String(visitsState.size),
      q: visitsState.q,
      kind: visitsState.kind,
      from: visitsState.from,
      to: visitsState.to,
      sort: visitsState.sort,
      order: visitsState.order,
    });
    if (visitsState.today) qs.set('today', '1');
    if (visitsState.err) qs.set('err', '1');
    try {
      const {status, data} = await api(`visits?${qs.toString()}`);
      if (status === 401) { showLogin('会话已过期，请重新登录。'); return; }
      if (status !== 200 || !data) {
        box.innerHTML = '<p class="auth-err">读取实时请求流失败</p>';
        return;
      }
      visitsState.total = data.total || 0;
      const items = data.items || [];
      const arrow = col => (visitsState.sort === col ? (visitsState.order === 'asc' ? ' ▲' : ' ▼') : ' ↕');
      const rows = items.map(r => {
        const [kLabel, kTone] = KIND_META[r.kind] || [r.kind || '请求', 'neutral'];
        const stTag = r.status >= 400
          ? `<span class="tag bad">${h(r.status)}</span>`
          : `<span class="tag ok">${h(r.status)}</span>`;
        const loc = [r.location || '未知地区', [r.asn, r.isp].filter(Boolean).join(' ')].filter(Boolean).join(' · ');
        const tgt = r.targetIp && r.targetIp !== r.ip
          ? `<code>${h(r.targetIp)}</code>${r.targetLabel ? ` <span class="tag neutral">${h(r.targetLabel)}</span>` : ''}`
          : `<span class="mut">本机</span>${r.targetLabel ? ` <span class="tag neutral">${h(r.targetLabel)}</span>` : ''}`;
        return `<tr class="clickable" data-ip="${h(r.ip || r.targetIp || '')}">
          <td class="mono">${h(r.time)}</td>
          <td><code>${h(r.ip || '-')}</code></td>
          <td class="td-full"><div class="ellip" title="${h(loc)}">${h(loc)}</div></td>
          <td><span class="tag ${kTone}">${h(kLabel)}</span></td>
          <td>${tgt}</td>
          <td>${h([r.os, r.browser].filter(Boolean).join(' · ') || '-')}</td>
          <td class="num">${stTag} <span class="mut">${h(r.ms)}ms</span></td>
        </tr>`;
      }).join('');

      box.innerHTML = `<div class="table-wrap"><table>
        <thead><tr>
          <th class="sortable" data-sort="time">时间 (UTC+8)${arrow('time')}</th>
          <th>来源 IP</th>
          <th>地区与自治系统</th>
          <th>动作</th>
          <th>目标地址</th>
          <th>客户端环境</th>
          <th class="sortable num" data-sort="ms">状态 / 耗时${arrow('ms')}</th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="7" class="mut">当前筛选条件下无记录</td></tr>'}</tbody>
      </table></div>`;
      labelizeTables(box);
      renderPager(byId('visitsPager'), visitsState.page, visitsState.size, visitsState.total);
    } catch {
      if (box.isConnected) box.innerHTML = '<p class="auth-err">网络异常，无法读取实时记录</p>';
    }
  }

  function renderPager(el, page, size, total) {
    if (!el) return;
    const pages = Math.max(1, Math.ceil(total / size));
    if (pages <= 1) {
      el.innerHTML = `<div class="pager"><span>共 ${fmtNum(total)} 条内存采样记录</span></div>`;
      return;
    }
    let btns = '';
    for (let p = Math.max(1, page - 2); p <= Math.min(pages, page + 2); p++) {
      btns += `<button type="button" class="btn sm ${p === page ? 'active' : ''}" data-page="${p}">${p}</button>`;
    }
    el.innerHTML = `<div class="pager">
      <span>第 ${page} / ${pages} 页 · 共 ${fmtNum(total)} 条</span>
      <div class="pager-btns">
        <button type="button" class="btn sm" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>上一页</button>
        ${btns}
        <button type="button" class="btn sm" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''}>下一页</button>
      </div>
    </div>`;
  }

  function buildAnalyticsSvg(series) {
    const keys = [
      {k: 'pageViews', label: '页面访问', color: '#0b6b88'},
      {k: 'lookups', label: '成功查询', color: '#15803d'},
      {k: 'uv', label: '独立访客', color: '#2563eb'},
      {k: 'cliLookups', label: 'CLI/JSON', color: '#0d9488'},
      {k: 'probes', label: '443 实测', color: '#b86600'},
      {k: 'errors', label: '异常请求', color: '#cf222e'},
    ];
    const vis = keys.filter(k => !chartHidden.has(k.k));
    const mob = window.innerWidth <= 680;
    const W = mob ? 430 : 940;
    const H = 236;
    const padL = 42, padR = 16, padT = 14, padB = 32;
    const n = series.length;
    const bar = analyticsType === 'bar';
    let maxV = 1;
    series.forEach(s => vis.forEach(k => { if ((s[k.k] || 0) > maxV) maxV = s[k.k] || 0; }));
    const band = (W - padL - padR) / Math.max(n, 1);
    const X = i => (bar ? padL + band * (i + 0.5) : padL + (n <= 1 ? 0 : i * (W - padL - padR) / (n - 1)));
    const Y = val => padT + (H - padT - padB) * (1 - val / maxV);

    chartSeries = series;
    chartGeom = {W, H, padL, padR, padT, padB, band, bar, n, maxV, keys, vis};

    let svg = `<svg id="plot" viewBox="0 0 ${W} ${H}" style="width:100%;height:auto;display:block">`;
    [0, 0.5, 1].forEach(fr => {
      const val = Math.round(maxV * fr);
      const yy = Y(val);
      svg += `<line x1="${padL}" y1="${yy}" x2="${W - padR}" y2="${yy}" stroke="var(--line)" stroke-opacity=".6"/><text x="2" y="${yy + 4}" font-size="11" fill="var(--mut)">${val}</text>`;
    });
    [0, Math.floor(n / 2), n - 1].forEach(i => {
      if (series[i]) svg += `<text x="${X(i)}" y="${H - 8}" font-size="11" fill="var(--mut)" text-anchor="middle">${h(series[i].date.slice(5))}</text>`;
    });

    if (bar) {
      const bw = Math.max(2, Math.min(24, band * 0.72 / Math.max(vis.length, 1)));
      const y0 = Y(0);
      vis.forEach((k, ki) => series.forEach((s, i) => {
        if (!s.covered) return;
        const val = s[k.k] || 0;
        const x = X(i) - bw * vis.length / 2 + bw * ki;
        const y = Y(val);
        const hh = Math.max(val > 0 ? 1.5 : 0, y0 - y);
        svg += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${hh.toFixed(1)}" fill="${k.color}" rx="1.5"/>`;
      }));
    } else {
      vis.forEach(k => {
        const pts = series.flatMap((s, i) => (s.covered ? [`${X(i).toFixed(1)},${Y(s[k.k] || 0).toFixed(1)}`] : []));
        if (pts.length === 1) {
          const [cx, cy] = pts[0].split(',');
          svg += `<circle cx="${cx}" cy="${cy}" r="3.2" fill="${k.color}"/>`;
        } else if (pts.length > 1) {
          svg += `<polyline points="${pts.join(' ')}" fill="none" stroke="${k.color}" stroke-width="2"/>`;
        }
      });
    }
    svg += `<line id="chartLine" x1="0" y1="${padT}" x2="0" y2="${H - padB}" stroke="var(--mut)" stroke-dasharray="3 3" style="display:none"/>`;
    svg += '</svg>';

    const legend = `<div class="chart-legend">${keys.map(k => {
      const off = chartHidden.has(k.k);
      return `<button type="button" class="legend-btn ${off ? 'off' : ''}" data-series="${k.k}"><i style="background:${k.color}"></i>${h(k.label)}</button>`;
    }).join('')}</div>`;

    return `<div class="chart-box" id="chartBox">${svg}<div class="chart-tip" id="chartTip"></div>${legend}</div>`;
  }

  function distSheetHtml(title, items) {
    const list = Array.isArray(items) ? items : [];
    const maxReq = list.reduce((m, x) => Math.max(m, x.requests || 0), 1);
    const rows = list.map(x => {
      const w = Math.max(3, (x.requests || 0) / maxReq * 100);
      return `<tr>
        <td><div class="ellip" title="${h(x.name)}">${h(x.name)}</div></td>
        <td class="num">${fmtNum(x.visitors)}</td>
        <td class="num">${fmtNum(x.requests)}</td>
        <td class="num"><span class="share-bar"><i style="width:${w.toFixed(1)}%"></i></span></td>
      </tr>`;
    }).join('');
    return `<section class="sheet">
      <div class="sheet-head"><h2>${h(title)}</h2></div>
      <div class="table-wrap">
        <table class="matrix">
          <thead><tr><th>维度</th><th class="num">访客</th><th class="num">请求</th><th class="num">比重</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="4" class="mut">暂无采样</td></tr>'}</tbody>
        </table>
      </div>
    </section>`;
  }

  function renderAnalyticsView() {
    const v = byId('view');
    if (!overviewCache) {
      v.innerHTML = '<p class="mut">加载中…</p>';
      return;
    }
    const seriesAll = parseUsageSeries(overviewCache.usage, lastNow);
    const live = overviewCache.live || {};
    const selected = seriesAll ? seriesAll.slice(-analyticsSpan) : [];

    const dayRows = selected.slice().reverse().map(r => {
      if (!r.covered) {
        return `<tr><td class="mono">${h(r.date)}</td><td colspan="6" class="mut">未采集</td></tr>`;
      }
      return `<tr>
        <td class="mono">${h(r.date)}</td>
        <td class="num">${fmtNum(r.uv)}</td>
        <td class="num">${fmtNum(r.pageViews)}</td>
        <td class="num">${fmtNum(r.lookups)}</td>
        <td class="num">${fmtNum(r.cliLookups)}</td>
        <td class="num">${fmtNum(r.probes)}</td>
        <td class="num">${fmtNum(r.errors)}</td>
      </tr>`;
    }).join('');

    v.innerHTML = `
      <section class="sheet">
        <div class="sheet-head">
          <h2>逐日趋势（近 ${analyticsSpan} 天）</h2>
          <div class="toolbar" style="margin:0">
            <select id="anaSpan" aria-label="统计周期">
              ${[7, 14, 30].map(d => `<option value="${d}" ${analyticsSpan === d ? 'selected' : ''}>近 ${d} 天</option>`).join('')}
            </select>
            <button type="button" class="btn sm ${analyticsType === 'line' ? 'active' : ''}" data-chart-type="line">折线</button>
            <button type="button" class="btn sm ${analyticsType === 'bar' ? 'active' : ''}" data-chart-type="bar">柱状</button>
          </div>
        </div>
        ${seriesAll ? buildAnalyticsSvg(selected) : '<p class="mut">暂无可用趋势数据。</p>'}
        ${seriesAll ? `<details id="dayDetails" style="margin-top:12px"><summary style="cursor:pointer;color:var(--acc);font-size:13px;font-weight:600">查看每日数值</summary>
          <div class="table-wrap" style="margin-top:10px">
            <table class="matrix">
              <thead><tr><th>日期</th><th class="num">独立访客</th><th class="num">页面访问</th><th class="num">成功查询</th><th class="num">CLI/JSON</th><th class="num">443 实测</th><th class="num">失败查询</th></tr></thead>
              <tbody id="dayRows">${dayRows}</tbody>
            </table>
          </div></details>` : ''}
      </section>
      <div class="dist-grid">
        ${distSheetHtml('国家与地区分布', live.regions)}
        ${distSheetHtml('自治系统 (ASN) 分布', live.asns)}
        ${distSheetHtml('客户端环境分布', live.clients)}
      </div>`;
  }

  function parseQuotaPair(quotaStr, used) {
    const m = String(quotaStr || '').match(/(\d+)\s*\/\s*(day|month|min|hour|日|月)/i);
    if (!m || !integer(used)) return null;
    const cap = Number(m[1]);
    return cap > 0 ? {used, cap, pct: Math.min(100, used / cap * 100)} : null;
  }

  function renderSourcesView() {
    const v = byId('view');
    if (!overviewCache) {
      v.innerHTML = '<p class="mut">加载中…</p>';
      return;
    }
    const sources = overviewCache.sources || {};
    const online = Array.isArray(sources.online) ? sources.online : null;
    const datasets = Array.isArray(sources.datasets) ? sources.datasets : null;

    let onlineHtml = '';
    if (!online) {
      onlineHtml = '<p id="onlineInfo" class="mut">来源状态不可用。</p>';
    } else if (!online.length) {
      onlineHtml = '<p id="onlineInfo" class="mut">暂无已登记的在线服务。</p>';
    } else {
      const cards = online.map(item => {
        const blocked = stamp(item.blocked_until);
        const limited = Number.isFinite(blocked) && blocked > lastNow;
        const qp = parseQuotaPair(item.quota, item.used);
        const tag = limited
          ? `<span class="tag warn">限流至 ${h(bjClock.format(blocked))}</span>`
          : '<span class="tag ok">正常</span>';
        const tone = limited ? 'bad' : qp && qp.pct >= 80 ? 'warn' : '';
        const quotaTxt = item.quota
          ? `${item.quota} · 已用 ${integer(item.used) ? fmtNum(item.used) : '未知'}`
          : '公共免钥接口';
        return `<div class="quota-item">
          <div class="quota-top"><strong>${h(item.name || '未命名服务')}</strong>${tag}</div>
          <div class="quota-meta"><span>${h(quotaTxt)}</span>${qp ? `<span class="mono">${qp.pct.toFixed(0)}%</span>` : ''}</div>
          ${qp ? `<div class="meter"><i class="${tone}" style="width:${qp.pct.toFixed(1)}%"></i></div>` : ''}
        </div>`;
      }).join('');
      onlineHtml = `<div id="onlineInfo" class="sheet-sub">${online.length} 个在线信誉与路由服务</div><div id="online" class="quota-grid">${cards}</div>`;
    }

    let dsHtml = '';
    if (!datasets) {
      dsHtml = '<p id="datasetInfo" class="mut">来源状态不可用。</p>';
    } else if (!datasets.length) {
      dsHtml = '<p id="datasetInfo" class="mut">暂无已登记的数据集。</p>';
    } else {
      const kw = dsFilter.q.trim().toLowerCase();
      const filtered = datasets.filter(d => {
        if (dsFilter.status && d.status !== dsFilter.status) return false;
        if (kw && !String((d.label || '') + ' ' + (d.id || '') + ' ' + (d.error || '')).toLowerCase().includes(kw)) return false;
        return true;
      });
      const rows = filtered.map(item => {
        const stTag = item.status === 'ok'
          ? '<span class="tag ok">可用</span>'
          : item.status === 'error'
          ? '<span class="tag bad">错误</span>'
          : '<span class="tag warn">待加载</span>';
        const upd = stamp(item.updated_at);
        return `<tr>
          <td><strong>${h(item.label || item.id || '未命名数据集')}</strong></td>
          <td>${stTag}</td>
          <td class="num">${integer(item.entries) ? fmtNum(item.entries) : '-'}</td>
          <td class="mono">${Number.isFinite(upd) ? h(bjClock.format(upd)) : '-'}</td>
          <td class="td-full">${item.error ? `<span style="color:var(--bad)">${h(item.error)}</span>` : '<span class="mut">—</span>'}</td>
        </tr>`;
      }).join('');
      dsHtml = `
        <div class="sheet-head">
          <h2>离线情报库与路由表 <span id="datasetInfo" class="sheet-sub">${datasets.length} 份数据集</span></h2>
          <div class="toolbar" style="margin:0">
            <input id="dsSearch" placeholder="检索数据集名称" value="${h(dsFilter.q)}">
            <select id="dsStatus" aria-label="数据集状态">
              <option value="">全部状态</option>
              <option value="error" ${dsFilter.status === 'error' ? 'selected' : ''}>仅错误</option>
              <option value="ok" ${dsFilter.status === 'ok' ? 'selected' : ''}>正常可用</option>
            </select>
          </div>
        </div>
        <div class="table-wrap">
          <table id="datasets">
            <thead><tr><th>名称</th><th>状态</th><th class="num">条目数</th><th>最近同步</th><th>异常说明</th></tr></thead>
            <tbody>${rows || '<tr><td colspan="5" class="mut">无匹配数据集</td></tr>'}</tbody>
          </table>
        </div>`;
    }

    v.innerHTML = `
      <section class="sheet">
        <div class="sheet-head"><h2>在线服务配额</h2></div>
        ${onlineHtml}
      </section>
      <section class="sheet">
        ${dsHtml}
      </section>`;
    labelizeTables(v);
  }

  function adminGateUrl(k) {
    return location.origin + '/admin' + (k ? '?k=' + encodeURIComponent(k) : '');
  }

  function renderSecurityView() {
    const auth = overviewCache?.auth || {};
    const curKey = auth.gateKey || new URLSearchParams(location.search).get('k') || '';
    const curUrl = adminGateUrl(curKey);
    const v = byId('view');

    v.innerHTML = `
      <div class="sec-grid">
        <section class="sheet">
          <div class="sheet-head"><h2>隐身门禁链接 (参数 k)</h2></div>
          <p class="mut">未携带正确参数 k 访问 /admin 一律返回 404；轮换后旧链接立即作废，当前已登录会话自动同步新链接。</p>
          <div class="url-readout">
            <code id="secUrlNow">${h(curUrl)}</code>
            <button type="button" class="btn sm" data-action="copy-sec-url">复制</button>
          </div>
          <div class="sec-form">
            <input id="secTokPw" type="password" autocomplete="current-password" placeholder="输入当前口令以确认轮换">
            <div>
              <button type="button" class="btn sm danger" data-action="rotate-token">重置访问令牌</button>
              <span id="secTokMsg" class="mut" style="margin-left:8px"></span>
            </div>
          </div>
          <div id="secUrlNew" class="url-rotated" hidden></div>
        </section>

        <section class="sheet">
          <div class="sheet-head"><h2>管理员账号与口令</h2></div>
          <p class="mut" style="margin-bottom:10px">更新后立即写入服务端状态目录生效，无需重启进程。</p>
          <div class="sec-form">
            <input id="secUser" type="text" autocomplete="username" placeholder="管理员账号" value="${h(auth.username || 'admin')}">
            <input id="secOld" type="password" autocomplete="current-password" placeholder="当前口令">
            <input id="secNew" type="password" autocomplete="new-password" placeholder="新口令（至少 6 位非空白字符）">
            <input id="secNew2" type="password" autocomplete="new-password" placeholder="再次输入新口令">
            <div>
              <button type="button" class="btn sm primary" data-action="change-pw">保存更新</button>
              <span id="secPwMsg" class="mut" style="margin-left:8px"></span>
            </div>
          </div>
        </section>
      </div>

      <section class="sheet">
        <div class="sheet-head">
          <h2>防爆破锁定名单</h2>
          <span class="sheet-sub">单 IP 连错 3 次锁 1 小时 → 再错 3 次锁 3 小时 → 再错 3 次永久封禁</span>
        </div>
        <div id="ipBlocks"><p class="mut">加载中…</p></div>
      </section>

      <section class="sheet">
        <div class="sheet-head"><h2>登录审计流水</h2></div>
        <div id="loginLogs"><p class="mut">加载中…</p></div>
      </section>`;

    void loadSecurityTables();
  }

  async function loadSecurityTables() {
    const blocksEl = byId('ipBlocks');
    const logsEl = byId('loginLogs');
    if (!blocksEl || !logsEl) return;
    try {
      const [bRes, lRes] = await Promise.all([api('ip-blocks'), api('login-logs')]);
      if (bRes.status === 200 && bRes.data) {
        const items = bRes.data.items || [];
        const activeCnt = items.filter(x => x.permanent || x.strike > 0).length;
        const badge = byId('secNavBadge');
        badge.textContent = String(activeCnt);
        badge.hidden = activeCnt === 0;
        const rows = items.map(x => {
          const st = x.permanent
            ? '<span class="tag bad">永久封禁</span>'
            : x.blockedUntil
            ? `<span class="tag warn">锁定至 ${h(x.blockedUntil)}</span>`
            : `<span class="tag neutral">计数 (${h(x.failCount)}/3)</span>`;
          return `<tr>
            <td><code>${h(x.ip)}</code></td>
            <td>${h(x.location || '-')}</td>
            <td>${st}</td>
            <td class="num">${h(x.strike)}</td>
            <td class="mono">${h(x.updatedAt)}</td>
            <td><button type="button" class="btn sm" data-unblock="${h(x.ip)}">解除封锁</button></td>
          </tr>`;
        }).join('');
        blocksEl.innerHTML = `<div class="table-wrap"><table>
          <thead><tr><th>来源 IP</th><th>归属地</th><th>状态</th><th class="num">锁定轮次</th><th>最近触发</th><th>操作</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="6" class="mut">当前无异常锁定记录</td></tr>'}</tbody>
        </table></div>`;
        labelizeTables(blocksEl);
      }
      if (lRes.status === 200 && lRes.data) {
        const rows = (lRes.data.items || []).map(x => `<tr>
          <td class="mono">${h(x.time)}</td>
          <td><code>${h(x.ip || '-')}</code></td>
          <td>${h(x.location || '-')}</td>
          <td>${h(x.username || '-')}</td>
          <td>${x.ok ? '<span class="tag ok">通过</span>' : `<span class="tag bad">${h(x.reason || '拒绝')}</span>`}</td>
        </tr>`).join('');
        logsEl.innerHTML = `<div class="table-wrap"><table>
          <thead><tr><th>时间 (UTC+8)</th><th>来源 IP</th><th>归属地</th><th>账号</th><th>结果</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="mut">暂无登录记录</td></tr>'}</tbody>
        </table></div>`;
        labelizeTables(logsEl);
      }
    } catch {
      if (blocksEl.isConnected) blocksEl.innerHTML = '<p class="auth-err">读取安全记录失败</p>';
    }
  }

  async function openVisitorModal(ip) {
    if (!ip) return;
    const dlg = byId('ipDialog');
    byId('dName').textContent = `IP 档案 · ${ip}`;
    byId('dBody').innerHTML = '<p class="mut">正在读取离线情报与关联轨迹…</p>';
    if (!dlg.open) dlg.showModal();
    paintAutoRefreshLabel();

    try {
      const {status, data} = await api(`visitor?ip=${encodeURIComponent(ip)}`);
      if (status !== 200 || !data) {
        byId('dBody').innerHTML = '<p class="auth-err">无法读取该 IP 的档案信息</p>';
        return;
      }
      const s = data.summary || {};
      const hist = data.history || [];
      const rows = hist.map(r => {
        const [kLabel, kTone] = KIND_META[r.kind] || [r.kind, 'neutral'];
        return `<tr>
          <td class="mono">${h(r.time)}</td>
          <td><span class="tag ${kTone}">${h(kLabel)}</span></td>
          <td><code>${h(r.targetIp || r.ip)}</code></td>
          <td>${h([r.os, r.browser].filter(Boolean).join(' · '))}</td>
          <td class="num">${h(r.status)} · ${h(r.ms)}ms</td>
        </tr>`;
      }).join('');

      byId('dBody').innerHTML = `
        <div style="display:flex;justify-content:space-between;align-items:center;gap:8px;flex-wrap:wrap">
          <code>${h(data.ip)}</code>
          <a class="btn sm primary" style="text-decoration:none" href="/${encodeURIComponent(data.ip)}" target="_blank" rel="noreferrer">在前台执行完整评估 ↗</a>
        </div>
        <div class="dossier-kv">
          <div><span>地理位置</span><b>${h(s.location || '未知')}</b></div>
          <div><span>离线类型结论</span><b>${h(s.label || '未知')}</b></div>
          <div><span>自治系统 (ASN)</span><b>${h([s.asn, s.isp].filter(Boolean).join(' · ') || '未知')}</b></div>
          <div><span>宣告路由前缀</span><b class="mono">${h(s.prefix || '未知')}</b></div>
        </div>
        <h3 style="font-size:13px;margin-bottom:8px">近期关联请求（${hist.length} 条）</h3>
        <div class="table-wrap">
          <table class="matrix">
            <thead><tr><th>时间</th><th>动作</th><th>目标 IP</th><th>客户端</th><th class="num">耗时</th></tr></thead>
            <tbody>${rows || '<tr><td colspan="5" class="mut">内存环形缓冲中无关联请求</td></tr>'}</tbody>
          </table>
        </div>`;
    } catch {
      byId('dBody').innerHTML = '<p class="auth-err">网络异常，读取失败</p>';
    }
  }

  /* ---------- Navigation & Refresh ---------- */

  function navTo(view, params = {}, resetStack = false) {
    closeModal();
    if (resetStack) {
      navStack = [{view, params}];
    } else {
      const top = navStack[navStack.length - 1];
      if (top && top.view === view) navStack[navStack.length - 1] = {view, params};
      else navStack.push({view, params});
    }
    const subBar = byId('subBar');
    subBar.hidden = navStack.length <= 1;
    if (navStack.length > 1) {
      byId('subCrumb').textContent = `当前视图：${VIEW_TITLES[view] || view}`;
    }
    document.querySelectorAll('#topNav .tab[data-view]').forEach(el => {
      el.classList.toggle('active', el.dataset.view === view);
    });

    if (view === 'visits') {
      visitsState = {
        page: 1,
        size: 20,
        total: 0,
        q: params.q || '',
        kind: params.kind || '',
        from: params.from || '',
        to: params.to || '',
        today: Boolean(params.today),
        err: Boolean(params.err),
        sort: 'time',
        order: 'desc',
      };
      renderVisitsShell();
    } else if (view === 'analytics') {
      if (params.span) analyticsSpan = Number(params.span) || 7;
      renderAnalyticsView();
    } else if (view === 'sources') {
      renderSourcesView();
    } else if (view === 'security') {
      renderSecurityView();
    } else {
      renderDashboardView();
    }
  }

  function navBack() {
    if (navStack.length <= 1) return;
    navStack.pop();
    const prev = navStack[navStack.length - 1];
    navTo(prev.view, prev.params, false);
  }

  async function pullOverview(initial = false) {
    const current = ++generation;
    if (initial) {
      byId('bootNotice').hidden = false;
      byId('bootNotice').dataset.tone = 'info';
      byId('notice').textContent = '正在连接节点控制台…';
      byId('retry').hidden = true;
    }
    try {
      const {status, data, now} = await api('overview');
      if (current !== generation) return false;
      lastNow = now;
      if (status === 401) {
        showLogin(loggedIn ? '会话已过期，请重新登录。' : '');
        return false;
      }
      if (status !== 200 || !data || typeof data !== 'object' || Array.isArray(data)) {
        throw new Error('bad overview');
      }
      overviewCache = data;
      loggedIn = true;
      byId('loginPage').hidden = true;
      byId('bootNotice').hidden = true;
      byId('app').hidden = false;
      setBanner('');
      updateHeaderBadges(data.sources);
      return true;
    } catch {
      if (current !== generation) return false;
      if (!loggedIn) {
        byId('bootNotice').hidden = false;
        byId('bootNotice').dataset.tone = 'error';
        byId('notice').textContent = '无法读取管理后台，请稍后重试。';
        byId('retry').hidden = false;
      } else {
        setBanner('刷新失败，当前显示上次成功读取的数据。', true);
      }
      return false;
    }
  }

  function fmtClock(ms) {
    const d = new Date(ms);
    return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}:${String(d.getSeconds()).padStart(2, '0')}`;
  }

  function markRefreshed() {
    byId('refreshedAt').textContent = `${fmtClock(Date.now())} 同步`;
  }

  function autoRefreshPausedReason() {
    if (document.hidden) return '后台标签页';
    if (byId('ipDialog').open) return '查看档案中';
    const ae = document.activeElement;
    if (ae && /^(INPUT|SELECT|TEXTAREA)$/.test(ae.tagName) && ae.id !== 'autoRefreshChk') return '输入中';
    if (Date.now() - lastInteractAt < BROWSE_IDLE_MS) return '浏览操作中';
    if ((window.scrollY || document.documentElement.scrollTop || 0) > 6) return '向下滚动浏览中';
    return '';
  }

  function paintAutoRefreshLabel() {
    const sec = byId('arSec');
    const lab = byId('autoRefreshLabel');
    if (!sec || !lab) return;
    const on = Boolean(autoRefreshTimer);
    const reason = on ? autoRefreshPausedReason() : '';
    lab.classList.toggle('paused', Boolean(reason));
    sec.textContent = !on ? '暂停' : (reason ? '挂起' : `${arLeft}s`);
    lab.title = !on ? '勾选开启 10 秒自动同步' : (reason ? `已挂起：${reason}` : `${arLeft} 秒后自动同步`);
  }

  function stopAutoRefresh() {
    if (autoRefreshTimer) clearInterval(autoRefreshTimer);
    autoRefreshTimer = null;
  }

  function setAutoRefresh(on) {
    try { localStorage.setItem('ip_admin_ar', on ? '1' : '0'); } catch {}
    byId('autoRefreshChk').checked = Boolean(on);
    stopAutoRefresh();
    arLeft = AUTO_REFRESH_MS / 1000;
    if (!on) {
      paintAutoRefreshLabel();
      return;
    }
    autoRefreshTimer = setInterval(() => {
      if (!loggedIn) return;
      if (autoRefreshPausedReason()) {
        paintAutoRefreshLabel();
        return;
      }
      arLeft--;
      if (arLeft <= 0) {
        arLeft = AUTO_REFRESH_MS / 1000;
        void refreshCurrent(true);
      }
      paintAutoRefreshLabel();
    }, 1000);
    paintAutoRefreshLabel();
  }

  async function refreshCurrent(silent = false) {
    if (refreshing) return;
    refreshing = true;
    const btn = byId('refreshBtn');
    if (!silent) btn.disabled = true;
    let ok = false;
    try {
      const view = currentView();
      ok = await pullOverview(false);
      if (ok) {
        if (view === 'dashboard') renderDashboardView();
        else if (view === 'visits') await loadVisitsData();
        else if (view === 'analytics') renderAnalyticsView();
        else if (view === 'sources') renderSourcesView();
        else if (view === 'security') await loadSecurityTables();
      }
    } finally {
      refreshing = false;
      btn.disabled = false;
      if (ok) markRefreshed();
      arLeft = AUTO_REFRESH_MS / 1000;
      paintAutoRefreshLabel();
    }
  }

  /* ---------- Actions ---------- */

  async function handleChangePassword() {
    const username = byId('secUser').value.trim();
    const old_password = byId('secOld').value;
    const new_password = byId('secNew').value;
    const new2 = byId('secNew2').value;
    const msg = byId('secPwMsg');
    msg.style.color = 'var(--bad)';
    if (!old_password) { msg.textContent = '请输入当前口令'; return; }
    if (new_password.length < 6) { msg.textContent = '新口令至少 6 位'; return; }
    if (new_password !== new2) { msg.textContent = '两次输入的新口令不一致'; return; }
    try {
      const {status, data} = await api('change-password', {username, old_password, new_password});
      if (status === 200) {
        msg.style.color = 'var(--good)';
        msg.textContent = '已更新并持久化保存';
        byId('secOld').value = '';
        byId('secNew').value = '';
        byId('secNew2').value = '';
        if (overviewCache?.auth && data?.username) overviewCache.auth.username = data.username;
        toast('登录凭据已更新');
      } else {
        msg.textContent = data?.error || '更新失败';
      }
    } catch {
      msg.textContent = '网络异常，更新失败';
    }
  }

  async function handleRotateToken() {
    const pw = byId('secTokPw').value;
    const msg = byId('secTokMsg');
    msg.style.color = 'var(--bad)';
    if (!pw) { msg.textContent = '请输入当前口令确认'; return; }
    if (!window.confirm('确认轮换访问令牌 k？旧链接将立即返回 404，请保存生成的新链接。')) return;
    try {
      const {status, data} = await api('rotate-url-token', {password: pw});
      if (status === 200 && data?.url_token) {
        const newUrl = adminGateUrl(data.url_token);
        if (overviewCache?.auth) {
          overviewCache.auth.gateKey = data.url_token;
          overviewCache.auth.gated = true;
        }
        try { history.replaceState(history.state, '', `/admin?k=${encodeURIComponent(data.url_token)}`); } catch {}
        byId('secUrlNow').textContent = newUrl;
        byId('secTokPw').value = '';
        msg.style.color = 'var(--good)';
        msg.textContent = '已生成新令牌';
        const box = byId('secUrlNew');
        box.hidden = false;
        box.innerHTML = `新后台地址已生效（地址栏已同步更新）：<br><code>${h(newUrl)}</code>`;
        toast('访问令牌已轮换');
      } else {
        msg.textContent = data?.error || '轮换失败';
      }
    } catch {
      msg.textContent = '网络异常，轮换失败';
    }
  }

  async function doLogout() {
    const current = ++generation;
    byId('logout').disabled = true;
    try {
      const {status} = await api('logout', {});
      if (current !== generation) return;
      if (status !== 204 && status !== 401) {
        setBanner('退出未确认，请重试。', true);
        return;
      }
      showLogin('已退出登录。');
    } catch {
      if (current === generation) setBanner('退出未确认，请重试。', true);
    } finally {
      byId('logout').disabled = false;
    }
  }

  /* ---------- Event Delegation ---------- */

  ['scroll', 'wheel', 'touchmove', 'pointerdown', 'keydown'].forEach(ev => {
    document.addEventListener(ev, () => { lastInteractAt = Date.now(); }, {passive: true, capture: true});
  });

  byId('loginForm').addEventListener('submit', async ev => {
    ev.preventDefault();
    const current = ++generation;
    const uInput = byId('u');
    const pInput = byId('p');
    byId('submitLogin').disabled = true;
    byId('loginErr').textContent = '';
    try {
      const {status, data} = await api('login', {username: uInput.value.trim(), password: pInput.value});
      if (current !== generation) return;
      if (status === 204) {
        pInput.value = '';
        const ok = await pullOverview(true);
        if (ok) {
          navTo('dashboard', {}, true);
          markRefreshed();
          let arOn = true;
          try { arOn = localStorage.getItem('ip_admin_ar') !== '0'; } catch {}
          setAutoRefresh(arOn);
        }
        return;
      }
      byId('loginErr').textContent = status === 401
        ? '账号或密码不正确。'
        : status === 429
        ? (data?.error || '尝试过于频繁，请稍后再试。')
        : '登录失败，请稍后重试。';
      pInput.focus();
      pInput.select();
    } catch {
      if (current === generation) byId('loginErr').textContent = '无法连接控制台接口。';
    } finally {
      byId('submitLogin').disabled = false;
    }
  });

  byId('topNav').addEventListener('click', ev => {
    const tab = ev.target.closest('.tab[data-view]');
    if (tab) navTo(tab.dataset.view, {}, true);
  });

  byId('backBtn').addEventListener('click', navBack);
  byId('refreshBtn').addEventListener('click', () => void refreshCurrent(false));
  byId('retry').addEventListener('click', () => void boot());
  byId('logout').addEventListener('click', doLogout);
  byId('autoRefreshChk').addEventListener('change', ev => setAutoRefresh(ev.target.checked));
  byId('drawerClose').addEventListener('click', closeModal);
  byId('ipDialog').addEventListener('click', ev => {
    if (ev.target === byId('ipDialog')) closeModal();
  });

  byId('view').addEventListener('click', async ev => {
    const navEl = ev.target.closest('[data-nav]');
    if (navEl) {
      let params = {};
      try { params = JSON.parse(navEl.dataset.params || '{}'); } catch {}
      navTo(navEl.dataset.nav, params, false);
      return;
    }
    const actBtn = ev.target.closest('[data-action]');
    if (actBtn) {
      const act = actBtn.dataset.action;
      if (act === 'visits-search') {
        visitsState.q = byId('vSearch')?.value.trim() || '';
        visitsState.kind = byId('vKind')?.value || '';
        visitsState.from = byId('vFrom')?.value || '';
        visitsState.to = byId('vTo')?.value || '';
        visitsState.page = 1;
        renderVisitsShell();
      } else if (act === 'visits-reset') {
        navTo('visits', {}, false);
      } else if (act === 'visits-toggle-today') {
        visitsState.today = !visitsState.today;
        visitsState.page = 1;
        renderVisitsShell();
      } else if (act === 'visits-toggle-err') {
        visitsState.err = !visitsState.err;
        visitsState.page = 1;
        renderVisitsShell();
      } else if (act === 'copy-sec-url') {
        const txt = byId('secUrlNow')?.textContent || '';
        if (navigator.clipboard) {
          await navigator.clipboard.writeText(txt).catch(() => {});
          toast('链接已复制');
        }
      } else if (act === 'change-pw') {
        await handleChangePassword();
      } else if (act === 'rotate-token') {
        await handleRotateToken();
      }
      return;
    }
    const sortTh = ev.target.closest('th.sortable[data-sort]');
    if (sortTh) {
      const col = sortTh.dataset.sort;
      if (visitsState.sort === col) visitsState.order = visitsState.order === 'asc' ? 'desc' : 'asc';
      else { visitsState.sort = col; visitsState.order = 'desc'; }
      visitsState.page = 1;
      void loadVisitsData();
      return;
    }
    const pageBtn = ev.target.closest('.pager button[data-page]');
    if (pageBtn && !pageBtn.disabled) {
      visitsState.page = Number(pageBtn.dataset.page) || 1;
      void loadVisitsData();
      return;
    }
    const ipRow = ev.target.closest('[data-ip]');
    if (ipRow && ipRow.dataset.ip) {
      void openVisitorModal(ipRow.dataset.ip);
      return;
    }
    const cType = ev.target.closest('[data-chart-type]');
    if (cType) {
      analyticsType = cType.dataset.chartType;
      renderAnalyticsView();
      return;
    }
    const pill = ev.target.closest('.legend-btn[data-series]');
    if (pill) {
      const k = pill.dataset.series;
      if (!chartHidden.delete(k)) chartHidden.add(k);
      if (chartHidden.size >= 6) chartHidden.delete(k);
      renderAnalyticsView();
      return;
    }
    const unblock = ev.target.closest('[data-unblock]');
    if (unblock) {
      const ip = unblock.dataset.unblock;
      await api('ip-blocks/unblock', {ip});
      toast(`已解除 ${ip} 的锁定`);
      await loadSecurityTables();
    }
  });

  byId('view').addEventListener('change', ev => {
    if (ev.target.id === 'anaSpan') {
      analyticsSpan = Number(ev.target.value) || 7;
      renderAnalyticsView();
    } else if (ev.target.id === 'vKind') {
      visitsState.kind = ev.target.value;
      visitsState.page = 1;
      renderVisitsShell();
    } else if (ev.target.id === 'dsStatus') {
      dsFilter.status = ev.target.value;
      renderSourcesView();
    }
  });

  byId('view').addEventListener('input', ev => {
    if (ev.target.id === 'dsSearch') {
      const pos = ev.target.selectionStart;
      dsFilter.q = ev.target.value;
      renderSourcesView();
      const next = byId('dsSearch');
      if (next) {
        next.focus();
        if (typeof pos === 'number') next.setSelectionRange(pos, pos);
      }
    }
  });

  byId('view').addEventListener('keydown', ev => {
    if (ev.key === 'Enter' && ev.target.id === 'vSearch') {
      visitsState.q = ev.target.value.trim();
      visitsState.page = 1;
      renderVisitsShell();
    }
  });

  byId('view').addEventListener('mousemove', ev => {
    const svg = ev.target.closest('#plot');
    const tip = byId('chartTip');
    const line = byId('chartLine');
    if (!svg || !tip || !line || !chartGeom || !chartSeries.length) return;
    const rect = svg.getBoundingClientRect();
    const {W, padL, padR, band, bar, n, vis} = chartGeom;
    const vx = (ev.clientX - rect.left) * W / rect.width;
    let i = bar ? Math.round((vx - padL) / band - 0.5) : (n <= 1 ? 0 : Math.round((vx - padL) * (n - 1) / (W - padL - padR)));
    i = Math.max(0, Math.min(n - 1, i));
    const s = chartSeries[i];
    const cx = bar ? padL + band * (i + 0.5) : padL + (n <= 1 ? 0 : i * (W - padL - padR) / (n - 1));
    line.setAttribute('x1', String(cx));
    line.setAttribute('x2', String(cx));
    line.style.display = '';
    tip.innerHTML = `<div class="mono" style="color:var(--mut);margin-bottom:2px">${h(s.date)}</div>` +
      (s.covered
        ? vis.map(k => `<div><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${k.color};margin-right:6px"></span>${h(k.label)}：<strong class="mono">${fmtNum(s[k.k] || 0)}</strong></div>`).join('')
        : '<div>未采集</div>');
    tip.style.display = 'block';
    const px = cx * rect.width / W;
    const tw = tip.offsetWidth;
    tip.style.left = `${Math.max(4, Math.min(rect.width - tw - 4, px > rect.width / 2 ? px - tw - 12 : px + 12))}px`;
    tip.style.top = '8px';
  });

  byId('view').addEventListener('mouseleave', () => {
    const tip = byId('chartTip');
    const line = byId('chartLine');
    if (tip) tip.style.display = 'none';
    if (line) line.style.display = 'none';
  }, true);

  window.addEventListener('pagehide', () => {
    ++generation;
    stopAutoRefresh();
    byId('p').value = '';
  });

  async function boot() {
    const ok = await pullOverview(true);
    if (ok) {
      navTo('dashboard', {}, true);
      markRefreshed();
      let arOn = true;
      try { arOn = localStorage.getItem('ip_admin_ar') !== '0'; } catch {}
      setAutoRefresh(arOn);
    }
  }

  void boot();
})();
