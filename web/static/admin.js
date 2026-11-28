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
    dashboard: '仪表盘',
    visits: '实时访问',
    analytics: '数据分析',
    sources: '数据源与配额',
    security: '账号安全',
  };

  const KIND_META = {
    view: ['网页访问', 'brand'],
    self_lookup: ['查本机 IP', 'ok'],
    target_lookup: ['查他人 IP', 'warn'],
    cli: ['终端 / JSON', 'gray'],
    probe: ['443 实测', 'brand'],
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
  let lastRefreshAt = 0;
  let lastInteractAt = 0;

  function toast(msg, ok = true) {
    const el = document.createElement('div');
    el.className = 'toast' + (ok ? '' : ' bad');
    el.textContent = msg;
    document.body.appendChild(el);
    setTimeout(() => el.classList.add('show'), 16);
    setTimeout(() => {
      el.classList.remove('show');
      setTimeout(() => el.remove(), 220);
    }, 2600);
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

  function cmpYest(todayVal, yestVal) {
    const t = Number(todayVal) || 0;
    const y = Number(yestVal) || 0;
    const diff = t - y;
    const arrow = diff > 0 ? `<span style="color:#16a34a">↑${fmtNum(diff)}</span>` : diff < 0 ? `<span style="color:#8a90a6">↓${fmtNum(Math.abs(diff))}</span>` : '<span style="color:#8a90a6">持平</span>';
    return `昨日 ${fmtNum(y)} · ${arrow}`;
  }

  function currentView() {
    return navStack.length ? navStack[navStack.length - 1].view : 'dashboard';
  }

  function toggleNav(open) {
    const sb = byId('sidebar');
    const mk = byId('navMask');
    const on = open === undefined ? !sb.classList.contains('open') : Boolean(open);
    sb.classList.toggle('open', on);
    mk.classList.toggle('open', on);
  }

  function closeDrawer() {
    byId('drawer').classList.remove('open');
    byId('mask').classList.remove('open');
    paintAutoRefreshLabel();
  }

  function showLogin(msg = '') {
    loggedIn = false;
    overviewCache = null;
    stopAutoRefresh();
    closeDrawer();
    byId('bootNotice').hidden = true;
    byId('app').hidden = true;
    byId('view').replaceChildren();
    byId('loginPage').hidden = false;
    byId('p').value = '';
    byId('loginErr').textContent = msg;
    byId('p').focus();
  }

  function updateSourceBadges(sources) {
    const dsErr = Array.isArray(sources?.datasets) ? sources.datasets.filter(d => d?.status === 'error').length : 0;
    const onLim = Array.isArray(sources?.online) ? sources.online.filter(o => {
      const b = stamp(o?.blocked_until);
      return Number.isFinite(b) && b > lastNow;
    }).length : 0;
    const total = dsErr + onLim;
    const badge = byId('sourcesNavBadge');
    badge.textContent = String(total);
    badge.classList.toggle('show', total > 0);
    const rb = byId('roleBadge');
    if (dsErr > 0) {
      rb.className = 'role-badge warn';
      rb.textContent = `${dsErr} 项数据集异常`;
    } else {
      rb.className = 'role-badge master';
      rb.textContent = '主节点 · 在线';
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
      v.innerHTML = '<div class="muted">加载中…</div>';
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
    const topRegion = Array.isArray(live.regions) && live.regions.length ? live.regions[0].name : '等待新请求采样';

    const card = (ic, bg, fg, label, val, subHtml, navView, navParams) => `
      <div class="metric" data-nav="${h(navView)}" data-params="${h(JSON.stringify(navParams || {}))}">
        <div class="ic" style="background:${bg};color:${fg}">${ic}</div>
        <div class="m-body">
          <div class="v">${h(val)}</div>
          <div class="l">${h(label)}</div>
          ${subHtml ? `<div class="cmp">${subHtml}</div>` : ''}
        </div>
        <div class="go">›</div>
      </div>`;

    let usageSummaryHtml = '';
    if (!series) {
      const msg = usage == null ? '未采集访问统计。' : '访问统计不可用，不能按零流量计算。';
      usageSummaryHtml = `<div class="panel"><div class="panel-head"><div class="title">请求量汇总</div></div><p id="coverage" class="muted">${h(msg)}</p><table id="totals" hidden></table></div>`;
    } else {
      const since = cnDate(stamp(usage.startedAt));
      const anyTraffic = s30.pageViews + s30.lookups + s30.errors > 0;
      const emptyMsg = !anyTraffic ? (since >= series[0].date ? '接入以来未记录到流量。' : '近 30 天未记录到流量。') : '';
      usageSummaryHtml = `
        <div class="panel">
          <div class="panel-head">
            <div class="title">时段流量汇总</div>
            <span id="coverage" class="muted">${h(emptyMsg)}自 ${h(since)} 起采集，按北京时间归日 · 实时明细仅驻留内存不写磁盘</span>
          </div>
          <table class="matrix">
            <thead><tr><th>时段</th><th class="num">独立访客</th><th class="num">页面访问</th><th class="num">成功查询</th><th class="num">终端 / JSON</th><th class="num">443 实测</th><th class="num">异常请求</th></tr></thead>
            <tbody id="totals">
              <tr><td><b>今日</b></td><td class="num"><b>${fmtNum(todayUV)}</b></td><td class="num"><b>${fmtNum(s1.pageViews)}</b></td><td class="num"><b>${fmtNum(s1.lookups)}</b></td><td class="num">${fmtNum(s1.cliLookups)}</td><td class="num">${fmtNum(s1.probes)}</td><td class="num">${fmtNum(s1.errors)}</td></tr>
              <tr><td>近 7 天</td><td class="num">${fmtNum(live.uv7d ?? s7.uv)}</td><td class="num">${fmtNum(s7.pageViews)}</td><td class="num">${fmtNum(s7.lookups)}</td><td class="num">${fmtNum(s7.cliLookups)}</td><td class="num">${fmtNum(s7.probes)}</td><td class="num">${fmtNum(s7.errors)}</td></tr>
              <tr><td>近 30 天</td><td class="num">${fmtNum(live.uv30d ?? s30.uv)}</td><td class="num">${fmtNum(s30.pageViews)}</td><td class="num">${fmtNum(s30.lookups)}</td><td class="num">${fmtNum(s30.cliLookups)}</td><td class="num">${fmtNum(s30.probes)}</td><td class="num">${fmtNum(s30.errors)}</td></tr>
            </tbody>
          </table>
        </div>`;
    }

    v.innerHTML = `
      <div class="sec-title">📊 今日实时</div>
      <div class="metrics">
        ${card('👀', '#eef0ff', '#6C63FF', '独立访客 (UV)', fmtNum(todayUV), cmpYest(todayUV, yestUV), 'visits', {today: true})}
        ${card('🌐', '#e8f7ee', '#16a34a', '页面访问 (PV)', fmtNum(todayRow.pageViews), cmpYest(todayRow.pageViews, yestRow.pageViews), 'visits', {today: true, kind: 'view'})}
        ${card('🔍', '#eef4ff', '#2563eb', '成功查询', fmtNum(todayRow.lookups), cmpYest(todayRow.lookups, yestRow.lookups), 'visits', {today: true})}
        ${card('🖥', '#f0eefe', '#7c3aed', '终端 / JSON 调用', fmtNum(todayRow.cliLookups), cmpYest(todayRow.cliLookups, yestRow.cliLookups), 'visits', {today: true, kind: 'cli_json'})}
        ${card('⚡', '#fff5e9', '#d97706', '443 连通实测', fmtNum(todayRow.probes), cmpYest(todayRow.probes, yestRow.probes), 'visits', {today: true, kind: 'probe'})}
        ${card('❌', '#fdeaea', '#dc2626', '异常与限流', fmtNum(todayRow.errors), cmpYest(todayRow.errors, yestRow.errors), 'visits', {today: true, err: true})}
      </div>

      <div class="sec-title">📈 累计规模 · 情报引擎</div>
      <div class="metrics">
        ${card('📅', '#eef4ff', '#2563eb', '近 7 天查询', fmtNum(s7.lookups), `页面访问 ${fmtNum(s7.pageViews)} · 访客 ${fmtNum(live.uv7d ?? s7.uv)}`, 'analytics', {span: 7})}
        ${card('🗓', '#f0eefe', '#7c3aed', '近 30 天查询', fmtNum(s30.lookups), `页面访问 ${fmtNum(s30.pageViews)} · 访客 ${fmtNum(live.uv30d ?? s30.uv)}`, 'analytics', {span: 30})}
        ${card('🔎', '#fdf2e0', '#d97706', '查他人 IP 次数', fmtNum(s30.targetLookups), '近 30 天查询外部指定 IP', 'visits', {kind: 'target_lookup'})}
        ${card('📡', '#e6f6f0', '#0d9488', '在线信誉源', onlineArr ? `${onlineOk} / ${onlineArr.length}` : '不可用', onlineLimited > 0 ? `<span style="color:#d97706">${onlineLimited} 个接口限流冷却中</span>` : '在线配额状态正常', 'sources', {})}
        ${card('🗂', '#eef0ff', '#6C63FF', '离线情报库', dsArr ? `${dsOk} / ${dsArr.length}` : '不可用', dsErr > 0 ? `<span style="color:#dc2626">${dsErr} 项加载错误</span>` : `共 ${fmtNum(dsEntries)} 条网段记录`, 'sources', {})}
        ${card('🌍', '#e9fbf0', '#16a34a', '活跃来源地区', fmtNum((live.regions || []).length), `首位：${h(topRegion)}`, 'analytics', {span: 30})}
      </div>
      ${usageSummaryHtml}`;
  }

  function renderVisitsShell() {
    const chips = [];
    if (visitsState.today) chips.push('今日');
    if (visitsState.err) chips.push('仅异常');
    if (visitsState.kind) {
      const km = {view: '网页访问', self_lookup: '查本机 IP', target_lookup: '查他人 IP', cli_json: '终端 / JSON', probe: '443 实测', error: '异常请求'};
      chips.push(km[visitsState.kind] || visitsState.kind);
    }
    if (visitsState.from || visitsState.to) chips.push(`${visitsState.from || '不限'} ~ ${visitsState.to || '不限'}`);

    const chipHtml = chips.length
      ? `<span class="filter-chip">${h(chips.join(' + '))} <button type="button" data-action="visits-reset" title="清除筛选">×</button></span>`
      : '';

    byId('view').innerHTML = `
      <div class="panel">
        <div class="panel-head">
          <div class="title">实时访问与查询流 ${chipHtml}</div>
          <div class="tools">
            <input id="vSearch" placeholder="搜索 IP / 地区 / ASN / 系统" value="${h(visitsState.q)}">
            <select id="vKind" aria-label="请求类型">
              <option value="">全部类型</option>
              <option value="view" ${visitsState.kind === 'view' ? 'selected' : ''}>网页访问</option>
              <option value="self_lookup" ${visitsState.kind === 'self_lookup' ? 'selected' : ''}>查本机 IP</option>
              <option value="target_lookup" ${visitsState.kind === 'target_lookup' ? 'selected' : ''}>查他人 IP</option>
              <option value="cli_json" ${visitsState.kind === 'cli_json' ? 'selected' : ''}>终端 / JSON</option>
              <option value="probe" ${visitsState.kind === 'probe' ? 'selected' : ''}>443 实测</option>
              <option value="error" ${visitsState.kind === 'error' ? 'selected' : ''}>异常请求</option>
            </select>
            <input type="date" id="vFrom" aria-label="开始日期" value="${h(visitsState.from)}">
            <input type="date" id="vTo" aria-label="结束日期" value="${h(visitsState.to)}">
            <button type="button" class="btn-ghost btn-sm quick-filter ${visitsState.today ? 'active' : ''}" data-action="visits-toggle-today">今日</button>
            <button type="button" class="btn-ghost btn-sm quick-filter ${visitsState.err ? 'active' : ''}" data-action="visits-toggle-err">仅异常</button>
            <button type="button" class="btn-primary btn-sm" data-action="visits-search">搜索</button>
            <button type="button" class="btn-ghost btn-sm" data-action="visits-reset">重置</button>
          </div>
        </div>
        <div class="muted" style="margin-bottom:10px">仅保留进程内存最近 1,000 条实时记录（不写入磁盘日志）· 点击任意行查看离线归属详情</div>
        <div id="visitsTable"><div class="muted">加载中…</div></div>
        <div id="visitsPager"></div>
      </div>`;
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
        box.innerHTML = '<div class="err">读取实时访问记录失败</div>';
        return;
      }
      visitsState.total = data.total || 0;
      const items = data.items || [];
      const arrow = col => (visitsState.sort === col ? (visitsState.order === 'asc' ? ' ▲' : ' ▼') : ' ↕');
      const rows = items.map(r => {
        const [kLabel, kTone] = KIND_META[r.kind] || [r.kind || '请求', 'gray'];
        const stBadge = r.status >= 400
          ? `<span class="badge bad">${h(r.status)}</span>`
          : `<span class="badge ok">${h(r.status)}</span>`;
        const loc = [r.location || '未知地区', [r.asn, r.isp].filter(Boolean).join(' ')].filter(Boolean).join(' · ');
        const tgt = r.targetIp && r.targetIp !== r.ip
          ? `<code>${h(r.targetIp)}</code>${r.targetLabel ? ` <span class="badge gray">${h(r.targetLabel)}</span>` : ''}`
          : `<span class="muted">本机</span>${r.targetLabel ? ` <span class="badge gray">${h(r.targetLabel)}</span>` : ''}`;
        return `<tr class="clickable" data-ip="${h(r.ip || r.targetIp || '')}">
          <td>${h(r.time)}</td>
          <td><code>${h(r.ip || '-')}</code></td>
          <td class="td-full"><div class="ellip" title="${h(loc)}">${h(loc)}</div></td>
          <td><span class="badge ${kTone}">${h(kLabel)}</span></td>
          <td>${tgt}</td>
          <td>${h([r.os, r.browser].filter(Boolean).join(' · ') || '-')}</td>
          <td class="num">${stBadge} <span class="muted">${h(r.ms)}ms</span></td>
          <td><button type="button" class="btn-ghost btn-sm" data-ip="${h(r.ip || r.targetIp || '')}">详情</button></td>
        </tr>`;
      }).join('');

      box.innerHTML = `<table>
        <thead><tr>
          <th class="sortable" data-sort="time">时间${arrow('time')}</th>
          <th>访客 IP</th>
          <th>归属地 / 运营商</th>
          <th>类型</th>
          <th>查询目标</th>
          <th>系统 / 客户端</th>
          <th class="sortable num" data-sort="ms">状态 / 耗时${arrow('ms')}</th>
          <th>操作</th>
        </tr></thead>
        <tbody>${rows || '<tr><td colspan="8" class="muted">暂无匹配的实时访问记录</td></tr>'}</tbody>
      </table>`;
      labelizeTables(box);
      renderPager(byId('visitsPager'), visitsState.page, visitsState.size, visitsState.total);
    } catch {
      if (box.isConnected) box.innerHTML = '<div class="err">网络异常，无法读取实时记录</div>';
    }
  }

  function renderPager(el, page, size, total) {
    if (!el) return;
    const pages = Math.max(1, Math.ceil(total / size));
    if (pages <= 1) {
      el.innerHTML = `<div class="pager"><span>共 ${fmtNum(total)} 条 · 每页 ${size} 条</span></div>`;
      return;
    }
    let btns = '';
    for (let p = Math.max(1, page - 2); p <= Math.min(pages, page + 2); p++) {
      btns += `<button type="button" class="${p === page ? 'active' : ''}" data-page="${p}">${p}</button>`;
    }
    el.innerHTML = `<div class="pager">
      <span>第 ${page} / ${pages} 页 · 共 ${fmtNum(total)} 条</span>
      <button type="button" data-page="${page - 1}" ${page <= 1 ? 'disabled' : ''}>上一页</button>
      ${btns}
      <button type="button" data-page="${page + 1}" ${page >= pages ? 'disabled' : ''}>下一页</button>
    </div>`;
  }

  function buildAnalyticsSvg(series) {
    const keys = [
      {k: 'pageViews', label: '页面访问', color: '#6C63FF'},
      {k: 'lookups', label: '成功查询', color: '#16a34a'},
      {k: 'uv', label: '独立访客', color: '#9333ea'},
      {k: 'cliLookups', label: '终端/JSON', color: '#2563eb'},
      {k: 'probes', label: '443 实测', color: '#d97706'},
      {k: 'errors', label: '异常请求', color: '#dc2626'},
    ];
    const vis = keys.filter(k => !chartHidden.has(k.k));
    const mob = window.innerWidth <= 640;
    const W = mob ? 430 : 920;
    const H = mob ? 250 : 250;
    const padL = 42, padR = 18, padT = 16, padB = 36;
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
      svg += `<line x1="${padL}" y1="${yy}" x2="${W - padR}" y2="${yy}" stroke="#eef0f4"/><text x="2" y="${yy + 4}" font-size="11" fill="#9aa0b4">${val}</text>`;
    });
    [0, Math.floor(n / 2), n - 1].forEach(i => {
      if (series[i]) svg += `<text x="${X(i)}" y="${H - 10}" font-size="11" fill="#9aa0b4" text-anchor="middle">${h(series[i].date.slice(5))}</text>`;
    });

    if (bar) {
      const bw = Math.max(2, Math.min(26, band * 0.72 / Math.max(vis.length, 1)));
      const y0 = Y(0);
      vis.forEach((k, ki) => series.forEach((s, i) => {
        if (!s.covered) return;
        const val = s[k.k] || 0;
        const x = X(i) - bw * vis.length / 2 + bw * ki;
        const y = Y(val);
        const hh = Math.max(val > 0 ? 1.5 : 0, y0 - y);
        svg += `<rect x="${x.toFixed(1)}" y="${y.toFixed(1)}" width="${bw.toFixed(1)}" height="${hh.toFixed(1)}" fill="${k.color}" rx="2"/>`;
      }));
    } else {
      vis.forEach(k => {
        const coveredPts = series.flatMap((s, i) => (s.covered ? [`${X(i).toFixed(1)},${Y(s[k.k] || 0).toFixed(1)}`] : []));
        if (coveredPts.length === 1) {
          const [cx, cy] = coveredPts[0].split(',');
          svg += `<circle cx="${cx}" cy="${cy}" r="3.5" fill="${k.color}"/>`;
        } else if (coveredPts.length > 1) {
          svg += `<polyline points="${coveredPts.join(' ')}" fill="none" stroke="${k.color}" stroke-width="2.2"/>`;
        }
      });
    }
    svg += `<line id="chartLine" x1="0" y1="${padT}" x2="0" y2="${H - padB}" stroke="#b8bece" stroke-dasharray="3 3" style="display:none"/>`;
    svg += '</svg>';

    const legend = `<div class="chart-legend">${keys.map(k => {
      const off = chartHidden.has(k.k);
      return `<span class="chart-pill" data-series="${k.k}" style="${off ? 'color:#b4b8c8;background:#f5f6fa' : `color:#3f4458;background:${k.color}16`}">
        <i style="background:${off ? '#d5d8e2' : k.color}"></i>${h(k.label)}
      </span>`;
    }).join('')}</div>`;

    return `<div class="chart-box" id="chartBox">${svg}<div class="chart-tip" id="chartTip"></div>${legend}</div>`;
  }

  function distPanelHtml(title, subtitle, items) {
    const list = Array.isArray(items) ? items : [];
    const maxReq = list.reduce((m, x) => Math.max(m, x.requests || 0), 1);
    const rows = list.map(x => {
      const w = Math.max(2, (x.requests || 0) / maxReq * 100);
      return `<tr>
        <td><b>${h(x.name)}</b></td>
        <td><div class="src-share"><div class="bar"><div class="bar-in" style="width:${w.toFixed(1)}%"></div></div></div></td>
        <td class="num">${fmtNum(x.visitors)}</td>
        <td class="num">${fmtNum(x.requests)}</td>
      </tr>`;
    }).join('');
    return `<div class="panel">
      <div class="panel-head"><div class="title">${h(title)} <span class="muted" style="font-weight:400">${h(subtitle)}</span></div></div>
      <table class="matrix">
        <thead><tr><th>名称</th><th>请求占比</th><th class="num">访客数</th><th class="num">请求数</th></tr></thead>
        <tbody>${rows || '<tr><td colspan="4" class="muted">暂无实时采样数据</td></tr>'}</tbody>
      </table>
    </div>`;
  }

  function renderAnalyticsView() {
    const v = byId('view');
    if (!overviewCache) {
      v.innerHTML = '<div class="muted">加载中…</div>';
      return;
    }
    const seriesAll = parseUsageSeries(overviewCache.usage, lastNow);
    const live = overviewCache.live || {};
    const selected = seriesAll ? seriesAll.slice(-analyticsSpan) : [];

    const dayRows = selected.slice().reverse().map(r => {
      if (!r.covered) {
        return `<tr><td>${h(r.date)}</td><td colspan="6" class="muted">未采集</td></tr>`;
      }
      return `<tr>
        <td>${h(r.date)}</td>
        <td class="num">${fmtNum(r.uv)}</td>
        <td class="num">${fmtNum(r.pageViews)}</td>
        <td class="num">${fmtNum(r.lookups)}</td>
        <td class="num">${fmtNum(r.cliLookups)}</td>
        <td class="num">${fmtNum(r.probes)}</td>
        <td class="num">${fmtNum(r.errors)}</td>
      </tr>`;
    }).join('');

    v.innerHTML = `
      <div class="panel">
        <div class="panel-head">
          <div class="title">流量与查询趋势（近 ${analyticsSpan} 天）</div>
          <div class="tools">
            <select id="anaSpan" aria-label="统计周期">
              ${[7, 14, 30].map(d => `<option value="${d}" ${analyticsSpan === d ? 'selected' : ''}>近 ${d} 天</option>`).join('')}
            </select>
            <button type="button" class="btn-ghost btn-sm ${analyticsType === 'line' ? 'quick-filter active' : ''}" data-chart-type="line">折线图</button>
            <button type="button" class="btn-ghost btn-sm ${analyticsType === 'bar' ? 'quick-filter active' : ''}" data-chart-type="bar">柱状图</button>
          </div>
        </div>
        ${seriesAll ? buildAnalyticsSvg(selected) : '<p class="muted">暂无可用趋势数据。</p>'}
        ${seriesAll ? `<details id="dayDetails" style="margin-top:14px"><summary class="ulink">查看每日数值</summary>
          <table class="matrix" style="margin-top:10px">
            <thead><tr><th>日期</th><th class="num">独立访客</th><th class="num">页面访问</th><th class="num">成功查询</th><th class="num">终端/JSON</th><th class="num">443 实测</th><th class="num">失败查询</th></tr></thead>
            <tbody id="dayRows">${dayRows}</tbody>
          </table></details>` : ''}
      </div>
      ${distPanelHtml('🌍 来访国家 / 地区分布', '实时内存采样', live.regions)}
      ${distPanelHtml('🏢 热门运营商 / ASN 分布', '实时内存采样', live.asns)}
      ${distPanelHtml('💻 客户端与系统分布', '已兼容 iOS 26/27+ 冻结 UA 还原', live.clients)}`;
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
      v.innerHTML = '<div class="muted">加载中…</div>';
      return;
    }
    const sources = overviewCache.sources || {};
    const online = Array.isArray(sources.online) ? sources.online : null;
    const datasets = Array.isArray(sources.datasets) ? sources.datasets : null;

    let onlineHtml = '';
    if (!online) {
      onlineHtml = '<p id="onlineInfo" class="muted">来源状态不可用。</p>';
    } else if (!online.length) {
      onlineHtml = '<p id="onlineInfo" class="muted">暂无已登记的在线服务。</p>';
    } else {
      const cards = online.map(item => {
        const blocked = stamp(item.blocked_until);
        const limited = Number.isFinite(blocked) && blocked > lastNow;
        const qp = parseQuotaPair(item.quota, item.used);
        const badge = limited
          ? `<span class="badge warn">限流至 ${h(bjClock.format(blocked))}</span>`
          : '<span class="badge ok">正常可用</span>';
        const barTone = limited ? 'bad' : qp && qp.pct >= 80 ? 'warn' : '';
        const quotaTxt = item.quota
          ? `${item.quota} · 已用 ${integer(item.used) ? fmtNum(item.used) : '未知'}`
          : '公共免钥 / 未设固定日配额';
        return `<div class="svc-card">
          <div class="svc-head">
            <div class="svc-title">${h(item.name || '未命名服务')}</div>
            ${badge}
          </div>
          <div class="bar-cap"><span>${h(quotaTxt)}</span>${qp ? `<b>${qp.pct.toFixed(0)}%</b>` : ''}</div>
          ${qp ? `<div class="bar"><div class="bar-in ${barTone}" style="width:${qp.pct.toFixed(1)}%"></div></div>` : ''}
        </div>`;
      }).join('');
      onlineHtml = `<div id="onlineInfo" class="muted">共 ${online.length} 个在线信誉与路由数据源</div><div id="online" class="svc-grid">${cards}</div>`;
    }

    let dsHtml = '';
    if (!datasets) {
      dsHtml = '<p id="datasetInfo" class="muted">来源状态不可用。</p>';
    } else if (!datasets.length) {
      dsHtml = '<p id="datasetInfo" class="muted">暂无已登记的数据集。</p>';
    } else {
      const kw = dsFilter.q.trim().toLowerCase();
      const filtered = datasets.filter(d => {
        if (dsFilter.status && d.status !== dsFilter.status) return false;
        if (kw && !String((d.label || '') + ' ' + (d.id || '') + ' ' + (d.error || '')).toLowerCase().includes(kw)) return false;
        return true;
      });
      const rows = filtered.map(item => {
        const stBadge = item.status === 'ok'
          ? '<span class="badge ok">可用</span>'
          : item.status === 'error'
          ? '<span class="badge bad">错误</span>'
          : '<span class="badge warn">待加载</span>';
        const upd = stamp(item.updated_at);
        return `<tr>
          <td><b>${h(item.label || item.id || '未命名数据集')}</b></td>
          <td>${stBadge}</td>
          <td class="num">${integer(item.entries) ? fmtNum(item.entries) + ' 条' : '-'}</td>
          <td>${Number.isFinite(upd) ? h(bjClock.format(upd)) : '-'}</td>
          <td class="td-full">${item.error ? `<span style="color:var(--bad)">${h(item.error)}</span>` : '<span class="muted">—</span>'}</td>
        </tr>`;
      }).join('');
      dsHtml = `
        <div class="panel-head">
          <div class="title">离线情报库与路由表 <span id="datasetInfo" class="muted" style="font-weight:400">${datasets.length} 个数据集</span></div>
          <div class="tools">
            <input id="dsSearch" placeholder="搜索数据集名称" value="${h(dsFilter.q)}">
            <select id="dsStatus" aria-label="数据集状态">
              <option value="">全部状态</option>
              <option value="error" ${dsFilter.status === 'error' ? 'selected' : ''}>仅看错误</option>
              <option value="ok" ${dsFilter.status === 'ok' ? 'selected' : ''}>正常可用</option>
            </select>
          </div>
        </div>
        <table id="datasets">
          <thead><tr><th>数据集名称</th><th>状态</th><th class="num">条目规模</th><th>最近更新</th><th>异常详情</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="muted">没有匹配的数据集</td></tr>'}</tbody>
        </table>`;
    }

    v.innerHTML = `
      <div class="panel">
        <div class="panel-head"><div class="title">在线服务与配额监控</div></div>
        ${onlineHtml}
      </div>
      <div class="panel">
        ${dsHtml}
      </div>`;
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
      <div class="panel">
        <div class="panel-head"><div class="title">后台访问链接（登录令牌 k）</div></div>
        <div class="muted" style="margin-bottom:8px">${curKey ? '未携带正确令牌 k 访问 /admin 将直接返回 404 隐身；重置后<b>旧链接立即失效</b>，当前已登录会话不受影响。' : '当前尚未启用 URL 隐身令牌 k，点击下方按钮可立即生成专属 ?k= 隐身后台链接。'}</div>
        <div style="margin-bottom:12px">
          当前访问链接：<br>
          <span id="secUrlNow" class="sec-url-box">${h(curUrl)}</span>
          <button type="button" class="btn-ghost btn-sm" data-action="copy-sec-url">复制链接</button>
        </div>
        <div class="sec-form">
          <input id="secTokPw" type="password" autocomplete="current-password" placeholder="输入当前登录密码确认">
          <div>
            <button type="button" class="btn-danger btn-sm" data-action="rotate-token">重置访问令牌（换新链接）</button>
            <span id="secTokMsg" class="muted" style="margin-left:8px"></span>
          </div>
        </div>
        <div id="secUrlNew" class="sec-url-ok" hidden></div>
      </div>

      <div class="panel">
        <div class="panel-head"><div class="title">修改管理员账号与登录密码</div></div>
        <div class="muted" style="margin-bottom:12px">修改后自动加密持久化至服务端状态目录，立即生效无需重启服务。</div>
        <div class="sec-form">
          <input id="secUser" type="text" autocomplete="username" placeholder="管理员账号" value="${h(auth.username || 'admin')}">
          <input id="secOld" type="password" autocomplete="current-password" placeholder="当前密码">
          <input id="secNew" type="password" autocomplete="new-password" placeholder="新密码（至少 6 位非空白字符）">
          <input id="secNew2" type="password" autocomplete="new-password" placeholder="确认新密码">
          <div>
            <button type="button" class="btn-primary btn-sm" data-action="change-pw">保存新密码</button>
            <span id="secPwMsg" class="muted" style="margin-left:8px"></span>
          </div>
        </div>
      </div>

      <div class="panel">
        <div class="panel-head">
          <div class="title">登录防护 <span class="muted" style="font-weight:400">（同一 IP 连错 3 次锁 1 小时 → 再错 3 次锁 3 小时 → 再错 3 次永久封锁）</span></div>
        </div>
        <div id="ipBlocks"><div class="muted">加载中…</div></div>
      </div>

      <div class="panel">
        <div class="panel-head"><div class="title">后台登录记录</div></div>
        <div id="loginLogs"><div class="muted">加载中…</div></div>
      </div>`;

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
        byId('secNavBadge').textContent = String(items.filter(x => x.permanent || x.strike > 0).length);
        byId('secNavBadge').classList.toggle('show', items.some(x => x.permanent || x.strike > 0));
        const rows = items.map(x => {
          const st = x.permanent
            ? '<span class="badge bad">永久封锁</span>'
            : x.blockedUntil
            ? `<span class="badge warn">锁定至 ${h(x.blockedUntil)}</span>`
            : `<span class="badge gray">失败计数 (${h(x.failCount)}/3)</span>`;
          return `<tr>
            <td><code>${h(x.ip)}</code></td>
            <td>${h(x.location || '-')}</td>
            <td>${st}</td>
            <td class="num">${h(x.strike)}</td>
            <td>${h(x.updatedAt)}</td>
            <td><button type="button" class="btn-ghost btn-sm" data-unblock="${h(x.ip)}">解除封锁</button></td>
          </tr>`;
        }).join('');
        blocksEl.innerHTML = `<table>
          <thead><tr><th>来源 IP</th><th>归属地</th><th>状态</th><th class="num">累计锁定轮次</th><th>最近触发</th><th>操作</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="6" class="muted">当前无异常锁定或封锁记录</td></tr>'}</tbody>
        </table>`;
        labelizeTables(blocksEl);
      }
      if (lRes.status === 200 && lRes.data) {
        const rows = (lRes.data.items || []).map(x => `<tr>
          <td>${h(x.time)}</td>
          <td><code>${h(x.ip || '-')}</code></td>
          <td>${h(x.location || '-')}</td>
          <td>${h(x.username || '-')}</td>
          <td>${x.ok ? '<span class="badge ok">登录成功</span>' : `<span class="badge bad">${h(x.reason || '失败')}</span>`}</td>
        </tr>`).join('');
        logsEl.innerHTML = `<table>
          <thead><tr><th>时间 (北京时间)</th><th>来源 IP</th><th>归属地</th><th>尝试账号</th><th>结果</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="muted">暂无登录审计记录</td></tr>'}</tbody>
        </table>`;
        labelizeTables(logsEl);
      }
    } catch {
      if (blocksEl.isConnected) blocksEl.innerHTML = '<div class="err">读取安全记录失败</div>';
    }
  }

  async function openVisitorDrawer(ip) {
    if (!ip) return;
    byId('dName').textContent = `IP 详情 · ${ip}`;
    byId('dBody').innerHTML = '<div class="muted">正在查询离线归属与访问轨迹…</div>';
    byId('mask').classList.add('open');
    byId('drawer').classList.add('open');
    paintAutoRefreshLabel();

    try {
      const {status, data} = await api(`visitor?ip=${encodeURIComponent(ip)}`);
      if (status !== 200 || !data) {
        byId('dBody').innerHTML = '<div class="err">无法读取该 IP 的详情信息</div>';
        return;
      }
      const s = data.summary || {};
      const hist = data.history || [];
      const rows = hist.map(r => {
        const [kLabel, kTone] = KIND_META[r.kind] || [r.kind, 'gray'];
        return `<tr>
          <td>${h(r.time)}</td>
          <td><span class="badge ${kTone}">${h(kLabel)}</span></td>
          <td><code>${h(r.targetIp || r.ip)}</code></td>
          <td>${h([r.os, r.browser].filter(Boolean).join(' · '))}</td>
          <td class="num">${h(r.status)} · ${h(r.ms)}ms</td>
        </tr>`;
      }).join('');

      byId('dBody').innerHTML = `
        <div style="margin-bottom:14px;display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">
          <code>${h(data.ip)}</code>
          <a class="btn-primary btn-sm" style="text-decoration:none" href="/${encodeURIComponent(data.ip)}" target="_blank" rel="noreferrer">在前台完整检测此 IP ↗</a>
        </div>
        <div class="kv-grid">
          <div class="kv-item"><span>地理位置</span><b>${h(s.location || '未知')}</b></div>
          <div class="kv-item"><span>离线类型判定</span><b>${h(s.label || '未知')}</b></div>
          <div class="kv-item"><span>自治系统 (ASN)</span><b>${h([s.asn, s.isp].filter(Boolean).join(' · ') || '未知')}</b></div>
          <div class="kv-item"><span>BGP / 路由前缀</span><b>${h(s.prefix || '未知')}</b></div>
        </div>
        <div class="sec-title" style="margin-top:8px">最近关联请求（${hist.length} 条）</div>
        <table>
          <thead><tr><th>时间</th><th>动作</th><th>目标 IP</th><th>客户端</th><th class="num">耗时</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="5" class="muted">内存环形缓冲中暂无该 IP 的关联记录</td></tr>'}</tbody>
        </table>`;
    } catch {
      byId('dBody').innerHTML = '<div class="err">网络错误，无法读取详情</div>';
    }
  }

  /* ---------- Navigation & Refresh ---------- */

  function navTo(view, params = {}, resetStack = false) {
    toggleNav(false);
    closeDrawer();
    if (resetStack) {
      navStack = [{view, params}];
    } else {
      const top = navStack[navStack.length - 1];
      if (top && top.view === view) navStack[navStack.length - 1] = {view, params};
      else navStack.push({view, params});
    }
    byId('backBtn').hidden = navStack.length <= 1;
    byId('pageTitleText').textContent = VIEW_TITLES[view] || '运营后台';
    document.querySelectorAll('#sideNav .nav-item[data-view]').forEach(el => {
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
      byId('notice').textContent = '正在核对管理会话…';
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
      byId('footHost').textContent = location.host || '在线';
      setBanner('');
      updateSourceBadges(data.sources);
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
    lastRefreshAt = Date.now();
    const el = byId('refreshedAt');
    el.innerHTML = `${h(fmtClock(lastRefreshAt))}<span class="upd-txt"> 更新</span>`;
    el.classList.remove('flash');
    void el.offsetWidth;
    el.classList.add('flash');
  }

  function autoRefreshPausedReason() {
    if (document.hidden) return '页面在后台';
    if (byId('drawer').classList.contains('open')) return '正在查看详情';
    const ae = document.activeElement;
    if (ae && /^(INPUT|SELECT|TEXTAREA)$/.test(ae.tagName) && ae.id !== 'autoRefreshChk') return '正在输入';
    if (Date.now() - lastInteractAt < BROWSE_IDLE_MS) return '正在浏览';
    if ((window.scrollY || document.documentElement.scrollTop || 0) > 6) return '正在浏览';
    return '';
  }

  function paintAutoRefreshLabel() {
    const sec = byId('arSec');
    const lab = byId('autoRefreshLabel');
    if (!sec || !lab) return;
    const on = Boolean(autoRefreshTimer);
    const reason = on ? autoRefreshPausedReason() : '';
    lab.classList.toggle('paused', Boolean(reason));
    sec.textContent = !on ? '10s' : (reason ? '暂停' : `${arLeft}s`);
    lab.title = !on ? '开启后每 10 秒自动刷新当前页数据' : (reason ? `自动刷新已暂停：${reason}` : `${arLeft} 秒后自动刷新`);
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
    const started = Date.now();
    if (!silent) {
      btn.classList.add('busy');
      btn.disabled = true;
    }
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
      const wait = silent ? 0 : Math.max(0, 260 - (Date.now() - started));
      setTimeout(() => {
        refreshing = false;
        btn.classList.remove('busy');
        btn.disabled = false;
        if (ok) markRefreshed();
        arLeft = AUTO_REFRESH_MS / 1000;
        paintAutoRefreshLabel();
      }, wait);
    }
  }

  /* ---------- Actions & Event Delegation ---------- */

  async function handleChangePassword() {
    const username = byId('secUser').value.trim();
    const old_password = byId('secOld').value;
    const new_password = byId('secNew').value;
    const new2 = byId('secNew2').value;
    const msg = byId('secPwMsg');
    msg.style.color = 'var(--bad)';
    if (!old_password) { msg.textContent = '请输入当前密码'; return; }
    if (new_password.length < 6) { msg.textContent = '新密码至少 6 位'; return; }
    if (new_password !== new2) { msg.textContent = '两次输入的新密码不一致'; return; }
    try {
      const {status, data} = await api('change-password', {username, old_password, new_password});
      if (status === 200) {
        msg.style.color = 'var(--ok)';
        msg.textContent = '密码已修改并持久化保存';
        byId('secOld').value = '';
        byId('secNew').value = '';
        byId('secNew2').value = '';
        if (overviewCache?.auth && data?.username) overviewCache.auth.username = data.username;
        toast('登录密码已更新');
      } else {
        msg.textContent = data?.error || '修改失败';
      }
    } catch {
      msg.textContent = '网络错误，修改失败';
    }
  }

  async function handleRotateToken() {
    const pw = byId('secTokPw').value;
    const msg = byId('secTokMsg');
    msg.style.color = 'var(--bad)';
    if (!pw) { msg.textContent = '请输入当前密码确认'; return; }
    if (!window.confirm('确认重置后台访问令牌 k？旧的后台链接将立即返回 404 失效，请务必收藏新链接。')) return;
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
        msg.style.color = 'var(--ok)';
        msg.textContent = '已重置';
        const box = byId('secUrlNew');
        box.hidden = false;
        box.innerHTML = `✅ 新的后台访问网址（旧网址已立即失效，地址栏已同步更新）：<br><code>${h(newUrl)}</code>`;
        toast('已生成新的 ?k= 访问链接');
      } else {
        msg.textContent = data?.error || '重置失败';
      }
    } catch {
      msg.textContent = '网络错误，重置失败';
    }
  }

  async function doLogout() {
    const current = ++generation;
    byId('logout').disabled = true;
    byId('sidebarLogout').disabled = true;
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
      byId('sidebarLogout').disabled = false;
    }
  }

  /* ---------- Event Listeners ---------- */

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
        ? (data?.error || '登录尝试过于频繁，请稍后再试。')
        : '登录失败，请稍后重试。';
      pInput.focus();
      pInput.select();
    } catch {
      if (current === generation) byId('loginErr').textContent = '无法连接管理后台。';
    } finally {
      byId('submitLogin').disabled = false;
    }
  });

  byId('sideNav').addEventListener('click', ev => {
    const item = ev.target.closest('.nav-item[data-view]');
    if (item) navTo(item.dataset.view, {}, true);
  });
  byId('sideNav').addEventListener('keydown', ev => {
    if (ev.key !== 'Enter' && ev.key !== ' ') return;
    const item = ev.target.closest('.nav-item[data-view]');
    if (item) { ev.preventDefault(); navTo(item.dataset.view, {}, true); }
  });

  byId('menuBtn').addEventListener('click', () => toggleNav());
  byId('navMask').addEventListener('click', () => toggleNav(false));
  byId('backBtn').addEventListener('click', navBack);
  byId('refreshBtn').addEventListener('click', () => void refreshCurrent(false));
  byId('retry').addEventListener('click', () => void boot());
  byId('logout').addEventListener('click', doLogout);
  byId('sidebarLogout').addEventListener('click', doLogout);
  byId('autoRefreshChk').addEventListener('change', ev => setAutoRefresh(ev.target.checked));
  byId('mask').addEventListener('click', closeDrawer);
  byId('drawerClose').addEventListener('click', closeDrawer);
  document.addEventListener('keydown', ev => { if (ev.key === 'Escape') closeDrawer(); });

  byId('view').addEventListener('click', async ev => {
    const metric = ev.target.closest('.metric[data-nav]');
    if (metric) {
      let params = {};
      try { params = JSON.parse(metric.dataset.params || '{}'); } catch {}
      navTo(metric.dataset.nav, params, false);
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
          toast('后台链接已复制');
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
      void openVisitorDrawer(ipRow.dataset.ip);
      return;
    }
    const cType = ev.target.closest('[data-chart-type]');
    if (cType) {
      analyticsType = cType.dataset.chartType;
      renderAnalyticsView();
      return;
    }
    const pill = ev.target.closest('.chart-pill[data-series]');
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
      toast(`已解除 ${ip} 的封锁`);
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
    tip.innerHTML = `<div style="opacity:.75;margin-bottom:2px">${h(s.date)}</div>` +
      (s.covered
        ? vis.map(k => `<div><span style="display:inline-block;width:8px;height:8px;border-radius:2px;background:${k.color};margin-right:6px"></span>${h(k.label)}：<b>${fmtNum(s[k.k] || 0)}</b></div>`).join('')
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
