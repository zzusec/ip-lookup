(() => {
  'use strict';
  const byId = id => document.getElementById(id);
  const fields = ['pageViews', 'lookups', 'errors'];
  const labels = ['页面访问', '成功查询', '失败查询'];
  const integer = value => Number.isSafeInteger(value) && value >= 0;
  const number = new Intl.NumberFormat('zh-CN');
  const clock = new Intl.DateTimeFormat('zh-CN', {timeZone: 'Asia/Shanghai', dateStyle: 'medium', timeStyle: 'short', hour12: false});
  const dayMs = 86400000;
  const cnDate = millis => new Date(millis + 8 * 3600000).toISOString().slice(0, 10);
  const isoDay = millis => new Date(millis).toISOString().slice(0, 10);
  const text = (tag, value) => { const node = document.createElement(tag); node.textContent = value; return node; };
  const stamp = raw => typeof raw === 'string' && /^\d{4}-\d{2}-\d{2}T.+(?:Z|[+-]\d{2}:\d{2})$/.test(raw) ? Date.parse(raw) : NaN;
  let generation = 0, days = null, span = 7;

  function announce(message, error = false) {
    byId('notice').textContent = message;
    byId('notice').dataset.tone = error ? 'error' : 'info';
  }

  async function api(path, body) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 12000);
    try {
      const response = await fetch(`/admin/api/${path}`, {
        method: body === undefined ? 'GET' : 'POST', body: body === undefined ? undefined : JSON.stringify(body),
        headers: body === undefined ? {Accept: 'application/json'} : {'Content-Type': 'application/json'},
        credentials: 'same-origin', cache: 'no-store', redirect: 'error', referrerPolicy: 'no-referrer', signal: controller.signal,
      });
      const fetched = Date.parse(response.headers.get('Date'));
      return {status: response.status, now: Number.isFinite(fetched) ? fetched : Date.now(),
        data: path === 'overview' && response.status === 200 ? await response.json() : null};
    } finally { clearTimeout(timer); }
  }

  function clearPrivate() {
    days = null; span = 7;
    byId('dashboard').hidden = true;
    byId('logout').hidden = true;
    byId('dayDetails').open = false;
    for (const id of ['asOf','coverage','totals','dayRows','datasets','online','plot','axis','datasetInfo','onlineInfo']) byId(id).replaceChildren();
  }

  function promptLogin(message = '') {
    clearPrivate();
    byId('login').hidden = false;
    byId('retry').hidden = true;
    byId('password').value = '';
    byId('password').focus();
    announce(message);
  }

  function series(usage, now) {
    if (!usage || usage.schema !== 1 || usage.site !== 'ip' || !Array.isArray(usage.days) || usage.days.length > 30) return null;
    const start = stamp(usage.startedAt), updated = stamp(usage.updatedAt);
    if (!Number.isFinite(start) || !Number.isFinite(updated) || updated < start) return null;
    const today = cnDate(now), since = cnDate(start);
    if (since > today) return null;
    const lookup = new Map();
    for (const row of usage.days) {
      const date = row?.date;
      if (typeof date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !Number.isFinite(Date.parse(date)) || isoDay(Date.parse(date)) !== date ||
          date < since || date > today || lookup.has(date) || !fields.every(key => integer(row[key]))) return null;
      lookup.set(date, fields.map(key => row[key]));
    }
    const end = Date.parse(today + 'T00:00:00Z');
    return Array.from({length: 30}, (_, index) => {
      const date = isoDay(end - (29 - index) * dayMs);
      return {date, values: date < since ? null : lookup.get(date) || [0, 0, 0]};
    });
  }

  function countRow(tbody, label, values) {
    const row = tbody.insertRow();
    const title = text('th', label);
    title.scope = 'row'; row.append(title);
    if (!values) {
      const missing = row.insertCell(); missing.colSpan = 3; missing.textContent = '未采集';
    } else {
      values.forEach(value => { row.insertCell().textContent = number.format(value); });
    }
  }

  function renderTrend() {
    byId('dayRows').replaceChildren();
    byId('plot').replaceChildren();
    byId('axis').replaceChildren();
    document.querySelectorAll('[data-span]').forEach(button => {
      button.disabled = !days;
      button.setAttribute('aria-pressed', String(Number(button.dataset.span) === span));
    });
    byId('trend').hidden = !days;
    byId('dayDetails').hidden = !days;
    if (!days) return;
    const selected = days.slice(-span);
    for (const row of [...selected].reverse()) countRow(byId('dayRows'), row.date, row.values);
    const high = Math.max(1, ...selected.flatMap(row => row.values || []));
    fields.forEach((field, index) => {
      const points = selected.flatMap((row, position) => row.values ? [[5 + position * 590 / (span - 1), 100 - row.values[index] * 95 / high]] : []);
      if (!points.length) return;
      const single = points.length === 1;
      const shape = document.createElementNS('http://www.w3.org/2000/svg', single ? 'circle' : 'polyline');
      shape.setAttribute('class', `series-${index}`);
      if (single) {
        shape.setAttribute('cx', points[0][0]); shape.setAttribute('cy', points[0][1]); shape.setAttribute('r', '2.5');
      } else shape.setAttribute('points', points.map(pair => pair.join(',')).join(' '));
      byId('plot').append(shape);
    });
    byId('axis').append(text('span', selected[0].date), text('span', selected.at(-1).date));
  }

  function renderUsage(usage, now) {
    days = series(usage, now);
    byId('totals').replaceChildren();
    byId('totals').closest('table').hidden = !days;
    if (!days) {
      byId('coverage').textContent = usage == null ? '未采集访问统计。' : '访问统计不可用，不能按零流量计算。';
    } else {
      let total = [];
      for (const [label, size] of [['今日', 1], ['近 7 天', 7], ['近 30 天', 30]]) {
        const covered = days.slice(-size).filter(row => row.values);
        total = fields.map((field, index) => covered.reduce((sum, row) => sum + row.values[index], 0));
        countRow(byId('totals'), label, total);
      }
      const since = cnDate(stamp(usage.startedAt));
      const empty = !total.some(Boolean) ? (since >= days[0].date ? '接入以来未记录到流量。' : '近 30 天未记录到流量。') : '';
      byId('coverage').textContent = `${empty}自 ${since} 起采集，按北京时间归日。查询按请求计数，不代表访客数。`;
    }
    renderTrend();
  }

  function sourceList(id, summary, list, render, empty) {
    byId(id).replaceChildren();
    if (!Array.isArray(list)) { byId(summary).textContent = '来源状态不可用。'; return; }
    byId(summary).textContent = list.length ? `${list.length} 个来源` : empty;
    for (const item of list) {
      if (!item || typeof item !== 'object') continue;
      const [label, details, bad] = render(item);
      const row = document.createElement('li');
      row.dataset.tone = bad ? 'error' : '';
      row.append(text('strong', label), text('small', details)); byId(id).append(row);
    }
  }

  function renderSources(sources) {
    sourceList('datasets', 'datasetInfo', sources?.datasets, item => {
      const status = ({ok: '可用', error: '错误', pending: '待加载'})[item.status] || '状态未知';
      const updated = stamp(item.updated_at);
      const description = [status, integer(item.entries) ? `${number.format(item.entries)} 条` : '', Number.isFinite(updated) ? `更新 ${clock.format(updated)}` : '', item.error];
      return [item.label || item.id || '未命名数据集', description.filter(Boolean).join(' · '), item.status === 'error'];
    }, '暂无已登记的数据集。');
    sourceList('online', 'onlineInfo', sources?.online, item => {
      const quota = item.quota ? `${item.quota} · 已用 ${integer(item.used) ? number.format(item.used) : '未知'}` : '未提供配额读数';
      const blocked = stamp(item.blocked_until);
      const limited = Number.isFinite(blocked) && blocked > Date.now();
      return [item.name || '未命名服务', limited ? `${quota} · 限流至 ${clock.format(blocked)}` : quota, limited];
    }, '暂无已登记的在线服务。');
  }

  async function refresh() {
    const current = ++generation;
    byId('refresh').disabled = true; byId('retry').hidden = true;
    announce('正在读取运营数据…');
    try {
      const {status, data, now} = await api('overview');
      if (current !== generation) return;
      if (status === 401) { promptLogin(byId('dashboard').hidden ? '' : '会话已过期，请重新登录。'); return; }
      if (status !== 200 || !data || typeof data !== 'object' || Array.isArray(data)) throw Error();
      byId('login').hidden = true; byId('logout').hidden = false; byId('dashboard').hidden = false;
      byId('asOf').textContent = `读取于 ${clock.format(now)} · 北京时间`;
      renderUsage(data.usage, now); renderSources(data.sources); announce('');
    } catch {
      if (current !== generation) return;
      const hidden = byId('dashboard').hidden;
      announce(hidden ? '无法读取管理后台，请稍后重试。' : '刷新失败，当前显示上次成功读取的数据。', true);
      byId('retry').hidden = !hidden;
    } finally { if (current === generation) byId('refresh').disabled = false; }
  }

  byId('loginForm').addEventListener('submit', async event => {
    event.preventDefault();
    const current = ++generation;
    const input = byId('password'); byId('submitLogin').disabled = true;
    try {
      const {status} = await api('login', {password: input.value});
      if (current !== generation) return;
      if (status === 204) { input.value = ''; byId('login').hidden = true; await refresh(); return; }
      announce(status === 401 ? '密码不正确。' : status === 429 ? '登录尝试过于频繁，请稍后再试。' : '登录失败，请稍后重试。', true);
      input.focus(); input.select();
    } catch { if (current === generation) announce('无法连接管理后台。', true); }
    finally { byId('submitLogin').disabled = false; }
  });

  byId('logout').addEventListener('click', async () => {
    const current = ++generation;
    byId('logout').disabled = true; byId('refresh').disabled = true;
    try {
      const {status} = await api('logout', {});
      if (current !== generation) return;
      if (status !== 204 && status !== 401) throw Error();
      promptLogin('已退出登录。');
    } catch { if (current === generation) announce('退出未确认，请重试。', true); }
    finally { byId('logout').disabled = false; byId('refresh').disabled = false; }
  });

  document.querySelectorAll('[data-span]').forEach(button => button.addEventListener('click', () => { span = Number(button.dataset.span); renderTrend(); }));
  const legend = document.querySelector('#trend figcaption');
  legend.replaceChildren(...labels.map((label, index) => { const item = text('span', label); item.className = `series-${index}`; return item; }));
  byId('refresh').addEventListener('click', refresh); byId('retry').addEventListener('click', refresh);
  window.addEventListener('pagehide', () => { ++generation; clearPrivate(); byId('password').value = ''; });
  window.addEventListener('pageshow', event => { if (event.persisted) void refresh(); });
  void refresh();
})();
