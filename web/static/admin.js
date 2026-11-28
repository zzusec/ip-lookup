/* IP Lookup — Stealth ?k= Admin Analytics, Live IP Stream & Source Health Console */
(function () {
  'use strict';

  // Apply persisted light/dark theme immediately before paint
  try {
    const saved = localStorage.getItem('iplookup:admin:theme');
    if (saved === 'dark' || (!saved && window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches && false)) {
      document.documentElement.classList.add('dark');
    }
  } catch (e) {}

  const $ = (s, root = document) => root.querySelector(s);
  const $$ = (s, root = document) => Array.from(root.querySelectorAll(s));
  const esc = s => String(s ?? '').replace(/[&<>"]/g, c => ({'&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;'})[c]);

  let URL_KEY = (() => {
    try { return (new URLSearchParams(location.search).get('k') || '').trim(); } catch (e) { return ''; }
  })();

  let REG_ZH = null;
  try { REG_ZH = new Intl.DisplayNames(['zh-CN'], {type: 'region'}); } catch (e) {}

  function flagEmoji(cc) {
    if (!cc || !/^[A-Za-z]{2}$/.test(cc)) return '🌐';
    const u = cc.toUpperCase() === 'TW' ? 'CN' : cc.toUpperCase();
    return String.fromCodePoint(0x1F1E6 + u.charCodeAt(0) - 65, 0x1F1E6 + u.charCodeAt(1) - 65);
  }

  function countryName(cc, fallback = '') {
    if (fallback) return fallback;
    if (!cc) return '';
    const u = String(cc).toUpperCase();
    if (u === 'TW') return '中国台湾';
    if (u === 'HK') return '中国香港';
    if (u === 'MO') return '中国澳门';
    try { return (REG_ZH && REG_ZH.of(u)) || u; } catch (e) { return u; }
  }

  function chinaDayFromDate(dt) {
    return new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Asia/Shanghai',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
    }).format(dt);
  }

  function shiftChinaDay(ymd, deltaDays) {
    const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(ymd);
    if (!m) return ymd;
    const d = new Date(Date.UTC(Number(m[1]), Number(m[2]) - 1, Number(m[3]) + deltaDays, 12, 0, 0));
    return d.toISOString().slice(0, 10);
  }

  function shortTime(s) {
    if (!s) return '–';
    return String(s).length >= 19 ? String(s).slice(5) : String(s);
  }

  function toast(msg) {
    const el = $('#admToast');
    if (!el) return;
    el.textContent = msg;
    el.hidden = false;
    clearTimeout(toast._t);
    toast._t = setTimeout(() => { el.hidden = true; }, 2400);
  }

  async function copyText(txt, label = '已复制') {
    try {
      await navigator.clipboard.writeText(txt);
      toast(label);
    } catch (e) {
      toast('浏览器限制剪贴板，请手动复制');
    }
  }

  const STATE = {
    tab: 'visits',
    host: '',
    day: '',
    kind: '',
    errOnly: false,
    q: '',
    page: 1,
    size: 40,
    serverNow: null,
    overview: null,
    hasLoadedOnce: false,
  };

  function authHeaders(extra = {}) {
    return URL_KEY ? {...extra, 'X-Admin-Key': URL_KEY} : extra;
  }

  function showNotice(msg) {
    const bar = $('#admNoticeBar');
    if (!bar) return;
    if (!msg) {
      bar.hidden = true;
      bar.textContent = '';
    } else {
      bar.hidden = false;
      bar.textContent = msg;
    }
  }

  function showViewState(mode, username = '', loginMessage = '') {
    const loginEl = $('#loginView');
    const hdrEl = $('#admHeader');
    const dashEl = $('#dashView');
    const errEl = $('#loadErrorView');

    if (loginEl) loginEl.hidden = mode !== 'login';
    if (hdrEl) hdrEl.hidden = mode === 'login';
    if (dashEl) dashEl.hidden = mode !== 'dash';
    if (errEl) errEl.hidden = mode !== 'error';

    const uBadge = $('#admUserBadge');
    if (uBadge) {
      uBadge.hidden = !(mode !== 'login' && username);
      if (username) uBadge.textContent = username;
    }

    if (mode === 'login') {
      if (loginMessage && $('#admLoginErr')) {
        $('#admLoginErr').textContent = loginMessage;
      }
      setTimeout(() => {
        const pIn = $('#admPassInput');
        const uIn = $('#admUserInput');
        if (uIn && !uIn.value) uIn.focus();
        else if (pIn) pIn.focus();
      }, 30);
    }
  }

  const KIND_BADGE = {
    view: ['网页访问', 'badge-blue'],
    self_lookup: ['本机查询', 'badge-emerald'],
    target_lookup: ['查外部 IP', 'badge-amber'],
    cli: ['CLI / JSON', 'badge-purple'],
    probe: ['443 实测', 'badge-emerald'],
    error: ['异常请求', 'badge-rose'],
  };

  function parseUsageWindow(usage, serverDateHeader) {
    const refDate = serverDateHeader ? new Date(serverDateHeader) : (STATE.serverNow || new Date());
    if (!Number.isNaN(refDate.getTime())) STATE.serverNow = refDate;
    const anchor = chinaDayFromDate(STATE.serverNow || new Date());

    if (!usage || typeof usage !== 'object' || !Array.isArray(usage.days)) {
      return {anchor, valid: false, missing: true, malformed: false, map: new Map(), startDay: ''};
    }

    let malformed = false;
    const map = new Map();
    for (const d of usage.days) {
      if (!d || typeof d.date !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(d.date)) {
        malformed = true;
        continue;
      }
      map.set(d.date, {
        date: d.date,
        uv: Math.max(0, Number(d.uv || 0)),
        pageViews: Math.max(0, Number(d.pageViews || 0)),
        lookups: Math.max(0, Number(d.lookups || 0)),
        cliLookups: Math.max(0, Number(d.cliLookups || 0)),
        targetLookups: Math.max(0, Number(d.targetLookups || 0)),
        probes: Math.max(0, Number(d.probes || 0)),
        errors: Math.max(0, Number(d.errors || 0)),
      });
    }

    let startDay = '';
    if (usage.startedAt) {
      const sd = new Date(usage.startedAt);
      if (!Number.isNaN(sd.getTime())) startDay = chinaDayFromDate(sd);
    }
    return {anchor, valid: !malformed, missing: false, malformed, map, startDay};
  }

  function updateHeaderSiteLinks() {
    const activeHost = STATE.host || location.host;
    const isLocal = /^(localhost|127\.|\[::1\])/i.test(activeHost);
    const proto = isLocal ? location.protocol : 'https:';
    const frontBtn = $('#btnOpenFront');
    if (frontBtn) {
      frontBtn.href = `${proto}//${activeHost}/`;
      frontBtn.textContent = STATE.host ? `查询站 (${STATE.host.split('.')[1] || STATE.host}) ↗` : '打开查询站 ↗';
    }
    const whoBtn = $('#btnOpenSiblingWho');
    if (whoBtn) {
      if (/^ip\./i.test(activeHost)) {
        const whoHost = activeHost.replace(/^ip\./i, 'who.');
        whoBtn.href = `https://${whoHost}/`;
        whoBtn.hidden = false;
        whoBtn.title = `打开对应风控检测站 ${whoHost}`;
      } else {
        whoBtn.hidden = true;
      }
    }
  }

  function updateSecretUrlDisplay(gateKey, hosts = []) {
    if (gateKey) URL_KEY = gateKey;
    const codeEl = $('#secCurrentUrl');
    const suffix = URL_KEY ? `/admin?k=${URL_KEY}` : '/admin';
    if (codeEl) {
      codeEl.textContent = `${location.origin}${suffix}`;
    }
    const multiEl = $('#secMultiUrls');
    if (multiEl) {
      const otherHosts = (hosts || []).map(h => h.host).filter(h => h && h !== location.hostname);
      if (otherHosts.length > 0) {
        multiEl.hidden = false;
        multiEl.innerHTML = otherHosts.map(h => {
          const full = `https://${h}${suffix}`;
          return `
            <div class="token-box">
              <code class="token-code font-mono">${esc(full)}</code>
              <button type="button" data-copyurl="${esc(full)}" class="btn-ghost btn-xs">复制链接</button>
            </div>
          `;
        }).join('');
      } else {
        multiEl.hidden = true;
        multiEl.innerHTML = '';
      }
    }
  }

  function renderHostSwitch(hosts) {
    const nav = $('#admHostSwitch');
    if (!nav) return;
    const list = Array.isArray(hosts) ? hosts : [];
    if (!list.length) {
      nav.hidden = true;
      nav.innerHTML = '';
      return;
    }
    nav.hidden = false;
    const totalReq = list.reduce((acc, h) => acc + Number(h.requests30d || 0), 0);
    const pills = [
      `<button type="button" data-hosttab="" class="ev-pill ${STATE.host === '' ? 'is-active' : ''}">全部站点<span class="host-pill-cnt font-mono">${totalReq}</span></button>`,
      ...list.map(h => {
        const on = STATE.host === h.host;
        const cnt = Number(h.requests30d || h.recentCount || 0);
        return `<button type="button" data-hosttab="${esc(h.host)}" class="ev-pill ${on ? 'is-active' : ''}">${esc(h.host)}<span class="host-pill-cnt font-mono">${cnt}</span></button>`;
      }),
    ];
    nav.innerHTML = pills.join('');
    updateHeaderSiteLinks();
  }

  function renderOverview(data, dateHdr) {
    STATE.overview = data;
    const live = data.live || {};
    const auth = data.auth || {};
    renderHostSwitch(live.hosts || []);
    if (auth.gateKey) updateSecretUrlDisplay(auth.gateKey, live.hosts || []);
    else updateSecretUrlDisplay(URL_KEY, live.hosts || []);

    if (auth.username) {
      const uBadge = $('#admUserBadge');
      if (uBadge) {
        uBadge.hidden = false;
        uBadge.textContent = auth.username;
      }
      const uField = $('#secNewUser');
      if (uField && !uField.value) uField.placeholder = `当前账号: ${auth.username}`;
    }

    const win = parseUsageWindow(data.usage, dateHdr);
    if (win.missing) {
      showNotice('未采集访问统计。');
    } else if (win.malformed) {
      showNotice('访问统计存在格式异常记录，不能按零流量计算。');
    } else {
      showNotice('');
    }

    const yestKey = shiftChinaDay(win.anchor, -1);
    const todayRec = win.map.get(win.anchor) || {uv: 0, pageViews: 0, lookups: 0, cliLookups: 0, targetLookups: 0, probes: 0, errors: 0};
    const yestRec = win.map.get(yestKey) || {uv: 0, pageViews: 0, lookups: 0, cliLookups: 0, targetLookups: 0, probes: 0, errors: 0};

    // Build 30-day chronological series
    const days30 = [];
    let sum30Pv = 0, sum30Lookups = 0, sum30Target = 0, sum30Probes = 0, sum30Errors = 0, sum30Uv = 0, sum7Uv = 0;
    for (let i = 29; i >= 0; i--) {
      const dayKey = shiftChinaDay(win.anchor, -i);
      const rec = win.map.get(dayKey);
      const uncollected = !rec && win.startDay && dayKey < win.startDay;
      const uv = rec ? rec.uv : 0;
      const pv = rec ? rec.pageViews : 0;
      const lk = rec ? rec.lookups : 0;
      const cli = rec ? rec.cliLookups : 0;
      const tgt = rec ? rec.targetLookups : 0;
      const prb = rec ? rec.probes : 0;
      const err = rec ? rec.errors : 0;
      sum30Pv += pv;
      sum30Lookups += lk;
      sum30Target += tgt;
      sum30Probes += prb;
      sum30Errors += err;
      sum30Uv += uv;
      if (i <= 6) sum7Uv += uv;
      days30.push({day: dayKey, uv, pv, lookups: lk, totalReq: pv + lk, cli, tgt, prb, err, uncollected});
    }

    const todayUv = live.todayUv ?? todayRec.uv;
    const yestUv = live.yestUv ?? yestRec.uv;
    const uv7 = live.uv7d ?? sum7Uv;
    const uv30 = live.uv30d ?? sum30Uv;

    if (!win.valid) {
      $('#kpiTodayUv').textContent = '--';
      $('#kpiTodaySub').textContent = win.missing ? '未采集访问统计。' : '统计数据需人工核查';
      $('#kpiYestUv').textContent = '--';
      $('#kpiYestSub').textContent = '--';
      $('#kpi7dUv').textContent = '--';
      $('#kpi30dSub').textContent = '--';
      $('#kpiLookupTotal').textContent = '--';
      $('#kpiLookupSub').textContent = '--';
    } else {
      $('#kpiTodayUv').textContent = String(todayUv);
      $('#kpiTodaySub').textContent = `网页 ${todayRec.pageViews} 次 · 查询 ${todayRec.lookups} 次`;

      const dUv = todayUv - yestUv;
      const dBadge = $('#kpiDeltaBadge');
      if (dBadge) {
        dBadge.textContent = dUv === 0 ? '较昨日持平' : dUv > 0 ? `较昨日 +${dUv}` : `较昨日 ${dUv}`;
        dBadge.className = 'font-mono ' + (dUv > 0 ? 'badge-emerald' : 'badge-muted');
      }

      $('#kpiYestUv').textContent = String(yestUv);
      $('#kpiYestSub').textContent = `昨日网页 ${yestRec.pageViews} 次 · 查询 ${yestRec.lookups} 次`;

      $('#kpi7dUv').textContent = `${uv7} 人`;
      $('#kpi30dSub').textContent = `30日独立 IP ${uv30} · 总请求 ${sum30Pv + sum30Lookups}`;

      $('#kpiLookupTotal').textContent = `${sum30Lookups} 次`;
      $('#kpiTodayModeBadge').textContent = `CLI ${todayRec.cliLookups} / 实测 ${todayRec.probes}`;
      $('#kpiLookupSub').textContent = `查外部 IP ${sum30Target} · 443实测 ${sum30Probes} · 异常 ${sum30Errors}`;
    }

    // Card 5: Top Regions
    const regBox = $('#kpiTopRegions');
    const regs = (live.regions || []).slice(0, 3);
    if (regBox) {
      regBox.innerHTML = regs.length
        ? regs.map(r => `
            <div class="region-row">
              <span class="region-name">${flagEmoji(r.cc)} ${esc(countryName(r.cc, r.name))}</span>
              <span class="region-count">${Number(r.visitors || 0)} IP <span class="region-req">(${Number(r.requests || 0)})</span></span>
            </div>
          `).join('')
        : `<div class="text-muted">等待首批访客记录…</div>`;
    }

    // Row 2: 30-day interactive bar chart
    const chartBox = $('#dailyChartBox');
    const maxVal = Math.max(1, ...days30.map(d => Math.max(d.totalReq, d.uv)));
    if (chartBox) {
      chartBox.innerHTML = days30.map((d, idx) => {
        const totPct = d.totalReq > 0 ? Math.max(8, Math.round((d.totalReq / maxVal) * 100)) : 3;
        const uvRatio = d.uv > 0 ? Math.min(100, Math.max(18, Math.round((d.uv / Math.max(1, d.totalReq)) * 100))) : 0;
        const selected = STATE.day === d.day;
        const shortDay = d.day.slice(5);
        const showOnMobile = idx % 5 === 0 || idx === 29 || selected;
        const tip = d.uncollected
          ? `${d.day}\n未采集（早于统计启动日期）`
          : `${d.day}\n独立访客 (UV): ${d.uv} 人\n网页浏览: ${d.pv} 次 · IP 查询: ${d.lookups} 次\nCLI/JSON: ${d.cli} · 443实测: ${d.prb} · 异常: ${d.err}`;
        return `
          <button type="button" data-daybar="${esc(d.day)}" title="${esc(tip)}" class="day-bar-btn">
            <span class="day-bar-top font-mono ${showOnMobile ? '' : 'hide-xs'}">${d.uv > 0 ? d.uv : ''}</span>
            <div class="day-bar-track">
              <div class="day-bar-outer ${d.totalReq > 0 ? '' : 'is-empty'} ${selected ? 'is-selected' : ''}" style="height:${totPct}%">
                ${uvRatio > 0 ? `<div class="day-bar-inner" style="height:${uvRatio}%"></div>` : ''}
              </div>
            </div>
            <span class="day-bar-lbl font-mono ${selected ? 'is-selected' : ''} ${showOnMobile ? '' : 'hide-xs'}">${esc(shortDay)}</span>
          </button>
        `;
      }).join('');
    }

    // 30-day numerical breakdown table (reverse chronological: newest first, oldest last)
    const dayRows = $('#dayRows');
    if (dayRows) {
      dayRows.innerHTML = [...days30].reverse().map(d => {
        if (d.uncollected) {
          return `
            <tr>
              <td class="font-mono">${esc(d.day)}</td>
              <td colspan="6" class="text-muted">未采集</td>
            </tr>
          `;
        }
        return `
          <tr>
            <td class="font-mono">${esc(d.day)}</td>
            <td class="font-mono">${d.uv}</td>
            <td class="font-mono">${d.pv}</td>
            <td class="font-mono">${d.lookups}</td>
            <td class="font-mono">${d.cli}</td>
            <td class="font-mono">${d.prb}</td>
            <td class="font-mono">${d.err}</td>
          </tr>
        `;
      }).join('');
    }

    const dayBtn = $('#btnClearDayFilter');
    if (dayBtn) {
      dayBtn.hidden = !STATE.day;
      if (STATE.day) dayBtn.textContent = `仅看 ${STATE.day} ✕`;
    }

    renderUniqueIps(live.topIps || []);
    renderSources(data.sources || {});
  }

  function renderUniqueIps(ips) {
    const badge = $('#badgeIpsCnt');
    if (badge) badge.textContent = String(ips.length);

    const tbody = $('#ipsTableBody');
    if (!tbody) return;
    const kw = STATE.q.trim().toLowerCase();
    const list = kw
      ? ips.filter(x => `${x.ip} ${x.cc || ''} ${x.location || ''} ${x.asn || ''} ${x.isp || ''} ${x.os || ''} ${x.browser || ''} ${(x.targets || []).join(' ')}`.toLowerCase().includes(kw))
      : ips;

    if (!list.length) {
      tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">暂无匹配的独立 IP 汇总记录</td></tr>`;
      return;
    }

    tbody.innerHTML = list.map(x => {
      const locWithFlag = x.cc ? `${flagEmoji(x.cc)} ${x.location || countryName(x.cc)}` : (x.location || '');
      const geo = [locWithFlag, x.asn, x.isp].filter(Boolean).join(' · ') || '–';
      const dev = [x.os, x.browser].filter(Boolean).join(' · ') || '–';
      const hostBadges = (x.hosts || []).map(h => `<button type="button" data-selecthost="${esc(h)}" class="badge-muted font-mono host-tag-btn" title="仅看 ${esc(h)}">${esc(h)}</button>`).join(' ');
      const targetsHtml = (x.targets || []).length
        ? x.targets.map(t => `<button type="button" data-openip="${esc(t)}" class="badge-amber font-mono" style="border:0;cursor:pointer">${esc(t)}</button>`).join(' ')
        : `<button type="button" data-openip="${esc(x.ip)}" class="dossier-chip"><span class="font-mono">${esc(x.label || '查看档案')}</span></button>`;

      return `
        <tr>
          <td>
            <div class="cell-type-stack">
              <div class="cell-ip-group">
                <button type="button" data-filterip="${esc(x.ip)}" class="ip-filter-btn" title="筛选该 IP 全部访问明细">${esc(x.ip)}</button>
                <button type="button" data-copyip="${esc(x.ip)}" class="tiny-action">复制</button>
                <a href="/${encodeURIComponent(x.ip)}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" class="tiny-link">查询↗</a>
              </div>
              ${hostBadges}
            </div>
          </td>
          <td class="cell-truncate" title="${esc(geo)}">${esc(geo)}</td>
          <td class="cell-truncate" title="${esc(dev)}">${esc(dev)}</td>
          <td class="font-mono">
            <strong>${Number(x.views || 0)}</strong> 网页 ·
            <span>${Number(x.lookups || 0)}</span> 查询 ·
            <span>${Number(x.probes || 0)}</span> 实测
          </td>
          <td class="font-mono text-muted">${esc(shortTime(x.firstSeen))} → ${esc(shortTime(x.lastSeen))}</td>
          <td>${targetsHtml}</td>
        </tr>
      `;
    }).join('');
  }

  function renderSources(sources) {
    const online = Array.isArray(sources.online) ? sources.online : [];
    const datasets = Array.isArray(sources.datasets) ? sources.datasets : [];

    let alertCount = 0;
    const nowMs = (STATE.serverNow || new Date()).getTime();

    const onlineEl = $('#online');
    if (onlineEl) {
      if (!online.length) {
        onlineEl.innerHTML = `<div class="text-muted">未配置在线情报源</div>`;
      } else {
        onlineEl.innerHTML = online.map(p => {
          const blockedUntil = p.blocked_until ? new Date(p.blocked_until) : null;
          const isLimited = blockedUntil && !Number.isNaN(blockedUntil.getTime()) && blockedUntil.getTime() > nowMs;
          if (isLimited) alertCount++;

          const used = Number(p.used || 0);
          const qStr = String(p.quota || '不限');
          const m = /^(\d+)/.exec(qStr);
          const limitNum = m ? Number(m[1]) : 0;
          const pct = limitNum > 0 ? Math.min(100, Math.round((used / limitNum) * 100)) : 0;
          const fillCls = isLimited || pct >= 90 ? 'is-hot' : pct >= 70 ? 'is-warn' : '';

          return `
            <div class="quota-card">
              <div class="quota-top">
                <span class="quota-name" title="${esc(p.name)}">${esc(p.name)}</span>
                <span class="${isLimited ? 'badge-rose' : 'badge-emerald'}">${isLimited ? '限流' : '正常'}</span>
              </div>
              <div class="quota-meta font-mono">
                <span>${esc(qStr)} · 已用 ${used}</span>
                <span>${limitNum > 0 ? `${pct}%` : '按需'}</span>
              </div>
              <div class="quota-bar">
                <div class="quota-fill ${fillCls}" style="width:${limitNum > 0 ? pct : (used > 0 ? 18 : 4)}%"></div>
              </div>
            </div>
          `;
        }).join('');
      }
    }

    const dsBody = $('#datasetsBody');
    let okDs = 0;
    if (dsBody) {
      if (!datasets.length) {
        dsBody.innerHTML = `<tr><td colspan="5" class="empty-cell">暂无离线数据集报告</td></tr>`;
      } else {
        dsBody.innerHTML = datasets.map(ds => {
          const st = String(ds.status || '');
          const isOk = st === 'ok' || st === 'loaded';
          if (isOk) okDs++;
          else alertCount++;
          const stLabel = isOk ? '正常' : st === 'missing' ? '缺失' : '错误';
          const stCls = isOk ? 'badge-emerald' : st === 'missing' ? 'badge-amber' : 'badge-rose';
          const entries = ds.entries ? Number(ds.entries).toLocaleString('en-US') : '0';
          const sizeMb = ds.bytes ? `${(Number(ds.bytes) / (1024 * 1024)).toFixed(1)} MB` : '';
          const meta = [sizeMb, ds.updated_at ? String(ds.updated_at).slice(0, 10) : ''].filter(Boolean).join(' · ') || '–';
          const detail = ds.error || ds.path || '已就绪';
          return `
            <tr>
              <td class="cell-wrap-safe"><strong>${esc(ds.label || ds.id || '-')}</strong></td>
              <td><span class="${stCls}">${stLabel}</span></td>
              <td class="font-mono">${esc(entries)}</td>
              <td class="font-mono text-muted">${esc(meta)}</td>
              <td class="cell-wrap-safe text-muted">${esc(detail)}</td>
            </tr>
          `;
        }).join('');
      }
    }

    const srcBadge = $('#badgeSourcesCnt');
    if (srcBadge) {
      srcBadge.textContent = alertCount > 0 ? `${alertCount} 告警` : String(online.length + datasets.length);
      srcBadge.className = 'tab-pill font-mono ' + (alertCount > 0 ? 'badge-rose' : '');
    }
    if ($('#onlineSummaryBadge')) $('#onlineSummaryBadge').textContent = `共 ${online.length} 个在线源`;
    if ($('#datasetSummaryBadge')) $('#datasetSummaryBadge').textContent = `就绪 ${okDs} / ${datasets.length} 个离线库`;
  }

  async function loadVisits() {
    const qs = new URLSearchParams({
      page: String(STATE.page),
      size: String(STATE.size),
    });
    if (STATE.host) qs.set('host', STATE.host);
    if (STATE.day) qs.set('day', STATE.day);
    if (STATE.kind) qs.set('kind', STATE.kind);
    if (STATE.errOnly) qs.set('err', '1');
    if (STATE.q) qs.set('q', STATE.q);

    let r;
    try {
      r = await fetch(`/admin/api/visits?${qs}`, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: authHeaders(),
      });
    } catch (e) {
      return;
    }
    if (r.status === 401) {
      showViewState('login', '', '会话已过期，请重新登录。');
      return;
    }
    if (!r.ok) return;
    const res = await r.json().catch(() => null);
    if (!res) return;

    const total = Number(res.total || 0);
    const items = Array.isArray(res.items) ? res.items : [];
    const cntBadge = $('#badgeVisitsCnt');
    if (cntBadge) cntBadge.textContent = String(total);

    const tbody = $('#visitsTableBody');
    if (tbody) {
      if (!items.length) {
        tbody.innerHTML = `<tr><td colspan="6" class="empty-cell">暂无匹配的访问与查询明细</td></tr>`;
      } else {
        tbody.innerHTML = items.map(row => {
          const [evLabel, evCls] = KIND_BADGE[row.kind] || [row.kind || '请求', 'badge-muted'];
          const locWithFlag = row.cc ? `${flagEmoji(row.cc)} ${row.location || countryName(row.cc)}` : (row.location || '');
          const geo = [locWithFlag, row.asn, row.isp].filter(Boolean).join(' · ') || '–';
          const dev = [row.os, row.browser].filter(Boolean).join(' · ') || '–';
          const tgt = row.targetIp && row.targetIp !== row.ip ? `查 ${row.targetIp}` : (row.targetLabel || '本机网络');
          const inspectIp = row.targetIp || row.ip;

          const hostHtml = row.host
            ? `<button type="button" data-selecthost="${esc(row.host)}" class="badge-muted font-mono host-tag-btn" title="仅看 ${esc(row.host)}">${esc(row.host)}</button>`
            : '';

          return `
            <tr data-rowip="${esc(inspectIp)}">
              <td class="font-mono text-muted">${esc(shortTime(row.time))}</td>
              <td><div class="cell-type-stack"><span class="${evCls}">${esc(evLabel)}</span>${hostHtml}</div></td>
              <td>
                <div class="cell-ip-group">
                  <button type="button" data-filterip="${esc(row.ip)}" class="ip-filter-btn" title="筛选该 IP 全部轨迹">${esc(row.ip)}</button>
                  <button type="button" data-copyip="${esc(row.ip)}" class="tiny-action">复制</button>
                  <a href="/${encodeURIComponent(row.ip)}" target="_blank" rel="noopener noreferrer" referrerpolicy="no-referrer" class="tiny-link">查询↗</a>
                </div>
              </td>
              <td class="cell-truncate" title="${esc(geo)}">${esc(geo)}</td>
              <td class="cell-truncate text-muted" title="${esc(dev)}">${esc(dev)}</td>
              <td>
                <button type="button" data-openip="${esc(inspectIp)}" class="dossier-chip">
                  <span class="font-mono"><strong>${esc(tgt)}</strong></span>
                  <span class="font-mono text-muted">${Number(row.ms || 0)}ms · 档案</span>
                </button>
              </td>
            </tr>
          `;
        }).join('');
      }
    }

    const start = total ? (STATE.page - 1) * STATE.size + 1 : 0;
    const end = Math.min(total, (STATE.page - 1) * STATE.size + items.length);
    if ($('#visitsPageInfo')) {
      $('#visitsPageInfo').textContent = total ? `显示第 ${start}–${end} 条 / 共 ${total} 条` : '共 0 条记录';
    }
    if ($('#btnPrevPage')) $('#btnPrevPage').disabled = STATE.page <= 1;
    if ($('#btnNextPage')) $('#btnNextPage').disabled = STATE.page * STATE.size >= total;
  }

  async function loadSecurityLists() {
    try {
      const [bRes, lRes] = await Promise.all([
        fetch('/admin/api/ip-blocks', {cache: 'no-store', credentials: 'same-origin', headers: authHeaders()}),
        fetch('/admin/api/login-logs', {cache: 'no-store', credentials: 'same-origin', headers: authHeaders()}),
      ]);

      if (bRes.ok) {
        const bJson = await bRes.json().catch(() => ({items: []}));
        const blocks = Array.isArray(bJson.items) ? bJson.items : [];
        const bBody = $('#ipBlocksBody');
        if (bBody) {
          bBody.innerHTML = blocks.length
            ? blocks.map(b => {
                const statusTxt = b.permanent
                  ? '永久封锁'
                  : b.strike > 0
                    ? `第 ${b.strike} 轮锁定至 ${shortTime(b.blockedUntil)}`
                    : `已失败 ${b.failCount} 次`;
                return `
                  <tr>
                    <td class="font-mono"><strong>${esc(b.ip)}</strong></td>
                    <td>${esc(b.location || '–')}</td>
                    <td><span class="${b.permanent || b.strike > 0 ? 'badge-rose' : 'badge-amber'}">${esc(statusTxt)}</span></td>
                    <td><button type="button" data-unblockip="${esc(b.ip)}" class="btn-ghost btn-xs">解除封锁</button></td>
                  </tr>
                `;
              }).join('')
            : `<tr><td colspan="4" class="empty-cell">当前没有被锁定的来源 IP</td></tr>`;
        }
      }

      if (lRes.ok) {
        const lJson = await lRes.json().catch(() => ({items: []}));
        const logs = Array.isArray(lJson.items) ? lJson.items : [];
        const lBody = $('#loginLogsBody');
        if (lBody) {
          lBody.innerHTML = logs.length
            ? logs.slice(0, 30).map(l => `
                <tr>
                  <td class="font-mono text-muted">${esc(shortTime(l.time))}</td>
                  <td><span class="font-mono">${esc(l.ip)}</span> · ${esc(l.location || '–')}</td>
                  <td class="font-mono">${esc(l.username)}</td>
                  <td><span class="${l.ok ? 'badge-emerald' : 'badge-rose'}">${esc(l.reason || (l.ok ? '成功' : '失败'))}</span></td>
                </tr>
              `).join('')
            : `<tr><td colspan="4" class="empty-cell">尚无管理员登录记录</td></tr>`;
        }
      }
    } catch (e) {}
  }

  async function openIpDossier(ip) {
    if (!ip) return;
    const modal = $('#ipDetailModal');
    const body = $('#mdlBody');
    if (!modal || !body) return;

    $('#mdlIpBadge').textContent = ip;
    $('#mdlOpenLookupBtn').href = `/${encodeURIComponent(ip)}`;
    body.innerHTML = `<div class="empty-cell">正在查询 ${esc(ip)} 的离线档案与轨迹…</div>`;
    modal.hidden = false;

    try {
      const r = await fetch(`/admin/api/visitor?ip=${encodeURIComponent(ip)}`, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: authHeaders(),
      });
      if (!r.ok) {
        body.innerHTML = `<div class="empty-cell">未能读取该 IP 的档案信息</div>`;
        return;
      }
      const data = await r.json();
      const s = data.summary || {};
      const hist = Array.isArray(data.history) ? data.history : [];

      const histHtml = hist.length
        ? hist.map(h => {
            const [lbl, cls] = KIND_BADGE[h.kind] || [h.kind, 'badge-muted'];
            return `
              <tr>
                <td class="font-mono text-muted">${esc(shortTime(h.time))}</td>
                <td><span class="${cls}">${esc(lbl)}</span></td>
                <td class="font-mono">${esc(h.targetIp || h.ip)}</td>
                <td>${esc([h.os, h.browser].filter(Boolean).join(' · ') || '–')}</td>
                <td class="font-mono text-muted">${Number(h.ms || 0)}ms</td>
              </tr>
            `;
          }).join('')
        : `<tr><td colspan="5" class="empty-cell">当前内存环形缓冲区中暂无更多历史轨迹</td></tr>`;

      body.innerHTML = `
        <div class="dossier-meta-grid">
          <div class="dossier-stat">
            <div class="dossier-stat-k">国家 / 地区与城市</div>
            <div class="dossier-stat-v">${s.cc ? flagEmoji(s.cc) + ' ' : ''}${esc(s.location || s.country || '未知')}</div>
          </div>
          <div class="dossier-stat">
            <div class="dossier-stat-k">ASN 与运营商</div>
            <div class="dossier-stat-v font-mono">${esc([s.asn, s.isp].filter(Boolean).join(' ') || '未知')}</div>
          </div>
          <div class="dossier-stat">
            <div class="dossier-stat-k">BGP 路由前缀</div>
            <div class="dossier-stat-v font-mono">${esc(s.prefix || '–')}</div>
          </div>
          <div class="dossier-stat">
            <div class="dossier-stat-k">网络属性判定</div>
            <div class="dossier-stat-v">${esc(s.label || '普通网络')}</div>
          </div>
        </div>
        <div>
          <h4 class="section-title" style="margin-bottom:8px">关联访问与查询记录 (${hist.length} 条)</h4>
          <div class="surface-sheet table-card">
            <div class="table-scroll">
              <table class="adm-table adm-table-compact">
                <thead>
                  <tr>
                    <th>时间</th>
                    <th>类型</th>
                    <th>目标 IP</th>
                    <th>终端与浏览器</th>
                    <th>耗时</th>
                  </tr>
                </thead>
                <tbody>${histHtml}</tbody>
              </table>
            </div>
          </div>
        </div>
      `;
    } catch (e) {
      body.innerHTML = `<div class="empty-cell">请求失败，请稍后重试</div>`;
    }
  }

  function switchTab(tab) {
    STATE.tab = tab;
    $$('#admTabs .seg-tab').forEach(btn => {
      const on = btn.dataset.admtab === tab;
      btn.setAttribute('aria-selected', on ? 'true' : 'false');
      btn.classList.toggle('is-active', on);
    });
    $$('[data-admpanel]').forEach(p => {
      p.hidden = p.dataset.admpanel !== tab;
    });
    const filterBar = $('#admFilterBar');
    if (filterBar) filterBar.hidden = !(tab === 'visits' || tab === 'ips');
    const evPills = $('#eventFilterPills');
    if (evPills) evPills.hidden = tab !== 'visits';

    if (tab === 'ips' && STATE.overview) {
      renderUniqueIps((STATE.overview.live && STATE.overview.live.topIps) || []);
    } else if (tab === 'security') {
      loadSecurityLists();
    }
  }

  async function refreshAll(manual = false) {
    const ovUrl = STATE.host ? `/admin/api/overview?host=${encodeURIComponent(STATE.host)}` : '/admin/api/overview';
    let r;
    try {
      r = await fetch(ovUrl, {
        cache: 'no-store',
        credentials: 'same-origin',
        headers: authHeaders(),
      });
    } catch (e) {
      if (!STATE.hasLoadedOnce) {
        showViewState('error');
      } else {
        showNotice('刷新失败，当前显示上次成功加载的数据。');
      }
      return false;
    }

    if (r.status === 401) {
      const msg = STATE.hasLoadedOnce ? '会话已过期，请重新登录。' : '';
      STATE.hasLoadedOnce = false;
      showViewState('login', '', msg);
      return false;
    }

    if (!r.ok) {
      if (!STATE.hasLoadedOnce) {
        showViewState('error');
      } else {
        showNotice('刷新失败，当前显示上次成功加载的数据。');
      }
      return false;
    }

    const data = await r.json().catch(() => null);
    if (!data) {
      if (!STATE.hasLoadedOnce) showViewState('error');
      return false;
    }

    STATE.hasLoadedOnce = true;
    showViewState('dash', (data.auth && data.auth.username) || 'admin');
    renderOverview(data, r.headers.get('Date'));
    await loadVisits();
    if (STATE.tab === 'security') await loadSecurityLists();

    const syncEl = $('#admLastSync');
    if (syncEl) {
      syncEl.textContent = `更新于 ${new Date().toLocaleTimeString('zh-CN', {hour12: false})}`;
    }
    if (manual) toast('已刷新最新数据');
    return true;
  }

  function toggleTheme() {
    const dark = document.documentElement.classList.toggle('dark');
    try { localStorage.setItem('iplookup:admin:theme', dark ? 'dark' : 'light'); } catch (e) {}
  }

  document.addEventListener('DOMContentLoaded', () => {
    $('#btnLoginTheme')?.addEventListener('click', toggleTheme);
    $('#btnAdmTheme')?.addEventListener('click', toggleTheme);

    $('#btnTogglePwd')?.addEventListener('click', () => {
      const pIn = $('#admPassInput');
      const btn = $('#btnTogglePwd');
      if (!pIn || !btn) return;
      const show = pIn.type === 'password';
      pIn.type = show ? 'text' : 'password';
      btn.textContent = show ? '隐藏' : '显示';
    });

    $('#admLoginForm')?.addEventListener('submit', async e => {
      e.preventDefault();
      const u = ($('#admUserInput')?.value || '').trim();
      const p = $('#admPassInput')?.value || '';
      const errEl = $('#admLoginErr');
      const btn = $('#admLoginBtn');
      if (errEl) errEl.textContent = '';
      if (!p) {
        if (errEl) errEl.textContent = '请输入管理员账号与密码';
        return;
      }
      if (btn) {
        btn.disabled = true;
        btn.textContent = '正在验证…';
      }
      try {
        const r = await fetch('/admin/api/login', {
          method: 'POST',
          credentials: 'same-origin',
          headers: authHeaders({'Content-Type': 'application/json'}),
          body: JSON.stringify({username: u, password: p}),
        });
        if (r.status === 204 || r.ok) {
          if ($('#admPassInput')) $('#admPassInput').value = '';
          await refreshAll(false);
          toast('登录成功');
        } else {
          const j = await r.json().catch(() => ({}));
          if (errEl) {
            errEl.textContent = j?.error?.message || (r.status === 429 ? '登录尝试过多，请稍后再试' : '账号或密码不正确。');
          }
          $('#admPassInput')?.select();
        }
      } catch (err) {
        if (errEl) errEl.textContent = '网络请求失败，请重试';
      } finally {
        if (btn) {
          btn.disabled = false;
          btn.textContent = '登 录';
        }
      }
    });

    $('#btnAdmLogout')?.addEventListener('click', async () => {
      try {
        const r = await fetch('/admin/api/logout', {
          method: 'POST',
          credentials: 'same-origin',
          headers: authHeaders({'Content-Type': 'application/json'}),
          body: '{}',
        });
        if (!r.ok && r.status !== 204) {
          showNotice('退出未确认，请重试。');
          toast('退出未确认，请重试。');
          return;
        }
      } catch (e) {
        showNotice('退出未确认，请重试。');
        return;
      }
      $('#ipDetailModal').hidden = true;
      STATE.hasLoadedOnce = false;
      showViewState('login', '', '已退出登录。');
      toast('已安全退出登录');
    });

    $('#btnRefreshAdm')?.addEventListener('click', () => refreshAll(true));
    $('#retry')?.addEventListener('click', () => refreshAll(false));

    $('#admHostSwitch')?.addEventListener('click', e => {
      const btn = e.target.closest('[data-hosttab]');
      if (!btn) return;
      STATE.host = btn.dataset.hosttab || '';
      STATE.page = 1;
      updateHeaderSiteLinks();
      refreshAll(false);
    });

    $('#admTabs')?.addEventListener('click', e => {
      const btn = e.target.closest('[data-admtab]');
      if (btn) switchTab(btn.dataset.admtab);
    });

    $('#eventFilterPills')?.addEventListener('click', e => {
      const btn = e.target.closest('[data-evf]');
      if (!btn) return;
      const val = btn.dataset.evf || '';
      if (val === 'err') {
        STATE.kind = '';
        STATE.errOnly = true;
      } else {
        STATE.kind = val;
        STATE.errOnly = false;
      }
      STATE.page = 1;
      $$('#eventFilterPills .ev-pill').forEach(b => {
        b.classList.toggle('is-active', (b.dataset.evf || '') === val);
      });
      loadVisits();
    });

    let qTimer = null;
    $('#admSearchInput')?.addEventListener('input', e => {
      clearTimeout(qTimer);
      qTimer = setTimeout(() => {
        STATE.q = (e.target.value || '').trim();
        STATE.page = 1;
        if (STATE.tab === 'visits') loadVisits();
        else if (STATE.tab === 'ips' && STATE.overview) {
          renderUniqueIps((STATE.overview.live && STATE.overview.live.topIps) || []);
        }
      }, 200);
    });

    $('#dailyChartBox')?.addEventListener('click', e => {
      const bar = e.target.closest('[data-daybar]');
      if (!bar) return;
      const d = bar.dataset.daybar;
      STATE.day = STATE.day === d ? '' : d;
      STATE.page = 1;
      if (STATE.overview) renderOverview(STATE.overview, null);
      switchTab('visits');
      loadVisits();
    });

    $('#btnClearDayFilter')?.addEventListener('click', () => {
      STATE.day = '';
      STATE.page = 1;
      if (STATE.overview) renderOverview(STATE.overview, null);
      loadVisits();
    });

    $('#btnPrevPage')?.addEventListener('click', () => {
      if (STATE.page > 1) {
        STATE.page--;
        loadVisits();
      }
    });

    $('#btnNextPage')?.addEventListener('click', () => {
      STATE.page++;
      loadVisits();
    });

    $('#dashView')?.addEventListener('click', async e => {
      const openBtn = e.target.closest('[data-openip]');
      if (openBtn) {
        openIpDossier(openBtn.dataset.openip);
        return;
      }
      const fIp = e.target.closest('[data-filterip]');
      if (fIp) {
        const ip = fIp.dataset.filterip;
        if ($('#admSearchInput')) $('#admSearchInput').value = ip;
        STATE.q = ip;
        STATE.page = 1;
        switchTab('visits');
        loadVisits();
        return;
      }
      const cIp = e.target.closest('[data-copyip]');
      if (cIp) {
        copyText(cIp.dataset.copyip, `已复制 IP ${cIp.dataset.copyip}`);
        return;
      }
      const cUrl = e.target.closest('[data-copyurl]');
      if (cUrl) {
        copyText(cUrl.dataset.copyurl, '已复制后台入口链接');
        return;
      }
      const selHost = e.target.closest('[data-selecthost]');
      if (selHost) {
        const h = selHost.dataset.selecthost || '';
        STATE.host = STATE.host === h ? '' : h;
        STATE.page = 1;
        refreshAll(false);
        return;
      }
      const unblk = e.target.closest('[data-unblockip]');
      if (unblk) {
        const ip = unblk.dataset.unblockip;
        const r = await fetch('/admin/api/ip-blocks/unblock', {
          method: 'POST',
          credentials: 'same-origin',
          headers: authHeaders({'Content-Type': 'application/json'}),
          body: JSON.stringify({ip}),
        });
        if (r.ok) {
          toast(`已解除 ${ip} 的封锁`);
          loadSecurityLists();
        }
        return;
      }
      // Clicking a visit row outside buttons/links opens IP dossier too
      const row = e.target.closest('tr[data-rowip]');
      if (row && !e.target.closest('a, button')) {
        openIpDossier(row.dataset.rowip);
      }
    });

    $('#btnCopyAdmUrl')?.addEventListener('click', () => {
      const urlTxt = $('#secCurrentUrl')?.textContent || '';
      if (urlTxt) copyText(urlTxt, '已复制后台入口链接');
    });

    $('#rotateTokenForm')?.addEventListener('submit', async e => {
      e.preventDefault();
      const pw = $('#secTokPw')?.value || '';
      if (!pw) {
        toast('请输入当前管理密码以确认重置');
        return;
      }
      if (!confirm('确定要重置后台访问令牌 (?k=) 吗？重置后旧链接将立即返回 404。')) return;
      const r = await fetch('/admin/api/rotate-url-token', {
        method: 'POST',
        credentials: 'same-origin',
        headers: authHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify({password: pw}),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok && j?.url_token) {
        if ($('#secTokPw')) $('#secTokPw').value = '';
        updateSecretUrlDisplay(j.url_token, (STATE.overview?.live?.hosts) || []);
        try {
          history.replaceState(null, '', `/admin?k=${encodeURIComponent(j.url_token)}`);
        } catch (err) {}
        toast('已生成新的访问令牌，请保存新链接');
      } else {
        toast(j?.error?.message || '重置失败，请检查当前密码');
      }
    });

    $('#changePwForm')?.addEventListener('submit', async e => {
      e.preventDefault();
      const username = ($('#secNewUser')?.value || '').trim();
      const oldPassword = $('#secOldPw')?.value || '';
      const newPassword = $('#secNewPw')?.value || '';
      if (!oldPassword || !newPassword) {
        toast('请填写当前密码与新密码');
        return;
      }
      const r = await fetch('/admin/api/change-password', {
        method: 'POST',
        credentials: 'same-origin',
        headers: authHeaders({'Content-Type': 'application/json'}),
        body: JSON.stringify({username, old_password: oldPassword, new_password: newPassword}),
      });
      const j = await r.json().catch(() => ({}));
      if (r.ok) {
        if ($('#secOldPw')) $('#secOldPw').value = '';
        if ($('#secNewPw')) $('#secNewPw').value = '';
        if (j?.username && $('#admUserBadge')) $('#admUserBadge').textContent = j.username;
        toast('管理员凭据已更新并持久化保存');
      } else {
        toast(j?.error?.message || '修改密码失败');
      }
    });

    $('#mdlCloseBtn')?.addEventListener('click', () => { $('#ipDetailModal').hidden = true; });
    $('#ipDetailModal')?.addEventListener('click', e => {
      if (e.target === $('#ipDetailModal')) $('#ipDetailModal').hidden = true;
    });
    document.addEventListener('keydown', e => {
      if (e.key === 'Escape' && $('#ipDetailModal') && !$('#ipDetailModal').hidden) {
        $('#ipDetailModal').hidden = true;
      }
    });

    refreshAll(false);
  });
})();
