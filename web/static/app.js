'use strict';
const $ = selector => document.querySelector(selector);
const address = $('#ipAddress'), label = $('#ipLabel'), result = $('#result'), score = $('#score');
const value = $('#scoreValue'), level = $('#scoreLevel'), total = $('#scoreTotal'), statusEl = $('#status');
const form = $('#q'), input = $('#qi'), qerr = $('#qerr'), copyButton = $('#copy');
const V4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
function normIP(raw) {
  const ip = String(raw || '').trim().replace(/^\[(.*)\]$/, '$1');
  if (V4.test(ip)) return ip;
  if (!ip.includes(':') || !/^[0-9a-f:.]+$/i.test(ip)) return '';
  if (ip.includes('.') && !/:(\d+\.){3}\d+$/.test(ip)) return '';
  const halves = ip.split('::');
  if (halves.length > 2) return '';
  const groups = halves.flatMap(p => p ? p.split(':') : []);
  let count = groups.length;
  if (groups[count - 1]?.includes('.')) {
    if (!V4.test(groups.pop())) return '';
    count++;
  }
  if (!groups.every(g => /^[0-9a-f]{1,4}$/i.test(g))) return '';
  return (halves.length === 2 ? count <= 7 : count === 8) ? ip.toLowerCase() : '';
}
let currentIP = normIP(address.textContent), sequence = 0, controller, loading = false;
function showIP(ip) {
  currentIP = normIP(ip);
  address.replaceChildren();
  if (currentIP) {
    for (const part of currentIP.match(/[^:]+:*|:+/g)) {
      address.append(part);
      address.append(document.createElement('wbr'));
    }
  } else address.textContent = '获取中…';
  copyButton.disabled = !currentIP;
  copyButton.textContent = '复制';
}
async function getJSON(url, parent, ms = 25000) {
  if (parent.aborted) throw new DOMException('查询已取消', 'AbortError');
  const c = new AbortController(), abort = () => c.abort();
  const timer = setTimeout(abort, ms);
  parent.addEventListener('abort', abort, {once: true});
  try {
    const r = await fetch(url, {signal: c.signal, cache: 'no-store', headers: {accept: 'application/json'}});
    let body;
    try { body = await r.json(); } catch { throw new Error('服务器未返回有效结果'); }
    if (!r.ok) {
      if (r.status === 429) throw new Error('查询太频繁，请稍后再试');
      throw new Error(typeof body?.error === 'string' ? body.error : '查询失败，请重新检测');
    }
    if (!body || typeof body !== 'object' || Array.isArray(body)) throw new Error('服务器未返回有效结果');
    return body;
  } finally {
    clearTimeout(timer);
    parent.removeEventListener('abort', abort);
  }
}
function clearError() { input.removeAttribute('aria-invalid'); qerr.hidden = true; }
function showError(text) { input.setAttribute('aria-invalid', 'true'); qerr.textContent = text; qerr.hidden = false; }
async function lookup(ip, initialIP = '') {
  const own = ++sequence;
  controller?.abort(); controller = new AbortController();
  const signal = controller.signal;
  loading = true;
  clearError(); input.value = ip;
  label.textContent = ip ? 'IP 地址' : '我的 IP';
  document.title = (ip ? ip + ' · ' : '') + 'IP 查询';
  showIP(ip || initialIP);
  value.textContent = '—'; level.textContent = '评估中…'; total.hidden = false;
  delete score.dataset.rating;
  statusEl.textContent = ''; result.setAttribute('aria-busy', 'true');
  if (!currentIP) {
    getJSON('/api/ip', signal, 6000).then(r => {
      if (own === sequence && loading && normIP(r.ip)) showIP(r.ip);
    }).catch(() => {
      // The full lookup remains authoritative; its failure is shown below.
      if (own === sequence && loading && !currentIP) address.textContent = '暂未获取到 IP';
    });
  }
  try {
    const params = new URLSearchParams({mode: 'full', ...(ip ? {ip} : {})});
    const r = await getJSON('/api/lookup?' + params, signal);
    if (own !== sequence) return;
    if (!normIP(r.ip)) throw new Error('服务器未返回有效 IP');
    showIP(r.ip);
    if (r.bogon) {
      level.textContent = '不适用'; total.hidden = true;
      statusEl.textContent = String(r.bogon);
    } else {
      if (typeof r.score?.value !== 'number' || !Number.isFinite(r.score.value) || r.score.value < 0 || r.score.value > 100)
        throw new Error('纯净度结果暂不可用，请重新检测');
      const v = r.score.value;
      value.textContent = String(v);
      level.textContent = typeof r.score.level === 'string' && r.score.level ? r.score.level
        : v >= 95 ? '极度纯净' : v >= 80 ? '纯净' : v >= 50 ? '良好' : v >= 25 ? '中性' : '可疑';
      score.dataset.rating = v >= 80 ? 'high' : v >= 50 ? 'medium' : 'low';
    }
  } catch (e) {
    if (own !== sequence) return;
    value.textContent = '—'; level.textContent = '未能评估';
    statusEl.textContent = e.name === 'AbortError' ? '评估超时，请重新检测' : e instanceof TypeError ? '连接失败，请重新检测' : e.message;
  } finally {
    if (own === sequence) { loading = false; result.setAttribute('aria-busy', 'false'); }
  }
}
function go(ip) {
  if (location.pathname !== '/' + ip) history.pushState(null, '', '/' + ip);
  lookup(ip);
}
function route(initial = false) {
  let raw = '';
  try { raw = decodeURIComponent(location.pathname.slice(1)).replace(/\/+$/, ''); } catch {}
  const ip = normIP(raw), firstIP = initial ? currentIP : '';
  lookup(ip, firstIP);
  if (raw && !ip) { history.replaceState(null, '', '/'); showError('请输入有效的 IPv4 或 IPv6 地址'); }
}
form.addEventListener('submit', event => {
  event.preventDefault();
  const ip = normIP(input.value);
  if (ip) return go(ip);
  showError('请输入有效的 IPv4 或 IPv6 地址'); input.focus();
});
input.addEventListener('input', clearError);
$('#me').addEventListener('click', () => go(''));
$('.brand').addEventListener('click', event => {
  if (event.button || event.metaKey || event.ctrlKey || event.shiftKey || event.altKey) return;
  event.preventDefault(); go('');
});
copyButton.addEventListener('click', async () => {
  const ip = currentIP;
  if (!ip) return;
  let copied = false;
  try { await navigator.clipboard.writeText(ip); copied = true; } catch {
    const text = document.createElement('textarea');
    text.value = ip; text.className = 'vh'; document.body.append(text); text.select();
    try { copied = document.execCommand('copy'); } catch {}
    text.remove();
  }
  if (currentIP === ip) copyButton.textContent = copied ? '已复制' : '复制失败';
});
addEventListener('popstate', () => route());
route(true);
