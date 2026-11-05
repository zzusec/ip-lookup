// Synthetic browser fixtures; no third-party requests leave this test.
// Run: node --test web/connection.ui.test.cjs
'use strict';
const {test, before, after} = require('node:test');
const assert = require('node:assert/strict');
const {createServer} = require('node:http');
const {readFile} = require('node:fs/promises');
const {existsSync} = require('node:fs');
const {join} = require('node:path');
const playwright = ['playwright', '/opt/homebrew/lib/node_modules/@playwright/cli/node_modules/playwright']
  .map(p => { try { return require.resolve(p); } catch { return null; } }).find(Boolean);
if (!playwright) throw new Error('Install Playwright to run browser tests; this suite downloads no dependencies.');
const {chromium} = require(playwright);
let browser, server, origin;

before(async () => {
  const files = new Map([
    ['/', ['index.html', 'text/html']],
    ['/8.8.8.8', ['index.html', 'text/html']],
    ...['app.js', 'connection.js', 'style.css', 'favicon.svg'].map(f => ['/static/' + f, ['static/' + f,
      f.endsWith('.js') ? 'application/javascript' : f.endsWith('.css') ? 'text/css' : 'image/svg+xml']]),
  ]);
  server = createServer(async (req, res) => {
    const f = files.get(new URL(req.url, 'http://localhost').pathname);
    if (!f) { res.writeHead(404).end(); return; }
    try { res.writeHead(200, {'Content-Type': f[1]}); res.end(await readFile(join(__dirname, f[0]))); }
    catch { res.writeHead(500).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  const cached = join(process.env.HOME, 'Library/Caches/ms-playwright/chromium_headless_shell-1228/chrome-headless-shell-mac-arm64/chrome-headless-shell');
  browser = await chromium.launch({headless: true, ...(process.env.CHROMIUM_PATH ? {executablePath: process.env.CHROMIUM_PATH}
    : existsSync(cached) ? {executablePath: cached} : {})});
});
after(async () => { await browser?.close(); await new Promise(resolve => server?.close(resolve)); });

function report(ip, mode) {
  return {ip, version: 4, mode, queried_at: '2026-11-05T07:00:00Z', elapsed_ms: 12,
    verdict: {type: 'cdn', type_label: 'CDN', label: 'CDN', confidence: 'high', evidence: []},
    score: {value: 85, level: '纯净', factors: []}, flags: {},
    geo: {country: '澳大利亚', country_code: 'AU', time_zone: 'Australia/Sydney'},
    network: {asn: 13335, as_name: 'Synthetic fixture network'}, geo_sources: []};
}
async function fixture({width = 1440, failV6 = false, hold = false, colorScheme = 'light', ecs = '1.1.1.0/24', delayQuery = false} = {}) {
  const page = await browser.newPage({viewport: {width, height: 900}, colorScheme, timezoneId: 'Asia/Shanghai'});
  const seen = [], errors = [], held = [];
  page.on('pageerror', e => errors.push(e.message));
  await page.addInitScript(() => {
    window.__rtcClosed = 0;
    window.RTCPeerConnection = class extends EventTarget {
      createDataChannel() {}
      async createOffer() { return {type: 'offer', sdp: ''}; }
      async setLocalDescription() {
        queueMicrotask(() => {
          if (this.closed) return;
          for (const [address, type] of [['1.1.1.1', 'srflx'], ['192.168.1.2', 'host'], ['fixture.local', 'host']]) {
            const e = new Event('icecandidate');
            e.candidate = {address, type, candidate: `candidate:1 1 udp 1 ${address} 1234 typ ${type}`};
            this.onicecandidate?.(e); this.dispatchEvent(e);
          }
          this.iceGatheringState = 'complete';
          const e = new Event('icecandidate'); e.candidate = null;
          this.onicecandidate?.(e); this.dispatchEvent(e);
          this.onicegatheringstatechange?.(); this.dispatchEvent(new Event('icegatheringstatechange'));
        });
      }
      close() { if (!this.closed) window.__rtcClosed++; this.closed = true; }
    };
  });
  await page.route('**/*', async route => {
    const u = new URL(route.request().url());
    if (u.origin === origin) {
      if (u.pathname === '/api/lookup') {
        if (delayQuery && u.searchParams.has('ip')) await new Promise(resolve => setTimeout(resolve, 300));
        return route.fulfill({json: report(u.searchParams.get('ip') || '1.1.1.1', u.searchParams.get('mode'))});
      }
      if (u.pathname === '/api/ip') return route.fulfill({json: {ip: '1.1.1.1', version: 4}});
      return route.continue();
    }
    seen.push(u);
    if (hold) { held.push(route); return; }
    const headers = {'access-control-allow-origin': '*'};
    const json = data => route.fulfill({headers, json: data});
    if (u.hostname === 'api6.ipify.org') return failV6 ? route.abort() : json({ip: '2606:4700:4700::1111'});
    if (u.hostname.endsWith('ipify.org')) return json({ip: '1.1.1.1'});
    if (u.pathname === '/cdn-cgi/trace') return route.fulfill({headers, contentType: 'text/plain',
      body: `ip=${u.hostname === 'claude.ai' ? '8.8.4.4' : '1.1.1.1'}\nloc=AU\ncolo=SYD\nwarp=off\nhttp=http/2\ntls=TLSv1.3\n`});
    if (u.hostname === 'myip.ipip.net') return json({ret: 'ok', data: {ip: '9.9.9.9', location: ['中国', '示例地区']}});
    if (u.hostname.endsWith('.edns.ip-api.com')) return json({dns: {ip: '8.8.8.8', geo: 'United States - Google LLC'},
      edns: {ip: ecs, geo: 'Australia - Fixture provider'}});
    if (u.hostname === 'tcpip.incolumitas.com') return json({lookup_ip: '1.1.1.1', avg_score_os_class: {Linux: 11.25},
      perfect_score: 20.5, os_mismatch: null});
    errors.push('Unexpected third-party URL: ' + u.origin + u.pathname);
    return route.abort();
  });
  return {page, seen, errors, async release() { for (const r of held) { try { await r.abort(); } catch {} } }};
}
const finished = page => page.locator('.conn-progress').filter({hasText: '检测完成'}).waitFor();

test('self lookup shows destination observations, random DNS, unknown IPv6 and an exportable report', async () => {
  const f = await fixture({failV6: true});
  try {
    await f.page.goto(origin);
    await finished(f.page);
    const text = await f.page.locator('#connection').innerText();
    assert.match(text, /ChatGPT/); assert.match(text, /Claude/);
    assert.match(text, /EDNS 客户端子网/); assert.match(text, /TCP/);
    assert.match(text, /mDNS/); assert.match(text, /未能确认/);
    assert.doesNotMatch(text, /无 IPv6|国内直连、国外走代理|已确认.*泄露/);
    assert.match(await f.page.locator('[data-probe="v6"]').innerText(), /未能确认/);
    const dns = f.seen.find(u => u.hostname.endsWith('.edns.ip-api.com'));
    assert.match(dns.hostname, /^[a-f0-9]{32}\.edns\.ip-api\.com$/);
    const downloadEvent = f.page.waitForEvent('download');
    await f.page.getByRole('button', {name: '导出检测报告'}).click();
    const stream = await (await downloadEvent).createReadStream();
    let raw = ''; for await (const part of stream) raw += part;
    const exported = JSON.parse(raw);
    assert.equal(exported.schema, 'ip-lookup-connection/v1');
    assert.equal(exported.ipReport.ip, '1.1.1.1');
    assert.equal(exported.connection.probes.find(p => p.id === 'v6').status, 'error');
    assert.ok(exported.connection.finishedAt);
    assert.deepEqual(f.errors, []);
  } finally { await f.page.close(); }
});

test('an arbitrary IP never probes the visitor until 查我的 IP is selected', async () => {
  const f = await fixture();
  try {
    await f.page.goto(origin + '/8.8.8.8');
    await f.page.locator('.v-ip').filter({hasText: '8.8.8.8'}).waitFor();
    assert.equal(await f.page.locator('#connection').count(), 0);
    assert.equal(f.seen.length, 0);
    await f.page.getByRole('button', {name: '查我的 IP'}).click();
    await finished(f.page);
    assert.ok(f.seen.length > 0);
    assert.deepEqual(f.errors, []);
  } finally { await f.page.close(); }
});

test('navigation cancels pending probes and old results cannot reappear', async () => {
  const f = await fixture({hold: true});
  try {
    await f.page.goto(origin);
    await f.page.locator('#connection').waitFor();
    await f.page.locator('#qi').fill('8.8.8.8');
    await f.page.locator('#q button[type=submit]').click();
    await f.page.locator('.v-ip').filter({hasText: '8.8.8.8'}).waitFor();
    await f.release();
    assert.equal(await f.page.locator('#connection').count(), 0);
    assert.ok(await f.page.evaluate(() => window.__rtcClosed) >= 1);
    assert.deepEqual(f.errors, []);
  } finally { await f.release(); await f.page.close(); }
});

test('a stopped panel cannot restart probes while the next IP lookup is pending', async () => {
  const f = await fixture({delayQuery: true});
  try {
    await f.page.goto(origin);
    await finished(f.page);
    const count = f.seen.length;
    await f.page.locator('#qi').fill('8.8.8.8');
    await f.page.locator('#q button[type=submit]').click();
    assert.equal(await f.page.getByRole('button', {name: '重新检测连接'}).isDisabled(), true);
    await f.page.getByRole('button', {name: '重新检测连接'}).dispatchEvent('click');
    await f.page.locator('.v-ip').filter({hasText: '8.8.8.8'}).waitFor();
    assert.equal(f.seen.length, count);
    assert.equal(await f.page.locator('#connection').count(), 0);
    assert.deepEqual(f.errors, []);
  } finally { await f.page.close(); }
});

test('missing ECS precision and malformed ECS stay visible without losing a valid DNS observation', async () => {
  for (const ecs of ['1.1.1.0', 'not-an-ip']) {
    const f = await fixture({ecs});
    try {
      await f.page.goto(origin);
      await finished(f.page);
      const row = await f.page.locator('[data-probe="dns"]').innerText();
      assert.match(row, /8\.8\.8\.8/); assert.match(row, /已返回/);
      assert.match(row, ecs === 'not-an-ip' ? /EDNS 字段未能确认/ : /EDNS 客户端信息/);
      assert.doesNotMatch(await f.page.locator('.conn-findings').innerText(), /EDNS 携带不同的公网客户端子网/);
      assert.deepEqual(f.errors, []);
    } finally { await f.page.close(); }
  }
});

test('retest uses a fresh DNS name; desktop and mobile stay within the viewport', async () => {
  for (const width of [1440, 393]) {
    const f = await fixture({width});
    try {
      await f.page.goto(origin);
      await finished(f.page);
      await f.page.getByRole('button', {name: '重新检测连接'}).click();
      await finished(f.page);
      const dns = f.seen.filter(u => u.hostname.endsWith('.edns.ip-api.com')).map(u => u.hostname);
      assert.equal(dns.length, 2); assert.equal(new Set(dns).size, 2);
      const overflow = await f.page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
      assert.equal(overflow, 0, `${width}px viewport overflow`);
      assert.deepEqual(f.errors, []);
      if (process.env.IP_LOOKUP_SCREENSHOTS) await f.page.screenshot({path: join(process.env.IP_LOOKUP_SCREENSHOTS,
        width === 1440 ? 'desktop.png' : 'mobile.png'), fullPage: true});
    } finally { await f.page.close(); }
  }
});
