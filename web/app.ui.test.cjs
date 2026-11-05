// Browser regression tests use synthetic API responses; no third-party traffic leaves this suite.
// Run: node --test web/app.ui.test.cjs
// Optional screenshots: IP_LOOKUP_SCREENSHOTS=/absolute/path node --test web/app.ui.test.cjs
'use strict';

const {test, before, after} = require('node:test');
const assert = require('node:assert/strict');
const {createServer} = require('node:http');
const {readFile, mkdir} = require('node:fs/promises');
const {existsSync} = require('node:fs');
const {join} = require('node:path');

const playwright = ['playwright', '/opt/homebrew/lib/node_modules/@playwright/cli/node_modules/playwright']
  .map(name => { try { return require.resolve(name); } catch { return null; } }).find(Boolean);
if (!playwright) throw new Error('Install Playwright to run browser tests; this suite downloads no dependencies.');
const {chromium} = require(playwright);

const SELF = '1.1.1.1', TARGET = '8.8.8.8';
const V6 = '2606:4700:4700:1111:2222:3333:4444:5555';
let browser, server, origin;

before(async () => {
  const assets = new Map([
    ['/static/app.js', ['static/app.js', 'application/javascript']],
    ['/static/style.css', ['static/style.css', 'text/css']],
    ['/static/favicon.svg', ['static/favicon.svg', 'image/svg+xml']],
  ]);
  server = createServer(async (req, res) => {
    const path = new URL(req.url, 'http://localhost').pathname;
    const asset = assets.get(path);
    try {
      if (asset) {
        res.writeHead(200, {'Content-Type': asset[1]});
        return res.end(await readFile(join(__dirname, asset[0])));
      }
      if (path.startsWith('/api/') || path.startsWith('/static/')) return res.writeHead(404).end();
      const ip = decodeURIComponent(path.slice(1)) || SELF;
      const html = (await readFile(join(__dirname, 'index.html'), 'utf8')).replaceAll('__IP_ADDRESS__', ip);
      res.writeHead(200, {'Content-Type': 'text/html; charset=utf-8'});
      res.end(html);
    } catch {
      res.writeHead(500).end();
    }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  origin = `http://127.0.0.1:${server.address().port}`;
  const cached = join(process.env.HOME, 'Library/Caches/ms-playwright/chromium_headless_shell-1228/chrome-headless-shell-mac-arm64/chrome-headless-shell');
  browser = await chromium.launch({headless: true,
    ...(process.env.CHROMIUM_PATH ? {executablePath: process.env.CHROMIUM_PATH}
      : existsSync(cached) ? {executablePath: cached} : {})});
});

after(async () => {
  await browser?.close();
  if (server) await new Promise(resolve => server.close(resolve));
});

function deferred() {
  let resolve;
  const promise = new Promise(done => { resolve = done; });
  return {promise, resolve};
}

function report(ip, value = ip === TARGET ? 42 : 85) {
  return {
    ip, version: ip.includes(':') ? 6 : 4, mode: 'full', queried_at: '2026-11-05T07:00:00Z', elapsed_ms: 12,
    verdict: {type: 'cdn', type_label: 'CDN', label: 'CDN', confidence: 'high',
      evidence: [{kind: 'cdn', source: 'Fixture Evidence Source', detail: 'Fixture Evidence Detail', weight: 15}]},
    score: {value, level: value >= 80 ? '纯净' : '中性', factors: [{name: 'Fixture Score Deduction', delta: -15}]},
    flags: {is_cdn: true},
    geo: {country: 'Fixture Country', country_code: 'AU', city: 'Fixture City', lat: -33.86, lon: 151.2},
    network: {asn: 13335, as_name: 'Fixture Network Name', isp: 'Fixture ISP'},
    geo_sources: [{source: 'Fixture Geolocation Source', country: 'Fixture Country', city: 'Fixture City'}],
    sources: [{name: 'Fixture Provider Source', status: 'ok'}],
  };
}

async function fixture({width = 1440, colorScheme = 'light', javascriptEnabled = true,
  lookup = ip => ({json: report(ip)}), clientIP = () => ({json: {ip: SELF, version: 4}}), clipboardOK = true} = {}) {
  const context = await browser.newContext({viewport: {width, height: width === 393 ? 852 : 900},
    colorScheme, javaScriptEnabled: javascriptEnabled, timezoneId: 'Asia/Shanghai'});
  const page = await context.newPage();
  page.setDefaultTimeout(5000);
  const requests = [], external = [], errors = [];
  let closed = false;
  page.on('pageerror', error => errors.push(error.message));
  await page.addInitScript(({clipboardOK}) => {
    window.__uiFetches = [];
    window.__uiProbeCalls = 0;
    const nativeFetch = window.fetch.bind(window);
    window.fetch = (input, options) => {
      const entry = {url: new URL(typeof input === 'string' ? input : input.url, location.href).href, aborted: false};
      window.__uiFetches.push(entry);
      options?.signal?.addEventListener('abort', () => { entry.aborted = true; }, {once: true});
      return nativeFetch(input, options).catch(error => {
        if (error.name === 'AbortError') entry.aborted = true;
        throw error;
      });
    };
    window.RTCPeerConnection = class {
      constructor() { window.__uiProbeCalls++; throw new Error('The simple IP page must not start WebRTC probes.'); }
    };
    Object.defineProperty(navigator, 'clipboard', {configurable: true, value: {
      writeText: async text => {
        if (!clipboardOK) throw new Error('Synthetic clipboard denial');
        window.__uiCopied = text;
      },
    }});
    if (!clipboardOK) document.execCommand = () => false;
  }, {clipboardOK});
  await page.route('**/*', async route => {
    const url = new URL(route.request().url());
    const done = deferred(), request = {url, method: route.request().method(), done: done.promise};
    requests.push(request);
    try {
      if (url.origin !== origin) {
        external.push(url.origin + url.pathname);
        return await route.abort();
      }
      if (url.pathname === '/api/lookup' || url.pathname === '/api/ip') {
        const ip = url.searchParams.get('ip') || SELF;
        const response = await (url.pathname === '/api/lookup' ? lookup(ip, request) : clientIP(request));
        return await route.fulfill(response);
      }
      await route.continue();
    } catch (error) {
      if (!closed && !/Target .*closed|Request is already handled|Invalid InterceptionId|intercepted request/i.test(error.message)) {
        errors.push(error.message);
      }
    } finally {
      done.resolve();
    }
  });
  return {page, requests, external, errors,
    lookups: () => requests.filter(request => request.url.pathname === '/api/lookup'),
    ipRequests: () => requests.filter(request => request.url.pathname === '/api/ip'),
    async close() { closed = true; await context.close(); },
  };
}

async function textIs(page, selector, value) {
  await page.waitForFunction(([selector, value]) => document.querySelector(selector)?.textContent.trim() === value,
    [selector, String(value)]);
}

async function settled(page, ip, score) {
  await textIs(page, '#ipAddress', ip);
  await textIs(page, '#scoreValue', score);
  await page.waitForFunction(() => document.querySelector('#result')?.getAttribute('aria-busy') === 'false');
}

async function submit(page, ip) {
  await page.locator('#qi').fill(ip);
  await page.locator('#q').evaluate(form => form.requestSubmit());
}

async function onlyExpectedTraffic(f) {
  assert.deepEqual(f.external, [], 'the simple page must make no external requests');
  assert.equal(f.requests.some(({url}) => /connection\.js|leaflet|\/tiles?\b/.test(url.pathname)), false,
    'connection and map components must not be loaded');
  assert.ok(f.lookups().length > 0, 'the page must actually query the full report');
  assert.equal(f.lookups().some(({url}) => url.searchParams.get('mode') === 'fast'), false,
    'an offline-only report must not be used as a provisional purity score');
  assert.equal(await f.page.evaluate(() => window.__uiProbeCalls), 0);
  assert.deepEqual(f.errors, []);
}

async function screenshot(page, name) {
  if (!process.env.IP_LOOKUP_SCREENSHOTS) return;
  await mkdir(process.env.IP_LOOKUP_SCREENSHOTS, {recursive: true});
  await page.screenshot({path: join(process.env.IP_LOOKUP_SCREENSHOTS, name + '.png'), fullPage: true});
}

test('the server-rendered IP is readable before JavaScript runs', async () => {
  for (const path of ['/', '/' + TARGET]) {
    const f = await fixture({javascriptEnabled: false});
    try {
      await f.page.goto(origin + path);
      assert.equal((await f.page.locator('#ipAddress').innerText()).trim(), path === '/' ? SELF : TARGET);
      assert.equal((await f.page.locator('#scoreValue').innerText()).trim(), '—');
      assert.equal(f.lookups().length, 0);
      assert.deepEqual(f.external, []);
    } finally { await f.close(); }
  }
});

test('a pending full report immediately shows the IP without inventing a purity score', async () => {
  const gate = deferred();
  const f = await fixture({lookup: () => gate.promise});
  try {
    await f.page.goto(origin);
    await f.page.waitForFunction(() => window.__uiFetches.some(({url}) => new URL(url).pathname === '/api/lookup'));
    await textIs(f.page, '#ipAddress', SELF);
    await textIs(f.page, '#ipLabel', '我的 IP');
    await textIs(f.page, '#scoreValue', '—');
    assert.match(await f.page.locator('#scoreLevel').innerText(), /^评估中/);
    assert.equal(await f.page.locator('#result').getAttribute('aria-busy'), 'true');
    assert.equal(f.lookups().length, 1, 'one full lookup is enough for the first render');
    assert.equal(f.ipRequests().length, 0, 'an IP already rendered by the server needs no extra discovery request');
    await screenshot(f.page, 'loading');
    gate.resolve({json: report(SELF)});
    await settled(f.page, SELF, 85);
    await onlyExpectedTraffic(f);
  } finally { gate.resolve({json: report(SELF)}); await f.close(); }
});

test('a completed report exposes IP and purity only, with license text hidden until requested', async () => {
  const f = await fixture();
  try {
    await f.page.goto(origin);
    await settled(f.page, SELF, 85);
    await textIs(f.page, '#scoreLevel', '纯净');
    await textIs(f.page, '#scoreTotal', '/100');
    assert.equal(await f.page.locator('#copy').isVisible(), true);
    const bodyText = await f.page.locator('body').textContent();
    assert.doesNotMatch(bodyText, /Fixture (?:Country|City|Network Name|ISP|Evidence|Score Deduction|Geolocation Source|Provider Source)/,
      'extra API fields must not be rendered into hidden result panels');
    assert.doesNotMatch(bodyText, /Merged-IP|IP Geolocation by DB-IP|OpenStreetMap/,
      'the removed source and map copyright sentence must not remain in collapsed content');
    assert.equal(await f.page.locator('table, #connection, .map, .mapcard, .factors').count(), 0);
    const visibleText = await f.page.locator('body').innerText();
    assert.doesNotMatch(visibleText, /\bASN\b|地理位置|位置地图|判定依据|多源地理|连接明细|扣分|CC BY/);
    const attribution = f.page.locator('#attribution');
    assert.equal(await f.page.locator('details').count(), 1, 'only data attribution is expandable');
    assert.equal(await attribution.getAttribute('open'), null);
    await textIs(f.page, '#attribution summary', '数据说明');
    await attribution.locator('summary').click();
    assert.equal(await attribution.getAttribute('open'), '');
    assert.match(await attribution.innerText(), /CC BY|许可|DB-IP|Merged-IP/);
    await attribution.locator('summary').click();
    assert.doesNotMatch(await f.page.locator('body').innerText(), /CC BY/);
    assert.equal(f.lookups().length, 1);
    await onlyExpectedTraffic(f);
  } finally { await f.close(); }
});

test('input validation, lookup, back/forward navigation and repeated self lookup preserve the selected IP', async () => {
  const f = await fixture();
  try {
    await f.page.goto(origin);
    await settled(f.page, SELF, 85);
    const initialRequests = f.lookups().length;
    for (const invalid of ['not-an-ip', '192.0.2.1::', '1:2:3:4:5:192.0.2.1::']) {
      await submit(f.page, invalid);
      assert.equal(await f.page.locator('#qerr').isVisible(), true);
      assert.equal(await f.page.locator('#qi').getAttribute('aria-invalid'), 'true');
      assert.equal(new URL(f.page.url()).pathname, '/');
      assert.equal(f.lookups().length, initialRequests);
    }
    await settled(f.page, SELF, 85);
    await submit(f.page, TARGET);
    await settled(f.page, TARGET, 42);
    await textIs(f.page, '#ipLabel', 'IP 地址');
    assert.equal(await f.page.locator('#qerr').isVisible(), false);
    assert.equal(new URL(f.page.url()).pathname, '/' + TARGET);
    await f.page.goBack();
    await settled(f.page, SELF, 85);
    await f.page.goForward();
    await settled(f.page, TARGET, 42);
    await f.page.locator('#me').click();
    await settled(f.page, SELF, 85);
    assert.equal(new URL(f.page.url()).pathname, '/');
    const previousCount = f.lookups().length, previousIPCount = f.ipRequests().length;
    await f.page.locator('#me').click();
    await f.page.waitForFunction(expected => window.__uiFetches.filter(({url}) => new URL(url).pathname === '/api/lookup').length === expected,
      previousCount + 1);
    await settled(f.page, SELF, 85);
    assert.equal(f.lookups().length, previousCount + 1, '查我的 IP also rechecks an already selected self IP');
    assert.equal(f.ipRequests().length, previousIPCount + 1);
    await onlyExpectedTraffic(f);
  } finally { await f.close(); }
});

test('查我的 IP shows the quick IP while its full purity report is still pending', async () => {
  const full = deferred(), ip = deferred();
  const f = await fixture({lookup: address => address === SELF ? full.promise : {json: report(address)}, clientIP: () => ip.promise});
  try {
    await f.page.goto(origin + '/' + TARGET);
    await settled(f.page, TARGET, 42);
    await f.page.locator('#me').click();
    await f.page.waitForFunction(() => window.__uiFetches.some(({url}) => new URL(url).pathname === '/api/ip'));
    await textIs(f.page, '#scoreValue', '—');
    ip.resolve({json: {ip: SELF, version: 4}});
    await textIs(f.page, '#ipAddress', SELF);
    await textIs(f.page, '#ipLabel', '我的 IP');
    await textIs(f.page, '#scoreValue', '—');
    assert.equal(await f.page.locator('#result').getAttribute('aria-busy'), 'true');
    assert.equal(f.lookups().length, 2);
    full.resolve({json: report(SELF, 93)});
    await settled(f.page, SELF, 93);
    await onlyExpectedTraffic(f);
  } finally {
    ip.resolve({json: {ip: SELF, version: 4}});
    full.resolve({json: report(SELF, 93)});
    await f.close();
  }
});

test('changing the query aborts the previous fetch and a late report cannot mix its IP or score into the result', async () => {
  const stale = deferred();
  const f = await fixture({lookup: ip => ip === SELF ? stale.promise : {json: report(ip, 42)}});
  try {
    await f.page.goto(origin);
    await f.page.waitForFunction(() => window.__uiFetches.some(({url}) => new URL(url).pathname === '/api/lookup'));
    const oldRequest = f.lookups()[0];
    await submit(f.page, TARGET);
    await settled(f.page, TARGET, 42);
    await f.page.waitForFunction(() => window.__uiFetches.some(({url, aborted}) => {
      const parsed = new URL(url);
      return parsed.pathname === '/api/lookup' && !parsed.searchParams.has('ip') && aborted;
    }));
    stale.resolve({json: report(SELF, 99)});
    await oldRequest.done;
    // Cross a rendering boundary after the old response handler has had a chance to settle.
    await f.page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await settled(f.page, TARGET, 42);
    await textIs(f.page, '#ipLabel', 'IP 地址');
    assert.equal(new URL(f.page.url()).pathname, '/' + TARGET);
    await onlyExpectedTraffic(f);
  } finally { stale.resolve({json: report(SELF, 99)}); await f.close(); }
});

test('a late quick self-IP response cannot replace a newer explicit query', async () => {
  const quick = deferred(), full = deferred();
  const f = await fixture({lookup: ip => ip === SELF ? full.promise : {json: report(ip)}, clientIP: () => quick.promise});
  try {
    await f.page.goto(origin + '/' + TARGET);
    await settled(f.page, TARGET, 42);
    await f.page.locator('#me').click();
    await f.page.waitForFunction(() => window.__uiFetches.some(({url}) => new URL(url).pathname === '/api/ip'));
    const quickRequest = f.ipRequests()[0], fullRequest = f.lookups().at(-1);
    await submit(f.page, '9.9.9.9');
    await settled(f.page, '9.9.9.9', 85);
    await f.page.waitForFunction(() => window.__uiFetches.some(({url, aborted}) => new URL(url).pathname === '/api/ip' && aborted));
    quick.resolve({json: {ip: SELF, version: 4}});
    full.resolve({json: report(SELF, 99)});
    await Promise.all([quickRequest.done, fullRequest.done]);
    await f.page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await settled(f.page, '9.9.9.9', 85);
    await onlyExpectedTraffic(f);
  } finally {
    quick.resolve({json: {ip: SELF, version: 4}});
    full.resolve({json: report(SELF, 99)});
    await f.close();
  }
});

for (const [name, status, json] of [
  ['full-report failure', 503, {error: 'Synthetic provider unavailable'}],
  ['rate limiting', 429, {error: '查询太频繁', retry_after: 7}],
]) {
  test(`${name} retains the IP and leaves purity unknown instead of showing 0 or 100`, async () => {
    const f = await fixture({lookup: () => ({status, json})});
    try {
      await f.page.goto(origin + '/' + TARGET);
      await settled(f.page, TARGET, '—');
      await textIs(f.page, '#scoreLevel', '未能评估');
      const message = (await f.page.locator('#status').innerText()).trim();
      assert.ok(message.length > 0, 'the failure must be visible');
      if (status === 429) assert.match(message, /频繁|稍后|7/);
      assert.equal(f.lookups().length, 1, 'a failed full report must not fall back to an offline purity score');
      await onlyExpectedTraffic(f);
    } finally { await f.close(); }
  });
}

test('reserved addresses have no numerical purity rating', async () => {
  const ip = '192.0.2.1';
  const f = await fixture({lookup: () => ({json: {...report(ip, 0), bogon: '文档示例地址（TEST-NET-1）'}})});
  try {
    await f.page.goto(origin + '/' + ip);
    await settled(f.page, ip, '—');
    assert.equal(await f.page.locator('#scoreTotal').isVisible(), false);
    assert.match(await f.page.locator('body').innerText(), /文档示例地址|保留地址/);
    assert.doesNotMatch(await f.page.locator('#scoreLevel').innerText(), /纯净|可疑/);
    await onlyExpectedTraffic(f);
  } finally { await f.close(); }
});

test('copying the displayed IP gives success or failure feedback', async () => {
  for (const clipboardOK of [true, false]) {
    const f = await fixture({clipboardOK});
    try {
      await f.page.goto(origin + '/' + TARGET);
      await settled(f.page, TARGET, 42);
      await f.page.locator('#copy').click();
      await textIs(f.page, '#copy', clipboardOK ? '已复制' : '复制失败');
      if (clipboardOK) assert.equal(await f.page.evaluate(() => window.__uiCopied), TARGET);
      await onlyExpectedTraffic(f);
    } finally { await f.close(); }
  }
});

for (const [name, width, colorScheme] of [['desktop', 1440, 'light'], ['mobile', 393, 'light'], ['dark', 1440, 'dark']]) {
  test(`${name}: a long IPv6 address remains readable without horizontal page overflow`, async () => {
    const f = await fixture({width, colorScheme});
    try {
      await f.page.goto(origin + '/' + V6);
      await settled(f.page, V6, 85);
      assert.equal(await f.page.locator('#ipAddress').isVisible(), true);
      const dimensions = await f.page.evaluate(() => {
        const ip = document.querySelector('#ipAddress'), root = document.documentElement;
        const bounds = ip.getBoundingClientRect();
        return {viewport: root.clientWidth, pageWidth: root.scrollWidth, left: bounds.left, right: bounds.right,
          ipWidth: ip.clientWidth, ipContentWidth: ip.scrollWidth,
          dark: matchMedia('(prefers-color-scheme: dark)').matches};
      });
      assert.equal(dimensions.pageWidth, dimensions.viewport, `${width}px page must not scroll horizontally`);
      assert.ok(dimensions.left >= 0 && dimensions.right <= dimensions.viewport, 'the complete IP element must fit on screen');
      assert.ok(dimensions.ipContentWidth <= dimensions.ipWidth + 1, 'the IP must wrap or scale rather than clip inside its own element');
      assert.equal(dimensions.dark, colorScheme === 'dark');
      await screenshot(f.page, name);
      await onlyExpectedTraffic(f);
    } finally { await f.close(); }
  });
}
