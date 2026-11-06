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
    ['/static/vendor/leaflet/leaflet.js', ['static/vendor/leaflet/leaflet.js', 'application/javascript']],
    ['/static/vendor/leaflet/leaflet.css', ['static/vendor/leaflet/leaflet.css', 'text/css']],
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
    score: {value, level: value >= 95 ? '极度纯净' : value >= 80 ? '纯净' : value >= 50 ? '良好' : value >= 25 ? '中性' : '可疑',
      factors: [{name: 'Fixture Score Deduction', delta: -15}]},
    flags: {is_cdn: true},
    native: {status: 'native', label: '原生 IP', registered_country: 'AU', geo_country: 'AU', registry: 'Fixture Registry'},
    geo: {country: 'Fixture Country', country_code: 'AU', region: 'Fixture Region', city: 'Fixture City', lat: 0, lon: 0},
    network: {asn: 13335, as_name: 'Fixture Network Name', as_domain: 'example.org', as_country: 'AU',
      net_range: '1.1.1.0 – 1.1.1.255', prefix: '1.1.1.0/24', isp: 'Fixture ISP', org: 'Fixture Organization'},
    geo_sources: [
      {source: 'Merged-IP', country: 'Fixture Country', country_code: 'AU', region: 'Fixture Region', city: 'Fixture City'},
      {source: 'Fixture Hidden Geolocation Source', country: 'Fixture Hidden Geolocation Country'},
    ],
    risk: [{source: 'Fixture Provider Source', value: 0, detail: 'Fixture Risk Detail'}],
    dnsbl: [
      {zone: 'clean.fixture.test', listed: false},
      {zone: 'error.fixture.test', listed: false, error: 'Fixture DNSBL Timeout'},
    ],
    sources: [
      {name: 'Fixture Provider Source', kind: 'online', status: 'ok', ms: 8, reputation_source: true, reputation: true},
      {name: 'Fixture Failed Source', kind: 'online', status: 'timeout', ms: 12,
        error: 'Fixture Source Timeout', reputation_source: true},
      {name: 'DNSBL', kind: 'dns', status: 'ok', ms: 3},
    ],
  };
}

function locatedReport(ip, value) {
  const result = report(ip, value);
  result.score.data_status = 'limited';
  result.score.coverage = {received: 3, total: 6};
  return {...result, geo: {...result.geo, lat: -33.86, lon: 151.2, accuracy_km: 10}};
}

async function fixture({width = 1440, height = width === 393 ? 852 : 900, colorScheme = 'light', javascriptEnabled = true,
  lookup = ip => ({json: report(ip)}), clipboardOK = true} = {}) {
  const context = await browser.newContext({viewport: {width, height},
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
      constructor() { window.__uiProbeCalls++; throw new Error('The IP report must not start WebRTC probes.'); }
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
        if (url.protocol === 'https:' && url.hostname === 'tile.openstreetmap.org' && /^\/\d+\/\d+\/\d+\.png$/.test(url.pathname)) {
          return await route.fulfill({contentType: 'image/png', body: Buffer.from(
            'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mP8/x8AAusB9Wl6ZWQAAAAASUVORK5CYII=', 'base64')});
        }
        return await route.abort();
      }
      if (url.pathname === '/api/lookup' || url.pathname === '/api/ip') {
        const ip = url.searchParams.get('ip') || SELF;
        let response = url.pathname === '/api/lookup' ? await lookup(ip, request) : {json: {ip: SELF, version: 4}};
        if (response.json && url.pathname === '/api/lookup') {
          response = {...response, json: {...response.json, mode: url.searchParams.get('mode') || 'full'}};
        }
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

async function openScoreDetails(page) {
  const toggle = page.locator('#scoreDetailsToggle');
  assert.equal(await toggle.evaluate(button => button.tagName), 'BUTTON');
  assert.equal((await toggle.innerText()).trim(), '评分详情');
  assert.equal(await toggle.isEnabled(), true);
  await toggle.click();
  await page.locator('#scoreDetails').waitFor({state: 'visible'});
  assert.equal(await page.locator('#scoreDetails').evaluate(dialog => dialog instanceof HTMLDialogElement && dialog.open), true);
}

async function onlyExpectedTraffic(f, {map = false} = {}) {
  if (map) {
    assert.ok(f.external.every(url => /^https:\/\/tile\.openstreetmap\.org\/\d+\/\d+\/\d+\.png$/.test(url)),
      'only map tile requests may leave the site');
  } else {
    assert.deepEqual(f.external, [], 'a report without coordinates must make no external requests');
    assert.equal(f.requests.some(({url}) => /leaflet/.test(url.pathname)), false,
      'a report without coordinates must not load the map library');
  }
  assert.equal(f.requests.some(({url}) => /connection\.js/.test(url.pathname)), false,
    'the removed connection probes must not be loaded');
  assert.ok(f.lookups().some(({url}) => url.searchParams.get('mode') === 'fast'));
  assert.ok(f.lookups().some(({url}) => url.searchParams.get('mode') === 'full'));
  assert.equal(f.ipRequests().length, 0, 'fast lookup already provides the IP without a separate discovery request');
  assert.equal(await f.page.evaluate(() => window.__uiProbeCalls), 0);
  assert.deepEqual(f.errors, []);
}

async function screenshot(page, name, {fullPage = true} = {}) {
  if (!process.env.IP_LOOKUP_SCREENSHOTS) return;
  await mkdir(process.env.IP_LOOKUP_SCREENSHOTS, {recursive: true});
  await page.screenshot({path: join(process.env.IP_LOOKUP_SCREENSHOTS, name + '.png'), fullPage});
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

test('fast lookup shows the upper report while its purity rating waits for the full lookup', async () => {
  const gate = deferred();
  const f = await fixture({lookup: (ip, {url}) => url.searchParams.get('mode') === 'full'
    ? gate.promise : {json: report(ip, 100)}});
  try {
    await f.page.goto(origin);
    await f.page.waitForFunction(() => window.__uiFetches.some(({url}) => new URL(url).pathname === '/api/lookup'));
    await textIs(f.page, '#ipAddress', SELF);
    await f.page.getByText('Fixture Network Name', {exact: true}).first().waitFor();
    await textIs(f.page, '#scoreValue', '—');
    assert.match(await f.page.locator('#scoreLevel').innerText(), /^评估中/);
    assert.equal(await f.page.locator('#result').getAttribute('aria-busy'), 'true');
    assert.equal(await f.page.locator('#scoreDetailsToggle').isEnabled(), false,
      'an incomplete assessment must not open stale score details');
    assert.equal(await f.page.locator('#scoreDetails').isVisible(), false);
    assert.deepEqual(f.lookups().map(({url}) => url.searchParams.get('mode')).sort(), ['fast', 'full']);
    assert.equal(f.ipRequests().length, 0, 'an IP already rendered by the server needs no extra discovery request');
    await screenshot(f.page, 'loading');
    gate.resolve({json: report(SELF)});
    await settled(f.page, SELF, 85);
    await onlyExpectedTraffic(f);
  } finally { gate.resolve({json: report(SELF)}); await f.close(); }
});

test('the upper report shows IP type, geography and network while the removed lower sections stay absent', async () => {
  const f = await fixture();
  try {
    await f.page.goto(origin);
    await settled(f.page, SELF, 85);
    await textIs(f.page, '#scoreLevel', '纯净');
    await textIs(f.page, '#scoreTotal', '/100');
    assert.equal(await f.page.locator('#copy').isVisible(), true);
    const summary = await f.page.locator('#result').innerText();
    assert.match(summary, /AS13335/);
    assert.match(summary, /example\.org/);
    assert.match(summary, /1\.1\.1\.0.*1\.1\.1\.255/);
    assert.match(summary, /Fixture (?:City|Region)/);
    assert.match(summary, /原生 IP/);
    assert.match(summary, /置信度/);
    assert.match(summary, /CDN/);
    assert.equal(await f.page.locator('#result .ring').isVisible(), true);
    assert.equal(await f.page.getByRole('heading', {name: '地理位置', exact: true}).isVisible(), true);
    assert.equal(await f.page.getByRole('heading', {name: /^网络(?:资料|信息)?$/}).isVisible(), true);
    const visibleText = await f.page.locator('body').innerText();
    assert.match(visibleText, /Fixture Country/);
    assert.match(visibleText, /Fixture Network Name/);
    assert.match(visibleText, /Fixture ISP/);
    assert.doesNotMatch(visibleText, /Fixture (?:Evidence|Score Deduction|Hidden Geolocation|Provider Source)/,
      'score deductions and source details appear only after opening score details');
    assert.doesNotMatch(await f.page.locator('#out').textContent(), /Fixture (?:Evidence|Score Deduction|Hidden Geolocation|Provider Source)/,
      'removed lower panels must not be hidden inside the main report');
    assert.equal(await f.page.locator('#out table, #connection, #out .map, #out .mapcard, #out .factors, #evidenceCard').count(), 0);
    assert.doesNotMatch(visibleText, /判定依据|多源地理|我的连接|连接明细|扣分|CC BY/);
    assert.equal(await f.page.locator('details').count(), 0, 'removed content must not be kept in collapsed panels');
    assert.equal(await f.page.locator('#attribution').count(), 0);
    assert.equal(await f.page.getByText('数据说明', {exact: true}).count(), 0,
      'the data attribution entry has been removed from the page');
    const gh = f.page.locator('footer a.gh-link');
    assert.equal(await gh.isVisible(), true);
    assert.equal(await gh.getAttribute('href'), 'https://github.com/zzusec/ip-lookup');
    assert.equal(await gh.getAttribute('target'), '_blank');
    assert.equal(await gh.getAttribute('rel'), 'noopener noreferrer');
    assert.equal(await f.page.locator('#scoreDetails').isVisible(), false);
    assert.equal(await f.page.locator('#scoreDetails').evaluate(dialog => dialog.closest('#out')), null,
      'the native dialog must survive result replacement outside #out');
    assert.equal(f.lookups().length, 2);
    await onlyExpectedTraffic(f);
  } finally { await f.close(); }
});

test('score details explain deductions, normalised risks, DNSBL results and source status in a dismissible dialog', async () => {
  const f = await fixture({lookup: ip => {
    const result = report(ip, 70);
    result.score.factors = [
      {name: 'Fixture Score Deduction', delta: -15},
      {name: 'DNSBL 命中 1 个', delta: -5},
      {name: '第三方风险分均值 40', delta: -10},
    ];
    result.score.data_status = 'limited';
    result.score.coverage = {received: 1, total: 2};
    Object.assign(result.risk[0], {value: 60, effective_value: 40, scoring_note: 'Fixture Risk Scoring Note'});
    result.dnsbl.unshift({zone: 'listed.fixture.test', listed: true, answer: '127.0.0.2'});
    result.sources[1].status = 'quota';
    result.sources[1].error = 'Fixture Source Error';
    result.sources[0].note = 'Fixture Source Note';
    return {json: result};
  }});
  try {
    await f.page.goto(origin + '/' + TARGET);
    await settled(f.page, TARGET, 70);
    assert.equal(await f.page.locator('#scoreDetails').isVisible(), false);
    assert.doesNotMatch(await f.page.locator('body').innerText(), /Fixture Score Deduction|listed\.fixture\.test/);
    await openScoreDetails(f.page);
    const details = await f.page.locator('#scoreDetailsBody').innerText();
    assert.ok(details.includes(TARGET), 'the detail view identifies the currently assessed IP');
    assert.match(details, /70/);
    assert.match(details, /Fixture Score Deduction/);
    assert.match(details, /-15|−15/);
    assert.match(details, /DNSBL 命中 1 个/);
    assert.match(details, /-5|−5/);
    assert.match(details, /第三方风险分均值 40/);
    assert.match(details, /-10|−10/);
    assert.match(details, /Fixture Provider Source/);
    assert.match(details, /Fixture Risk Detail/);
    assert.match(details, /60\s*\/\s*100/);
    assert.match(details, /40\s*\/\s*100/);
    assert.match(details, /Fixture Risk Scoring Note/);
    assert.match(details, /计分风险均值\s*40/);
    assert.match(details, /4.*取整.*扣\s*10\s*分/);
    assert.match(details, /标准化|归一化/);
    assert.match(details, /越高.{0,12}(?:风险|危险)|风险.{0,12}越高/);
    assert.match(details, /listed\.fixture\.test/);
    assert.match(details, /127\.0\.0\.2/);
    assert.match(details, /clean\.fixture\.test/);
    assert.match(details, /未命中/);
    assert.match(details, /error\.fixture\.test/);
    assert.match(details, /Fixture DNSBL Timeout/);
    assert.match(details, /Fixture Failed Source/);
    assert.match(details, /Fixture Source Error/);
    assert.match(details, /Fixture Source Note/);
    assert.match(details, /配额|额度|quota/);
    assert.match(details, /数据有限/);
    await screenshot(f.page, 'details', {fullPage: false});
    await f.page.keyboard.press('Escape');
    await f.page.locator('#scoreDetails').waitFor({state: 'hidden'});
    assert.equal(await f.page.evaluate(() => document.activeElement?.id), 'scoreDetailsToggle');
    await openScoreDetails(f.page);
    assert.equal(await f.page.locator('#scoreDetailsClose').evaluate(button => button.tagName), 'BUTTON');
    await f.page.locator('#scoreDetailsClose').click();
    await f.page.locator('#scoreDetails').waitFor({state: 'hidden'});
    assert.equal(await f.page.evaluate(() => document.activeElement?.id), 'scoreDetailsToggle');
    await settled(f.page, TARGET, 70);
    await onlyExpectedTraffic(f);
  } finally { await f.close(); }
});

test('score details treat provider names, risk details and errors as text', async () => {
  const source = '<img src=x onerror="window.__scoreInjected=true">';
  const riskDetail = '<script>window.__scoreInjected=true</script>';
  const sourceError = '<svg onload="window.__scoreInjected=true">Source error</svg>';
  const dnsError = '<img src=x onerror="window.__scoreInjected=true">DNS error';
  const f = await fixture({lookup: ip => {
    const result = report(ip, 70);
    result.score.factors.push({name: '第三方风险分均值 60', delta: -15});
    result.risk = [{source, value: 60, detail: riskDetail}];
    result.dnsbl = [{zone: 'unsafe.fixture.test', listed: false, error: dnsError}];
    result.sources = [{name: source, kind: 'online', status: 'error', error: sourceError}];
    return {json: result};
  }});
  try {
    await f.page.goto(origin);
    await settled(f.page, SELF, 70);
    await openScoreDetails(f.page);
    const details = await f.page.locator('#scoreDetailsBody').innerText();
    for (const literal of [source, riskDetail, sourceError, dnsError]) assert.ok(details.includes(literal));
    assert.equal(await f.page.locator('#scoreDetailsBody img, #scoreDetailsBody svg, #scoreDetailsBody script, #scoreDetailsBody [onerror], #scoreDetailsBody [onload]').count(), 0);
    assert.equal(await f.page.evaluate(() => window.__scoreInjected), undefined);
    await onlyExpectedTraffic(f);
  } finally { await f.close(); }
});

test('legacy score factors remain readable when optional risk and DNSBL fields are absent', async () => {
  const f = await fixture({lookup: ip => {
    const result = report(ip);
    delete result.risk;
    delete result.dnsbl;
    return {json: result};
  }});
  try {
    await f.page.goto(origin);
    await settled(f.page, SELF, 85);
    await openScoreDetails(f.page);
    const details = await f.page.locator('#scoreDetailsBody').innerText();
    assert.match(details, /Fixture Score Deduction/);
    assert.match(details, /-15|−15/);
    assert.match(details, /风险/);
    assert.match(details, /DNSBL/);
    assert.match(details, /暂无|没有|未返回|未提供/);
    await onlyExpectedTraffic(f);
  } finally { await f.close(); }
});

test('a new lookup closes and clears score details before showing the next IP assessment', async () => {
  const next = deferred();
  const perIP = ip => {
    const result = report(ip, 85);
    result.score.factors = [{name: ip === SELF ? 'Previous IP deduction' : 'Current IP deduction', delta: -15}];
    return result;
  };
  const f = await fixture({lookup: (ip, {url}) => ip === TARGET && url.searchParams.get('mode') === 'full'
    ? next.promise : {json: perIP(ip)}});
  try {
    await f.page.goto(origin);
    await settled(f.page, SELF, 85);
    await openScoreDetails(f.page);
    assert.match(await f.page.locator('#scoreDetailsBody').innerText(), /Previous IP deduction/);
    // A browser navigation or external query can start while a modal is open.
    await f.page.locator('#qi').evaluate((input, ip) => {
      input.value = ip;
      input.form.requestSubmit();
    }, TARGET);
    await f.page.locator('#scoreDetails').waitFor({state: 'hidden'});
    assert.equal((await f.page.locator('#scoreDetailsBody').textContent()).trim(), '',
      'the old detail snapshot must be removed as soon as the query changes');
    assert.equal(await f.page.locator('#scoreDetailsToggle').isEnabled(), false);
    next.resolve({json: perIP(TARGET)});
    await settled(f.page, TARGET, 85);
    await openScoreDetails(f.page);
    const details = await f.page.locator('#scoreDetailsBody').innerText();
    assert.ok(details.includes(TARGET));
    assert.match(details, /Current IP deduction/);
    assert.doesNotMatch(details, /Previous IP deduction|1\.1\.1\.1/);
    await onlyExpectedTraffic(f);
  } finally { next.resolve({json: perIP(TARGET)}); await f.close(); }
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
    assert.equal(await f.page.locator('#qerr').isVisible(), false);
    assert.equal(new URL(f.page.url()).pathname, '/' + TARGET);
    await f.page.goBack();
    await settled(f.page, SELF, 85);
    await f.page.goForward();
    await settled(f.page, TARGET, 42);
    await f.page.locator('#me').click();
    await settled(f.page, SELF, 85);
    assert.equal(new URL(f.page.url()).pathname, '/');
    const previousCount = f.lookups().length;
    await f.page.locator('#me').click();
    await f.page.waitForFunction(expected => window.__uiFetches.filter(({url}) => new URL(url).pathname === '/api/lookup').length === expected,
      previousCount + 2);
    await settled(f.page, SELF, 85);
    assert.equal(f.lookups().length, previousCount + 2, '查我的 IP also rechecks an already selected self IP');
    await onlyExpectedTraffic(f);
  } finally { await f.close(); }
});

test('查我的 IP shows its fast report while the full purity assessment is pending', async () => {
  const full = deferred(), fast = deferred();
  const f = await fixture({lookup: (ip, {url}) => ip === SELF
    ? url.searchParams.get('mode') === 'fast' ? fast.promise : full.promise
    : {json: report(ip)}});
  try {
    await f.page.goto(origin + '/' + TARGET);
    await settled(f.page, TARGET, 42);
    await f.page.locator('#me').click();
    await f.page.waitForFunction(() => window.__uiFetches.filter(({url}) => {
      const parsed = new URL(url);
      return parsed.pathname === '/api/lookup' && !parsed.searchParams.has('ip');
    }).length === 2);
    await textIs(f.page, '#scoreValue', '—');
    fast.resolve({json: report(SELF, 100)});
    await textIs(f.page, '#ipAddress', SELF);
    await f.page.getByText('Fixture Network Name', {exact: true}).first().waitFor();
    await textIs(f.page, '#scoreValue', '—');
    assert.equal(await f.page.locator('#result').getAttribute('aria-busy'), 'true');
    assert.equal(f.lookups().length, 4);
    full.resolve({json: report(SELF, 93)});
    await settled(f.page, SELF, 93);
    await onlyExpectedTraffic(f);
  } finally {
    fast.resolve({json: report(SELF, 100)});
    full.resolve({json: report(SELF, 93)});
    await f.close();
  }
});

test('changing the query aborts the previous fetch and a late report cannot mix its IP or score into the result', async () => {
  const stale = deferred();
  const oldReport = {...report(SELF, 99), score: {value: 99, level: '极度纯净',
    factors: [{name: 'Stale score factor must stay absent', delta: -1}]}};
  const f = await fixture({lookup: ip => ip === SELF ? stale.promise : {json: report(ip, 42)}});
  try {
    await f.page.goto(origin);
    await f.page.waitForFunction(() => window.__uiFetches.some(({url}) => new URL(url).pathname === '/api/lookup'));
    await f.page.waitForFunction(() => window.__uiFetches.length === 2);
    const oldRequests = [...f.lookups()];
    await submit(f.page, TARGET);
    await settled(f.page, TARGET, 42);
    await f.page.waitForFunction(() => {
      const old = window.__uiFetches.filter(({url}) => {
        const parsed = new URL(url);
        return parsed.pathname === '/api/lookup' && !parsed.searchParams.has('ip');
      });
      return old.length === 2 && old.every(({aborted}) => aborted);
    });
    await openScoreDetails(f.page);
    stale.resolve({json: oldReport});
    await Promise.all(oldRequests.map(request => request.done));
    // Cross a rendering boundary after the old response handler has had a chance to settle.
    await f.page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await settled(f.page, TARGET, 42);
    assert.equal(new URL(f.page.url()).pathname, '/' + TARGET);
    assert.equal(await f.page.locator('#scoreDetails').isVisible(), true);
    const details = await f.page.locator('#scoreDetailsBody').innerText();
    assert.ok(details.includes(TARGET));
    assert.doesNotMatch(details, /Stale score factor must stay absent|1\.1\.1\.1/,
      'a late response must not overwrite the currently open detail snapshot');
    await onlyExpectedTraffic(f);
  } finally { stale.resolve({json: oldReport}); await f.close(); }
});

test('a late fast self report cannot replace a newer explicit query', async () => {
  const fast = deferred(), full = deferred();
  const f = await fixture({lookup: (ip, {url}) => ip === SELF
    ? url.searchParams.get('mode') === 'fast' ? fast.promise : full.promise
    : {json: report(ip)}});
  try {
    await f.page.goto(origin + '/' + TARGET);
    await settled(f.page, TARGET, 42);
    await f.page.locator('#me').click();
    await f.page.waitForFunction(() => window.__uiFetches.filter(({url}) => {
      const parsed = new URL(url);
      return parsed.pathname === '/api/lookup' && !parsed.searchParams.has('ip');
    }).length === 2);
    const oldRequests = f.lookups().filter(({url}) => !url.searchParams.has('ip'));
    await submit(f.page, '9.9.9.9');
    await settled(f.page, '9.9.9.9', 85);
    await f.page.waitForFunction(() => window.__uiFetches.filter(({url}) => {
      const parsed = new URL(url);
      return parsed.pathname === '/api/lookup' && !parsed.searchParams.has('ip');
    }).every(({aborted}) => aborted));
    fast.resolve({json: report(SELF, 100)});
    full.resolve({json: report(SELF, 99)});
    await Promise.all(oldRequests.map(request => request.done));
    await f.page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    await settled(f.page, '9.9.9.9', 85);
    await onlyExpectedTraffic(f);
  } finally {
    fast.resolve({json: report(SELF, 100)});
    full.resolve({json: report(SELF, 99)});
    await f.close();
  }
});

for (const [name, status, json] of [
  ['full-report failure', 503, {error: 'Synthetic provider unavailable'}],
  ['rate limiting', 429, {error: '查询太频繁', retry_after: 7}],
]) {
  test(`${name} retains the IP and leaves purity unknown instead of showing 0 or 100`, async () => {
    const f = await fixture({lookup: (ip, {url}) => url.searchParams.get('mode') === 'fast'
      ? {json: report(ip, 100)} : {status, json}});
    try {
      await f.page.goto(origin + '/' + TARGET);
      await settled(f.page, TARGET, '—');
      await textIs(f.page, '#scoreLevel', '未能评估');
      const message = (await f.page.locator('#status').innerText()).trim();
      assert.ok(message.length > 0, 'the failure must be visible');
      if (status === 429) assert.match(message, /频繁|稍后|7/);
      assert.equal(await f.page.getByText('Fixture Network Name', {exact: true}).first().isVisible(), true,
        'a failed full report must preserve basic information returned by the fast lookup');
      assert.equal(f.lookups().length, 2, 'a failed full report must not trigger extra fallback requests');
      await onlyExpectedTraffic(f);
    } finally { await f.close(); }
  });
}

test('score data status distinguishes missing risk data from limited and sufficiently covered ratings', async () => {
  for (const [dataStatus, value, displayed, note] of [
    ['unavailable', 100, '—', '数据不足'],
    ['limited', 64, '64', '数据有限'],
    ['complete', 85, '85', '数据较充分'],
  ]) {
    const f = await fixture({lookup: ip => {
      const result = report(ip, value);
      result.score.data_status = dataStatus;
      result.score.coverage = {received: dataStatus === 'complete' ? 2 : dataStatus === 'limited' ? 1 : 0, total: 2};
      if (dataStatus === 'unavailable') {
        result.score.factors = [];
        result.risk = [];
        result.sources[0] = {...result.sources[0], status: 'empty', reputation: false};
      }
      return {json: result};
    }});
    try {
      await f.page.goto(origin + '/' + TARGET);
      await settled(f.page, TARGET, displayed);
      const score = f.page.locator('#score');
      assert.equal(await score.getByText(note, {exact: false}).isVisible(), true);
      assert.match(await score.locator('.score-data').innerText(), /[012]\/2 信誉源/);
      if (dataStatus === 'unavailable') {
        await textIs(f.page, '#scoreLevel', '未能评估');
        assert.doesNotMatch(await score.locator('.ring').getAttribute('aria-label'), /100|纯净/,
          'no successful risk data must not be presented as a perfect rating');
      }
      assert.equal(await f.page.getByText('Fixture Network Name', {exact: true}).first().isVisible(), true);
      await openScoreDetails(f.page);
      const details = await f.page.locator('#scoreDetailsBody').innerText();
      assert.ok(details.includes(TARGET));
      assert.ok(details.includes(note));
      if (dataStatus === 'unavailable') assert.match(details, /未能评估|没有|缺少|未返回|不足/,
        'an unknown rating still explains its missing reputation data');
      await onlyExpectedTraffic(f);
    } finally { await f.close(); }
  }
});

test('valid coordinates load the same-site map library and only OSM tiles, then disappear for an address without coordinates', async () => {
  const full = deferred();
  const f = await fixture({lookup: (ip, {url}) => ip !== SELF ? {json: report(ip)}
    : url.searchParams.get('mode') === 'full' ? full.promise : {json: locatedReport(ip, 100)}});
  try {
    await f.page.goto(origin);
    await f.page.locator('.map .leaflet-tile-loaded').first().waitFor();
    await textIs(f.page, '#scoreValue', '—');
    assert.equal(await f.page.getByRole('heading', {name: /^位置地图/}).isVisible(), true);
    assert.match(await f.page.locator('.map .leaflet-control-attribution').innerText(), /OpenStreetMap/);
    const tileCount = f.external.length;
    assert.ok(tileCount > 0, 'the map must request tiles instead of showing an empty placeholder');
    full.resolve({json: locatedReport(SELF, 85)});
    await settled(f.page, SELF, 85);
    await f.page.evaluate(() => new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(resolve))));
    assert.equal(f.external.length, tileCount, 'replacing fast with full data must keep an unchanged map');
    assert.equal(f.requests.filter(({url}) => url.pathname.endsWith('/leaflet.js')).length, 1);
    assert.equal(await f.page.locator('.map.leaflet-container').count(), 1);
    await submit(f.page, TARGET);
    await settled(f.page, TARGET, 42);
    assert.equal(await f.page.locator('.mapcard, .map').count(), 0);
    await onlyExpectedTraffic(f, {map: true});
  } finally { full.resolve({json: locatedReport(SELF, 85)}); await f.close(); }
});

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

for (const [name, width, height, colorScheme] of [
  ['desktop', 1440, 900, 'light'], ['mobile', 393, 852, 'light'],
  ['mobile-short', 390, 664, 'light'], ['dark', 1440, 900, 'dark'],
]) {
  test(`${name}: a long IPv6 address remains readable without horizontal page overflow`, async () => {
    const f = await fixture({width, height, colorScheme, lookup: ip => {
      const result = locatedReport(ip);
      result.network.as_name = 'Fixture Network Name ' + 'Long Network Organization '.repeat(12);
      return {json: result};
    }});
    try {
      await f.page.goto(origin + '/' + V6);
      await settled(f.page, V6, 85);
      await f.page.locator('.map .leaflet-tile-loaded').first().waitFor();
      assert.equal(await f.page.locator('#ipAddress').isVisible(), true);
      const dimensions = await f.page.evaluate(() => {
        const ip = document.querySelector('#ipAddress'), root = document.documentElement;
        const bounds = ip.getBoundingClientRect(), ring = document.querySelector('#score .ring').getBoundingClientRect();
        const toggle = document.querySelector('#scoreDetailsToggle').getBoundingClientRect();
        return {viewport: root.clientWidth, pageWidth: root.scrollWidth, height: innerHeight,
          left: bounds.left, right: bounds.right, ipTop: bounds.top, ipBottom: bounds.bottom,
          ringTop: ring.top, ringBottom: ring.bottom, toggleBottom: toggle.bottom,
          ipWidth: ip.clientWidth, ipContentWidth: ip.scrollWidth,
          dark: matchMedia('(prefers-color-scheme: dark)').matches};
      });
      assert.equal(dimensions.pageWidth, dimensions.viewport, `${width}px page must not scroll horizontally`);
      assert.ok(dimensions.left >= 0 && dimensions.right <= dimensions.viewport, 'the complete IP element must fit on screen');
      assert.ok(dimensions.ipContentWidth <= dimensions.ipWidth + 1, 'the IP must wrap or scale rather than clip inside its own element');
      assert.equal(dimensions.dark, colorScheme === 'dark');
      if (width <= 393) {
        assert.ok(dimensions.ipTop >= 0 && dimensions.ipBottom < dimensions.height,
          `${width}×${height}: the entire IP stays in the first screen`);
        assert.ok(dimensions.ringTop >= 0 && dimensions.ringBottom < dimensions.height,
          `${width}×${height}: the purity ring stays in the first screen even with a long IP and ASN name`);
        assert.ok(dimensions.toggleBottom < dimensions.height, 'the score detail action is available in the first screen');
      }
      await screenshot(f.page, name);
      if (name === 'mobile') {
        await openScoreDetails(f.page);
        const modal = await f.page.locator('#scoreDetails').evaluate(dialog => {
          const bounds = dialog.getBoundingClientRect(), root = document.documentElement;
          return {left: bounds.left, right: bounds.right, top: bounds.top, bottom: bounds.bottom,
            width: root.clientWidth, height: innerHeight, pageWidth: root.scrollWidth};
        });
        assert.ok(modal.left >= 0 && modal.right <= modal.width, 'the mobile dialog fits the viewport width');
        assert.ok(modal.top >= 0 && modal.bottom <= modal.height, 'long details scroll within the mobile dialog');
        assert.equal(modal.pageWidth, modal.width);
        await screenshot(f.page, 'details-mobile', {fullPage: false});
      }
      await onlyExpectedTraffic(f, {map: true});
    } finally { await f.close(); }
  });
}
