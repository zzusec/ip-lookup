'use strict';

const {test, before, after} = require('node:test');
const assert = require('node:assert/strict');
const {createServer} = require('node:http');
const {randomBytes} = require('node:crypto');
const {readFile} = require('node:fs/promises');
const {existsSync} = require('node:fs');
const {join} = require('node:path');

const playwright = ['playwright', '/opt/homebrew/lib/node_modules/@playwright/cli/node_modules/playwright']
  .map(name => { try { return require.resolve(name); } catch { return null; } }).find(Boolean);
if (!playwright) throw new Error('Install Playwright to run the admin UI tests.');
const {chromium} = require(playwright);

const rawDate = '2026-11-27T17:00:00Z'; // 2026-11-28 01:00:00 UTC+8
const stamp = {schema: 1, site: 'ip', startedAt: '2026-11-04T16:30:00Z', updatedAt: rawDate};
const usage = {...stamp, days: [
  {date: '2026-11-05', pageViews: 30, lookups: 100, errors: 7, uv: 18, cliLookups: 12, targetLookups: 9, probes: 4},
  {date: '2026-11-22', pageViews: 3, lookups: 2, errors: 1, uv: 2, cliLookups: 1, targetLookups: 0, probes: 1},
  {date: '2026-11-28', pageViews: 1, lookups: 5, errors: 0, uv: 1, cliLookups: 2, targetLookups: 1, probes: 1},
]};
const sourceName = '<img src="/unexpected">' + 'LongOfflineDataset'.repeat(14);
const sources = {
  datasets: [{label: sourceName, status: 'error', error: '无法解包', entries: 0}],
  online: [{name: 'Example', quota: '100/day', used: 42, blocked_until: '2040-01-01T00:00:00Z'}],
};
const live = {
  todayUv: 1,
  yestUv: 0,
  uv7d: 3,
  uv30d: 21,
  recentCount: 1,
  regions: [{name: '新加坡', cc: 'SG', visitors: 1, requests: 5}],
  asns: [{name: 'AS45143 Singtel Mobile', visitors: 1, requests: 5}],
  clients: [{name: 'iOS 27.2 · Safari 27.2', visitors: 1, requests: 5}],
  topIps: [{
    ip: '119.234.40.14',
    cc: 'SG',
    location: '新加坡',
    asn: 'AS45143',
    isp: 'Singtel Mobile',
    label: '移动网络',
    os: 'iOS 27.2',
    browser: 'Safari 27.2',
    views: 1,
    lookups: 4,
    probes: 1,
    errors: 0,
    firstSeen: '2026-11-28 00:50:00',
    lastSeen: '2026-11-28 00:55:00',
    targets: ['8.8.8.8'],
  }],
};

let browser;

before(async () => {
  const installed = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  const executablePath = process.env.CHROMIUM_PATH || (existsSync(installed) ? installed : undefined);
  browser = await chromium.launch({headless: true, executablePath});
});
after(async () => { await browser?.close(); });

async function fixture(t, width, authenticated = false) {
  const rotatedKey = randomBytes(8).toString('hex');
  const state = {
    usage,
    sources,
    live,
    gateKey: randomBytes(8).toString('hex'),
    rotatedKey,
    username: 'admin',
    overviewStatus: 200,
    logoutStatus: 204,
    requests: [],
  };
  const assets = {
    '/admin': ['admin.html', 'text/html'],
    '/admin/': ['admin.html', 'text/html'],
    '/static/admin.js': ['static/admin.js', 'application/javascript'],
    '/static/admin.css': ['static/admin.css', 'text/css'],
    '/static/favicon.svg': ['static/favicon.svg', 'image/svg+xml'],
  };
  const server = createServer(async (request, response) => {
    const u = new URL(request.url, 'http://127.0.0.1');
    const path = u.pathname;
    state.requests.push([request.method, request.url]);
    response.setHeader('Date', new Date(rawDate).toUTCString());
    response.setHeader('Cache-Control', 'no-store');
    if (Object.hasOwn(assets, path)) {
      if (path.startsWith('/admin') && !authenticated && u.searchParams.get('k') !== state.gateKey && !(request.headers.cookie || '').includes('ip_lookup_gate=ok') && !(request.headers.cookie || '').includes('admin_session=fixture')) {
        return response.writeHead(404, {'Content-Type': 'text/plain; charset=utf-8'}).end('404 page not found\n');
      }
      const [file, type] = assets[path];
      response.setHeader('Content-Type', type);
      response.setHeader('Content-Security-Policy', "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'");
      if (u.searchParams.get('k') === state.gateKey) {
        response.setHeader('Set-Cookie', 'ip_lookup_gate=ok; Path=/admin; HttpOnly; SameSite=Strict');
      }
      return response.end(await readFile(join(__dirname, file)));
    }
    let body = '';
    for await (const chunk of request) body += chunk;
    if (path === '/admin/api/login' && request.method === 'POST') {
      assert.equal(request.headers['content-type'], 'application/json');
      const payload = JSON.parse(body);
      if (payload.username !== state.username || payload.password !== 'test-password') return response.writeHead(401).end();
      return response.writeHead(204, {'Set-Cookie': 'admin_session=fixture; Path=/admin; HttpOnly; SameSite=Strict'}).end();
    }
    if (path === '/admin/api/logout' && request.method === 'POST') {
      assert.deepEqual(JSON.parse(body), {});
      return response.writeHead(state.logoutStatus, state.logoutStatus === 204 ? {'Set-Cookie': 'admin_session=; Max-Age=0; Path=/admin; HttpOnly'} : {}).end();
    }
    if (!(request.headers.cookie || '').includes('admin_session=fixture')) {
      return response.writeHead(401).end();
    }
    if (path === '/admin/api/overview' && request.method === 'GET') {
      response.writeHead(state.overviewStatus, {'Content-Type': 'application/json'});
      return response.end(JSON.stringify({
        usage: state.usage,
        sources: state.sources,
        live: state.live,
        auth: {username: state.username, gateKey: state.gateKey, gated: true},
      }));
    }
    if (path === '/admin/api/visits' && request.method === 'GET') {
      const dayParam = u.searchParams.get('day') || '';
      const allItems = [{
        id: 1,
        time: '2026-11-28 00:55:00',
        day: '2026-11-28',
        ip: '119.234.40.14',
        cc: 'SG',
        location: '新加坡',
        country: '新加坡',
        asn: 'AS45143',
        isp: 'Singtel Mobile',
        kind: 'view',
        targetIp: '119.234.40.14',
        targetLabel: '移动网络',
        os: 'iOS 27.2',
        browser: 'Safari 27.2',
        status: 200,
        ms: 28,
      }];
      const items = dayParam ? allItems.filter(x => x.day === dayParam) : allItems;
      response.writeHead(200, {'Content-Type': 'application/json'});
      return response.end(JSON.stringify({
        total: items.length,
        page: 1,
        size: 40,
        items,
      }));
    }
    if (path === '/admin/api/visitor' && request.method === 'GET') {
      response.writeHead(200, {'Content-Type': 'application/json'});
      return response.end(JSON.stringify({
        ip: u.searchParams.get('ip') || '119.234.40.14',
        summary: {cc: 'SG', country: '新加坡', location: '新加坡', asn: 'AS45143', isp: 'Singtel Mobile', label: '移动网络', prefix: '119.234.32.0/20'},
        history: [],
      }));
    }
    if (path === '/admin/api/ip-blocks' && request.method === 'GET') {
      response.writeHead(200, {'Content-Type': 'application/json'});
      return response.end(JSON.stringify({items: []}));
    }
    if (path === '/admin/api/login-logs' && request.method === 'GET') {
      response.writeHead(200, {'Content-Type': 'application/json'});
      return response.end(JSON.stringify({items: [{time: '2026-11-28 01:00:00', ip: '198.51.100.1', location: '中国', username: 'admin', ok: true, reason: '登录成功'}]}));
    }
    if (path === '/admin/api/rotate-url-token' && request.method === 'POST') {
      state.gateKey = state.rotatedKey;
      response.writeHead(200, {'Content-Type': 'application/json'});
      return response.end(JSON.stringify({url_token: state.gateKey}));
    }
    response.writeHead(404).end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const context = await browser.newContext({viewport: {width, height: 860}, timezoneId: 'America/Los_Angeles'});
  const page = await context.newPage();
  const violations = [];
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    violations.push(route.request().url());
    return route.abort();
  });
  page.on('pageerror', err => violations.push(String(err)));
  if (authenticated) await context.addCookies([{name: 'admin_session', value: 'fixture', url: origin}]);
  t.after(async () => {
    await context.close();
    await new Promise(resolve => server.close(resolve));
    assert.deepEqual(violations, []);
    assert.ok(state.requests.every(([, urlStr]) => !urlStr.includes('/unexpected')));
  });
  return {page, origin, state, context};
}

test('stealth ?k= gate, Zinc surface dashboard, 30d bar filter, 4 tabs, modal, token rotation and logout', async t => {
  const {page, origin, state} = await fixture(t, 1280);

  // Unkeyed /admin returns 404 stealth gate
  const unkeyed = await page.goto(origin + '/admin');
  assert.equal(unkeyed.status(), 404);

  // Keyed ?k= opens clean Zinc login card
  await page.goto(`${origin}/admin?k=${state.gateKey}`);
  await page.locator('#loginView').waitFor();
  assert.equal(await page.locator('#dashView').isVisible(), false);

  // Password show/hide & dark mode toggle
  await page.locator('#btnLoginTheme').click();
  assert.equal(await page.evaluate(() => document.documentElement.classList.contains('dark')), true);
  await page.locator('#btnLoginTheme').click();
  assert.equal(await page.evaluate(() => document.documentElement.classList.contains('dark')), false);

  await page.getByLabel('登录密码').fill('wrong');
  await page.locator('#admLoginBtn').click();
  await page.getByText('账号或密码不正确。').waitFor();

  await page.getByLabel('管理员账号').fill('admin');
  await page.getByLabel('登录密码').fill('test-password');
  await page.locator('#admLoginBtn').click();
  await page.locator('#dashView').waitFor();

  // Verify China-day KPI cards & 30d daily breakdown
  assert.equal(await page.locator('#kpiTodayUv').textContent(), '1');
  assert.match(await page.locator('#kpiTodaySub').textContent(), /网页 1 次 · 查询 5 次/);
  assert.match(await page.locator('#kpi30dSub').textContent(), /30日独立 IP 21 · 总请求 141/);
  assert.match(await page.locator('#kpiLookupTotal').textContent(), /107 次/);
  assert.match(await page.locator('#kpiTopRegions').innerText(), /新加坡[\s\S]*1 IP/);

  await page.getByText('查看每日数值汇总').click();
  assert.equal(await page.locator('#dayRows tr').count(), 30);
  assert.match(await page.locator('#dayRows tr').last().textContent(), /未采集/);

  // Click a 30-day bar to filter that day and then clear
  await page.locator('[data-daybar="2026-11-05"]').click();
  await page.locator('#btnClearDayFilter').waitFor();
  assert.match(await page.locator('#btnClearDayFilter').textContent(), /仅看 2026-11-05/);
  await page.locator('#btnClearDayFilter').click();

  // Verify real-time visits table & IP dossier modal
  await page.getByText('119.234.40.14').first().waitFor();
  await page.getByText('iOS 27.2 · Safari 27.2').first().waitFor();
  await page.locator('#visitsTableBody [data-openip="119.234.40.14"]').first().click();
  await page.locator('#ipDetailModal').waitFor();
  await page.getByText('119.234.32.0/20').waitFor();
  await page.locator('#mdlCloseBtn').click();

  // Tab 2: Unique IPs aggregation
  await page.locator('#admTabs [data-admtab="ips"]').click();
  assert.match(await page.locator('#ipsTableBody').innerText(), /119\.234\.40\.14[\s\S]*1 网页 · 4 查询 · 1 实测[\s\S]*8\.8\.8\.8/);

  // Tab 3: Sources & Quotas (verify XSS img neutralization)
  await page.locator('#admTabs [data-admtab="sources"]').click();
  assert.match(await page.locator('#online').innerText(), /限流[\s\S]*100\/day · 已用 42[\s\S]*42%/);
  assert.match(await page.locator('#datasets').innerText(), /错误[\s\S]*无法解包/);
  assert.equal(await page.locator('#datasets img').count(), 0);

  // Tab 4: Security & ?k= token rotation
  page.once('dialog', d => d.accept());
  await page.locator('#admTabs [data-admtab="security"]').click();
  await page.locator('#secTokPw').fill('test-password');
  await page.locator('[data-action="rotate-token"]').click();
  await page.getByText(new RegExp(state.rotatedKey)).first().waitFor();

  // Logout failure handling then clean logout
  state.logoutStatus = 503;
  await page.locator('#btnAdmLogout').click();
  await page.getByText('退出未确认，请重试。').first().waitFor();
  assert.equal(await page.locator('#dashView').isVisible(), true);

  state.logoutStatus = 204;
  await page.locator('#btnAdmLogout').click();
  await page.getByText('已退出登录。').waitFor();
  assert.equal(await page.locator('#dashView').isVisible(), false);
});

test('mobile 393px viewport, zero horizontal overflow across all tabs, malformed data, retry and expiry', async t => {
  const {page, origin, state} = await fixture(t, 393, true);
  state.overviewStatus = 503;
  await page.goto(origin + '/admin/');
  await page.locator('#retry').waitFor();

  state.overviewStatus = 200;
  await page.locator('#retry').click();
  await page.locator('#dashView').waitFor();

  const noOverflow = () => page.evaluate(() => document.documentElement.scrollWidth <= document.documentElement.clientWidth);
  assert.ok(await noOverflow());

  for (const tab of ['visits', 'ips', 'sources', 'security']) {
    await page.locator(`#admTabs [data-admtab="${tab}"]`).click();
    assert.ok(await noOverflow(), `overflow on tab ${tab}`);
  }

  state.overviewStatus = 500;
  await page.locator('#btnRefreshAdm').click();
  await page.getByText(/显示上次成功加载的数据/).waitFor();

  state.overviewStatus = 200;
  state.usage = null;
  await page.locator('#btnRefreshAdm').click();
  await page.locator('#admNoticeBar').getByText('未采集访问统计。').waitFor();

  state.usage = {...usage, days: [{date: 'not a date', pageViews: 0, lookups: 0, errors: 0}]};
  await page.locator('#btnRefreshAdm').click();
  await page.getByText(/不能按零流量计算/).waitFor();

  state.overviewStatus = 401;
  await page.locator('#btnRefreshAdm').click();
  await page.getByText(/会话已过期/).waitFor();
  assert.equal(await page.locator('#dashView').isVisible(), false);
});
