'use strict';

const {test, before, after} = require('node:test');
const assert = require('node:assert/strict');
const {createServer} = require('node:http');
const {readFile} = require('node:fs/promises');
const {existsSync} = require('node:fs');
const {join} = require('node:path');

const playwright = ['playwright', '/opt/homebrew/lib/node_modules/@playwright/cli/node_modules/playwright']
  .map(name => { try { return require.resolve(name); } catch { return null; } }).find(Boolean);
if (!playwright) throw new Error('Install Playwright to run the admin UI tests.');
const {chromium} = require(playwright);
const rawDate = '2026-11-27T17:00:00Z';
const stamp = {schema: 1, site: 'ip', startedAt: '2026-11-04T16:30:00Z', updatedAt: rawDate};
const usage = {...stamp, days: [
  {date: '2026-11-05', pageViews: 30, lookups: 100, errors: 7},
  {date: '2026-11-22', pageViews: 3, lookups: 2, errors: 1},
  {date: '2026-11-28', pageViews: 1, lookups: 5, errors: 0},
]};
const sourceName = '<img src="/unexpected">' + 'LongOfflineDataset'.repeat(14);
const sources = {datasets: [{label: sourceName, status: 'error', error: '无法解包', entries: 0}], online: [{name:'Example', quota:'100/day', used:42, blocked_until:'2040-01-01T00:00:00Z'}]};
let browser;

before(async () => {
  const installed = '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome';
  const executablePath = process.env.CHROMIUM_PATH || (existsSync(installed) ? installed : undefined);
  browser = await chromium.launch({headless: true, executablePath});
});
after(async () => { await browser?.close(); });

async function fixture(t, width, authenticated = false) {
  const state = {usage, sources, overviewStatus: 200, logoutStatus: 204, requests: []};
  const assets = {'/admin': ['admin.html','text/html'], '/admin/': ['admin.html','text/html'], '/static/admin.js': ['static/admin.js','application/javascript'], '/static/admin.css': ['static/admin.css','text/css'], '/static/style.css': ['static/style.css','text/css'], '/static/favicon.svg': ['static/favicon.svg','image/svg+xml']};
  const server = createServer(async (request, response) => {
    const path = request.url;
    state.requests.push([request.method, path]);
    response.setHeader('Date', new Date(rawDate).toUTCString());
    response.setHeader('Cache-Control', 'no-store');
    if (Object.hasOwn(assets, path)) {
      const [file, type] = assets[path];
      response.setHeader('Content-Type', type);
      response.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; frame-ancestors 'none'");
      return response.end(await readFile(join(__dirname, file)));
    }
    let body = '';
    for await (const chunk of request) body += chunk;
    if (path === '/admin/api/login' && request.method === 'POST') {
      assert.equal(request.headers['content-type'], 'application/json');
      if (JSON.parse(body).password !== 'test-password') return response.writeHead(401).end();
      return response.writeHead(204, {'Set-Cookie':'admin_session=fixture; Path=/admin; HttpOnly; SameSite=Strict'}).end();
    }
    if (path === '/admin/api/logout' && request.method === 'POST') {
      assert.deepEqual(JSON.parse(body), {});
      return response.writeHead(state.logoutStatus, state.logoutStatus === 204 ? {'Set-Cookie':'admin_session=; Max-Age=0; Path=/admin; HttpOnly'} : {}).end();
    }
    if (path === '/admin/api/overview' && request.method === 'GET') {
      if (request.headers.cookie !== 'admin_session=fixture') return response.writeHead(401).end();
      assert.equal(request.headers.authorization, undefined);
      response.writeHead(state.overviewStatus, {'Content-Type':'application/json'});
      return response.end(JSON.stringify({usage: state.usage, sources: state.sources}));
    }
    response.writeHead(404).end();
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  const origin = `http://127.0.0.1:${server.address().port}`;
  const context = await browser.newContext({viewport:{width, height: 850}, timezoneId: 'America/Los_Angeles'});
  const page = await context.newPage();
  const violations = [];
  await context.route('**/*', route => {
    if (new URL(route.request().url()).origin === origin) return route.continue();
    violations.push(route.request().url()); return route.abort();
  });
  page.on('pageerror', err => violations.push(String(err)));
  if (authenticated) await context.addCookies([{name:'admin_session', value:'fixture', url:origin}]);
  t.after(async () => {
    await context.close();
    await new Promise(resolve => server.close(resolve));
    assert.deepEqual(violations, []);
    assert.ok(state.requests.every(([, path]) => !path.includes('?') && !path.includes('/unexpected')));
  });
  return {page, origin, state, context};
}

test('password login, same-origin cookie, China-day aggregates and independent logout', async t => {
  const {page, origin, state} = await fixture(t, 1230);
  await page.goto(origin + '/admin'); await page.locator('#login').waitFor();
  assert.equal(await page.locator('#dashboard').isVisible(), false);
  await page.getByLabel('管理密码').fill('wrong'); await page.getByRole('button',{name:'登录',exact:true}).click();
  await page.getByText('密码不正确。').waitFor();
  await page.getByLabel('管理密码').fill('test-password'); await page.locator('#submitLogin').click();
  await page.locator('#dashboard').waitFor();
  assert.deepEqual(await page.locator('#totals tr').allTextContents(), ['今日150','近 7 天471','近 30 天341078']);
  assert.match(await page.locator('#online').innerText(), /100\/day.*42.*限流/);
  assert.match(await page.locator('#datasets').innerText(), /错误.*无法解包/);
  assert.equal(await page.locator('#datasets img').count(), 0);
  await page.getByText('查看每日数值').click();
  assert.equal(await page.locator('#dayRows tr').count(), 7);
  await page.getByRole('button',{name:'30 天'}).click();
  assert.equal(await page.locator('#dayRows tr').count(), 30);
  assert.match(await page.locator('#dayRows tr').last().textContent(), /未采集/);
  assert.equal(await page.locator('#plot polyline').count(), 3);
  state.logoutStatus = 503; await page.locator('#logout').click();
  await page.getByText('退出未确认，请重试。').waitFor(); assert.equal(await page.locator('#dashboard').isVisible(), true);
  state.logoutStatus = 204; await page.locator('#logout').click(); await page.getByText('已退出登录。').waitFor();
  assert.equal(await page.locator('#totals tr').count(), 0); assert.equal(await page.locator('#datasets').innerText(), '');
  assert.equal(await page.getByLabel('管理密码').inputValue(), '');
  await page.reload(); await page.locator('#login').waitFor();
});

test('mobile viewport, empty vs disabled, malformed read, retry and expiry', async t => {
  const {page, origin, state} = await fixture(t, 393, true);
  state.overviewStatus = 503;
  await page.goto(origin + '/admin/'); await page.locator('#retry').waitFor();
  state.overviewStatus = 200; await page.locator('#retry').click(); await page.locator('#dashboard').waitFor();
  const noOverflow = () => page.evaluate(() => document.documentElement.scrollWidth === document.documentElement.clientWidth);
  assert.ok(await noOverflow()); await page.getByRole('button',{name:'30 天'}).click(); await page.getByText('查看每日数值').click(); assert.ok(await noOverflow());
  state.overviewStatus = 500; await page.locator('#refresh').click(); await page.getByText(/显示上次成功/).waitFor();
  assert.equal(await page.locator('#totals tr').count(), 3);
  state.overviewStatus = 200; state.usage = {...stamp, days: []}; state.sources = {datasets: [], online: null};
  await page.locator('#refresh').click(); await page.getByText(/接入以来未记录到流量/).waitFor();
  assert.equal(await page.locator('#totals tr').first().textContent(), '今日000');
  assert.match(await page.locator('#datasetInfo').textContent(), /暂无/); assert.match(await page.locator('#onlineInfo').textContent(), /不可用/);
  state.usage = null; await page.locator('#refresh').click(); await page.getByText('未采集访问统计。').waitFor();
  assert.equal(await page.locator('#totals').isVisible(), false);
  state.usage = {...usage, days: [{date:'not a date',pageViews:0,lookups:0,errors:0}]};
  await page.locator('#refresh').click(); await page.getByText(/不能按零流量计算/).waitFor();
  state.overviewStatus = 401; await page.locator('#refresh').click(); await page.getByText(/会话已过期/).waitFor();
  assert.equal(await page.locator('#dashboard').isVisible(), false); assert.equal(await page.locator('#plot').innerHTML(), '');
});
