'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const {webcrypto} = require('node:crypto');
const source = fs.readFileSync(path.join(__dirname, 'static/connection.js'), 'utf8');
function load(overrides = {}) {
  const sandbox = {module: {exports: {}}, AbortController, Uint8Array, crypto: webcrypto, Intl, Date,
    setTimeout, clearTimeout, navigator: {languages: ['zh-CN', 'en'], language: 'zh-CN'}, ...overrides};
  vm.runInNewContext(source, sandbox, {filename: 'connection.js'});
  return sandbox.module.exports;
}
const api = load();
const probe = (id, data, status = 'ok') => ({id, label: id, status, data});
const snap = probes => ({startedAt: '2026-11-05T12:00:00Z', environment: {timeZone: 'Asia/Shanghai', offsetMinutes: 480, languages: ['zh-CN']}, probes});
const ids = findings => Array.from(findings, f => f.id);
const plain = value => JSON.parse(JSON.stringify(value));
function response(data, raw) { return {ok: true, status: 200, json: async () => data, text: async () => raw === undefined ? JSON.stringify(data) : raw}; }
function fixtureFetch(calls = []) {
  return async (url, options) => {
    calls.push({url, options});
    if (url.includes('.edns.ip-api.com')) return response({dns: {ip: '8.8.8.8', geo: 'United States - Google LLC'}, edns: {ip: '1.1.1.0/24', geo: 'Australia - Example'}});
    if (url.includes('tcpip.incolumitas')) return response({lookup_ip: '1.1.1.1', avg_score_os_class: {Linux: 13.15, 'Mac OS': 5.39}, perfect_score: 20.5,
      relay: {flagged: true, probability: 0.9959, threshold: 0.8, ua_os: 'Mac OS'}, os_mismatch: true});
    if (url.includes('/cdn-cgi/trace')) return response(null, 'ip=1.1.1.1\nloc=AU\ncolo=SYD\nwarp=off\ntls=TLSv1.3\nhttp=h2\n');
    if (url.includes('myip.ipip.net')) return response({ret: 'ok', data: {ip: '1.1.1.1', location: ['中国', '上海']}});
    return response({ip: url.includes('api6.ipify') ? '2606:4700:4700::1111' : '1.1.1.1'});
  };
}

test('IP normalization validates syntax, compresses IPv6 and unmaps IPv4', () => {
  assert.equal(api.canonicalIP('[2606:4700:0000:0000:0000:0000:0000:1111]'), '2606:4700::1111');
  assert.equal(api.canonicalIP('::'), '::');
  assert.equal(api.canonicalIP('fe80::1%en0'), 'fe80::1');
  assert.equal(api.canonicalIP('::ffff:8.8.8.8'), '8.8.8.8');
  assert.equal(api.canonicalIP('::ffff:0808:0808'), '8.8.8.8');
  for (const invalid of ['1.2.3.256', '01.2.3.4', '1.2.3', 'a::b::c', '1:2:3:4:5:6:7', ':1:2:3:4:5:6:7', '2606:4700::fffff', 'foo.local', null])
    assert.equal(api.canonicalIP(invalid), '', String(invalid));
  assert.equal(api.sameIP('2606:4700::1', '2606:4700:0:0:0:0:0:1'), true);
  assert.equal(api.sameIP('', ''), false);
});

test('public-address classification excludes reserved, local, CGNAT and documentation ranges', () => {
  for (const ip of ['8.8.8.8', '1.1.1.1', '2606:4700:4700::1111']) assert.equal(api.isPublic(ip), true, ip);
  for (const ip of ['0.1.2.3', '10.0.0.1', '100.64.1.1', '127.0.0.1', '169.254.1.1', '172.16.0.1', '192.168.1.1',
    '198.18.0.1', '203.0.113.1', '224.1.1.1', '255.255.255.255', '::1', 'fe80::1', 'fc00::1', '2001:db8::1', 'invalid'])
    assert.equal(api.isPublic(ip), false, ip);
});

test('CIDR matching respects bit boundaries, protocol families and IPv6 /64', () => {
  assert.equal(api.containsSubnet('8.8.8.0/25', '8.8.8.127'), true);
  assert.equal(api.containsSubnet('8.8.8.0/25', '8.8.8.128'), false);
  assert.equal(api.containsSubnet('8.8.8.8/32', '8.8.8.8'), true);
  assert.equal(api.containsSubnet('0.0.0.0/0', '1.1.1.1'), true);
  assert.equal(api.containsSubnet('2606:4700::/64', '2606:4700::ffff'), true);
  assert.equal(api.containsSubnet('2606:4700::/64', '2606:4700:0:1::1'), false);
  for (const subnet of ['8.8.8.8/33', '8.8.8.8/-1', '8.8.8.8', '::/129', '::/1.5']) assert.equal(api.containsSubnet(subnet, '8.8.8.8'), false);
  assert.equal(api.samePrefix('2606:4700::1', '2606:4700::2'), true);
  assert.equal(api.samePrefix('8.8.8.8', '2606:4700::1', 0), false);
});

test('only distinct addresses of the same family produce an egress-difference finding', () => {
  assert.deepEqual(ids(api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('v6', {ip: '2606:4700::1'})]))), []);
  assert.deepEqual(ids(api.analyze(snap([probe('site', {ip: '2606:4700::1'}), probe('v6', {ip: '2606:4700:0:0:0:0:0:1'})]))), []);
  const differences = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('cn', {ip: '8.8.8.8'})]));
  assert.deepEqual(ids(differences), ['egress-v4']);
  assert.equal(differences[0].level, 'info');
  assert.match(differences[0].detail, /不能/);
});

test('WebRTC IPv6 privacy addresses are a prefix observation rather than a leak warning', () => {
  const result = api.analyze(snap([probe('site', {ip: '2606:4700:4700::1'}), probe('rtc', {publicIPs: ['2606:4700:4700::2'], localIPs: [], mdns: false})]));
  assert.deepEqual(ids(result), ['rtc-prefix']);
  assert.equal(result[0].level, 'info');
});

test('WebRTC uses same-family observations and never treats private or mDNS addresses as public leakage', () => {
  const result = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('rtc', {publicIPs: ['2606:4700::1', '192.168.1.1'], localIPs: ['192.168.1.1'], mdns: true})]));
  assert.deepEqual(ids(result), ['rtc-unknown-v6']);
  assert.equal(result[0].level, 'info');
  const local = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('rtc', {publicIPs: [], localIPs: ['10.0.0.1'], mdns: true})]));
  assert.deepEqual(ids(local), ['rtc-local']);
  assert.equal(local[0].level, 'info');
});

test('a distinct public WebRTC path yields a qualified warning against the site reference', () => {
  const result = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('cn', {ip: '8.8.8.8'}), probe('rtc', {publicIPs: ['8.8.8.8'], localIPs: [], mdns: false})]));
  const finding = result.find(f => f.id === 'rtc-different-v4');
  assert.equal(finding.level, 'warn');
  assert.match(finding.detail, /尚不能确认/);
});

test('public DNS across countries is informational and does not establish a DNS leak', () => {
  const result = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('dns', {ip: '8.8.8.8', country: 'United States', org: 'Google LLC'})]),
    {ip: '1.1.1.1', geo: {country_code: 'AU'}});
  assert.deepEqual(ids(result), ['dns-country']);
  assert.equal(result[0].level, 'info');
  assert.match(result[0].detail, /不能单凭国家不同认定/);
  assert.deepEqual(ids(api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('dns', {ip: '8.8.8.8', country: 'United States'})]),
    {ip: '1.1.1.1', geo: {country_code: 'US'}})), []);
});

test('ECS comparisons validate subnet containment and keep /0 and cross-family observations inconclusive', () => {
  const analyzeECS = subnet => api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('dns', {ip: '8.8.8.8', ecs: {subnet}})]));
  assert.deepEqual(ids(analyzeECS('1.1.1.0/24')), ['ecs-matches']);
  assert.deepEqual(ids(analyzeECS('8.8.8.0/24')), ['ecs-different']);
  assert.equal(analyzeECS('8.8.8.0/24')[0].level, 'warn');
  assert.deepEqual(ids(analyzeECS('0.0.0.0/0')), ['ecs-masked']);
  assert.deepEqual(ids(analyzeECS('192.168.1.0/24')), ['ecs-local']);
  assert.deepEqual(ids(analyzeECS('2606:4700::/64')), ['ecs-unknown']);
  assert.deepEqual(ids(analyzeECS('invalid')), []);
});

test('TCP relay and OS mismatch cannot be applied to an unobserved HTTP exit', () => {
  const result = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('tcp', {ip: '8.8.8.8', os: 'Linux', relay: true, mismatch: true})]));
  assert.deepEqual(ids(result), ['tcp-path']);
  assert.equal(result[0].level, 'info');
  const matched = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('tcp', {ip: '1.1.1.1', os: 'Linux', uaOS: 'Mac OS', relay: null, mismatch: true})]));
  assert.deepEqual(ids(matched), ['tcp-os']);
  assert.equal(matched[0].level, 'info');
});

test('time-zone observations use the current UTC offset without modifying the lookup score', () => {
  const lookup = {ip: '1.1.1.1', score: {value: 98, factors: []}, geo: {time_zone: 'America/New_York'}};
  const before = JSON.stringify(lookup), snapshot = snap([probe('site', {ip: '1.1.1.1'})]);
  assert.deepEqual(ids(api.analyze(snapshot, lookup)), ['time-zone']);
  assert.equal(JSON.stringify(lookup), before);
  assert.deepEqual(ids(api.analyze(snapshot, {...lookup, geo: {time_zone: 'Asia/Shanghai'}})), []);
  assert.deepEqual(ids(api.analyze(snapshot, {...lookup, ip: '8.8.8.8'})), []);
});

test('all failed or unsupported probes return an unknown observation instead of a safety verdict', () => {
  const result = api.analyze(snap([probe('site', null, 'error'), probe('rtc', null, 'unsupported')]));
  assert.deepEqual(ids(result), ['unavailable']);
  assert.equal(result[0].level, 'info');
});

test('successful target traces describe reachability rather than account or region availability', () => {
  const result = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), probe('chatgpt', {ip: '1.1.1.1'}), probe('cf', {ip: '1.1.1.1', warp: 'on'})]));
  assert.deepEqual(ids(result), ['warp', 'target-reachability']);
  assert.match(result[1].detail, /不代表账号可登录/);
});

test('collection emits pending and completed snapshots, uses isolated requests, and preserves raw TCP score units', async () => {
  const calls = [], updates = [], module = load({fetch: fixtureFetch(calls)});
  const result = await module.collect({onUpdate: s => updates.push(plain(s))});
  assert.equal(result.probes.length, 11);
  assert.equal(updates.length, 12);
  assert.ok(updates[0].probes.every(p => p.status === 'pending'));
  assert.ok(result.finishedAt);
  assert.ok(result.probes.every(p => p.status !== 'pending'));
  assert.equal(result.probes.find(p => p.id === 'rtc').status, 'unsupported');
  for (const {options} of calls) {
    assert.equal(options.cache, 'no-store');
    assert.equal(options.credentials, 'omit');
    assert.equal(options.referrerPolicy, 'no-referrer');
  }
  const tcp = result.probes.find(p => p.id === 'tcp').data;
  assert.deepEqual(plain(tcp), {ip: '1.1.1.1', os: 'Linux', relay: true, mismatch: true, probability: 0.9959, score: 13.15, perfectScore: 20.5, uaOS: 'Mac OS'});
  assert.equal(result.probes.find(p => p.id === 'cn').data.location, '中国 上海');
  const dnsURLs = calls.filter(c => c.url.includes('.edns.ip-api.com')).map(c => c.url);
  assert.match(dnsURLs[0], /^https:\/\/[a-f0-9]{32}\.edns\.ip-api\.com\/json$/);
  const next = await module.collect();
  assert.notEqual(next, result);
  assert.notEqual(next.probes, result.probes);
  assert.notEqual(calls.filter(c => c.url.includes('.edns.ip-api.com'))[1].url, dnsURLs[0]);
});

test('missing TCP classifier fields remain unknown and optional ECS may be absent', async () => {
  const base = fixtureFetch(), module = load({fetch: async (url, opts) => {
    if (url.includes('tcpip.incolumitas')) return response({lookup_ip: '1.1.1.1', avg_score_os_class: {Linux: 11.25, Windows: 3.99}, perfect_score: 20.5, os_mismatch: null});
    if (url.includes('.edns.ip-api.com')) return response({dns: {ip: '8.8.8.8', geo: 'United States - Google LLC'}});
    return base(url, opts);
  }});
  const result = await module.collect();
  const tcp = result.probes.find(p => p.id === 'tcp').data;
  assert.equal(tcp.relay, null);
  assert.equal(tcp.mismatch, null);
  assert.equal(tcp.probability, undefined);
  assert.equal(tcp.confidence, undefined);
  assert.equal(result.probes.find(p => p.id === 'dns').data.ecs, undefined);
});

test('malformed responses, wrong address family, and network errors remain visible', async () => {
  const module = load({fetch: async url => {
    if (url.includes('api6.ipify')) return response({ip: '1.1.1.1'});
    if (url.includes('api4.ipify')) throw new TypeError('Network request failed');
    return response({}, '<html>blocked</html>');
  }});
  const result = await module.collect();
  assert.ok(result.probes.every(p => p.status === 'error' || p.status === 'unsupported'));
  assert.match(result.probes.find(p => p.id === 'v6').error, /有效/);
  assert.match(result.probes.find(p => p.id === 'v4').error, /Network request failed/);
  assert.ok(result.probes.every(p => p.error && p.error !== '无 IPv6'));
});

test('pre-aborted collection starts no requests or callbacks', async () => {
  const controller = new AbortController(); controller.abort();
  let fetched = false, updated = false;
  const module = load({fetch: async () => { fetched = true; }});
  await assert.rejects(module.collect({signal: controller.signal, onUpdate: () => { updated = true; }}), {name: 'AbortError'});
  assert.equal(fetched, false);
  assert.equal(updated, false);
});

test('cancellation aborts every request, closes WebRTC, clears timers and suppresses subsequent updates', async () => {
  const calls = [], timers = new Set(); let closed = 0, updated = 0;
  class RTC {
    createDataChannel() {}
    createOffer() { return Promise.resolve({}); }
    setLocalDescription() { return Promise.resolve(); }
    close() { closed++; }
  }
  const module = load({RTCPeerConnection: RTC,
    setTimeout(fn, ms) { const id = setTimeout(fn, ms); timers.add(id); return id; },
    clearTimeout(id) { clearTimeout(id); timers.delete(id); },
    fetch(url, options) { calls.push({url, options}); return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError'})), {once: true})); }});
  const controller = new AbortController(), run = module.collect({signal: controller.signal, onUpdate: () => { updated++; }});
  assert.equal(updated, 1);
  controller.abort();
  await assert.rejects(run, {name: 'AbortError'});
  assert.equal(updated, 1);
  assert.equal(calls.length, 10);
  assert.ok(calls.every(c => c.options.signal.aborted));
  assert.equal(closed, 1);
  assert.equal(timers.size, 0);
});

test('request timeouts are visible per probe and clear all timers', async () => {
  const timers = new Set();
  const module = load({
    setTimeout(fn) { const id = setTimeout(fn, 2); timers.add(id); return id; },
    clearTimeout(id) { clearTimeout(id); timers.delete(id); },
    fetch(url, options) { return new Promise((resolve, reject) => options.signal.addEventListener('abort', () => reject(Object.assign(new Error('aborted'), {name: 'AbortError'})), {once: true})); }});
  const result = await module.collect();
  assert.match(result.probes.find(p => p.id === 'v6').error, /请求超时/);
  assert.match(result.probes.find(p => p.id === 'tcp').error, /8000/);
  assert.equal(timers.size, 0);
});

test('WebRTC separates public, private and mDNS candidates and closes on completion', async () => {
  let closed = 0;
  class RTC {
    createDataChannel() {}
    createOffer() { return Promise.resolve({}); }
    setLocalDescription() {
      for (const address of ['8.8.8.8', '192.168.1.2', 'abc.local', '8.8.8.8']) this.onicecandidate({candidate: {address}});
      this.onicecandidate({candidate: null});
      return Promise.resolve();
    }
    close() { closed++; }
  }
  const module = load({RTCPeerConnection: RTC, fetch: fixtureFetch()});
  const result = await module.collect(), rtc = result.probes.find(p => p.id === 'rtc');
  assert.equal(rtc.status, 'ok');
  assert.deepEqual(plain(rtc.data), {publicIPs: ['8.8.8.8'], localIPs: ['192.168.1.2'], mdns: true});
  assert.equal(closed, 1);
});

test('WebRTC offer errors are exposed instead of becoming an empty successful result', async () => {
  let closed = 0;
  class RTC { createDataChannel() {} createOffer() { return Promise.reject(new Error('offer denied')); } close() { closed++; } }
  const result = await load({RTCPeerConnection: RTC, fetch: fixtureFetch()}).collect();
  const rtc = result.probes.find(p => p.id === 'rtc');
  assert.equal(rtc.status, 'error');
  assert.match(rtc.error, /offer denied/);
  assert.equal(closed, 1);
});

test('bare ECS addresses remain prefix-unknown while malformed ECS leaves the valid resolver visible', async () => {
  const base = fixtureFetch();
  async function runWith(edns) {
    return load({fetch: async (url, opts) => url.includes('.edns.ip-api.com')
      ? response({dns: {ip: '8.8.8.8', geo: 'United States - Google LLC'}, edns}) : base(url, opts)}).collect();
  }
  const v4 = (await runWith({ip: '1.1.1.0'})).probes.find(p => p.id === 'dns');
  assert.equal(v4.status, 'ok');
  assert.equal(v4.data.ecs.subnet, '1.1.1.0');
  assert.equal(v4.data.ecs.prefixUnknown, true);
  const unknown = api.analyze(snap([probe('site', {ip: '1.1.1.1'}), v4]));
  assert.deepEqual(ids(unknown), ['ecs-prefix-unknown']);
  assert.equal(unknown[0].level, 'info');
  const v6 = (await runWith({ip: '2606:4700::1'})).probes.find(p => p.id === 'dns');
  assert.equal(v6.data.ecs.subnet, '2606:4700::1');
  assert.equal(v6.data.ecs.prefixUnknown, true);
  const malformed = (await runWith({ip: 'None'})).probes.find(p => p.id === 'dns');
  assert.equal(malformed.status, 'ok');
  assert.equal(malformed.data.ip, '8.8.8.8');
  assert.equal(malformed.data.ecs, undefined);
  assert.match(malformed.data.ecsError, /无效/);
});

test('WebRTC time limit preserves partial candidates and explicitly marks the observation incomplete', async () => {
  let closed = 0;
  class RTC {
    createDataChannel() {}
    createOffer() { return Promise.resolve({}); }
    setLocalDescription() { this.onicecandidate({candidate: {address: '8.8.8.8'}}); return Promise.resolve(); }
    close() { closed++; }
  }
  const module = load({RTCPeerConnection: RTC, fetch: fixtureFetch(), setTimeout: fn => setTimeout(fn, 2)});
  const rtc = (await module.collect()).probes.find(p => p.id === 'rtc');
  assert.equal(rtc.status, 'ok');
  assert.deepEqual(plain(rtc.data.publicIPs), ['8.8.8.8']);
  assert.equal(rtc.data.timedOut, true);
  assert.match(rtc.data.note, /部分观测/);
  assert.equal(closed, 1);
});

test('a completed mDNS-only WebRTC gather is an observation of hidden candidates', async () => {
  class RTC {
    createDataChannel() {}
    createOffer() { return Promise.resolve({}); }
    setLocalDescription() { this.onicecandidate({candidate: {address: 'host.local'}}); this.onicecandidate({candidate: null}); return Promise.resolve(); }
    close() {}
  }
  const rtc = (await load({RTCPeerConnection: RTC, fetch: fixtureFetch()}).collect()).probes.find(p => p.id === 'rtc');
  assert.equal(rtc.status, 'ok');
  assert.equal(rtc.data.mdns, true);
  assert.equal(rtc.data.timedOut, undefined);
  const findings = api.analyze(snap([rtc]));
  assert.deepEqual(ids(findings), ['rtc-local']);
  assert.equal(findings[0].level, 'info');
});
