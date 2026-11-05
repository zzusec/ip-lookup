(function (root, factory) {
  'use strict';
  const api = factory(root);
  if (typeof module === 'object' && module.exports) module.exports = api;
  else root.IPConnection = api;
})(typeof globalThis === 'object' ? globalThis : this, function (root) {
  'use strict';

  function parseIP(value) {
    if (typeof value !== 'string') return null;
    let ip = value.trim();
    if (ip.startsWith('[') && ip.endsWith(']')) ip = ip.slice(1, -1);
    if (!ip.includes(':')) {
      if (!/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(ip)) return null;
      const bytes = ip.split('.').map(Number);
      return bytes.every(n => n <= 255) ? {family: 4, bytes} : null;
    }
    if (ip.includes('%')) {
      if (!/^[^%]+%[\w.-]+$/.test(ip)) return null;
      ip = ip.slice(0, ip.indexOf('%'));
    }
    if (ip.includes('.')) {
      const at = ip.lastIndexOf(':'), tail = parseIP(ip.slice(at + 1));
      if (!tail || tail.family !== 4) return null;
      const b = tail.bytes;
      ip = ip.slice(0, at + 1) + ((b[0] << 8) | b[1]).toString(16) + ':' + ((b[2] << 8) | b[3]).toString(16);
    }
    if (!/^[\da-f:]+$/i.test(ip)) return null;
    const halves = ip.split('::');
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(':') : [];
    const right = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
    if (![...left, ...right].every(x => /^[\da-f]{1,4}$/i.test(x))) return null;
    const missing = 8 - left.length - right.length;
    if (halves.length === 1 ? missing !== 0 : missing < 1) return null;
    const words = [...left, ...Array(missing).fill('0'), ...right].map(x => parseInt(x, 16));
    const bytes = words.flatMap(n => [n >> 8, n & 255]);
    if (bytes.slice(0, 10).every(x => x === 0) && bytes[10] === 255 && bytes[11] === 255)
      return {family: 4, bytes: bytes.slice(12)};
    return {family: 6, bytes};
  }
  function formatIP(parsed) {
    if (parsed.family === 4) return parsed.bytes.join('.');
    const w = [];
    for (let i = 0; i < 16; i += 2) w.push(((parsed.bytes[i] << 8) | parsed.bytes[i + 1]).toString(16));
    let start = -1, length = 1;
    for (let i = 0; i < 8;) {
      if (w[i] !== '0') { i++; continue; }
      let j = i;
      while (j < 8 && w[j] === '0') j++;
      if (j - i > length) { start = i; length = j - i; }
      i = j;
    }
    return start < 0 ? w.join(':') : w.slice(0, start).join(':') + '::' + w.slice(start + length).join(':');
  }
  const canonicalIP = value => { const p = parseIP(value); return p ? formatIP(p) : ''; };
  const sameIP = (a, b) => { const x = canonicalIP(a); return Boolean(x && x === canonicalIP(b)); };
  function prefixMatches(a, b, bits) {
    if (!a || !b || a.family !== b.family || !Number.isInteger(bits) || bits < 0 || bits > a.bytes.length * 8) return false;
    const full = Math.floor(bits / 8), partial = bits % 8;
    for (let i = 0; i < full; i++) if (a.bytes[i] !== b.bytes[i]) return false;
    return !partial || (a.bytes[full] >> (8 - partial)) === (b.bytes[full] >> (8 - partial));
  }
  function samePrefix(a, b, bits) {
    const x = parseIP(a), y = parseIP(b);
    return prefixMatches(x, y, bits == null ? x && x.family === 6 ? 64 : 24 : bits);
  }
  function parseSubnet(value) {
    if (typeof value !== 'string') return null;
    const parts = value.trim().split('/'), ip = parseIP(parts[0]);
    if (parts.length !== 2 || !ip || !/^(0|[1-9]\d{0,2})$/.test(parts[1])) return null;
    const bits = Number(parts[1]);
    return bits <= ip.bytes.length * 8 ? {ip, bits} : null;
  }
  function containsSubnet(subnet, ip) {
    const p = parseSubnet(subnet);
    return Boolean(p && prefixMatches(p.ip, parseIP(ip), p.bits));
  }
  const PRIVATE4 = ['0.0.0.0/8', '10.0.0.0/8', '100.64.0.0/10', '127.0.0.0/8', '169.254.0.0/16',
    '172.16.0.0/12', '192.0.0.0/24', '192.0.2.0/24', '192.88.99.0/24', '192.168.0.0/16',
    '198.18.0.0/15', '198.51.100.0/24', '203.0.113.0/24', '224.0.0.0/3'];
  function isPublic(value) {
    const ip = canonicalIP(value), p = parseIP(ip);
    if (!p) return false;
    if (p.family === 4) return !PRIVATE4.some(s => containsSubnet(s, ip));
    return containsSubnet('2000::/3', ip) && !containsSubnet('2001::/23', ip) && !containsSubnet('2001:db8::/32', ip);
  }
  const text = value => typeof value === 'string' ? value.trim().slice(0, 300) : '';
  const finite = value => typeof value === 'number' && Number.isFinite(value) ? value : undefined;
  const country = value => /^[a-z]{2}$/i.test(text(value)) ? text(value).toUpperCase() : '';
  function record(value) {
    if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('响应不是有效的对象');
    return value;
  }
  function httpData(value, family) {
    const o = record(value), ip = canonicalIP(o.ip);
    if (!ip || family && parseIP(ip).family !== family) throw new Error('响应缺少有效的 IPv' + (family || '4/IPv6') + ' 地址');
    const out = {ip, version: parseIP(ip).family};
    for (const k of ['loc', 'colo', 'warp', 'tls', 'http']) if (text(o[k])) out[k] = text(o[k]);
    return out;
  }
  function traceData(raw) {
    const fields = {};
    for (const line of String(raw).split('\n')) {
      const i = line.indexOf('=');
      if (i > 0) fields[line.slice(0, i)] = line.slice(i + 1).trim();
    }
    return httpData(fields);
  }
  function splitGeo(value) {
    const parts = text(value).split(/\s+-\s+/);
    return {country: parts.shift() || '', org: parts.join(' - ')};
  }
  function dnsData(value) {
    const o = record(value), dns = record(o.dns), ip = canonicalIP(dns.ip);
    if (!ip) throw new Error('DNS 响应缺少有效的解析器地址');
    const geo = splitGeo(dns.geo), out = {ip, country: country(dns.countryCode) || text(dns.country) || geo.country,
      org: text(dns.org) || geo.org};
    const edns = o.edns;
    const subnet = typeof edns === 'string' ? edns : edns && typeof edns === 'object' ? edns.ip || edns.subnet : '';
    if (subnet) {
      const host = canonicalIP(subnet), normalized = host || text(subnet);
      if (!host && !parseSubnet(normalized)) out.ecsError = 'EDNS 客户端子网格式无效，无法核对该字段';
      else {
        const eg = splitGeo(edns && edns.geo);
        out.ecs = {subnet: normalized};
        if (host) out.ecs.prefixUnknown = true;
        if (eg.country) out.ecs.country = eg.country;
        if (eg.org) out.ecs.org = eg.org;
      }
    }
    return out;
  }
  function tcpData(value) {
    const o = record(value), ip = canonicalIP(o.lookup_ip);
    if (!ip) throw new Error('TCP 响应缺少本次观测的 lookup_ip');
    let os = text(o.os), score;
    if (o.avg_score_os_class && typeof o.avg_score_os_class === 'object' && !Array.isArray(o.avg_score_os_class)) {
      const ranked = Object.entries(o.avg_score_os_class).filter(([name, n]) => text(name) && finite(n) !== undefined).sort((a, b) => b[1] - a[1]);
      if (ranked.length) { os = ranked[0][0]; score = ranked[0][1]; }
    }
    if (!os) throw new Error('TCP 响应缺少可用的系统指纹');
    const relay = o.relay && typeof o.relay === 'object' && !Array.isArray(o.relay) ? o.relay : null;
    const out = {ip, os, relay: relay && typeof relay.flagged === 'boolean' ? relay.flagged : null,
      mismatch: typeof o.os_mismatch === 'boolean' ? o.os_mismatch : null};
    if (relay && finite(relay.probability) !== undefined && relay.probability >= 0 && relay.probability <= 1)
      out.probability = relay.probability;
    if (score !== undefined) out.score = score;
    if (finite(o.perfect_score) !== undefined) out.perfectScore = o.perfect_score;
    if (relay && text(relay.ua_os)) out.uaOS = text(relay.ua_os);
    else if (text(o.ua_os)) out.uaOS = text(o.ua_os);
    return out;
  }
  function abortError() { const e = new Error('检测已取消'); e.name = 'AbortError'; return e; }
  function unsupported(message) { const e = new Error(message); e.name = 'NotSupportedError'; return e; }
  function checkAbort(signal) { if (signal && signal.aborted) throw abortError(); }
  async function request(url, signal, type = 'json', timeout = 6000) {
    checkAbort(signal);
    const ctl = new root.AbortController();
    let expired = false;
    const cancel = () => ctl.abort(), timer = root.setTimeout(() => { expired = true; ctl.abort(); }, timeout);
    if (signal) signal.addEventListener('abort', cancel, {once: true});
    try {
      const response = await root.fetch(url, {signal: ctl.signal, cache: 'no-store', credentials: 'omit',
        referrerPolicy: 'no-referrer', headers: {accept: type === 'json' ? 'application/json' : 'text/plain'}});
      if (!response.ok) throw new Error('HTTP ' + response.status);
      return await (type === 'json' ? response.json() : response.text());
    } catch (error) {
      if (signal && signal.aborted) throw abortError();
      if (expired) throw new Error('请求超时（' + timeout + ' ms）');
      throw error;
    } finally {
      root.clearTimeout(timer);
      if (signal) signal.removeEventListener('abort', cancel);
    }
  }
  function rtcData(signal) {
    return new Promise((resolve, reject) => {
      checkAbort(signal);
      if (typeof root.RTCPeerConnection !== 'function') return reject(unsupported('浏览器不支持 WebRTC'));
      let pc, timer, settled = false;
      const data = {publicIPs: [], localIPs: [], mdns: false}, errors = new Set();
      const cancel = () => finish(abortError());
      function finish(error) {
        if (settled) return;
        settled = true;
        root.clearTimeout(timer);
        if (signal) signal.removeEventListener('abort', cancel);
        if (pc) { pc.onicecandidate = null; pc.onicecandidateerror = null; try { pc.close(); } catch {} }
        if (!error && !data.publicIPs.length && !data.localIPs.length && !data.mdns)
          error = new Error('未收集到 ICE 地址；无法确认 WebRTC 出口' + (errors.size ? '（' + [...errors].join('；') + '）' : ''));
        error ? reject(error) : resolve(data);
      }
      try {
        pc = new root.RTCPeerConnection({iceServers: [{urls: ['stun:stun.l.google.com:19302', 'stun:stun.cloudflare.com:3478']} ]});
        if (signal) signal.addEventListener('abort', cancel, {once: true});
        timer = root.setTimeout(() => {
          data.timedOut = true;
          data.note = 'ICE 采集到达 6 秒时限，以下为部分观测；未取得的候选仍未知';
          finish();
        }, 6000);
        pc.onicecandidateerror = event => errors.add('STUN ' + (event.errorCode || '') + ' ' + text(event.errorText));
        pc.onicecandidate = event => {
          if (!event.candidate) return finish();
          const c = event.candidate, parts = text(c.candidate).split(/\s+/), address = text(c.address) || parts[4] || '';
          if (/\.local\.?$/i.test(address)) { data.mdns = true; return; }
          const ip = canonicalIP(address);
          if (!ip) return;
          const list = isPublic(ip) ? data.publicIPs : data.localIPs;
          if (!list.includes(ip)) list.push(ip);
        };
        pc.createDataChannel('connection-probe');
        Promise.resolve(pc.createOffer()).then(offer => {
          if (!settled) return pc.setLocalDescription(offer);
        }).catch(finish);
      } catch (error) { finish(error); }
    });
  }
  function environment() {
    let timeZone = '';
    try { timeZone = Intl.DateTimeFormat().resolvedOptions().timeZone || ''; } catch {}
    const nav = root.navigator;
    return {timeZone, offsetMinutes: -new Date().getTimezoneOffset(),
      languages: nav ? Array.from(nav.languages || (nav.language ? [nav.language] : [])).filter(v => typeof v === 'string').slice(0, 10) : []};
  }
  async function collect({signal: parent, onUpdate} = {}) {
    checkAbort(parent);
    // A single parent listener also avoids accumulating Node AbortSignal
    // listeners when the same module is exercised outside the browser.
    const listeners = new Set();
    const cancelled = () => { for (const listener of [...listeners]) listener(); };
    const signal = {get aborted() { return Boolean(parent && parent.aborted); },
      addEventListener(type, listener) { if (type === 'abort') listeners.add(listener); },
      removeEventListener(type, listener) { if (type === 'abort') listeners.delete(listener); }};
    if (parent) parent.addEventListener('abort', cancelled, {once: true});
    const snapshot = {startedAt: new Date().toISOString(), environment: environment(), probes: []};
    const json = url => request(url, signal);
    const trace = url => request(url, signal, 'text').then(traceData);
    const defs = [
      ['site', '本站观察', () => json('/api/ip').then(o => httpData(o))],
      ['v4', 'IPv4', () => json('https://api4.ipify.org?format=json').then(o => httpData(o, 4))],
      ['v6', 'IPv6', () => json('https://api6.ipify.org?format=json').then(o => httpData(o, 6))],
      ['pref', '双栈优先协议', () => json('https://api64.ipify.org?format=json').then(o => httpData(o))],
      ['cf', 'Cloudflare', () => trace('https://1.1.1.1/cdn-cgi/trace')],
      ['chatgpt', 'ChatGPT', () => trace('https://chatgpt.com/cdn-cgi/trace')],
      ['claude', 'Claude', () => trace('https://claude.ai/cdn-cgi/trace')],
      ['cn', '国内目标', async () => {
        try {
          const o = record(await json('https://myip.ipip.net/json'));
          if (o.ret !== 'ok') throw new Error('国内目标响应无效');
          const d = httpData(o.data);
          if (Array.isArray(o.data.location)) d.location = o.data.location.filter(x => typeof x === 'string').join(' ');
          return d;
        } catch (first) {
          checkAbort(signal);
          try { return httpData(await json('https://api.ipify.cn/?format=json')); }
          catch (second) { checkAbort(signal); throw new Error('国内目标均未返回有效结果：' + first.message + '；' + second.message); }
        }
      }],
      ['dns', 'DNS / EDNS', async () => {
        if (!root.crypto || typeof root.crypto.getRandomValues !== 'function') throw unsupported('缺少安全随机数，无法发起独立 DNS 探测');
        const nonce = Array.from(root.crypto.getRandomValues(new Uint8Array(16)), x => x.toString(16).padStart(2, '0')).join('');
        return dnsData(await json('https://' + nonce + '.edns.ip-api.com/json'));
      }],
      ['rtc', 'WebRTC / STUN', () => rtcData(signal)],
      ['tcp', 'TCP 系统指纹', () => request('https://tcpip.incolumitas.com/classify?by_ip=1', signal, 'json', 8000).then(tcpData)],
    ];
    snapshot.probes = defs.map(([id, label]) => ({id, label, status: 'pending'}));
    let left = defs.length;
    try {
      if (onUpdate) onUpdate(snapshot);
      const results = await Promise.allSettled(defs.map(async ([, , run], index) => {
        const started = Date.now(), p = snapshot.probes[index];
        try { checkAbort(signal); p.data = await run(); p.status = 'ok'; }
        catch (error) {
          p.status = error && error.name === 'NotSupportedError' ? 'unsupported' : 'error';
          p.error = text(error && error.message) || '检测失败';
        }
        p.ms = Math.max(0, Date.now() - started);
        if (--left === 0) snapshot.finishedAt = new Date().toISOString();
        if (!signal.aborted && onUpdate) onUpdate(snapshot);
      }));
      checkAbort(signal);
      const callbackError = results.find(result => result.status === 'rejected');
      if (callbackError) throw callbackError.reason;
      return snapshot;
    } finally {
      if (parent) parent.removeEventListener('abort', cancelled);
      listeners.clear();
    }
  }
  const HTTP_IDS = new Set(['site', 'v4', 'v6', 'pref', 'cf', 'chatgpt', 'claude', 'cn']);
  function countryKey(value) {
    let v = text(value);
    if (/^[a-z]{2}$/i.test(v)) {
      try { v = new Intl.DisplayNames(['en'], {type: 'region'}).of(v.toUpperCase()); } catch {}
    }
    return v.toLowerCase().replace(/^the\s+/, '').replace(/[^a-z]/g, '');
  }
  function zoneOffset(timeZone, at) {
    try {
      const parts = new Intl.DateTimeFormat('en-US', {timeZone, year: 'numeric', month: '2-digit', day: '2-digit',
        hour: '2-digit', minute: '2-digit', second: '2-digit', hourCycle: 'h23'}).formatToParts(at);
      const n = Object.fromEntries(parts.filter(p => p.type !== 'literal').map(p => [p.type, Number(p.value)]));
      return Math.round((Date.UTC(n.year, n.month - 1, n.day, n.hour, n.minute, n.second) - at.getTime()) / 60000);
    } catch { return null; }
  }
  function analyze(snapshot, lookupResult) {
    const probes = snapshot && Array.isArray(snapshot.probes) ? snapshot.probes : [];
    const ok = probes.filter(p => p.status === 'ok' && p.data && typeof p.data === 'object');
    const byID = new Map(ok.map(p => [p.id, p]));
    const http = ok.filter(p => HTTP_IDS.has(p.id) && canonicalIP(p.data.ip));
    const findings = [], push = (id, level, title, detail) => findings.push({id, level, title, detail});
    if (!ok.length) {
      push('unavailable', 'info', '尚无可用的连接观测', '本轮探测没有返回有效证据。请求失败或浏览器不支持，不能据此确认无 IPv6、无代理或没有泄露。');
      return findings;
    }
    for (const family of [4, 6]) {
      const group = http.filter(p => parseIP(p.data.ip).family === family);
      const unique = [...new Set(group.map(p => canonicalIP(p.data.ip)))];
      if (unique.length > 1) {
        const privacy = family === 6 && unique.every(ip => samePrefix(ip, unique[0], 64));
        push('egress-v' + family, 'info', 'IPv' + family + ' 目标之间存在出口差异',
          group.map(p => p.label + '：' + canonicalIP(p.data.ip)).join('；') + '。' +
          (privacy ? '这些地址属于同一 /64，可能是 IPv6 隐私地址变化，不能仅凭地址不同认定代理分流。' : '这是多出口或分流线索；也可能来自多出口 NAT、负载均衡，不能仅凭此判断国内直连或国外代理。'));
      }
    }
    const rtc = byID.get('rtc');
    if (rtc) {
      const d = rtc.data, publicIPs = Array.isArray(d.publicIPs) ? [...new Set(d.publicIPs.map(canonicalIP).filter(isPublic))] : [];
      for (const ip of publicIPs) {
        const family = parseIP(ip).family, sameFamily = http.filter(p => parseIP(p.data.ip).family === family);
        const site = sameFamily.find(p => p.id === 'site'), refs = site ? [site] : sameFamily;
        if (!refs.length) {
          push('rtc-unknown-v' + family, 'info', 'WebRTC 公网地址缺少同协议参考',
            ip + ' 没有可比较的 IPv' + family + ' HTTP 出口；不能拿 IPv4 与 IPv6 的差异判断泄露。');
        } else if (refs.some(p => sameIP(ip, p.data.ip))) {
          // A matching observation needs no warning.
        } else if (family === 6 && refs.some(p => samePrefix(ip, p.data.ip, 64))) {
          push('rtc-prefix', 'info', 'WebRTC 与 HTTP 位于同一 IPv6 /64',
            ip + ' 与 HTTP 地址不同，但前 64 位一致，可能是隐私地址或同一接入网的地址；这不是独立的真实公网 IP 泄露证据。');
        } else {
          push('rtc-different-v' + family, 'warn', 'WebRTC 与 HTTP 的公网出口不同',
            'WebRTC：' + ip + '；HTTP：' + refs.map(p => canonicalIP(p.data.ip)).join('、') +
            '。UDP/STUN 与 HTTP 可能走不同路径，需结合实际代理策略核对；尚不能确认哪个地址是本机真实出口。');
        }
      }
      if (!publicIPs.length) push('rtc-local', 'info', 'WebRTC 未提供可比较的公网地址',
        d.mdns ? '仅观测到本机地址或 mDNS 名称。mDNS 隐藏了候选地址；这不能证明没有公网旁路。' : '本机或保留地址不作为真实公网泄露证据；也不能据此确认公网出口安全。');
    }
    const dns = byID.get('dns');
    if (dns) {
      const d = dns.data, reference = byID.get('site') || http[0], lookup = lookupResult || {};
      const geoMatches = reference && sameIP(lookup.ip, reference.data.ip);
      const exitCountry = geoMatches && lookup.geo && lookup.geo.country_code || reference && reference.data.loc;
      if (d.country && exitCountry && countryKey(d.country) && countryKey(d.country) !== countryKey(exitCountry))
        push('dns-country', 'info', 'DNS 与 HTTP 出口的地理定位不同',
          'DNS：' + d.country + (d.org ? ' / ' + d.org : '') + '；HTTP：' + exitCountry +
          '。公共 DNS、Anycast、DoH 和数据库差异均可能造成跨国定位，不能单凭国家不同认定 DNS 泄露。');
      const ecs = d.ecs && !d.ecs.prefixUnknown && parseSubnet(d.ecs.subnet);
      if (d.ecs && d.ecs.prefixUnknown && canonicalIP(d.ecs.subnet))
        push('ecs-prefix-unknown', 'info', 'EDNS 客户端信息缺少前缀长度',
          canonicalIP(d.ecs.subnet) + ' 是接口返回的裸地址，可能是已脱敏的网络地址；接口未提供 ECS 前缀长度，无法核对覆盖范围。');
      if (ecs) {
        const subnet = d.ecs.subnet, refs = http.filter(p => parseIP(p.data.ip).family === ecs.ip.family);
        if (ecs.bits === 0) push('ecs-masked', 'info', 'EDNS 客户端子网被置为 /0', '本轮观察到 ' + subnet + '，它不携带可比较的客户端网络前缀；这不代表其他 DNS 路径也没有 ECS。');
        else if (!isPublic(formatIP(ecs.ip))) push('ecs-local', 'info', 'EDNS 携带非公网客户端子网', subnet + ' 属于本机、私网或保留地址，不能将它当作真实公网 IP。');
        else if (!refs.length) push('ecs-unknown', 'info', 'EDNS 客户端子网缺少同协议参考', subnet + ' 没有同地址族 HTTP 出口可供核对，无法判断它来自哪条路径。');
        else if (refs.some(p => containsSubnet(subnet, p.data.ip))) push('ecs-matches', 'info', 'EDNS 客户端子网覆盖已观测出口', subnet + ' 包含至少一个本轮 HTTP 出口；这只说明该次 ECS 观测与已知路径相符。');
        else push('ecs-different', 'warn', 'EDNS 携带不同的公网客户端子网', subnet + ' 不包含本轮同协议 HTTP 出口。解析器向下游附带了另一网络前缀，可能暴露额外的接入网信息，需要核对 DNS / 代理配置。');
      }
    }
    const tcp = byID.get('tcp');
    if (tcp && canonicalIP(tcp.data.ip)) {
      const d = tcp.data, matches = http.some(p => sameIP(p.data.ip, d.ip));
      if (!matches) push('tcp-path', 'info', 'TCP 指纹与已观测 HTTP 出口不在同一路径',
        '指纹接口观测到 ' + canonicalIP(d.ip) + '，未匹配本轮 HTTP 出口。该系统指纹可能属于其他出口，暂不据此推断当前连接的代理或系统不一致。');
      else {
        if (d.relay === true) push('tcp-relay', 'warn', 'TCP 指纹提供了中继线索',
          '指纹接口的 lookup_ip 已与本轮 HTTP 出口核对，但 relay 是第三方分类结果，可能受 NAT、网关或协议栈影响，不能单独证明存在代理。');
        if (d.mismatch === true) push('tcp-os', 'info', 'TCP 与浏览器系统线索不一致',
          'TCP 系统倾向为 ' + text(d.os) + (d.uaOS ? '，浏览器标识为 ' + text(d.uaOS) : '') +
          '。系统指纹、浏览器标识和出口设备可能不同；这是弱线索，不单独作为代理判据。');
      }
    }
    const cf = byID.get('cf');
    if (cf && String(cf.data.warp).toLowerCase() === 'on') push('warp', 'info', 'Cloudflare 报告 WARP 已开启',
      '这是该 Cloudflare 请求路径的观测，不据此改变 IP 类型或其他目标的出口判断。');
    if (byID.has('chatgpt') || byID.has('claude')) push('target-reachability', 'info', '目标站点返回了连接观测',
      'ChatGPT / Claude 的 trace 可达仅说明该端点的请求成功，不代表账号可登录、地区解锁或完整服务可用。');
    const env = snapshot && snapshot.environment, lookup = lookupResult || {};
    if (env && Number.isFinite(env.offsetMinutes) && lookup.geo && lookup.geo.time_zone && http.some(p => sameIP(p.data.ip, lookup.ip))) {
      const at = new Date(snapshot.startedAt), offset = zoneOffset(lookup.geo.time_zone, Number.isNaN(at.getTime()) ? new Date() : at);
      if (offset !== null && offset !== env.offsetMinutes) push('time-zone', 'info', '浏览器与出口定位的时区偏移不同',
        '浏览器：' + (text(env.timeZone) || '未知时区') + '；出口数据库：' + text(lookup.geo.time_zone) +
        '。旅行、手动设置、远程桌面和出口路由均可能造成差异，此项只作环境信息，不影响纯净度评分。');
    }
    return findings;
  }
  return {collect, analyze, canonicalIP, sameIP, isPublic, samePrefix, containsSubnet};
});
