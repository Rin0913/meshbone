"""VIEW: HTML pages, page assets, Prometheus text and terminal output. Pure: they format what they are given."""

import base64, html, json, re, time, urllib.parse

from . import settings, store


PAGE_STYLE = """<style>
:root{color-scheme:light dark;--bg:#fbfbfa;--fg:#1c1c1a;--muted:#6f6f68;--line:#deded7;--ok:#2f7d4f;--bad:#c2413a;--hub:#2d5fa8;--client:#8a8a80;--s1:#2a78d6;--s2:#eb6834}
@media (prefers-color-scheme:dark){:root{--bg:#161615;--fg:#ecece6;--muted:#9a9a90;--line:#34342f;--ok:#5fbf85;--bad:#f07a70;--hub:#7fa9ea;--client:#8f8f86;--s1:#3987e5;--s2:#d95926}}
body{font:14px/1.45 system-ui,sans-serif;margin:0;padding:20px;background:var(--bg);color:var(--fg);max-width:1100px;margin-inline:auto}
h1{font-size:20px;margin:0 0 4px}h2{font-size:15px;margin:28px 0 8px}h3{font-size:14px;margin:0}p{margin:4px 0;color:var(--muted)}a{color:var(--hub)}
nav{margin:0 0 14px;display:flex;gap:16px;flex-wrap:wrap}nav b{color:var(--fg)}
canvas{width:100%;display:block}#map{border:1px solid var(--line);border-radius:8px;margin:14px 0 6px}
.scroll{overflow-x:auto}table{border-collapse:collapse;width:100%}td,th{border-bottom:1px solid var(--line);padding:6px 10px;text-align:left;white-space:nowrap}
th{font-weight:600;color:var(--muted);font-size:12px}td.n,th.n{text-align:right;font-variant-numeric:tabular-nums}code,td.m{font-family:ui-monospace,monospace;font-size:13px}
input{font:inherit;padding:3px 5px;width:10em}input[name=cost]{width:4em}input.w{width:16em}button{font:inherit;padding:3px 10px}button.on{font-weight:600;border-color:var(--fg)}
pre{padding:10px;border:1px solid var(--line);border-radius:6px;white-space:pre-wrap}.key span,.tag{display:inline-block;margin-right:16px}
.tag{margin-right:4px;padding:0 6px;border:1px solid var(--line);border-radius:10px;font-size:12px}
.bar{display:flex;gap:6px;flex-wrap:wrap;align-items:center;margin:10px 0}.bar span{color:var(--muted);margin-left:10px}.bar input{width:13em}
.chart{border:1px solid var(--line);border-radius:8px;padding:12px 14px;margin:12px 0;position:relative}.chart p{font-size:12px}
.k{display:inline-block;width:14px;height:0;border-top:2px solid;vertical-align:middle;margin:0 5px 0 12px}
#tip{position:fixed;pointer-events:none;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:6px 9px;font-size:12px;box-shadow:0 2px 8px #0003;display:none}
#tip b{font-variant-numeric:tabular-nums}form.grid{display:flex;gap:6px;flex-wrap:wrap}
</style>"""


MAP_SCRIPT = """<script>
const T = __DATA__, cv = document.getElementById('map'), g = cv.getContext('2d');
const css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const KEY = 'meshbone-map-' + (T.mesh || ''), hubs = T.nodes.filter(n => n.hub), clients = T.nodes.filter(n => !n.hub);
let saved = {}; try { saved = JSON.parse(localStorage.getItem(KEY) || '{}'); } catch (e) {}
let pos = {}, drag = null;
function layout(W, H) {                          // hubs on an inner ring, clients on an outer one; saved drags win
  const cx = W / 2, cy = H / 2;
  const sendsVia = n => { const l = T.links.find(l => l.a === n.id && l.primary); return l ? hubs.findIndex(h => h.id === l.b) : hubs.length; };
  const order = clients.slice().sort((a, b) => sendsVia(a) - sendsVia(b) || a.id - b.id);
  const r1 = hubs.length > 1 ? Math.min(W, H) * 0.16 : 0;
  hubs.forEach((n, i) => { const a = 2 * Math.PI * i / hubs.length - Math.PI / 2; pos[n.id] = [cx + r1 * Math.cos(a), cy + r1 * Math.sin(a)]; });
  order.forEach((n, i) => { const a = 2 * Math.PI * (i + 0.5) / order.length - Math.PI / 2; pos[n.id] = [cx + W * 0.40 * Math.cos(a), cy + H * 0.38 * Math.sin(a)]; });
  for (const n of T.nodes) if (saved[n.name]) pos[n.id] = [saved[n.name][0] * W, saved[n.name][1] * H];
}
function labelsOf(n) { return [n.name, n.ip].concat(n.subnets.map(s => 'net ' + s), n.vips.map(v => 'vip ' + v), n.public ? ['public ' + n.public] : []); }
function draw() {
  const W = cv.clientWidth, H = Math.max(420, Math.min(760, W * 0.66)), k = devicePixelRatio || 1;
  cv.width = W * k; cv.height = H * k; cv.style.height = H + 'px'; g.setTransform(k, 0, 0, k, 0, 0); g.clearRect(0, 0, W, H);
  if (!Object.keys(pos).length || cv.dataset.w != W) { pos = {}; layout(W, H); cv.dataset.w = W; }
  const cx = W / 2, cy = H / 2;
  g.textAlign = 'center'; g.textBaseline = 'middle';
  for (const l of T.links) {                       // links first, nodes on top
    const [x1, y1] = pos[l.a], [x2, y2] = pos[l.b], hubLink = hubs.some(h => h.id === l.a);
    g.beginPath(); g.moveTo(x1, y1); g.lineTo(x2, y2);
    g.strokeStyle = css(l.up ? '--ok' : '--bad'); g.setLineDash(l.up ? [] : [5, 5]);
    g.lineWidth = l.up && (hubLink || l.primary) ? 2.5 : 1; g.globalAlpha = !l.up ? 0.4 : !hubLink && !l.primary ? 0.45 : 1; g.stroke();
    g.globalAlpha = 1; g.setLineDash([]);
    if (l.up && l.ms != null) {                   // the ping sits near the client end, clear of the middle
      g.font = '12px system-ui, sans-serif';
      const label = l.ms + ' ms', t = hubLink ? 0.5 : 0.3, mx = x1 + (x2 - x1) * t, my = y1 + (y2 - y1) * t, w = g.measureText(label).width + 8;
      g.fillStyle = css('--bg'); g.fillRect(mx - w / 2, my - 8, w, 16); g.fillStyle = css('--fg'); g.fillText(label, mx, my);
    }
  }
  for (const n of T.nodes) {
    const [x, y] = pos[n.id], r = n.hub ? 15 : 9, linked = n.hub || T.links.some(l => l.a === n.id && l.up);
    g.beginPath(); g.arc(x, y, r, 0, 2 * Math.PI); g.fillStyle = css(n.hub ? '--hub' : linked ? '--client' : '--bg'); g.fill();
    g.lineWidth = n.me ? 3 : 1.5; g.strokeStyle = css(n.me ? '--fg' : n.hub ? '--hub' : '--client'); g.stroke();
    if (n.admin) { g.beginPath(); g.arc(x, y, r + 4, 0, 2 * Math.PI); g.lineWidth = 1; g.setLineDash([2, 3]); g.strokeStyle = css('--fg'); g.stroke(); g.setLineDash([]); }
    // labels go away from the centre for clients (outer ring) and towards it for hubs (inner ring), so they meet nobody
    const up = n.hub ? (y < cy - 1 ? 1 : -1) : (y < cy - 1 ? -1 : 1), lines = labelsOf(n);
    lines.forEach((t, i) => {
      g.font = (i ? '11px ui-monospace, monospace' : '600 13px system-ui, sans-serif');
      const ty = y + up * (r + 13) + (up > 0 ? i : i - lines.length + 1) * 14, w = g.measureText(t).width + 6;
      g.fillStyle = css('--bg'); g.globalAlpha = 0.85; g.fillRect(x - w / 2, ty - 7, w, 14); g.globalAlpha = 1;
      g.fillStyle = css(i ? '--muted' : '--fg'); g.fillText(t, x, ty);
    });
  }
}
function at(e) { const b = cv.getBoundingClientRect(); return [e.clientX - b.left, e.clientY - b.top]; }
cv.onpointerdown = e => {                        // drag a node; where it lands is remembered in this browser
  const [x, y] = at(e);
  const hit = T.nodes.find(n => Math.hypot(pos[n.id][0] - x, pos[n.id][1] - y) < 18);
  if (hit) { drag = hit; cv.setPointerCapture(e.pointerId); cv.style.cursor = 'grabbing'; }
};
cv.onpointermove = e => {
  if (!drag) { const [x, y] = at(e); cv.style.cursor = T.nodes.some(n => Math.hypot(pos[n.id][0] - x, pos[n.id][1] - y) < 18) ? 'grab' : ''; return; }
  const [x, y] = at(e); pos[drag.id] = [Math.max(10, Math.min(cv.clientWidth - 10, x)), Math.max(10, Math.min(cv.clientHeight - 10, y))]; draw();
};
cv.onpointerup = cv.onpointercancel = e => {
  if (!drag) return;
  saved[drag.name] = [pos[drag.id][0] / cv.clientWidth, pos[drag.id][1] / cv.clientHeight];
  try { localStorage.setItem(KEY, JSON.stringify(saved)); } catch (x) {}
  drag = null; cv.style.cursor = '';
};
cv.ondblclick = () => { saved = {}; try { localStorage.removeItem(KEY); } catch (x) {} pos = {}; draw(); };
draw(); addEventListener('resize', () => { pos = {}; draw(); }); matchMedia('(prefers-color-scheme: dark)').addEventListener('change', draw);
</script>"""


TRAFFIC_SCRIPT = """<script>
const $ = s => document.querySelector(s), css = v => getComputedStyle(document.documentElement).getPropertyValue(v).trim();
const PRESETS = [['1 h', 3600], ['6 h', 21600], ['24 h', 86400], ['7 d', 604800], ['30 d', 2592000], ['90 d', 7776000]];
let range = {span: 3600}, D = null, charts = [];
const rate = v => { v = Math.abs(v); const u = ['b/s', 'kb/s', 'Mb/s', 'Gb/s']; let i = 0; while (v >= 1000 && i < 3) { v /= 1000; i++; } return (v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + u[i]; };
const size = v => { const u = ['B', 'kB', 'MB', 'GB', 'TB']; let i = 0; while (v >= 1000 && i < 4) { v /= 1000; i++; } return (v >= 100 || i === 0 ? v.toFixed(0) : v.toFixed(1)) + ' ' + u[i]; };
const clock = (t, long) => { const d = new Date(t * 1000), p = n => String(n).padStart(2, '0'), hm = p(d.getHours()) + ':' + p(d.getMinutes());
  return long || D.to - D.from > 86400 ? (d.getMonth() + 1) + '/' + d.getDate() + ' ' + hm : hm; };
const el = (tag, text, cls) => { const e = document.createElement(tag); if (text != null) e.textContent = text; if (cls) e.className = cls; return e; };
const local = t => { const d = new Date(t * 1000 - new Date().getTimezoneOffset() * 60000); return d.toISOString().slice(0, 16); };

function bar() {
  const b = $('#bar'); b.textContent = '';
  for (const [name, span] of PRESETS) {
    const x = el('button', name, range.span === span ? 'on' : ''); x.onclick = () => { range = {span}; load(); }; b.append(x);
  }
  const f = el('input'), t = el('input'), go = el('button', 'show'); f.type = t.type = 'datetime-local';
  if (D) { f.value = local(D.from); t.value = local(D.to); }
  go.onclick = () => { const a = Date.parse(f.value) / 1000, z = Date.parse(t.value) / 1000; if (a < z) { range = {from: a, to: z}; load(); } };
  b.append(el('span', 'or from'), f, el('span', 'to'), t, go);
}

async function load() {
  const now = Math.floor(Date.now() / 1000), to = range.to || now, from = range.from || to - range.span;
  D = await (await fetch('/api/traffic?from=' + from + '&to=' + to)).json();
  const first = Math.min(...D.links.flatMap(l => l.points.map(p => p[0])));   // history may be younger than the window
  D.since = isFinite(first) && first - D.from > (D.to - D.from) * 0.2 ? first : null; if (D.since) D.from = D.since - D.step;
  bar(); render();
}

function render() {
  const sum = $('#sum'), box = $('#charts'); sum.textContent = ''; box.textContent = ''; charts = [];
  $('#note').textContent = D.links.length ? 'one point = ' + (D.step >= 3600 ? D.step / 3600 + ' h' : D.step / 60 + ' min') + ' average' + (D.since ? ' \u00b7 nothing was recorded before ' + clock(D.since, true) + ', so the charts start there' : '') : 'no traffic recorded in this period';
  const head = el('tr'); ['link', 'to the hub', 'from the hub', 'peak', 'average ping'].forEach((h, i) => head.append(el('th', h, i ? 'n' : ''))); sum.append(head);
  const rows = D.links.map(l => {
    const a = D.names[l.peer] || '#' + l.peer, b = D.names[l.reporter] || '#' + l.reporter, bps = l.points.map(p => [p[0], p[1] * 8 / D.step, p[2] * 8 / D.step]);
    const rx = l.points.reduce((s, p) => s + p[1], 0), tx = l.points.reduce((s, p) => s + p[2], 0), ms = l.points.filter(p => p[3] != null);
    return {a, b, bps, rx, tx, peak: Math.max(0, ...bps.map(p => Math.max(p[1], p[2]))), ms: ms.length ? ms.reduce((s, p) => s + p[3], 0) / ms.length : null};
  }).sort((x, y) => y.rx + y.tx - x.rx - x.tx);
  for (const r of rows) {
    const tr = el('tr'); tr.append(el('td', r.a + ' \\u21c4 ' + r.b), el('td', size(r.rx), 'n'), el('td', size(r.tx), 'n'), el('td', rate(r.peak), 'n'), el('td', r.ms == null ? '-' : r.ms.toFixed(0) + ' ms', 'n')); sum.append(tr);
    const card = el('div', null, 'chart'), cv = el('canvas'), key = el('p');
    const k1 = el('i', null, 'k'), k2 = el('i', null, 'k'); k1.style.borderColor = css('--s1'); k2.style.borderColor = css('--s2');
    key.append(k1, r.a + ' \\u2192 ' + r.b + ' (' + size(r.rx) + ')', k2, r.b + ' \\u2192 ' + r.a + ' (' + size(r.tx) + ')');
    card.append(el('h3', r.a + ' \\u21c4 ' + r.b), key, cv); box.append(card); charts.push([cv, r]);
  }
  charts.forEach(c => draw(...c));
}

function draw(cv, r, hover) {
  const W = cv.clientWidth, H = 190, k = devicePixelRatio || 1, g = cv.getContext('2d'), L = 62, R = 8, T = 8, B = 22;
  cv.width = W * k; cv.height = H * k; cv.style.height = H + 'px'; g.setTransform(k, 0, 0, k, 0, 0); g.clearRect(0, 0, W, H);
  let top = Math.max(1000, r.peak), mag = Math.pow(10, Math.floor(Math.log10(top))); top = Math.ceil(top / mag) * mag;   // a clean axis maximum
  const mid = T + (H - T - B) / 2, x = t => L + (t - D.from) / (D.to - D.from) * (W - L - R), y = v => mid - v / top * (H - T - B) / 2;
  g.font = '11px system-ui, sans-serif'; g.textBaseline = 'middle'; g.lineWidth = 1;
  for (const v of [top, top / 2, 0, -top / 2, -top]) {            // one axis: up is towards the hub, down is from it
    g.strokeStyle = css('--line'); g.beginPath(); g.moveTo(L, y(v)); g.lineTo(W - R, y(v)); g.stroke();
    g.fillStyle = css('--muted'); g.textAlign = 'right'; g.fillText(rate(v), L - 8, y(v));
  }
  g.textAlign = 'center';
  for (let i = 0; i <= 4; i++) { const t = D.from + (D.to - D.from) * i / 4; g.fillText(clock(t), Math.min(W - R - 22, Math.max(L + 22, x(t))), H - 9); }
  [[1, '--s1', 1], [2, '--s2', -1]].forEach(([col, color, sign]) => {
    let seg = [];
    const flush = () => {
      if (!seg.length) return;
      g.beginPath(); seg.forEach((p, i) => i ? g.lineTo(x(p[0]), y(sign * p[col])) : g.moveTo(x(p[0]), y(sign * p[col])));
      g.strokeStyle = css(color); g.lineWidth = 2; g.lineJoin = g.lineCap = 'round'; g.stroke();
      g.lineTo(x(seg[seg.length - 1][0]), mid); g.lineTo(x(seg[0][0]), mid); g.closePath(); g.globalAlpha = 0.1; g.fillStyle = css(color); g.fill(); g.globalAlpha = 1; seg = [];
    };
    r.bps.forEach((p, i) => { if (i && p[0] - r.bps[i - 1][0] > D.step * 1.5) flush(); seg.push(p); }); flush();   // a gap means nobody was measuring
  });
  if (hover) {
    g.strokeStyle = css('--muted'); g.lineWidth = 1; g.beginPath(); g.moveTo(x(hover[0]), T); g.lineTo(x(hover[0]), H - B); g.stroke();
    [[1, '--s1', 1], [2, '--s2', -1]].forEach(([col, color, sign]) => { g.beginPath(); g.arc(x(hover[0]), y(sign * hover[col]), 4, 0, 7); g.fillStyle = css(color); g.fill(); g.lineWidth = 2; g.strokeStyle = css('--bg'); g.stroke(); });
  }
  cv.onpointermove = e => {
    if (!r.bps.length) return;
    const box = cv.getBoundingClientRect(), t = D.from + (e.clientX - box.left - L) / (W - L - R) * (D.to - D.from);
    const p = r.bps.reduce((a, b) => Math.abs(b[0] - t) < Math.abs(a[0] - t) ? b : a); draw(cv, r, p);
    const tip = $('#tip'); tip.textContent = '';
    const row = (color, value, label) => { const d = el('div'), key = el('i', null, 'k'); key.style.borderColor = css(color); key.style.marginLeft = 0; d.append(key, el('b', value), ' ' + label); return d; };
    tip.append(el('div', clock(p[0], true)), row('--s1', rate(p[1]), r.a + ' \\u2192 ' + r.b), row('--s2', rate(p[2]), r.b + ' \\u2192 ' + r.a));
    tip.style.display = 'block'; tip.style.left = Math.min(innerWidth - tip.offsetWidth - 8, e.clientX + 14) + 'px'; tip.style.top = e.clientY + 14 + 'px';
  };
  cv.onpointerleave = () => { $('#tip').style.display = 'none'; draw(cv, r); };
}
load(); setInterval(() => { if (range.span) load(); }, 60000); addEventListener('resize', () => charts.forEach(c => draw(...c)));
</script>"""


SIGN_SCRIPT = """<script>
// Ed25519 signing in the page: the browser offers no crypto API over plain http, and the key must not leave it.
const big = b => b.reduce((n, x, i) => n + (BigInt(x) << BigInt(8 * i)), 0n);
const bytes = (n, len) => Uint8Array.from({length: len}, (_, i) => Number((n >> BigInt(8 * i)) & 255n));
const cat = (...p) => Uint8Array.from(p.flatMap(x => [...x]));
const M = (1n << 64n) - 1n, rotr = (x, n) => ((x >> n) | (x << (64n - n))) & M;
const root = (n, k) => { let x = 1n << BigInt(Math.ceil(n.toString(2).length / k)); for (;;) { const y = ((BigInt(k) - 1n) * x + n / x ** BigInt(k - 1)) / BigInt(k); if (y >= x) return x; x = y; } };
const primes = []; for (let n = 2; primes.length < 80; n++) if (primes.every(p => n % p)) primes.push(n);
const K = primes.map(p => root(BigInt(p) << 192n, 3) & M), H0 = primes.slice(0, 8).map(p => root(BigInt(p) << 128n, 2) & M);
function sha512(m) {
  const l = m.length, n = Math.ceil((l + 17) / 128) * 128, p = new Uint8Array(n); p.set(m); p[l] = 0x80;
  for (let i = 0; i < 8; i++) p[n - 1 - i] = Number((BigInt(l) * 8n >> BigInt(8 * i)) & 255n);
  let h = H0.slice();
  for (let o = 0; o < n; o += 128) {
    const w = []; for (let i = 0; i < 16; i++) { let v = 0n; for (let j = 0; j < 8; j++) v = (v << 8n) | BigInt(p[o + 8 * i + j]); w.push(v); }
    for (let i = 16; i < 80; i++) { const a = w[i - 15], b = w[i - 2];
      w.push((w[i - 16] + (rotr(a, 1n) ^ rotr(a, 8n) ^ (a >> 7n)) + w[i - 7] + (rotr(b, 19n) ^ rotr(b, 61n) ^ (b >> 6n))) & M); }
    let [a, b, c, d, e, f, g, y] = h;
    for (let i = 0; i < 80; i++) {
      const t1 = (y + (rotr(e, 14n) ^ rotr(e, 18n) ^ rotr(e, 41n)) + ((e & f) ^ (~e & M & g)) + K[i] + w[i]) & M;
      const t2 = ((rotr(a, 28n) ^ rotr(a, 34n) ^ rotr(a, 39n)) + ((a & b) ^ (a & c) ^ (b & c))) & M;
      y = g; g = f; f = e; e = (d + t1) & M; d = c; c = b; b = a; a = (t1 + t2) & M;
    }
    h = [a, b, c, d, e, f, g, y].map((v, i) => (v + h[i]) & M);
  }
  const out = new Uint8Array(64); h.forEach((v, i) => { for (let j = 0; j < 8; j++) out[8 * i + j] = Number((v >> BigInt(56 - 8 * j)) & 255n); }); return out;
}
const P = 2n ** 255n - 19n, L = 2n ** 252n + 27742317777372353535851937790883648493n;
const mod = (a, m = P) => ((a % m) + m) % m;
const pow = (b, e, m = P) => { let r = 1n; b = mod(b, m); while (e > 0n) { if (e & 1n) r = r * b % m; b = b * b % m; e >>= 1n; } return r; };
const inv = a => pow(a, P - 2n), D = mod(-121665n * inv(121666n)), By = mod(4n * inv(5n));
const Bx = (() => { const x2 = mod((By * By - 1n) * inv(D * By * By + 1n)); let x = pow(x2, (P + 3n) / 8n); if (mod(x * x - x2) !== 0n) x = mod(x * pow(2n, (P - 1n) / 4n)); return x & 1n ? P - x : x; })();
const add = ([X1, Y1, Z1, T1], [X2, Y2, Z2, T2]) => { const A = mod((Y1 - X1) * (Y2 - X2)), B = mod((Y1 + X1) * (Y2 + X2)), C = mod(2n * D * T1 * T2), Q = mod(2n * Z1 * Z2), E = B - A, F = Q - C, G = Q + C, H = B + A; return [mod(E * F), mod(G * H), mod(F * G), mod(E * H)]; };
const mul = (k, p) => { let r = [0n, 1n, 1n, 0n]; while (k > 0n) { if (k & 1n) r = add(r, p); p = add(p, p); k >>= 1n; } return r; };
const enc = ([X, Y, Z]) => { const zi = inv(Z); return bytes(mod(Y * zi) | ((mod(X * zi) & 1n) << 255n), 32); };
const BASE = [Bx, By, 1n, mod(Bx * By)];
function sign(msg, seed) {
  const h = sha512(seed), a = (big(h.slice(0, 32)) & ((1n << 254n) - 8n)) | (1n << 254n), pub = enc(mul(a, BASE));
  const r = mod(big(sha512(cat(h.slice(32), msg))), L), R = enc(mul(r, BASE));
  return {pub, sig: cat(R, bytes(mod(r + mod(big(sha512(cat(R, pub, msg))), L) * a, L), 32))};
}
const b64 = b => btoa(String.fromCharCode(...b));
</script>"""


LOGIN_SCRIPT = """<script>
const S = __DATA__, form = document.getElementById('login'), key = document.getElementById('key');
const fail = t => { document.getElementById('why').textContent = t; return false; };
form.onsubmit = e => {
  e.preventDefault();
  let seed = [];
  try { seed = Uint8Array.from(atob(key.value.trim()), c => c.charCodeAt(0)); } catch (x) {}
  if (seed.length !== 32) return fail('that is not an admin key');
  if (Math.abs(Date.now() / 1000 - S.now) > 300) return fail('the clock of this node and yours differ by more than five minutes');
  const minutes = Math.max(1, Math.min(S.max, +form.minutes.value || 30)), nbf = S.now - 60, exp = S.now + minutes * 60;
  const made = sign(new TextEncoder().encode(['meshbone-session', S.mesh, S.admin_pub, S.pub, nbf, exp].join('\\n')), seed);
  if (b64(made.pub) !== S.admin_pub) return fail('this key does not belong to this mesh');
  form.nbf.value = nbf; form.exp.value = exp; form.sig.value = b64(made.sig); key.value = '';
  form.submit();   // only the token goes to the node; the key field has no name and was just emptied
};
</script>"""


def esc(v):
    return html.escape(str(v), quote=True)


def human(n):
    if n is None:
        return "-"
    for unit in ("B", "kB", "MB", "GB"):
        if n < 1000:
            return f"{n:.0f} {unit}" if unit == "B" or n >= 100 else f"{n:.1f} {unit}"
        n /= 1000
    return f"{n:.1f} TB"


def tags(labels):
    return "".join(f"<span class=tag>{esc(l)}</span>" for l in labels) or "-"


def page_head(mesh, title, here):
    tabs = [("/", "map"), ("/traffic", "traffic"), ("/metrics", "metrics"), ("/api", "API")]
    return (
        f"<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>"
        f"<title>{esc(title)} - mesh {esc(mesh['name'])}</title>{PAGE_STYLE}<nav><b>mesh {esc(mesh['name'])}</b>"
        + "".join(f"<b>{t}</b>" if t == here else f"<a href='{u}'>{t}</a>" for u, t in tabs)
        + "</nav>"
    )


def view_map(mesh, topo):
    """The whole mesh at a glance: the graph, the nodes, the links."""
    here = next(n for n in topo["nodes"] if n["me"])
    names = {n["id"]: n["name"] for n in topo["nodes"]}
    out = [
        page_head(mesh, "map", "map").replace("<title>", "<meta http-equiv=refresh content=60><title>"),
        f"<p>nodes <code>{esc(mesh['net'])}</code> &middot; cluster IPs <code>{esc(mesh['cluster_net'])}</code> &middot; "
        f"this page is <code>{store.admin_vip(mesh)}</code> on every hub, answered now by <b>{esc(here['name'])}</b></p>"
        "<canvas id=map></canvas><p class=key><span>large dot: hub</span><span>small dot: client</span>"
        "<span>thick line: hub-to-hub, or the hub a client sends through</span><span>thin line: standby link</span>"
        "<span>faint dashed red: no link</span><span>number: ping across that link</span>"
        "<span>dotted ring: admin node</span><span>bold outline: the node answering</span>"
        "<span>drag a node to move it (remembered here); double-click the map to reset</span></p>",
        "<h2>nodes</h2><div class=scroll><table><tr><th>role<th>name<th>address<th>endpoint<th>subnets"
        "<th>sends through<th>seen by<th>labels<th>description",
    ]
    for n in topo["nodes"]:
        mine = [l for l in topo["links"] if l["a"] == n["id"] or (n["hub"] and l["b"] == n["id"])]
        via = next((names[l["b"]] for l in mine if l["primary"] and l["a"] == n["id"]), "")
        seen_by = ", ".join(sorted(names[l["b"] if l["a"] == n["id"] else l["a"]] for l in mine if l["up"])) or "nobody"
        role = (
            ("hub" if n["hub"] else "client")
            + (" · admin" if n["admin"] else "")
            + (" · simple" if n["simple"] else "")
        )
        role = "transit router" if n["transit"] else role + (" · internet exit" if n["exit"] else "")
        out.append(
            f"<tr><td>{role}<td><b>{esc(n['name'])}</b><td class=m>{n['ip']}<td class=m>{esc(n['endpoint'] or 'behind NAT')}"
            f"<td class=m>{esc(' '.join(n['subnets'] + ['vip ' + v for v in n['vips']]) or '-')}"
            f"<td>{esc(via or ('-' if n['hub'] else 'not connected'))}<td>{esc(seen_by)}<td>{tags(n['labels'])}"
            f"<td>{esc(n['desc'] or '-')}{(' · public ' + esc(n['public'])) if n['public'] else ''}"
        )
    out.append(
        "</table></div><h2>links</h2><div class=scroll><table><tr><th>from<th>to<th>state<th class=n>ping"
        "<th class=n>sent, last hour<th class=n>received, last hour<th>"
    )
    for l in topo["links"]:
        out.append(
            f"<tr><td>{esc(names[l['a']])}<td>{esc(names[l['b']])}<td>{'up' if l['up'] else 'down'}"
            f"<td class=n>{str(l['ms']) + ' ms' if l['ms'] is not None else '-'}"
            f"<td class=n>{human(l['to_hub_1h'])}<td class=n>{human(l['from_hub_1h'])}<td>{'in use' if l['primary'] else ''}"
        )
    admins = " &middot; ".join(
        f"<a href='http://{n['ip']}:{settings.ADMIN_PORT}/admin'>{esc(n['name'])}</a>"
        for n in topo["nodes"]
        if n["admin"]
    )
    out.append(
        "</table></div><p>Sent and received are from the first node's side; <a href=/traffic>graphs over time</a>.</p>"
        f"<h2>manage</h2><p>{admins or 'no admin node is online'}</p>"
        "<p>Changes are signed on an admin node; hubs only show the mesh.</p>"
    )
    out.append(MAP_SCRIPT.replace("__DATA__", json.dumps(topo).replace("</", "<\\/")))
    return "".join(out).encode()


def view_traffic(mesh):
    return (
        page_head(mesh, "traffic", "traffic")
        + "<p>Bytes carried by each link, as counted by the hub at one end. Traffic between two clients shows up on "
        "both of their links to the hub that relayed it.</p><div class=bar id=bar></div><p id=note></p>"
        "<div class=scroll><table id=sum></table></div><div id=charts></div><div id=tip></div>" + TRAFFIC_SCRIPT
    ).encode()


def view_api(mesh):
    base = f"http://{store.admin_vip(mesh)}:{settings.ADMIN_PORT}"
    paths = [
        (
            "/api/nodes",
            "every node: name, role, ip, endpoint, subnets, vips, labels, desc, admin. Filters: <code>?label=X</code> "
            "(repeatable, all must match), <code>?role=hub|client</code>, <code>?name=N</code>",
        ),
        ("/api/topology", "nodes plus every link with state, ping and whether it is in use (what the map draws)"),
        ("/api/policy", "the firewall policy: the default and the ordered rules"),
        ("/api/dns", "the zone, the upstream resolvers and every name the mesh resolver answers"),
        (
            "/api/traffic",
            "per-link byte counts in buckets. <code>?from=UNIX&amp;to=UNIX</code> (default: last 6 h), "
            "<code>&amp;step=SECONDS</code> (default: about 240 points)",
        ),
        (
            "/metrics",
            f"the same in Prometheus text format; also reachable as <code>http://{store.metrics_vip(mesh)}:{settings.ADMIN_PORT}/metrics</code>",
        ),
    ]
    return (
        page_head(mesh, "API", "API")
        + f"<p>Read-only, JSON, no login, reachable only from inside the mesh. Any hub answers on <code>{base}</code>.</p>"
        "<div class=scroll><table><tr><th>path<th>returns"
        + "".join(f"<tr><td class=m><a href='{p}'>{p}</a><td style='white-space:normal'>{d}" for p, d in paths)
        + "</table></div>"
    ).encode()


def view_login(mesh, sid, pub, now, note):
    """Ask for the admin key - and turn it, inside the browser, into a token for this session only."""
    facts = {
        "sid": sid,
        "pub": pub,
        "now": now,
        "mesh": mesh["name"],
        "admin_pub": mesh["admin_pub"],
        "max": settings.SESSION_MAX // 60,
    }
    return (
        page_head(mesh, "manage", "")
        + "<h1>manage</h1><p>Paste the mesh's admin key. It stays in this browser: the page uses it once to sign a token "
        "that lets this node sign changes for a limited time, and only the token is sent.</p>"
        + (f"<pre>{esc(note)}</pre>" if note else "")
        + "<form id=login method=post action=/admin/login class=grid>"
        f'<input type=hidden name=sid value="{esc(sid)}"><input type=hidden name=nbf><input type=hidden name=exp>'
        "<input type=hidden name=sig><input id=key type=password class=w placeholder='admin key' autocomplete=off required> "
        "<label>valid for <input name=minutes value=30 style='width:4em'> minutes</label> "
        "<button>sign in</button></form><p id=why style='color:var(--bad)'></p>"
        "<p>The token only works on this node, from your address, until it expires. Changes made with it are signed by "
        "a key that exists only for this session.</p>"
        + SIGN_SCRIPT
        + LOGIN_SCRIPT.replace("__DATA__", json.dumps(facts).replace("</", "<\\/"))
    ).encode()


def view_metrics(topo, totals):
    """The mesh in Prometheus text format."""
    out, names = [], {n["id"]: n["name"] for n in topo["nodes"]}

    def quoted(v):
        return str(v).replace("\\", "\\\\").replace('"', '\\"')

    def family(name, kind, text, samples):
        out.extend([f"# HELP {name} {text}", f"# TYPE {name} {kind}"])
        for labels, value in samples:  # no backslashes inside f-strings: nodes may run Python older than 3.12
            out.append("%s{%s} %s" % (name, ",".join('%s="%s"' % (k, quoted(v)) for k, v in labels.items()), value))

    family(
        "meshbone_node_info",
        "gauge",
        "One per node in the mesh.",
        [
            (
                {
                    "node": n["name"],
                    "role": "hub" if n["hub"] else "client",
                    "ip": n["ip"],
                    "labels": ",".join(n["labels"]),
                },
                1,
            )
            for n in topo["nodes"]
        ],
    )
    pairs = [({"from": names[l["a"]], "to": names[l["b"]]}, l) for l in topo["links"]]
    family(
        "meshbone_link_up",
        "gauge",
        "1 if the hub at the far end currently sees the node.",
        [(k, int(l["up"])) for k, l in pairs],
    )
    family(
        "meshbone_link_in_use",
        "gauge",
        "1 if the client sends through this hub.",
        [(k, int(l["primary"])) for k, l in pairs],
    )
    family(
        "meshbone_link_ping_ms",
        "gauge",
        "Round-trip time across the link.",
        [(k, l["ms"]) for k, l in pairs if l["ms"] is not None],
    )
    known = [(names[r], names[p], rx, tx) for r, p, rx, tx in totals if r in names and p in names]
    family(
        "meshbone_link_received_bytes_total",
        "counter",
        "Bytes the hub received from the peer.",
        [({"hub": h, "peer": p}, rx) for h, p, rx, tx in known],
    )
    family(
        "meshbone_link_sent_bytes_total",
        "counter",
        "Bytes the hub sent to the peer.",
        [({"hub": h, "peer": p}, tx) for h, p, rx, tx in known],
    )
    return ("\n".join(out) + "\n").encode()


def view_admin(mesh, me, nodes, csrf, note, soft, until, held, origin, pol, dns):
    zone = dns["zone"]
    """The management page: nodes, adding one, software versions, the password."""
    out = [
        page_head(mesh, "manage", ""),
        f"<h1>manage</h1><p>on <b>{esc(me)}</b> &middot; "
        + (
            f"signing with your token for another {max(0, until - int(time.time())) // 60 + 1} min &middot; "
            "<a href=/admin/logout>end the session</a>"
            if until
            else "this node holds the admin key &middot; <a href=/admin/login>use a token instead</a>"
        )
        + f" &middot; also reachable as <code>http://{store.admin_vip(mesh)}:{settings.ADMIN_PORT}/admin</code> on every hub</p>",
    ]
    if note:
        out.append(f"<pre>{esc(note)}</pre>")
    hidden = f"<input type=hidden name=csrf value={csrf}>"
    out.append(
        "<h2>nodes</h2><p>A node with an endpoint is a hub: enter one and it becomes a hub once a client has reached it "
        "there; clear it and it is a client again.</p><div class=scroll><table>"
        "<tr><th>role<th>name<th>address<th>endpoint<th>subnets<th>labels<th>DNS names<th>description<th>public IP<th>cost (ms)<th>"
    )
    for i, r in enumerate(nodes):
        approve = f" <button name=action value=approve>make hub at {esc(r['wants'])}</button>" if r["wants"] else ""
        simple = (
            f" &middot; <a href='/admin/simple?name={urllib.parse.quote(r['name'])}'>QR / config</a>"
            if r.get("simple") and held
            else ""
        )
        out.append(
            f"<tr><td>{r['role']}{simple}<td><b>{esc(r['name'])}</b><td class=m>{r['ip']}"
            f"<td><input form=f{i} name=endpoint value=\"{esc(r['endpoint'])}\" placeholder='host:port'>"
            f"<td><input form=f{i} name=subnets value=\"{esc(' '.join(r['subnets']))}\">"
            f"<td><input form=f{i} name=labels value=\"{esc(' '.join(r.get('labels', [])))}\">"
            f"<td><input form=f{i} name=dns value=\"{esc(' '.join(r.get('dns', [])))}\" placeholder='{esc(r['name'])}.{esc(zone)}'>"
            f"<td><input form=f{i} class=w name=desc value=\"{esc(r.get('desc', ''))}\">"
            f"<td><input form=f{i} name=public value=\"{esc(r.get('public', ''))}\" placeholder='via the exit router'>"
            f"<td><input form=f{i} name=cost value={r['cost']}>"
            f"<td><form id=f{i} method=post>{hidden}<input type=hidden name=name value=\"{esc(r['name'])}\">"
            f"<button name=action value=set>save</button> <button name=action value=revoke>revoke</button>"
            f"{approve}</form>"
        )
    out.append(
        f"</table></div><h2>add a node</h2><form method=post class=grid>{hidden}"
        "<input name=name placeholder=name required> <input name=endpoint placeholder='host:port (hub only)'> "
        "<input name=ip placeholder='address (automatic)'> <input name=subnets placeholder=subnets> "
        "<input name=labels placeholder=labels> <input class=w name=desc placeholder=description> "
        "<input class=w name=remote placeholder='install over ssh: user:password@host' autocomplete=off> "
        "<input class=w name=identity placeholder='private key for that login (optional, used once)' autocomplete=off> "
        "<label><input type=checkbox name=simple value=1 style='width:auto'> simple client (phone, plain WireGuard)</label> "
        "<button name=action value=invite>add</button></form>"
        f"<p>With an ssh destination the node is installed and joined right away. The login starts from <b>{esc(me)}</b> "
        "and can prove itself in three ways: a password in the destination, a private key pasted next to it, or this "
        f"node's own key - add this line to <code>~/.ssh/authorized_keys</code> of the account on the target:</p>"
        f"<pre>{esc(origin or 'this node creates its key the first time it is needed')}</pre><p>Several hops are separated by "
        "<code>;</code>, each with or without a password, and each is reached through the one before it. "
        "Without one you get a config file to carry over (it holds the new node's private key).</p>"
    )
    rel, short = soft["release"], lambda sha: sha[:12] or "-"
    out.append(
        f"<h2>software</h2><p>this node runs <code>{short(soft['running'])}</code> &middot; published for the mesh: "
        + (
            f"<code>{short(rel['sha'])}</code> from {esc(rel.get('source', '?'))}, {esc(rel.get('time', ''))}"
            if rel
            else "nothing yet"
        )
        + "</p><div class=scroll><table><tr><th>node<th>runs<th>last update"
    )
    for n in soft["nodes"]:
        u = n["update"]
        last = (
            "-"
            if not u
            else f"{short(u.get('sha', ''))} "
            + ("installed" if u.get("ok") else "refused, kept the old version: " + str(u.get("why", "")))
        )
        mark = "" if not rel or not n["code"] else " (current)" if rel["sha"].startswith(n["code"]) else " (behind)"
        out.append(
            f"<tr><td><b>{esc(n['name'])}</b><td class=m>{esc(n['code'] or '?')}{mark}<td style='white-space:normal'>{esc(last)}"
        )
    source = rel.get("source", "") if rel else ""
    repo = re.match(r"https://raw\.githubusercontent\.com/([\w.-]+/[\w.-]+)/", source)
    out.append(
        f"</table></div><form method=post class=grid style='margin-top:10px'>{hidden}"
        f"<input class=w name=source placeholder='https://github.com/OWNER/REPO' value=\"{esc('https://github.com/' + repo[1] if repo else '')}\" required> "
        "<input name=ref placeholder='branch, tag or commit (main)'> "
        "<button name=action value=update>fetch, verify here, roll out</button></form>"
        + (
            f"<form method=post style='margin-top:6px'>{hidden}<button name=action value=rollback>roll the mesh back to "
            f"{short(soft['previous'])}</button></form>"
            if soft["previous"]
            else ""
        )
        + "<p>The new version is first installed on this node. Only if this node is still healthy afterwards is it signed and "
        "handed to the others; each of them tests it the same way and keeps its old version if anything goes wrong.</p>"
        "<details><summary>update log of this node</summary><pre>"
        + esc("\n".join(" ".join(f"{k}={v}" for k, v in e.items()) for e in soft["log"]) or "empty")
        + "</pre></details>"
    )
    out.append(
        f"<h2>DNS</h2><p>Every node is <code>&lt;name&gt;.{esc(zone)}</code>, plus the names in its DNS column; a label that is "
        "a valid host name resolves to all nodes carrying it. The resolver is <code>"
        f"{store.dns_vip(mesh)}</code> on every hub (also <code>dns.{esc(zone)}</code>); names outside the zone go to "
        f"{esc(', '.join(dns['upstream']))}.</p><form method=post class=grid>{hidden}"
        f"<input name=zone value=\"{esc(zone)}\"> <input class=w name=upstream value=\"{esc(' '.join(dns['upstream']))}\"> "
        "<button name=action value=dns>save</button></form>"
        "<h2>firewall</h2><p>Who may open connections to whom across the mesh. Rules are tried from the top and the first "
        f"match decides; without a match the default applies, which is <b>{pol['default']}</b>. Answers, ping and the mesh's "
        "own ports always pass.</p><div class=scroll><table><tr><th>#<th>action<th>from<th>to<th>ports<th>"
    )
    for i, r in enumerate(pol["rules"], 1):
        out.append(
            f"<tr><td>{i}<td>{esc(r['action'])}<td class=m>{esc(r['from'])}<td class=m>{esc(r['to'])}"
            f"<td class=m>{esc(r.get('ports') or 'all traffic')}<td><form method=post>{hidden}"
            f"<input type=hidden name=rule value={i}><button name=action value=policy_del>remove</button></form>"
        )
    out.append(
        f"</table></div><form method=post class=grid style='margin-top:10px'>{hidden}"
        "<select name=verdict><option>deny<option>allow</select> from <input name=src placeholder='group' required> "
        "to <input name=dst placeholder='group' required> <input name=ports placeholder='tcp/22,443 udp/53 (all)'> "
        f"<button name=action value=policy_add>add rule</button></form><form method=post class=grid style='margin-top:6px'>{hidden}"
        "otherwise <select name=default><option>allow<option>deny</select> <button name=action value=policy_default>set default"
        "</button></form><p>A group is a label (the nodes carrying it), <code>@name</code>, <code>nodes</code>, "
        "<code>hubs</code>, <code>clients</code>, <code>subnets</code> (every announced network), <code>LABEL+net</code> "
        "(the networks behind those nodes), <code>any</code>, or an address. Example: deny from <code>subnets</code> to "
        "<code>nodes</code> lets the mesh reach into the subnets but not the other way round.</p>"
    )
    if not held:
        return "".join(out).encode()
    out.append(
        f"<h2>password</h2><form method=post class=grid>{hidden}"
        "<input type=password name=new1 placeholder='new password' required minlength=8 autocomplete=new-password> "
        "<input type=password name=new2 placeholder='again' required autocomplete=new-password> "
        "<button name=action value=passwd>change</button></form>"
        "<p>Applies to this page on every admin node. Your browser will ask for it again.</p>"
    )
    return "".join(out).encode()


def view_simple(mesh, name, hub, hubs, text, code, stored):
    """One simple client: its QR code and config."""
    link = "/admin/simple?name=" + urllib.parse.quote(name)
    code = (
        code[code.index("<svg") :]
        if code and "<svg" in code
        else "<p>No QR code: qrencode is not installed on this node.</p>"
    )
    others = " &middot; ".join(
        f"<b>{esc(h)}</b>" if h == hub or not stored else f"<a href='{link}&hub={urllib.parse.quote(h)}'>{esc(h)}</a>"
        for h in hubs
    )
    download = "data:text/plain;base64," + base64.b64encode(text.encode()).decode()
    return (
        page_head(mesh, name, "")
        + f"<h1>{esc(name)}</h1><p>A plain WireGuard client. Scan this with the WireGuard app, "
        f'or <a download="{esc(name)}.conf" href="{download}">download {esc(name)}.conf</a>. <a href=/admin>back</a></p>'
        f"<p>connects through: {others}</p>"
        f"<div style='background:#fff;display:inline-block;padding:10px;border-radius:8px;margin:12px 0;width:min(320px,90vw)'>{code}</div>"
        + (
            ""
            if stored
            else "<p><b>Save it now.</b> This node does not keep the device's key, so this page cannot be shown again.</p>"
        )
        + "<p>Plain WireGuard uses one hub and cannot switch by itself: if that hub is down, export the config again through "
        "another one. The config lists the networks known now; export it again after adding subnets or hubs.</p>"
        f"<details><summary>show the config (contains the private key)</summary><pre>{esc(text)}</pre></details>"
    ).encode()


def view_transit(name, transit, gateway, mesh, text):
    """What the router's operator needs: the plain WireGuard config, and the same as VyOS commands."""
    wg = "wg1"
    priv = next(l.split(" = ")[1] for l in text.splitlines() if l.startswith("PrivateKey"))
    psk = next(l.split(" = ")[1] for l in text.splitlines() if l.startswith("PresharedKey"))
    host, _, port = gateway["endpoint"].rpartition(":")
    lines = [
        f"{name}: transit router linked to hub {gateway['name']}, delivering {', '.join(transit['public_nets'])}",
        "",
        "WireGuard config for the router (any WireGuard; the router needs no other knowledge of the mesh):",
        "",
        text.rstrip(),
        "",
        f"The same as VyOS commands (interface {wg}; adjust the name and the endpoint's port if taken):",
        "",
        f"set interfaces wireguard {wg} description 'meshbone {mesh['name']}'",
        f"set interfaces wireguard {wg} address {store.router_ip(mesh, transit['id'])}/32",
        f"set interfaces wireguard {wg} port {transit['transit'].rpartition(':')[2]}",
        f"set interfaces wireguard {wg} private-key {priv}",
        f"set interfaces wireguard {wg} mtu 1420",
        f"set interfaces wireguard {wg} peer {gateway['name']} public-key {gateway['pk']}",
        f"set interfaces wireguard {wg} peer {gateway['name']} preshared-key {psk}",
        f"set interfaces wireguard {wg} peer {gateway['name']} address {host} ",
        f"set interfaces wireguard {wg} peer {gateway['name']} port {port}",
        f"set interfaces wireguard {wg} peer {gateway['name']} allowed-ips {store.router_ip(mesh, gateway['id'])}/32",
    ]
    lines += [f"set interfaces wireguard {wg} peer {gateway['name']} allowed-ips {p}" for p in transit["public_nets"]]
    lines += [f"set interfaces wireguard {wg} peer {gateway['name']} persistent-keepalive 25"]
    lines += [f"set protocols static route {p} interface {wg}" for p in transit["public_nets"]]
    lines += [
        "",
        "Everything else happens on the hub: public addresses are mapped 1:1 onto nodes there, and the nodes'",
        "internet traffic leaves through the router. Assign addresses with `meshbone set NODE --public IP`.",
    ]
    return "\n".join(lines)


def view_status(mesh, nodes, notes, once, is_admin, version):
    """`meshbone status` as text."""
    lines = [
        f"mesh {mesh['name']} {mesh['net']}, cluster {mesh['cluster_net']} (map http://{store.admin_vip(mesh)}:{settings.ADMIN_PORT}/ "
        f"on every hub){' (--once)' if once else ''}{', admin node' if is_admin else ''}, version {version[:12] or '?'}"
    ]
    for r in nodes:
        lines.append(
            f"{r['role']:<6} {r['name']:<16} {r['ip']:<15} {r['endpoint'] or '(nat)':<24} "
            f"{r['link']:<40} {' '.join(r['subnets'] + r['vips'])}"
            + (f"  cost {r['eff']}" if r["eff"] else "")
            + "".join(f" [{l}]" for l in r.get("labels", []))
            + (f"  # {r['desc']}" if r.get("desc") else "")
            + (f"  [asks to be a hub at {r['wants']}]" if r["wants"] else "")
        )
    return "\n".join(lines + ["warning: " + w for w in notes])


def view_policy(pol):
    """The policy as text, for the terminal."""
    lines = [f"default: {pol['default']} (for new connections no rule matches)"]
    for i, r in enumerate(pol["rules"], 1):
        lines.append(
            f"{i:>3}  {r['action']:<5} from {r['from']:<18} to {r['to']:<18} {r.get('ports') or 'all traffic'}"
        )
    return "\n".join(lines + ["always allowed: answers, ping, and the mesh's own ports between nodes"])


def view_dns(settings, records):
    lines = [f"zone {settings['zone']}, other names go to {' then '.join(settings['upstream'])}"]
    for name, values in sorted(records.items()):
        if not name.endswith(".in-addr.arpa"):
            lines.append(f"  {name:<40} {', '.join(str(v) for v in values)}")
    return "\n".join(lines)
