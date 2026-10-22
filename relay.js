#!/usr/bin/env node
/**
 * IPServer Remote — in-memory MJPEG relay.
 * Device  : GET /device/ws?id=XXXXXXXX   (WebSocket, binary JPEG frames)
 * Viewer  : GET /watch/XXXXXXXX          (HTML)
 *           GET /watch/XXXXXXXX/ws       (WebSocket)
 * Health  : GET /health
 *
 * Frames live in RAM only. Nothing is logged or written to disk.
 */
'use strict';

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer, WebSocket } = require('ws');
const { URL } = require('url');

const PORT = parseInt(process.env.PORT || '8080', 10);
const MAX_DEVICES = parseInt(process.env.MAX_DEVICES || '500', 10);
const MAX_VIEWERS = parseInt(process.env.MAX_VIEWERS || '8', 10);
const MAX_FRAME = parseInt(process.env.MAX_FRAME_BYTES || String(1024 * 1024), 10);
const DEVICE_IDLE_MS = parseInt(process.env.DEVICE_IDLE_MS || '90000', 10);
const VIEW_PASSWORD = process.env.VIEW_PASSWORD || '25262728';
const ID_RE = /^[0-9A-Za-z]{8}$/;

/** @typedef {{ ws: import('ws').WebSocket, pinHash: string|null, name: string, viewers: Set<import('ws').WebSocket>, lastFrame: Buffer|null, lastSeen: number, authed: Set<import('ws').WebSocket> }} Device */

/** @type {Map<string, Device>} */
const devices = new Map();

/** ip -> { t, n } */
const hits = new Map();

function log(...a) {
  const ts = new Date().toISOString();
  console.log(ts, ...a);
}

function clientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || '0.0.0.0';
}

function rateLimit(ip, maxPerMin) {
  const now = Date.now();
  let h = hits.get(ip);
  if (!h || now - h.t > 60000) {
    h = { t: now, n: 0 };
    hits.set(ip, h);
  }
  h.n++;
  return h.n <= maxPerMin;
}

function sha256(s) {
  return crypto.createHash('sha256').update(String(s), 'utf8').digest('hex');
}

function sendJson(ws, obj) {
  if (ws.readyState === WebSocket.OPEN) {
    try { ws.send(JSON.stringify(obj)); } catch (_) {}
  }
}

function htmlPage(id) {
  const safe = String(id).replace(/[^0-9A-Za-z]/g, '');
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<meta name="theme-color" content="#0a0a0a"/>
<title>IPServer Remote</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#0a0a0a;color:#eee;font-family:system-ui,-apple-system,Segoe UI,sans-serif;min-height:100%}
body{padding:16px}
header{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px}
h1{font-size:20px}
.sub{color:#9e9e9e;font-size:13px}
.dot{width:10px;height:10px;border-radius:50%;background:#ff1744;display:inline-block;margin-inline-end:8px}
.dot.on{background:#00c853;box-shadow:0 0 8px #00c853;animation:pulse 1.4s infinite}
@keyframes pulse{0%{opacity:1}50%{opacity:.45}100%{opacity:1}}
.stage{background:#1a1a2e;border-radius:16px;overflow:hidden;position:relative}
img#v{display:block;width:100%;max-height:70vh;object-fit:contain;background:#000;min-height:180px}
.bar{display:flex;gap:8px;align-items:center;padding:10px 12px;font-size:13px;color:#9e9e9e}
.bar b{color:#eee}
.sp{flex:1}
button{background:#1e88e5;color:#fff;border:0;border-radius:22px;padding:8px 14px;font-size:13px;cursor:pointer}
button.ghost{background:#263238}
.note{margin-top:12px;color:#ffd54f;font-size:12px}
.btns{display:flex;gap:10px;margin-bottom:14px}
.btns button{flex:1;border:0;border-radius:28px;padding:14px 12px;font-size:16px;font-weight:700;cursor:pointer;color:#fff}
#btn_on{background:#00c853}
#btn_off{background:#ff1744}
.btns button:disabled{opacity:.35;cursor:default}
.qbox{margin:0 0 16px;padding:12px;background:#10232a;border:2px solid #00bcd4;border-radius:16px}
.qbox .qlabel{text-align:center;color:#80deea;font-weight:800;font-size:15px;margin-bottom:10px}
.qs{display:flex;gap:8px}
.qs button{flex:1;border:0;border-radius:14px;padding:12px 6px;font-size:14px;font-weight:800;background:#263238;color:#eee;cursor:pointer;line-height:1.25}
.qs button small{display:block;font-weight:600;font-size:11px;opacity:.85;margin-top:2px}
.qs button.on{background:#00bcd4;color:#00363a}
.pin{margin:24px auto;max-width:280px;background:#1a1a2e;padding:20px;border-radius:16px;text-align:center}
.pin input{width:100%;margin:12px 0;padding:10px;font-size:22px;text-align:center;border-radius:10px;border:1px solid #2a2a4a;background:#12122a;color:#eee;letter-spacing:4px}
.pin button{width:100%;border:0;border-radius:28px;padding:14px;font-size:16px;font-weight:700;background:#00c853;color:#fff;cursor:pointer}
.pin .sub{margin-bottom:8px}
.pin .err{color:#ff5252;font-size:13px;min-height:18px;margin-bottom:8px}
.wait{padding:40px 16px;text-align:center;color:#9e9e9e}
</style>
</head>
<body>
<div id="gate" class="pin">
  <div class="sub">أدخل كلمة السر للمتابعة</div>
  <div class="err" id="gerr"></div>
  <input id="gpw" type="password" inputmode="numeric" maxlength="16" autocomplete="off" autofocus/>
  <button type="button" id="gbtn">دخول</button>
</div>
<div id="main" style="display:none">
<header>
  <div>
    <h1>IPServer Remote</h1>
    <div class="sub">سرفريو اي بي · ${safe}</div>
  </div>
  <div><span id="dot" class="dot"></span><span id="st">الكاميرا مطفأة</span></div>
</header>
<div class="btns">
  <button id="btn_on" type="button">تشغيل الكاميرا</button>
  <button id="btn_off" type="button" disabled>إيقاف الكاميرا</button>
</div>
<div class="qbox">
  <div class="qlabel">الجودة</div>
  <div class="qs">
    <button type="button" data-q="low">منخفضة<small>360p</small></button>
    <button type="button" data-q="medium" class="on">متوسطة<small>720p</small></button>
    <button type="button" data-q="high">عالية<small>1080p</small></button>
  </div>
</div>
<div class="stage" id="stage">
  <div class="wait" id="wait">اضغط تشغيل الكاميرا</div>
  <img id="v" alt="stream" style="display:none"/>
  <div class="bar">
    <span>FPS <b id="fps">0</b></span>
    <span class="sp"></span>
    <button id="fs">ملء الشاشة</button>
  </div>
</div>
</div>
<script>
(function(){
  var ID=${JSON.stringify(safe)};
  var PASS=${JSON.stringify(VIEW_PASSWORD)};
  var img, fpsEl, dot, st, wait, btnOn, btnOff;
  var frames=0, last=Date.now(), ws, live=false, unlocked=false, pw='', qlevel='medium';
  function setButtons(){ if(!btnOn) return; btnOn.disabled=live; btnOff.disabled=!live; }
  function setOn(on, msg){
    if(!dot) return;
    dot.className=on?'dot on':'dot';
    st.textContent=msg || (on?'مباشر':'الكاميرا مطفأة');
  }
  function wsUrl(){
    var proto=location.protocol==='https:'?'wss:':'ws:';
    return proto+'//'+location.host+'/watch/'+ID+'/ws';
  }
  function showFrame(buf){
    wait.style.display='none';
    img.style.display='block';
    var blob=new Blob([buf],{type:'image/jpeg'});
    var url=URL.createObjectURL(blob);
    var prev=img.src;
    img.src=url;
    if(prev && prev.indexOf('blob:')===0) URL.revokeObjectURL(prev);
    frames++;
    setOn(true);
  }
  function connect(){
    try{ if(ws) ws.close(); }catch(e){}
    ws=new WebSocket(wsUrl());
    ws.binaryType='arraybuffer';
    ws.onopen=function(){
      setOn(false,'متصل بالسرفر…');
      ws.send(JSON.stringify({type:'auth',password:pw}));
      ws.send(JSON.stringify({type:'quality',q:qlevel}));
    };
    ws.onmessage=function(e){
      if(typeof e.data==='string'){
        try{
          var j=JSON.parse(e.data);
          if(j.type==='need_password'){
            setOn(false,'أدخل كلمة السر');
          } else if(j.type==='auth_ok'){
            setOn(false,'بانتظار الصورة…');
          } else if(j.type==='auth_fail'){
            setOn(false,'كلمة السر غير صحيحة');
            stopCam();
            document.getElementById('gate').style.display='block';
            document.getElementById('main').style.display='none';
            document.getElementById('gerr').textContent='كلمة السر غير صحيحة';
          } else if(j.type==='waiting'){
            wait.style.display='block'; img.style.display='none';
            setOn(false,'بانتظار الجهاز…');
          } else if(j.type==='error'){
            setOn(false, j.message||'خطأ');
          }
        }catch(_){}
        return;
      }
      showFrame(e.data);
    };
    ws.onclose=function(){
      setOn(false, live?'إعادة الاتصال…':'الكاميرا مطفأة');
      if(live) setTimeout(function(){ if(live) connect(); }, 1500);
    };
    ws.onerror=function(){ try{ws.close();}catch(_){} };
  }
  function startCam(){
    if(live) return;
    live=true;
    setButtons();
    wait.textContent='جاري التشغيل…';
    wait.style.display='block';
    img.style.display='none';
    setOn(false,'جاري التشغيل…');
    connect();
  }
  function stopCam(){
    live=false;
    setButtons();
    try{ if(ws) ws.close(); }catch(e){}
    ws=null;
    if(wait) wait.textContent='اضغط تشغيل الكاميرا';
    if(wait) wait.style.display='block';
    if(img){ img.style.display='none';
      var prev=img.src;
      try{ img.removeAttribute('src'); }catch(e){}
      if(prev && prev.indexOf('blob:')===0){ try{ URL.revokeObjectURL(prev); }catch(e){} }
    }
    setOn(false);
  }
  function unlock(){
    pw=(document.getElementById('gpw').value||'').trim();
    if(pw!==PASS){
      document.getElementById('gerr').textContent='كلمة السر غير صحيحة';
      return;
    }
    unlocked=true;
    document.getElementById('gate').style.display='none';
    document.getElementById('main').style.display='block';
    img=document.getElementById('v');
    fpsEl=document.getElementById('fps');
    dot=document.getElementById('dot');
    st=document.getElementById('st');
    wait=document.getElementById('wait');
    btnOn=document.getElementById('btn_on');
    btnOff=document.getElementById('btn_off');
    btnOn.onclick=startCam;
    btnOff.onclick=stopCam;
    var qb=document.querySelectorAll('[data-q]');
    function markQ(lv){
      qlevel=lv;
      for(var i=0;i<qb.length;i++) qb[i].className=qb[i].getAttribute('data-q')===lv?'on':'';
      if(ws && ws.readyState===1) try{ ws.send(JSON.stringify({type:'quality',q:lv})); }catch(e){}
    }
    for(var i=0;i<qb.length;i++) (function(btn){
      btn.onclick=function(){ markQ(btn.getAttribute('data-q')); };
    })(qb[i]);
    document.getElementById('fs').onclick=function(){
      var el=img;
      if(el.requestFullscreen) el.requestFullscreen();
      else if(el.webkitRequestFullscreen) el.webkitRequestFullscreen();
    };
    setButtons();
  }
  document.getElementById('gbtn').onclick=unlock;
  document.getElementById('gpw').addEventListener('keydown', function(e){
    if(e.key==='Enter') unlock();
  });
  window.addEventListener('pagehide', stopCam);
  setInterval(function(){
    var n=Date.now(), dt=(n-last)/1000;
    if(dt>=1){ if(fpsEl) fpsEl.textContent=Math.round(frames/dt); frames=0; last=n; }
  },1000);
})();
</script>
</body>
</html>`;
}

function openAppPage() {
  return `<!DOCTYPE html>
<html lang="ar" dir="rtl">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover"/>
<meta name="theme-color" content="#0a0a0a"/>
<title>دخول</title>
<style>
*{box-sizing:border-box;margin:0;padding:0}
html,body{background:#0a0a0a;color:#eee;font-family:system-ui,-apple-system,Segoe UI,sans-serif;min-height:100%}
body{display:flex;align-items:center;justify-content:center;padding:24px;min-height:100vh}
.card{width:100%;max-width:340px;background:#1a1a2e;border-radius:18px;padding:28px 22px;text-align:center}
.sub{color:#9e9e9e;font-size:14px;margin-bottom:22px;line-height:1.7}
a.btn{display:block;width:100%;border-radius:28px;padding:16px;font-size:18px;font-weight:800;background:#00c853;color:#fff;text-decoration:none}
.hint{margin-top:16px;color:#80deea;font-size:12px;line-height:1.5}
</style>
</head>
<body>
<div class="card">
  <div class="sub">كروم لا يفتح التطبيق من شريط البحث. اضغط الزر الأخضر في هذه الصفحة.</div>
  <a class="btn" id="go" href="intent://open#Intent;scheme=mofer;package=com.ipserver.remote;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;end">دخول التطبيق</a>
  <div class="hint">بعدها أدخل كلمة السر داخل التطبيق</div>
</div>
<script>
(function(){
  var u='intent://open#Intent;scheme=mofer;package=com.ipserver.remote;action=android.intent.action.VIEW;category=android.intent.category.BROWSABLE;end';
  try { window.location.replace(u); } catch(e) {}
  setTimeout(function(){ try { window.location.href=u; } catch(e) {} }, 400);
})();
</script>
</body>
</html>`;
}

function assetLinks() {
  return JSON.stringify([{
    relation: ['delegate_permission/common.handle_all_urls'],
    target: {
      namespace: 'android_app',
      package_name: 'com.ipserver.remote',
      sha256_cert_fingerprints: [
        'EA:E0:62:43:9E:97:99:6B:FF:E0:3A:0D:30:F7:C8:2D:46:85:34:59:6C:36:D6:E7:0A:05:3A:EB:70:6E:DB:DB'
      ]
    }
  }]);
}

function landingPage() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>IPServer Remote Relay</title>
<style>
body{font-family:system-ui,sans-serif;background:#0a0a0a;color:#eee;max-width:720px;margin:40px auto;padding:0 16px;line-height:1.5}
code{background:#1a1a2e;padding:2px 6px;border-radius:4px}
a{color:#4fc3f7}
h1{color:#00c853}
</style>
</head>
<body>
<h1>IPServer Remote Relay</h1>
<p>This is a private MJPEG relay. Point the Android app at this URL in Settings.</p>
<ul>
<li>Device WebSocket: <code>/device/ws?id=XXXXXXXX</code></li>
<li>Viewer page: <code>/watch/XXXXXXXX</code></li>
<li>Health: <a href="/health">/health</a></li>
</ul>
<p>Frames pass through memory only. They are not stored. Use an unguessable 8-character device ID and an optional PIN.</p>
</body>
</html>`;
}

function write(res, code, type, body, extra) {
  const buf = Buffer.isBuffer(body) ? body : Buffer.from(String(body), 'utf8');
  const headers = Object.assign({
    'Content-Type': type,
    'Content-Length': buf.length,
    'Cache-Control': 'no-store',
    'X-Content-Type-Options': 'nosniff',
  }, extra || {});
  res.writeHead(code, headers);
  res.end(buf);
}

const server = http.createServer((req, res) => {
  const ip = clientIp(req);
  if (!rateLimit(ip, 180)) {
    write(res, 429, 'text/plain; charset=utf-8', 'rate limit');
    return;
  }
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (_) {
    write(res, 400, 'text/plain', 'bad url');
    return;
  }
  const path = u.pathname;

  if (path === '/health' || path === '/healthz') {
    write(res, 200, 'text/plain; charset=utf-8', 'OK');
    return;
  }
  if (path === '/' || path === '/index.html') {
    write(res, 200, 'text/html; charset=utf-8', landingPage());
    return;
  }
  if (path === '/app' || path === '/open') {
    write(res, 200, 'text/html; charset=utf-8', openAppPage());
    return;
  }
  if (path === '/.well-known/assetlinks.json') {
    write(res, 200, 'application/json; charset=utf-8', assetLinks());
    return;
  }
  const m = path.match(/^\/watch\/([0-9A-Za-z]{8})\/?$/);
  if (m) {
    write(res, 200, 'text/html; charset=utf-8', htmlPage(m[1]));
    return;
  }

  if (req.method === 'GET' && (path === '/device/viewers' || path === '/device/wait-viewers')) {
    const id = u.searchParams.get('id') || '';
    if (!ID_RE.test(id)) {
      write(res, 400, 'text/plain; charset=utf-8', 'bad id');
      return;
    }
    const dev = devices.get(id);
    if (!dev) {
      write(res, 200, 'application/json; charset=utf-8', '{"ok":true,"viewers":0}');
      return;
    }
    dev.lastSeen = Date.now();
    const n = viewerCount(dev);
    if (path === '/device/viewers' || n > 0) {
      write(res, 200, 'application/json; charset=utf-8', jsonViewers(dev));
      return;
    }
    let done = false;
    const finish = (count) => {
      if (done || res.writableEnded) return;
      done = true;
      write(res, 200, 'application/json; charset=utf-8', jsonViewers(dev));
    };
    const t = setTimeout(() => finish(viewerCount(dev)), 25000);
    if (!dev.viewerWaiters) dev.viewerWaiters = [];
    const waiter = (count) => {
      clearTimeout(t);
      finish(count);
    };
    dev.viewerWaiters.push(waiter);
    req.on('close', () => {
      clearTimeout(t);
      if (dev.viewerWaiters) {
        const i = dev.viewerWaiters.indexOf(waiter);
        if (i >= 0) dev.viewerWaiters.splice(i, 1);
      }
    });
    return;
  }

  // HTTP fallback for Android devices that cannot complete a WebSocket upgrade.
  if (req.method === 'POST' && (path === '/device/hello' || path === '/device/frame' || path === '/device/push')) {
    const id = u.searchParams.get('id') || '';
    if (!ID_RE.test(id)) {
      write(res, 400, 'text/plain; charset=utf-8', 'bad id');
      return;
    }
    const max = path === '/device/hello' ? 4096 : MAX_FRAME;
    readBody(req, max).then((buf) => {
      const dev = ensureDevice(id);
      if (!dev) {
        write(res, 503, 'text/plain; charset=utf-8', 'busy');
        return;
      }
      if (path === '/device/hello') {
        try { applyHello(dev, JSON.parse(buf.toString('utf8'))); } catch (_) {}
        dev.lastSeen = Date.now();
        log('device hello http', id, dev.name || '', ip);
        write(res, 200, 'application/json; charset=utf-8', jsonViewers(dev));
        return;
      }
      if (buf.length >= 20) broadcastJpeg(dev, buf);
      write(res, 200, 'application/json; charset=utf-8', jsonViewers(dev));
    }).catch((err) => {
      log('http device error', id, err && err.message);
      try { write(res, 400, 'text/plain; charset=utf-8', 'bad body'); } catch (_) {}
    });
    return;
  }

  write(res, 404, 'text/plain; charset=utf-8', 'not found');
});

const wss = new WebSocketServer({ noServer: true, maxPayload: MAX_FRAME + 1024 });

server.on('upgrade', (req, socket, head) => {
  const ip = clientIp(req);
  if (!rateLimit(ip, 240)) {
    socket.write('HTTP/1.1 429 Too Many Requests\r\nConnection: close\r\n\r\n');
    socket.destroy();
    return;
  }
  let u;
  try { u = new URL(req.url, 'http://localhost'); } catch (_) {
    socket.destroy();
    return;
  }
  const path = u.pathname;

  if (path === '/device/ws') {
    const id = u.searchParams.get('id') || '';
    if (!ID_RE.test(id)) {
      socket.write('HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n');
      socket.destroy();
      return;
    }
    wss.handleUpgrade(req, socket, head, (ws) => onDevice(ws, id, ip));
    return;
  }

  const vm = path.match(/^\/watch\/([0-9A-Za-z]{8})\/ws$/);
  if (vm) {
    wss.handleUpgrade(req, socket, head, (ws) => onViewer(ws, vm[1], ip));
    return;
  }

  socket.write('HTTP/1.1 404 Not Found\r\nConnection: close\r\n\r\n');
  socket.destroy();
});

function readBody(req, max) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on('data', (c) => {
      n += c.length;
      if (n > max) {
        req.destroy();
        reject(new Error('too big'));
        return;
      }
      chunks.push(c);
    });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

function ensureDevice(id) {
  let dev = devices.get(id);
  if (dev) return dev;
  if (devices.size >= MAX_DEVICES) return null;
  dev = {
    ws: null,
    pinHash: null,
    name: '',
    viewers: new Set(),
    lastFrame: null,
    lastSeen: Date.now(),
    authed: new Set(),
    viewerWaiters: [],
    quality: 'medium',
  };
  devices.set(id, dev);
  return dev;
}

function applyHello(dev, j) {
  if (!j || typeof j !== 'object') return;
  if (typeof j.name === 'string') dev.name = j.name.slice(0, 80);
  if (typeof j.pinHash === 'string' && /^[0-9a-f]{64}$/i.test(j.pinHash)) {
    dev.pinHash = j.pinHash.toLowerCase();
  } else if (j.type === 'hello') {
    dev.pinHash = null;
  }
}

function viewerCount(dev) {
  return dev && dev.viewers ? dev.viewers.size : 0;
}

function jsonViewers(dev) {
  return JSON.stringify({
    ok: true,
    viewers: viewerCount(dev),
    quality: (dev && dev.quality) ? dev.quality : 'medium',
  });
}

function applyQuality(dev, q) {
  if (!dev) return;
  if (q !== 'low' && q !== 'medium' && q !== 'high') return;
  dev.quality = q;
  if (dev.ws && dev.ws.readyState === WebSocket.OPEN) {
    sendJson(dev.ws, { type: 'quality', q: q });
  }
}

function wakeViewers(dev) {
  if (!dev) return;
  const n = viewerCount(dev);
  if (dev.ws && dev.ws.readyState === WebSocket.OPEN) {
    sendJson(dev.ws, { type: 'viewers', count: n });
  }
  const waiters = dev.viewerWaiters || [];
  dev.viewerWaiters = [];
  for (const fn of waiters) {
    try { fn(n); } catch (_) {}
  }
}

function broadcastJpeg(dev, buf) {
  if (!dev || !buf || buf.length < 20 || buf.length > MAX_FRAME) return;
  dev.lastFrame = buf;
  dev.lastSeen = Date.now();
  for (const v of dev.viewers) {
    if (v.readyState !== WebSocket.OPEN) continue;
    if (dev.pinHash && !dev.authed.has(v)) continue;
    if (v.bufferedAmount > 2 * buf.length) continue;
    try { v.send(buf, { binary: true }); } catch (_) {}
  }
}

function onDevice(ws, id, ip) {
  if (devices.size >= MAX_DEVICES && !devices.has(id)) {
    sendJson(ws, { type: 'error', message: 'too_many_devices' });
    ws.close(1013, 'busy');
    return;
  }
  const prev = devices.get(id);
  if (prev && prev.ws && prev.ws !== ws) {
    try { prev.ws.close(4000, 'replaced'); } catch (_) {}
  }
  const dev = ensureDevice(id);
  if (!dev) {
    sendJson(ws, { type: 'error', message: 'too_many_devices' });
    ws.close(1013, 'busy');
    return;
  }
  dev.ws = ws;
  dev.lastSeen = Date.now();
  log('device connect', id, ip);

  ws.on('message', (data, isBinary) => {
    dev.lastSeen = Date.now();
    if (!isBinary) {
      try {
        const j = JSON.parse(data.toString());
        if (j && j.type === 'hello') {
          applyHello(dev, j);
          log('device hello', id, dev.name, dev.pinHash ? 'pin' : 'open');
        }
      } catch (_) {}
      return;
    }
    const buf = Buffer.isBuffer(data) ? data : Buffer.from(data);
    broadcastJpeg(dev, buf);
  });

  ws.on('close', () => {
    if (dev.ws === ws) dev.ws = null;
    log('device disconnect', id);
  });
  ws.on('error', () => {});
  ws.on('ping', () => { dev.lastSeen = Date.now(); });
  ws.on('pong', () => { dev.lastSeen = Date.now(); });
  sendJson(ws, { type: 'ok' });
  sendJson(ws, { type: 'viewers', count: viewerCount(dev) });
  if (dev.quality) sendJson(ws, { type: 'quality', q: dev.quality });
}

function onViewer(ws, id, ip) {
  log('viewer', id, ip);
  const attach = () => devices.get(id);
  let unlocked = false;

  sendJson(ws, { type: 'need_password' });

  ws.on('message', (data, isBinary) => {
    if (isBinary) return;
    let j;
    try { j = JSON.parse(data.toString()); } catch (_) { return; }
    if (!j) return;
    if (j.type === 'quality') {
      if (!unlocked) return;
      const dev = attach();
      applyQuality(dev, String(j.q || j.quality || ''));
      return;
    }
    if (j.type !== 'auth' && j.type !== 'password') return;
    const pass = String(j.password || j.pin || '');
    if (pass === VIEW_PASSWORD) {
      unlocked = true;
      sendJson(ws, { type: 'auth_ok' });
      tryJoin();
    } else {
      sendJson(ws, { type: 'auth_fail' });
    }
  });

  const tryJoin = () => {
    if (!unlocked) return;
    const dev = attach();
    if (!dev) {
      sendJson(ws, { type: 'waiting' });
      return;
    }
    if (dev.viewers.size >= MAX_VIEWERS && !dev.viewers.has(ws)) {
      sendJson(ws, { type: 'error', message: 'too_many_viewers' });
      ws.close(1013, 'busy');
      return;
    }
    const wasNew = !dev.viewers.has(ws);
    dev.viewers.add(ws);
    dev.authed.add(ws);
    if (wasNew) wakeViewers(dev);
    sendJson(ws, { type: 'auth_ok' });
    if (dev.lastFrame && ws.readyState === WebSocket.OPEN) {
      try { ws.send(dev.lastFrame, { binary: true }); } catch (_) {}
    }
  };

  const iv = setInterval(() => {
    if (ws.readyState !== WebSocket.OPEN) {
      clearInterval(iv);
      return;
    }
    const dev = attach();
    if (unlocked && dev && !dev.viewers.has(ws)) tryJoin();
  }, 1500);

  const cleanup = () => {
    clearInterval(iv);
    const dev = attach();
    if (dev) {
      const had = dev.viewers.delete(ws);
      dev.authed.delete(ws);
      if (had) wakeViewers(dev);
    }
  };
  ws.on('close', cleanup);
  ws.on('error', cleanup);
}

setInterval(() => {
  const now = Date.now();
  for (const [id, dev] of devices) {
    if (now - dev.lastSeen > DEVICE_IDLE_MS) {
      log('device idle kick', id);
      try { if (dev.ws) dev.ws.close(4001, 'idle'); } catch (_) {}
      devices.delete(id);
      for (const v of dev.viewers) {
        try { sendJson(v, { type: 'waiting' }); } catch (_) {}
      }
    }
  }
  if (hits.size > 5000) hits.clear();
}, 15000);

server.listen(PORT, '0.0.0.0', () => {
  log('IPServer Remote relay listening on', PORT);
});
