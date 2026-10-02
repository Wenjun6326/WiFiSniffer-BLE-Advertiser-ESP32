// Dashboard page served from the access point at http://192.168.4.1/
//
// Kept in its own header rather than inline in the .ino: the page is a large
// raw string literal full of JavaScript template syntax, and having it here
// keeps the firmware source readable and lets the page be edited without
// touching the capture logic.
//
// A plain `const char[]`.  On the ESP32 const data already lives in
// flash-mapped memory, so PROGMEM buys nothing, and in this position the
// placement form `static const char X[] PROGMEM = ...` is not valid syntax.
#pragma once

static const char PAGE_HTML[] = R"xPAGEx(<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Test_1101 monitor</title><style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
header{padding:14px 16px;background:#171a21;border-bottom:1px solid #262b36;position:sticky;top:0;z-index:9}
h1{margin:0;font-size:17px;font-weight:600}.sub{color:#8b93a7;font-size:12px;margin-top:3px}
.wrap{padding:12px 16px 40px;max-width:900px;margin:0 auto}
.cards{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px}
.card{background:#171a21;border:1px solid #262b36;border-radius:8px;padding:10px 14px;min-width:86px}
.card .n{font-size:22px;font-weight:700}.card .l{font-size:11px;color:#8b93a7;text-transform:uppercase;letter-spacing:.04em}
h2{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#8b93a7;margin:20px 0 8px}
table{width:100%;border-collapse:collapse;font-size:13px}
td,th{text-align:left;padding:6px 8px;border-bottom:1px solid #1e222b}
th{color:#8b93a7;font-weight:500;font-size:11px;text-transform:uppercase}
tr:hover td{background:#151922}.mono{font-family:ui-monospace,Consolas,monospace}
.ev{padding:4px 0;border-bottom:1px solid #161a22;display:flex;gap:8px;font-size:12.5px;align-items:baseline}
.t{color:#6b7386;white-space:nowrap;font-variant-numeric:tabular-nums}
.k{font-weight:600;padding:1px 6px;border-radius:4px;white-space:nowrap;font-size:11px}
.k-TLS{background:#123524;color:#5ee08a}.k-REQ{background:#2a1f3d;color:#c39bff}
.k-DHCP{background:#12283a;color:#6fc4f5}.k-DEV{background:#123524;color:#5ee08a}
.k-PING{background:#3a3312;color:#f5d76f}.k-JOIN{background:#123524;color:#5ee08a}
.k-LEAVE{background:#3a1616;color:#f58a8a}.k-ARP{background:#122033;color:#7fb2e6}
a{color:#6fc4f5}.foot{color:#6b7386;font-size:11px;margin-top:20px}
</style></head><body>
<header><h1>Test_1101 &mdash; monitor</h1>
<div class="sub">standalone &middot; open network &middot; passive capture &middot; no PC needed</div></header>
<div class="wrap">
<div class="cards" id="cards"></div>
<h2>Servers contacted</h2><div id="hosts"></div>
<h2>Devices</h2><div id="devs"></div>
<h2>Recent events</h2><div id="events"></div>
<div class="foot"><a href="/events.log">download full log</a> &middot; <a href="/api">JSON API</a> &middot; <a href="/admin">admin panel</a></div>
</div><script>
const esc=s=>(s==null?'':String(s)).replace(/[<>&"]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));
const hms=t=>{const s=Math.floor(t%86400);return [Math.floor(s/3600),Math.floor(s/60)%60,s%60].map(v=>String(v).padStart(2,'0')).join(':')};
async function tick(){let d;try{d=await (await fetch('/api')).json()}catch(e){return}
 document.getElementById('cards').innerHTML=[['clients',d.clients],['frames',d.frames],['servers',d.hosts.length],['logged',d.logged]]
  .map(([l,n])=>`<div class="card"><div class="n">${n}</div><div class="l">${l}</div></div>`).join('');
 document.getElementById('hosts').innerHTML=d.hosts.length
  ?'<table><tr><th>service</th><th>hostname</th><th>hits</th><th>last</th></tr>'+d.hosts.map(h=>
    `<tr><td>${esc(h.service)||'<span class=t>unknown</span>'}</td><td class="mono">${esc(h.host)}</td><td>${h.n}</td><td class="t">${hms(h.last)}</td></tr>`).join('')+'</table>'
  :'<div class="t">nothing yet &mdash; open an app on the connected phone</div>';
 document.getElementById('devs').innerHTML=d.devices.length
  ?'<table><tr><th>mac</th><th>ip</th><th>host</th><th>rssi</th><th>frames</th></tr>'+d.devices.map(v=>
    `<tr><td class="mono">${esc(v.mac)}</td><td class="mono">${esc(v.ip)}</td><td>${esc(v.host)}</td><td>${v.rssi}</td><td>${v.frames}</td></tr>`).join('')+'</table>'
  :'<div class="t">no device connected</div>';
 document.getElementById('events').innerHTML=d.events.map(e=>
  `<div class="ev"><span class="t">${hms(e.t)}</span><span class="k k-${esc(e.k)}">${esc(e.k)}</span><span>${esc(e.m)}</span></div>`).join('')
  ||'<div class="t">waiting...</div>';
}
tick();setInterval(tick,2000);
</script></body></html>)xPAGEx";
