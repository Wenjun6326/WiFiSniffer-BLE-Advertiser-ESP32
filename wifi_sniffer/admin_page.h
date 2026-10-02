// Admin control panel, served from the access point at http://192.168.4.1/admin
//
// Kept in its own header for the same reason as web_page.h: a large raw string
// literal full of JavaScript template syntax does not survive being inlined in
// the .ino.
//
// Authentication: HTTP Basic.  The firmware stores only a SHA1 of the password
// (see admin_pass / admin_auth in wifi_sniffer.ino), never the plaintext, and
// the browser re-sends the credentials on every request so the page's buttons
// just work.
//
// Bilingual (English / 简体中文), chosen in the browser:
//   * first visit follows navigator.language, so a Chinese browser opens in
//     Chinese without anyone having to find the switch
//   * the EN / 中文 buttons in the header override it, and the choice is kept in
//     localStorage so it survives a reload
//   * every visible string is in the i18n table below and is applied by
//     applyLang(); no text is hardcoded in the markup except numbers and units
//   * messages that the device itself sends back (the response to a button
//     press) arrive in English from the firmware; they are shown as sent, with
//     the panel's own equivalent underneath, so the log and the screen agree
#pragma once

static const char ADMIN_HTML[] = R"xADMINx(<!doctype html><html><head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Test_1101 admin</title><style>
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,"Noto Sans SC","Microsoft YaHei",sans-serif;margin:0;background:#0f1115;color:#e6e6e6}
header{padding:14px 16px;background:#171a21;border-bottom:1px solid #262b36;position:sticky;top:0;z-index:9;display:flex;justify-content:space-between;align-items:center;gap:10px;flex-wrap:wrap}
h1{margin:0;font-size:17px;font-weight:600}
.hright{display:flex;align-items:center;gap:10px}
.langbtn{background:#1e2634;border:1px solid #2f3a4d;color:#8b93a7;border-radius:6px;padding:3px 9px;font-size:12px;cursor:pointer}
.langbtn.sel{background:#12283a;border-color:#23506e;color:#9fd8ff}
.badge{font-size:11px;background:#3a2a12;color:#f5c26f;padding:2px 8px;border-radius:10px}
.wrap{padding:14px 16px 40px;max-width:900px;margin:0 auto}
section{background:#171a21;border:1px solid #262b36;border-radius:10px;padding:14px 16px;margin-bottom:14px}
h2{margin:0 0 10px;font-size:13px;text-transform:uppercase;letter-spacing:.05em;color:#8b93a7}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
button{background:#1e2634;color:#dbe4f0;border:1px solid #2f3a4d;border-radius:7px;padding:8px 14px;font-size:13px;cursor:pointer}
button:hover{background:#26303f}
button.on{background:#123524;border-color:#2a6b45;color:#7fe6a5}
button.off{background:#2a1a1a;border-color:#5a2a2a;color:#f0a0a0}
button.danger{background:#3a1616;border-color:#6b2a2a;color:#f58a8a}
.kv{font-size:12.5px;color:#8b93a7;margin-top:10px;line-height:1.7}
.kv b{color:#dbe4f0;font-weight:600}
.msg{background:#12283a;border:1px solid #23506e;color:#9fd8ff;padding:8px 12px;border-radius:7px;font-size:12.5px;margin-bottom:12px}
.warn{background:#3a2a12;border-color:#6b4a1a;color:#f5c26f}
.grid{display:grid;grid-template-columns:repeat(auto-fill,minmax(150px,1fr));gap:10px}
.stat{background:#12161d;border:1px solid #232a36;border-radius:8px;padding:10px}
.stat .n{font-size:20px;font-weight:700}.stat .l{font-size:11px;color:#8b93a7;text-transform:uppercase}
input[type=text],input[type=password]{background:#0f1319;border:1px solid #2f3a4d;color:#dbe4f0;border-radius:7px;padding:8px 10px;font-size:13px;width:190px}
a{color:#6fc4f5}
</style></head><body>
<header>
  <h1>Test_1101 &mdash; admin</h1>
  <div class="hright">
    <button class="langbtn" id="lang-en" onclick="setLang('en')">EN</button>
    <button class="langbtn" id="lang-zh" onclick="setLang('zh')">中文</button>
    <span class="badge" data-t="auth">authenticated</span>
  </div>
</header>
<div class="wrap">

<div id="msg"></div>

<section>
<h2 data-t="capture">Capture</h2>
<div class="row">
  <button id="bForeign" onclick="act('foreign')">--</button>
  <button id="bHostdbg" onclick="act('hostdbg')">--</button>
</div>
<div class="kv" data-td="capture_help">--</div>
</section>

<section>
<h2 data-t="ble">BLE advertiser</h2>
<div class="msg warn" data-td="ble_warn">--</div>
<div class="row">
  <button id="bJuice" onclick="act('juice')">--</button>
  <button id="bTx" onclick="act('juicetx')">--</button>
</div>
<div class="kv" id="juicestat" style="margin-top:8px">--</div>
<div class="kv" id="juicehelp" data-td="ble_help">--</div></section>

<section>
<h2 data-t="status">Status</h2>
<div class="grid" id="stats"></div>
<div class="kv" id="kv"></div>
</section>

<section>
<h2 data-t="ap">Access point</h2>
<div class="row">
  <input type="text" id="ssid" placeholder="SSID">
  <input type="password" id="pw">
  <button onclick="act('applyap')" data-t="apply">Apply</button>
</div>
<div class="kv" data-t="ap_help">--</div>
</section>

<section>
<h2 data-t="log">Log</h2>
<div class="row">
  <a href="/events.log"><button data-t="log_download">Download events.log</button></a>
  <button onclick="act('clearlog')" data-t="log_clear">Clear log</button>
  <button onclick="act('reboot')" class="danger" data-t="reboot">Reboot device</button>
</div>
<div class="kv" data-t="log_help">--</div>
</section>

</div><script>
// ---------------------------------------------------------------- i18n table
// Plain string map.  {0}, {1}... are substituted positionally by fmt().
const I18N = {
 en: {
  title:"Test_1101 admin", auth:"authenticated",
  capture:"Capture", ble:"BLE advertiser", status:"Status", ap:"Access point", log:"Log",
  capture_help:"All-frames mode also streams traffic from <b>other networks</b> on channel 1 &mdash; noisy, but useful for surveying the band. Host-debug explains why a frame yielded no server name.",
  allframes_on:"all frames: ON", allframes_off:"all frames: OFF",
  hostdbg_on:"host debug: ON", hostdbg_off:"host debug: OFF",
  ble_warn:"Broadcasts the Apple proximity-pairing advertisements that AirPods, Apple TV and HomePod use to announce themselves, so iOS/iPadOS/macOS devices nearby raise pairing prompts. Lab use on your own devices only: transmitting is regulated and the prompts are unwanted by anyone who did not opt in.",
  ble_on:"BLE advertiser: ON", ble_off:"BLE advertiser: OFF",
  ble_off_label:"BLE advertiser: OFF · auto-off {0}",
  tx_short:"tx {0} dBm", tx_full:"transmit power: {0} dBm",
  juice_tpl:"transmitting &middot; {0} &middot; auto-off in <b>{1}s</b> &middot; sent <b>{2}</b>",
  juice_err:"<b>last error:</b> {0} ({1})",
  juice_idle:"idle",
  ble_help:"Stops itself after the time on the button &mdash; the timer lives on the device, not in the browser &mdash; and it is off at every boot. The power button steps the transmit power: Apple expects about +4 dBm and the chip defaults to +9, so try 3 dBm with the phone ~20 cm away. While it runs, the sniffer and the AP share one radio.",
  clients:"clients", frames:"frames", ours:"ours", foreign:"foreign",
  servers:"servers", logged:"logged", dropped:"dropped", uptime:"uptime",
  ssid_ph:"SSID", pw_ph:"new password (blank = open)",
  apply:"Apply",
  ap_help:"Changing this restarts the radio; every connected client is dropped and must rejoin. Leave the password blank to keep the network open.",
  log_download:"Download events.log", log_clear:"Clear log", reboot:"Reboot device",
  log_help:"The log lives in flash and survives power loss. It is capped and rotates automatically, so download it before it wraps.",
  working:"working...", reqfail:"request failed: {0}", unknown:"unknown action", off:"off",
  kv:"SSID <b>{0}</b> &middot; channel <b>{1}</b> &middot; flash log <b>{2} KB</b> &middot; free heap <b>{3} KB</b> &middot; client(s) <b>{4}</b>",
  mins:"{0} min", secs:"{0}s"
 },
 zh: {
  title:"Test_1101 管理面板", auth:"已认证",
  capture:"抓包", ble:"BLE 广播器", status:"状态", ap:"接入点", log:"日志",
  capture_help:"“全部帧”模式会同时串流信道 1 上<b>其它网络</b>的流量 &mdash;&mdash; 嘈杂，但适合勘察频段。主机调试用来解释某一帧为什么没解析出服务器名。",
  allframes_on:"全部帧：开", allframes_off:"全部帧：关",
  hostdbg_on:"主机调试：开", hostdbg_off:"主机调试：关",
  ble_warn:"广播 AirPods、Apple TV、HomePod 用来宣告自己的苹果邻近配对广播包，使附近的 iOS/iPadOS/macOS 设备弹出配对提示。仅限在实验室对自己的设备使用：无线电发射受法规约束，未同意的旁人并不想要这些弹窗。",
  ble_on:"BLE 广播器：开", ble_off:"BLE 广播器：关",
  ble_off_label:"BLE 广播器：关 · {0}后自动关闭",
  tx_short:"发射 {0} dBm", tx_full:"发射功率：{0} dBm",
  juice_tpl:"正在广播 &middot; {0} &middot; <b>{1} 秒</b>后自动关闭 &middot; 已发 <b>{2}</b> 包",
  juice_err:"<b>上次错误：</b>{0}（{1} 次）",
  juice_idle:"空闲",
  ble_help:"到达按钮上显示的时间后自动停止 &mdash;&mdash; 计时器在设备里而不在浏览器里，且每次开机都是关闭状态。功率按钮用于切换发射功率：苹果期望约 +4 dBm，芯片默认 +9 dBm，建议先用 3 dBm、手机放在约 20 厘米处。广播期间抓包与接入点共用同一个射频。",
  clients:"客户端", frames:"帧数", ours:"本网", foreign:"其它网",
  servers:"服务器", logged:"已记录", dropped:"丢弃", uptime:"运行",
  ssid_ph:"SSID", pw_ph:"新密码（留空 = 开放网络）",
  apply:"应用",
  ap_help:"修改后射频会重启；所有已连接客户端会被断开并需要重新加入。密码留空表示保持开放网络。",
  log_download:"下载 events.log", log_clear:"清空日志", reboot:"重启设备",
  log_help:"日志保存在 flash 中，断电不丢。它有条数上限并自动轮转，所以在写满前先下载。",
  working:"处理中…", reqfail:"请求失败：{0}", unknown:"未知操作", off:"关闭",
  kv:"SSID <b>{0}</b> &middot; 信道 <b>{1}</b> &middot; flash 日志 <b>{2} KB</b> &middot; 空闲内存 <b>{3} KB</b> &middot; 客户端 <b>{4}</b>",
  mins:"{0} 分钟", secs:"{0} 秒"
 }
};

let lang = 'en';
const t = k => (I18N[lang] && I18N[lang][k] !== undefined) ? I18N[lang][k] : (I18N.en[k] || k);
const fmt = (s, ...a) => String(s).replace(/\{(\d+)\}/g, (m, i) => a[+i] !== undefined ? a[+i] : m);
const esc = s => (s == null ? '' : String(s)).replace(/[<>&"]/g, c => ({'<':'&lt;','>':'&gt;','&':'&amp;','"':'&quot;'}[c]));

function setLang(l) {
  lang = (l === 'zh') ? 'zh' : 'en';
  try { localStorage.setItem('lang', lang); } catch (e) {}
  applyLang();
  tick();
}

// Walk the markup once per language change: data-t holds a key applied as plain
// text, data-tp a key used as a placeholder, data-td a key whose value contains
// markup (the warning banner) and has to be set as HTML - setting it as text is
// how "&mdash;" and "<b>" ended up visible on the page.
function applyLang() {
  document.documentElement.lang = (lang === 'zh') ? 'zh-Hans' : 'en';
  document.title = t('title');
  document.querySelectorAll('[data-t]').forEach(e => { e.textContent = t(e.getAttribute('data-t')); });
  document.querySelectorAll('[data-tp]').forEach(e => { e.placeholder = t(e.getAttribute('data-tp')); });
  document.querySelectorAll('[data-td]').forEach(e => { e.innerHTML = t(e.getAttribute('data-td')); });
  document.getElementById('lang-en').className = 'langbtn' + (lang === 'en' ? ' sel' : '');
  document.getElementById('lang-zh').className = 'langbtn' + (lang === 'zh' ? ' sel' : '');
}

function initLang() {
  let saved = null;
  try { saved = localStorage.getItem('lang'); } catch (e) {}
  if (saved === 'zh' || saved === 'en') { lang = saved; }
  else { lang = (navigator.language || 'en').toLowerCase().startsWith('zh') ? 'zh' : 'en'; }
}

// ---------------------------------------------------------------- panel
function say(msg, warn) {
  document.getElementById('msg').innerHTML = msg ? `<div class="msg${warn ? ' warn' : ''}">${msg}</div>` : '';
}

async function getJSON(url) { return (await fetch(url)).json(); }

// The firmware answers a button press in English (it has no idea what language
// this page is in).  The panel therefore maps the reply onto its own wording for
// the states it knows, and shows the device's original line underneath.
function translateReply(a, raw) {
  const r = (raw || '').trim();
  if (a === 'juice') {
    if (r.indexOf('already off') >= 0) return t('ble_off');
    if (r.indexOf('failed') >= 0) return t('ble_off') + ' — ' + r;
    if (r.indexOf('ON for') >= 0) return t('ble_on');
    if (r.indexOf('OFF') >= 0) return t('ble_off');
  }
  if (a === 'juicetx') {
    const m = r.match(/(-?\d+)\s*dBm/);
    if (m) return fmt(t('tx_full'), m[1]);
  }
  if (a === 'clearlog') return lang === 'zh' ? '日志已清空' : 'log cleared';
  if (a === 'reboot') return lang === 'zh' ? '正在重启…' : 'rebooting...';
  if (a === 'applyap') return lang === 'zh' ? '正在应用 &mdash; 射频重启，客户端需重新加入' : r;
  if (a === 'foreign') return r.indexOf('ON') >= 0 ? t('allframes_on') : t('allframes_off');
  if (a === 'hostdbg') return r.indexOf('ON') >= 0 ? t('hostdbg_on') : t('hostdbg_off');
  return r;
}

async function act(a) {
  let body = 'a=' + encodeURIComponent(a);
  if (a === 'applyap') {
    const s = document.getElementById('ssid').value.trim();
    const p = document.getElementById('pw').value;
    if (!s) { say(lang === 'zh' ? 'SSID 不能为空' : 'SSID cannot be empty', 1); return; }
    body += '&ssid=' + encodeURIComponent(s) + '&pw=' + encodeURIComponent(p);
  }
  say(esc(t('working')));
  try {
    const r = await fetch('/admin/act', {method:'POST',
      headers:{'Content-Type':'application/x-www-form-urlencoded'}, body});
    const raw = await r.text();
    const shown = translateReply(a, raw);
    say(esc(shown) + (shown !== raw.trim() && raw.trim() ? `<br><span style="opacity:.6">${esc(raw.trim())}</span>` : ''));
  } catch (e) { say(esc(fmt(t('reqfail'), e)), 1); }
  setTimeout(tick, 600);
}

function human(ms) {
  return ms >= 60000 ? fmt(t('mins'), Math.round(ms / 60000)) : fmt(t('secs'), Math.round(ms / 1000));
}

async function tick() {
  let d; try { d = await getJSON('/api'); } catch (e) { return }
  document.getElementById('stats').innerHTML = [
    ['clients', d.clients], ['frames', d.frames], ['ours', d.ours], ['foreign', d.foreign],
    ['servers', d.hosts.length], ['logged', d.logged], ['dropped', d.serdrop], ['uptime', d.uptime + 's']
  ].map(([l, n]) => `<div class="stat"><div class="n">${n}</div><div class="l">${esc(t(l))}</div></div>`).join('');

  const st = await getJSON('/admin/state');
  const bF = document.getElementById('bForeign'), bH = document.getElementById('bHostdbg');
  bF.textContent = (st.foreign ? t('allframes_on') : t('allframes_off')); bF.className = st.foreign ? 'on' : 'off';
  bH.textContent = (st.hostdbg ? t('hostdbg_on') : t('hostdbg_off')); bH.className = st.hostdbg ? 'on' : 'off';

  const bJ = document.getElementById('bJuice');
  bJ.textContent = st.juice ? t('ble_on') : fmt(t('ble_off_label'), human(st.juice_window * 1000));
  bJ.className = st.juice ? 'danger' : '';
  const bT = document.getElementById('bTx');
  bT.textContent = fmt(t('tx_short'), st.juice_tx);

  document.getElementById('juicestat').innerHTML = st.juice
    ? fmt(t('juice_tpl'), esc(st.juice_tpl), st.juice_left, st.juice_cycles)
    : (st.juice_errors ? fmt(t('juice_err'), esc(st.juice_err), st.juice_errors) : t('juice_idle'));

  document.getElementById('ssid').placeholder = st.ssid;
  document.getElementById('kv').innerHTML =
    fmt(t('kv'), esc(st.ssid), st.channel, st.log_kb, st.heap_kb, st.clients);
}

initLang();
applyLang();
tick();
setInterval(tick, 3000);
</script></body></html>)xADMINx";
