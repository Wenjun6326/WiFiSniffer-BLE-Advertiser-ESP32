/*
 * Test_1101 - open access point + 802.11 monitor, with a real DHCP server.
 * ---------------------------------------------------------------------------
 * For lab testing of YOUR OWN devices and network only.
 *
 * What it does
 *   * raises an open SoftAP named Test_1101 (no password)
 *   * runs a DHCP server, so clients get a real lease and a hostname is recorded
 *   * answers every DNS query with its own address and routes nothing, so the
 *     client stays connected but has no working internet
 *   * passively captures 802.11 frames and streams them, plus the decoded
 *     events a reader actually cares about
 *
 * Hard limit you cannot engineer around
 *   An ESP32-S3 has ONE radio.  While it runs the SoftAP the radio is parked on
 *   that AP's channel, so this sees devices that join Test_1101 plus broadcast
 *   traffic on that channel.  It cannot follow a client to another network.
 *
 * Encryption: the AP is open, so associated-client frames are unencrypted on the
 * air and DNS/HTTP payloads are readable.  TLS contents stay encrypted - the
 * metadata (who, when, how big, which host via SNI-free DNS) is still visible.
 *
 * Serial protocol (115200 8N1), one record per line, '@' prefixed:
 *   @BOOT  banner / configuration
 *   @AP    access point is up
 *   @STA   ev=join|leave mac=.. rssi=..
 *   @DHCP  ev=discover|request|ack mac=.. ip=.. host=..
 *   @ARP   ip=.. mac=..
 *   @DNS   mac=.. ip=.. q=example.com
 *   @ICMP  ev=echo-request mac=.. ip=.. dst=..
 *   @PKT   t=.. a1=.. a2=.. a3=.. rssi=.. ch=.. len=.. seq=.. [info=..]
 *   @JUICE BLE proximity advertiser: ON / OFF / auto-off / ERR (see juice.h)
 *   @STAT  counters
 * Commands accepted on the same port:
 *   @CMD foreign=on|off     also stream frames from other networks
 *   @CMD hostdbg=on|off     explain why a frame yielded no server name
 *   @CMD juice=on|off       BLE proximity advertiser, 60 s maximum
 */

#include <WiFi.h>
#include <WiFiAP.h>
#include <WiFiUdp.h>
#include <esp_wifi.h>
#include <esp_wifi_types.h>
#include <WebServer.h>
#include <LittleFS.h>
#include <string.h>

// ---------------------------------------------------------------------------
// configuration
// ---------------------------------------------------------------------------
static const char *AP_SSID = "Test_1101";
static const char *AP_PASS = "";        // open network
static const uint8_t AP_CHANNEL = 1;    // fixed: the monitor rides on it
static const uint8_t AP_MAX_STA = 8;
static const IPAddress AP_IP(192, 168, 4, 1);
static const IPAddress AP_MASK(255, 255, 255, 0);
static const uint8_t LEASE_FIRST = 100; // 192.168.4.100 upwards
static const uint8_t LEASE_LAST = 120;

static const uint32_t STAT_INTERVAL_MS = 2000;
static const bool PRINT_PAYLOAD = true;
static const uint16_t PAYLOAD_MAX = 48;

// Channel 1 is crowded; foreign traffic is counted but not streamed unless asked.
static const uint32_t OTHER_BEACON_SAMPLE = 48;
static const uint32_t OTHER_DATA_SAMPLE = 24;

// ---------------------------------------------------------------------------
// shared state
// ---------------------------------------------------------------------------
struct StaRec {
  uint8_t mac[6];
  IPAddress ip;
  char host[24];
  bool used;
  uint32_t frames;
  int8_t rssi;
};

static StaRec clients[AP_MAX_STA];
static portMUX_TYPE stMux = portMUX_INITIALIZER_UNLOCKED;

static uint8_t ap_bssid[6] = {0};
static bool ap_bssid_valid = false;
static volatile bool g_show_foreign = false;
static volatile bool g_hostdbg = false;      // report why a frame gave no host
static volatile uint32_t c_pkts = 0, c_ours = 0, c_foreign = 0;
static volatile uint32_t c_mgmt = 0, c_ctrl = 0, c_data = 0;
static volatile uint32_t c_bytes = 0, c_serial_drop = 0;

// Distinct servers seen via TLS SNI / HTTP Host; shown on the status panel.
static volatile uint32_t c_hosts = 0;

// ---------------------------------------------------------------------------
// dual-output event pipeline
//
// Everything interesting goes through one queue so the two consumers stay in
// step: the main loop drains it and writes each record BOTH to the serial port
// (the cmd window) and to the flash log (the standalone web page).  Either can
// be used on its own, or both at once.
//
// The queue exists because the capture callback runs in the WiFi task, where
// touching flash is unsafe and a blocking write would cost frames.
// ---------------------------------------------------------------------------
static const int EV_RING = 96;
static const int EV_LEN = 112;
static char ev_ring[EV_RING][EV_LEN];
static volatile int ev_head = 0;
static volatile int ev_count = 0;
static portMUX_TYPE evMux = portMUX_INITIALIZER_UNLOCKED;

static WiFiUDP dhcp;

// ---------------------------------------------------------------------------
// standalone operation: event ring + flash log + web console
//
// The sniffer callback runs in the WiFi task, where touching flash is unsafe
// (it can stall the other core mid-erase).  So the callback only ever appends a
// short string to a RAM ring; the main loop drains that ring, writes it to
// LittleFS and serves it over HTTP.  This is what makes the device work with no
// PC attached - power it from any USB charger, join the AP, open 192.168.4.1.
// ---------------------------------------------------------------------------
static WebServer web(80);
static bool fs_ok = false;
static const char *LOG_PATH = "/events.log";
static const size_t LOG_MAX_BYTES = 512 * 1024;
static uint32_t log_written = 0;

// Ring of servers seen via TLS SNI / HTTP Host, newest wins.  Kept in RAM so the
// dashboard can rank them without reading the flash log.
static const int HOST_RING = 48;
struct HostRec {
  char name[64];
  char service[32];
  uint16_t hits;
  uint32_t last;
  bool used;
};
static HostRec hosts_seen[HOST_RING];
static volatile int host_head = 0;
static volatile int host_n = 0;
static portMUX_TYPE hostMux = portMUX_INITIALIZER_UNLOCKED;

// Map a hostname to the service a person would name.  Duplicated in the PC
// console so the standalone page and the serial view agree.
static const char *service_of(const char *h) {
  static const struct { const char *key; const char *name; } T[] = {
    {"weixin.qq.com", "WeChat"},        {"wechat.com", "WeChat"},
    {"wechatpay", "WeChat Pay"},        {"tencent-cloud.net", "Tencent Cloud"},
    {"myqcloud.com", "Tencent Cloud"},  {"qpic.cn", "Tencent"},
    {"gtimg.cn", "Tencent"},            {"qq.com", "Tencent QQ"},
    {"icloud.com", "Apple iCloud"},     {"mzstatic.com", "App Store"},
    {"cdn-apple.com", "Apple CDN"},     {"apple.com", "Apple"},
    {"googleapis.com", "Google APIs"},  {"gstatic.com", "Google"},
    {"gvt1.com", "Google Play"},        {"android.com", "Android"},
    {"baidu.com", "Baidu"},             {"bdstatic.com", "Baidu"},
    {"alipay.com", "Alipay"},           {"alibaba.com", "Alibaba"},
    {"alicdn.com", "Alibaba CDN"},      {"aliyuncs.com", "Alibaba Cloud"},
    {"taobao.com", "Taobao"},           {"tmall.com", "Tmall"},
    {"weibo.com", "Weibo"},             {"sinaimg.cn", "Sina"},
    {"xiaomi.com", "Xiaomi"},           {"miui.com", "Xiaomi MIUI"},
    {"mi.com", "Xiaomi"},               {"huawei.com", "Huawei"},
    {"hicloud.com", "Huawei Cloud"},    {"douyin.com", "Douyin"},
    {"bytedance.com", "ByteDance"},     {"byteimg.com", "ByteDance"},
    {"toutiao.com", "Toutiao"},         {"kuaishou.com", "Kuaishou"},
    {"bilibili.com", "Bilibili"},       {"hdslb.com", "Bilibili CDN"},
    {"zhihu.com", "Zhihu"},             {"jd.com", "JD"},
    {"meituan.com", "Meituan"},         {"pinduoduo.com", "Pinduoduo"},
    {"netflix.com", "Netflix"},         {"microsoft.com", "Microsoft"},
    {"live.com", "Microsoft"},          {"office.com", "Microsoft Office"},
    {"cloudflare.com", "Cloudflare"},   {"amazonaws.com", "AWS"},
    {"facebook.com", "Facebook"},       {"instagram.com", "Instagram"},
    {"whatsapp.net", "WhatsApp"},       {"github.com", "GitHub"},
    {"resolver.arpa", "DNS probe"},
  };
  for (size_t i = 0; i < sizeof(T) / sizeof(T[0]); i++) {
    if (strstr(h, T[i].key)) return T[i].name;
  }
  return "";
}

static void remember_host(const char *host) {
  if (!host || !host[0]) return;

  portENTER_CRITICAL(&hostMux);
  // already known? bump it
  for (int i = 0; i < HOST_RING; i++) {
    if (hosts_seen[i].used && strcmp(hosts_seen[i].name, host) == 0) {
      hosts_seen[i].hits++;
      hosts_seen[i].last = millis() / 1000;
      portEXIT_CRITICAL(&hostMux);
      return;
    }
  }
  HostRec *r = &hosts_seen[host_head];
  strncpy(r->name, host, sizeof(r->name) - 1);
  r->name[sizeof(r->name) - 1] = 0;
  const char *svc = service_of(host);
  strncpy(r->service, svc, sizeof(r->service) - 1);
  r->service[sizeof(r->service) - 1] = 0;
  r->hits = 1;
  r->last = millis() / 1000;
  r->used = true;
  host_head = (host_head + 1) % HOST_RING;
  if (host_n < HOST_RING) host_n++;
  portEXIT_CRITICAL(&hostMux);
}

// Push one event into the ring.  Called from both tasks, so it is guarded.
static void push_event(const char *text) {
  if (!text || !text[0]) return;
  portENTER_CRITICAL(&evMux);
  strncpy(ev_ring[ev_head], text, EV_LEN - 1);
  ev_ring[ev_head][EV_LEN - 1] = 0;
  ev_head = (ev_head + 1) % EV_RING;
  if (ev_count < EV_RING) ev_count++;
  portEXIT_CRITICAL(&evMux);
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------
static void mac_str(const uint8_t *m, char *out) {
  sprintf(out, "%02x:%02x:%02x:%02x:%02x:%02x", m[0], m[1], m[2], m[3], m[4], m[5]);
}

static void ip_str(const IPAddress &a, char *out) {
  sprintf(out, "%u.%u.%u.%u", a[0], a[1], a[2], a[3]);
}

static StaRec *client_find(const uint8_t *mac) {
  for (int i = 0; i < AP_MAX_STA; i++) {
    if (clients[i].used && memcmp(clients[i].mac, mac, 6) == 0) return &clients[i];
  }
  return nullptr;
}

static StaRec *client_add(const uint8_t *mac) {
  StaRec *c = client_find(mac);
  if (c) return c;
  for (int i = 0; i < AP_MAX_STA; i++) {
    if (!clients[i].used) {
      memset(&clients[i], 0, sizeof(StaRec));
      memcpy(clients[i].mac, mac, 6);
      clients[i].used = true;
      return &clients[i];
    }
  }
  return nullptr;
}

// Resolve the client that owns a MAC, for labelling events with an IP.
static bool ip_of_mac(const uint8_t *mac, IPAddress &out) {
  bool ok = false;
  portENTER_CRITICAL(&stMux);
  StaRec *c = client_find(mac);
  if (c && (uint32_t)c->ip != 0) { out = c->ip; ok = true; }
  portEXIT_CRITICAL(&stMux);
  return ok;
}

static void emit(const char *s) {
  Serial.write((const uint8_t *)s, strlen(s));
}

// Queue an event for the drainer in loop().  Safe from either task.
static void push_event(const char *kind, const char *msg) {
  if (!kind || !msg) return;
  char rec[EV_LEN];
  snprintf(rec, sizeof(rec), "%s\t%lu\t%s", kind, (unsigned long)(millis() / 1000), msg);
  portENTER_CRITICAL(&evMux);
  strncpy(ev_ring[ev_head], rec, EV_LEN - 1);
  ev_ring[ev_head][EV_LEN - 1] = 0;
  ev_head = (ev_head + 1) % EV_RING;
  if (ev_count < EV_RING) ev_count++;
  portEXIT_CRITICAL(&evMux);
}

// printf-style convenience wrapper.
static void push_eventf(const char *kind, const char *fmt, ...) {
  char msg[EV_LEN];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  push_event(kind, msg);
}

// Same thing under the name juice.h calls: that header is included further
// down, next to the pages, and needs a logger that already exists by then.
static void juice_logf(const char *fmt, ...) {
  char msg[EV_LEN];
  va_list ap;
  va_start(ap, fmt);
  vsnprintf(msg, sizeof(msg), fmt, ap);
  va_end(ap);
  push_event("JUICE", msg);
}

// ---------------------------------------------------------------------------
// DHCP server
// ---------------------------------------------------------------------------
static void dhcp_reply(uint8_t *req, uint16_t len, uint8_t msg_type,
                       const IPAddress &yiaddr, const char *hostname) {
  uint8_t resp[300];
  memset(resp, 0, sizeof(resp));

  resp[0] = 2;                                   // BOOTREPLY
  resp[1] = 1;                                   // ethernet
  resp[2] = 6;                                   // hlen
  memcpy(resp + 4, req + 4, 4);                  // xid
  resp[10] = req[10];                            // flags
  memcpy(resp + 16, &yiaddr, 4);                 // yiaddr
  memcpy(resp + 20, &AP_IP, 4);                  // siaddr (next server)
  memcpy(resp + 28, req + 28, 6);                // chaddr
  resp[236] = 0x63; resp[237] = 0x82; resp[238] = 0x53; resp[239] = 0x63;

  uint16_t o = 240;
  resp[o++] = 53; resp[o++] = 1; resp[o++] = msg_type;          // message type
  resp[o++] = 54; resp[o++] = 4; memcpy(resp + o, &AP_IP, 4); o += 4;   // server id
  resp[o++] = 51; resp[o++] = 4;                                 // lease time 1h
  resp[o++] = 0; resp[o++] = 0; resp[o++] = 0x0E; resp[o++] = 0x10;
  resp[o++] = 1; resp[o++] = 4; memcpy(resp + o, &AP_MASK, 4); o += 4;  // subnet mask
  resp[o++] = 3; resp[o++] = 4; memcpy(resp + o, &AP_IP, 4); o += 4;    // router
  resp[o++] = 6; resp[o++] = 4; memcpy(resp + o, &AP_IP, 4); o += 4;    // dns
  if (hostname && hostname[0]) {                                  // echo hostname
    uint8_t hl = (uint8_t)strnlen(hostname, 20);
    resp[o++] = 12; resp[o++] = hl; memcpy(resp + o, hostname, hl); o += hl;
  }
  resp[o++] = 255;

  dhcp.beginPacket(IPAddress(255, 255, 255, 255), 68);
  dhcp.write(resp, o);
  dhcp.endPacket();
}

static void dhcp_handle() {
  int sz = dhcp.parsePacket();
  if (sz < 240) return;

  static uint8_t buf[600];
  int len = dhcp.read(buf, sizeof(buf));
  if (len < 240) return;
  if (buf[0] != 1) return;                        // not a BOOTREQUEST
  if (buf[236] != 0x63 || buf[237] != 0x82 || buf[238] != 0x53 || buf[239] != 0x63) return;

  const uint8_t *cmac = buf + 28;
  uint8_t msg = 0;
  IPAddress req_ip;
  char host[24] = {0};

  uint16_t o = 240;
  while (o < len) {
    uint8_t opt = buf[o++];
    if (opt == 0) continue;
    if (opt == 255) break;
    if (o >= len) break;
    uint8_t olen = buf[o++];
    if (o + olen > len) break;
    if (opt == 53 && olen >= 1) msg = buf[o];
    else if (opt == 50 && olen == 4) req_ip = IPAddress(buf[o], buf[o + 1], buf[o + 2], buf[o + 3]);
    else if (opt == 12) {
      uint8_t k = olen > 20 ? 20 : olen;
      memcpy(host, buf + o, k);
      host[k] = 0;
      for (uint8_t i = 0; i < k; i++) {
        char c = host[i];
        if (c < 32 || c > 126) host[i] = '?';
        else if (c == '"') host[i] = '\'';
      }
    }
    o += olen;
  }

  char ms[18], ips[20];
  mac_str(cmac, ms);

  if (msg == 1 || msg == 3) {                     // DISCOVER / REQUEST
    portENTER_CRITICAL(&stMux);
    StaRec *c = client_add(cmac);
    if (c) {
      if ((uint32_t)c->ip == 0) {
        // deterministic lease from the MAC, so a client keeps its address
        uint8_t slot = LEASE_FIRST + (cmac[5] % (LEASE_LAST - LEASE_FIRST + 1));
        c->ip = IPAddress(192, 168, 4, slot);
      }
      if (host[0] && !c->host[0]) strncpy(c->host, host, sizeof(c->host) - 1);
    }
    IPAddress assigned = c ? c->ip : AP_IP;
    char hbuf[24];
    strncpy(hbuf, c ? c->host : "", sizeof(hbuf) - 1);
    hbuf[sizeof(hbuf) - 1] = 0;
    portEXIT_CRITICAL(&stMux);

    ip_str(assigned, ips);
    push_eventf("DHCP", "ev=%s mac=%s ip=%s host=\"%s\"",
                msg == 1 ? "discover" : "request", ms, ips, hbuf);
  }

  if (msg == 1) {
    char hbuf[24] = {0};
    portENTER_CRITICAL(&stMux);
    StaRec *c = client_find(cmac);
    IPAddress assigned = c ? c->ip : AP_IP;
    if (c) { strncpy(hbuf, c->host, sizeof(hbuf) - 1); }
    portEXIT_CRITICAL(&stMux);
    dhcp_reply(buf, len, 2, assigned, hbuf);      // OFFER
  } else if (msg == 3) {
    char hbuf[24] = {0};
    portENTER_CRITICAL(&stMux);
    StaRec *c = client_find(cmac);
    IPAddress assigned = c ? c->ip : AP_IP;
    if (c) { strncpy(hbuf, c->host, sizeof(hbuf) - 1); }
    portEXIT_CRITICAL(&stMux);
    dhcp_reply(buf, len, 5, assigned, hbuf);      // ACK
    ip_str(assigned, ips);
    push_eventf("DHCP", "ev=ack mac=%s ip=%s host=\"%s\"", ms, ips, hbuf);
  }
}

// ---------------------------------------------------------------------------
// captive DNS: log the queried name, then answer with our own address
// ---------------------------------------------------------------------------
static WiFiUDP dnsSrv;

static void dns_handle() {
  int sz = dnsSrv.parsePacket();
  if (sz < 12 || sz > 512) return;

  static uint8_t q[512];
  int len = dnsSrv.read(q, sizeof(q));
  if (len < 12) return;

  IPAddress from = dnsSrv.remoteIP();
  uint16_t port = dnsSrv.remotePort();

  // decode the first question name
  char name[128];
  int n = 0, i = 12;
  while (i < len && q[i] != 0 && n < (int)sizeof(name) - 2) {
    uint8_t lab = q[i++];
    if (lab > 63) break;                          // compression pointer: stop
    for (uint8_t k = 0; k < lab && i < len && n < (int)sizeof(name) - 2; k++) {
      char c = (char)q[i++];
      name[n++] = (c >= 32 && c < 127) ? c : '?';
    }
    name[n++] = '.';
  }
  if (n > 0 && name[n - 1] == '.') n--;
  name[n] = 0;
  if (n == 0) return;

  int qend = i + 1 + 4;                           // null + qtype + qclass

  char ips[20], ms[18];
  ip_str(from, ips);
  mac_str(ap_bssid, ms);                          // placeholder, replaced below

  // look up the client that owns this IP, for the MAC column
  char cmac[18] = "?";
  portENTER_CRITICAL(&stMux);
  for (int k = 0; k < AP_MAX_STA; k++) {
    if (clients[k].used && clients[k].ip == from) { mac_str(clients[k].mac, cmac); break; }
  }
  portEXIT_CRITICAL(&stMux);

  push_eventf("DNS", "mac=%s ip=%s q=%s", cmac, ips, name);

  // build the reply: same id/flags, question echoed, one A record -> AP_IP
  uint8_t r[600];
  if (qend + 16 > (int)sizeof(r)) return;
  memcpy(r, q, qend);
  r[2] = 0x81; r[3] = 0x80;                       // standard response, no error
  r[6] = 0; r[7] = 1;                             // ancount = 1
  r[8] = 0; r[9] = 0; r[10] = 0; r[11] = 0;
  int o = qend;
  r[o++] = 0xC0; r[o++] = 0x0C;                   // name -> offset 12
  r[o++] = 0x00; r[o++] = 0x01;                   // type A
  r[o++] = 0x00; r[o++] = 0x01;                   // class IN
  r[o++] = 0x00; r[o++] = 0x00; r[o++] = 0x00; r[o++] = 0x3C;  // ttl 60
  r[o++] = 0x00; r[o++] = 0x04;                   // rdlength
  memcpy(r + o, &AP_IP, 4); o += 4;

  dnsSrv.beginPacket(from, port);
  dnsSrv.write(r, o);
  dnsSrv.endPacket();
}

// ---------------------------------------------------------------------------
// OLED status display (SSD1306 / SH1106, I2C)
//
// This is deliberately decoupled from the sniffer: if the panel is missing, is
// wired differently or does not answer, the access point and packet capture
// carry on unaffected.  The screen is only redrawn when the client count
// actually changes, so it costs essentially nothing.
//
// Wiring on this board, confirmed by an I2C scan:
//     VCC -> 3V3   GND -> GND   SCL -> GPIO5   SDA -> GPIO4   addr 0x3C
// ---------------------------------------------------------------------------
#define OLED_ENABLE 0
#define OLED_SDA 4
#define OLED_SCL 5

// 1.3" modules are usually SH1106, whose 132-column RAM means the visible
// window starts at column 2; an SSD1306 needs offset 0.  Both variants are
// built and launched side by side so the right one can simply be picked.
#define OLED_SH1106 1

static const uint8_t OLED_ADDR = 0x3C;
static bool oled_ok = false;

// -1 = use the value implied by OLED_SH1106; 0..3 = forced column offset
static int oled_manual_offset = -1;

#include <Wire.h>

static void oled_cmd(uint8_t c) {
  Wire.beginTransmission(OLED_ADDR);
  Wire.write((uint8_t)0x00);
  Wire.write(c);
  Wire.endTransmission();
}

// Defined further down with the other controller-register code; forward
// declared here so oled_init can call them.
static void oled_apply_profile(int prof);
static const char *profile_name(int p);

// Default register set for this module:
//   0 = SSD1306, 1 = SH1106 (alt COM), 2 = SH1106 (sequential COM)
#define OLED_PROFILE_DEFAULT 1

static void oled_init() {
#if OLED_ENABLE
  Wire.begin(OLED_SDA, OLED_SCL, 400000);
  Wire.setTimeOut(50);
  delay(50);

  Wire.beginTransmission(OLED_ADDR);
  if (Wire.endTransmission() != 0) {
    Serial.println("@OLED absent (no ACK at 0x3C) - continuing without it");
    return;
  }

  oled_apply_profile(OLED_PROFILE_DEFAULT);
  oled_ok = true;
  Serial.printf("@OLED ready at 0x%02X profile=%d (%s)\n",
                OLED_ADDR, OLED_PROFILE_DEFAULT, profile_name(OLED_PROFILE_DEFAULT));
#endif
}

// 5x7 font, ASCII 32..127, packed one byte per column (bit 0 = top row).
static const uint8_t FONT5X7[][5] = {
  {0x00,0x00,0x00,0x00,0x00}, {0x00,0x00,0x5F,0x00,0x00}, {0x00,0x07,0x00,0x07,0x00},
  {0x14,0x7F,0x14,0x7F,0x14}, {0x24,0x2A,0x7F,0x2A,0x12}, {0x23,0x13,0x08,0x64,0x62},
  {0x36,0x49,0x55,0x22,0x50}, {0x00,0x05,0x03,0x00,0x00}, {0x00,0x1C,0x22,0x41,0x00},
  {0x00,0x41,0x22,0x1C,0x00}, {0x14,0x08,0x3E,0x08,0x14}, {0x08,0x08,0x3E,0x08,0x08},
  {0x00,0x50,0x30,0x00,0x00}, {0x08,0x08,0x08,0x08,0x08}, {0x00,0x60,0x60,0x00,0x00},
  {0x20,0x10,0x08,0x04,0x02}, {0x3E,0x51,0x49,0x45,0x3E}, {0x00,0x42,0x7F,0x40,0x00},
  {0x42,0x61,0x51,0x49,0x46}, {0x21,0x41,0x45,0x4B,0x31}, {0x18,0x14,0x12,0x7F,0x10},
  {0x27,0x45,0x45,0x45,0x39}, {0x3C,0x4A,0x49,0x49,0x30}, {0x01,0x71,0x09,0x05,0x03},
  {0x36,0x49,0x49,0x49,0x36}, {0x06,0x49,0x49,0x29,0x1E}, {0x00,0x36,0x36,0x00,0x00},
  {0x00,0x56,0x36,0x00,0x00}, {0x08,0x14,0x22,0x41,0x00}, {0x14,0x14,0x14,0x14,0x14},
  {0x00,0x41,0x22,0x14,0x08}, {0x02,0x01,0x51,0x09,0x06}, {0x32,0x49,0x79,0x41,0x3E},
  {0x7E,0x11,0x11,0x11,0x7E}, {0x7F,0x49,0x49,0x49,0x36}, {0x3E,0x41,0x41,0x41,0x22},
  {0x7F,0x41,0x41,0x22,0x1C}, {0x7F,0x49,0x49,0x49,0x41}, {0x7F,0x09,0x09,0x09,0x01},
  {0x3E,0x41,0x49,0x49,0x7A}, {0x7F,0x08,0x08,0x08,0x7F}, {0x00,0x41,0x7F,0x41,0x00},
  {0x20,0x40,0x41,0x3F,0x01}, {0x7F,0x08,0x14,0x22,0x41}, {0x7F,0x40,0x40,0x40,0x40},
  {0x7F,0x02,0x0C,0x02,0x7F}, {0x7F,0x04,0x08,0x10,0x7F}, {0x3E,0x41,0x41,0x41,0x3E},
  {0x7F,0x09,0x09,0x09,0x06}, {0x3E,0x41,0x51,0x21,0x5E}, {0x7F,0x09,0x19,0x29,0x46},
  {0x46,0x49,0x49,0x49,0x31}, {0x01,0x01,0x7F,0x01,0x01}, {0x3F,0x40,0x40,0x40,0x3F},
  {0x1F,0x20,0x40,0x20,0x1F}, {0x3F,0x40,0x38,0x40,0x3F}, {0x63,0x14,0x08,0x14,0x63},
  {0x07,0x08,0x70,0x08,0x07}, {0x61,0x51,0x49,0x45,0x43}, {0x00,0x7F,0x41,0x41,0x00},
  {0x02,0x04,0x08,0x10,0x20}, {0x00,0x41,0x41,0x7F,0x00}, {0x04,0x02,0x01,0x02,0x04},
  {0x40,0x40,0x40,0x40,0x40}, {0x00,0x01,0x02,0x04,0x00}, {0x20,0x54,0x54,0x54,0x78},
  {0x7F,0x48,0x44,0x44,0x38}, {0x38,0x44,0x44,0x44,0x20}, {0x38,0x44,0x44,0x48,0x7F},
  {0x38,0x54,0x54,0x54,0x18}, {0x08,0x7E,0x09,0x01,0x02}, {0x0C,0x52,0x52,0x52,0x3E},
  {0x7F,0x08,0x04,0x04,0x78}, {0x00,0x44,0x7D,0x40,0x00}, {0x20,0x40,0x44,0x3D,0x00},
  {0x7F,0x10,0x28,0x44,0x00}, {0x00,0x41,0x7F,0x40,0x00}, {0x7C,0x04,0x18,0x04,0x78},
  {0x7C,0x08,0x04,0x04,0x78}, {0x38,0x44,0x44,0x44,0x38}, {0x7C,0x14,0x14,0x14,0x08},
  {0x08,0x14,0x14,0x18,0x7C}, {0x7C,0x08,0x04,0x04,0x08}, {0x48,0x54,0x54,0x54,0x20},
  {0x04,0x3F,0x44,0x40,0x20}, {0x3C,0x40,0x40,0x20,0x7C}, {0x1C,0x20,0x40,0x20,0x1C},
  {0x3C,0x40,0x30,0x40,0x3C}, {0x44,0x28,0x10,0x28,0x44}, {0x0C,0x50,0x50,0x50,0x3C},
  {0x44,0x64,0x54,0x4C,0x44}, {0x00,0x08,0x36,0x41,0x00}, {0x00,0x00,0x7F,0x00,0x00},
  {0x00,0x41,0x36,0x08,0x00}, {0x08,0x04,0x08,0x10,0x08},
};

// Draw one character of a scaled string into the framebuffer.
// scale 1 => 5x7, scale 2 => 10x14, etc.
static void fb_char(uint8_t *fb, int x, int y, char ch, int scale) {
  if (ch < 32 || ch > 127) ch = '?';
  const uint8_t *g = FONT5X7[(uint8_t)ch - 32];
  for (int col = 0; col < 5; col++) {
    uint8_t bits = g[col];
    for (int row = 0; row < 7; row++) {
      if (!(bits & (1 << row))) continue;
      for (int dy = 0; dy < scale; dy++) {
        for (int dx = 0; dx < scale; dx++) {
          int px = x + col * scale + dx;
          int py = y + row * scale + dy;
          if (px < 0 || px >= 128 || py < 0 || py >= 64) continue;
          fb[(py / 8) * 128 + px] |= (0x80 >> (px % 8));
        }
      }
    }
  }
}

static void fb_text(uint8_t *fb, int x, int y, const char *s, int scale) {
  for (; *s; s++) {
    fb_char(fb, x, y, *s, scale);
    x += 6 * scale;
  }
}

static int text_width(const char *s, int scale) {
  return (int)strlen(s) * 6 * scale - scale;
}

// Roughly centre a string horizontally.
static void fb_text_centered(uint8_t *fb, int y, const char *s, int scale) {
  int w = text_width(s, scale);
  fb_text(fb, (128 - w) / 2, y, s, scale);
}

static void oled_flush(const uint8_t *fb) {
  if (!oled_ok) return;
#if OLED_SH1106
  uint8_t colOffset = 2;
#else
  uint8_t colOffset = 0;
#endif
  if (oled_manual_offset >= 0) colOffset = (uint8_t)oled_manual_offset;
  for (uint8_t page = 0; page < 8; page++) {
    oled_cmd((uint8_t)(0xB0 | page));
    oled_cmd((uint8_t)(colOffset & 0x0F));
    oled_cmd((uint8_t)(0x10 | ((colOffset >> 4) & 0x0F)));
    Wire.beginTransmission(OLED_ADDR);
    Wire.write((uint8_t)0x40);
    Wire.write(fb + (size_t)page * 128, 128);
    Wire.endTransmission();
  }
}

// Draw a horizontal line through the framebuffer, respecting page boundaries.
// Defined before the sweep and the status screen, which both use it.
static void fb_hline(uint8_t *fb, int x, int y, int w) {
  for (int i = 0; i < w; i++) {
    int px = x + i;
    if (px < 0 || px >= 128 || y < 0 || y >= 64) continue;
    fb[(y / 8) * 128 + px] |= (0x80 >> (px % 8));
  }
}

// Which set of controller registers to use.  Selected at runtime so the panel
// can be matched on real hardware: app note values for the SH1106 differ from
// the SSD1306 in the COM-pin configuration and the address window handling, and
// feeding the wrong set produces either garbage or a blank screen.
enum OledProfile { PROF_SSD1306 = 0, PROF_SH1106_ALT, PROF_SH1106_SEQ, PROF_COUNT };

static const char *profile_name(int p) {
  switch (p) {
    case PROF_SSD1306:     return "SSD1306";
    case PROF_SH1106_ALT:  return "SH1106 alt-COM";
    case PROF_SH1106_SEQ:  return "SH1106 seq-COM";
    default:               return "?";
  }
}

static int oled_profile = PROF_SSD1306;

static void oled_apply_profile(int prof) {
  oled_profile = prof;
  oled_cmd(0xAE);                                  // display off while changing
  oled_cmd(0xD5); oled_cmd(0x80);                  // clock divide / oscillator
  oled_cmd(0xA8); oled_cmd(0x3F);                  // multiplex ratio 64
  oled_cmd(0xD3); oled_cmd(0x00);                  // display offset 0
  oled_cmd(0x40);                                  // start line 0
  oled_cmd(0x8D); oled_cmd(0x14);                  // charge pump on
  oled_cmd(0x20); oled_cmd(0x02);                  // page addressing mode
  oled_cmd(0xA1);                                  // segment remap
  oled_cmd(0xC8);                                  // COM scan direction remapped
  switch (prof) {
    case PROF_SSD1306:                               // SSD1306 datasheet values
      oled_cmd(0xDA); oled_cmd(0x12);
      break;
    case PROF_SH1106_ALT:                            // SH1106 app note: alt-COM
      oled_cmd(0xDA); oled_cmd(0x12);
      oled_cmd(0xAD); oled_cmd(0x8B);                // SH1106 internal DC-DC
      break;
    case PROF_SH1106_SEQ:                            // sequential COM layout
      oled_cmd(0xDA); oled_cmd(0x02);
      oled_cmd(0xAD); oled_cmd(0x8B);
      break;
  }
  oled_cmd(0x81); oled_cmd(0xCF);                  // contrast
  oled_cmd(0xD9); oled_cmd(0xF1);                  // pre-charge
  oled_cmd(0xDB); oled_cmd(0x40);                  // VCOMH deselect
  oled_cmd(0xA4);                                  // resume from RAM
  oled_cmd(0xA6);                                  // normal (not inverted)
  oled_cmd(0x2E);                                  // scroll off
  oled_cmd(0xAF);                                  // display on
}

// Walk every profile with a labelled card, so the correct combination can be
// identified by eye rather than deduced from the module's marking.
//   hold_ms: how long each combination stays on screen.  A large value (via
//   "@CMD oledsweep slow") is much easier than counting fast flashes.
static void oled_profile_sweep(uint32_t hold_ms = 600) {
#if OLED_ENABLE
  if (!oled_ok) return;
  Serial.printf("@OLED profile sweep: %u ms per step, watch for a complete box\n",
                (unsigned)hold_ms);

  for (int prof = 0; prof < PROF_COUNT; prof++) {
    for (int off = 0; off <= 3; off++) {
      oled_apply_profile(prof);
      oled_manual_offset = off;
      Serial.printf("@OLED NOW profile=%d (%s) colOffset=%d\n",
                    prof, profile_name(prof), off);

      uint32_t t0 = millis();
      while (millis() - t0 < hold_ms) {
        static uint8_t fb[1024];
        memset(fb, 0, sizeof(fb));
        char buf[24];

        // Big step label, readable from across the desk.
        snprintf(buf, sizeof(buf), "P%d", prof);
        fb_text_centered(fb, 4, buf, 3);
        snprintf(buf, sizeof(buf), "off %d", off);
        fb_text_centered(fb, 30, buf, 2);

        // A complete rectangle: all four edges visible and unbroken is what
        // identifies the right combination.
        fb_hline(fb, 0, 0, 128);
        fb_hline(fb, 0, 63, 128);
        for (int y = 0; y < 64; y++) {
          fb[(y / 8) * 128 + 0]   |= (0x80 >> 0);
          fb[(y / 8) * 128 + 127] |= (0x80 >> 7);
        }
        oled_flush(fb);
        delay(50);
      }
    }
  }
  oled_manual_offset = -1;
  oled_apply_profile(OLED_PROFILE_DEFAULT);
  Serial.println("@OLED sweep done - which P<n> showed a complete box?");
#endif
}

// The status screen: who is connected, and how much traffic we have seen.
static void oled_show_status(int nclients, uint32_t frames, uint32_t hosts) {
#if OLED_ENABLE
  if (!oled_ok) return;

  static uint8_t fb[1024];
  memset(fb, 0, sizeof(fb));

  char buf[24];

  // headline
  if (nclients <= 0) {
    fb_text_centered(fb, 4, "NO CLIENT", 2);
    fb_text_centered(fb, 24, "no one connected", 1);
  } else {
    snprintf(buf, sizeof(buf), "%d CLIENT%s", nclients, nclients == 1 ? "" : "S");
    fb_text_centered(fb, 4, buf, 2);
    snprintf(buf, sizeof(buf), "%d device%s online", nclients, nclients == 1 ? "" : "s");
    fb_text_centered(fb, 24, buf, 1);
  }

  // separator
  fb_hline(fb, 0, 40, 128);

  // counters
  fb_text(fb, 4, 46, "Test_1101", 1);
  snprintf(buf, sizeof(buf), "frames %lu", (unsigned long)frames);
  fb_text(fb, 4, 56, buf, 1);
  snprintf(buf, sizeof(buf), "hosts %lu", (unsigned long)hosts);
  fb_text(fb, 70, 56, buf, 1);

  oled_flush(fb);
#endif
}

// ---------------------------------------------------------------------------
// frame analysis helpers
// ---------------------------------------------------------------------------
static const char *frame_type_name(uint8_t sub, uint8_t ftype) {
  if (ftype == 0) {
    switch (sub) {
      case 0:  return "mgmt-assoc-req";
      case 1:  return "mgmt-assoc-resp";
      case 2:  return "mgmt-reassoc-req";
      case 3:  return "mgmt-reassoc-resp";
      case 4:  return "mgmt-probe-req";
      case 5:  return "mgmt-probe-resp";
      case 8:  return "mgmt-beacon";
      case 10: return "mgmt-disassoc";
      case 11: return "mgmt-auth";
      case 12: return "mgmt-deauth";
      case 13: return "mgmt-action";
      default: return "mgmt";
    }
  }
  if (ftype == 1) return "ctrl";
  return "data";
}

// ---------------------------------------------------------------------------
// application-layer extraction
//
// DNS alone is not enough to say what a device is talking to: phones widely use
// encrypted DNS (DoH/DoT) and hard-coded IPs.  The TLS ClientHello, however,
// carries the destination hostname in the clear (SNI) *before* encryption
// starts, so parsing it gives the real server name for both cases.  Plain HTTP
// is covered too via the Host header.
//
// Limitation: a frame is at most ~1500 bytes, so this only fires when the
// ClientHello arrives in a single frame, which is the normal case for the
// initial handshake.
// ---------------------------------------------------------------------------

// Build "a.b.c" into buf, returning false when it is not actually a name.
static bool sniff_only_digits_dots(const uint8_t *p, uint16_t n) {
  bool dot = false;
  for (uint16_t i = 0; i < n; i++) {
    uint8_t c = p[i];
    if (c == '.') { dot = true; continue; }
    if (c < '0' || c > '9') return false;
  }
  return dot;
}

// Extract the SNI host name from a TLS ClientHello.  Returns length, 0 if absent.
static uint16_t tls_sni(const uint8_t *p, uint16_t n, char *out, uint16_t outsz) {
  if (n < 5 + 4 + 2 + 32 + 1) return 0;
  if (p[0] != 0x16) return 0;                       // handshake record
  if (p[5] != 0x01) return 0;                       // ClientHello
  uint32_t i = 5 + 4;                               // record hdr + hs hdr

  if (i + 34 > n) return 0;
  i += 2 + 32;                                      // version + random
  if (i >= n) return 0;
  uint8_t sid = p[i++];
  if (i + sid > n) return 0;
  i += sid;                                         // session id
  if (i + 2 > n) return 0;
  uint16_t cs = (uint16_t)((p[i] << 8) | p[i + 1]);
  i += 2 + cs;                                      // cipher suites
  if (i >= n) return 0;
  uint8_t cm = p[i++];
  if (i + cm > n) return 0;
  i += cm;                                          // compression methods
  if (i + 2 > n) return 0;
  uint16_t extlen = (uint16_t)((p[i] << 8) | p[i + 1]);
  i += 2;
  uint32_t end = i + extlen;
  if (end > n) end = n;                             // tolerate truncation

  while (i + 4 <= end) {
    uint16_t etype = (uint16_t)((p[i] << 8) | p[i + 1]);
    uint16_t elen  = (uint16_t)((p[i + 2] << 8) | p[i + 3]);
    i += 4;
    if (i + elen > end) break;
    if (etype == 0x0000) {                          // server_name
      // RFC 6066: extension_data IS the ServerNameList, so it starts directly
      // with ServerName: name_type(1) + length(2) + name.  There is NO extra
      // outer length field; skipping two bytes here (as an earlier revision
      // did) shifts everything and the first two hostname characters get read
      // as the type field.  See tools/test_sni_parser.py for the regression test.
      uint32_t q = i;
      if (q + 3 > end) break;
      uint8_t ntype = p[q++];
      uint16_t nlen = (uint16_t)((p[q] << 8) | p[q + 1]);
      q += 2;
      if (ntype == 0 && q + nlen <= end) {
        uint16_t k = nlen < outsz - 1 ? nlen : outsz - 1;
        memcpy(out, p + q, k);
        out[k] = 0;
        for (uint16_t z = 0; z < k; z++) {
          if (out[z] < 32 || out[z] > 126) out[z] = '?';
        }
        return k;
      }
    }
    i += elen;
  }
  return 0;
}

// Extract the Host header from a plaintext HTTP request.
static uint16_t http_host(const uint8_t *p, uint16_t n, char *out, uint16_t outsz) {
  if (n < 16) return 0;
  if (memcmp(p, "GET ", 4) && memcmp(p, "POST", 4) && memcmp(p, "HEAD", 4) &&
      memcmp(p, "PUT ", 4) && memcmp(p, "CONN", 4)) return 0;
  for (uint16_t i = 0; i + 6 < n; i++) {
    if ((p[i] == 'H' || p[i] == 'h') &&
        (p[i + 1] == 'o' || p[i + 1] == 'O') &&
        (p[i + 2] == 's' || p[i + 2] == 'S') &&
        (p[i + 3] == 't' || p[i + 3] == 'T') && p[i + 4] == ':') {
      uint16_t j = i + 5;
      while (j < n && (p[j] == ' ' || p[j] == '\t')) j++;
      uint16_t k = 0;
      while (j < n && k < outsz - 1) {
        char c = (char)p[j++];
        if (c == '\r' || c == '\n') break;
        if (c == ':') break;                        // drop the port
        if (c < 32 || c > 126) break;
        out[k++] = c;
      }
      out[k] = 0;
      return k;
    }
  }
  return 0;
}

// For data frames, reach the IP header through the LLC/SNAP shim.
// Returns the ethertype (0x0800 IPv4, 0x0806 ARP) or 0 when absent.
static uint16_t llc_ethertype(const uint8_t *f, uint16_t len, uint16_t *ipoff) {
  uint16_t hdr = 24;
  bool qos = false;
  if (len < 26) return 0;
  uint8_t subtype = (f[0] >> 4) & 0x0F;
  if ((f[0] & 0x0C) == 0x08 && (subtype & 0x08)) qos = true;   // QoS data
  if (qos) hdr += 2;
  if (hdr + 8 > len) return 0;
  // LLC/SNAP: AA AA 03 00 00 00 <ethertype>
  if (f[hdr] != 0xAA || f[hdr + 1] != 0xAA) return 0;
  uint16_t et = (uint16_t)((f[hdr + 6] << 8) | f[hdr + 7]);
  *ipoff = hdr + 8;
  return et;
}

// ---------------------------------------------------------------------------
// promiscuous callback
// ---------------------------------------------------------------------------
static char line[360];

static void IRAM_ATTR sniffer_cb(void *buf, wifi_promiscuous_pkt_type_t type) {
  const wifi_promiscuous_pkt_t *pkt = (const wifi_promiscuous_pkt_t *)buf;
  const uint8_t *f = pkt->payload;
  uint16_t len = pkt->rx_ctrl.sig_len;

  c_pkts++;
  c_bytes += len;
  if (type == WIFI_PKT_MGMT) c_mgmt++;
  else if (type == WIFI_PKT_CTRL) c_ctrl++;
  else c_data++;
  if (type == WIFI_PKT_CTRL) return;
  if (len < 10) return;

  uint8_t ftype = (f[0] >> 2) & 0x03;
  uint8_t sub   = (f[0] >> 4) & 0x0F;

  char a1[18], a2[18], a3[18];
  mac_str(f + 4, a1);
  mac_str(f + 10, a2);
  mac_str(f + 16, a3);

  // ---- who does this frame belong to? ----
  bool ours = false;
  bool from_our_client = false;
  uint8_t client_mac[6];
  memset(client_mac, 0, 6);

  if (ap_bssid_valid) {
    if (memcmp(f + 16, ap_bssid, 6) == 0 ||
        memcmp(f + 4,  ap_bssid, 6) == 0 ||
        memcmp(f + 10, ap_bssid, 6) == 0) {
      ours = true;
    } else {
      portENTER_CRITICAL(&stMux);
      for (int k = 0; k < AP_MAX_STA; k++) {
        if (!clients[k].used) continue;
        if (memcmp(f + 10, clients[k].mac, 6) == 0 ||
            memcmp(f + 4,  clients[k].mac, 6) == 0) {
          ours = true;
          from_our_client = true;
          memcpy(client_mac, clients[k].mac, 6);
          clients[k].frames++;
          clients[k].rssi = pkt->rx_ctrl.rssi;
          break;
        }
      }
      portEXIT_CRITICAL(&stMux);
    }
  }

  // ---- decode events worth their own line ----
  if (ftype == 2 && ours) {
    uint16_t ipoff = 0;
    uint16_t et = llc_ethertype(f, len, &ipoff);
    if (et == 0x0806 && ipoff + 28 <= len) {                 // ARP
      const uint8_t *a = f + ipoff;
      if (a[6] == 0 && a[7] == 1 && a[8] == 8) {             // request, IPv4
        char sender_ip[20], sender_mac[18];
        sprintf(sender_ip, "%u.%u.%u.%u", a[14], a[15], a[16], a[17]);
        mac_str(a + 8, sender_mac);
        // remember the binding so later events can show an IP
        portENTER_CRITICAL(&stMux);
        StaRec *c = client_find(a + 8);
        if (c && (uint32_t)c->ip == 0) c->ip = IPAddress(a[14], a[15], a[16], a[17]);
        portEXIT_CRITICAL(&stMux);
        push_eventf("ARP", "ip=%s mac=%s", sender_ip, sender_mac);
      }
    } else if (et == 0x0800 && ipoff + 20 <= len) {           // IPv4
      const uint8_t *ip = f + ipoff;
      uint8_t proto = ip[9];
      const uint16_t ihl = (uint16_t)((ip[0] & 0x0F) * 4);
      if (proto == 1 && ihl >= 20 && ipoff + ihl + 8 <= len) {   // ICMP
        const uint8_t *icmp = ip + ihl;
        uint8_t icmp_type = icmp[0];
        char src[20], dst[20];
        sprintf(src, "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
        sprintf(dst, "%u.%u.%u.%u", ip[16], ip[17], ip[18], ip[19]);
        push_eventf("PING", "ev=%s mac=%s src=%s dst=%s",
                    icmp_type == 8 ? "echo-request" :
                    icmp_type == 0 ? "echo-reply" : "other",
                    from_our_client ? a2 : "-", src, dst);
      } else if (proto == 6 && ihl >= 20 && ipoff + ihl + 20 <= len) {  // TCP
        const uint8_t *tcp = ip + ihl;
        const uint16_t thl = (uint16_t)(((tcp[12] >> 4) & 0x0F) * 4);
        const uint16_t dport = (uint16_t)((tcp[2] << 8) | tcp[3]);
        if (thl >= 20 && ipoff + ihl + thl <= len) {
          const uint8_t *play = tcp + thl;
          uint16_t plen = (uint16_t)(len - (ipoff + ihl + thl));
          if (plen > 0 && plen < 1200) {
            char host[128];
            bool is_tls = false;
            uint16_t hl = 0;
            if (plen > 6 && play[0] == 0x16 && play[5] == 0x01) {
              hl = tls_sni(play, plen, host, sizeof(host));
              is_tls = true;
            } else if (dport == 80 || dport == 8080) {
              hl = http_host(play, plen, host, sizeof(host));
            }
            if (hl > 0) {
              char src[20], dst[20];
              sprintf(src, "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
              sprintf(dst, "%u.%u.%u.%u", ip[16], ip[17], ip[18], ip[19]);
              // The most useful record this firmware produces: which server the
              // device is actually opening a connection to.  Queued so it lands
              // in both the cmd window and the standalone dashboard.
              remember_host(host);
              push_eventf("TLS", "via=%s mac=%s ip=%s port=%u host=%s dst=%s",
                          is_tls ? "tls-sni" : "http-host",
                          from_our_client ? a2 : "-", src,
                          (unsigned)dport, host, dst);
              c_hosts++;
            } else if (g_hostdbg && plen >= 6) {
              // Diagnostic: show why a candidate frame did not yield a host, so
              // "no SNI" can be told apart from "no frames".
              char src[20];
              sprintf(src, "%u.%u.%u.%u", ip[12], ip[13], ip[14], ip[15]);
              char hex[3 * 16 + 1];
              int k = 0;
              for (uint16_t z = 0; z < 16 && z < plen; z++)
                k += snprintf(hex + k, sizeof(hex) - k, "%02x ", play[z]);
              char out[220];
              int n = snprintf(out, sizeof(out),
                               "@HOSTDBG mac=%s ip=%s dport=%u plen=%u tls=%d head=%s\n",
                               from_our_client ? a2 : "-", src,
                               (unsigned)dport, (unsigned)plen, is_tls ? 1 : 0, hex);
              if (Serial.availableForWrite() >= n) Serial.write((const uint8_t *)out, n);
            }
          }
        }
      }
    }
  }

  // ---- hostname from probe/assoc requests ----
  char info[160];
  info[0] = 0;
  if (ftype == 0 && (sub == 4 || sub == 0 || sub == 2) && len > 26) {
    uint16_t off = 24;
    while (off + 2 <= len) {
      uint8_t id = f[off], elen = f[off + 1];
      if (off + 2 + elen > len) break;
      if (id == 0 && elen > 0) {
        char ssid[33];
        uint8_t k = elen > 32 ? 32 : elen;
        memcpy(ssid, f + off + 2, k);
        ssid[k] = 0;
        for (uint8_t z = 0; z < k; z++) {
          if (ssid[z] < 32 || ssid[z] > 126) ssid[z] = '?';
          else if (ssid[z] == '"') ssid[z] = '\'';
        }
        snprintf(info, sizeof(info), "ssid=\"%s\"", ssid);
        break;
      }
      off += 2 + elen;
    }
  } else if (ftype == 2 && PRINT_PAYLOAD && len > 24) {
    uint16_t avail = len - 24;
    if (avail > PAYLOAD_MAX) avail = PAYLOAD_MAX;
    const uint8_t *p = f + 24;
    int printable = 0;
    for (uint16_t i = 0; i < avail; i++) if (p[i] >= 32 && p[i] < 127) printable++;
    if (printable >= avail / 2) {
      char txt[PAYLOAD_MAX + 1];
      uint16_t k = 0;
      for (uint16_t i = 0; i < avail && k < PAYLOAD_MAX; i++) {
        char c = (char)p[i];
        txt[k++] = (c >= 32 && c < 127) ? c : '.';
      }
      txt[k] = 0;
      for (uint16_t i = 0; i < k; i++) if (txt[i] == '"') txt[i] = '\'';
      snprintf(info, sizeof(info), "text=\"%s\"", txt);
    }
  }

  bool wants_us = info[0] && strstr(info, AP_SSID) != nullptr;

  if (!ours && !wants_us) {
    c_foreign++;
    if (!g_show_foreign) return;
    static uint32_t fb = 0, fd = 0;
    if (ftype == 0 && sub == 8) { if ((++fb % OTHER_BEACON_SAMPLE) != 0) return; }
    else if (ftype == 2) { if ((++fd % OTHER_DATA_SAMPLE) != 0) return; }
    else return;
  } else {
    c_ours++;
  }

  uint16_t seq = (uint16_t)((f[22] | (f[23] << 8)) >> 4);
  int n = snprintf(line, sizeof(line),
                   "@PKT t=%s a1=%s a2=%s a3=%s rssi=%d ch=%u len=%u seq=%u%s%s\n",
                   frame_type_name(sub, ftype), a1, a2, a3,
                   pkt->rx_ctrl.rssi, pkt->rx_ctrl.channel, len, seq,
                   info[0] ? " " : "", info);
  if (n > 0) {
    if (!Serial.availableForWrite() || Serial.availableForWrite() < n) c_serial_drop++;
    else Serial.write((const uint8_t *)line, n);
  }
}

static void startSniffer() {
  wifi_promiscuous_filter_t filter = {};
  filter.filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT | WIFI_PROMIS_FILTER_MASK_DATA;
  esp_wifi_set_promiscuous_filter(&filter);
  esp_wifi_set_promiscuous_rx_cb(&sniffer_cb);
  esp_wifi_set_promiscuous(true);
  esp_wifi_set_channel(AP_CHANNEL, WIFI_SECOND_CHAN_NONE);
}

// ---------------------------------------------------------------------------
// station join / leave
// ---------------------------------------------------------------------------
static void onStaJoin() {
  wifi_sta_list_t list;
  if (esp_wifi_ap_get_sta_list(&list) != ESP_OK) return;
  for (int i = 0; i < list.num; i++) {
    const uint8_t *m = list.sta[i].mac;
    bool known;
    portENTER_CRITICAL(&stMux);
    known = client_find(m) != nullptr;
    if (!known) {
      StaRec *c = client_add(m);
      if (c) c->rssi = list.sta[i].rssi;
    }
    portEXIT_CRITICAL(&stMux);
    if (!known) {
      char ms[18];
      mac_str(m, ms);
      push_eventf("STA", "ev=join mac=%s rssi=%d", ms, list.sta[i].rssi);
    }
  }
}

static void onStaLeave() {
  wifi_sta_list_t list;
  esp_wifi_ap_get_sta_list(&list);
  portENTER_CRITICAL(&stMux);
  for (int k = 0; k < AP_MAX_STA; k++) {
    if (!clients[k].used) continue;
    bool still = false;
    for (int i = 0; i < list.num; i++) {
      if (memcmp(list.sta[i].mac, clients[k].mac, 6) == 0) { still = true; break; }
    }
    if (!still) {
      char ms[18];
      mac_str(clients[k].mac, ms);
      push_eventf("STA", "ev=leave mac=%s", ms);
    }
  }
  portEXIT_CRITICAL(&stMux);
}

// ---------------------------------------------------------------------------
// flash log + web console (the standalone half of the dual output)
// ---------------------------------------------------------------------------
static void storage_init() {
  // The stock 16MB partition table labels the filesystem "spiffs" even though we
  // format it as LittleFS; that label is what LittleFS.begin() looks for.
  fs_ok = LittleFS.begin(true, "/littlefs", 10, "spiffs");
  if (!fs_ok) {
    Serial.println("@FS mount failed - flash logging disabled, cmd output still works");
    return;
  }
  Serial.printf("@FS ready: %u KB total, %u KB used, log=%s\n",
                (unsigned)(LittleFS.totalBytes() / 1024),
                (unsigned)(LittleFS.usedBytes() / 1024), LOG_PATH);
}

static void log_line(const char *line) {
  if (!fs_ok) return;
  File f = LittleFS.open(LOG_PATH, "a");
  if (!f) return;
  if (f.size() > LOG_MAX_BYTES) {
    f.close();
    LittleFS.remove(LOG_PATH);           // bounded: restart when it grows too big
    f = LittleFS.open(LOG_PATH, "a");
    if (!f) return;
    f.print("# --- log rotated ---\n");
  }
  f.print(line);
  f.print('\n');
  log_written++;
  f.close();
}

#include "web_page.h"   // the dashboard HTML, kept out of this file
#include "admin_page.h" // the admin panel HTML
#include "juice.h"      // Apple proximity BLE advertiser, admin-triggered only
#include <mbedtls/sha1.h>   // for the admin password hash

// Escape a value for embedding in the JSON payload.
static String jesc(const char *s) {
  String o;
  for (const char *p = s; p && *p; p++) {
    switch (*p) {
      case '"':  o += "\\\""; break;
      case '\\': o += "\\\\"; break;
      case '\n': o += "\\n";  break;
      case '\r': break;
      case '\t': o += ' ';    break;
      default:
        if ((uint8_t)*p < 0x20) o += ' ';
        else o += *p;
    }
  }
  return o;
}

static void handle_root() {
  web.sendHeader("Cache-Control", "no-store");
  web.send_P(200, "text/html", PAGE_HTML);
}

static void handle_api() {
  String j = "{";
  wifi_sta_list_t list;
  int ncli = 0;
  if (esp_wifi_ap_get_sta_list(&list) == ESP_OK) ncli = list.num;

  j += "\"clients\":" + String(ncli);
  j += ",\"frames\":" + String((unsigned long)c_pkts);
  j += ",\"ours\":" + String((unsigned long)c_ours);
  j += ",\"foreign\":" + String((unsigned long)c_foreign);
  j += ",\"serdrop\":" + String((unsigned long)c_serial_drop);
  j += ",\"uptime\":" + String(millis() / 1000);
  j += ",\"logged\":" + String((unsigned long)log_written);

  // Public, and deliberately so: the dashboard shows a banner while the BLE
  // advertiser is transmitting.  A transmitting radio that the monitor page
  // does not mention is worse than one the whole LAN can see.
  {
    bool running;
    uint32_t left, cyc, errs;
    const char *tpl, *err;
    juice_get(running, left, cyc, errs, tpl, err);
    j += ",\"juice\":{\"on\":" + String(running ? "true" : "false") +
         ",\"left\":" + String(left) +
         ",\"cycles\":" + String(cyc) +
         ",\"errors\":" + String(errs) +
         ",\"tpl\":\"" + jesc(tpl) + "\"}";
  }

  j += ",\"devices\":[";
  portENTER_CRITICAL(&stMux);
  bool first = true;
  for (int i = 0; i < AP_MAX_STA; i++) {
    if (!clients[i].used) continue;
    char ms[18], ips[20];
    mac_str(clients[i].mac, ms);
    if ((uint32_t)clients[i].ip != 0) ip_str(clients[i].ip, ips);
    else strcpy(ips, "-");
    if (!first) j += ",";
    first = false;
    j += "{\"mac\":\"" + String(ms) + "\",\"ip\":\"" + String(ips) +
         "\",\"host\":\"" + jesc(clients[i].host) + "\",\"rssi\":" +
         String(clients[i].rssi) + ",\"frames\":" +
         String((unsigned long)clients[i].frames) + "}";
  }
  portEXIT_CRITICAL(&stMux);
  j += "]";

  j += ",\"hosts\":[";
  portENTER_CRITICAL(&hostMux);
  bool firstH = true;
  for (int i = 0; i < host_n; i++) {
    int idx = (host_head - 1 - i + HOST_RING * 2) % HOST_RING;   // newest first
    if (!hosts_seen[idx].used) continue;
    if (!firstH) j += ",";
    firstH = false;
    j += "{\"host\":\"" + jesc(hosts_seen[idx].name) +
         "\",\"service\":\"" + jesc(hosts_seen[idx].service) +
         "\",\"n\":" + String(hosts_seen[idx].hits) +
         ",\"last\":" + String(hosts_seen[idx].last) + "}";
  }
  portEXIT_CRITICAL(&hostMux);
  j += "]";

  j += ",\"events\":[";
  int cnt, start;
  portENTER_CRITICAL(&evMux);
  cnt = ev_count;
  start = (ev_head - cnt + EV_RING) % EV_RING;
  portEXIT_CRITICAL(&evMux);
  int shown = cnt < 40 ? cnt : 40;
  for (int i = cnt - shown; i < cnt; i++) {
    int idx = (start + i) % EV_RING;
    char buf[EV_LEN];
    portENTER_CRITICAL(&evMux);
    strncpy(buf, ev_ring[idx], EV_LEN - 1);
    buf[EV_LEN - 1] = 0;
    portEXIT_CRITICAL(&evMux);

    char *k = buf;
    char *t = strchr(buf, '\t');
    if (!t) continue;
    *t++ = 0;
    char *m = strchr(t, '\t');
    if (!m) continue;
    *m++ = 0;

    if (i > cnt - shown) j += ",";
    j += "{\"k\":\"" + jesc(k) + "\",\"t\":" + String(t) + ",\"m\":\"" + jesc(m) + "\"}";
  }
  j += "]";

  j += "}";
  web.sendHeader("Cache-Control", "no-store");
  web.send(200, "application/json", j);
}

static void handle_log() {
  if (!fs_ok || !LittleFS.exists(LOG_PATH)) {
    web.send(200, "text/plain", "no log yet\n");
    return;
  }
  File f = LittleFS.open(LOG_PATH, "r");
  web.sendHeader("Content-Disposition", "attachment; filename=events.log");
  web.streamFile(f, "text/plain");
  f.close();
}

static void web_init() {
  web.on("/", handle_root);
  web.on("/api", handle_api);
  web.on("/events.log", handle_log);
  // Unknown paths fall back to the dashboard; with the catch-all DNS this gives
  // the familiar captive-portal behaviour when a phone probes for connectivity.
  web.onNotFound(handle_root);
  web.begin();
  Serial.println("@WEB http://192.168.4.1/  (/api JSON, /events.log download)");
}

// Drain the event queue: one record, two outputs.
static void pump_events() {
  static int drained = 0;
  int cnt, start;
  portENTER_CRITICAL(&evMux);
  cnt = ev_count;
  start = (ev_head - cnt + EV_RING) % EV_RING;
  portEXIT_CRITICAL(&evMux);

  if (cnt < drained) drained = 0;
  while (drained < cnt) {
    int idx = (start + drained) % EV_RING;
    drained++;
    char buf[EV_LEN];
    portENTER_CRITICAL(&evMux);
    strncpy(buf, ev_ring[idx], EV_LEN - 1);
    buf[EV_LEN - 1] = 0;
    portEXIT_CRITICAL(&evMux);

    // stored as KIND \t seconds \t message
    char *k = buf;
    char *t = strchr(buf, '\t');
    if (!t) continue;
    *t++ = 0;
    char *m = strchr(t, '\t');
    if (!m) continue;
    *m++ = 0;

    char ser[EV_LEN + 8];
    snprintf(ser, sizeof(ser), "@%s %s\n", k, m);
    Serial.write((const uint8_t *)ser, strlen(ser));      // cmd window

    char logl[EV_LEN + 16];
    snprintf(logl, sizeof(logl), "%s\t%s\t%s", t, k, m);
    log_line(logl);                                        // standalone page
  }
  if (drained > cnt) drained = cnt;
}

// ---------------------------------------------------------------------------
// admin panel: HTTP Basic auth over SHA1, operations from the browser
//
// Only a SHA1 of the password is stored - in flash, once the device has booted -
// so a password change survives a reboot and the plaintext never has to live in
// the binary beyond the first-run default.
// ---------------------------------------------------------------------------
#define ADMIN_USER "admin"
#define ADMIN_DEFAULT_SHA1 "f8708bd13af2ed54859947ddfa116bb59f5c0ab9"  // "1324123"
static const char *ADMIN_HASH_PATH = "/admin.sha1";

static char admin_hash[41] = ADMIN_DEFAULT_SHA1;
static String admin_last_msg = "ready";
static char cfg_ssid[33] = {0};
static char cfg_pass[64] = {0};

static void sha1_hex(const char *in, char *out /* 41 bytes */) {
  unsigned char d[20];
  mbedtls_sha1((const unsigned char *)in, strlen(in), d);
  for (int i = 0; i < 20; i++) sprintf(out + i * 2, "%02x", d[i]);
  out[40] = 0;
}

static void admin_load_hash() {
  if (!fs_ok || !LittleFS.exists(ADMIN_HASH_PATH)) return;
  File f = LittleFS.open(ADMIN_HASH_PATH, "r");
  if (!f) return;
  String s = f.readString();
  f.close();
  s.trim();
  if (s.length() == 40) {
    strncpy(admin_hash, s.c_str(), sizeof(admin_hash) - 1);
    admin_hash[sizeof(admin_hash) - 1] = 0;
    Serial.println("@ADMIN using stored password hash");
  }
}

static void admin_save_hash(const char *plain) {
  sha1_hex(plain, admin_hash);
  if (!fs_ok) return;
  File f = LittleFS.open(ADMIN_HASH_PATH, "w");
  if (!f) return;
  f.print(admin_hash);
  f.close();
  Serial.println("@ADMIN password changed");
}

// Every admin route calls this first; it answers the 401 itself when the
// credentials are missing or wrong, so callers just return.
//
// authenticateBasicSHA1 - NOT authenticate(user, password).  The latter compares
// the supplied password literally, so passing a hash to it can never match; that
// mistake produces a permanent 401 even with the right password.  This variant
// hashes what arrived and compares digests, which is what lets the firmware keep
// only a hash and never the plaintext.
//
// Credentials travel as base64 over plain HTTP (no TLS on this device), so treat
// the panel as trusted-LAN only: anyone who can see the traffic can replay them.
static bool admin_ok() {
  if (web.authenticateBasicSHA1(ADMIN_USER, admin_hash)) return true;
  web.requestAuthentication(BASIC_AUTH, "Test_1101 admin",
                            "authentication required");
  return false;
}

static void handle_admin_state() {
  if (!admin_ok()) return;
  wifi_sta_list_t list;
  int n = 0;
  if (esp_wifi_ap_get_sta_list(&list) == ESP_OK) n = list.num;
  uint32_t logkb = 0;
  if (fs_ok && LittleFS.exists(LOG_PATH)) {
    File f = LittleFS.open(LOG_PATH, "r");
    if (f) { logkb = (f.size() + 1023) / 1024; f.close(); }
  }
  String j = "{";
  j += "\"foreign\":" + String(g_show_foreign ? "true" : "false");
  j += ",\"hostdbg\":" + String(g_hostdbg ? "true" : "false");
  // juice= is parsed here as well as in /admin/act because page reloads and
  // bookmarks land on this route, and a GET that quietly switched a radio
  // transmitter on would be a nasty surprise.  Explicit, and logged either way.
  if (web.hasArg("juice")) {
    bool want = web.arg("juice") == "on";
    bool running;
    uint32_t left, cyc, errs;
    const char *tpl, *err;
    juice_get(running, left, cyc, errs, tpl, err);
    if (want != running) {
      uint32_t rem = 0;
      juice_set_enabled(want, &rem);
      Serial.printf("@ADMIN juice=%s requested over GET\n", want ? "on" : "off");
    }
  }
  {
    bool running;
    uint32_t left, cyc, errs;
    const char *tpl, *err;
    juice_get(running, left, cyc, errs, tpl, err);
    j += ",\"juice\":" + String(running ? "true" : "false");
    j += ",\"juice_left\":" + String(left);
    j += ",\"juice_cycles\":" + String(cyc);
    j += ",\"juice_errors\":" + String(errs);
    j += ",\"juice_tpl\":\"" + jesc(tpl) + "\"";
    j += ",\"juice_err\":\"" + jesc(err) + "\"";
    j += ",\"juice_window\":" + String((unsigned long)(JUICE_WAKE_MS / 1000));
    j += ",\"juice_tx\":" + String((int)juice_power_dbm_get());
  }
  j += ",\"ssid\":\"" + jesc(cfg_ssid) + "\"";
  j += ",\"channel\":" + String(AP_CHANNEL);
  j += ",\"log_kb\":" + String(logkb);
  j += ",\"heap_kb\":" + String(ESP.getFreeHeap() / 1024);
  j += ",\"clients\":" + String(n);
  j += ",\"msg\":\"" + jesc(admin_last_msg.c_str()) + "\"";
  j += "}";
  web.sendHeader("Cache-Control", "no-store");
  web.send(200, "application/json", j);
}

static void handle_admin_act() {
  if (!admin_ok()) return;
  String a = web.arg("a");
  String out;

  if (a == "foreign") {
    g_show_foreign = !g_show_foreign;
    out = g_show_foreign ? "all frames: ON (other networks included)"
                         : "all frames: OFF (own clients only)";
  } else if (a == "hostdbg") {
    g_hostdbg = !g_hostdbg;
    out = g_hostdbg ? "host debug: ON" : "host debug: OFF";
  } else if (a == "juice") {
    // Toggle, but the OFF path is also the one the watchdog uses, so a second
    // click always stops the transmitter no matter what state it thinks it is in.
    bool running;
    uint32_t left, cyc, errs;
    const char *tpl, *err;
    juice_get(running, left, cyc, errs, tpl, err);
    uint32_t rem = 0;
    bool want = !running;
    bool ok = juice_set_enabled(want, &rem);
    if (want && !ok) {
      out = "BLE advertiser failed to start (see log)";
    } else if (!want && !running) {
      out = "BLE advertiser is already off";
    } else if (want) {
      out = String("BLE advertiser ON for ") + String(JUICE_WAKE_MS / 1000) +
            "s - pairing prompts will appear on Apple devices in range";
    } else {
      out = "BLE advertiser OFF";
    }
  } else if (a == "juicetx") {
    // Step the transmit power and apply it immediately, without restarting the
    // advertiser, so the effect on a phone in the room can be watched live.
    int8_t next = juice_next_power_dbm();
    juice_set_power_dbm(next);
    out = String("BLE transmit power: ") + String((int)next) + " dBm";
    Serial.printf("@ADMIN %s\n", out.c_str());
    juice_logf("tx power -> %d dBm", (int)next);
  } else if (a == "clearlog") {
    if (fs_ok && LittleFS.exists(LOG_PATH)) LittleFS.remove(LOG_PATH);
    log_written = 0;
    out = "log cleared";
  } else if (a == "applyap") {
    String ssid = web.arg("ssid");
    String pw = web.arg("pw");
    if (ssid.length() == 0 || ssid.length() > 32) {
      out = "SSID must be 1..32 characters";
    } else if (pw.length() > 0 && pw.length() < 8) {
      out = "WPA password needs at least 8 characters (or leave blank for open)";
    } else {
      strncpy(cfg_ssid, ssid.c_str(), sizeof(cfg_ssid) - 1);
      cfg_ssid[sizeof(cfg_ssid) - 1] = 0;
      strncpy(cfg_pass, pw.c_str(), sizeof(cfg_pass) - 1);
      cfg_pass[sizeof(cfg_pass) - 1] = 0;
      // Answer first: reconfiguring the radio drops the very link carrying this
      // request, so the reply has to be on the wire before softAP() is called.
      web.send(200, "text/plain",
               "applying - the radio restarts and clients must rejoin");
      delay(250);
      WiFi.softAP(cfg_ssid, strlen(cfg_pass) ? cfg_pass : NULL,
                  AP_CHANNEL, 0, AP_MAX_STA);
      Serial.printf("@ADMIN AP reconfigured: ssid=%s auth=%s\n",
                    cfg_ssid, strlen(cfg_pass) ? "wpa2" : "open");
      return;
    }
  } else if (a == "reboot") {
    web.send(200, "text/plain", "rebooting...");
    delay(200);
    ESP.restart();
    return;
  } else {
    out = "unknown action";
  }

  admin_last_msg = out;
  Serial.printf("@ADMIN %s\n", out.c_str());
  web.send(200, "text/plain", out);
}

static void handle_admin_page() {
  if (!admin_ok()) return;
  web.sendHeader("Cache-Control", "no-store");
  web.send_P(200, "text/html", ADMIN_HTML);
}

static void admin_init() {
  strncpy(cfg_ssid, AP_SSID, sizeof(cfg_ssid) - 1);
  cfg_pass[0] = 0;                             // default: open network
  admin_load_hash();
  web.on("/admin", handle_admin_page);
  web.on("/admin/state", handle_admin_state);
  web.on("/admin/act", HTTP_POST, handle_admin_act);
  Serial.printf("@ADMIN panel at /admin (user=%s)\n", ADMIN_USER);
}

// ---------------------------------------------------------------------------
void setup() {
  Serial.begin(115200);
  delay(400);

  Serial.println();
  Serial.println("@BOOT sniffer-ap Test_1101");
  Serial.printf("@BOOT fw=%s %s\n", __DATE__, __TIME__);
  Serial.println("@BOOT NOTE: for lab testing of your own devices only.");

  WiFi.mode(WIFI_AP);
  WiFi.softAPConfig(AP_IP, AP_IP, AP_MASK);

  if (!WiFi.softAP(AP_SSID, AP_PASS, AP_CHANNEL, 0, AP_MAX_STA)) {
    Serial.println("@ERR softAP failed");
    return;
  }

  // Deliberately no enableNAPT(): the ESP32 will not route client traffic,
  // which is what makes the network a dead end while still accepting clients.

  memset(clients, 0, sizeof(clients));
  dhcp.begin(67);
  dnsSrv.begin(53);

  oled_init();
  oled_show_status(0, 0, 0);        // show "no one connected" immediately

  if (esp_wifi_get_mac(WIFI_IF_AP, ap_bssid) == ESP_OK) {
    ap_bssid_valid = true;
    char bs[18];
    mac_str(ap_bssid, bs);
    Serial.printf("@BOOT bssid=%s\n", bs);
  }

  startSniffer();

  // Standalone half: mount the flash log and start the dashboard.  Both outputs
  // stay live, so the cmd window and the web page show the same events.
  storage_init();
  web_init();
  admin_init();

  char ip[20];
  ip_str(AP_IP, ip);
  Serial.printf("@AP ssid=%s ch=%u ip=%s open=1 napt=off dhcp=on\n",
                AP_SSID, AP_CHANNEL, ip);
  Serial.println("@BOOT clients get an address but no route out (no NAT)");
  Serial.println("@BOOT standalone mode: power from any charger, then open the web UI");

  WiFi.onEvent([](WiFiEvent_t e, WiFiEventInfo_t i) {
    if (e == ARDUINO_EVENT_WIFI_AP_STACONNECTED) onStaJoin();
    else if (e == ARDUINO_EVENT_WIFI_AP_STADISCONNECTED) onStaLeave();
  });

  Serial.println("@READY");
}

static uint32_t last_stat = 0;
static uint32_t last_devdump = 0;

// Redraw only when something visible changed: the panel costs an I2C transfer
// and the WiFi sniffer matters more.
static void oled_tick(int nclients) {
#if OLED_ENABLE
  static int last_clients = -1;
  static uint32_t last_frames = 0;
  if (last_clients == nclients && (c_pkts - last_frames) < 2000) return;
  last_clients = nclients;
  last_frames = c_pkts;
  oled_show_status(nclients, c_pkts, c_hosts);
#endif
}

// Snapshot of the client table, sent only when it actually changes.
// Repeating it every couple of seconds flooded the console and the CSV with
// identical rows, burying the events that matter.
static void dump_devices() {
  static uint32_t last_sig = 0xFFFFFFFF;
  uint32_t sig = 2166136261u;                     // FNV-1a over the table

  portENTER_CRITICAL(&stMux);
  for (int i = 0; i < AP_MAX_STA; i++) {
    if (!clients[i].used) continue;
    for (int k = 0; k < 6; k++) sig = (sig ^ clients[i].mac[k]) * 16777619u;
    sig = (sig ^ (uint32_t)clients[i].ip) * 16777619u;
    for (const char *h = clients[i].host; *h; h++) sig = (sig ^ (uint8_t)*h) * 16777619u;
  }
  int n = 0;
  for (int i = 0; i < AP_MAX_STA; i++) if (clients[i].used) n++;
  sig = (sig ^ (uint32_t)n) * 16777619u;
  portEXIT_CRITICAL(&stMux);

  if (sig == last_sig) return;
  last_sig = sig;

  portENTER_CRITICAL(&stMux);
  Serial.printf("@DEVCOUNT n=%d\n", n);
  for (int i = 0; i < AP_MAX_STA; i++) {
    if (!clients[i].used) continue;
    char ms[18], ips[20];
    mac_str(clients[i].mac, ms);
    if ((uint32_t)clients[i].ip != 0) ip_str(clients[i].ip, ips);
    else strcpy(ips, "-");
    Serial.printf("@DEV mac=%s ip=%s host=\"%s\" rssi=%d frames=%lu\n",
                  ms, ips, clients[i].host, clients[i].rssi,
                  (unsigned long)clients[i].frames);
  }
  portEXIT_CRITICAL(&stMux);
}

void loop() {
  // serve the standalone dashboard first: it is what a phone talks to
  web.handleClient();

  dhcp_handle();
  dns_handle();
  pump_events();            // one queue -> serial (cmd) + flash (web)
  juice_tick();             // rotates the BLE payload, enforces the auto-off

  uint32_t now = millis();
  if (now - last_devdump >= STAT_INTERVAL_MS) {
    last_devdump = now;
    dump_devices();
  }
  if (now - last_stat >= STAT_INTERVAL_MS) {
    last_stat = now;
    wifi_sta_list_t list;
    int n = 0;
    if (esp_wifi_ap_get_sta_list(&list) == ESP_OK) n = list.num;
    oled_tick(n);                     // panel follows the live client count
    Serial.printf("@STAT pkts=%lu ours=%lu foreign=%lu mgmt=%lu ctrl=%lu data=%lu "
                  "bytes=%lu serdrop=%lu clients=%d foreign_shown=%d\n",
                  (unsigned long)c_pkts, (unsigned long)c_ours, (unsigned long)c_foreign,
                  (unsigned long)c_mgmt, (unsigned long)c_ctrl, (unsigned long)c_data,
                  (unsigned long)c_bytes, (unsigned long)c_serial_drop, n,
                  g_show_foreign ? 1 : 0);
  }

  static char cmd[64];
  static uint8_t cmdlen = 0;
  while (Serial.available()) {
    char ch = (char)Serial.read();
    if (ch == '\n' || ch == '\r') {
      cmd[cmdlen] = 0;
      if (cmdlen > 4 && strncmp(cmd, "@CMD", 4) == 0) {
        if (strstr(cmd, "foreign=on")) { g_show_foreign = true; Serial.println("@ACK foreign=on"); }
        else if (strstr(cmd, "foreign=off")) { g_show_foreign = false; Serial.println("@ACK foreign=off"); }
        else if (strstr(cmd, "hostdbg=on")) { g_hostdbg = true; Serial.println("@ACK hostdbg=on"); }
        else if (strstr(cmd, "hostdbg=off")) { g_hostdbg = false; Serial.println("@ACK hostdbg=off"); }
        else if (strstr(cmd, "juice=on")) {
          uint32_t rem = 0;
          bool ok = juice_set_enabled(true, &rem);
          Serial.printf("@ACK juice=on%s\n", ok ? "" : " failed");
        }
        else if (strstr(cmd, "juice=off")) {
          uint32_t rem = 0;
          juice_set_enabled(false, &rem);
          Serial.println("@ACK juice=off");
        }
        else if (strstr(cmd, "juice=tx")) {
          // juice=tx=N sets an exact dBm; bare juice=tx steps to the next preset.
          int8_t dbm = juice_next_power_dbm();
          const char *eq = strchr(cmd, '=');
          if (eq && eq[1] == 't' && eq[2] == 'x' && eq[3] == '=' && eq[4]) {
            dbm = (int8_t)atoi(eq + 4);
          }
          juice_set_power_dbm(dbm);
          Serial.printf("@ACK juice=tx=%d applied=%d\n", (int)dbm, (int)juice_power_dbm_get());
        }
        else if (strstr(cmd, "juice=verbose")) {
          juice_set_log_packets(true);
          Serial.println("@ACK juice=verbose on");
        }
        else if (strstr(cmd, "juice=quiet")) {
          juice_set_log_packets(false);
          Serial.println("@ACK juice=verbose off");
        }
        else if (strstr(cmd, "oledsweep")) { Serial.println("@ACK oledsweep"); oled_profile_sweep(strstr(cmd, "slow") ? 4000 : 600); }
        else Serial.println("@ACK unknown");
      }
      cmdlen = 0;
    } else if (cmdlen < sizeof(cmd) - 1) {
      cmd[cmdlen++] = ch;
    }
  }
  delay(2);
}











