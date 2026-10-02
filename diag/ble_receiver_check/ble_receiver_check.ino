/*
 * Scratch diagnostic - NOT part of the project firmware.
 *
 * Why it exists
 *   "No popup on the iPhone" has two very different causes: the packets never
 *   reach the air, or they do and iOS ignores them.  This separates the two by
 *   listening instead of guessing, and it is the only tool here that can prove
 *   what the ESP32 actually radiates.
 *
 * What it does, in order, on one boot:
 *   1. SCAN, 20 s - list every advertisement whose manufacturer data carries
 *      Apple's company id 0x004C, decoded far enough to name the Continuity
 *      message type and the model id.  Any Apple device in the room shows up
 *      here, so an empty list means nothing is being heard at all.
 *   2. ADVERTISE, 30 s - send exactly the packets juice.h sends, so a phone can
 *      be held against the board during this window and the operator can say
 *      whether a prompt appeared.
 *   3. SCAN, 20 s - if our own 0x07 packets come back here, the radio is
 *      radiating them and any remaining problem is on the receiving side.
 *      A phone that consumed a prompt in phase 2 does not show up as a scan hit,
 *      so an empty phase 3 is not by itself a failure - phase 1 is the control.
 *
 * Scanning and advertising cannot overlap: one radio, and NimBLE will not run
 * both.  That is why the phases are sequential.
 *
 * Advertising mode note, learned the hard way (see wifi_sniffer/juice.h):
 *   BLEAdvertising::setAdvertisementType() writes the BLUEDROID enum value
 *   straight into NimBLE's conn_mode, and the two disagree:
 *       0x00 -> conn_mode 0 = BLE_GAP_CONN_MODE_NON   (non-connectable)
 *       0x02 -> conn_mode 2 = BLE_GAP_CONN_MODE_UND   (connectable)
 *       0x03 -> conn_mode 3 = invalid                 (BLE_HS_EINVAL, rc=3)
 *   So 0x00 plus setScanResponse(false) is what produces a true
 *   ADV_NONCONN_IND.  The flags byte in the payload must match: BR/EDR-not-
 *   supported only (0x04), not "general discoverable" (0x06).
 *
 * Serial 115200, output prefixed @RX.
 */
#include <BLEDevice.h>
#include <BLEAdvertising.h>
#include <BLEScan.h>
#include <BLEAdvertisedDevice.h>

static const uint32_t SCAN1_SECONDS = 20;
static const uint32_t ADV_SECONDS = 30;
static const uint32_t SCAN2_SECONDS = 20;
static const uint32_t ADV_ROT_MS = 300;

// The same raw PDUs juice.h uses: flags + Apple manufacturer data, rebuilt with
// a correct AD length byte.  Flags are 0x04 here: BR/EDR not supported, and
// deliberately NOT the discoverable bit, because a non-connectable,
// non-scannable broadcaster is by definition not discoverable.
static const uint8_t ADV_FLAGS = 0x04;

// The same raw PDUs juice.h uses: flags + Apple manufacturer data, rebuilt with
// a correct AD length byte.
struct Pkt {
  const char *name;
  uint8_t tail[29];
  uint8_t tail_len;
};

static const Pkt PKTS[] = {
  {"AirPods Pro", {0x4c, 0x00, 0x07, 0x19, 0x07, 0x0e, 0x20, 0x75, 0xaa, 0x30, 0x01, 0x00,
                   0x00, 0x45, 0x12, 0x12, 0x12}, 17},
  {"AirPods Gen 3", {0x4c, 0x00, 0x07, 0x19, 0x07, 0x13, 0x20, 0x75, 0xaa, 0x30, 0x01, 0x00,
                     0x00, 0x45, 0x12, 0x12, 0x12}, 17},
  {"AppleTV Setup", {0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc1, 0x01,
                     0x60, 0x4c, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}, 21},
  {"Vision Pro", {0x4c, 0x00, 0x04, 0x04, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xc1, 0x24,
                  0x60, 0x4c, 0x95, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00}, 21},
};
static const size_t PKTS_N = sizeof(PKTS) / sizeof(PKTS[0]);

static BLEScan *scanner = nullptr;
static BLEAdvertising *adv = nullptr;
static volatile uint32_t hits = 0;

static const char *continuity_name(uint8_t t) {
  switch (t) {
    case 0x01: return "iBeacon-ish";
    case 0x02: return "iBeacon";
    case 0x05: return "AirDrop";
    case 0x07: return "proximity-pairing";
    case 0x09: return "AirPlay target";
    case 0x0a: return "AirPlay source";
    case 0x0c: return "handoff";
    case 0x0d: return "hotspot";
    case 0x0e: return "nearby-info";
    case 0x0f: return "nearby-action";
    case 0x10: return "nearby-info-v2";
    case 0x12: return "find-my";
    case 0x04: return "setup/pairing";
    default:   return "other";
  }
}

static void hexcat(char *dst, size_t dstlen, const uint8_t *p, size_t n) {
  size_t o = 0;
  for (size_t i = 0; i < n && o + 3 < dstlen; i++) {
    o += snprintf(dst + o, dstlen - o, "%02x", p[i]);
  }
}

class Rx : public BLEAdvertisedDeviceCallbacks {
  void onResult(BLEAdvertisedDevice dev) override {
    if (!dev.haveManufacturerData()) return;
    String md = dev.getManufacturerData();

    // Apple's company id, little-endian, is the first thing in the field.
    if (md.length() < 3 || (uint8_t)md[0] != 0x4C || (uint8_t)md[1] != 0x00) return;

    hits++;
    const uint8_t *b = (const uint8_t *)md.c_str();
    const size_t n = md.length();
    const uint8_t type = b[2];
    char hex[2 * 40 + 1];
    hexcat(hex, sizeof(hex), b, n > 40 ? 40 : n);

    const uint8_t *mac = dev.getAddress().getNative();
    char extra[48] = "";
    if (type == 0x07 && n >= 8) {
      // proximity pairing: [type][len 0x19][len 0x07][status][model lo][model hi]...
      snprintf(extra, sizeof(extra), " model=0x%02x%02x status=0x%02x",
               b[6], b[5], b[4]);
    }
    Serial.printf("@RX APPLE rssi=%d type=0x%02x(%s) mac=%02x:%02x:%02x:%02x:%02x:%02x md=%s%s\n",
                  dev.getRSSI(), type, continuity_name(type),
                  mac[5], mac[4], mac[3], mac[2], mac[1], mac[0], hex, extra);
  }
};

static Rx rxCallback;

static void do_scan(uint32_t seconds) {
  Serial.printf("@RX scan start %lus\n", (unsigned long)seconds);
  scanner->clearResults();
  scanner->start(seconds, false);
  const uint32_t t0 = millis();
  while (millis() - t0 < (seconds * 1000 + 1500)) {
    delay(200);
  }
  scanner->stop();
  Serial.printf("@RX scan done hits=%lu\n", (unsigned long)hits);
}

static bool start_advertising() {
  char raw[31];
  const Pkt &p = PKTS[0];
  size_t o = 0;
  raw[o++] = 0x02; raw[o++] = 0x01; raw[o++] = (char)ADV_FLAGS;
  raw[o++] = (char)(1 + p.tail_len);
  raw[o++] = (char)0xFF;
  memcpy(raw + o, p.tail, p.tail_len);
  o += p.tail_len;

  BLEAdvertisementData d;
  d.addData(raw, o);
  // 0x00 = BLE_GAP_CONN_MODE_NON under NimBLE, i.e. the non-connectable PDU.
  adv->setAdvertisementType(0x00);
  adv->setMinInterval(160);
  adv->setMaxInterval(320);
  adv->setScanResponse(false);         // required: makes it ADV_NONCONN_IND, not ADV_SCAN_IND
  adv->setAdvertisementData(d);

  for (int i = 0; i < 10; i++) {
    if (adv->start(0, nullptr)) return true;
    delay(100);
  }
  return false;
}

static void rotate() {
  static size_t idx = 0;
  idx = (idx + 1) % PKTS_N;
  const Pkt &p = PKTS[idx];
  char raw[31];
  size_t o = 0;
  raw[o++] = 0x02; raw[o++] = 0x01; raw[o++] = (char)ADV_FLAGS;
  raw[o++] = (char)(1 + p.tail_len);
  raw[o++] = (char)0xFF;
  memcpy(raw + o, p.tail, p.tail_len);
  o += p.tail_len;
  BLEAdvertisementData d;
  d.addData(raw, o);
  adv->setAdvertisementData(d);
}

void setup() {
  Serial.begin(115200);
  delay(600);
  Serial.println();
  Serial.println("@RX begin - BLE receiver/transmitter check");
  Serial.printf("@RX chip=%s heap=%u\n", ESP.getChipModel(), (unsigned)ESP.getFreeHeap());

  BLEDevice::init("Test_1101-rx");
  for (int i = 0; i < 30 && !BLEDevice::getInitialized(); i++) delay(100);

  scanner = BLEDevice::getScan();
  scanner->setAdvertisedDeviceCallbacks(&rxCallback, false);
  scanner->setActiveScan(true);
  scanner->setInterval(100);
  scanner->setWindow(99);
  adv = BLEDevice::getAdvertising();
  Serial.printf("@RX ready heap=%u\n", (unsigned)ESP.getFreeHeap());

  // phase 1: what is in the air around here right now
  do_scan(SCAN1_SECONDS);

  // phase 2: transmit our packets, so a phone can be held next to the board
  Serial.printf("@RX advertise start %lus - hold the phone next to the board NOW\n",
                (unsigned long)ADV_SECONDS);
  if (!start_advertising()) {
    Serial.println("@RX advertise FAILED to start");
  } else {
    const uint32_t t0 = millis();
    uint32_t last = 0;
    while (millis() - t0 < ADV_SECONDS * 1000) {
      if (millis() - last >= ADV_ROT_MS) { last = millis(); rotate(); }
      delay(20);
    }
    adv->stop();
    Serial.printf("@RX advertise done after %lus\n", (unsigned long)ADV_SECONDS);
  }

  // phase 3: can we hear ourselves / anything else?
  delay(500);
  uint32_t before = hits;
  do_scan(SCAN2_SECONDS);
  Serial.printf("@RX summary new_hits=%lu total_hits=%lu\n",
                (unsigned long)(hits - before), (unsigned long)hits);
  Serial.println("@RX END - if phase 1 and 3 were empty, nothing on 2.4 GHz is being heard");
}

void loop() {
  delay(1000);
}
