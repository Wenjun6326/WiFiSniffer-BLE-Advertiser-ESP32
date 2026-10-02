/*
 * Scratch diagnostic - NOT part of the project firmware.
 *
 * Question it was written to answer: can this ESP32-S3 advertise BLE at all, and
 * does raising the SoftAP first change the answer?
 *
 * ANSWER (measured on the board, ESP32-S3 rev2, esp32 core 3.3.12, 2026-10):
 *
 *   Advertising works.  The blocker was the advertising PDU type.
 *
 *   Every non-connectable attempt (ESP_BLE_ADV_TYPE_NONCONN_IND, 0x03) is
 *   rejected by this core's NimBLE before it reaches the radio:
 *       E NimBLE: ble_gap_adv_validate rc=3        (BLE_HS_EINVAL)
 *   and it fails identically:
 *     - with the raw PDU or with BLEAdvertisementData's high level builder
 *     - with a scan response on or off
 *     - with the default intervals or 160/320
 *     - with WiFi down and with the SoftAP up
 *   which rules out the data, the timings and radio coexistence.
 *
 *   Connectable undirected (0x00) starts in every one of those combinations.
 *   The sniffer firmware therefore advertises with 0x00; see the note in
 *   wifi_sniffer/juice.h.  Heap cost of the BLE stack: ~68 KB with WiFi down,
 *   and the AP plus BLE together leave ~164 KB free.
 *
 * Kept because the matrix is the evidence for that decision, and because it is
 * the first thing to re-run if a core upgrade changes the answer.
 *
 * Serial 115200, output prefixed @DIAG.
 */
#include <BLEDevice.h>
#include <BLEAdvertising.h>

// The sniffer's PDU: flags + Apple manufacturer data, 22 bytes.
static const uint8_t PDU[] = {
  0x02, 0x01, 0x06,
  0x14, 0xff, 0x4c, 0x00, 0x07, 0x19, 0x07, 0x0e, 0x20, 0x75, 0xaa, 0x30,
  0x01, 0x00, 0x00, 0x45, 0x12, 0x12, 0x12
};

static BLEAdvertising *adv = nullptr;

// one full attempt: reset the advertiser, apply the settings, try to start
static void attempt(const char *label, uint8_t adv_type, bool scan_rsp,
                    uint16_t itvl_min, uint16_t itvl_max, bool use_raw) {
  adv->stop();
  delay(150);

  if (use_raw) {
    char buf[sizeof(PDU)];
    memcpy(buf, PDU, sizeof(PDU));
    BLEAdvertisementData d;
    d.addData(buf, sizeof(buf));
    adv->setAdvertisementData(d);
  } else {
    // the ordinary high level path: name plus Apple manufacturer data
    BLEAdvertisementData d;
    d.setName("Test_1101");
    d.setManufacturerData(String("\x4c\x00\x07\x19\x07\x0e\x20\x75\xaa\x30\x01\x00\x00\x45\x12\x12\x12"));
    adv->setAdvertisementData(d);
  }

  adv->setAdvertisementType(adv_type);
  adv->setScanResponse(scan_rsp);
  if (itvl_min) { adv->setMinInterval(itvl_min); adv->setMaxInterval(itvl_max); }

  bool ok = adv->start(0, nullptr);
  Serial.printf("@DIAG %-34s type=%u scan=%u itvl=%u/%u raw=%u -> %s\n",
                label, adv_type, scan_rsp ? 1 : 0, itvl_min, itvl_max, use_raw ? 1 : 0,
                ok ? "OK" : "FAIL");
  if (ok) Serial.printf("@DIAG SUCCESS %s\n", label);
}

void setup() {
  Serial.begin(115200);
  delay(500);
  Serial.println();
  Serial.println("@DIAG matrix begin");

  BLEDevice::init("Test_1101");
  for (int i = 0; i < 30 && !BLEDevice::getInitialized(); i++) delay(100);
  adv = BLEDevice::getAdvertising();
  Serial.printf("@DIAG init done, heap=%u\n", (unsigned)ESP.getFreeHeap());

  // 1. the exact combination the firmware uses
  attempt("firmware as written", 0x03, false, 160, 320, true);
  // 2. raw data, connectable type
  attempt("connectable undirected", 0x00, false, 160, 320, true);
  // 3. raw data, default intervals (stack picks)
  attempt("raw, default intervals", 0x03, false, 0, 0, true);
  // 4. raw data, no interval limits, connectable
  attempt("connectable, default itvl", 0x00, false, 0, 0, true);
  // 5. high level builder instead of a raw PDU
  attempt("high level adv data", 0x03, false, 160, 320, false);
  // 6. scan response enabled
  attempt("raw + scan response", 0x03, true, 160, 320, true);
  // 7. connectable + scan response
  attempt("connectable + scan rsp", 0x00, true, 160, 320, true);

  Serial.printf("@DIAG matrix done heap=%u\n", (unsigned)ESP.getFreeHeap());
  Serial.println("@DIAG END");
}

void loop() {
  delay(1000);
}
