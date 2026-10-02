# What goes on the air

Byte-level reference for the two protocols this project touches, so the next
person does not have to re-derive them from a phone that will not cooperate.
Everything here was verified against the sources named at the bottom.

---

## 1. What this project transmits (legacy Continuity proximity)

A complete legacy advertising PDU, 31 bytes maximum, built in
`wifi_sniffer/juice.h` and sent as raw data so the stack merges nothing into it.

```
offset  bytes                     meaning
0       02 01 04                  flags: BR/EDR not supported, NOT discoverable
3       12                        AD length: type byte + Apple payload
4       ff                        AD type: manufacturer specific
5-6     4c 00                     Apple company id (0x004C, little-endian)
7       07                        Continuity message type
8       19                        message length
9       07                        proximity-pairing payload length
10      <model lo>                accessory model id, low byte
11      <model hi>                ... high byte
12-19   20 75 aa 30 01 00 00 45   fixed tail
20-22   12 12 12                  fixed tail
```

Two families exist, and they differ in the message type and in where the model id
sits:

| family | AD length | message | model id at | notes |
|---|---|---|---|---|
| audio (AirPods, Beats) | 31 upstream | `07 19` | index 7 | upstream pads to 31 bytes; only byte 7 varies across ~22 products |
| setup (Apple TV, HomePod) | 23 upstream | `04 04 2a` | index 13 | only byte 13 varies across 13 flows |

**Fitting 31 bytes.** Upstream sends 33 bytes (3 flags + a 31-byte packet) through
NimBLE extended advertising on BLE 5 parts. That does not fit a legacy PDU, so
this project drops the 12 zero padding bytes at the end of the audio packets and
recomputes the AD length byte. The bytes a receiver parses sit before the
padding, at fixed offsets, so shortening the tail does not move them.

Model ids used here (Apple's own, from their Bluetooth accessory database):
`02` AirPods · `0e` AirPods Pro · `0f` Gen 2 · `13` Gen 3 · `14` Pro Gen 2 ·
`24` Pro Gen 2 USB-C · `0a` Max · `11` Beats Studio Buds · `12` Beats Fit Pro ·
`0b` Powerbeats Pro. Setup flows: `01` AppleTV Setup · `06` Pair · `0b` HomePod ·
`09` Setup New Phone · `02` Transfer Number · `13` Keyboard · `1e` TV Color
Balance · `24` Vision Pro.

### Transmit power

Apple's specification fixes a proximity accessory at about **+4 dBm** conducted
and designs the pairing card to appear at **~20 cm**. The ESP32 defaults to
**+9 dBm**. This firmware defaults to **3 dBm** (the stack's step nearest to
Apple's figure) and exposes 3 / 0 / 6 / 9 / −3 / −9 dBm at runtime.

---

## 2. What Apple accepts now (registered proximity pairing)

From the Accessory Proximity-Triggered Pairing Specification, iOS 26.5 release:

```
offset  bytes     meaning
0       10        length of the ProximityPairing payload
1       16        16-bit UUID service data type
2-3     fe 25     ProximityPairing service UUID
4       --        advertising subtype
5-6     ff 20     test company id (or a registered one)
7-9     --        24-bit accessory model id
10      --        RSSI offset
```

The RSSI offset is the two's complement of the RSSI the phone sees, as an
unsigned byte: −55 dBm → `256 − 55 = 201` = `0xC9`. If it is too low, the card
appears from further away.

The payload alone is not sufficient. The specification requires the accessory to
be registered through Apple's portal, or — while testing — to be claimed by an
**installed app** whose `Info.plist` has:

* `NSAccessorySetupSupports` including Bluetooth
* `NSAccessorySetupProximityServices`, an array whose entries carry `ModelID`,
  `CompanyID`, `BundleID`, `Image` and `AccessoryName` matching what is
  advertised

There is also a self-certification step with RF measurements (section 7) for
products going to release.

**Consequence:** an unregistered broadcaster cannot satisfy these conditions, no
matter what it transmits. That is why the prompts stopped, and it is why this
project's advertiser is documented as a radio testbed rather than a prompt
generator.

---

## 3. Non-connectable advertising on the Arduino core's NimBLE backend

This one costs an afternoon if you do not know it:

```cpp
// WRONG on the NimBLE backend, despite being the documented Bluedroid constant:
adv->setAdvertisementType(0x03);   // ESP_BLE_ADV_TYPE_NONCONN_IND
// -> E NimBLE: ble_gap_adv_validate rc=3   (BLE_HS_EINVAL), advertising never starts

// RIGHT on this backend:
adv->setAdvertisementType(0x00);   // writes NimBLE conn_mode 0 = BLE_GAP_CONN_MODE_NON
adv->setScanResponse(false);       // required, or it becomes ADV_SCAN_IND
```

`setAdvertisementType()` assigns its argument directly to NimBLE's `conn_mode`
without translating, and the enums do not line up:

| Bluedroid constant | value | NimBLE `conn_mode` | result |
|---|---|---|---|
| `ESP_BLE_ADV_TYPE_IND` | 0x00 | 0 = `NON` | non-connectable — what a broadcaster wants |
| `ESP_BLE_ADV_TYPE_SCAN_IND` | 0x02 | 2 = `UND` | connectable |
| `ESP_BLE_ADV_TYPE_NONCONN_IND` | 0x03 | 3 = invalid | `BLE_HS_EINVAL` |

`diag/ble_advertiser_check` walks the whole matrix (raw vs builder data, scan
response on/off, default vs explicit intervals, with and without WiFi) and is the
evidence for the table above. Reproduce it before trusting this section on a
different core version.

---

## Sources

* Apple, [Accessory Proximity-Triggered Pairing Specification](https://developer.apple.com/download/files/Accessory-Proximity-Triggered-Pairing-Specification.pdf)
  (2026-09-01, iOS 26.5 release) — sections 2.4–2.7, 4, 5, 6.2
* ckcr4lyf, [EvilAppleJuice-ESP32](https://github.com/ckcr4lyf/EvilAppleJuice-ESP32)
  — `src/devices.cpp` `generatePacket()` and `src/devices.hpp` for the legacy
  packet tails and model ids
* arduino-esp32 3.3.12 `libraries/BLE/src/BLEAdvertising.cpp` — the
  `setAdvertisementType` pass-through and the `start()` disc-mode logic
* Espressif NimBLE, `ble_gap.c` `ble_gap_adv_validate()` / `ble_gap_adv_type()` —
  the enum mapping and the EINVAL branch
* [USENIX Security: Apple Continuity analysis](https://www.usenix.org/system/files/sec21-stute.pdf)
  — iCloud-association filtering of proximity prompts
* [webpronews: iOS 18.1 MFi security check](https://www.webpronews.com/apples-ios-18-1-blocks-fake-mfi-accessories-with-new-security-check/)
