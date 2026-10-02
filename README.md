# WiFiSniffer-BLE-Advertiser-ESP32

A standalone ESP32-S3 test platform with two halves that share one 2.4 GHz radio:

* **a WiFi monitor with its own access point** — raises an open AP, runs a real
  DHCP server and a catch-all DNS server, and passively captures the 802.11
  frames of whatever joins it. Everything is decoded on the device: DNS queries,
  HTTP hosts, TLS SNI, DHCP leases, ARP, ICMP, associations. It works with no PC
  attached — power it from any USB charger and open its web UI.
* **a BLE proximity-pairing advertiser** — broadcasts the Apple Continuity
  proximity advertisements, one template every 300 ms, behind an admin-panel
  switch with a hard 60-second auto-off.

Both are meant for a bench, with your own devices. Read
[Scope and legal](#scope-and-legal) before you flash it.

> **The BLE advertiser does not produce pairing prompts on iOS 26.5 or later.**
> This is not a bug and it is not fixable in firmware — see
> [Why the prompts stopped](#why-the-prompts-stopped). It still transmits, and it
> is still a useful BLE/RF testbed.

---

## Contents

| Path | What it is |
|---|---|
| `wifi_sniffer/` | the firmware: AP + monitor + web UI + BLE advertiser |
| `diag/ble_advertiser_check/` | minimal sketch: walks the advertising-parameter matrix and reports which combinations the stack accepts |
| `diag/ble_receiver_check/` | minimal sketch: scans for Apple advertisements, then transmits, then scans again |
| `tools/` | build/flash scripts, the PC-side monitor, and the test suite |
| `tools/arduino-cli/` | pinned `arduino-cli` binary |

---

## Hardware

| | |
|---|---|
| Board | ESP32-S3 DevKitC-1 (16 MB flash), tested on chip rev 2 |
| USB | CH343 bridge, appears as `COMx` |
| OLED (optional) | 128×64 I²C, **SH1106** by default / SSD1306 via a build flag; SDA GPIO4, SCL GPIO5, address 0x3C |
| Requirements | ESP32 Arduino core **3.3.12** (NimBLE backend, no extra libraries) |

The single radio matters: while the AP is up the monitor is parked on channel 1,
and while BLE is transmitting the sniffer loses time slices. That is physics, not
a configuration mistake.

---

## Build and flash

```powershell
# toolchain into .\ .arduino15 and .\.arduino-dl (kept inside the project, ~4 GB)
pwsh -File tools\fetch-tools.ps1

# compile + upload, huge_app partition scheme, OLED driver selectable
pwsh -File tools\flash-sniffer.ps1 -Port COM6
pwsh -File tools\flash-sniffer.ps1 -BuildOnly
pwsh -File tools\flash-sniffer.ps1 -Oled ssd1306
```

`huge_app` is required, not cosmetic: with BLE linked in the image is ~1.24 MB and
the stock app slot is 1.25 MB. See the header of `tools/flash-sniffer.ps1`.

---

## Using it

Join the open network `Test_1101`, then:

| URL | What |
|---|---|
| `http://192.168.4.1/` | monitor dashboard (public): clients, servers contacted, live events |
| `http://192.168.4.1/admin` | **admin panel** (HTTP Basic, `admin` / `1324123`) |
| `http://192.168.4.1/api` | JSON state |
| `http://192.168.4.1/events.log` | download the flash-backed log |

The admin panel is **bilingual**: it follows the browser language on first visit
and the `EN / 中文` buttons override it, remembered in `localStorage`.

The panel's BLE section has two buttons:

* **BLE advertiser** — starts/stops the advertising; stops itself after 60 s no
  matter what the browser does, and is off at every boot.
* **transmit power** — steps the BLE TX power through 3 / 0 / 6 / 9 / −3 / −9 dBm
  and applies it live. It defaults to **3 dBm** because Apple's specification
  puts a proximity accessory at about +4 dBm and designs the pairing card to
  appear at ~20 cm; the chip's own default is +9 dBm.

Everything is also on the serial port at 115200 8N1, one record per line:

```
@CMD juice=on | juice=off | juice=tx | juice=tx=6 | juice=verbose | juice=quiet
@CMD foreign=on | hostdbg=on | oledsweep [slow]
```

In verbose mode the firmware prints every packet it transmits, which is the only
honest way to see what is going out on the air:

```
@JUICE packet n=0 name=AirPods len=22 tx=3dBm raw=02010412ff4c00071907022075aa3001000045121212
```

---

## Why the prompts stopped

The advertiser emits the Apple Continuity proximity-pairing advertisement —
company ID `0x004C`, message type `0x07 0x19`, a model id, and `ADV_NONCONN_IND`
with the BR/EDR-not-supported flag. That is the format the EvilAppleJuice-style
projects use, and it is what made iPhones show pairing cards years ago.

Apple's current [Accessory Proximity-Triggered Pairing Specification][spec]
(document dated 2026-09-01, covering the **iOS 26.5** release) describes only one
protocol for third-party accessories, and it is a different one:

| byte | value | meaning |
|---|---|---|
| 0 | `0x10` | length |
| 1 | `0x16` | 16-bit service data type |
| 2–3 | `0xFE25` | ProximityPairing service UUID |
| 4 | — | advertising subtype |
| 5–6 | `0xFF20` | **test** company ID, or a registered one |
| 7–9 | — | model id |
| 10 | — | RSSI offset |

Its conditions are not just the payload. The spec requires the accessory details
to come from Apple's registration portal, or — for testing — from **an installed
app** whose `Info.plist` declares `NSAccessorySetupSupports`, Bluetooth, and an
`NSAccessorySetupProximityServices` array matching the advertised `ModelID` and
`CompanyID`.

Measured against that document, the identifiers this project transmits are simply
absent: `0x004C` appears **0 times**, `0x07` appears **0 times**, and the words
"legacy", "continuity" and "AirPods" appear **0 times**. Apple did not blacklist
the old packet; it replaced the mechanism with one that requires registration and
a companion app, so an unregistered broadcaster cannot satisfy the trigger
conditions.

Relevant history, in order: iCloud-association filtering of Continuity prompts
([USENIX Security](https://www.usenix.org/system/files/sec21-stute.pdf)), the
MFi security check in [iOS 18.1](https://www.webpronews.com/apples-ios-18-1-blocks-fake-mfi-accessories-with-new-security-check/),
and the registered-accessory protocol in iOS 26.5.

**Not proven, and worth saying so:** this project can demonstrate that the
packets leave the radio, but it cannot observe what iOS does with them. The
conclusion above rests on Apple's published requirements, not on a packet capture
taken inside a phone.

[spec]: https://developer.apple.com/download/files/Accessory-Proximity-Triggered-Pairing-Specification.pdf

---

## Three bugs worth knowing about

Found while building this, all reproducible, all documented in the source:

1. **`setAdvertisementType()` silently mis-maps on the NimBLE backend.** It writes
   the *Bluedroid* enum value straight into NimBLE's `conn_mode`, and the two
   disagree — `0x03` (`ESP_BLE_ADV_TYPE_NONCONN_IND`) becomes `conn_mode = 3`,
   which NimBLE rejects with `ble_gap_adv_validate rc=3` (`BLE_HS_EINVAL`) before
   anything reaches the radio. The working value is `0x00`, which means
   `BLE_GAP_CONN_MODE_NON` on this backend — *not* the connectable mode the same
   number means under Bluedroid. `diag/ble_advertiser_check` is the matrix that
   established this.
2. **Raw advertising data must be internally consistent.** The payload carries its
   own AD length byte and flags, so shortening a packet without recomputing the
   length — or claiming "LE general discoverable" on a non-connectable,
   non-scannable PDU — produces something a receiver is entitled to ignore.
3. **`advData.addData()` on the NimBLE path applies in place**, which allows the
   payload to be rotated while advertising stays up instead of restarting the
   advertiser every 300 ms.

Also open, and documented rather than hidden: under sustained browser load with
the advertiser running, the web server has been seen to stop responding until the
board is reset. It does not reproduce when idle.

---

## Tests

```powershell
python tools\check_juice.py                 # offline: packet layout, panel JS, i18n contract
pwsh   -File tools\test_juice.ps1 -WithHttp # serial + HTTP end-to-end
pwsh   -File tools\test_panel.ps1           # renders the panel in both languages
pwsh   -File tools\test_admin.ps1           # admin auth and state
pwsh   -File tools\test_standalone.ps1      # the no-PC-attached web console
python tools\wifi_monitor.py --port COM6    # live PC-side monitor -> capture.csv
```

`check_juice.py` decodes every advertising template, verifies the AD length,
Apple company id, Continuity type and the 31-byte legacy limit, and checks that
both language tables define the same keys.

---

## Scope and legal

This is a radio transmitter and a network monitor. Use it on hardware and
networks you own or are authorised to test, on a bench, with your own devices.

* Broadcasting these advertisements where other people can receive them is
  regulated radio transmission, and the pairing prompts are unwanted by anyone
  who did not opt in.
* The access point is **open and serves no internet on purpose** (there is no NAT,
  so clients get an address and no route out). It exists to observe devices that
  join it — do not run it where people might join expecting real connectivity.
* `/admin` uses HTTP Basic over plain HTTP. The credentials are base64 on the
  wire. Treat the panel as trusted-LAN only.

No warranty. See `LICENSE`.
