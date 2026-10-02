#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Two offline checks that need no board:

  1. every packet in wifi_sniffer/juice.h carries Apple manufacturer data in the
     shape the firmware sends it, within the 31-byte legacy advertising limit
  2. the JavaScript inside the admin page still parses (node --check)

    python tools/check_juice.py

The point of (1) is that a wrong length byte or a shifted payload produces a
packet that looks fine in the source and does nothing on the air, which is a
miserable thing to debug from the other side of a phone screen.

What goes out, per juice_send():
   02 01 06 | <len> ff <Apple data...>
   flags      AD header
so the template's own first two bytes are replaced, and 3 + 2 + len(tail) must
stay within 31 bytes.
"""

import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
JUICE = ROOT / "wifi_sniffer" / "juice.h"
ADMIN = ROOT / "wifi_sniffer" / "admin_page.h"

ok = 0
bad = 0


def check(cond, msg):
    global ok, bad
    if cond:
        ok += 1
        print("   PASS  %s" % msg)
    else:
        bad += 1
        print("   FAIL  %s" % msg)


# ---------------------------------------------------------------------------
# 1. packet structure
# ---------------------------------------------------------------------------
TEMPLATE_RE = re.compile(
    r'\{\s*"(?P<name>[^"]+)"\s*,\s*\{(?P<bytes>[0-9A-Fa-fx,\s]*?)\}\s*\}'
)

FLAGS = bytes([0x02, 0x01, 0x06])          # the firmware prepends this
APPLE = bytes([0x4C, 0x00])

print("=== what goes on the air ===")
text = JUICE.read_text(encoding="utf-8", errors="replace")
body = text.split("JUICE_TEMPLATES[] = {", 1)
if len(body) != 2:
    print("   FAIL  no JUICE_TEMPLATES table found")
    sys.exit(1)
body = body[1].split("\n};", 1)[0]

templates = []
for m in TEMPLATE_RE.finditer(body):
    raw = bytes(int(v, 16) for v in re.findall(r"0x([0-9A-Fa-f]{2})", m.group("bytes")))
    templates.append((m.group("name"), raw))

check(len(templates) >= 2, "table has at least two templates to rotate (%d found)" % len(templates))

audio = setup = 0
for name, packet in templates:
    if len(packet) < 6:
        check(False, "%s: only %d bytes - too short to be a packet" % (name, len(packet)))
        continue
    if packet[1] != 0xFF:
        check(False, "%s: AD type is 0x%02x, expected 0xFF (manufacturer specific)" % (name, packet[1]))
        continue
    if packet[2:4] != APPLE:
        check(False, "%s: company id is %s, expected Apple 4c 00" % (name, packet[2:4].hex(" ")))
        continue

    # juice_send() sends the tail (the template minus its own AD header) behind a
    # rebuilt header, because the upstream length byte describes a 33-byte
    # extended advertisement rather than what fits here.
    tail = packet[2:]
    on_air = FLAGS + bytes([1 + len(tail), 0xFF]) + tail
    if len(on_air) > 31:
        check(False, "%s: %d bytes on the air, over the 31-byte legacy limit" % (name, len(on_air)))
        continue

    # The two families differ in the continuity message type right after the
    # company id; audio is 07 19, the setup handshake is 04 04 2a.
    if packet[4:6] == bytes([0x07, 0x19]):
        audio += 1
        if packet[6] != 0x07:
            check(False, "%s: audio payload length byte is 0x%02x, upstream uses 0x07" % (name, packet[6]))
            continue
        if packet[8:19] != bytes.fromhex("2075aa3001000045121212"):
            check(False, "%s: audio tail differs from the upstream template" % name)
            continue
        if any(packet[19:]):
            check(False, "%s: audio padding is not zero" % name)
            continue
        model = packet[7]
    elif packet[4:7] == bytes([0x04, 0x04, 0x2A]):
        setup += 1
        if packet[7:13] != bytes.fromhex("0000000f05c1"):
            check(False, "%s: setup prefix differs from the upstream template" % name)
            continue
        if packet[14:23] != bytes.fromhex("604c95000010000000"):
            check(False, "%s: setup suffix differs from the upstream template" % name)
            continue
        model = packet[13]
    else:
        check(False, "%s: unknown continuity message type %s" % (name, packet[4:7].hex(" ")))
        continue
    ok += 1
    print("   PASS  %-26s %2d bytes on the air, model id 0x%02x, continuity %s"
          % (name, len(on_air), model, packet[4:7].hex(" ")))

check(audio > 0, "audio family present (%d)" % audio)
check(setup > 0, "setup family present (%d)" % setup)

# the timings the firmware and the panel text both quote
m = re.search(r"JUICE_WAKE_MS\s*=\s*(\d+)", text)
check(bool(m) and int(m.group(1)) == 60000,
      "auto-off window is 60 s in the firmware" + (" (saw %s)" % m.group(1) if m else " (not found)"))

# ---------------------------------------------------------------------------
# 2. the admin page script
# ---------------------------------------------------------------------------
print("=== admin page script ===")
page = ADMIN.read_text(encoding="utf-8", errors="replace")
m = re.search(r'R"xADMINx\((.*)\)xADMINx"', page, re.S)
check(bool(m), "admin page raw literal found")
if m:
    html = m.group(1)
    for frag in ("id=\"bJuice\"", "juice_tpl", "juice_left", "act('juice')"):
        check(frag in html, "page references %s" % frag)

    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    check(bool(scripts), "page has a script block (%d)" % len(scripts))
    for i, js in enumerate(scripts):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False,
                                         encoding="utf-8") as fh:
            fh.write(js)
            path = fh.name
        try:
            r = subprocess.run(["node", "--check", path], capture_output=True, text=True)
            check(r.returncode == 0,
                  "script %d parses under node%s" % (i, "" if r.returncode == 0 else ": " + r.stderr.strip()[:200]))
        except FileNotFoundError:
            print("   SKIP  node not available")
        finally:
            Path(path).unlink(missing_ok=True)

    # ---- i18n contract -----------------------------------------------------
    # A key that exists in only one language shows up as a raw key name on
    # screen, which is exactly the kind of thing nobody notices until a
    # non-English user opens the page, so it is checked here instead.
    print("=== bilingual panel ===")
    # A table ends with a line holding just "}" - but that line also closes a
    # *nested* object earlier in the file, so each language is matched on its own
    # rather than with one findall that would stop at the first inner brace.
    tables = {}
    for name in ("en", "zh"):
        m2 = re.search(r"\n %s: \{(.*?)\n \},?\n" % name, html, re.S)
        if m2:
            tables[name] = dict(re.findall(r'(\w+):"((?:[^"\\]|\\.)*)"\s*,?', m2.group(1)))
    check(set(tables) == {"en", "zh"}, "both language tables present (%s)" % ", ".join(sorted(tables)))

    if set(tables) == {"en", "zh"}:
        en, zh = set(tables["en"]), set(tables["zh"])
        check(en == zh,
              "en and zh define the same keys (en-only: %s; zh-only: %s)"
              % (sorted(en - zh) or "none", sorted(zh - en) or "none"))
        check(len(en) >= 40, "translation table covers the page (%d keys)" % len(en))

        used = set(re.findall(r'data-t(?:p|d)?="([^"]+)"', html))
        # only t('key') calls are translation lookups; act('juice') and friends
        # are firmware action names that happen to sit in the same quotes
        used |= set(re.findall(r"(?<![\w.])t\('([^']+)'\)", html))
        missing = sorted(k for k in used if k not in tables["en"])
        check(not missing, "every key the markup or script uses exists (%s)"
              % ("missing: " + ", ".join(missing) if missing else "%d keys" % len(used)))

        # CJK characters must actually be CJK, not placeholder latin
        cjk = sum(1 for v in tables["zh"].values() if re.search(r"[\u4e00-\u9fff]", v))
        check(cjk >= len(tables["zh"]) * 0.8,
              "zh table is genuinely translated (%d/%d values contain Chinese)" % (cjk, len(tables["zh"])))

    check("setLang" in html and "navigator.language" in html and "localStorage" in html,
          "language switch, browser detection and persistence are all wired")

# ---------------------------------------------------------------------------
print("\n===== %d passed, %d failed =====" % (ok, bad))
sys.exit(1 if bad else 0)
