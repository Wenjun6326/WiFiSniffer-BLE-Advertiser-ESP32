#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Reset the board over the serial control lines and print what the sketch logs.

    python read_serial.py [COM6] [seconds]

The ESP32-S3 DevKitC-1 wires DTR/RTS to EN and GPIO0 through the CH343, so
toggling them restarts the sketch (rather than dropping into the bootloader).
"""

import sys
import time

import serial

port = sys.argv[1] if len(sys.argv) > 1 else "COM6"
seconds = float(sys.argv[2]) if len(sys.argv) > 2 else 8.0

try:
    ser = serial.Serial(port, 115200, timeout=0.2)
except Exception as exc:                     # noqa: BLE001
    print("could not open %s: %s" % (port, exc))
    sys.exit(1)

# classic ESP auto-reset: RTS -> EN, DTR -> GPIO0.  Keep DTR low so the chip
# boots normally into the sketch instead of the ROM download loader.
ser.dtr = False
ser.rts = True
time.sleep(0.15)
ser.rts = False
time.sleep(0.05)

t0 = time.time()
buf = bytearray()
while time.time() - t0 < seconds:
    chunk = ser.read(4096)
    if chunk:
        buf.extend(chunk)
    else:
        time.sleep(0.05)
ser.close()

text = bytes(buf).decode("utf-8", "replace")
print("---- serial output (%d bytes) ----" % len(buf))
print(text if text.strip() else "(no output captured)")
