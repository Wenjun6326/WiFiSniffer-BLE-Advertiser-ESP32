#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Pull the readable text out of a PDF without a PDF library.

    python tools/pdf_text.py <file.pdf> [outfile.txt]

Why this exists: the Apple proximity-pairing specification is the authority on
what an accessory must broadcast, and it is a PDF.  The usual libraries
(pypdf, pdfminer) are not installed here and this machine's C: volume is nearly
full, so the text is reassembled by hand instead.

How: every FlateDecode stream is decompressed, then the text-showing operators
are walked in order.  Each BT/ET block sets a text matrix and prints one or more
glyphs with (..) Tj or [ (a) -0.3 (b) ] TJ.  Emitting the glyphs in order, with
a newline per positioning block, reproduces the document closely enough to read
and to grep.
"""

import re
import sys
import zlib
from pathlib import Path


def unescape(s: bytes) -> str:
    out = bytearray()
    i = 0
    while i < len(s):
        c = s[i]
        if c == 0x5C and i + 1 < len(s):          # backslash
            n = s[i + 1]
            mapping = {0x6E: 10, 0x72: 13, 0x74: 9, 0x62: 8, 0x66: 12,
                       0x28: 0x28, 0x29: 0x29, 0x5C: 0x5C}
            if n in mapping:
                out.append(mapping[n]); i += 2; continue
            if 0x30 <= n <= 0x37:                  # octal escape
                j = i + 1
                oct_digits = b""
                while j < len(s) and len(oct_digits) < 3 and 0x30 <= s[j] <= 0x37:
                    oct_digits += bytes([s[j]]); j += 1
                out.append(int(oct_digits, 8) & 0xFF); i = j; continue
            out.append(n); i += 2; continue
        out.append(c); i += 1
    return out.decode("latin-1")


def stream_texts(path: Path):
    raw = path.read_bytes()
    for m in re.finditer(rb"stream\r?\n", raw):
        start = m.end()
        end = raw.find(b"endstream", start)
        if end < 0:
            continue
        try:
            data = zlib.decompress(raw[start:end])
        except Exception:
            continue
        if b"Tj" not in data and b"TJ" not in data:
            continue
        yield data


TOKEN = re.compile(
    rb"\((?:\\.|[^()\\])*\)"                       # literal string
    rb"|<[0-9A-Fa-f\s]+>"                          # hex string
    rb"|\[[^\]]*\]\s*TJ"                           # array show
    rb"|\((?:\\.|[^()\\])*\)\s*Tj"                 # simple show
    rb"|T\*|Td|TD|Tm|ET|BT",                       # positioning
    re.S,
)


def page_text(data: bytes) -> str:
    lines, cur = [], []
    for t in TOKEN.finditer(data):
        tok = t.group(0)
        if tok in (b"T*", b"Td", b"TD", b"Tm"):
            if cur:
                lines.append("".join(cur)); cur = []
            continue
        if tok in (b"BT", b"ET"):
            continue
        if tok.startswith(b"["):
            body = tok[: tok.rfind(b"]")]
            for s in re.finditer(rb"\((?:\\.|[^()\\])*\)", body, re.S):
                cur.append(unescape(s.group(0)[1:-1]))
        elif tok.startswith(b"<"):
            hx = re.sub(rb"\s+", b"", tok[1:-1])
            if len(hx) % 2:
                hx += b"0"
            try:
                cur.append(bytes.fromhex(hx.decode()).decode("latin-1"))
            except Exception:
                pass
        else:
            body = tok[: tok.rfind(b")")]
            body = body[body.find(b"(") + 1 :]
            cur.append(unescape(body))
    if cur:
        lines.append("".join(cur))
    return "\n".join(lines)


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2
    src = Path(sys.argv[1])
    out = Path(sys.argv[2]) if len(sys.argv) > 2 else src.with_suffix(".txt")
    chunks = []
    for i, data in enumerate(stream_texts(src)):
        txt = page_text(data)
        if txt.strip():
            chunks.append("===== stream %d =====\n%s" % (i, txt))
    text = "\n".join(chunks)
    out.write_text(text, encoding="utf-8")
    print("wrote %s (%d chars from %d text streams)" % (out, len(text), len(chunks)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
