#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Offline test for the firmware's TLS SNI / HTTP Host extraction.

Builds a synthetic ClientHello the same way a phone does, then re-implements the
C parser step by step so the algorithm can be verified without the hardware.
If this passes but the device shows nothing, the fault is in frame capture
rather than in the parsing logic.
"""

import struct
import sys

HOST = "long.weixin.qq.com"


def build_client_hello(host):
    """A realistic ClientHello: SNI is preceded by other extensions on purpose."""
    sni = host.encode()

    # extension: server_name
    server_name = b"\x00" + struct.pack("!H", len(sni)) + sni
    ext_sni = struct.pack("!HH", 0x0000, len(server_name)) + server_name

    # plausible neighbours so the parser has to walk past real data
    ext_grease = struct.pack("!HH", 0x0a0a, 1) + b"\x00"
    ext_groups = struct.pack("!HH", 0x000a, 6) + struct.pack("!H", 4) + struct.pack("!HH", 0x001d, 0x0017)
    ext_sigalgs = struct.pack("!HH", 0x000d, 4) + struct.pack("!H", 2) + struct.pack("!H", 0x0403)
    ext_alpn_payload = struct.pack("!H", 6) + b"\x02h2" + b"\x08http/1.1"
    ext_alpn = struct.pack("!HH", 0x0010, len(ext_alpn_payload)) + ext_alpn_payload

    extensions = ext_grease + ext_sni + ext_groups + ext_sigalgs + ext_alpn
    ext_block = struct.pack("!H", len(extensions)) + extensions

    body = (
        b"\x03\x03"                      # legacy version TLS1.2
        + bytes(range(32))               # random
        + b"\x00"                        # no session id
        + struct.pack("!H", 2) + b"\x13\x01"          # cipher suites
        + b"\x01\x00"                    # compression: null
        + ext_block
    )
    hs = b"\x01" + struct.pack("!I", len(body))[1:] + body   # ClientHello
    rec = b"\x16\x03\x01" + struct.pack("!H", len(hs)) + hs
    return rec


def parse_sni(p, n, verbose=False):
    """Port of the C implementation in wifi_sniffer.ino."""
    def log(*a):
        if verbose:
            print("   ", *a)

    if n < 5 + 4 + 2 + 32 + 1:
        log("too short"); return None
    if p[0] != 0x16:
        log("not a handshake record: 0x%02x" % p[0]); return None
    if p[5] != 0x01:
        log("not a ClientHello: 0x%02x" % p[5]); return None

    i = 5 + 4
    i += 2 + 32
    sid = p[i]; i += 1
    i += sid
    cs = struct.unpack("!H", p[i:i + 2])[0]; i += 2 + cs
    cm = p[i]; i += 1
    i += cm
    extlen = struct.unpack("!H", p[i:i + 2])[0]; i += 2
    end = min(i + extlen, n)
    log("extensions: len=%d, region %d..%d of %d" % (extlen, i, end, n))

    while i + 4 <= end:
        etype, elen = struct.unpack("!HH", p[i:i + 4])
        i += 4
        log("ext type=0x%04x len=%d at %d" % (etype, elen, i))
        if i + elen > end:
            log("extension truncated"); break
        if etype == 0x0000:
            # RFC 6066: extension_data IS the ServerNameList, i.e. it starts
            # directly with ServerName: name_type(1) + length(2) + name.
            # There is NO extra outer length field here - adding one (as an
            # earlier revision did) shifts everything by two bytes and the first
            # two characters of the hostname get read as the type field.
            q = i
            ntype = p[q]; q += 1
            nlen = struct.unpack("!H", p[q:q + 2])[0]; q += 2
            log("server_name: type=%d len=%d" % (ntype, nlen))
            if ntype == 0 and q + nlen <= end:
                return p[q:q + nlen].decode()
            return None
        i += elen
    return None


def main():
    rec = build_client_hello(HOST)
    print("synthetic ClientHello: %d bytes" % len(rec))
    print("expect SNI      : %s" % HOST)
    got = parse_sni(rec, len(rec), verbose=True)
    print("parser returned : %s" % got)

    ok = got == HOST
    print()
    print("RESULT: %s" % ("PASS - the algorithm is correct" if ok else "FAIL - algorithm bug"))

    # also check the truncation path, which is what a 1500-byte frame can cause
    for cut in (len(rec), len(rec) - 10, 120, 80):
        r = parse_sni(rec[:cut], cut)
        print("   truncated to %4d bytes -> %s" % (cut, r))

    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
