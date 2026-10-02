#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Live console for the Test_1101 sniffer AP  (designed to run in a cmd window).

Shows, as they happen:
    connected devices      MAC, vendor, DHCP address, hostname, RSSI
    network requests       the domain names clients ask DNS for
    ping / ICMP            echo requests and replies
    ARP bindings           who owns which IP
    frame log              per-frame type, addresses, RSSI, length
    counters               packet rates, client count, dropped frames

Everything is appended to a CSV so a session can be analysed afterwards.

    python wifi_monitor.py --port COM6
    python wifi_monitor.py --port COM6 --frerign      # also other networks' frames
    python wifi_monitor.py --no-frames                # events only, no frame log
"""

import argparse
import csv
import os
import re
import sys
import time
from datetime import datetime

try:
    import serial
    from serial.tools import list_ports
except ImportError:
    print("pyserial is required:  python -m pip install --user pyserial")
    sys.exit(2)


# ---------------------------------------------------------------- presentation
class C:
    RESET = "\033[0m"
    DIM = "\033[2m"
    BOLD = "\033[1m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[97m"
    GREY = "\033[90m"

    @classmethod
    def off(cls):
        for k in list(vars(cls)):
            if k.isupper():
                setattr(cls, k, "")


def service_of(host):
    """Map a hostname to the service a human would name.

    Apps rarely talk to their own domain, so this matches on the patterns that
    actually show up in mobile traffic.  Unknown hosts are returned unchanged.
    """
    h = host.lower()
    table = [
        ("weixin.qq.com", "WeChat 微信"),
        ("wechat.com", "WeChat 微信"),
        ("wechatpay", "WeChat Pay 微信支付"),
        ("wx.qq.com", "WeChat 微信"),
        ("tencent-cloud.net", "Tencent Cloud 腾讯云"),
        ("myqcloud.com", "Tencent Cloud 腾讯云"),
        ("qpic.cn", "Tencent 腾讯"),
        ("gtimg.cn", "Tencent 腾讯"),
        ("qq.com", "Tencent QQ"),
        ("apple.com", "Apple 苹果"),
        ("icloud.com", "Apple iCloud"),
        ("mzstatic.com", "Apple App Store"),
        ("cdn-apple.com", "Apple CDN"),
        ("googleapis.com", "Google APIs"),
        ("gstatic.com", "Google 静态资源"),
        ("google.com", "Google"),
        ("gvt1.com", "Google Play"),
        ("android.com", "Google Android"),
        ("baidu.com", "Baidu 百度"),
        ("bdstatic.com", "Baidu 百度"),
        ("alipay.com", "Alipay 支付宝"),
        ("alibaba.com", "Alibaba 阿里"),
        ("alicdn.com", "Alibaba CDN"),
        ("aliyuncs.com", "Alibaba Cloud 阿里云"),
        ("taobao.com", "Taobao 淘宝"),
        ("tmall.com", "Tmall 天猫"),
        ("weibo.com", "Weibo 微博"),
        ("sinaimg.cn", "Sina 新浪"),
        ("xiaomi.com", "Xiaomi 小米"),
        ("miui.com", "Xiaomi MIUI"),
        ("mi.com", "Xiaomi 小米"),
        ("huawei.com", "Huawei 华为"),
        ("hicloud.com", "Huawei Cloud"),
        ("douyin.com", "Douyin 抖音"),
        ("bytedance.com", "ByteDance 字节跳动"),
        ("byteimg.com", "ByteDance 字节跳动"),
        ("toutiao.com", "Toutiao 头条"),
        ("kuaishou.com", "Kuaishou 快手"),
        ("bilibili.com", "Bilibili 哔哩哔哩"),
        ("hdslb.com", "Bilibili CDN"),
        ("zhihu.com", "Zhihu 知乎"),
        ("jd.com", "JD 京东"),
        ("360.cn", "Qihoo 360"),
        ("meituan.com", "Meituan 美团"),
        ("pinduoduo.com", "Pinduoduo 拼多多"),
        ("netflix.com", "Netflix"),
        ("microsoft.com", "Microsoft"),
        ("windowsupdate.com", "Windows Update"),
        ("live.com", "Microsoft Live"),
        ("office.com", "Microsoft Office"),
        ("cloudflare.com", "Cloudflare"),
        ("akamai", "Akamai CDN"),
        ("amazonaws.com", "AWS"),
        ("facebook.com", "Facebook"),
        ("instagram.com", "Instagram"),
        ("whatsapp.net", "WhatsApp"),
        ("twitter.com", "Twitter/X"),
        ("github.com", "GitHub"),
        ("push.apple.com", "Apple 推送服务"),
        ("courier.push.apple.com", "Apple 推送服务"),
        ("resolver.arpa", "DNS 加密能力探测"),
    ]
    for key, name in table:
        if key in h:
            return name
    # fall back to the registrable-ish tail so long CDN hosts stay readable
    parts = h.split(".")
    return host


def enable_ansi_on_windows():
    """cmd.exe needs VT processing switched on explicitly."""
    if os.name != "nt":
        return
    try:
        import ctypes
        k = ctypes.windll.kernel32
        h = k.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if k.GetConsoleMode(h, ctypes.byref(mode)):
            k.SetConsoleMode(h, mode.value | 0x0004)      # ENABLE_VIRTUAL_TERMINAL_PROCESSING
    except Exception:
        pass


OUI = {
    "00:1A:7D": "Apple", "3C:22:FB": "Apple", "F0:18:98": "Apple", "A4:C3:F0": "Apple",
    "DC:A6:32": "RaspberryPi", "B8:27:EB": "RaspberryPi", "E4:5F:01": "RaspberryPi",
    "24:6F:28": "Espressif", "30:AE:A4": "Espressif", "7C:DF:A1": "Espressif",
    "84:CC:A8": "Espressif", "AC:67:B2": "Espressif", "C8:C9:A3": "Espressif",
    "D8:A0:1D": "Espressif", "EC:DA:3B": "Espressif", "F4:CF:A2": "Espressif",
    "44:65:0D": "Amazon", "68:54:FD": "Amazon", "F0:81:73": "Amazon",
    "8C:85:90": "Intel", "94:E6:F7": "Intel", "34:13:E8": "Intel", "3C:58:C2": "Intel",
    "00:1A:11": "Google", "F4:F5:D8": "Google", "54:60:09": "Google",
    "1C:F2:9A": "Xiaomi", "64:CC:2E": "Xiaomi", "78:11:DC": "Xiaomi",
    "F8:A4:5F": "Xiaomi", "50:8F:4C": "Xiaomi", "8C:53:C3": "Xiaomi",
    "DC:44:6D": "Samsung", "8C:77:12": "Samsung", "F4:0E:22": "Samsung",
    "78:1F:DB": "Samsung", "AC:5F:3E": "Samsung",
    "B4:CD:27": "Huawei", "48:DB:50": "Huawei", "24:69:68": "Huawei", "E0:24:7F": "Huawei",
    "00:E0:4C": "Realtek", "52:54:00": "QEMU", "00:0C:29": "VMware", "08:00:27": "VirtualBox",
}


def vendor(mac):
    if not mac or len(mac) < 8:
        return ""
    up = mac.upper()
    first = int(up[0:2], 16)
    if first & 0x02:
        return "randomised"          # phones rotate their MAC
    return OUI.get(up[:8], "")


FRAME_COLOR = [
    ("mgmt-probe-req", C.CYAN), ("mgmt-probe-resp", C.CYAN),
    ("mgmt-beacon", C.GREY), ("mgmt-auth", C.YELLOW),
    ("mgmt-assoc", C.GREEN), ("mgmt-deauth", C.RED), ("mgmt-disassoc", C.RED),
    ("data", C.BLUE), ("ctrl", C.GREY),
]


def frame_color(t):
    for key, col in FRAME_COLOR:
        if t.startswith(key):
            return col
    return C.BLUE


KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')


def parse_kv(line):
    out = {}
    for k, v in KV.findall(line):
        if v.startswith('"') and v.endswith('"'):
            v = v[1:-1]
        out[k] = v
    return out


# ---------------------------------------------------------------- monitor
class Monitor:
    def __init__(self, args):
        self.args = args
        self.devices = {}          # mac -> {ip, host, rssi, first, last, frames}
        self.frames = {}
        self.dns = {}              # domain -> count
        self.hosts = {}            # server hostname seen in TLS/HTTP -> count
        self.icmp = 0
        self._foreign_requested = False
        self._announced = set()
        self.lock = __import__("threading").Lock()
        self.t0 = time.time()
        self.csv_file = self.csv_writer = None
        if args.log:
            new = not os.path.exists(args.log)
            self.csv_file = open(args.log, "a", newline="", encoding="utf-8")
            self.csv_writer = csv.writer(self.csv_file)
            if new:
                self.csv_writer.writerow(["time", "kind", "type", "a1", "a2", "a3",
                                          "rssi", "ch", "len", "seq", "info"])

    # ---- device bookkeeping ----
    def dev(self, mac):
        if not mac or mac == "-":
            return None
        with self.lock:
            d = self.devices.setdefault(mac, {"ip": "", "host": "", "rssi": "",
                                              "first": time.time(), "last": time.time(),
                                              "frames": 0})
            d["last"] = time.time()
            return d

    def dev_label(self, mac):
        d = self.dev(mac)
        if not d:
            return f"{C.WHITE}{mac}{C.RESET}"
        bits = [f"{C.WHITE}{C.BOLD}{mac}{C.RESET}"]
        if d["ip"]:
            bits.append(f"{C.YELLOW}{d['ip']}{C.RESET}")
        if d["host"]:
            bits.append(f"{C.MAGENTA}{d['host']}{C.RESET}")
        ven = vendor(mac)
        if ven:
            bits.append(f"{C.DIM}{ven}{C.RESET}")
        return " ".join(bits)

    # ---- record handlers ----
    def show(self, line, pad=""):
        print(pad + line, flush=True)

    def tag(self, name, color):
        return f"{color}{C.BOLD}[{name}]{C.RESET}"

    def on_sta(self, kv):
        mac, ev = kv.get("mac", "?"), kv.get("ev")
        d = self.dev(mac)
        if d and "rssi" in kv:
            d["rssi"] = kv["rssi"]
        if ev == "join":
            self.show(f"{self.tag('JOIN ', C.GREEN)} {self.dev_label(mac)}  "
                      f"{C.DIM}rssi={kv.get('rssi')}dBm{C.RESET}")
        else:
            self.show(f"{self.tag('LEAVE', C.RED)} {self.dev_label(mac)}")

    def on_dhcp(self, kv):
        mac, ev = kv.get("mac", "?"), kv.get("ev")
        d = self.dev(mac)
        if d:
            if kv.get("ip"):
                d["ip"] = kv["ip"]
            if kv.get("host"):
                d["host"] = kv["host"]
        if ev == "discover":
            self.show(f"{self.tag('DHCP ', C.CYAN)} {self.dev_label(mac)} "
                      f"{C.DIM}discover{C.RESET}")
        elif ev == "request":
            self.show(f"{self.tag('DHCP ', C.CYAN)} {self.dev_label(mac)} "
                      f"{C.DIM}request -> {kv.get('ip','?')}{C.RESET}")
        else:
            self.show(f"{self.tag('DHCP ', C.GREEN)} {self.dev_label(mac)} "
                      f"{C.BOLD}lease {kv.get('ip','?')}{C.RESET}")

    def on_arp(self, kv):
        mac, ip = kv.get("mac", "?"), kv.get("ip", "?")
        d = self.dev(mac)
        if d and not d["ip"]:
            d["ip"] = ip
        self.show(f"{self.tag('ARP  ', C.BLUE)} {ip} {C.DIM}is at{C.RESET} {mac} "
                  f"{C.DIM}{vendor(mac)}{C.RESET}")

    def on_host(self, kv):
        """A real connection to a named server: the headline event of this tool."""
        host = kv.get("host", "")
        if not host:
            return
        mac, ip, port, via = kv.get("mac", ""), kv.get("ip", ""), kv.get("port", ""), kv.get("via", "")
        if mac and mac != "-":
            who = self.dev_label(mac)
        elif ip:
            who = f"{C.YELLOW}{ip}{C.RESET}"
        else:
            who = "?"
        svc = service_of(host)
        # Show the friendly service name when we recognise it, and the raw
        # hostname when that adds information.
        if svc != host:
            shown = f"{C.BOLD}{C.WHITE}{svc}{C.RESET} {C.DIM}({host}){C.RESET}"
        else:
            shown = f"{C.BOLD}{C.WHITE}{host}{C.RESET}"
        tag = "TLS  " if via == "tls-sni" else "HTTP "
        self.show(f"{self.tag(tag, C.GREEN)} {who} {C.DIM}:{port} ->{C.RESET} {shown}")
        with self.lock:
            self.hosts[host] = self.hosts.get(host, 0) + 1

    def on_dns(self, kv):
        q = kv.get("q", "")
        mac = kv.get("mac", "?")
        ip = kv.get("ip", "")
        with self.lock:
            self.dns[q] = self.dns.get(q, 0) + 1
        # The firmware may not have a MAC for this source yet (a client that
        # reused a cached lease, for instance), so fall back to the source IP.
        if mac and mac != "?":
            who = self.dev_label(mac)
        elif ip:
            who = f"{C.YELLOW}{ip}{C.RESET}"
        else:
            who = "?"
        self.show(f"{self.tag('REQ  ', C.MAGENTA)} {who} "
                  f"{C.BOLD}{C.WHITE}{q}{C.RESET}")

    def on_icmp(self, kv):
        with self.lock:
            self.icmp += 1
        ev = kv.get("ev", "")
        arrow = "->" if ev == "echo-request" else "<-"
        self.show(f"{self.tag('PING ', C.YELLOW)} {self.dev_label(kv.get('mac','?'))} "
                  f"{kv.get('src','?')} {arrow} {kv.get('dst','?')} {C.DIM}{ev}{C.RESET}")

    def on_pkt(self, kv):
        t = kv.get("t", "?")
        a2, info = kv.get("a2", ""), kv.get("info", "")
        with self.lock:
            self.frames[t] = self.frames.get(t, 0) + 1
            if a2:
                d = self.devices.setdefault(a2, {"ip": "", "host": "", "rssi": "",
                                                 "first": time.time(), "last": time.time(),
                                                 "frames": 0})
                d["frames"] = d.get("frames", 0) + 1
                d["last"] = time.time()
        if self.args.no_frames and not info:
            return
        if self.args.events_only:
            return
        ts = datetime.now().strftime("%H:%M:%S")
        extra = f"  {C.YELLOW}{info}{C.RESET}" if info else ""
        self.show(f"{C.DIM}{ts}{C.RESET} {frame_color(t)}{t:<17}{C.RESET} "
                  f"{a2} {C.DIM}->{C.RESET} {kv.get('a1','')} "
                  f"{C.DIM}rssi={kv.get('rssi')} len={kv.get('len')}{C.RESET}{extra}")

    def on_dev(self, kv):
        """Periodic client-table snapshot from the firmware."""
        mac = kv.get("mac", "?")
        d = self.dev(mac)
        if not d:
            return
        if kv.get("ip") and kv["ip"] != "-":
            d["ip"] = kv["ip"]
        if kv.get("host"):
            d["host"] = kv["host"]
        if kv.get("rssi"):
            d["rssi"] = kv["rssi"]
        if kv.get("frames"):
            d["frames"] = max(d.get("frames", 0), int(kv["frames"]))

    def on_devcount(self, kv):
        # Announce a device the first time we learn its address; after that the
        # per-request lines already carry the identity.
        with self.lock:
            n = int(kv.get("n", "0"))
        if n:
            for mac, d in list(self.devices.items()):
                if mac in self._announced or not d.get("ip"):
                    continue
                self._announced.add(mac)
                host = f"  {C.MAGENTA}{d['host']}{C.RESET}" if d.get("host") else ""
                self.show(f"{self.tag('DEV  ', C.GREEN)} {self.dev_label(mac)}"
                          f"{host}  {C.DIM}connected{C.RESET}")

    def on_stat(self, kv):
        clients = kv.get("clients", "?")
        stream = "all-frames" if kv.get("foreign_shown") == "1" else "own-clients-only"
        self.show(f"{C.DIM}[STAT ] frames={kv.get('pkts')} ours={kv.get('ours')} "
                  f"foreign={kv.get('foreign')} clients={C.BOLD}{clients}{C.RESET}"
                  f"{C.DIM} {stream} dropped={kv.get('serdrop')}{C.RESET}")

    def log_csv(self, kind, kv):
        if not self.csv_writer:
            return
        self.csv_writer.writerow([
            datetime.now().isoformat(timespec="milliseconds"), kind,
            kv.get("t", ""), kv.get("a1", ""), kv.get("a2", ""), kv.get("a3", ""),
            kv.get("rssi", ""), kv.get("ch", ""), kv.get("len", ""), kv.get("seq", ""),
            kv.get("info", kv.get("q", kv.get("ev", ""))),
        ])
        self.csv_file.flush()

    # ---- main loop ----
    def run(self, port, baud):
        """Run forever, surviving anything that is not a Ctrl+C.

        The serial link is genuinely fragile here: flashing the board makes it
        re-enumerate, and any other program that opens the port steals it.  A
        monitoring tool that dies on those events is useless, so the loop
        reconnects instead of exiting and reports what happened.
        """
        self.banner(port, baud)
        backoff = 2.0

        while True:
            ser = None
            try:
                ser = serial.Serial(port, baud, timeout=0.3,
                                    write_timeout=2.0)
                backoff = 2.0
                if self._foreign_requested:
                    time.sleep(0.2)
                    ser.write(b"@CMD foreign=on\n")
                self._consume(ser)
                # _consume only returns when the port went away
            except KeyboardInterrupt:
                print(f"\n{C.YELLOW}stopped by user.{C.RESET}")
                break
            except Exception as exc:                       # noqa: BLE001
                # Never let an unexpected error kill the monitor silently:
                # name it, then keep trying.
                print(f"\n{C.RED}monitor error ({type(exc).__name__}): {exc}{C.RESET}")
            finally:
                if ser:
                    try:
                        ser.close()
                    except Exception:
                        pass

            print(f"{C.YELLOW}serial link lost - reconnecting to {port} "
                  f"in {backoff:.0f}s  (Ctrl+C to stop){C.RESET}")
            try:
                time.sleep(backoff)
            except KeyboardInterrupt:
                print(f"\n{C.YELLOW}stopped by user.{C.RESET}")
                break
            backoff = min(backoff * 1.5, 15.0)

        if self.csv_file:
            self.csv_file.close()
        self.summary()

    def _consume(self, ser):
        """Read and dispatch until the port fails."""
        if self.args.foreign and not self._foreign_requested:
            self._foreign_requested = True
            time.sleep(0.2)
            ser.write(b"@CMD foreign=on\n")
            self.show(f"{C.DIM}requested frames from other networks too{C.RESET}")

        buf = bytearray()
        idle = time.time()
        while True:
            chunk = ser.read(4096)
            if not chunk:
                # A heartbeat makes an idle monitor obviously alive rather than
                # looking hung, and confirms the port is still readable.
                if time.time() - idle > 30:
                    idle = time.time()
                    print(f"{C.DIM}... waiting for a device to connect "
                          f"({datetime.now().strftime('%H:%M:%S')}){C.RESET}",
                          flush=True)
                continue
            idle = time.time()
            buf.extend(chunk)
            while b"\n" in buf:
                raw, _, rest = buf.partition(b"\n")
                buf = bytearray(rest)
                try:
                    line = raw.decode("utf-8", "replace").strip()
                except Exception:
                    continue
                if not line.startswith("@"):
                    if self.args.verbose and line:
                        self.show(f"{C.DIM}{line}{C.RESET}")
                    continue
                try:
                    self._dispatch(line)
                except Exception as exc:                   # noqa: BLE001
                    print(f"{C.RED}bad record dropped ({exc}): "
                          f"{line[:100]}{C.RESET}")

    def _dispatch(self, line):
        kind = line[1:].split(" ", 1)[0]
        kv = parse_kv(line)
        if kind == "STA":
            self.on_sta(kv); self.log_csv("STA", kv)
        elif kind == "DEVCOUNT":
            self.on_devcount(kv)
        elif kind == "DEV":
            self.on_dev(kv); self.log_csv("DEV", kv)
        elif kind == "DHCP":
            self.on_dhcp(kv); self.log_csv("DHCP", kv)
        elif kind == "ARP":
            self.on_arp(kv); self.log_csv("ARP", kv)
        elif kind == "DNS":
            self.on_dns(kv); self.log_csv("DNS", kv)
        elif kind == "HOST":
            self.on_host(kv); self.log_csv("HOST", kv)
        elif kind == "ICMP":
            self.on_icmp(kv); self.log_csv("ICMP", kv)
        elif kind == "PKT":
            self.on_pkt(kv); self.log_csv("PKT", kv)
        elif kind == "STAT":
            self.on_stat(kv)
        elif kind in ("BOOT", "AP"):
            self.show(f"{C.DIM}{line}{C.RESET}")
        elif kind == "READY":
            self.show(f"\n{C.GREEN}{C.BOLD}AP is up.  Connect a device "
                      f"to 'Test_1101' (no password) and watch it here."
                      f"{C.RESET}\n")
        else:
            self.show(f"{C.DIM}{line}{C.RESET}")

    def banner(self, port, baud):
        print(f"{C.MAGENTA}{C.BOLD}"
              "+" + "-" * 74 + "+\n"
              "|  Test_1101  -  soft AP + 802.11 monitor" + " " * 32 + "|\n"
              "|  Passive monitoring.  Use only on your own devices and network." + " " * 7 + "|\n"
              "+" + "-" * 74 + f"+{C.RESET}")
        print(f"{C.DIM}port {port} @ {baud}   Ctrl+C to stop{C.RESET}\n")

    def summary(self):
        dur = time.time() - self.t0
        print(f"\n{C.BOLD}=========== session summary ({dur:.0f}s) ==========={C.RESET}")
        if self.devices:
            print(f"{C.BOLD}devices seen ({len(self.devices)}){C.RESET}")
            for mac, d in sorted(self.devices.items(),
                                 key=lambda kv: -kv[1].get("frames", 0)):
                ip = d.get("ip") or "-"
                host = f"  ({d['host']})" if d.get("host") else ""
                print(f"   {mac}  {ip:<15} {d.get('frames',0):>6} frames  "
                      f"{C.DIM}{vendor(mac)}{host}{C.RESET}")
        if self.hosts:
            print(f"{C.BOLD}servers contacted ({len(self.hosts)} hosts, "
                  f"{sum(self.hosts.values())} connections){C.RESET}")
            for h, n in sorted(self.hosts.items(), key=lambda kv: -kv[1])[:30]:
                print(f"   {n:>4}x  {service_of(h):<28} {C.DIM}{h}{C.RESET}")
        if self.dns:
            print(f"{C.BOLD}DNS requests ({sum(self.dns.values())}){C.RESET}")
            for q, n in sorted(self.dns.items(), key=lambda kv: -kv[1])[:25]:
                print(f"   {n:>4}x  {q}")
        if self.icmp:
            print(f"{C.BOLD}ICMP frames: {self.icmp}{C.RESET}")
        if self.frames:
            print(f"{C.BOLD}frames by type{C.RESET}")
            for t, n in sorted(self.frames.items(), key=lambda kv: -kv[1]):
                print(f"   {n:>6}  {t}")
        if self.args.log:
            print(f"{C.DIM}CSV: {os.path.abspath(self.args.log)}{C.RESET}")


def autodetect_port():
    """Pick the ESP32's CH343/CP210x port when --port is not given."""
    for p in list_ports.comports():
        desc = (p.description or "") + (p.manufacturer or "")
        if any(k in desc for k in ("CH343", "CH340", "CP210", "USB-Enhanced", "Espressif")):
            return p.device
    ports = [p.device for p in list_ports.comports()]
    return ports[0] if ports else None


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", default=None,
                    help="serial port; auto-detected when omitted")
    ap.add_argument("--baud", type=int, default=115200)
    ap.add_argument("--log", default="capture.csv",
                    help="CSV for every record (default capture.csv)")
    ap.add_argument("--no-frames", action="store_true",
                    help="hide frame lines that carry no payload detail")
    ap.add_argument("--events-only", action="store_true",
                    help="show only device / DHCP / DNS / ICMP events")
    ap.add_argument("--foreign", action="store_true",
                    help="also stream frames from OTHER networks (noisy)")
    ap.add_argument("--verbose", action="store_true",
                    help="echo the firmware boot log too")
    ap.add_argument("--no-color", action="store_true")
    args = ap.parse_args()

    if os.name == "nt":
        enable_ansi_on_windows()

    if args.no_color or not sys.stdout.isatty():
        C.off()

    port = args.port or autodetect_port()
    if not port:
        print("no serial port found - is the board plugged in with a DATA cable?")
        return 1

    Monitor(args).run(port, args.baud)
    return 0


if __name__ == "__main__":
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    sys.exit(main())
