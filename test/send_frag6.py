#!/usr/bin/env python3
"""IPv6 단편 두 조각을 AF_PACKET 으로 직접 주입한다.

담당자 리뷰(RFC 8200 4.5)로 드러난 경로를 재현한다. 핵심은 **첫 조각과 후속
조각이 같은 전달 판정을 받아야 한다**는 것이다. 갈리면 일부 조각만 백엔드에
도착해 재조립이 깨진다.

전달 판정이 L4 를 보지 않으므로 세 형태 모두 전달된다. 특히 dstopts 는 후속
조각에서 L4 를 알아낼 방법이 없는 형태인데, L4 를 판정에서 뺀 덕에 두 조각이
같은 결론에 도달한다.

mode
    udp       IPv6 | Frag(NH=17) | UDP | data        → 양쪽 다 REDIRECT 기대
    icmp6     IPv6 | Frag(NH=58) | ICMPv6 | data     → 양쪽 다 REDIRECT 기대
    dstopts   IPv6 | Frag(NH=60) | DstOpts | UDP ... → 양쪽 다 REDIRECT 기대

사용: send_frag6.py <iface> <dst_mac> <src_mac> <src6> <dst6> <mode>
"""
import socket
import struct
import sys

iface, dmac, smac, src6, dst6, mode = sys.argv[1:7]

NH_FRAGMENT = 44
NH_DSTOPTS = 60
NH_UDP = 17
NH_ICMPV6 = 58
UDP_DPORT = 9001


def mac(text):
    return bytes(int(x, 16) for x in text.split(":"))


def ip6(text):
    return socket.inet_pton(socket.AF_INET6, text)


eth = mac(dmac) + mac(smac) + struct.pack("!H", 0x86DD)
data = bytes(range(16))

if mode == "udp":
    first_nh = NH_UDP
    frag_part = struct.pack("!HHHH", 40000, UDP_DPORT, 8 + len(data), 0) + data
elif mode == "icmp6":
    first_nh = NH_ICMPV6
    # Echo Request: type 128, code 0, csum, id, seq
    frag_part = struct.pack("!BBHHH", 128, 0, 0, 0x1234, 1) + data
elif mode == "dstopts":
    first_nh = NH_DSTOPTS
    # NextHeader, HdrExtLen=0, PadN(type 1, len 4) + 4바이트 = 8바이트
    dstopts = struct.pack("!BB", NH_UDP, 0) + b"\x01\x04\x00\x00\x00\x00"
    frag_part = dstopts + struct.pack("!HHHH", 40000, UDP_DPORT, 8 + len(data), 0) + data
else:
    sys.exit("mode 는 udp | icmp6 | dstopts")

# 8바이트 경계로 자른다 — 단편 오프셋이 8바이트 단위이기 때문
split = (len(frag_part) // 2) & ~7
first, second = frag_part[:split], frag_part[split:]
ident = 0x12345678


def build(payload, offset_units, more):
    w2 = (offset_units << 3) | (1 if more else 0)   # offset(13) | res(2) | M(1)
    fraghdr = struct.pack("!BBHI", first_nh, 0, w2, ident)
    plen = len(fraghdr) + len(payload)
    v6 = struct.pack("!IHBB", 6 << 28, plen, NH_FRAGMENT, 64)
    return eth + v6 + ip6(src6) + ip6(dst6) + fraghdr + payload


s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
s.send(build(first, 0, True))
s.send(build(second, split // 8, False))
s.close()

print("mode=%s  first=%dB(off 0, M=1)  second=%dB(off %d, M=0)"
      % (mode, len(first), len(second), split // 8))
