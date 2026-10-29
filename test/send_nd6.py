#!/usr/bin/env python3
"""ICMPv6 두 종류를 AF_PACKET 으로 주입해 ND 예외가 동작하는지 본다.

전달 판정에서 L4 를 뺐으므로 VIP 로 오는 ICMPv6 는 백엔드로 간다. VIP 를
소유한 쪽이 백엔드이니 그게 맞다. 예외는 ND 하나다.

NUD 가 보내는 유니캐스트 NS 는 목적지가 VIP 라 배정표 키가 맞아 버린다.
그대로 전달하면 백엔드가 자기 MAC 을 실은 NA 를 돌려주고, 클라이언트의
neighbor 캐시가 그 MAC 으로 갱신된다. 그 뒤로는 트래픽이 LB 를 건너뛰어
분산도 절체도 무력화된다.

mode
    ns     Neighbor Solicitation (type 135), target=dst6   → ND 기대 (전달 안 함)
    echo   Echo Request (type 128)                         → REDIRECT 기대

사용: send_nd6.py <iface> <dst_mac> <src_mac> <src6> <dst6> <mode>
"""
import socket
import struct
import sys

iface, dmac, smac, src6, dst6, mode = sys.argv[1:7]

NH_ICMPV6 = 58
TYPE_ECHO_REQUEST = 128
TYPE_NEIGHBOR_SOLICIT = 135
OPT_SOURCE_LLADDR = 1


def mac(text):
    return bytes(int(x, 16) for x in text.split(":"))


def ip6(text):
    return socket.inet_pton(socket.AF_INET6, text)


def checksum(src, dst, payload):
    """ICMPv6 체크섬은 의사헤더를 포함한다 (RFC 4443 2.3). 생략할 수 없다."""
    pseudo = src + dst + struct.pack("!I", len(payload)) + b"\x00\x00\x00" \
        + bytes([NH_ICMPV6])
    buf = pseudo + payload
    if len(buf) % 2:
        buf += b"\x00"
    total = 0
    for i in range(0, len(buf), 2):
        total += (buf[i] << 8) | buf[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


if mode == "ns":
    # reserved(4) + target(16) + Source Link-Layer Address 옵션(8)
    body = b"\x00" * 4 + ip6(dst6) \
        + bytes([OPT_SOURCE_LLADDR, 1]) + mac(smac)
    msg = struct.pack("!BBH", TYPE_NEIGHBOR_SOLICIT, 0, 0) + body
elif mode == "echo":
    body = struct.pack("!HH", 0x1234, 1) + bytes(range(16))
    msg = struct.pack("!BBH", TYPE_ECHO_REQUEST, 0, 0) + body
else:
    sys.exit("mode 는 ns | echo")

csum = checksum(ip6(src6), ip6(dst6), msg)
msg = msg[:2] + struct.pack("!H", csum) + msg[4:]

eth = mac(dmac) + mac(smac) + struct.pack("!H", 0x86DD)
v6 = struct.pack("!IHBB", 6 << 28, len(msg), NH_ICMPV6, 255)
pkt = eth + v6 + ip6(src6) + ip6(dst6) + msg

s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW)
s.bind((iface, 0))
s.send(pkt)
s.close()

print("mode=%s  type=%d  len=%dB  csum=0x%04x" % (mode, msg[0], len(msg), csum))
