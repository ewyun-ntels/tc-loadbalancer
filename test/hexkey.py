#!/usr/bin/env python3
"""struct lb_key (36B) 를 bpftool 이 받는 hex 문자열로 만든다.

    family(1) pad(3) saddr(16) daddr(16)

IPv4 는 앞 4바이트만 채우고 나머지는 0 이다 (lb_common.h).

사용: hexkey.py <4|6> <src> <dst>
"""
import ipaddress
import sys

fam, src, dst = int(sys.argv[1]), sys.argv[2], sys.argv[3]

out = [fam, 0, 0, 0]
for addr in (src, dst):
    packed = ipaddress.ip_address(addr).packed
    out += list(packed) + [0] * (16 - len(packed))

print(" ".join("%02x" % b for b in out))
