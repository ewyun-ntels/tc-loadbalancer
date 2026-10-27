#!/usr/bin/env python3
"""`bpftool -j map dump` 출력을 받아 per-CPU 값을 합산해 출력한다.

lb_stats 는 PERCPU_ARRAY 라 CPU 별 값이 따로 나온다. 그대로 읽으면
한 CPU 값만 보게 되므로 반드시 합산해야 한다.
"""
import json
import sys

NAMES = [
    "RX", "REDIRECT", "MISS", "NOT_IP", "NOT_L4", "INACTIVE",
    "MALFORMED", "STORE_FAIL", "VLAN", "EXTHDR", "EXTHDR_DEEP",
]


def le(hexwords):
    """bpftool 의 ["0x2a","0x00",...] 를 리틀엔디언 정수로."""
    return int.from_bytes(bytes(int(x, 16) for x in hexwords), "little")


rows = json.load(sys.stdin)
for entry in rows:
    idx = le(entry["key"])
    if "values" in entry:                       # PERCPU
        total = sum(le(v["value"]) for v in entry["values"])
    else:                                       # 단일 값
        total = le(entry["value"])
    name = NAMES[idx] if idx < len(NAMES) else "idx%d" % idx
    mark = "  <--" if total and name in ("REDIRECT",) else ""
    print("   %-13s %d%s" % (name, total, mark))
