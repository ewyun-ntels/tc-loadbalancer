#!/usr/bin/env python3
"""`bpftool -j map dump` 출력을 받아 per-CPU 값을 합산해 출력한다.

lb_stats 는 PERCPU_ARRAY 라 CPU 별 값이 따로 나온다. 그대로 읽으면
한 CPU 값만 보게 되므로 반드시 합산해야 한다.

사용
    bpftool -j map dump id N | sumstats.py              전체 표
    bpftool -j map dump id N | sumstats.py --one MISS    값 하나만 (스크립트용)
"""
import json
import sys

# 순서가 lb_common.h 의 enum lb_stat 과 1:1 로 맞아야 한다.
# 인덱스로 이름을 찾으므로 중간에 끼워 넣으면 전부 어긋난다 — 추가는 끝에.
NAMES = [
    "RX", "REDIRECT", "MISS", "NOT_IP", "PROTO_OTHER", "INACTIVE",
    "MALFORMED", "STORE_FAIL", "VLAN", "EXTHDR", "EXTHDR_DEEP", "FRAG_LATER",
    "ND",
]


def le(hexwords):
    """bpftool 의 ["0x2a","0x00",...] 를 리틀엔디언 정수로."""
    return int.from_bytes(bytes(int(x, 16) for x in hexwords), "little")


def total_of(entry):
    if "values" in entry:          # PERCPU — 합산 필수
        return sum(le(v["value"]) for v in entry["values"])
    return le(entry["value"])      # 단일 값


rows = json.load(sys.stdin)
counts = {}
for entry in rows:
    idx = le(entry["key"])
    name = NAMES[idx] if idx < len(NAMES) else "idx%d" % idx
    counts[name] = total_of(entry)

if len(sys.argv) >= 3 and sys.argv[1] == "--one":
    print(counts.get(sys.argv[2], 0))
else:
    for name in NAMES:
        if name in counts:
            mark = "  <--" if counts[name] and name == "REDIRECT" else ""
            print("   %-13s %d%s" % (name, counts[name], mark))
