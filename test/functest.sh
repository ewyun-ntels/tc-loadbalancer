#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-2.0
#
# 1a 기능 시험 — veth + 브리지로 "같은 L2" 를 모사해 DSR 왕복 전체를 본다.
#
#   netns cl ─ veth ─┐                        ┌─ veth ─ netns be
#                    ├─ br-lbtest (같은 L2) ──┤      lo:VIP, arp_ignore=1
#   netns lb ─ veth ─┘                        └
#        tc ingress + lb_kern.o
#
# 경로
#   1) cl 이 VIP 로 송신. 목적지 MAC 은 lb (정적 neigh 로 고정 — 실제로는
#      스위치가 BGP next-hop 해석으로 채우는 자리다)
#   2) 브리지가 lb 로 전달
#   3) lb 의 tc ingress 가 목적지 MAC 을 be 것으로 바꿔 같은 포트로 되돌림
#   4) 브리지가 be 로 전달. be 는 lo 의 VIP 로 수신
#   5) be 가 출발지 VIP 로 cl 에 직접 응답 — lb 를 거치지 않음 (DSR)
#
# 사용: sudo ./test/functest.sh [all|setup|populate|run|stats|teardown]
set -euo pipefail

cd "$(dirname "$0")/.."
OBJ=bpf/lb_kern.o
T=test

BR=br-lbtest
NS_CL=lbt-cl
NS_LB=lbt-lb
NS_BE=lbt-be

CL4=10.200.0.10
LB4=10.200.0.20
BE4=10.200.0.30
VIP4=10.200.0.100

CL6=fd00:200::10
LB6=fd00:200::20
BE6=fd00:200::30
VIP6=fd00:200::100

PORT=9000

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()  { printf '   \033[32mok\033[0m   %s\n' "$*"; }
bad() { printf '   \033[31mFAIL\033[0m %s\n' "$*"; }

need_root() { [ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요"; exit 1; }; }

# ---------------------------------------------------------------- teardown
teardown() {
	for ns in $NS_CL $NS_LB $NS_BE; do
		ip netns del "$ns" 2>/dev/null || true
	done
	ip link del $BR 2>/dev/null || true
	rm -rf /sys/fs/bpf/lb_assign /sys/fs/bpf/lb_stats /sys/fs/bpf/tc 2>/dev/null || true
	ok "정리 완료"
}

# ------------------------------------------------------------------- setup
setup() {
	say "토폴로지 구성"
	teardown >/dev/null 2>&1 || true

	mountpoint -q /sys/fs/bpf || mount -t bpf bpf /sys/fs/bpf

	ip link add $BR type bridge
	ip link set $BR up
	modprobe br_netfilter 2>/dev/null || true
	sysctl -qw net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true
	sysctl -qw net.bridge.bridge-nf-call-ip6tables=0 2>/dev/null || true

	local i=0 spec ns v4 v6 rest
	for spec in "$NS_CL:$CL4:$CL6" "$NS_LB:$LB4:$LB6" "$NS_BE:$BE4:$BE6"; do
		ns=${spec%%:*}; rest=${spec#*:}; v4=${rest%%:*}; v6=${rest#*:}
		i=$((i + 1))

		ip netns add "$ns"
		ip link add "p$i" type veth peer name "h$i"
		ip link set "h$i" master $BR
		ip link set "h$i" up
		ip link set "p$i" netns "$ns"

		ip netns exec "$ns" ip link set lo up
		ip netns exec "$ns" ip link set "p$i" name eth0
		ip netns exec "$ns" ip addr add "$v4/24" dev eth0
		ip netns exec "$ns" ip -6 addr add "$v6/64" dev eth0 nodad
		ip netns exec "$ns" ip link set eth0 up
	done
	ok "netns 3개 + 브리지"

	# 백엔드: VIP 를 lo 에 올리고 ARP 응답을 막는다 (설계 메모 9번)
	ip netns exec $NS_BE ip addr add "$VIP4/32" dev lo
	ip netns exec $NS_BE ip -6 addr add "$VIP6/128" dev lo nodad
	ip netns exec $NS_BE sysctl -qw net.ipv4.conf.all.arp_ignore=1
	ip netns exec $NS_BE sysctl -qw net.ipv4.conf.all.arp_announce=2
	ip netns exec $NS_BE sysctl -qw net.ipv4.conf.eth0.arp_ignore=1
	ip netns exec $NS_BE sysctl -qw net.ipv4.conf.eth0.arp_announce=2
	ok "백엔드 lo:VIP + arp_ignore=1 arp_announce=2"

	# 클라이언트: VIP 의 MAC 을 lb 로 고정.
	# 실제 환경에서는 스위치가 BGP next-hop 으로 해석하는 자리다.
	local lbmac bemac
	lbmac=$(ip netns exec $NS_LB cat /sys/class/net/eth0/address)
	bemac=$(ip netns exec $NS_BE cat /sys/class/net/eth0/address)
	ip netns exec $NS_CL ip neigh replace "$VIP4" lladdr "$lbmac" dev eth0 nud permanent
	ip netns exec $NS_CL ip -6 neigh replace "$VIP6" lladdr "$lbmac" dev eth0 nud permanent
	ok "클라이언트 정적 neigh: VIP → $lbmac (lb)"
	echo "        백엔드 MAC = $bemac"

	ip netns exec $NS_LB tc qdisc add dev eth0 clsact
	ip netns exec $NS_LB tc filter add dev eth0 ingress bpf da obj "$OBJ" sec tc
	ok "tc ingress 부착"
}

# ------------------------------------------------------------- 맵 채우기
map_id() { bpftool map show | awk -v n="$1" '$0 ~ ("name " n) {gsub(":","",$1); print $1; exit}'; }

populate() {
	say "배정표 채우기"
	local mid bemac
	mid=$(map_id lb_assign)
	[ -n "$mid" ] || { bad "lb_assign 맵을 못 찾음"; exit 1; }
	echo "        lb_assign map id = $mid"

	bemac=$(ip netns exec $NS_BE cat /sys/class/net/eth0/address)
	local val="$(echo "$bemac" | tr ':' ' ') 01 00"   # mac(6) flags(1) pad(1)

	bpftool map update id "$mid" \
		key hex $(python3 $T/hexkey.py 4 "$CL4" "$VIP4") \
		value hex $val
	ok "v4  $CL4 → $VIP4  ⇒  $bemac"

	bpftool map update id "$mid" \
		key hex $(python3 $T/hexkey.py 6 "$CL6" "$VIP6") \
		value hex $val
	ok "v6  $CL6 → $VIP6  ⇒  $bemac"
}

# ---------------------------------------------------------------- 트래픽
one_test() { # $1=label $2=vip
	local label=$1 vip=$2 out rc=0 lpid

	ip netns exec $NS_BE python3 $T/listener.py "$vip" "$PORT" &
	lpid=$!
	sleep 0.4

	out=$(ip netns exec $NS_CL timeout 8 python3 $T/connect.py "$vip" "$PORT" 2>&1) || rc=$?

	wait $lpid 2>/dev/null || true

	if [ $rc -eq 0 ]; then
		ok "$label 연결 성공"
		echo "$out" | sed 's/^/        /'
		if echo "$out" | grep -q "peer  : $vip"; then
			ok "$label 응답 출발지가 VIP — DSR 성립"
		else
			bad "$label 응답 출발지가 VIP 가 아님"
		fi
	else
		bad "$label 연결 실패 (rc=$rc)"
		echo "$out" | sed 's/^/        /'
	fi
}

run() {
	say "IPv4 — TCP 연결 (DSR 왕복)"
	one_test IPv4 "$VIP4"
	say "IPv6 — TCP 연결 (DSR 왕복)"
	one_test IPv6 "$VIP6"
}

# ------------------------------------------------------------------ 통계
stats() {
	say "lb_stats (per-CPU 합산)"
	local mid
	mid=$(map_id lb_stats) || true
	if [ -z "$mid" ]; then
		bad "lb_stats 맵을 못 찾음"
		return 0
	fi
	bpftool -j map dump id "$mid" | python3 $T/sumstats.py
}

case "${1:-all}" in
setup)    need_root; setup ;;
populate) need_root; populate ;;
run)      need_root; run ;;
stats)    need_root; stats ;;
teardown) need_root; teardown ;;
all)      need_root; setup; populate; run; stats
          say "완료 — 정리하려면: sudo $0 teardown" ;;
*)        echo "사용: sudo $0 [all|setup|populate|run|stats|teardown]"; exit 1 ;;
esac
