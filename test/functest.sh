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
# 사용: sudo ./test/functest.sh [all|setup|populate|tcp|udp|frag|nd|negative|stats|teardown]
set -euo pipefail

cd "$(dirname "$0")/.."
OBJ=bpf/lb_kern.o
FAILED=0
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
UPORT=9001

say() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
ok()  { printf '   \033[32mok\033[0m   %s\n' "$*"; }
bad() { FAILED=$((FAILED + 1)); printf '   \033[31mFAIL\033[0m %s\n' "$*"; }
note(){ printf '        %s\n' "$*"; }

need_root() { [ "$(id -u)" -eq 0 ] || { echo "sudo 로 실행하세요"; exit 1; }; }

# bad() 가 FAILED 를 올린다. 출력만 하고 0 으로 끝나면 CI 에서 안 걸린다.
finish() {
	if [ "$FAILED" -gt 0 ]; then
		printf '
%d건 실패
' "$FAILED"
		exit 1
	fi
	printf '
전부 통과
'
}

# ---------------------------------------------------------------- teardown
teardown() {
	for ns in $NS_CL $NS_LB $NS_BE; do
		ip netns del "$ns" 2>/dev/null || true
	done
	ip link del $BR 2>/dev/null || true
	# 우리가 만든 핀만 지운다. /sys/fs/bpf/tc 는 iproute2 공용 경로라
	# 통째로 지우면 같은 호스트의 다른 TC 프로그램 맵까지 날아간다.
	rm -rf /sys/fs/bpf/lb_assign /sys/fs/bpf/lb_stats 2>/dev/null || true
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
	note "백엔드 MAC = $bemac"

	ip netns exec $NS_LB tc qdisc add dev eth0 clsact
	ip netns exec $NS_LB tc filter add dev eth0 ingress bpf da obj "$OBJ" sec tc
	ok "tc ingress 부착"
}

# ------------------------------------------------------- 맵 · 통계 헬퍼
map_id() { bpftool map show | awk -v n="$1" '$0 ~ ("name " n) {gsub(":","",$1); print $1; exit}'; }

be_mac() { ip netns exec $NS_BE cat /sys/class/net/eth0/address; }

# $1=family $2=src $3=dst $4=flags(hex, 예: 01)
set_entry() {
	bpftool map update id "$(map_id lb_assign)" \
		key hex $(python3 $T/hexkey.py "$1" "$2" "$3") \
		value hex $(be_mac | tr ':' ' ') "$4" 00
}

del_entry() {
	bpftool map delete id "$(map_id lb_assign)" \
		key hex $(python3 $T/hexkey.py "$1" "$2" "$3")
}

counter() { # $1=이름
	bpftool -j map dump id "$(map_id lb_stats)" | python3 $T/sumstats.py --one "$1"
}

populate() {
	say "배정표 채우기"
	note "lb_assign map id = $(map_id lb_assign)"
	set_entry 4 "$CL4" "$VIP4" 01
	ok "v4  $CL4 → $VIP4  ⇒  $(be_mac)"
	set_entry 6 "$CL6" "$VIP6" 01
	ok "v6  $CL6 → $VIP6  ⇒  $(be_mac)"
}

# ------------------------------------------------------------- TCP 시험
tcp_one() { # $1=label $2=vip
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

tcp_test() {
	say "TCP IPv4 — DSR 왕복"
	tcp_one IPv4 "$VIP4"
	say "TCP IPv6 — DSR 왕복"
	tcp_one IPv6 "$VIP6"
}

# ------------------------------------------------------------- UDP 시험
udp_one() { # $1=label $2=vip $3=extra(옵션: --bind-any) $4=expect(ok|fail)
	local label=$1 vip=$2 extra=${3:-} expect=${4:-ok} out rc=0 lpid

	ip netns exec $NS_BE python3 $T/udp_listener.py "$vip" "$UPORT" $extra &
	lpid=$!
	sleep 0.4
	out=$(ip netns exec $NS_CL timeout 6 python3 $T/udp_client.py "$vip" "$UPORT" 2>&1) || rc=$?
	wait $lpid 2>/dev/null || true

	if [ "$expect" = ok ]; then
		if [ $rc -eq 0 ] && echo "$out" | grep -q "peer  : $vip"; then
			ok "$label 성공 — 응답 출발지가 VIP"
			echo "$out" | sed 's/^/        /'
		else
			bad "$label 실패 (rc=$rc)"
			echo "$out" | sed 's/^/        /'
		fi
	else
		if [ $rc -ne 0 ]; then
			ok "$label 예상대로 실패 — 0.0.0.0 바인딩은 DSR 이 깨진다"
			note "커널이 라우팅으로 출발지를 골라 VIP 가 아닌 주소로 응답"
			note "connect() 한 소켓이라 클라이언트 커널이 버림 → 타임아웃"
		else
			bad "$label 실패해야 하는데 성공했다"
			echo "$out" | sed 's/^/        /'
		fi
	fi
}

udp_test() {
	say "UDP IPv4 — VIP 바인딩 (정상)"
	udp_one "UDP IPv4" "$VIP4" "" ok
	say "UDP IPv6 — VIP 바인딩 (정상)"
	udp_one "UDP IPv6" "$VIP6" "" ok
	say "UDP IPv4 — 0.0.0.0 바인딩 (설계 메모 10·11번 확인)"
	udp_one "UDP any-bind" "$VIP4" "--bind-any" fail
}

# --------------------------------------------------- IPv6 단편화 시험
#
# 핵심 판정은 "첫 조각과 후속 조각이 같은 결론" 이다.
# 갈리면 일부만 백엔드에 도착해 재조립이 깨진다.
frag_one() { # $1=mode $2=기대 카운터 이름 $3=기대 증가분
	local mode=$1 want=$2 n=$3 before after delta lbmac clmac

	before=$(counter "$want")
	lbmac=$(ip netns exec $NS_LB cat /sys/class/net/eth0/address)
	clmac=$(ip netns exec $NS_CL cat /sys/class/net/eth0/address)

	ip netns exec $NS_CL python3 $T/send_frag6.py eth0 "$lbmac" "$clmac" "$CL6" "$VIP6" "$mode" | sed 's/^/        /'
	sleep 0.3

	after=$(counter "$want")
	delta=$((after - before))
	if [ "$delta" -eq "$n" ]; then
		ok "mode=$mode · $want +$delta (기대 $n) — 두 조각 판정 일치"
	else
		bad "mode=$mode · $want +$delta (기대 $n) — 조각 간 판정이 갈림"
	fi
}

frag_test() {
	say "IPv6 단편화 — 조각 간 판정 일관성 (RFC 8200 4.5)"
	note "전달 판정이 L4 를 안 보므로 세 형태 모두 두 조각이 그대로 전달된다"
	frag_one udp      REDIRECT 2
	frag_one icmp6    REDIRECT 2
	frag_one dstopts  REDIRECT 2
	note "FRAG_LATER = $(counter FRAG_LATER)  (관측용 — 전달 판정에는 미사용)"
	note "PROTO_OTHER = $(counter PROTO_OTHER)  (TCP/UDP 아님 — 전달은 했다)"
}

# ------------------------------------------------- IPv6 ND 예외 시험
#
# 전달 판정에서 L4 를 뺐으므로 VIP 로 오는 ICMPv6 도 백엔드로 간다.
# 단 하나의 예외가 ND 다 — NUD 가 보내는 유니캐스트 NS 는 목적지가 VIP 라
# 키가 맞는데, 전달하면 백엔드가 자기 MAC 으로 NA 를 돌려준다. 클라이언트
# 캐시가 그 MAC 으로 갱신되면 이후 트래픽이 LB 를 건너뛴다.
nd_test() {
	say "IPv6 ND — 주소 해석만 커널에 남긴다"
	local lbmac clmac before after delta
	lbmac=$(ip netns exec $NS_LB cat /sys/class/net/eth0/address)
	clmac=$(ip netns exec $NS_CL cat /sys/class/net/eth0/address)

	before=$(counter ND)
	ip netns exec $NS_CL python3 $T/send_nd6.py eth0 "$lbmac" "$clmac" "$CL6" "$VIP6" ns | sed 's/^/        /'
	sleep 0.3
	after=$(counter ND); delta=$((after - before))
	if [ "$delta" -eq 1 ]; then
		ok "유니캐스트 NS · ND +$delta — 전달 안 함 (캐시 오염 방지)"
	else
		bad "유니캐스트 NS · ND +$delta (기대 1)"
	fi

	before=$(counter REDIRECT)
	ip netns exec $NS_CL python3 $T/send_nd6.py eth0 "$lbmac" "$clmac" "$CL6" "$VIP6" echo | sed 's/^/        /'
	sleep 0.3
	after=$(counter REDIRECT); delta=$((after - before))
	if [ "$delta" -eq 1 ]; then
		ok "ICMPv6 echo · REDIRECT +$delta — VIP 소유자인 백엔드가 응답"
	else
		bad "ICMPv6 echo · REDIRECT +$delta (기대 1)"
	fi
	note "ND = $(counter ND)  ·  PROTO_OTHER = $(counter PROTO_OTHER)"
}

# -------------------------------------------------------- 음성 경로 시험
negative_test() {
	local before after rc

	say "INACTIVE — 백엔드를 비활성으로 (TC_ACT_SHOT 으로 차단)"
	before=$(counter INACTIVE)
	set_entry 4 "$CL4" "$VIP4" 00
	note "flags = 0x00 으로 변경"
	rc=0
	ip netns exec $NS_CL timeout 4 python3 $T/connect.py "$VIP4" "$PORT" >/dev/null 2>&1 || rc=$?
	after=$(counter INACTIVE)
	if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ]; then
		ok "전달 안 됨 · INACTIVE $before → $after"
	else
		bad "rc=$rc · INACTIVE $before → $after"
	fi
	set_entry 4 "$CL4" "$VIP4" 01
	note "flags 복구"

	say "MISS — 배정표에서 제거 (모르는 출발지 모사)"
	before=$(counter MISS)
	del_entry 4 "$CL4" "$VIP4"
	note "v4 항목 삭제"
	rc=0
	ip netns exec $NS_CL timeout 4 python3 $T/connect.py "$VIP4" "$PORT" >/dev/null 2>&1 || rc=$?
	after=$(counter MISS)
	if [ "$rc" -ne 0 ] && [ "$after" -gt "$before" ]; then
		ok "통과됨 · MISS $before → $after"
	else
		bad "rc=$rc · MISS $before → $after"
	fi
	set_entry 4 "$CL4" "$VIP4" 01
	note "항목 복구"
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
tcp)      need_root; tcp_test; finish ;;
udp)      need_root; udp_test; finish ;;
frag)     need_root; frag_test; finish ;;
nd)       need_root; nd_test; finish ;;
negative) need_root; negative_test; finish ;;
stats)    need_root; stats ;;
teardown) need_root; teardown ;;
all)      need_root; setup; populate; tcp_test; udp_test; frag_test; nd_test; negative_test; stats
          say "정리하려면: sudo $0 teardown"
          finish ;;
*)        echo "사용: sudo $0 [all|setup|populate|tcp|udp|frag|nd|negative|stats|teardown]"; exit 1 ;;
esac
