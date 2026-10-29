// SPDX-License-Identifier: GPL-2.0
/*
 * tc ingress L4 로드밸런서 — 1단계 성능 스파이크 (설계 메모 19.12)
 *
 * 하는 일
 *   배정표에서 백엔드를 찾아 목적지 MAC 만 바꾸고 같은 인터페이스 egress 로
 *   되돌린다. IP·TCP 헤더는 건드리지 않으므로 백엔드가 자기 lo VIP 로 온
 *   패킷으로 인식하고 출발지 VIP 로 직접 응답한다 (3·4번, DSR).
 *
 * 안 하는 일 — 전부 제어부 몫이다
 *   Maglev 폴백, 헬스체크 판정, 배정 계산, 백엔드 MAC 해석.
 *   이 단계에서는 bpftool 로 맵을 손으로 채운다.
 *
 * 전제
 *   tc 파드와 백엔드가 같은 L2(같은 Multus 서브넷)에 있다 (6번).
 *   L2 만 바꾸므로 IP·L4 체크섬은 재계산할 필요가 없다.
 *
 * 전달 판정에 L4 를 쓰지 않는다
 *   키가 (출발지 IP, VIP) 이므로 L4 를 알 필요가 없다. 등록된 출발지가 VIP 로
 *   보낸 IP 패킷이면 프로토콜과 무관하게 백엔드로 넘긴다. VIP 를 소유한 쪽이
 *   백엔드이므로 그 VIP 의 ICMP 에 답할 주체도 백엔드다.
 *
 *   이 구조가 중요한 까닭은 IPv6 단편이다. Fragment 뒤의 헤더는 첫 조각에만
 *   들어 있어 후속 조각만으로 L4 를 알아낼 방법이 없다(RFC 8200 4.5). L4 를
 *   판정에서 빼면 조각 간 결론이 갈릴 자리가 아예 없어진다.
 *
 *   프로토콜 분류는 통계로만 남긴다 — 틀려도 전달에 영향이 없다.
 *
 * 예외는 주소 해석뿐
 *   IPv6 ND 는 커널에 남긴다. 백엔드가 NA 를 돌려주면 클라이언트의 neighbor
 *   캐시가 백엔드 MAC 으로 갱신되어 이후 트래픽이 LB 를 건너뛴다.
 *
 * 알려진 한계
 *   VIP 로 오는 ICMP 오류(PMTUD 등)는 출발지가 라우터라 배정표에 맞지 않아
 *   통과된다. 키가 출발지 IP 기준인 한 구조적이며, 다루려면 ICMP 오류
 *   페이로드의 원본 IP 헤더를 파싱해 역조회하는 경로가 따로 필요하다.
 */
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

#include "lb_common.h"

/* <linux/in6.h> 를 끌어오면 커널 헤더와 충돌하므로 직접 둔다. */
#define IPPROTO_HOPOPTS_  0
#define IPPROTO_ROUTING_  43
#define IPPROTO_FRAGMENT_ 44
#define IPPROTO_NONE_     59
#define IPPROTO_DSTOPTS_  60
#define IPPROTO_ICMPV6_   58

/* ND 메시지 타입 범위 (RFC 4861) — RS · RA · NS · NA · Redirect */
#define ICMPV6_ND_FIRST 133
#define ICMPV6_ND_LAST  137

struct vlan_tag {
	__be16 tci;
	__be16 encap_proto;
};

/*
 * 확장헤더 앞 4바이트.
 *   nexthdr  다음 헤더 종류
 *   hdrlen   8바이트 단위 길이, 첫 8바이트는 제외 (Fragment 헤더에서는 reserved)
 *   w2       Fragment 헤더에서만 의미가 있다 — offset(13) | res(2) | M(1)
 */
struct ext_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
	__be16 w2;
};

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, struct lb_key);
	__type(value, struct lb_dest);
	__uint(max_entries, LB_MAX_ASSIGN);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lb_assign SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, LB_STAT__MAX);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} lb_stats SEC(".maps");

static __always_inline void bump(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&lb_stats, &slot);

	if (v)
		(*v)++;
}

/*
 * IPv6 확장헤더 체인을 따라가 L4 프로토콜과 그 오프셋을 찾는다.
 *
 * 포인터 산술 대신 bpf_skb_load_bytes 와 스칼라 오프셋을 쓴다. 가변 길이
 * 전진을 포인터로 하면 verifier 를 설득하기 까다롭지만, 헬퍼는 런타임에
 * 경계를 확인해 주므로 오프셋만 상한을 두면 된다.
 *
 * 결과는 통계와 ND 판별에만 쓴다. 전달 여부는 배정표만 보고 정하므로 여기서
 * L4 를 못 찾아도 패킷은 그대로 전달된다. 이 함수가 틀려도 조각 간 판정이
 * 갈리지 않는다는 뜻이다 — 1·2차 리뷰에서 지적된 문제가 모두 이 자리에서
 * 나왔으므로, 결정 권한을 빼는 것이 핵심이다.
 *
 * Fragment 헤더(RFC 8200 4.5)를 만나면 거기서 탐색을 끝낸다. 실물 헤더는 첫
 * 조각에만 있어 더 따라가면 후속 조각에서 엉뚱한 바이트를 읽는다.
 */
static __always_inline __u8 skip_exthdrs(struct __sk_buff *skb, __u8 nexthdr,
					 __u32 off, int *walked, int *frag,
					 int *later_frag, __u32 *l4_off)
{
	*walked = 0;
	*frag = 0;
	*later_frag = 0;

#pragma unroll
	for (int i = 0; i < LB_MAX_EXTHDR; i++) {
		struct ext_hdr eh;
		__u8 cur = nexthdr;

		if (cur != IPPROTO_HOPOPTS_ && cur != IPPROTO_ROUTING_ &&
		    cur != IPPROTO_FRAGMENT_ && cur != IPPROTO_DSTOPTS_)
			break;

		if (off > LB_MAX_HDR_OFF)
			break;
		if (bpf_skb_load_bytes(skb, off, &eh, sizeof(eh)) < 0)
			break;

		nexthdr = eh.nexthdr;
		(*walked)++;

		if (cur == IPPROTO_FRAGMENT_) {
			*frag = 1;
			/* 상위 13비트가 fragment offset. 0 이 아니면 후속 조각이다. */
			if (bpf_ntohs(eh.w2) & 0xfff8)
				*later_frag = 1;
			off += 8; /* Fragment 헤더는 길이가 고정이다 */
			break;
		}
		off += ((__u32)eh.hdrlen + 1) * 8;
	}

	*l4_off = off;
	return nexthdr;
}

SEC("tc")
int lb_ingress(struct __sk_buff *skb)
{
	void *data = (void *)(long)skb->data;
	void *data_end = (void *)(long)skb->data_end;
	struct ethhdr *eth = data;
	struct lb_key key = {};
	struct lb_dest *dst;
	__u8 newmacs[ETH_ALEN * 2];
	__u8 l4proto;
	void *l3;
	__be16 h_proto;
	__u32 l3_off = sizeof(*eth);
	__u32 l4_off = 0;
	int vlan_tags = 0;
	int frag = 0;
	int later_frag = 0;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;

	bump(LB_STAT_RX);

	/*
	 * 인라인 VLAN 태그 건너뛰기.
	 *
	 * Multus NAD 가 VLAN 을 종단하거나 NIC 가 태그를 skb 메타데이터로
	 * 벗겨 주면 여기 해당 사항이 없다. 부모 인터페이스에 붙여 태그가
	 * 패킷 데이터에 남는 구성에서만 동작한다.
	 * 태그는 읽기만 하고 건드리지 않는다 — 같은 L2 라 그대로 나가야 한다.
	 */
	l3 = (void *)(eth + 1);
	h_proto = eth->h_proto;

#pragma unroll
	for (int i = 0; i < LB_MAX_VLAN_DEPTH; i++) {
		struct vlan_tag *vt = l3;

		if (h_proto != bpf_htons(ETH_P_8021Q) &&
		    h_proto != bpf_htons(ETH_P_8021AD))
			break;
		if ((void *)(vt + 1) > data_end) {
			bump(LB_STAT_MALFORMED);
			return TC_ACT_OK;
		}
		h_proto = vt->encap_proto;
		l3 = (void *)(vt + 1);
		l3_off += sizeof(*vt);
		vlan_tags++;
	}
	if (vlan_tags)
		bump(LB_STAT_VLAN);

	if (h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = l3;

		if ((void *)(ip + 1) > data_end) {
			bump(LB_STAT_MALFORMED);
			return TC_ACT_OK;
		}
		/* ihl 이 5 미만이면 조작된 패킷이다. 옵션(>5)은 그대로 둔다 —
		 * 주소와 프로토콜은 고정 위치라 파싱에 영향이 없다. */
		if (ip->ihl < 5) {
			bump(LB_STAT_MALFORMED);
			return TC_ACT_OK;
		}
		key.family = 4;
		__builtin_memcpy(key.saddr, &ip->saddr, 4);
		__builtin_memcpy(key.daddr, &ip->daddr, 4);
		l4proto = ip->protocol;
	} else if (h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = l3;
		int walked;

		if ((void *)(ip6 + 1) > data_end) {
			bump(LB_STAT_MALFORMED);
			return TC_ACT_OK;
		}
		key.family = 6;
		__builtin_memcpy(key.saddr, &ip6->saddr, 16);
		__builtin_memcpy(key.daddr, &ip6->daddr, 16);

		l4proto = skip_exthdrs(skb, ip6->nexthdr,
				       l3_off + sizeof(*ip6), &walked, &frag,
				       &later_frag, &l4_off);
		if (walked)
			bump(LB_STAT_EXTHDR);
		if (walked >= LB_MAX_EXTHDR)
			bump(LB_STAT_EXTHDR_DEEP);
		/* 관측용 — 전달 판정에는 쓰지 않는다 */
		if (later_frag)
			bump(LB_STAT_FRAG_LATER);
	} else {
		bump(LB_STAT_NOT_IP);
		return TC_ACT_OK;
	}

	/*
	 * 주소 해석만 예외로 커널에 남긴다.
	 *
	 * IPv4 ARP 는 IP 가 아니라 위에서 NOT_IP 로 빠진다. IPv6 도 멀티캐스트
	 * NS 는 목적지가 solicited-node 주소라 배정표에 맞지 않는다. 그런데 NUD
	 * 가 보내는 유니캐스트 NS 는 목적지가 VIP 라 키가 맞아 버린다.
	 *
	 * 그대로 전달하면 백엔드가 자기 MAC 을 실은 NA 를 돌려주고, 클라이언트의
	 * neighbor 캐시가 그 MAC 으로 갱신된다. 이후 트래픽이 LB 를 건너뛰어 분산
	 * 도 절체도 무력화된다.
	 *
	 * 단편이면 위치와 무관하게 이 검사를 건너뛴다. 첫 조각만 ND 로 걸러내면
	 * 후속 조각은 전달되어 판정이 다시 갈린다. ND 는 단편화되지 않으므로
	 * 실제로 잃는 것은 없다.
	 */
	if (key.family == 6 && l4proto == IPPROTO_ICMPV6_ && !frag) {
		__u8 icmp6_type;

		if (bpf_skb_load_bytes(skb, l4_off, &icmp6_type, 1) == 0 &&
		    icmp6_type >= ICMPV6_ND_FIRST &&
		    icmp6_type <= ICMPV6_ND_LAST) {
			bump(LB_STAT_ND);
			return TC_ACT_OK;
		}
	}

	/*
	 * 여기서부터는 관측만 한다. TCP/UDP 가 아니어도 전달한다 — 키에 L4 가
	 * 없으니 전달을 막을 근거가 없다. 이 값이 0 이 아니면 어떤 프로토콜이
	 * 들어오는지 들여다볼 신호다.
	 */
	if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP)
		bump(LB_STAT_PROTO_OTHER);

	/*
	 * 맵에 없는 목적지는 우리 VIP 가 아니거나 아직 배정이 없는 경우다.
	 * 둘을 구분하려면 VIP 집합 맵이 하나 더 필요한데, 조회를 1회로 묶기
	 * 위해 이 단계에서는 구분하지 않고 커널로 넘긴다.
	 */
	dst = bpf_map_lookup_elem(&lb_assign, &key);
	if (!dst) {
		bump(LB_STAT_MISS);
		return TC_ACT_OK;
	}
	/*
	 * 비활성 백엔드로 가는 트래픽은 버린다.
	 *
	 * 통과시키면 목적지 VIP 가 LB 의 로컬 주소가 아니므로 커널 라우팅에
	 * 맡겨지고, ip_forward 설정에 따라 되돌아 나가는 루프가 생길 수 있다.
	 * 명시적으로 버리는 편이 결정론적이다.
	 *
	 * 비활성은 짧은 과도 상태다 — 제어부가 곧 살아있는 백엔드로 재배정한다
	 * (19.8). 그동안 클라이언트는 TCP 재전송으로 버틴다.
	 */
	if (!(dst->flags & LB_DEST_ACTIVE)) {
		bump(LB_STAT_INACTIVE);
		return TC_ACT_SHOT;
	}

	/*
	 * 출발지 MAC 은 현재 목적지 MAC 을 그대로 승계한다.
	 * 스위치가 BGP next-hop 해석으로 우리 MAC 을 적어 보냈으므로
	 * eth->h_dest 가 곧 이 인터페이스의 MAC 이다. 별도 설정이 필요 없다.
	 *
	 * 덮어쓰기 전에 읽어서 한 번에 12바이트를 쓴다.
	 * VLAN 태그가 있어도 MAC 은 오프셋 0 에 있으므로 위치는 같다.
	 */
	__builtin_memcpy(newmacs, dst->mac, ETH_ALEN);
	__builtin_memcpy(newmacs + ETH_ALEN, eth->h_dest, ETH_ALEN);

	/*
	 * 직접 쓰기 대신 store_bytes 를 쓴다. skb 가 복제된 상태(tcpdump 등)
	 * 에서도 안전하게 unclone 해 주기 때문이다. 직접 쓰기가 더 빠르므로
	 * 1b 성능 측정 때 두 방식을 비교한다.
	 * 호출 후 data/data_end 는 무효가 되므로 이후 패킷을 만지지 않는다.
	 */
	if (bpf_skb_store_bytes(skb, 0, newmacs, sizeof(newmacs), 0) < 0) {
		bump(LB_STAT_STORE_FAIL);
		return TC_ACT_OK;
	}

	bump(LB_STAT_REDIRECT);

	/* 같은 L2 헤어핀 — 들어온 인터페이스의 egress 로 되돌린다.
	 * flags 0 이 egress, BPF_F_INGRESS 면 수신 경로다. */
	return bpf_redirect(skb->ifindex, 0);
}
