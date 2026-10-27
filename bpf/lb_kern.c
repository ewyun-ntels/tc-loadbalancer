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
 * 알려진 한계
 *   VIP 로 오는 ICMP 오류(PMTUD 등)는 출발지가 라우터라 배정표에 맞지 않아
 *   통과된다. DSR 의 일반적 제약이며, 필요하면 내장 헤더를 파싱해 원래
 *   백엔드로 보내는 처리를 따로 넣어야 한다.
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

struct vlan_tag {
	__be16 tci;
	__be16 encap_proto;
};

/* 확장헤더 공통 앞 2바이트. hdrlen 은 8바이트 단위이며 첫 8바이트는 제외된다. */
struct ext_hdr {
	__u8 nexthdr;
	__u8 hdrlen;
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
 * IPv6 확장헤더 체인을 따라가 실제 L4 프로토콜을 찾는다.
 *
 * 포인터 산술 대신 bpf_skb_load_bytes 와 스칼라 오프셋을 쓴다. 가변 길이
 * 전진을 포인터로 하면 verifier 를 설득하기 까다롭지만, 헬퍼는 런타임에
 * 경계를 확인해 주므로 오프셋만 상한을 두면 된다.
 *
 * L4 헤더 자체는 읽지 않는다 — 키에 포트가 없기 때문이다.
 */
static __always_inline __u8 skip_exthdrs(struct __sk_buff *skb, __u8 nexthdr,
					 __u32 off, int *walked)
{
	*walked = 0;

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
		/* Fragment 헤더만 길이가 8바이트 고정이다. */
		off += (cur == IPPROTO_FRAGMENT_) ? 8 : ((__u32)eh.hdrlen + 1) * 8;
		(*walked)++;
	}

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
	int vlan_tags = 0;

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
				       l3_off + sizeof(*ip6), &walked);
		if (walked)
			bump(LB_STAT_EXTHDR);
		if (walked >= LB_MAX_EXTHDR)
			bump(LB_STAT_EXTHDR_DEEP);
	} else {
		bump(LB_STAT_NOT_IP);
		return TC_ACT_OK;
	}

	/*
	 * L4 포트는 보지 않는다 — 키가 출발지 IP 기준이기 때문이다(lb_common.h).
	 * 프로토콜 확인만으로 ICMP·ND 등을 걸러 커널이 직접 처리하게 둔다(10번).
	 */
	if (l4proto != IPPROTO_TCP && l4proto != IPPROTO_UDP) {
		bump(LB_STAT_NOT_L4);
		return TC_ACT_OK;
	}

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
	if (!(dst->flags & LB_DEST_ACTIVE)) {
		bump(LB_STAT_INACTIVE);
		return TC_ACT_OK;
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
