/* SPDX-License-Identifier: GPL-2.0 */
/*
 * eBPF 데이터 경로와 유저공간(제어부·시험 도구)이 공유하는 타입.
 * Go 에이전트가 생기면 이 헤더에서 타입을 생성한다.
 */
#ifndef LB_COMMON_H
#define LB_COMMON_H

/* 외부 시스템 10~20개 × VIP 2개(듀얼스택이면 4개) 를 넉넉히 덮는다. */
#define LB_MAX_ASSIGN 1024

/* 802.1Q + QinQ 까지. 그 이상은 이 환경에서 나올 이유가 없다. */
#define LB_MAX_VLAN_DEPTH 2

/* IPv6 확장헤더 체인 상한. 정상 트래픽에서 2개를 넘길 일이 없다. */
#define LB_MAX_EXTHDR 4

/* 확장헤더를 따라가다 멈출 바이트 오프셋 상한 (무한 루프 방지). */
#define LB_MAX_HDR_OFF 512

/*
 * 배정표 키.
 *
 * 목적지 VIP 를 키에 포함하는 이유는 15번이다 — 프라이머리/세컨더리 VIP 마다
 * 별도 배정표를 두고, 한 시스템의 두 백엔드가 겹치지 않게 한다.
 *
 * 출발지 포트는 키에 넣지 않는다. 14번 B안대로 출발지 IP 기준이라야
 * 재접속으로 포트가 바뀌어도 같은 백엔드로 간다.
 * 부수 효과로 IP 단편화도 자동 해결된다 — 모든 조각이 같은 키가 된다(10번).
 *
 * 키에 L4 가 없으므로 전달 판정도 L4 를 보지 않는다. 등록된 출발지가 VIP 로
 * 보낸 IP 패킷이면 프로토콜과 무관하게 백엔드로 넘긴다. IPv6 단편의 후속
 * 조각은 L4 를 알아낼 방법이 아예 없으므로(RFC 8200 4.5) 이 편이 구조적으로
 * 안전하다 — 조각 간 결론이 갈릴 자리가 없다.
 *
 * 듀얼스택을 맵 하나로 다루려고 주소를 16바이트 고정으로 둔다(8번).
 * IPv4 는 앞 4바이트만 쓰고 나머지는 0이다.
 */
struct lb_key {
	__u8 family; /* 4 | 6 */
	__u8 pad[3];
	__u8 saddr[16];
	__u8 daddr[16];
};

/*
 * 값에 백엔드 MAC 을 함께 둬서 패킷당 맵 조회를 1회로 끝낸다(19.12).
 * 배정표와 MAC 을 따로 두면 조회가 두 번이 된다.
 */
struct lb_dest {
	__u8 mac[6];
	__u8 flags;
	__u8 pad;
};

#define LB_DEST_ACTIVE 0x01 /* 헬스체크 결과. 꺼지면 전달하지 않는다 */

/* lb_stats 맵의 인덱스. per-CPU 이므로 읽을 때 합산해야 한다. */
enum lb_stat {
	LB_STAT_RX = 0,	    /* 이더넷 헤더까지 파싱된 전체 패킷 */
	LB_STAT_REDIRECT,   /* MAC 변경 후 egress 로 되돌림 */
	LB_STAT_MISS,	    /* 배정표에 없음 — 폴백은 다음 단계 */
	LB_STAT_NOT_IP,	    /* IPv4/IPv6 가 아님 (ARP 등) */
	LB_STAT_PROTO_OTHER,/* TCP/UDP 가 아님 — 관측용, 전달은 한다 */
	LB_STAT_INACTIVE,   /* 배정은 있으나 백엔드가 비활성 */
	LB_STAT_MALFORMED,  /* 헤더가 잘렸거나 ihl 이 비정상 */
	LB_STAT_STORE_FAIL, /* MAC 쓰기 실패 */
	LB_STAT_VLAN,	    /* 인라인 VLAN 태그를 건너뛴 패킷 */
	LB_STAT_EXTHDR,	    /* IPv6 확장헤더를 따라간 패킷 */
	LB_STAT_EXTHDR_DEEP,/* 확장헤더 상한 초과 — 관측용 */
	LB_STAT_FRAG_LATER, /* IPv6 후속 조각 — 관측용 */
	LB_STAT_ND,	    /* IPv6 ND — 주소 해석은 커널이 한다 */
	LB_STAT__MAX,
};

#endif /* LB_COMMON_H */
