# Go 제어부

기존 `bpf/lb_kern.c`와 `bpf/lb_common.h`를 그대로 사용하는 첫 Go 제어부다.
데이터 경로는 `(출발지 IP, VIP) → MAC + ACTIVE` 한 번 조회를 유지한다.

## 구성

| 경로 | 역할 |
| --- | --- |
| `cmd/lbctl` | 점검 시 실행하는 배정표 생성·검증 CLI |
| `cmd/lb-agent` | 각 TC LB 파드 안에서 실행하는 에이전트 |
| `internal/control` | Maglev, 알려진 클라이언트 균등 배정, 장애 재배정, 맵 ABI |
| `internal/agent` | 설정 재적용, TCP 헬스체크·히스테리시스, DNS·ARP/ND, BIRD, HTTP |
| `internal/dataplane` | cilium/ebpf ELF 로딩, 전용 pin, legacy TC direct-action 연결 |
| `test/agent_smoke.py` | 별도 netns·veth·브리지에서 제어부와 DSR 통합 검증 |

## 빌드와 실행

Linux, Go 1.24 이상, clang/LLVM, libbpf 개발 헤더가 필요하다. 에이전트 실행에는
BPF 로딩·TC 연결·인터페이스 바인딩 권한과 마운트된 bpffs가 필요하다.
WSL의 기존 `/usr/local/go/bin/go`가 1.18이면 새 Go를 별도 준비한다.

```sh
make                              # 기존 C 데이터 경로 빌드
make -f Makefile.control build     # bin/lb-agent, bin/lbctl
make -f Makefile.control test
make -f Makefile.control check

bin/lbctl generate -plan configs/plan.example.json -out /tmp/assignments.json
bin/lbctl validate -table /tmp/assignments.json
bin/lb-agent -config configs/agent.example.json -table /tmp/assignments.json -check
```

`-check`는 설정·배정표·ELF의 실제 BTF ABI를 읽기만 하며 TC나 맵을 변경하지 않는다.
예제 IP는 문서용이다. 실제 net1의 IPAM 구간, 백엔드 주소, VIP, 헬스 포트로 바꾼 뒤 실행한다.

```sh
sudo bin/lb-agent -config /etc/tc-lb/agent.json -table /etc/tc-lb/assignments.json
curl http://127.0.0.1:9090/readyz
curl http://127.0.0.1:9090/status
curl http://127.0.0.1:9090/metrics
```

에이전트는 현재 네트워크 네임스페이스의 `interface`에 연결한다. Pod의 net1에
붙이려면 같은 Pod 네트워크 네임스페이스에서 실행한다. 물리 NIC·bond·VLAN을
자동 탐색하거나 host 인터페이스로 이동시키지 않는다. 대상 인터페이스는 직접 지정한다.

## 배정 정책

`plan.example.json`은 안정적인 백엔드 ID(StatefulSet 서수), 클라이언트 ID·주소,
Primary·Secondary VIP를 담는다. `lbctl`이 최종 배정표를 만들어 모든 LB에 동일하게 배포한다.

- 백엔드 ID를 정렬하고 고정 해시·소수 크기 65537로 동등 가중치 Maglev 표를 만든다.
- 적은 클라이언트 10~20개는 Maglev 해시만으로 균등해지지 않는다. Maglev에서 후보 순서를
  얻고, 알려진 시스템의 Primary 개수와 같은 Primary 그룹의 Secondary 개수를 명시적으로 분산한다.
- 따라서 이 CLI는 **순수 Maglev 슬롯 조회 결과를 그대로 배정하는 구현이 아니다**.
  Primary·Secondary 분리 제약과 유한한 시스템 수의 균형을 추가한 배정 도구다.
- 같은 논리 시스템의 여러 주소는 같은 배정을 받는다. v4/v6의 백엔드 집합이 같으면
  두 주소 계열도 같은 배정을 받는다. 균형 기준은 시스템 개수이며 TPS·CPU·연결 수가 아니다.
- Primary/Secondary 동일 백엔드와 중복 `(출발지 IP, VIP)` 키를 거부한다.
- 장애 재배정은 HRW(별도 결정론적 해시)로 처리한다. 정상 기준 배정은 유지하고,
  장애 난 기준 배정만 바꾸며 짝의 정상 백엔드를 피한다.
- 한 대만 살아 있으면 두 VIP에 같은 백엔드를 넣지 않고 한쪽은 INACTIVE로 둔다.
  각 클라이언트가 Primary/Secondary 중 최소 한 경로를 가지면 해당 주소 계열의 VIP 광고를
  유지한다. 정상 기준 배정은 바꾸지 않으므로 살아있는 쪽이 Secondary이면 Primary가
  INACTIVE일 수 있다. 클라이언트가 두 VIP 사이에서 재접속하는 설계가 전제다.
  일부 행이 INACTIVE면 `degraded=true`와 `tc_lb_degraded=1`로 노출한다.
- IPv4/IPv6의 생존 집합과 광고를 분리한다. 어느 계열에도 경로가 없으면 전체 철회하고,
  한 계열만 서비스 가능하면 그 계열만 광고한다. `/readyz`는 서비스 가능한 계열이 하나 이상이면 성공한다.
- 복구하면 원래 배정으로 돌아간다. 이때 fallback 백엔드에 있던 TCP 연결은 재접속할 수 있다.
  백엔드가 바뀐 TCP 연결의 상태를 이전하거나 연결 자체를 보존하는 기능은 없다.

구성 변경도 재배정을 일으킬 수 있으므로 점검 절차에서 수행한다. 자동 부하 추종이나
수동 고정 배정 최적화는 아직 없다. 생성 후 표를 검토·수정하고 `validate`로 검사할 수 있다.

## 에이전트 동작

1. JSON 설정·배정표를 검증하고 인터페이스별 프로세스 잠금을 얻는다.
2. 전용 bpffs 경로에 맵·프로그램을 로딩하고, 지정한 전용 BIRD VIP 프로토콜을 비활성화한다.
3. 백엔드 주소를 해석하고 **net1 주소를 출발지로, 해당 인터페이스에 바인딩한 TCP connect**를 수행한다.
4. 같은 인터페이스의 ARP/ND 이웃에서 MAC을 찾는다. MAC까지 사용할 수 있어야 정상 후보가 된다.
5. 기본적으로 한 번 성공하면 활성화한다(`rise=1`). 예제 JSON은 `rise`를 생략하고 코드 기본값을 사용한다. 명시적으로 설정한 `rise` 값도 지원한다. 연속 `fall`회 실패로 제외하고 결정론적으로 재배정한다.
6. 맵을 채운 뒤 TC 필터를 확인하고, 각 클라이언트가 최소 한 VIP 경로를 갖는 주소 계열의 BIRD 광고를 활성화한다.

MAC·IP가 바뀐 백엔드는 성공 임계값을 새로 채운다. ARP/ND·인터페이스 열거 등 조회가
일시 실패하면 마지막으로 검증한 IP·MAC을 유지한 채 실패 횟수를 누적하고, `fall`에 도달하면
전달 대상에서 제외한다. 조회 실패로 생긴 빈 IP·MAC을 엔드포인트 교체로 오인하지 않는다.
새 IP가 확인됐거나 자기 MAC·허용 범위 밖 주소·게이트웨이 경로처럼 실제로 안전하지 않은
엔드포인트가 확인되면 기존 정상 상태를 재사용하지 않고 즉시 제외한다.
`backend_prefixes`는 백엔드
**할당 구간**을 CIDR로 제한한다. VIP는 그 구간 밖이어야 한다. 같은 L2 서브넷 전체를
무조건 넣지 말고 whereabouts의 백엔드 전용 범위를 표현한다. `forbidden_prefixes`에는
LB 전용 할당 구간을 넣을 수 있다. 같은 인터페이스의 직접 연결 경로만 허용하고,
자기 네임스페이스의 모든 IP·MAC, 멀티캐스트/잘못된 MAC, 게이트웨이를 통한 경로를 거부한다.
동일 주소 계열에서 두 백엔드 ID가 같은 IP나 MAC을 가리켜도 광고하지 않는다.

`ipv4`·`ipv6`는 실제 Multus IP 또는 해당 주소를 반환하는 DNS 이름이다. 일반 Kubernetes
Headless Service DNS는 대개 **eth0 Pod IP**를 반환한다. StatefulSet 이름만 넣으면 net1을
알 수 있다는 가정은 하지 않는다. Multus 주소를 게시하는 DNS/외부 주소 공급이 필요하며,
현재 버전에서는 명시적 net1 IP도 사용할 수 있다.

DNS 실패 시 직전 IP로 직접 헬스체크를 계속한다. 처음 보는 백엔드는 주소를 얻기 전까지
비활성이다. 배정표 파일이 사라지거나 JSON·세대 검사가 실패해도 마지막으로 수락한 표를
메모리에 유지한다. Pod 재시작을 넘는 설정 보존은 마운트한 설정 볼륨이 맡는다.

## 배정표 갱신과 맵 소유권

`lbctl generate -out`은 임시 파일을 쓴 뒤 rename한다. 변경할 때 `generation`을 증가시킨다.
에이전트는 각 체크 주기에 다시 읽으며, 이전 세대와 같은 세대의 내용 변경을 거부한다.
CRD informer·RBAC·Kubernetes API 클라이언트는 첫 버전에 포함하지 않았다.
ConfigMap/projected volume 또는 외부 배포기가 같은 JSON 산출물을 공급할 수 있다.

맵은 기본 `/sys/fs/bpf/tc-lb-net1/` 안에만 pin한다. 기존 테스트의 bpffs 루트 맵과
분리된다. 맵 종류·크기와 ELF의 구조체 필드 오프셋을 확인하고, 재시작 때는 프로그램의
tag 및 참조 map ID까지 확인한다. 다른 ingress 필터가 있으면 덮어쓰지 않고 거부한다.
따라서 같은 장치에서 CNI의 TC 프로그램과 공존하는 구성은 별도 설계·시험이 필요하다.

매 조정 주기마다 맵 동기화 후 실제 ingress 필터의 프로그램 ID·프로토콜·우선순위·handle을
다시 확인한다. 자기 필터 또는 clsact만 사라졌고 다른 ingress 필터가 없으면 동일 프로그램으로
재연결한다. 다른 필터가 생겼거나 재연결이 실패하면 `/readyz`를 먼저 실패로 바꾸고 VIP 광고를
철회한다. 같은 이름의 인터페이스가 다른 ifindex로 재생성된 경우도 자동 채택하지 않고 광고를
철회하며 에이전트 재시작을 요구한다. bond 절체 등으로 MAC만 바뀐 경우는 이를 인터페이스
재생성으로 취급하지 않는다. 감지·복구는 조정 주기에 이루어지므로 유실 순간부터 다음 검사까지의
트래픽 손실을 없애는 보장은 아니다.

맵 변경은 **항목별 갱신**이며 전체 표의 원자적 교체가 아니다. 기존 C의 단일 hash 맵으로
전체 교체를 보장할 수 없다. 실패 시 광고를 철회하고 재시도한다. 전체 세대 원자 전환이
필요하면 C 데이터 경로도 outer map 또는 세대 선택 구조로 바꿔야 한다.

삭제된 배정은 키를 지우지 않고 `ACTIVE=0` tombstone으로 남긴다. 기존 C에서 MISS가
커널로 PASS되는 동작 때문에, 삭제가 라우팅으로 우회되는 것을 막기 위함이다.
이 항목들도 1024개 용량에 포함된다. 용량 부족은 쓰기 전에 거부한다. tombstone 정리는
VIP 철회·트래픽 중단을 확인한 유지보수 때만 별도 수행한다.

정상 종료는 BIRD 철회 → 설정한 drain 대기 → 자신이 소유한 필터 제거 순서다.
qdisc, 잠금 파일, pin은 재시작을 위해 남긴다. 프로그램 변경 시 자동 업그레이드는 하지
않으며, VIP를 철회한 상태에서 명시적으로 기존 필터·전용 pin을 정리하고 새로 시작한다.

## BIRD 연동

기본 예제는 BIRD 없이 로컬 시험하는 설정이다. 실제 배포 때는 다음을 추가한다.

```json
"bird": {
  "config_file": "/etc/tc-lb/bird.conf",
  "socket": "/run/bird/bird.ctl",
  "ipv4_protocols": ["tc_vips4"],
  "ipv6_protocols": ["tc_vips6"],
  "drain": "2s"
}
```

각 프로토콜은 BGP 피어가 아니라 **이 LB의 VIP만 공급하는 전용 static 프로토콜**이어야 한다.
BIRD 설정에서 처음부터 `disabled;`로 두고 이 경로들만 BGP export하도록 구성한다.
에이전트가 `birdc -v -s ... enable/disable 이름`으로 제어하고 숫자 응답까지 확인한다.
소켓 재접속·BIRD 재시작을 고려해 매 주기 원하는 상태를 다시 적용한다.
기존 `protocols` 배열은 단일 주소 계열에서만 호환 지원한다. 듀얼스택에서는 위처럼
주소 계열별 바인딩을 명시해야 한다. 두 형식의 혼용과 프로토콜 이름 중복은 거부한다.

### 단일 컨테이너: lb-agent가 BIRD를 직접 관리

하나의 컨테이너에 `lb-agent`, `bird`, `birdc`를 넣는다. `lb-agent`를 컨테이너의
**PID 1로 직접 실행**하면 foreground BIRD가 그 자식이 된다. 별도 `lb-bird` 실행 파일과
BIRD 사이드카는 사용하지 않는다. 기본 전용 PID namespace를 전제로 하며,
`hostPID`·`shareProcessNamespace` 또는 PID 1을 차지하는 셸·init 래퍼를 사용하지 않는다.

```sh
# 컨테이너 entrypoint/command (셸을 쓰면 마지막에 exec)
/app/bin/lb-agent -config /etc/tc-lb/agent.json -table /etc/tc-lb/assignments.json
```

`agent.json`은 `configs/agent.bird.example.json` 형식을 사용한다. BIRD 구성에는
`configs/bird-vips.example.conf`의 static 프로토콜을 포함하고 실제 환경의 BGP 이웃·export
설정을 추가한다. `config_file`은 필수 절대 경로이며, `executable`의 기본값은 PATH의
`bird`, `pid_file`의 기본값은 제어 소켓과 같은 디렉터리의 `bird.pid`다. 에이전트는
`bird -f -c ... -s ... -P ...`를 직접 실행한다. `birdc`도 PATH에 있어야 한다.
배정표/설정 볼륨의 전달 방식은 별도 운영 결정 사항이다.

- 기동 시 VIP 프로토콜의 비활성화를 확인하고, 맵·TC·백엔드 상태를 확인한 뒤에만 광고한다.
- BIRD가 종료되면 즉시 readiness를 실패로 바꾸고 자식 BIRD만 다시 실행한다.
  에이전트와 eBPF 프로그램·pin·맵은 유지한다. 반복 기동 실패는 1초 간격으로 재시도한다.
- 새 BIRD도 VIP 비활성 상태로 시작한다. 다음 조정에서 전달 준비가 확인되면 광고를 재개한다.
- 제어 소켓 소실 등으로 VIP 철회를 확인할 수 없으면 BIRD를 종료한 뒤 다시 시작한다.
- 에이전트 PID 1이 급사하면 PID namespace의 다른 프로세스도 종료되어 BIRD가 남지 않는다.
  로컬 실행에는 Linux parent-death signal도 사용하지만, 배포 시 PID 1 조건을 지켜야 한다.
- 정상 종료는 VIP 철회 → drain → TC 해제 → BIRD 종료·회수 순서다.
- 살아 있는 외부 BIRD는 자동 인계하지 않는다. 기존 BIRD 컨테이너를 종료하고 단일 컨테이너로 교체한다.
- `/status`의 `bird_pid`·`bird_restarts`와 메트릭으로 자식 상태를 확인할 수 있다.
  프로세스가 살아 있지만 멈춘 경우의 감시는 별도 운영 검토 대상이다.
- BIRD 종료 후 스위치의 BGP/BFD 감지·ECMP 수렴 시간이 있으므로 즉시 절체를 보장하지 않는다.

실제 BIRD 제어 소켓과 VIP route 철회는 격리 netns에서 검증한다. 스위치와의 BGP/ECMP 수렴·실장비 성능은 별도 검증 대상이다.

## 검증

```sh
go test ./...
go vet ./...
sudo python3 test/agent_smoke.py
```

단위 테스트는 유한 클라이언트 배정 균형, 입력 순서 독립성, 장애 시 정상 배정 유지,
짝 분리, 복구, 히스테리시스, 맵 실패·용량·tombstone, 잘못된 설정 보존, HTTP 상태,
BIRD 응답 오류를 확인한다. `bpf/lb_kern.o`가 없으면 실제 ELF ABI 테스트만 건너뛴다.

통합 테스트는 별도 네임스페이스 6개 안에 클라이언트·LB·백엔드 3개·스위치용
브리지를 만든다. IPv4/IPv6 DSR 왕복, 실제 BPF verifier, 프로세스 급사 후 pin 재사용,
장애·복구 재배정, 잘못된 설정 유지, 삭제 배정 차단, 정상 종료 시 필터 제거를 검증한다.
호스트 NIC·라우팅·sysctl·기존 BPF 맵은 변경하지 않는다. 생성한 namespace와 pin만 정리하고
진단 로그는 출력한 `/tmp/tc-lb-agent-smoke-*` 경로에 남긴다.

이 검증은 실제 Multus/bond/VLAN, BGP·ECMP, 목표 pps 성능 검증을 대체하지 않는다.
기존 C의 PMTUD/ICMP 오류 역조회 제한과 MISS 처리도 그대로다.

BIRD 2가 설치된 Linux에서 자식 재시작·광고 보류·PID 1 급사 시험은 다음처럼 실행한다.
실행 파일 경로는 설치 위치에 맞춘다. 테스트는 init network namespace에서는 실행을 거부한다.
PID 1 시험에는 빌드된 에이전트·BPF object와 마운트된 bpffs도 필요하다.

```sh
go test -c -o bin/agent.test ./internal/agent
sudo unshare --mount --propagation private sh -c '
  mount -t bpf bpf /sys/fs/bpf &&
  cd internal/agent &&
  unshare --net env LB_TEST_PRIVILEGED=1 \
  LB_TEST_BIRD=/usr/sbin/bird LB_TEST_BIRDC=/usr/sbin/birdc \
  LB_TEST_AGENT="$PWD/../../bin/lb-agent" \
  LB_TEST_OBJECT="$PWD/../../bpf/lb_kern.o" \
  ../../bin/agent.test -test.v -test.run TestReal
'
```
