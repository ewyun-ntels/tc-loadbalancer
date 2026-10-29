# 제어부 검증 기록 — 2026-10-29

첫 절과 아래 보완 절은 적용 당시의 기록이다. 현재 BIRD 실행 구조와 검증 결과는 마지막
「단일 컨테이너 BIRD 직접 관리」 절을 기준으로 한다.

- Windows Go 1.26.5에서 `go test ./...`, `go vet ./...` 통과.
- `GOOS=linux GOARCH=amd64 CGO_ENABLED=0`으로 두 실행 파일 빌드 통과.
- 기존 C 소스를 clang 18로 빌드한 ELF와 Go 키/값 크기·필드 오프셋·통계 인덱스 검사 통과.
- WSL 커널 6.18에서 실제 BPF verifier와 TC direct-action 연결 통과.
- 별도 mount namespace의 bpffs, 별도 network namespace 6개에서 다음 통합 시험 통과:
  1. IPv4/IPv6 Primary·Secondary VIP TCP 왕복 및 DSR
  2. 에이전트 SIGKILL 후 기존 TC 필터·pin을 재사용해 재시작
  3. Primary 백엔드 장애 시 재배정, 정상 배정 유지
  4. 백엔드 복구 후 rise 임계값을 거쳐 원래 배정으로 복귀
  5. 잘못된 배정표 입력 시 마지막 정상 배정과 통신 유지
  6. 다음 세대 배정표에서 삭제한 IPv4/IPv6 클라이언트의 트래픽 차단
  7. 정상 종료 시 소유 필터 제거

초기 통합 시험에서 발견한 ELF 원본 tag와 로딩 후 kernel tag의 차이는,
같은 맵을 참조하는 비부착 후보 프로그램을 로딩한 뒤 kernel tag끼리 비교하도록 수정했다.
수정 후 프로세스 급사·재시작 시험이 통과했다.

실제 BIRD 제어 소켓/스위치, Multus DNS·IPAM, bond/VLAN, 목표 pps 시험은 포함하지 않았다.
Kubernetes CRD 클라이언트와 프로세스 급사 시 BIRD 광고를 철회하는 감독자는 아직 없다.
이 범위와 운영 조건은 `README.control-plane.md`에 명시했다.

## §19.14 3번 — TC 필터 유실 보완 (2026-10-29)

- Go 에이전트의 조정 루프와 TC 연결 함수에서 캐시된 attachment 판정을 제거했다.
- 매 주기 실제 프로그램 ID와 필터 속성을 재검증한다. 소유 필터/clsact만 사라진 경우
  다시 연결하고, 다른 필터·재연결 실패·인터페이스 ifindex 변경 시 readiness 실패와 광고 철회로 처리한다.
- 모의 테스트: 매 주기 재검사·복구, 광고 전 연결 확인, TC 오류 시 광고 철회,
  철회 명령 실행 전 `/readyz` 실패, 다음 주기 정상 복구를 확인했다.
- 실제 커널/격리 netns 테스트: 필터 삭제·clsact 삭제 후 재연결, 다른 필터 보호,
  잘못된 프로토콜·프로그램 ID 거부, 인터페이스 재생성·삭제 감지 모두 통과했다.
- 기존 Python 테스트와 C 소스는 변경하지 않았다. 히스테리시스와 단일 생존 백엔드 정책도 유지한다.

## 작업 목록 4·5·7 최초 보완 (2026-10-29, 7번 구조는 아래에서 대체)

- 4: 일시적인 IP/MAC 조회 실패는 마지막 검증 엔드포인트를 유지하며 fall을 누적한다.
  fall 도달 후 재배정하고 복귀는 rise를 적용한다. 실제 IP 변경과 위험한 엔드포인트는 즉시 제외한다.
- 5: 주소 계열별로 모든 클라이언트가 Primary/Secondary 중 최소 한 경로를 가지면 광고를 유지한다.
  단일 생존 시 짝 중 하나만 ACTIVE이며 degraded를 노출한다. IPv4/IPv6 광고는 독립적으로 제어한다.
- 7: BIRD 컨테이너의 `lb-bird` 감독자가 에이전트의 readiness 소실을 감시해 광고를 철회한다.
  철회 실패 시 BIRD를 종료하고, 감독자 급사 시 parent-death signal로 자식 BIRD를 종료한다.
  배포 시 BIRD 컨테이너 entrypoint를 이 실행 파일로 지정해야 적용된다.
- Windows Go 1.26.5의 전체 단위 테스트·정적 검사와 Linux amd64 빌드 통과.
- Linux 격리 netns의 실제 BIRD 2.14에서 다음을 확인했다:
  - HTTP 에이전트 프로세스 SIGKILL 후 IPv4·IPv6 VIP route 제거
  - IPv4/IPv6 독립 광고와 철회
  - 제어 소켓 소실로 철회가 실패하면 BIRD 프로세스 종료
  - `lb-bird` 프로세스 SIGKILL 시 자식 BIRD 종료
- 실제 BIRD의 0008..0011 프로토콜 상태 응답을 정상으로 처리하도록 수정했다.
  BIRD greeting만 있는 응답과 오류 응답은 계속 거부한다.
- 기존 C·Python 파일을 변경하지 않고 기존 DSR 통합 테스트 전 항목 통과.
- 실제 스위치의 BGP/ECMP 수렴·실장비 성능은 이번 검증 범위에 포함하지 않았다.

## 단일 컨테이너 BIRD 직접 관리 (2026-10-29)

- `lb-agent`를 컨테이너 PID 1로 직접 실행하고 foreground BIRD를 자식으로 관리한다.
  별도 `cmd/lb-bird`·`internal/watchdog`와 두 컨테이너 배치를 제거했다.
- BIRD 종료 시 readiness를 즉시 실패로 공개하고 BIRD만 재시작한다. 새 BIRD의 VIP를
  비활성화한 뒤 기존 조정 루프로 맵·TC·생존 상태를 확인해야 광고를 재개한다.
  자식 종료와 겹친 이전 조정 결과가 readiness를 다시 성공으로 덮어쓰지 못하게 한다.
- VIP 철회 명령도 실패하면 BIRD 자체를 종료하고 재기동한다. 설정 오류·반복 급사는
  1초 간격으로 재시도하며 eBPF 프로그램과 맵은 유지한다.
- Windows Go 전체 테스트·정적 검사, Linux amd64 빌드·정적 검사 통과.
- 격리 mount/net namespace의 실제 BIRD 2.14에서 다음을 확인했다:
  - BIRD SIGKILL → 같은 에이전트 아래 새 BIRD 시작 → 조정 전 IPv4·IPv6 VIP route 없음
  - 조정 성공 후 IPv4·IPv6 VIP route 복구, 기존 배정 맵 내용 유지
  - 잘못된 BIRD 설정의 기동 실패 후 설정을 바로잡으면 다음 기동 성공
  - 실제 에이전트를 별도 PID namespace의 PID 1로 실행하고 실제 TC/BPF 로딩
  - BIRD만 SIGKILL했을 때 에이전트 PID·TC 프로그램 ID·pin된 map ID 유지
  - 제어 소켓 삭제로 철회 불가능 시 BIRD 교체 후 정상 제어 복구, 에이전트·맵 유지
  - 에이전트 PID 1 SIGKILL 시 자식 BIRD 종료와 제어 소켓 사용 불가
- 기존 C·Python 파일 변경 없이 IPv4/IPv6 DSR 통합 테스트 전 항목 통과.
- 실제 Kubernetes/Multus 배포, 스위치 BGP/BFD/ECMP 수렴 및 성능은 별도 검증 대상이다.
  PID 1 급사 검증은 기본 전용 PID namespace 조건이며 hostPID·shareProcessNamespace나
  PID 1 래퍼 구성에는 적용되지 않는다.
