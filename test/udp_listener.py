#!/usr/bin/env python3
"""백엔드 UDP 리스너.

VIP 에 직접 바인딩해야 응답 출발지가 VIP 로 고정된다 (설계 메모 10·11번).

--bind-any 를 주면 0.0.0.0 에 바인딩한다. 그러면 커널이 라우팅으로 출발지를
고르므로 VIP 가 아니라 인터페이스 주소로 응답하게 되고 DSR 이 깨진다.
그 차이를 실제로 보여주기 위한 옵션이다.
"""
import socket
import sys

bind_any = "--bind-any" in sys.argv
args = [a for a in sys.argv[1:] if not a.startswith("--")]
host, port = args[0], int(args[1])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET

s = socket.socket(fam, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

if bind_any:
    bind_addr = "::" if fam == socket.AF_INET6 else "0.0.0.0"
else:
    bind_addr = host
s.bind((bind_addr, port))
s.settimeout(8)

try:
    data, peer = s.recvfrom(2048)
    print("recv %r from %s (bound to %s)" % (data, peer[0], bind_addr),
          file=sys.stderr)
    s.sendto(b"PONG-UDP", peer)
except socket.timeout:
    print("udp listener: timeout", file=sys.stderr)
    sys.exit(2)
finally:
    s.close()
