#!/usr/bin/env python3
"""백엔드 쪽 TCP 리스너.

VIP 에 직접 바인딩한다 — 그래야 응답 출발지가 VIP 로 고정된다(설계 메모 11번).
0.0.0.0 에 바인딩하면 커널이 송신 인터페이스 주소를 고를 수 있어 DSR 이 깨진다.
"""
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET

s = socket.socket(fam, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((host, port))
s.listen(1)
s.settimeout(10)

try:
    conn, peer = s.accept()
    print("accepted from %s" % (peer[0],), file=sys.stderr)
    conn.sendall(b"PONG from backend\n")
    conn.close()
except socket.timeout:
    print("listener: timeout", file=sys.stderr)
    sys.exit(2)
finally:
    s.close()
