#!/usr/bin/env python3
"""클라이언트 쪽 TCP 접속.

peer 주소가 VIP 로 나오는 것이 DSR 성립의 증거다. 백엔드가 자기 인터페이스
주소로 응답했다면 TCP 가 아예 맺어지지 않는다(출발지 불일치).
"""
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET

s = socket.socket(fam, socket.SOCK_STREAM)
s.settimeout(5)
s.connect((host, port))
data = s.recv(100).decode().strip()
peer = s.getpeername()[0]
local = s.getsockname()[0]
s.close()

print("recv  : %s" % data)
print("peer  : %s" % peer)
print("local : %s" % local)
