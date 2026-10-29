#!/usr/bin/env python3
"""UDP 클라이언트.

connect() 로 묶는다 — 그래야 VIP 가 아닌 출발지로 온 응답을 커널이 버린다.
DSR 이 깨진 경우가 "틀린 주소로 응답받음" 이 아니라 "타임아웃" 으로 드러나서
판정이 명확해진다.
"""
import socket
import sys

host, port = sys.argv[1], int(sys.argv[2])
fam = socket.AF_INET6 if ":" in host else socket.AF_INET

s = socket.socket(fam, socket.SOCK_DGRAM)
s.settimeout(3)
s.connect((host, port))
s.send(b"PING-UDP")
data = s.recv(100)

print("recv  : %s" % data.decode())
print("peer  : %s" % s.getpeername()[0])
s.close()
