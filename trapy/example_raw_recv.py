import socket

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

s.bind(('127.0.0.1', 0))

while True:
    packet, address = s.recvfrom(65565)
    print(len(packet))
    print(packet)

    input()
    s.sendto(b'asdasdasd', ('0.0.0.0', 0))
