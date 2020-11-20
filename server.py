import socket

from trapy.packet import Packet
from trapy.trapy import accept, listen, close

# s = listen('127.0.0.1:5000')

# while True:
#     c = accept(s)

# close(s)

s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# s.bind(('127.0.0.1', 0))

# while True:
#     packet, address = s.recvfrom(65565)
#     print(packet, address)
#     print('hello')

count = 0
for i in range(100):
    packet, address = s.recvfrom(65565)
    print(packet, address)

print(count)