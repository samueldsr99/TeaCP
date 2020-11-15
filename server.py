import socket

from trapy.packet import Packet
from trapy.trapy import accept, listen

s = listen('127.0.0.1:5000')

accept(s)

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# s.bind(('127.0.0.1', 0))

# packet, address = s.recvfrom(65565)
# print(packet, address)
