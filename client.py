import socket

from trapy.packet import Packet
from trapy.trapy import dial

c = dial('127.0.0.1:5000')

# s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

# packet = Packet.syn_packet()

# s.sendto(packet.prepare(), ('127.0.0.1', 0))
