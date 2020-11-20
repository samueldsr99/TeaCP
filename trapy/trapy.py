import socket
import logging
from .packet import Packet

from .utils import parse_address

logging.basicConfig(level=logging.DEBUG, format='%(message)s')


class Conn:
    host: str  # Socket host
    port: int  # Socket port
    peer: tuple  # peer socket (host, port)
    sock: socket.socket

    def __init__(self, sock: socket.socket = None, address: str = None):
        if sock is None:
            self.sock = socket.socket(
                socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP
            )
        self.host, self.port = self.sock.getsockname()
        self.peer = (None, None)
        if address is not None:
            self.bind(address)

    def bind(self, address):
        """
        Bind (host, port) of current socket to address
        """
        self.host, self.port = parse_address(address)
        self.sock.bind((self.host, 0))

    def set_peer(self, address: tuple):
        """
        Set (host, port) of peer socket
        """
        self.peer = (address[0], address[1])

    def __str__(self):
        return \
            f'({self.host}:{self.port}) -> ({self.peer[0], self.peer[1]})'


class ConnException(Exception):
    pass


def listen(address: str) -> Conn:
    """
    Prepares a connection that listen packets sended to address
    """
    conn = Conn(address=address)
    logging.info(f'Socket created and binded to: {address}')
    return conn


def accept(conn) -> Conn:
    """
    Wait for an incoming connection request
    """
    # Three-Way Handshake
    logging.info('Waiting for connections')

    while True:
        raw_packet, (host, _) = conn.sock.recvfrom(65565)
        syn_packet = Packet.from_bytes(raw_packet)
        port = syn_packet.header['source_port']

        # Check if SYN bit is on
        if syn_packet.header['destination_port'] == conn.port and \
                bool(syn_packet.header['flags'] & (1 << 1)):
            logging.info(f'*\tACK: Received from {host}:{port}')

            break

    # SYN Received, Send SYNACK using above syn packet
    packet = Packet.syn_packet(
                source=conn.port,
                dest=port,
                seq_number=syn_packet.header['sequence_number']
            )
    packet.header['ack_number'] = syn_packet.header['sequence_number'] + 1

    logging.info(f'*\tSYNACK: Sending to {host}:{port}')
    logging.info(f'Packet: {packet.header}')
    conn.sock.sendto(packet.prepare(), (host, port))

    # Wait for confirmation
    while True:
        raw_packet, (host, _) = conn.sock.recvfrom(65565)
        conf_packet = Packet.from_bytes(raw_packet)

        # Validate seq_number & ack_number
        ack_number = packet.header['ack_number']
        seq_number = packet.header['sequence_number']
        if conf_packet.header['destination_port'] == conn.port and \
                conf_packet.header['sequence_number'] == ack_number and \
                conf_packet.header['ack_number'] == seq_number + 1:
            logging.info(f'*\tCONFIRMATION: Received from {host}:{port}')

            break

    # Peer server socket
    conn.set_peer((host, port))

    client_conn = Conn()
    client_conn.bind(f'{conn.host}:{conn.port}')
    client_conn.set_peer((host, port))

    logging.info(f'peer to: {str(client_conn)}')
    return client_conn


def dial(address: str) -> Conn:
    """
    Try to establish connection with address and returns it
    """
    s_host, s_port = parse_address(address)

    conn = Conn()

    # Three-Way Handshake
    # Send SYN
    syn = Packet.syn_packet(source=conn.sock.getsockname()[1], dest=s_port)
    packet_to_send = syn.prepare()
    # Sequence number for future validation of SYNACK packet
    seq_number = syn.header['sequence_number']

    logging.info(f'processed packet to send header: {syn.header}')
    bytes_sended = conn.sock.sendto(packet_to_send, (s_host, s_port))
    logging.info(f'*\tACK: Sended {bytes_sended} bytes to {s_host}:{s_port}')

    # Receive SYNACK
    while True:
        raw_packet, (_, _) = conn.sock.recvfrom(65565)
        synack_packet = Packet.from_bytes(raw_packet)

        # Check if SYN bit is on
        if synack_packet.header['destination_port'] == conn.port and \
                bool(synack_packet.header['flags'] & (1 << 1)) and \
                synack_packet.header['ack_number'] == seq_number + 1:
            logging.info(f'*\tSYNACK: Received from {s_host}:{s_port}')
            logging.info(f'SYNACK packet: {synack_packet.header}')

            break

    # Send back confirmation
    final_packet = Packet(
        teacp_header={
            'destination_port': s_port,
            'sequence_number': synack_packet.header['ack_number'],
            'ack_number': synack_packet.header['sequence_number'] + 1,
        },
    )

    bs = conn.sock.sendto(final_packet.prepare(), (s_host, s_port))

    logging.info(f'*\tCONFIRMATION: Sended {bs} bytes to {s_host}:{s_port}')
    logging.info(f'confirmation packet header {final_packet.header}')

    host, port = conn.sock.getsockname()
    conn.bind(f'{host}:{port}')
    conn.set_peer((s_host, s_port))

    logging.info(f'peer to: {str(conn)}')

    return conn


def send(conn: Conn, data: bytes) -> int:
    """
    Send the bytes from data using conn and return the bytes sended
    """
    pass


def recv(conn: Conn, length: int) -> bytes:
    """
    Receives at most length bytes from conn
    """
    pass


def close(conn: Conn):
    """
    End's up the connection
    """
    # Send FIN to other endpoint
    fin_packet = Packet.fin_packet(
        source=conn.port,
        dest=conn.peer[1],
    )
    conn.sock.sendto(fin_packet.prepare(), (conn.peer[0], 0))

    logging.info(f'Packet sended: {fin_packet.header}')

    # Expect FIN
    while True:
        raw_packet, (host, _) = conn.sock.recvfrom(65565)

        packet = Packet.from_bytes(raw_packet)

        logging.info(f'Packet incoming: {packet.header}')

        # Check if FIN bit is on
        if packet.header['destination_port'] == conn.port and \
                bool(packet.header['flags'] & (1 << 2)):

            logging.info(f'*\tFIN Received from: {host}:{conn.peer[1]}')
            break

    logging.info(f'Connection closed with {host}:{conn.peer[1]}')
    conn.peer = (None, None)

#############################################################
#                           Utils                           #
#############################################################


def send_packet(packet: Packet, conn: Conn):
    """
    Sends a packet via conn socket
    This function is intended to use in a thread
    """
    pass


def receive_packet(packet: Packet, conn: Conn):
    """
    Receives a packet via conn socket
    This function is intended to use in a thread
    """
    pass
