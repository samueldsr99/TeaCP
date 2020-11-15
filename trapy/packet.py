"""
Packet class
"""

# Header fields in order
# (field, start_position, length)
HEADER = [
    ('source_port', 0, 2),
    ('destination_port', 2, 2),
    ('sequence_number', 4, 4),
    ('ack_number', 8, 4),
    ('offset', 12, 1),
    ('flags', 13, 1),
    ('window', 14, 2),
    ('checksum', 16, 2),
    ('urgent', 18, 2)
]


class Packet:
    def __init__(
        self,
        teacp_header: dict = None,
        data: bytes = b'',
        ack: int = 0,
        syn: int = 0,
        end: int = 0,
        rst: int = 0
    ):
        header = {
            key: teacp_header[key] if teacp_header.get(key) else 0 for key, _, _ in HEADER
        }
        self.header = header
        self.data = data

        if ack or syn or end or rst:
            self.header['flags'] = self._get_flags(
                ack=ack, syn=syn, end=end, rst=rst
            )

    def prepare(self) -> bytes:
        """
        Get the data to send in packet
        """
        self.header['checksum'] = self.calc_checksum()
        return self.build_header() + self.data

    def build_header(self) -> bytes:
        """
        Build packet header from self data
        """
        return self._build_teacp_header()

    def calc_checksum(self) -> int:
        """
        Calculates the data checksum
        """
        # wrap int.from_bytes function
        data = self.data
        checksum = 0

        for i in range(0, len(data), 2):
            w = ord(data[i]) + ord(data[i + 1] << 8)
            checksum += w

        checksum = (checksum >> 16) + (checksum & 0xffff)
        checksum = checksum + (checksum >> 16)
        checksum = ~checksum & 0xffff

        return checksum

    def validate_checksum(self) -> bool:
        """
        Check if self.header['checksum'] is valid
        """
        return self.header['checksum'] == self.validate_checksum()

    def _build_ip_header(self) -> bytes:
        """
        Get the IP header
        DEPRECATED
        """
        # Version, IHL, Type of Service | Total Length
        ip_header = b'\x45\x00\x00\x28'
        # Identification | Flags, Fragment Offset
        ip_header += b'\xab\xcd\x00\x00'
        # TTL, Protocol | Header Checksum
        ip_header += b'\x40\x06\xa6\xec'
        # Source Address
        ip_header += b'\x0a\x00\x00\x01'
        # Destination Address
        ip_header += b'\x0a\x00\x00\x02'

        return ip_header

    def _build_teacp_header(self) -> bytes:
        """
        Get the TeaCP header
        """
        teacp_header = b''
        header = self.header
        # wrap int.tobytes function
        itb = int.to_bytes

        for (field, _, length) in HEADER:
            teacp_header += itb(header[field], length, byteorder='big')

        return teacp_header

    @staticmethod
    def _get_flags(
            ack=0,
            syn=0,
            end=0,
            rst=0
    ):
        """
        Get flag number from params
        """
        return ack * (1 << 0) + \
            syn * (1 << 1) + \
            end * (1 << 2) + \
            rst * (1 << 3)

    @staticmethod
    def from_bytes(packet: bytes):
        """
        Returns Packet format from bytes packet
        """
        # wrap int.from_bytes function
        ifb = int.from_bytes

        # ignore IP headers
        offset = 20

        header = dict()

        for field, start_position, length in HEADER:
            start = offset + start_position
            header[field] = ifb(packet[start:start + length],
                                byteorder='big')

        data = packet[offset + header['offset']:]

        return Packet(header, data)

    @staticmethod
    def syn_packet(
        source: int = 0,
        dest: int = 0,
        seq_number: int = None,
        offset: int = 20
    ):
        """
        Returns SYN Packet class
        """
        if seq_number is None:
            from random import randint
            seq_number = randint(0, (1 << 16) - 1)

        header = {key: 0 for key, _, _ in HEADER}

        header['source_port'] = source
        header['destination_port'] = dest
        header['sequence_number'] = seq_number
        header['offset'] = offset

        syn_packet = Packet(header, data=b'', syn=1)
        syn_packet.header['checksum'] = syn_packet.calc_checksum()

        return syn_packet

    @staticmethod
    def empty_packet():
        """
        Returns an empty Packet class
        """
        header = {key: 0 for key, _, _ in HEADER}
        packet = Packet(header, data=b'')

        packet.header['checksum'] = packet.calc_checksum()

        return packet
