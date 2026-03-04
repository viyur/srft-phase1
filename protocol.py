'''
Implements IP header, UDP header, and application-layer 
reliable transfer prococol.
Reference: RFC 791(IP), RFC 768(UDP)
'''

import struct
import socket

# Define Packet Type Constants
TYPE_REQUEST = 0x01   # Client requests file (filename in payload)
TYPE_DATA = 0x02      # Server sends file chunk
TYPE_ACK = 0x03       # Client acknowledges received packets (cumulative)

TYPE_SYN_ACK  = 0x04  # Server tells Client the size of the file after client requests with filename (file size in payload)
TYPE_FIN      = 0x05  # Server signals Client that transfer is complete (md5hash of file in payload)

# Checksum
def compute_checksum(data: bytes) -> int:
    """
    Compute 16-bit checksum over data for corruption detection.
    Uses one's complement sum (no pseudo header as per project requirements).
    """
    if len(data) == 0:
        return 0
    if len(data) % 2:
        data = data + b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        w = data[i] + (data[i + 1] << 8)
        s = s + w
    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    return (~s) & 0xFFFF

def verify_checksum(data: bytes, stored_checksum: int) -> bool:
    """Verify that computed checksum matches stored value."""
    return compute_checksum(data) == stored_checksum



# Create IPV4 header
def _ip_checksum(header: bytes) -> int:
    """Compute IP header checksum."""
    if len(header) % 2:
        header = header + b'\x00'
    s = 0
    for i in range(0, len(header), 2):
        w = header[i] + (header[i + 1] << 8)
        s = s + w
    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    return (~s) & 0xFFFF


def build_ip_header(
    src_ip: str,
    dst_ip: str,
    protocol: int,
    payload_len: int,
    packet_id: int = 0
) -> bytes:
    """Build 20-byte IP header (no options)."""
    ihl_ver = (4 << 4) | 5
    total_len = 20 + payload_len
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        ihl_ver, 0, total_len, packet_id & 0xFFFF, 0, 64, protocol, 0,
        socket.inet_aton(src_ip), socket.inet_aton(dst_ip)
    )
    ip_checksum = _ip_checksum(ip_header)
    ip_header = ip_header[:10] + struct.pack('!H', ip_checksum) + ip_header[12:]
    return ip_header



# Create UDP header
def _udp_checksum(src_ip: str, dst_ip: str, udp_segment: bytes) -> int:
    """Compute UDP checksum with pseudo-header (RFC 768)."""
    pseudo = (
        socket.inet_aton(src_ip) +
        socket.inet_aton(dst_ip) +
        struct.pack('!BBH', 0, 17, len(udp_segment))
    )
    if len(udp_segment) % 2:
        udp_segment = udp_segment + b'\x00'
    s = 0
    for chunk in [pseudo, udp_segment]:
        for i in range(0, len(chunk), 2):
            w = chunk[i] + (chunk[i + 1] << 8)
            s = s + w
    s = (s >> 16) + (s & 0xFFFF)
    s = s + (s >> 16)
    result = (~s) & 0xFFFF
    return result if result else 0xFFFF

def build_udp_header(
    src_port: int, dst_port: int, udp_payload: bytes,
    src_ip: str, dst_ip: str
) -> bytes:
    """Build 8-byte UDP header with checksum."""
    udp_len = 8 + len(udp_payload)
    udp_header = struct.pack('!HHHH', src_port, dst_port, udp_len, 0)
    udp_checksum = _udp_checksum(src_ip, dst_ip, udp_header + udp_payload)
    udp_header = struct.pack('!HHH', src_port, dst_port, udp_len) + struct.pack('!H', udp_checksum)
    return udp_header



# Application Protocol 

HEADER_LEN = 11
FILE_SIZE_PREFIX = 4

def build_srft_packet(pkt_type: int, seq: int, ack: int, payload: bytes) -> bytes:
    """Build SRFT application-layer packet with checksum."""
    header_no_checksum = struct.pack('!BII', pkt_type, seq, ack)
    checksum_data = header_no_checksum + payload
    chk = compute_checksum(checksum_data)
    return header_no_checksum + struct.pack('!H', chk) + payload


def parse_srft_packet(data: bytes) -> tuple[int, int, int, bytes] | None:
    """Parse SRFT packet. Returns (type, seq, ack, payload) or None if invalid."""
    if len(data) < HEADER_LEN:
        return None
    pkt_type, seq, ack = struct.unpack('!BII', data[:9])
    stored_chk, = struct.unpack('!H', data[9:11])
    payload = data[11:]
    checksum_data = data[:9] + payload
    if not verify_checksum(checksum_data, stored_chk):
        return None
    return (pkt_type, seq, ack, payload)


# ============== Raw Packet Assembly ==============
def build_raw_packet(
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    srft_payload: bytes,
    packet_id: int = 0
) -> bytes:
    """Build full IP + UDP + SRFT packet for sending."""
    udp_payload = srft_payload
    udp_header = build_udp_header(
        src_port, dst_port, udp_payload, src_ip, dst_ip
    )
    ip_payload = udp_header + udp_payload
    ip_header = build_ip_header(
        src_ip, dst_ip, socket.IPPROTO_UDP, len(ip_payload), packet_id
    )
    return ip_header + ip_payload


def parse_raw_packet(data: bytes) -> tuple[str, int, str, int, bytes] | None:
    """
    Parse received raw packet. Returns (src_ip, src_port, dst_ip, dst_port, udp_payload)
    or None if invalid.
    """
    if len(data) < 28:  # IP header (min 20) + UDP header (8)
        return None
    ip_ihl = (data[0] & 0x0F) * 4
    if ip_ihl < 20:
        return None
    src_ip = socket.inet_ntoa(data[12:16])
    dst_ip = socket.inet_ntoa(data[16:20])
    protocol = data[9]
    if protocol != socket.IPPROTO_UDP:
        return None
    udp_start = ip_ihl
    src_port, dst_port, udp_len = struct.unpack('!HHH', data[udp_start:udp_start+6])
    udp_payload = data[udp_start + 8:udp_start + udp_len]
    return (src_ip, src_port, dst_ip, dst_port, udp_payload)