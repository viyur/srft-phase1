"""Unit tests for SRFT protocol. Run: python3 test_protocol.py"""

from protocol import (
    compute_checksum, verify_checksum,
    build_srft_packet, parse_srft_packet,
    build_raw_packet, parse_raw_packet,
    TYPE_REQUEST, TYPE_DATA, TYPE_ACK,
)


def test_checksum():
    data = b"hello"
    chk = compute_checksum(data)
    assert verify_checksum(data, chk)
    assert not verify_checksum(data, chk + 1)
    assert not verify_checksum(b"hellp", chk)
    print("test_checksum: OK")


def test_srft_packet():
    pkt = build_srft_packet(TYPE_REQUEST, 0, 0, b"test.txt")
    parsed = parse_srft_packet(pkt)
    assert parsed == (TYPE_REQUEST, 0, 0, b"test.txt")
    bad = pkt[:-1] + bytes([pkt[-1] ^ 1])
    assert parse_srft_packet(bad) is None
    print("test_srft_packet: OK")


def test_raw_packet():
    srft = build_srft_packet(TYPE_DATA, 1, 0, b"chunk1")
    raw = build_raw_packet("192.168.1.1", "192.168.1.2", 5000, 5001, srft)
    parsed = parse_raw_packet(raw)
    assert parsed is not None
    src_ip, src_port, dst_ip, dst_port, udp_payload = parsed
    assert src_ip == "192.168.1.1" and src_port == 5000
    assert dst_ip == "192.168.1.2" and dst_port == 5001
    assert udp_payload == srft
    print("test_raw_packet: OK")


if __name__ == "__main__":
    test_checksum()
    test_srft_packet()
    test_raw_packet()
    print("\nAll protocol tests passed.")