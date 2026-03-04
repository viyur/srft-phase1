"""
SRFT Receiver - DEBUG VERSION
"""

import hashlib
import math
import os
import socket
import threading
import time

from protocol import (
    TYPE_DATA, TYPE_ACK, TYPE_SYN_ACK, TYPE_FIN,
    build_srft_packet, parse_srft_packet,
    build_raw_packet, parse_raw_packet,
    unpack_srft_synack_payload,
    unpack_srft_fin_payload,
)
from config import (
    CHUNK_SIZE,
    SLIDING_WINDOW_SIZE,
    ACK_EVERY_N,
    ACK_INTERVAL_SEC,
    RECV_BUFFER_SIZE,
    DEFAULT_CLIENT_PORT,
    DEFAULT_SERVER_PORT,
)


class ReceiverStats:
    def __init__(self):
        self.packets_received = 0
        self.packets_discarded = 0
        self.duplicate_packets = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0

    def elapsed(self) -> str:
        secs = int(self.end_time - self.start_time)
        hh, rem = divmod(secs, 3600)
        mm, ss = divmod(rem, 60)
        return f"{hh:02d}:{mm:02d}:{ss:02d}"


class ReorderBuffer:
    def __init__(self):
        self._buffer: dict[int, bytes] = {}
        self._next_expected: int = 0
        self._lock = threading.Lock()

    @property
    def next_expected(self) -> int:
        with self._lock:
            return self._next_expected

    def accept(self, seq: int, data: bytes) -> bool:
        with self._lock:
            lo = self._next_expected
            hi = self._next_expected + SLIDING_WINDOW_SIZE
            if seq < lo:
                return False
            if seq >= hi:
                return False
            if seq in self._buffer:
                return False
            self._buffer[seq] = data
            return True

    def drain(self) -> list[bytes]:
        with self._lock:
            chunks = []
            while self._next_expected in self._buffer:
                chunks.append(self._buffer.pop(self._next_expected))
                self._next_expected += 1
            return chunks


class Receiver:
    def __init__(
        self,
        server_ip: str,
        output_dir: str = ".",
        client_port: int = DEFAULT_CLIENT_PORT,
        server_port: int = DEFAULT_SERVER_PORT,
        raw_mode: bool = True,
    ):
        self._server_ip = server_ip
        self._server_port = server_port
        self._client_port = client_port
        self._output_dir = output_dir
        self._raw_mode = raw_mode
        self._sock: socket.socket | None = None
        self._client_ip: str = ""

        self._file_size: int = 0
        self._total_chunks: int = 0
        self._filename: str = ""
        self._output_path: str = ""

        self._buffer = ReorderBuffer()
        self._packets_since_last_ack: int = 0
        self._transfer_done = threading.Event()

        self.stats = ReceiverStats()

    # ------------------------------------------------------------------ #
    # Public API                                                           #
    # ------------------------------------------------------------------ #

    def receive(self, filename: str) -> bool:
        self._filename = filename
        self._output_path = os.path.join(self._output_dir, filename)

        if self._raw_mode:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            self._client_ip = socket.gethostbyname(socket.gethostname())
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.bind(("0.0.0.0", self._client_port))
            self._client_ip = "127.0.0.1"

        try:
            self._send_request(filename)
            if not self._wait_for_synack():
                print("[ERROR] Did not receive SYN_ACK from server.")
                return False

            print("[DEBUG] SYN_ACK received, starting ACK thread and _receive_data")
            self.stats.start_time = time.time()
            ack_thread = threading.Thread(target=self._ack_loop, daemon=True)
            ack_thread.start()
            print("[DEBUG] ACK thread started, calling _receive_data now")

            success = self._receive_data()
            print(f"[DEBUG] _receive_data returned: {success}")
            self.stats.end_time = time.time()
            return success

        finally:
            self._sock.close()

    # ------------------------------------------------------------------ #
    # Send REQUEST                                                         #
    # ------------------------------------------------------------------ #

    def _send_request(self, filename: str):
        srft_pkt = build_srft_packet(
            pkt_type=0x01,
            seq=0,
            ack=0,
            payload=filename.encode(),
        )
        if self._raw_mode:
            raw = build_raw_packet(
                self._client_ip, self._server_ip,
                self._client_port, self._server_port,
                srft_pkt,
            )
            self._sock.sendto(raw, (self._server_ip, self._server_port))
        else:
            self._sock.sendto(srft_pkt, (self._server_ip, self._server_port))
        print(f"[REQUEST] Sent request for '{filename}'")

    # ------------------------------------------------------------------ #
    # Wait for SYN_ACK                                                     #
    # ------------------------------------------------------------------ #

    def _wait_for_synack(self, timeout: float = 5.0) -> bool:
        self._sock.settimeout(timeout)
        for attempt in range(3):
            try:
                while True:
                    result = self._recv_srft_packet()
                    if result is None:
                        continue
                    pkt_type, seq, ack, payload = result
                    if pkt_type == TYPE_SYN_ACK:
                        file_size = unpack_srft_synack_payload(payload)
                        if file_size is None:
                            print("[ERROR] Malformed SYN_ACK payload.")
                            return False
                        self._file_size = file_size
                        self._total_chunks = math.ceil(file_size / CHUNK_SIZE)
                        print(f"[SYN_ACK] File size: {file_size} bytes, "
                              f"total chunks: {self._total_chunks}")
                        return True
            except TimeoutError:
                print(f"[WARN] SYN_ACK timeout, retrying... ({attempt + 1}/3)")
                self._send_request(self._filename)
        return False

    # ------------------------------------------------------------------ #
    # ACK thread                                                           #
    # ------------------------------------------------------------------ #

    def _ack_loop(self):
        last_sent_ack = -1
        last_ack_time = time.time()
        while not self._transfer_done.is_set():
            time.sleep(0.01)
            now = time.time()
            next_exp = self._buffer.next_expected
            count = self._packets_since_last_ack
            time_elapsed = now - last_ack_time
            should_ack = (
                (count >= ACK_EVERY_N) or
                (time_elapsed >= ACK_INTERVAL_SEC and next_exp > last_sent_ack)
            )
            if should_ack and next_exp != last_sent_ack:
                self._send_ack(next_exp)
                last_sent_ack = next_exp
                last_ack_time = now
                self._packets_since_last_ack = 0

    def _send_ack(self, ack_num: int):
        srft_pkt = build_srft_packet(
            pkt_type=TYPE_ACK,
            seq=0,
            ack=ack_num,
            payload=b"",
        )
        if self._raw_mode:
            raw = build_raw_packet(
                self._client_ip, self._server_ip,
                self._client_port, self._server_port,
                srft_pkt,
            )
            self._sock.sendto(raw, (self._server_ip, self._server_port))
        else:
            self._sock.sendto(srft_pkt, (self._server_ip, self._server_port))
        print(f"[ACK] Sent cumulative ACK: next_expected={ack_num}")

    # ------------------------------------------------------------------ #
    # Packet receive helper                                                #
    # ------------------------------------------------------------------ #

    def _recv_srft_packet(self):
        print("[DEBUG] About to call recvfrom...")
        raw_data, addr = self._sock.recvfrom(RECV_BUFFER_SIZE)
        print(f"[DEBUG] recvfrom returned, addr={addr}")

        if self._raw_mode:
            parsed = parse_raw_packet(raw_data)
            if parsed is None:
                return None
            src_ip, src_port, _, _, udp_payload = parsed
        else:
            src_ip, src_port = addr
            udp_payload = raw_data
            print(f"[DEBUG] Received packet from {src_ip}:{src_port}, expected {self._server_ip}:{self._server_port}")

        if src_ip != self._server_ip or src_port != self._server_port:
            print(f"[DEBUG] Filtered out packet from {src_ip}:{src_port}")
            return None

        result = parse_srft_packet(udp_payload)
        if result is None:
            return None

        pkt_type, seq, ack, payload = result
        return pkt_type, seq, ack, payload

    # ------------------------------------------------------------------ #
    # Receive DATA + handle FIN                                            #
    # ------------------------------------------------------------------ #

    def _receive_data(self) -> bool:
        print("[DEBUG] _receive_data: ENTERED FUNCTION")
        self._sock.settimeout(5.0)
        print("[DEBUG] _receive_data: timeout set")
        md5_from_server: bytes | None = None

        print(f"[DEBUG] output_path={self._output_path}, total_chunks={self._total_chunks}")

        with open(self._output_path, "wb") as f:
            print("[DEBUG] File opened, entering while loop")
            while True:
                print(f"[DEBUG] Top of while loop, next_expected={self._buffer.next_expected}")
                try:
                    result = self._recv_srft_packet()
                except TimeoutError:
                    print(f"[DEBUG] Timeout in receive loop")
                    continue
                except Exception as e:
                    print(f"[DEBUG] Exception in recvfrom: {type(e).__name__}: {e}")
                    continue

                if result is None:
                    self.stats.packets_discarded += 1
                    continue

                pkt_type, seq, ack, payload = result
                print(f"[DEBUG] Got packet type={pkt_type}, seq={seq}")

                if pkt_type == TYPE_DATA:
                    self._handle_data(seq, payload, f)
                elif pkt_type == TYPE_FIN:
                    md5_from_server = unpack_srft_fin_payload(payload)
                    print(f"[FIN] Received FIN from server.")
                    break

        self._transfer_done.set()
        self._send_ack(self._buffer.next_expected)
        return self._verify_md5(md5_from_server)

    def _handle_data(self, seq: int, data: bytes, f):
        print(f"[DEBUG] _handle_data called seq={seq}")
        accepted = self._buffer.accept(seq, data)

        if not accepted:
            self.stats.duplicate_packets += 1
            print(f"[WARN] Duplicate or out-of-window packet seq={seq}, discarding.")
            return

        self.stats.packets_received += 1
        self._packets_since_last_ack += 1

        chunks = self._buffer.drain()
        print(f"[DEBUG] drain() returned {len(chunks)} chunks")
        for chunk in chunks:
            f.write(chunk)

        print(f"[DATA] Accepted seq={seq}, "
              f"next_expected={self._buffer.next_expected}/{self._total_chunks}")

    # ------------------------------------------------------------------ #
    # MD5 verification                                                     #
    # ------------------------------------------------------------------ #

    def _verify_md5(self, md5_from_server: bytes | None) -> bool:
        if md5_from_server is None:
            print("[ERROR] No MD5 received from server, transfer failed.")
            self._cleanup_output()
            return False

        with open(self._output_path, "rb") as f:
            computed_md5 = hashlib.md5(f.read()).digest()

        if computed_md5 == md5_from_server:
            print(f"[SUCCESS] MD5 verified. Transfer complete.")
            print(f"[STATS] Packets received : {self.stats.packets_received}")
            print(f"[STATS] Duplicates       : {self.stats.duplicate_packets}")
            print(f"[STATS] Checksum failures: {self.stats.packets_discarded}")
            print(f"[STATS] Duration         : {self.stats.elapsed()}")
            return True
        else:
            print("[ERROR] MD5 mismatch! File may be corrupted.")
            self._cleanup_output()
            return False

    def _cleanup_output(self):
        if os.path.exists(self._output_path):
            os.remove(self._output_path)
            print(f"[CLEANUP] Removed corrupted file: {self._output_path}")