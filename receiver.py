"""
SRFT Receiver - DEBUG VERSION
"""

import hashlib
import math
import os
import socket
import struct  # Phase 1: parse file_size from first DATA payload (struct.unpack)
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
    TIMEOUT_SEC,  # Phase 1: recv timeout for reliable transfer
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
# Determine the correct local IP address used to reach the server,
# required when constructing raw IP packets manually.
def resolve_local_ip(to_ip: str) -> str:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((to_ip, 1))
            return s.getsockname()[0]
        finally:
            s.close()

class Receiver:
    def __init__(
        self,
        server_ip: str,
        output_dir: str = ".",
        client_port: int = DEFAULT_CLIENT_PORT,
        server_port: int = DEFAULT_SERVER_PORT,
        raw_mode: bool = True,
        phase1: bool = False,  # Phase 1: use REQUEST->DATA->ACK flow (no SYN_ACK/FIN)
    ):
        self._phase1 = phase1
        self._server_ip = server_ip
        self._server_port = server_port
        self._client_port = client_port
        self._output_dir = output_dir
        self._raw_mode = raw_mode
        self._recv_sock: socket.socket | None = None
        self._send_sock: socket.socket | None = None
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

        # Phase 1 Support: switch between Phase 1 (no SYN_ACK/FIN) and Phase 2 (SYN_ACK/FIN)
        if self._phase1:
            return self._receive_phase1(filename)
        else:
            return self._receive_phase2(filename)

    # ------------------------------------------------------------------ #
    # Phase 1 Support: _receive_phase2 (original flow) + _receive_phase1  #
    # Phase 1: first DATA = file_size(4B)+chunk0, seq from 1, cumulative  #
    # ACK, no SYN_ACK/FIN. Phase 2: SYN_ACK/FIN with MD5 verification.   #
    # ------------------------------------------------------------------ #

    def _receive_phase2(self, filename: str) -> bool:
        """Phase 2: SYN_ACK/FIN flow"""
        # for raw mode, we need to create separate send and receive sockets
        if self._raw_mode:
            # Receive socket (captures UDP packets)
            self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

            # Send socket (we provide our own IP header)
            self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self._send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

            # Determine the correct local IP address used to reach the server
            self._client_ip = resolve_local_ip(self._server_ip)
            # macOS workaround: connect() + send() instead of sendto() for raw socket
            self._send_sock.connect((self._server_ip, self._server_port))

        # for mock mode, we can use a single UDP socket for both sending and receiving
        else:
            self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._recv_sock.bind(("0.0.0.0", self._client_port))

            # send socket same as receive socket in mock mode
            self._send_sock = self._recv_sock
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
        # catch any unexpected exceptions to ensure sockets are closed properly
        finally:
            # Cleanup sockets used during the transfer
            # Close the receive socket if it exists
            # In mock mode, this is the only socket used for both sending and receiving
            if self._recv_sock:
                self._recv_sock.close()
            # Close the send socket only if it is a different socket
            # (In raw mode we use separate send/receive sockets)
            # Avoid closing the same socket twice in mock mode
            if self._send_sock and self._send_sock is not self._recv_sock:
                self._send_sock.close()

    def _receive_phase1(self, filename: str) -> bool:
        """Phase 1: REQUEST->DATA->ACK flow. No SYN_ACK/FIN. First DATA payload =
        file_size(4B big-endian) + chunk0. Cumulative ACK on new highest consecutive seq."""
        if self._raw_mode:
            self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
            self._recv_sock.bind(("0.0.0.0", self._client_port))
            self._send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
            self._send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self._client_ip = resolve_local_ip(self._server_ip)
            # macOS workaround: connect() + send() instead of sendto() for raw socket
            self._send_sock.connect((self._server_ip, self._server_port))
        else:
            self._recv_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._recv_sock.bind(("0.0.0.0", self._client_port))
            self._send_sock = self._recv_sock
            self._client_ip = "127.0.0.1"

        try:
            self.stats.start_time = time.time()
            self._send_request(filename)

            received: dict[int, bytes] = {}
            base_seq = 1
            last_ack_sent = 0
            total_chunks = 0
            file_size = 0
            done = False
            ack_lock = threading.Lock()
            last_request_time = [time.time()]  # use list for nonlocal mutability

            def recv_loop():
                nonlocal done, total_chunks, file_size
                self._recv_sock.settimeout(TIMEOUT_SEC)
                deadline = time.time() + 300
                while not done and time.time() < deadline:
                    try:
                        result = self._recv_srft_packet()
                    except (TimeoutError, socket.timeout):
                        # No data yet: retransmit REQUEST every 2s (server may not be running)
                        with ack_lock:
                            if len(received) == 0 and time.time() - last_request_time[0] > 2.0:
                                self._send_request(filename)
                                last_request_time[0] = time.time()
                                print("[RETRY] Resent REQUEST (is mock server running?)")
                        continue
                    if result is None:
                        continue
                    pkt_type, seq, ack, payload = result
                    if pkt_type != TYPE_DATA:
                        continue
                    with ack_lock:
                        if seq not in received:
                            received[seq] = payload
                            self.stats.packets_received += 1
                            if seq == base_seq and len(payload) >= 4:
                                file_size, = struct.unpack("!I", payload[:4])
                                total_chunks = (file_size + CHUNK_SIZE - 1) // CHUNK_SIZE
                                total_chunks = max(1, total_chunks)
                        else:
                            self.stats.duplicate_packets += 1
                        sorted_seqs = sorted([s for s in received if s >= base_seq])
                        highest_consec = base_seq - 1
                        for s in sorted_seqs:
                            if s == highest_consec + 1:
                                highest_consec = s
                            else:
                                break
                        if highest_consec > last_ack_sent:
                            last_ack_sent = highest_consec
                            ack_pkt = build_srft_packet(TYPE_ACK, 0, highest_consec, b"")
                            if self._raw_mode:
                                raw = build_raw_packet(
                                    self._client_ip, self._server_ip,
                                    self._client_port, self._server_port, ack_pkt
                                )
                                self._send_sock.send(raw)
                            else:
                                self._send_sock.sendto(ack_pkt, (self._server_ip, self._server_port))

            recv_thread = threading.Thread(target=recv_loop, daemon=True)
            recv_thread.start()
            start_time = time.time()

            while time.time() - start_time < 300:
                time.sleep(TIMEOUT_SEC)
                with ack_lock:
                    if total_chunks > 0:
                        sorted_seqs = sorted([s for s in received if s >= base_seq])
                        highest = base_seq - 1
                        for s in sorted_seqs:
                            if s == highest + 1:
                                highest = s
                            else:
                                break
                        if highest >= base_seq + total_chunks - 1:
                            break
                time.sleep(0.1)

            done = True
            recv_thread.join(timeout=2)

            sorted_seqs = sorted([s for s in received if s >= base_seq])
            chunks_list = []
            expected = base_seq
            for s in sorted_seqs:
                if s == expected:
                    if expected == base_seq and len(received[s]) >= 4:
                        chunks_list.append(received[s][4:])
                    else:
                        chunks_list.append(received[s])
                    expected += 1
                elif s > expected:
                    break

            file_data = b"".join(chunks_list)
            if file_size > 0:
                file_data = file_data[:file_size]

            os.makedirs(os.path.dirname(self._output_path) or ".", exist_ok=True)
            with open(self._output_path, "wb") as f:
                f.write(file_data)

            self.stats.end_time = time.time()
            return len(file_data) > 0
        finally:
            if self._recv_sock:
                self._recv_sock.close()
            if self._send_sock and self._send_sock is not self._recv_sock:
                self._send_sock.close()
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
            self._send_sock.send(raw)
        else:
            self._send_sock.sendto(srft_pkt, (self._server_ip, self._server_port))
        print(f"[REQUEST] Sent request for '{filename}'")

    # ------------------------------------------------------------------ #
    # Wait for SYN_ACK                                                     #
    # ------------------------------------------------------------------ #

    def _wait_for_synack(self, timeout: float = 5.0) -> bool:
        self._recv_sock.settimeout(timeout)
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
            except socket.timeout:
                # Timeout while waiting for SYN_ACK from the server.
                # This may happen due to packet loss or delay, so resend the REQUEST
                # and retry up to the allowed number of attempts.
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
            self._send_sock.send(raw)
        else:
            self._send_sock.sendto(srft_pkt, (self._server_ip, self._server_port))
        print(f"[ACK] Sent cumulative ACK: next_expected={ack_num}")


    # ------------------------------------------------------------------ #
    # Packet receive helper                                                #
    # ------------------------------------------------------------------ #

    def _recv_srft_packet(self):
        raw_data, addr = self._recv_sock.recvfrom(RECV_BUFFER_SIZE)

        if self._raw_mode:
            parsed = parse_raw_packet(raw_data)
            if parsed is None:
                return None
            src_ip, src_port, _, _, udp_payload = parsed
        else:
            src_ip, src_port = addr
            udp_payload = raw_data

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

        # only receive operations need timeout behavior to prevent hanging indefinitely
        # send socket does not need receive timeout behavior
        self._recv_sock.settimeout(5.0)
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
        # records the transfer finish a bit closer to the actual receive completion, rather than waiting for MD5 verification which can take time for large files
        self.stats.end_time = time.time()
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