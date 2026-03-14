"""
Mock Server for testing SRFT Receiver (receiver.py)

Does NOT use SOCK_RAW - uses regular UDP socket for simplicity.
Implements simple sliding window flow control to match receiver's window.

Usage:
    # Phase 1 (no SYN_ACK/FIN, for macOS/local testing without sudo):
    python3 mock_server.py --scenario normal --file files/test.txt --phase1

    # Phase 2:
    python3 mock_server.py --scenario normal --file files/test_10mb_file
    python3 mock_server.py --scenario loss --file files/test_10mb_file --loss 0.03
    python3 mock_server.py --scenario reorder --file files/test_10mb_file
    python3 mock_server.py --scenario duplicate --file files/test_10mb_file
    python3 mock_server.py --scenario corrupt --file files/test_10mb_file
"""

import argparse
import hashlib
import math
import os
import random
import socket
import struct
import time
import threading

from protocol import (
    TYPE_REQUEST, TYPE_DATA, TYPE_ACK, TYPE_SYN_ACK, TYPE_FIN,
    build_srft_packet, parse_srft_packet,
    pack_srft_synack_payload, pack_srft_fin_payload,
)
from config import (
    CHUNK_SIZE,
    SLIDING_WINDOW_SIZE,
    DEFAULT_SERVER_PORT,
    TIMEOUT_SEC,
)


# ------------------------------------------------------------------ #
# Packet helpers                                                       #
# ------------------------------------------------------------------ #

def send_srft(sock: socket.socket, dst: tuple, pkt_type: int,
              seq: int, ack: int, payload: bytes):
    pkt = build_srft_packet(pkt_type, seq, ack, payload)
    sock.sendto(pkt, dst)


def recv_srft(sock: socket.socket, timeout: float = 2.0):
    sock.settimeout(timeout)
    try:
        data, addr = sock.recvfrom(65535)
        result = parse_srft_packet(data)
        if result is None:
            return None
        pkt_type, seq, ack, payload = result
        return pkt_type, seq, ack, payload, addr
    except TimeoutError:
        return None


# ------------------------------------------------------------------ #
# Sliding Window Sender                                                #
# ------------------------------------------------------------------ #

class SlidingWindowSender:
    """
    Simple Go-Back-N style sliding window sender for mock server.
    Sends up to SLIDING_WINDOW_SIZE packets without ACK,
    then waits. Retransmits on timeout.

    Supports:
    - loss_rate: randomly drop packets (0.0 to 1.0)
    - corrupt_seq: send a corrupted version of this seq number once
    - drop_seq: drop this seq number once (then retransmit normally)
    - reorder: send seq+1 before seq for first few chunks
    - duplicate_seq: send this seq number twice
    """

    def __init__(
        self,
        sock: socket.socket,
        client_addr: tuple,
        chunks: list[bytes],
        loss_rate: float = 0.0,
        corrupt_seq: int = -1,
        drop_seq: int = -1,
        duplicate_seq: int = -1,
    ):
        self.sock = sock
        self.client_addr = client_addr
        self.chunks = chunks
        self.total = len(chunks)
        self.loss_rate = loss_rate
        self.corrupt_seq = corrupt_seq
        self.drop_seq = drop_seq
        self.duplicate_seq = duplicate_seq

        self.base = 0          # oldest unACKed seq
        self.next_seq = 0      # next seq to send
        self.ack_lock = threading.Lock()
        self.sent_time: dict[int, float] = {}  # seq -> time sent
        self.corrupted_sent = False
        self.dropped_sent = False

        # stats
        self.packets_sent = 0
        self.retransmissions = 0

    def run(self):
        """Main send loop with sliding window."""
        print(f"[SENDER] Starting, total_chunks={self.total}, "
              f"window={SLIDING_WINDOW_SIZE}, loss_rate={self.loss_rate}")

        # Start ACK receiver thread
        ack_done = threading.Event()
        ack_thread = threading.Thread(
            target=self._recv_acks, args=(ack_done,), daemon=True
        )
        ack_thread.start()

        while self.base < self.total:
            # Fill window
            with self.ack_lock:
                while (self.next_seq < self.total and
                       self.next_seq < self.base + SLIDING_WINDOW_SIZE):
                    self._send_one(self.next_seq)
                    self.next_seq += 1

            # Check for timeouts
            now = time.time()
            with self.ack_lock:
                for seq in range(self.base, self.next_seq):
                    if seq in self.sent_time and now - self.sent_time[seq] > TIMEOUT_SEC:
                        print(f"[SENDER] Timeout seq={seq}, retransmitting from base={self.base}")
                        # Go-Back-N: retransmit from base
                        for r_seq in range(self.base, self.next_seq):
                            self._send_one(r_seq, is_retransmit=True)
                        self.retransmissions += (self.next_seq - self.base)
                        break

            time.sleep(0.001)

        ack_done.set()
        ack_thread.join(timeout=2.0)
        print(f"[SENDER] Done. Sent={self.packets_sent}, "
              f"Retransmissions={self.retransmissions}")

    def _send_one(self, seq: int, is_retransmit: bool = False):
        """Send a single DATA packet, applying scenario modifications."""
        data = self.chunks[seq]

        # Simulate packet loss
        if self.loss_rate > 0 and random.random() < self.loss_rate:
            print(f"[SENDER] Simulated loss seq={seq}")
            return

        # Drop specific seq once
        if seq == self.drop_seq and not self.dropped_sent and not is_retransmit:
            print(f"[SENDER] Dropping seq={seq} once")
            self.dropped_sent = True
            self.sent_time[seq] = time.time()
            return

        # Corrupt specific seq once
        if seq == self.corrupt_seq and not self.corrupted_sent and not is_retransmit:
            pkt = build_srft_packet(TYPE_DATA, seq, 0, data)
            pkt = pkt[:5] + bytes([pkt[5] ^ 0xFF]) + pkt[6:]
            self.sock.sendto(pkt, self.client_addr)
            print(f"[SENDER] Sent CORRUPT seq={seq}")
            self.corrupted_sent = True
            self.packets_sent += 1
            self.sent_time[seq] = time.time()
            return

        # Send duplicate
        if seq == self.duplicate_seq and not is_retransmit:
            send_srft(self.sock, self.client_addr, TYPE_DATA, seq, 0, data)
            self.packets_sent += 1
            print(f"[SENDER] Sending DUPLICATE seq={seq}")

        send_srft(self.sock, self.client_addr, TYPE_DATA, seq, 0, data)
        self.packets_sent += 1
        self.sent_time[seq] = time.time()

    def _recv_acks(self, done: threading.Event):
        """Background thread: receive ACKs and advance base."""
        while not done.is_set():
            result = recv_srft(self.sock, timeout=0.1)
            if result is None:
                continue
            pkt_type, seq, ack, payload, _ = result
            if pkt_type == TYPE_ACK:
                with self.ack_lock:
                    if ack > self.base:
                        print(f"[SENDER] ACK received: ack={ack}, "
                              f"advancing base {self.base}->{ack}")
                        # Clear sent_time for ACKed packets
                        for s in range(self.base, ack):
                            self.sent_time.pop(s, None)
                        self.base = ack


# ------------------------------------------------------------------ #
# Mock Server                                                          #
# ------------------------------------------------------------------ #

class Phase1Sender:
    """Phase 1: REQUEST->DATA->ACK, no SYN_ACK/FIN. First DATA = file_size(4B)+chunk0, seq from 1."""

    def __init__(self, sock: socket.socket, client_addr: tuple, file_bytes: bytes):
        self.sock = sock
        self.client_addr = client_addr
        self.file_size = len(file_bytes)
        self.chunks = [
            file_bytes[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
            for i in range(math.ceil(len(file_bytes) / CHUNK_SIZE))
        ]
        self.total_chunks = max(1, len(self.chunks))
        self.base_seq = 1
        self.last_ack = 0
        self.ack_lock = threading.Lock()
        self.sent_time: dict[int, float] = {}
        self.packets_sent = 0
        self.retransmissions = 0

    def run(self):
        sock = self.sock
        client = self.client_addr
        sock.settimeout(TIMEOUT_SEC)
        deadline = time.time() + 300

        # Send all DATA packets initially
        first_payload = struct.pack("!I", self.file_size) + self.chunks[0]
        pkt = build_srft_packet(TYPE_DATA, self.base_seq, 0, first_payload)
        sock.sendto(pkt, client)
        self.packets_sent += 1
        self.sent_time[self.base_seq] = time.time()

        for i in range(1, self.total_chunks):
            pkt = build_srft_packet(TYPE_DATA, self.base_seq + i, 0, self.chunks[i])
            sock.sendto(pkt, client)
            self.packets_sent += 1
            self.sent_time[self.base_seq + i] = time.time()

        while self.last_ack < self.total_chunks and time.time() < deadline:
            try:
                data, addr = sock.recvfrom(65535)
                if addr[0] != client[0] or addr[1] != client[1]:
                    continue
                result = parse_srft_packet(data)
                if result is None:
                    continue
                pkt_type, seq, ack, _ = result
                if pkt_type != TYPE_ACK:
                    continue
                with self.ack_lock:
                    # ack = highest consecutive seq received (e.g. ack=3 means received 1,2,3)
                    if ack >= self.base_seq:
                        num_acked = ack - self.base_seq + 1
                        if num_acked > self.last_ack:
                            self.last_ack = num_acked
                            for s in range(self.base_seq, ack + 1):
                                self.sent_time.pop(s, None)
            except (TimeoutError, socket.timeout, BlockingIOError):
                # Retransmit unacked
                for i in range(self.last_ack, self.total_chunks):
                    seq = self.base_seq + i
                    if seq == self.base_seq:
                        payload = struct.pack("!I", self.file_size) + self.chunks[0]
                    else:
                        payload = self.chunks[i]
                    pkt = build_srft_packet(TYPE_DATA, seq, 0, payload)
                    sock.sendto(pkt, client)
                    self.retransmissions += 1
                    self.sent_time[seq] = time.time()
            time.sleep(0.001)

        print(f"[PHASE1 SENDER] Done. last_ack={self.last_ack}/{self.total_chunks}, "
              f"sent={self.packets_sent}, retrans={self.retransmissions}")


class MockServer:
    def __init__(self, scenario: str, filename: str, loss_rate: float = 0.0, phase1: bool = False):
        self.scenario = scenario
        self.loss_rate = loss_rate
        self.phase1 = phase1

        if not os.path.exists(filename):
            raise FileNotFoundError(f"Test file '{filename}' not found.")

        with open(filename, "rb") as f:
            self.test_file_bytes = f.read()

        self.total_chunks = math.ceil(len(self.test_file_bytes) / CHUNK_SIZE)
        self.test_file_md5 = hashlib.md5(self.test_file_bytes).digest()
        self.chunks = [
            self.test_file_bytes[i * CHUNK_SIZE:(i + 1) * CHUNK_SIZE]
            for i in range(self.total_chunks)
        ]

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.bind(("0.0.0.0", DEFAULT_SERVER_PORT))
        mode = "Phase 1" if phase1 else "Phase 2"
        print(f"[MOCK SERVER] Listening on port {DEFAULT_SERVER_PORT}, "
              f"scenario='{scenario}', file='{filename}', mode={mode}, loss={loss_rate*100:.0f}%")
        print(f"[MOCK SERVER] {len(self.test_file_bytes):,} bytes, "
              f"{self.total_chunks} chunks, MD5={self.test_file_md5.hex()}")

    def run(self):
        # Step 1: Wait for REQUEST
        print("\n[MOCK SERVER] Waiting for REQUEST...")
        result = recv_srft(self.sock, timeout=10.0)
        if result is None:
            print("[ERROR] No REQUEST received.")
            return
        pkt_type, seq, ack, payload, client_addr = result
        if pkt_type != TYPE_REQUEST:
            print(f"[ERROR] Expected TYPE_REQUEST, got {pkt_type}")
            return
        print(f"[MOCK SERVER] REQUEST for '{payload.decode()}' from {client_addr}")

        if self.phase1:
            # Phase 1: no SYN_ACK/FIN, first DATA = file_size(4B)+chunk0, seq from 1
            sender = Phase1Sender(self.sock, client_addr, self.test_file_bytes)
            sender.run()
            print("[MOCK SERVER] Phase 1 transfer done.")
            return

        # Step 2: Send SYN_ACK (Phase 2 only)
        synack_payload = pack_srft_synack_payload(len(self.test_file_bytes))
        send_srft(self.sock, client_addr, TYPE_SYN_ACK, 0, 0, synack_payload)
        print(f"[MOCK SERVER] Sent SYN_ACK")
        time.sleep(0.1)

        # Step 3: Send DATA with sliding window (Phase 2)
        sender = SlidingWindowSender(
            sock=self.sock,
            client_addr=client_addr,
            chunks=self.chunks,
            loss_rate=self.loss_rate,
            corrupt_seq=3 if self.scenario == "corrupt" else -1,
            drop_seq=2 if self.scenario == "loss" else -1,
            duplicate_seq=1 if self.scenario == "duplicate" else -1,
        )

        # reorder: swap chunk 1 and 2
        if self.scenario == "reorder":
            reordered = self.chunks[:]
            reordered[1], reordered[2] = reordered[2], reordered[1]
            sender.chunks = reordered

        sender.run()

        # Step 4: Send FIN
        fin_payload = pack_srft_fin_payload(self.test_file_md5)
        send_srft(self.sock, client_addr, TYPE_FIN, self.total_chunks, 0, fin_payload)
        print(f"[MOCK SERVER] Sent FIN, MD5={self.test_file_md5.hex()}")

        # Retransmit FIN up to 3 times
        for attempt in range(3):
            result = recv_srft(self.sock, timeout=2.0)
            if result:
                pkt_type, _, ack, _, _ = result
                if pkt_type == TYPE_ACK:
                    print(f"[MOCK SERVER] Final ACK received: ack={ack}")
                    break
            print(f"[MOCK SERVER] Retransmitting FIN ({attempt+1}/3)")
            send_srft(self.sock, client_addr, TYPE_FIN, self.total_chunks, 0, fin_payload)

        print("[MOCK SERVER] Done.")


# ------------------------------------------------------------------ #
# Entry point                                                          #
# ------------------------------------------------------------------ #

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SRFT Mock Server")
    parser.add_argument(
        "--scenario",
        choices=["normal", "loss", "reorder", "duplicate", "corrupt"],
        default="normal",
    )
    parser.add_argument(
        "--file",
        default="test5chunks.bin",
        help="Test file to serve",
    )
    parser.add_argument(
        "--loss",
        type=float,
        default=0.0,
        help="Packet loss rate (0.0 to 1.0), e.g. 0.03 for 3%%",
    )
    parser.add_argument(
        "--phase1",
        action="store_true",
        help="Phase 1 mode: no SYN_ACK/FIN, first DATA = file_size(4B)+chunk0",
    )
    args = parser.parse_args()

    server = MockServer(args.scenario, args.file, args.loss, phase1=args.phase1)
    server.run()