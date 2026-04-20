# UDPServer.py
# Example command to run the server in mock mode (for local testing, no sudo required)
# python3 UDPServer.py --bind-ip 127.0.0.1 --port 5000 --dir files --mock

# Example command to run the server in raw mode (real testing, requires sudo)
# Replace <server_ip> with the server machine's actual IP address
# sudo python3 UDPServer.py --bind-ip <server_ip> --port 5000 --dir files

from protocol import (
    TYPE_REQUEST,
    TYPE_DATA,
    TYPE_ACK,
    TYPE_SYN_ACK,
    TYPE_FIN,
    build_srft_packet,
    parse_srft_packet,
    build_raw_packet,
    parse_raw_packet,
    pack_srft_synack_payload,
    pack_srft_fin_payload,
)

import os
import time
import socket
import argparse
import hashlib
import config
import struct

# converts a number of seconds into a time string formatted as hh:mm:ss
def format_hhmmss(seconds: int) -> str:
    hh = seconds // 3600
    mm = (seconds % 3600) // 60
    ss = seconds % 60
    return f"{hh:02d}:{mm:02d}:{ss:02d}"


# ensures the requested file remains inside the allowed directory
# and prevents attackers from accessing other files on the server.
# stopping users from accessing files outside the directory they are allowed to access.
# Return absolute path if safe, else None.
def safe_join(base_dir: str, user_path: str) -> str | None:
    # Take the directory path in base_dir
    # and convert it to the full absolute path on the system
    base_abs_path = os.path.abspath(base_dir)
    target = os.path.abspath(os.path.join(base_abs_path, user_path))
    # Allow exactly inside base_abs (including subdirs)
    if os.path.commonpath([base_abs_path, target]) != base_abs_path:
        return None
    return target


# determines which IP address the server
# should use as the source IP in the raw packet IP header.
def resolve_outgoing_ip(to_ip: str, bind_ip: str) -> str:
    # If the user specified a server IP
    # Then the function simply returns the specified IP
    if bind_ip != "0.0.0.0":
        return bind_ip
    # If bind_ip = "0.0.0.0"
    # Create a temporary UDP socket
    # connect the socket
    # Get the local IP address and return it
    # The close the socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((to_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()

# waits until the server receives a valid file request from a client
# Once it finds a valid request, it returns the client’s IP, client’s port,
# and the requested filename.
def recv_request(raw_recv_sock: socket.socket, listen_port: int, mock: bool) -> tuple[str, int, str]:
    while True:
        pkt, addr = raw_recv_sock.recvfrom(65535)
        print(f"[DEBUG] server recvfrom returned, addr={addr}, len={len(pkt)}")

        print(f"[DEBUG] server got raw packet len={len(pkt)}")

        if mock:
            #In mock mode, the packet pkt you receive already contains
            # only the SRFT protocol data,
            # so do not need to parse IP or UDP headers.
            src_ip, src_port = addr
            srft = parse_srft_packet(pkt)
            if not srft:
                continue

            pkt_type, _seq, _ack, payload = srft
            if pkt_type != TYPE_REQUEST:
                continue

            filename = payload.decode(errors="replace").strip()
            if not filename:
                continue

            return src_ip, src_port, filename
        else:
            # Parse the raw packet to extract IP/UDP information and the SRFT payload
            parsed = parse_raw_packet(pkt)
            if not parsed:
                continue

            src_ip, src_port, dst_ip, dst_port, udp_payload = parsed

            # Ignore packets not sent to the server's listening port.
            # Raw sockets receive all UDP packets on the machine, so we must
            # filter out packets that are not intended for this server.
            if dst_port != listen_port:
                continue

            print(f"[DEBUG] SRFT candidate packet from {src_ip}:{src_port} -> {dst_ip}:{dst_port}")
            # Attempt to parse the UDP payload as an SRFT packet.
            # If parsing fails (e.g., invalid format or checksum failure),
            # the packet is ignored.
            srft = parse_srft_packet(udp_payload)
            if not srft:
                continue
            # Extract SRFT packet fields
            pkt_type, _seq, _ack, payload = srft
            # Only process REQUEST packets here.
            # Other packet types (DATA, ACK, FIN) are not relevant when
            # waiting for a file request from a client.
            if pkt_type != TYPE_REQUEST:
                continue
            # Decode the requested filename from the payload
            # 'errors="replace"' prevents crashes if payload contains invalid bytes
            filename = payload.decode(errors="replace").strip()
            if not filename:
                continue
            return src_ip, src_port, filename


#This function waits for an ACK packet from the client for a limited amount of time.
#If it receives a valid ACK, it returns the acknowledgment number.
#If no valid ACK arrives before the timeout, it returns None.
# The server waits for ACKs because it is the side sending the data,
# and acknowledgements are required to ensure reliable delivery over UDP.
def wait_for_ack(
    raw_recv_sock: socket.socket,
    client_ip: str,
    client_port: int,
    server_port: int,
    timeout_sec: float,
    mock: bool
) -> int | None:
    raw_recv_sock.settimeout(timeout_sec)
    try:
        # Receive a packet
        pkt, addr = raw_recv_sock.recvfrom(65535)
    except socket.timeout:
        return None
    finally:
        raw_recv_sock.settimeout(None)
    if mock:
        src_ip, src_port = addr
        if src_ip != client_ip or src_port != client_port:
            return None

        srft = parse_srft_packet(pkt)
        if not srft:
            return None

        pkt_type, _rseq, rAck, _payload = srft
        if pkt_type != TYPE_ACK:
            return None

        return rAck
    # Parse the raw IP packet
    parsed = parse_raw_packet(pkt)
    if not parsed:
        return None
    src_ip, src_port, _dst_ip, dst_port, udp_payload = parsed
    # Verify packet comes from the expected client
    if src_ip != client_ip or src_port != client_port or dst_port != server_port:
        return None
    # Parse the SRFT packet
    srft = parse_srft_packet(udp_payload)
    if not srft:
        return None
    # Extract ACK information
    pkt_type, _rseq, rAck, _payload = srft
    # Ensure it is actually an ACK packet
    if pkt_type != TYPE_ACK:
        return None
    return rAck

# a helper function used by the SRFT server to send control packets (SYN_ACK/FIN) with seq=0 ack=0 (not data packets)
# raw_send_sock: socket.socket is a raw socket used to send packets
# the assignment requires building IP + UDP headers manually
# so cannot use a normal UDP socket
def send_control(
    raw_send_sock: socket.socket,
    server_ip: str,
    client_ip: str,
    server_port: int,
    client_port: int,
    pkt_type: int,
    payload: bytes,
    counters: dict,
    packet_id: int = 0,
    mock: bool = False,
):
    # builds the SRFT protocol packet, control packets use seq = 0, ack = 0
    # because they are not part of the sliding window data transfer
    srft_bytes = build_srft_packet(pkt_type, seq=0, ack=0, payload=payload)

    if mock:
        raw_send_sock.sendto(srft_bytes, (client_ip, client_port))
    else:
        ## wrap the SRFT packet inside of IP header, UDP header, SRFT payload
        # so the packet is a complete raw network packet
        raw_packet = build_raw_packet(server_ip, client_ip, server_port, client_port, srft_bytes, packet_id=packet_id)
        # send the packet to client
        raw_send_sock.sendto(raw_packet, (client_ip, client_port))
    # increments the counter required by the assignment:
    counters["packets_sent_total"] += 1


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--bind-ip", default="0.0.0.0", help="server bind ip (0.0.0.0 = auto)")
    parser.add_argument("--port", type=int, default=config.DEFAULT_SERVER_PORT, help="server UDP port")
    parser.add_argument("--dir", default=config.FILES_DIR, help="directory with files to serve")
    parser.add_argument("--chunk", type=int, default=config.CHUNK_SIZE, help="DATA payload size (bytes)")
    parser.add_argument("--timeout", type=float, default=config.TIMEOUT_SEC, help="retransmit timeout seconds")
    parser.add_argument("--window", type=int, default=getattr(config, "SLIDING_WINDOW_SIZE", 64), help="GBN window size")
    parser.add_argument("--mock", action="store_true", help="use plain UDP sockets for local testing")
    args = parser.parse_args()

    listen_port = args.port
    files_dir = args.dir
    chunk_size = args.chunk
    timeout = args.timeout
    window_size = max(1, args.window)

    if args.mock:
        raw_recv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        raw_recv.bind((args.bind_ip, listen_port))
        raw_send = raw_recv
    else:
        # Raw receiving socket (receives UDP packets)
        raw_recv = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)
        # Raw sending socket (we build IP header)
        raw_send = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        # tells the operating system that the program will include
        # the IP header itself when sending packets through the raw socket.
        # program is manually building the IP header. Without it,
        # the operating system would try to add its own IP header, which would break the packet.
        raw_send.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    print(f"[SRFT server] waiting for REQUEST on UDP port {listen_port} ...")
    client_ip, client_port, filename = recv_request(raw_recv, listen_port, mock=args.mock)
    print(f"[SRFT] request from {client_ip}:{client_port} for file: {filename}")

    server_ip = resolve_outgoing_ip(client_ip, args.bind_ip)

    # Build the absolute path of the requested file safely
    # safe_join prevents directory traversal attacks
    file_path = safe_join(files_dir, filename)
    # If the path is invalid or unsafe, reject the request
    if not file_path:
        print("Refusing path traversal / invalid file path.")
        return
    # Check if the file actually exists and is a regular file
    # If not, stop the transfer and notify the user
    if not os.path.exists(file_path) or not os.path.isfile(file_path):
        print(f"File not found: {file_path}")
        return

    # Get the size of the file in bytes
    file_size = os.path.getsize(file_path)
    # Calculate the total number of chunks required to send the file
    # Each chunk carries 'chunk_size' bytes of data
    # The formula performs ceiling division to ensure the last partial chunk is counted
    total_chunks = (file_size + chunk_size - 1) // chunk_size

    # Counters used to track packet statistics during the file transfer
    # These values are required for the final server report
    # - packets_sent_total: total number of packets sent by the server
    # - packets_retransmitted: number of packets retransmitted due to timeout or loss
    # - packets_received_from_client: number of ACK packets received from the client
    counters = {
        "packets_sent_total": 0,
        "packets_retransmitted": 0,
        "packets_received_from_client": 0,
    }

   # Pack the file size into 8 bytes using network byte order
    # This payload will be included in the SYN_ACK packet to inform the client
    # about the total size of the file to be transferred
    synack_payload = pack_srft_synack_payload(file_size)

    # Send a SYN_ACK control packet to the client
    # This packet informs the client that the request is accepted and provides
    # metadata (payload contains the file size)
    # Sequence and ACK numbers are 0
    # because this is a control message, not a DATA packet in the sliding window
    send_control(
        raw_send_sock=raw_send,
        server_ip=server_ip,
        client_ip=client_ip,
        server_port=listen_port,
        client_port=client_port,
        pkt_type=TYPE_SYN_ACK,
        payload=synack_payload,
        counters=counters,
        packet_id=0,
        mock=args.mock
    )

    # Compute the MD5 hash of the file
    # The file is read in 1MB blocks to avoid loading the entire file into memory
    # The resulting digest will be sent in the FIN packet so the client can verify
    # the integrity of the received file
    # reference: https://docs.python.org/3/library/hashlib.html
    md5 = hashlib.md5()
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            # adds more data to the hash computation
            md5.update(block)
    # returns the final MD5 hash value as raw bytes after all data has been processed with md5.update()
    md5_bytes = md5.digest()

    # --- Go-Back-N sending ---
    # base: oldest unacked seq
    # next_seq: next seq to send
    base = 0
    next_seq = 0

    # Buffer that stores sent DATA packets indexed by sequence number.
    # This allows the server to retransmit packets if ACKs are not received
    # within the timeout (used for the sliding window / Go-Back-N mechanism).
    send_buf: dict[int, bytes] = {}

    # timer deadline for base; None means timer off
    deadline: float | None = None

    # Read a specific chunk of the file based on its sequence number
    # Each sequence number corresponds to a fixed-size chunk of the file
    # The file pointer is moved to (seq * chunk_size), and chunk_size bytes
    # are read from that position.
    def read_chunk_by_seq(seq: int) -> bytes:
        with open(file_path, "rb") as f:
            f.seek(seq * chunk_size) # move to the start position of the chunk
            return f.read(chunk_size) # read one chunk of data

    start_t = time.time()
    packet_id = 1

    print(f"[SRFT] sending {file_size} bytes in {total_chunks} chunks "
          f"(chunk={chunk_size}, window={window_size}, timeout={timeout}s)")

    while base < total_chunks:
        # Send DATA packets while the window is not full and there are still chunks left to send
        while next_seq < total_chunks and next_seq < base + window_size:
             # Read the file chunk corresponding to the current sequence number
            chunk = read_chunk_by_seq(next_seq)
             # Build the SRFT DATA packet with the chunk as payload
            srft_bytes = build_srft_packet(TYPE_DATA, seq=next_seq, ack=0, payload=chunk)
            if args.mock:
                packet_bytes = srft_bytes
                raw_send.sendto(packet_bytes, (client_ip, client_port))
            else:
                packet_bytes = build_raw_packet(
                    server_ip, client_ip, listen_port, client_port, srft_bytes, packet_id=packet_id
                )
                raw_send.sendto(packet_bytes, (client_ip, client_port))

            # Increment packet ID
            packet_id = (packet_id + 1) & 0xFFFF_FFFF

            counters["packets_sent_total"] += 1

            # Store packet for retransmission
            send_buf[next_seq] = packet_bytes

            # If this is the first unacknowledged packet (base), start the retransmission timer
            if base == next_seq:
                deadline = time.time() + timeout  # start timer for base
             # Move to the next sequence number
            next_seq += 1

       # If there are no outstanding (unacknowledged) packets, stop the timer and loop
        # (Normally base < next_seq while transfer is in progress.)
        if base == next_seq:
            deadline = None
            continue

        # Wait for ACK or timeout
        now = time.time()

        # If the timer is not running yet, start it for the oldest unacked packet (base)
        if deadline is None:
            deadline = now + timeout

        # Compute how much time remains before timeout
        remainingTime = deadline - now

        # If the timer already expired, we have a timeout event
        if remainingTime <= 0:
            # Timeout: Go-Back-N retransmissions
            # Retransmit all outstanding packets in the current window: [base, next_seq)
            for s in range(base, next_seq):
                if args.mock:
                    raw_send.sendto(send_buf[s], (client_ip, client_port))
                else:
                    raw_send.sendto(send_buf[s], (client_ip, client_port))
                counters["packets_sent_total"] += 1
                counters["packets_retransmitted"] += 1
            # Restart the timer after retransmitting
            deadline = time.time() + timeout
            continue

        # Otherwise, wait for an ACK packet for up to remainingTime seconds
        rack = wait_for_ack(
            raw_recv_sock=raw_recv,
            client_ip=client_ip,
            client_port=client_port,
            server_port=listen_port,
            timeout_sec=remainingTime,
            mock = args.mock
        )
        # If no ACK arrives before remainingTime, try again; next iteration may timeout
        if rack is None:
            continue

        counters["packets_received_from_client"] += 1

        # Cumulative ACK: rack is the next expected sequence number at the client
        # This means all packets with seq < rack have been received correctly
        if rack > base:
            # remove all acked packets from buffer
            for s in range(base, min(rack, next_seq)):
                send_buf.pop(s, None)
            # Slide the window forward: base becomes the new oldest unacked seq.
            base = rack

            # Timer behavior:
            # - If everything is now acknowledged (base == next_seq), stop the timer.
            # - Otherwise restart the timer for the new base packet.
            if base == next_seq:
                deadline = None
            else:
                deadline = time.time() + timeout

    # Send FIN with MD5
    fin_payload = pack_srft_fin_payload(md5_bytes)
    print(f"[DEBUG] about to send SYN_ACK to {client_ip}:{client_port} from {server_ip}:{listen_port}")
    # Send the FIN control packet to signal the end of the file transfer
    # The payload contains the MD5 so the client can verify file integrity
    send_control(
        raw_send_sock=raw_send,
        server_ip=server_ip,
        client_ip=client_ip,
        server_port=listen_port,
        client_port=client_port,
        pkt_type=TYPE_FIN,
        payload=fin_payload,
        counters=counters,
        packet_id=packet_id,
        mock=args.mock
    )
    # Record the end time and calculate the total duration of the file transfer
    end_t = time.time()
    duration = int(end_t - start_t)

    print("\n===== SRFT Phase 1 Server Report =====")
    print(f"Name of the transferred file: {filename}")
    print(f"Size of the transferred file: {file_size}")
    print(f"The number of packets sent from the server: {counters['packets_sent_total']}")
    print(f"The number of retransmitted packets from the server: {counters['packets_retransmitted']}")
    print(f"The number of packets received from the client: {counters['packets_received_from_client']}")
    print(f"The time duration of the file transfer (hh:min:ss): {format_hhmmss(duration)}")

    # Save transfer report if a report file path is configured
    report_path = getattr(config, "REPORT_FILE", None)
    if report_path:
        try:
            with open(report_path, "w") as rf:
                rf.write(f"Name of the transferred file: {filename}\n")
                rf.write(f"Size of the transferred file: {file_size}\n")
                rf.write(f"The number of packets sent from the server: {counters['packets_sent_total']}\n")
                rf.write(f"The number of retransmitted packets from the server: {counters['packets_retransmitted']}\n")
                rf.write(f"The number of packets received from the client: {counters['packets_received_from_client']}\n")
                rf.write(f"The time duration of the file transfer (hh:min:ss): {format_hhmmss(duration)}\n")
            print(f"Report saved to {report_path}")
        except Exception as e:
            print("Failed to write report:", e)


if __name__ == "__main__":
    main()

