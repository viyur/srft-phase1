# UDPClient.py
# Example:
# sudo python3.11 UDPClient.py --server-ip <SERVER_EC2_IP>  --filename random.bin 
# server port and client port are set by default in config.py, you can change them by adding --server-port and --client-port arguments


import os
import time
import math
import socket
import argparse
import hashlib

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
    unpack_srft_synack_payload,
    unpack_srft_fin_payload,
)

import config


def resolve_local_ip(to_ip: str) -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect((to_ip, 1))
        return s.getsockname()[0]
    finally:
        s.close()


def send_request(
    send_sock: socket.socket,
    client_ip: str,
    server_ip: str,
    client_port: int,
    server_port: int,
    filename: str,
) -> None:
    srft = build_srft_packet(
        pkt_type=TYPE_REQUEST,
        seq=0,
        ack=0,
        payload=filename.encode(),
    )

    raw_pkt = build_raw_packet(
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        srft_payload=srft,
    )

    # macOS raw socket workaround: use connected raw socket + send()
    send_sock.send(raw_pkt)
    print(f"[REQUEST] requested file: {filename}")


def send_ack(
    send_sock: socket.socket,
    client_ip: str,
    server_ip: str,
    client_port: int,
    server_port: int,
    ack_num: int,
) -> None:
    srft = build_srft_packet(
        pkt_type=TYPE_ACK,
        seq=0,
        ack=ack_num,
        payload=b"",
    )

    raw_pkt = build_raw_packet(
        src_ip=client_ip,
        dst_ip=server_ip,
        src_port=client_port,
        dst_port=server_port,
        srft_payload=srft,
    )

    # macOS raw socket workaround: use connected raw socket + send()
    send_sock.send(raw_pkt)
    print(f"[ACK] sent cumulative ACK={ack_num}")


def recv_srft_packet(
    recv_sock: socket.socket,
    server_ip: str,
    server_port: int,
    client_port: int,
):
    raw_data, _ = recv_sock.recvfrom(config.RECV_BUFFER_SIZE)

    parsed = parse_raw_packet(raw_data)
    if parsed is None:
        return None

    src_ip, src_port, _dst_ip, dst_port, udp_payload = parsed

    if src_ip != server_ip:
        return None
    if src_port != server_port:
        return None
    if dst_port != client_port:
        return None

    srft = parse_srft_packet(udp_payload)
    if srft is None:
        return None

    return srft


def compute_md5(path: str) -> bytes:
    md5 = hashlib.md5()
    with open(path, "rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            md5.update(block)
    return md5.digest()


def receive_file(
    send_sock: socket.socket,
    recv_sock: socket.socket,
    client_ip: str,
    server_ip: str,
    client_port: int,
    server_port: int,
    filename: str,
    output_path: str,
) -> bool:
    send_request(send_sock, client_ip, server_ip, client_port, server_port, filename)

    file_size = None

    while file_size is None:
        result = recv_srft_packet(recv_sock, server_ip, server_port, client_port)
        if result is None:
            continue

        pkt_type, seq, ack, payload = result

        if pkt_type != TYPE_SYN_ACK:
            continue

        file_size = unpack_srft_synack_payload(payload)
        if file_size is None:
            print("[ERROR] malformed SYN_ACK payload")
            return False

        print(f"[SYN_ACK] file_size={file_size} bytes")

    total_chunks = math.ceil(file_size / config.CHUNK_SIZE) if file_size > 0 else 0
    expected_seq = 0
    server_md5 = None

    last_ack_time = time.time()
    packets_since_last_ack = 0

    with open(output_path, "wb") as f:
        while True:
            result = recv_srft_packet(recv_sock, server_ip, server_port, client_port)
            if result is None:
                continue

            pkt_type, seq, ack, payload = result

            if pkt_type == TYPE_DATA:
                now = time.time()

                if seq == expected_seq:
                    f.write(payload)
                    expected_seq += 1
                    packets_since_last_ack += 1

                    print(f"[DATA] accepted seq={seq}, next_expected={expected_seq}/{total_chunks}")

                    # delayed cumulative ACK
                    if (
                        packets_since_last_ack >= config.ACK_EVERY_N
                        or (now - last_ack_time >= config.ACK_INTERVAL_SEC)
                        or (expected_seq == total_chunks)
                    ):
                        send_ack(send_sock, client_ip, server_ip, client_port, server_port, expected_seq)
                        last_ack_time = now
                        packets_since_last_ack = 0

                else:
                    # duplicate or out-of-order
                    print(f"[DATA] discarded seq={seq}, expected={expected_seq}")

                    send_ack(send_sock, client_ip, server_ip, client_port, server_port, expected_seq)

                    last_ack_time = now
                    # packets_since_last_ack = 0

            elif pkt_type == TYPE_FIN:
                # final ACK for safety
                send_ack(send_sock, client_ip, server_ip, client_port, server_port, expected_seq)

                server_md5 = unpack_srft_fin_payload(payload)
                if server_md5 is None:
                    print("[ERROR] malformed FIN payload")
                    return False

                print("[FIN] received from server")
                break

    with open(output_path, "rb+") as f:
        f.truncate(file_size)

    local_md5 = compute_md5(output_path)
    local_md5_hex = local_md5.hex()

    print("\n===== SRFT Phase 1 Client Report =====")
    print(f"File name: {filename}")
    print(f"File size: {file_size} bytes")
    print(f"Number of packets received from server: {expected_seq}")
    print(f"Received file MD5: {local_md5_hex}")

    if local_md5 == server_md5:
        print("[SUCCESS] MD5 verified. Transfer complete.")
        return True

    print("[ERROR] MD5 mismatch. File may be corrupted.")
    try:
        os.remove(output_path)
        print(f"[CLEANUP] removed corrupted file: {output_path}")
    except OSError:
        pass
    return False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--server-ip", default="127.0.0.1", help="server IP address")
    parser.add_argument("--server-port", type=int, default=config.DEFAULT_SERVER_PORT, help="server UDP port")
    parser.add_argument("--client-port", type=int, default=config.DEFAULT_CLIENT_PORT, help="client UDP port")
    parser.add_argument("--filename", required=True, help="requested filename on server")
    parser.add_argument("--out-dir", default="received", help="directory on receiver side to save the file")
    args = parser.parse_args()

    os.makedirs(args.out_dir, exist_ok=True)
    output_path = os.path.join(args.out_dir, os.path.basename(args.filename))

    recv_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP)

    send_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    send_sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    client_ip = resolve_local_ip(args.server_ip)

    # macOS raw socket workaround
    send_sock.connect((args.server_ip, args.server_port))

    print(f"[CLIENT] local IP resolved as {client_ip}")
    print(f"[CLIENT] requesting {args.filename} from {args.server_ip}:{args.server_port}")
    print(f"[CLIENT] saving to {output_path}")

    start_time = time.time()

    try:
        ok = receive_file(
            send_sock=send_sock,
            recv_sock=recv_sock,
            client_ip=client_ip,
            server_ip=args.server_ip,
            client_port=args.client_port,
            server_port=args.server_port,
            filename=args.filename,
            output_path=output_path,
        )
    finally:
        recv_sock.close()
        send_sock.close()

    duration = int(time.time() - start_time)
    print(f"[CLIENT] duration: {duration} seconds")

    if ok:
        print("[CLIENT] transfer succeeded")
    else:
        print("[CLIENT] transfer failed")


if __name__ == "__main__":
    main()