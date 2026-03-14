"""
SRFT UDP Client - Entry Point

Usage:
    # Real mode (needs sudo, uses SOCK_RAW):
    sudo python3 SRFT_UDPClient.py --server 172.31.41.138 --file test.txt

    # Mock test mode (no sudo needed):
    python3 SRFT_UDPClient.py --server 127.0.0.1 --file test.txt --mock
"""

import argparse
import sys
import os

from receiver import Receiver
from config import DEFAULT_SERVER_PORT, DEFAULT_CLIENT_PORT


def parse_args():
    parser = argparse.ArgumentParser(description="SRFT UDP File Transfer Client")
    parser.add_argument(
        "--server",
        required=True,
        help="Server IP address (e.g. 172.31.41.138)",
    )
    parser.add_argument(
        "--file",
        required=True,
        help="Name of the file to request from server",
    )
    parser.add_argument(
        "--output-dir",
        default=".",
        help="Directory to save the received file (default: current directory)",
    )
    parser.add_argument(
        "--server-port",
        type=int,
        default=DEFAULT_SERVER_PORT,
        help=f"Server port (default: {DEFAULT_SERVER_PORT})",
    )
    parser.add_argument(
        "--client-port",
        type=int,
        default=DEFAULT_CLIENT_PORT,
        help=f"Client port (default: {DEFAULT_CLIENT_PORT})",
    )
    parser.add_argument(
        "--mock",
        action="store_true",
        help="Use plain UDP socket for mock server testing (no sudo needed)",
    )
    # Phase 1 Support: enable REQUEST->DATA->ACK flow (no SYN_ACK/FIN)
    parser.add_argument(
        "--phase1",
        action="store_true",
        help="Phase 1 mode: reliable transfer without SYN_ACK/FIN",
    )
    return parser.parse_args()


def check_root(raw_mode: bool):
    """Warn if raw mode is used without root privileges."""
    if raw_mode and os.geteuid() != 0:
        print("[ERROR] SOCK_RAW requires root privileges.")
        print("        Run with sudo, or use --mock for testing.")
        sys.exit(1)


def main():
    args = parse_args()
    raw_mode = not args.mock

    check_root(raw_mode)

    print("=" * 50)
    print("SRFT UDP Client")
    print(f"  Server     : {args.server}:{args.server_port}")
    print(f"  File       : {args.file}")
    print(f"  Output dir : {args.output_dir}")
    print(f"  Mode       : {'RAW (production)' if raw_mode else 'UDP (mock test)'}")
    print("=" * 50)

    # Phase 1 Support: pass phase1 flag to Receiver for protocol selection
    receiver = Receiver(
        server_ip=args.server,
        output_dir=args.output_dir,
        client_port=args.client_port,
        server_port=args.server_port,
        raw_mode=raw_mode,
        phase1=args.phase1,
    )

    success = receiver.receive(args.file)

    if success:
        output_path = os.path.join(args.output_dir, args.file)
        print(f"\n[DONE] File saved to: {output_path}")
        print(f"[DONE] Duration      : {receiver.stats.elapsed()}")
        print(f"[DONE] Packets recvd : {receiver.stats.packets_received}")
        print(f"[DONE] Duplicates    : {receiver.stats.duplicate_packets}")
        print(f"[DONE] Checksum fail : {receiver.stats.packets_discarded}")
        sys.exit(0)
    else:
        print("\n[FAILED] Transfer failed. Check logs above.")
        sys.exit(1)


if __name__ == "__main__":
    main()