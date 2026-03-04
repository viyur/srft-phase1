"""
SRFT Configuration
"""

DEFAULT_SERVER_PORT = 5000
DEFAULT_CLIENT_PORT = 5001
CHUNK_SIZE = 1024   # Bytes per DATA packet payload
TIMEOUT_SEC = 0.5   # Retransmission timeout
FILES_DIR = "files"
REPORT_FILE = "transfer_report.txt"

SLIDING_WINDOW_SIZE = 64   # 小于包数，可以测试window滑动
ACK_EVERY_N = 1     # 每包都ACK，调试方便
ACK_INTERVAL_SEC = 0.2
RECV_BUFFER_SIZE = 65535

