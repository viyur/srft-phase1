"""
SRFT Configuration
"""

DEFAULT_SERVER_PORT = 5000
DEFAULT_CLIENT_PORT = 5001
CHUNK_SIZE = 1024   # Bytes per DATA packet payload
TIMEOUT_SEC = 0.005  # Retransmission timeout
FILES_DIR = "files"
REPORT_FILE = "transfer_report.txt"

SLIDING_WINDOW_SIZE = 16   # 小于包数，可以测试window滑动
ACK_EVERY_N = 5     # client每收到5个包，就给server发一个ACK
ACK_INTERVAL_SEC = 0.02
RECV_BUFFER_SIZE = 65535

