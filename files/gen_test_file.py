"""
Generate a test file that is exactly 5 * CHUNK_SIZE bytes.
Each chunk is filled with a recognizable pattern for easy debugging.

Run: python3 gen_test_file.py
Output: random.bin
"""

import hashlib
from config import CHUNK_SIZE

FILENAME = "random.bin"
NUM_CHUNKS = 1024 

chunks = []
for i in range(NUM_CHUNKS):
    # Each chunk: starts with "CHUNK_XX:" then repeating "ABCDE..."
    header = f"CHUNK_{i:02d}:".encode()  # 9 bytes
    fill = (b"ABCDEFGHIJKLMNOPQRSTUVWXYZ" * 40)[:CHUNK_SIZE - len(header)]
    chunk = header + fill
    assert len(chunk) == CHUNK_SIZE
    chunks.append(chunk)

data = b"".join(chunks)
assert len(data) == NUM_CHUNKS * CHUNK_SIZE

with open(FILENAME, "wb") as f:
    f.write(data)

md5 = hashlib.md5(data).hexdigest()
print(f"Generated '{FILENAME}'")
print(f"  Size   : {len(data)} bytes ({NUM_CHUNKS} chunks x {CHUNK_SIZE} bytes)")
print(f"  MD5    : {md5}")
print(f"\nFirst bytes of each chunk:")
for i, chunk in enumerate(chunks):
    print(f"  chunk[{i}]: {chunk[:20]}")