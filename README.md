# SRFT — Secure Reliable File Transfer Protocol (Phase 1)

An application-layer reliable file transfer protocol built on raw UDP sockets, with manually constructed IP and UDP headers, implementing a **Go-Back-N sliding window** mechanism to ensure reliable delivery over unreliable networks.

---

## 1. Protocol Design

### 1.1 Packet Structure

Each transmitted packet is encapsulated from the network layer up as follows:

```
[ IP Header (20 bytes) ] [ UDP Header (8 bytes) ] [ SRFT Header (11 bytes) ] [ Payload ]
```

SRFT Header format (11 bytes total):

```
[ pkt_type (1B) | seq (4B) | ack (4B) | checksum (2B) ]
```

---

### 1.2 Five Packet Types

| Type | Value | Direction | Description |
|---|---|---|---|
| `TYPE_REQUEST` | `0x01` | Client → Server | Client requests a file; payload is the filename |
| `TYPE_SYN_ACK` | `0x04` | Server → Client | Server confirms the request; payload contains file size (4 bytes) |
| `TYPE_DATA` | `0x02` | Server → Client | Server sends a file chunk; payload is the data |
| `TYPE_ACK` | `0x03` | Client → Server | Client sends a cumulative acknowledgement |
| `TYPE_FIN` | `0x05` | Server → Client | Server signals transfer complete; payload is the file MD5 (16 bytes) |

---

### 1.3 Transfer Flow

```
Client                              Server
  |                                   |
  |------- TYPE_REQUEST ------------->|  payload = filename (e.g. "test_1gb_file")
  |                                   |
  |<------ TYPE_SYN_ACK -------------|  payload = file size (4 bytes, network byte order)
  |                                   |  seq=0, ack=0 (control packet, not in sliding window)
  |                                   |
  |<------ TYPE_DATA (seq=0) ---------|
  |<------ TYPE_DATA (seq=1) ---------|
  |<------ TYPE_DATA (seq=2) ---------|  ← continuous send within Go-Back-N window
  |<------ TYPE_DATA (seq=3) ---------|
  |<------ TYPE_DATA (seq=4) ---------|
  |------- TYPE_ACK (ack=5) --------->|  ← client sends cumulative ACK every 5 packets
  |          ...                      |
  |<------ TYPE_FIN ------------------|  payload = MD5 digest (16 bytes)
  |------- TYPE_ACK ----------------->|  final acknowledgement
```

---

### 1.4 Key Mechanisms

#### 1.4.1 Checksum

Before sending each SRFT packet, a 16-bit checksum is computed over:

```
checksum_data = SRFT Header (excluding checksum field) + payload
```

The method is **one's complement sum**: data is split into 2-byte groups, summed with carry wraparound, and the result is bitwise inverted. The receiver recomputes the checksum and discards any packet where the values do not match. IP and UDP headers also carry their respective standard checksums per RFC 791 and RFC 768.

---

#### 1.4.2 Sequence Numbers

Each `TYPE_DATA` packet carries a monotonically increasing sequence number starting at **0** (`seq=0, 1, 2, ...`), where each number corresponds to a fixed-size chunk of the file (default 1024 bytes).

The client maintains `expected_seq`, initialised to **0**:
- `seq == expected_seq`: write payload to file, increment `expected_seq`, process normally
- `seq != expected_seq` (duplicate or out-of-order): **discard immediately** and resend the current cumulative ACK

This is standard Go-Back-N receiver behaviour. By discarding out-of-order packets, the client withholds the ACK the server needs; the server's timer then fires and the entire window is retransmitted in order.

> The `ack` field means *next expected sequence number*. An `ACK=16` from the client means all packets with seq 0–15 have been received correctly.

---

#### 1.4.3 Cumulative ACK

The `ack` field in each `TYPE_ACK` packet is the next sequence number the client expects. To avoid sending one ACK per packet, the client uses a **delayed ACK strategy** and only sends an ACK when any of the following conditions is met:

| Trigger | Parameter | Default |
|---|---|---|
| N packets received since last ACK | `ACK_EVERY_N` | 5 |
| Time since last ACK exceeds threshold | `ACK_INTERVAL_SEC` | 0.02 s |
| Last data packet received | — | automatic |
| Out-of-order or duplicate packet received | — | immediate (negative feedback) |

---

#### 1.4.4 Retransmission due to Timeout

The server manages the send buffer using a Go-Back-N window:

- When `base` (the oldest unacknowledged packet) is sent, a timer is started with duration `TIMEOUT_SEC` (default 0.005 s)
- If an ACK is received before timeout, the window slides forward and the timer is restarted for the new `base`
- If no ACK arrives before timeout, **all packets in `[base, next_seq)` are retransmitted** and the timer is restarted

> **Why 0.005 s (5 ms)?**
> Under 4% packet loss with `timeout=0.03s` and `window=16`, a 1 GB transfer took 26 minutes. Analysis showed approximately 43,700 timeout events × 30 ms = 1,311 s — **83% of total transfer time was pure timeout stall**, with less than 20% spent actually transmitting data. EC2 intra-region RTT ≈ 1 ms; setting timeout to 5 ms (5× RTT) is sufficient for ACKs to arrive reliably, cutting total timeout stall from ~1,311 s to ~219 s and reducing transfer time to approximately 6–7 minutes.

---

## 2. Platform Requirements

> **macOS restricts raw sockets strictly — `IP_HDRINCL` does not work correctly on macOS.**

**Must run on:**
- ✅ **Linux EC2 instance** (recommended — see test results below)
- ✅ **Linux VM** (VirtualBox, VMware, UTM, etc.)
- ❌ macOS — raw socket mode not supported

---

## 3. Running on EC2

Because the program uses `SOCK_RAW` and `IP_HDRINCL`, it **can only run on Linux (AWS EC2)**. macOS is not supported.

### 3.1 Prerequisites
- Two EC2 Linux instances with the project files at `~/srft-phase1/`
- Security group allows UDP traffic on ports 5000 and 5001 between the two instances
- Python 3.11 installed

### 3.2 Quick Start

**Terminal 1 — SSH into the server instance:**
```bash
ssh -i srft-keypair.pem ec2-user@<SERVER_EC2_IP>
cd ~/srft-phase1
sudo python3.11 UDPServer.py --timeout 0.005 --window 16 --loss 4
```

**Terminal 2 — SSH into the client instance:**
```bash
ssh -i srft-keypair.pem ec2-user@<CLIENT_EC2_IP>
cd ~/srft-phase1
sudo python3.11 UDPClient.py --server-ip <SERVER_EC2_IP> --filename test_1gb_file
```

> By default, the server listens on `0.0.0.0:5000` and serves files from the `files/` directory. The `--loss` flag automatically configures `tc netem` on startup; supported values are `0`, `2`, `3`, and `4`.

### 3.3 Full Parameter Reference

**Server parameters:**
```bash
sudo python3.11 UDPServer.py \
  --bind-ip <SERVER_IP>   # IP to bind (default: 0.0.0.0, auto-detected)
  --port 5000             # listening port (default: 5000)
  --dir files             # directory of files to serve (default: files/)
  --chunk 1024            # DATA packet payload size in bytes (default: 1024)
  --timeout 0.005         # retransmission timeout in seconds (default: 0.005)
  --window 16             # Go-Back-N window size (default: 16)
  --loss 4                # packet loss % to apply via tc netem; 0/2/3/4 (default: 0)
  --mock                  # local test mode using plain UDP, no sudo required
```

**Client parameters:**
```bash
sudo python3.11 UDPClient.py \
  --server-ip <SERVER_IP>   # server IP address (required)
  --server-port 5000        # server port (default: 5000)
  --client-port 5001        # client source port (default: 5001)
  --filename test_1gb_file  # filename to request from server (required)
  --out-dir received        # local directory to save the received file (default: received/)
```

> **Note: raw socket mode requires `sudo python3.11`. Running without sudo will fail due to insufficient permissions.**

---

## 4. Packet Loss Configuration

The server automatically configures `tc netem` packet loss rules on startup via the `--loss` flag — **no manual `tc` commands needed**. Complete commands for each loss rate:

```bash
# 0% — no packet loss (clears any existing tc rule)
sudo python3.11 UDPServer.py --timeout 0.005 --window 16 --loss 0

# 2% packet loss
sudo python3.11 UDPServer.py --timeout 0.005 --window 16 --loss 2

# 3% packet loss
sudo python3.11 UDPServer.py --timeout 0.005 --window 16 --loss 3

# 4% packet loss
sudo python3.11 UDPServer.py --timeout 0.005 --window 16 --loss 4
```

Client command (unchanged across all loss rates):
```bash
sudo python3.11 UDPClient.py --server-ip <SERVER_EC2_IP> --filename <filename>
```

| Flag | Loss Rate | tc rule applied |
|---|---|---|
| `--loss 0` | 0% (no loss) | existing rule cleared |
| `--loss 2` | 2% | `tc qdisc add dev ens5 root netem loss 2%` |
| `--loss 3` | 3% | `tc qdisc add dev ens5 root netem loss 3%` |
| `--loss 4` | 4% | `tc qdisc add dev ens5 root netem loss 4%` |

Any existing tc rule on `ens5` is automatically deleted before the new rule is applied. The loss rate is recorded in the server report for easy comparison across test runs.

```bash
# Verify current tc rule manually
tc qdisc show dev ens5
```

---

## 5. Test Results & Performance Analysis

All tests run between two AWS EC2 Linux instances in the same region (RTT ≈ 1 ms). Integrity verified via MD5 checksum on every transfer.

**Server command:**
```bash
sudo python3.11 UDPServer.py --timeout 0.005 --window 16 --loss <0|2|3|4>
```

**Client command:**
```bash
sudo python3.11 UDPClient.py --server-ip 172.31.41.138 --filename <filename>
```

> Example: `sudo python3.11 UDPClient.py --server-ip 172.31.41.138 --filename test_1gb_file`

### 5.1 Performance Summary Table

| File | Size | Loss 0% | Loss 2% | Loss 3% | Loss 4% |
|---|---|---|---|---|---|
| test_10mb_file | 10 MB | 1s | 4s | 3s | 4s |
| test_100mb_file | 100 MB | 17s | 32s | 38s | 44s |
| test_500mb_file | 500 MB | 94s | 164s | 200s | 237s |
| test_800mb_file | 800 MB | 183s | 295s | 352s | 407s |
| test_1gb_file | 1 GB | 202s | 341s | 412s | 484s |

*All transfers passed MD5 verification — file integrity 100%.*

> For Phase 2 secure transfer test results (PSK + AEAD, 0% packet loss), refer to the Phase 2 README.

---

### 5.2 Detailed Test Results

#### Loss 0%

| File | Packets Sent | Retransmitted | ACKs Received | Duration (server) | Duration (client) |
|---|---|---|---|---|---|
| test_10mb_file | 10,242 | 0 | 2,049 | 00:00:01 | 1s |
| test_100mb_file | 102,402 | 0 | 20,481 | 00:00:17 | 18s |
| test_500mb_file | 513,682 | 1,680 | 103,530 | 00:01:30 | 94s |
| test_800mb_file | 825,986 | 6,784 | 169,997 | 00:02:52 | 183s |
| test_1gb_file | 1,057,650 | 9,072 | 215,359 | 00:03:07 | 202s |

#### Loss 2%

| File | Packets Sent | Retransmitted | ACKs Received | Duration (server) | Duration (client) |
|---|---|---|---|---|---|
| test_10mb_file | 15,890 | 5,648 | 6,543 | 00:00:04 | 4s |
| test_100mb_file | 137,168 | 34,766 | 52,025 | 00:00:32 | 32s |
| test_500mb_file | 683,122 | 171,120 | 259,507 | 00:02:40 | 164s |
| test_800mb_file | 1,098,754 | 279,552 | 417,780 | 00:04:44 | 295s |
| test_1gb_file | 1,398,226 | 349,648 | 529,084 | 00:05:27 | 341s |

#### Loss 3%

| File | Packets Sent | Retransmitted | ACKs Received | Duration (server) | Duration (client) |
|---|---|---|---|---|---|
| test_10mb_file | 15,287 | 5,045 | 6,658 | 00:00:03 | 3s |
| test_100mb_file | 153,298 | 50,896 | 66,734 | 00:00:38 | 38s |
| test_500mb_file | 772,162 | 260,160 | 338,170 | 00:03:17 | 200s |
| test_800mb_file | 1,239,074 | 419,872 | 542,748 | 00:05:41 | 352s |
| test_1gb_file | 1,576,850 | 528,272 | 687,663 | 00:06:37 | 412s |

#### Loss 4%

| File | Packets Sent | Retransmitted | ACKs Received | Duration (server) | Duration (client) |
|---|---|---|---|---|---|
| test_10mb_file | 16,521 | 6,279 | 7,677 | 00:00:04 | 4s |
| test_100mb_file | 169,970 | 67,568 | 81,361 | 00:00:44 | 45s |
| test_500mb_file | 866,050 | 354,048 | 416,938 | 00:03:53 | 237s |
| test_800mb_file | 1,381,250 | 562,048 | 667,677 | 00:06:36 | 407s |
| test_1gb_file | 1,761,755 | 713,177 | 846,582 | 00:07:51 | 484s |

---

### 5.3 Performance Analysis

#### 5.3.1 Throughput

Using the 1 GB file as a reference (server-side timing):

| Loss Rate | Transfer Duration | Effective Throughput |
|---|---|---|
| 0% | 187s | ~5.47 MB/s |
| 2% | 327s | ~3.13 MB/s |
| 3% | 397s | ~2.58 MB/s |
| 4% | 471s | ~2.17 MB/s |

Throughput is highest with no packet loss and degrades as loss increases due to retransmission overhead. Even at 4% loss, throughput remains above 2 MB/s.

#### 5.3.2 Retransmission Rate

Using the 1 GB file as a reference:

| Loss Rate | Retransmitted Packets | Retransmission Rate |
|---|---|---|
| 0% | 9,072 | 0.86% |
| 2% | 349,648 | 25.0% |
| 3% | 528,272 | 33.5% |
| 4% | 713,177 | 40.5% |

The small number of retransmissions at 0% loss (0.86%) reflects minor network jitter in the EC2 environment, not tc-configured loss. Go-Back-N's window retransmission behaviour causes the retransmission rate to far exceed the actual loss rate — a single lost packet triggers retransmission of the entire window.

#### 5.3.3 ACK_EVERY_N Behaviour

The effect of `ACK_EVERY_N = 5` is precisely verified by the ACK ratio at 0% packet loss:

| File | Original Packets | ACKs Received | Ratio (pkts/ACK) |
|---|---|---|---|
| test_10mb_file | 10,240 | 2,049 | **5.00** |
| test_100mb_file | 102,400 | 20,481 | **5.00** |
| test_1gb_file | 1,048,576 | 215,359 | **4.87 ≈ 5** |

At 0% loss, exactly 5 data packets correspond to 1 ACK, perfectly confirming the count-based trigger of `ACK_EVERY_N=5`.

Under packet loss, the ratio drops significantly (e.g. to ~2.0 at 2% loss with the 1 GB file) because out-of-order packets trigger immediate ACKs (negative feedback), and retransmitted packets also generate additional ACK responses. This demonstrates the three delayed-ACK triggers — count, interval timer, and immediate-on-out-of-order — working together to automatically increase feedback frequency under loss and accelerate retransmission.

---

## 6. Configuration Parameters

| Parameter | Default | Description |
|---|---|---|
| `DEFAULT_SERVER_PORT` | `5000` | Server listening port |
| `DEFAULT_CLIENT_PORT` | `5001` | Client source port |
| `CHUNK_SIZE` | `1024` bytes | DATA packet payload size |
| `TIMEOUT_SEC` | `0.005` s | Retransmission timeout |
| `SLIDING_WINDOW_SIZE` | `16` | Go-Back-N window size |
| `ACK_EVERY_N` | `5` | Send ACK every N received packets |
| `ACK_INTERVAL_SEC` | `0.02` s | Maximum interval between ACKs |
| `FILES_DIR` | `files/` | Server file directory |
| `REPORT_FILE` | `transfer_report.txt` | Server report output path |

---

## 7. Lessons Learned from AI

### Lesson 1 — Sliding Window / Go-Back-N

Initially, our implementation sent one packet and waited for the client to ACK it before sending the next — essentially stop-and-wait. Through discussion with AI, we learned about the **sliding window** concept and adopted the **Go-Back-N** algorithm, which allows the server to keep up to `WINDOW_SIZE` unacknowledged packets in flight simultaneously. This fundamentally improved throughput by decoupling sending from waiting for individual ACKs.

---

### Lesson 2 — Delayed ACK Needs More Than Just a Counter

Our first approach to avoiding per-packet ACKs was a simple counter: send an ACK every N packets (`ACK_EVERY_N = 5`). During testing, we noticed the transfer was unexpectedly slow and occasionally incorrect. While debugging with AI, we identified three missing cases:

1. **Time-based trigger**: if packets arrive slowly or the window stalls, the counter may never reach N. A secondary `ACK_INTERVAL_SEC` timer ensures an ACK is sent periodically regardless of packet count.
2. **Immediate ACK on out-of-order / duplicate packets**: when the client receives a packet with an unexpected sequence number, it must ACK immediately (negative feedback to the server) rather than waiting for the counter or timer.
3. **Immediate ACK on FIN**: the final FIN packet must also bypass the counter and trigger an ACK right away to complete the transfer cleanly.

Adding these three cases resolved the slow transfer and correctness issues.

---

### Lesson 3 — Reducing Window Size Does Not Fix Timeout Bottleneck

After observing that a 1 GB file transfer took **26 minutes** under 4% packet loss (with `timeout=0.03s`, `window=16`), our intuition was to reduce the window size to limit retransmissions. We tested `window=8` — retransmissions halved, but the transfer still took **26 minutes**.

AI helped us see why: with ~43,700 timeout events each stalling for 30 ms, roughly **83% of total transfer time was pure timeout waiting**, not data transmission. Changing window size only changes how many packets are retransmitted per timeout event — it does not reduce the number of timeout events themselves.

The correct fix was to reduce `TIMEOUT_SEC` directly. Since EC2 intra-region RTT ≈ 1 ms, a timeout of **0.005 s** (5× RTT) is sufficient for ACKs to arrive reliably while cutting the total timeout stall from ~1,311 s down to ~219 s — reducing the expected transfer time from 26 minutes to approximately 6–7 minutes.

---

## 8. References

- [RFC 791 — Internet Protocol (IP)](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 768 — User Datagram Protocol (UDP)](https://www.rfc-editor.org/rfc/rfc768)
- [Python `hashlib` documentation](https://docs.python.org/3/library/hashlib.html)
- [Python `struct` documentation](https://docs.python.org/3/library/struct.html)
- [Linux `tc` / `netem` documentation](https://man7.org/linux/man-pages/man8/tc-netem.8.html)
