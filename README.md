# SRFT — 简单可靠文件传输协议（Phase 1）

基于原始 UDP socket 构建的应用层可靠文件传输协议，手动构造 IP 与 UDP 头部，并实现了 **Go-Back-N 滑动窗口**机制以在不可靠网络上保障可靠传输。

---

## 协议设计详解

### 数据包结构

每个发送的数据包从底层到应用层依次封装如下：

```
[ IP Header (20 bytes) ] [ UDP Header (8 bytes) ] [ SRFT Header (11 bytes) ] [ Payload ]
```

SRFT Header 格式（共 11 字节）：

```
[ pkt_type (1B) | seq (4B) | ack (4B) | checksum (2B) ]
```

---

### 五种包类型

| 类型 | 值 | 方向 | 说明 |
|---|---|---|---|
| `TYPE_REQUEST` | `0x01` | Client → Server | 客户端请求文件，payload 为文件名 |
| `TYPE_SYN_ACK` | `0x04` | Server → Client | 服务端确认请求，payload 包含文件总大小（4字节） |
| `TYPE_DATA` | `0x02` | Server → Client | 服务端发送文件块，payload 为数据内容 |
| `TYPE_ACK` | `0x03` | Client → Server | 客户端发送累积确认号 |
| `TYPE_FIN` | `0x05` | Server → Client | 服务端通知传输完成，payload 为文件 MD5（16字节） |

---

### 完整传输流程

```
Client                              Server
  |                                   |
  |------- TYPE_REQUEST ------------->|  payload = 文件名（如 "test_800mb_file"）
  |                                   |
  |<------ TYPE_SYN_ACK -------------|  payload = 文件总大小（4字节，网络字节序）server告诉client文件大小
  |                                   |  seq=0, ack=0（控制包，不参与滑动窗口）
  |                                   |
  |<------ TYPE_DATA (seq=0) ---------|
  |<------ TYPE_DATA (seq=1) ---------|
  |<------ TYPE_DATA (seq=2) ---------|  ← Go-Back-N 窗口内连续发送
  |<------ TYPE_DATA (seq=3) ---------|
  |<------ TYPE_DATA (seq=4) ---------|
  |------- TYPE_ACK (ack=5) --------->|  ← client每收到 5 包发一次累积 ACK
  |          ...                      |
  |<------ TYPE_FIN ------------------|  payload = MD5 digest（16字节）Server在FIN里发送文件MD5
  |------- TYPE_ACK ----------------->|  最终确认
```

---

### 关键机制说明

#### 1. Checksum 校验（数据完整性）

每个 SRFT 包发送前，对以下内容计算 16 位校验和：

```
checksum_data = SRFT Header（不含 checksum 字段）+ payload
```

计算方法为**反码求和（one's complement sum）**：将数据按 2 字节分组求和，高位进位回加，最后取反。接收方用同样方法重新计算并与包中存储的值比对，不一致则直接丢弃该包。

IP 头部和 UDP 头部也分别计算了各自的标准 checksum，符合 RFC 791 和 RFC 768 规范。

---

#### 2. Sequence Numbers（序列号 — 检测重复与乱序）

服务端发送的每个 `TYPE_DATA` 包都携带一个从 **0** 开始的递增序列号（`seq=0, 1, 2, ...`），每个序列号对应文件的一个固定大小块（默认 1024 字节）。

客户端维护一个 `expected_seq`，初始值为 **0**：
- 收到的包 `seq == expected_seq`：写入文件，`expected_seq += 1`，正常处理
- 收到的包 `seq != expected_seq`（重复包或乱序包）：**直接丢弃**，并立即重新发送当前的累积 ACK

这是 **Go-Back-N** 的标准接收端行为——客户端通过丢弃乱序或重复包，让服务端无法收到ACK，一旦超时就退回重传整个窗口，这样来确保包的顺序不会混乱。

> `TYPE_SYN_ACK` 和 `TYPE_FIN` 等控制包的 seq 固定为 0，不参与滑动窗口计数而 `ACK` 指的的next expected seq，下一个期望收到的序列号，如果`UDPClient`发的 `ACK`是16，则说明`UDPClient`已经收到了序号为0到15的所有数据包。

---

#### 3. Cumulative ACK（累积确认号 — 避免逐包 ACK）

客户端发送的 `TYPE_ACK` 包中，`ack` 字段的值表示**下一个期望收到的序列号**，即服务端可以认为 `seq < ack` 的所有包均已被正确接收。

为了避免每收到一个包就发一次 ACK（会产生大量小包），客户端采用**延迟 ACK 策略**，满足以下任一条件时才发送 ACK：

| 触发条件 | 配置参数 | 默认值 |
|---|---|---|
| 累计收到 N 个包 | `ACK_EVERY_N` | 5 |
| 距离上次 ACK 超过一定时间 | `ACK_INTERVAL_SEC` | 0.02 秒 |
| 已收到最后一个数据包 | — | 自动触发 |
| 收到乱序/重复包 | — | 立即触发（负反馈） |

---

#### 4. Retransmission due to Timeout（超时重传）

服务端使用 Go-Back-N 窗口管理发送缓冲区：

- 每次发送 `base`（最旧未确认包）时，启动一个计时器，超时时间为 `TIMEOUT_SEC`（默认 0.005 秒）
- 若在超时前收到 ACK，则滑动窗口，为新的 `base` 重启计时器
- 若超时仍未收到 ACK，则**重传 `[base, next_seq)` 范围内所有未确认包**，并重启计时器

> **为什么 timeout 设为 0.005 秒（5ms）？**
> 在 4% 丢包条件下的实测中，使用 `timeout=0.03s` 和 `window=16` 传输 1GB 文件耗时长达 26 分钟。分析发现约 43,700 次超时事件 × 30ms = 1,311 秒（占总时长 83%）纯粹是在等待超时，真正传输数据的时间不足 20%。EC2 同区域 RTT ≈ 1ms，将 timeout 缩短至 5ms（RTT 的 5 倍）可在保证 ACK 可靠到达的前提下，将超时等待总时长从 1,311 秒降至约 219 秒，大幅提升传输效率。

---

## ⚠️ 平台限制 — macOS 不支持

> **macOS 对原始 socket 有严格限制，`IP_HDRINCL` 无法正常工作。**
>
> 在 macOS 上手动构造 IP + UDP 头部的数据包无法正确发送和接收，程序会报错或静默失败。

**必须在以下环境测试：**
- ✅ **Linux EC2 实例**（推荐，见下方测试结果）
- ✅ **Linux 虚拟机**（VirtualBox、VMware、UTM 等）
- ❌ macOS — 不支持 raw socket 模式

---

## 快速开始

### 最快方式（使用默认参数）

**服务端：**
```bash
sudo python3.11 UDPServer.py
```

**客户端：**
```bash
sudo python3.11 UDPClient.py --server-ip <EC2_SERVER_IP> --filename test_1gb_file

```

> 使用默认参数时，服务端监听 `0.0.0.0:5000`，文件目录为 `files/`。  
> 如需测试较小的文件，可将 `--filename test_1gb_file` 换成 `--filename test_10mb_file`，传输速度更快，便于调试。

---

### 完整参数说明

**服务端所有可用参数：**
```bash
sudo python3.11 UDPServer.py \
  --bind-ip <SERVER_IP>   # 服务端绑定 IP，默认 0.0.0.0（自动检测）
  --port 5000             # 监听端口，默认 5000
  --dir files             # 提供文件的目录，默认 files/
  --chunk 1024            # 每个 DATA 包的 payload 大小（字节），默认 1024
  --timeout 0.005         # 重传超时时间（秒），默认 0.005
  --window 16             # Go-Back-N 窗口大小，默认 16
  --loss 4                # 丢包率（%），自动配置 tc netem，支持 0/2/3/4，默认 0
  --mock                  # 本地测试模式，不使用 raw socket（无需 sudo）
```

**客户端所有可用参数：**
```bash
sudo python3.11 UDPClient.py \
  --server-ip <SERVER_IP>   # 服务端 IP 地址（必填）
  --server-port 5000        # 服务端端口，默认 5000
  --client-port 5001        # 客户端源端口，默认 5001
  --filename test_1gb_file  # 要请求的文件名（必填）
  --out-dir received        # 接收文件保存目录，默认 received/
```

> **注意：raw socket 模式下必须使用 `sudo python3.11` 运行，否则会因权限不足而报错。**

---

## 在 EC2 上运行（双机模式）

### 前提条件
- 两台 EC2 Linux 实例，项目文件均位于 `~/srft-phase1/`
- 安全组开放两台机器之间 UDP 5000、5001 端口
- 已安装 Python 3.11

### 操作步骤

**Terminal 1 — 登录服务端，启动服务：**
```bash
ssh -i srft-keypair.pem ec2-user@<SERVER_EC2_IP>
cd ~/srft-phase1
sudo python3.11 UDPServer.py --timeout 0.005 --window 16 --loss 4
```

> `--loss` 参数会在启动时自动配置 `tc netem` 丢包规则，并在 server report 中记录。支持 `0`、`2`、`3`、`4` 四种丢包率。

**Terminal 2 — 登录客户端，发起请求：**
```bash
ssh -i srft-keypair.pem ec2-user@<CLIENT_EC2_IP>
cd ~/srft-phase1
sudo python3.11 UDPClient.py --server-ip <SERVER_EC2_IP> --filename test_800mb_file
```

---



## EC2 丢包模拟配置（`--loss` 参数）

server 通过 `--loss` 参数在启动时自动配置 `tc netem` 丢包规则，**无需手动执行 `tc` 命令**。支持以下四种丢包率：

| 命令 | 丢包率 | 实际执行的 tc 规则 |
|---|---|---|
| `--loss 0` | 0%（无丢包） | 清除已有 tc 规则 |
| `--loss 2` | 2% | `tc qdisc add dev ens5 root netem loss 2%` |
| `--loss 3` | 3% | `tc qdisc add dev ens5 root netem loss 3%` |
| `--loss 4` | 4% | `tc qdisc add dev ens5 root netem loss 4%` |

启动时如果 `ens5` 上已有旧的 tc 规则，会自动先删除再添加新规则。丢包率会记录在 server report 中，便于对比不同丢包条件下的传输结果。

```bash
# 查看当前 tc 规则（手动确认用）
tc qdisc show dev ens5

# 手动清除（通常不需要，--loss 0 会自动处理）
sudo tc qdisc del dev ens5 root
```

---

## EC2 实测结果 —  1GB 文件传输

以下为两台 EC2 实例之间在 **模拟丢包**条件下传输 1GB 文件的实测数据：

### 服务端报告
```
Name of the transferred file: test_1gb_file
Size of the transferred file: 1073741824
The number of packets sent from the server: 1131666
The number of retransmitted packets from the server: 83088
The number of packets received from the client: 289198
The time duration of the file transfer (hh:min:ss): 00:05:57
Report saved to transfer_report.txt
```

### 客户端输出
```
[ACK] sent cumulative ACK=1048576
[FIN] received from server
[SUCCESS] MD5 verified. Transfer complete.
[CLIENT] duration: 371 seconds
[CLIENT] transfer succeeded
```

### 数据分析

指标,计算过程,数值,评价
有效吞吐量,1024 MB÷357 s,~2.87 MB/s,较前次略有下降，受重传影响明显
重传率,"83,088÷1,131,666",~7.34%,显著上升，网络环境存在明显丢包或拥塞
ACK 比例,"289,198:1,131,666",约 1 : 3.9,接近每 4 包一回执，符合高效确认机制
文件完整性,"基于 1,073,741,824 字节",100% 完整,传输虽然波动，但重传机制确保了数据可靠性

---

## 配置参数（`config.py`）

| 参数 | 默认值 | 说明 |
|---|---|---|
| `DEFAULT_SERVER_PORT` | `5000` | 服务端监听端口 |
| `DEFAULT_CLIENT_PORT` | `5001` | 客户端源端口 |
| `CHUNK_SIZE` | `1024` 字节 | 每个 DATA 包的数据大小 |
| `TIMEOUT_SEC` | `0.005` 秒 | 重传超时时间 |
| `SLIDING_WINDOW_SIZE` | `16` | Go-Back-N 窗口大小 |
| `ACK_EVERY_N` | `5` | 每收到 N 包发一次 ACK |
| `ACK_INTERVAL_SEC` | `0.02` 秒 | ACK 最大发送间隔 |
| `FILES_DIR` | `files/` | 服务端文件目录 |
| `REPORT_FILE` | `transfer_report.txt` | 服务端报告保存路径 |

---

## Lessons Learned from AI

### Lesson 1 — Sliding Window / Go-Back-N

Initially, our implementation sent one packet and waited for the client to ACK it before sending the next — essentially stop-and-wait. Through discussion with AI, we learned about the **sliding window** concept and adopted the **Go-Back-N** algorithm, which allows the server to keep up to `WINDOW_SIZE` unacknowledged packets in flight simultaneously. This fundamentally improved throughput by decoupling sending from waiting for individual ACKs.

---

### Lesson 2 — Delayed ACK Needs More Than Just a Counter

Our first approach to avoiding per-packet ACKs was a simple counter: send an ACK every N packets (`ACK_EVERY_N = 5`). During testing, we noticed the transfer was unexpectedly slow and occasionally incorrect. While debugging with AI, we identified two missing cases:

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

## 参考资料

- [RFC 791 — Internet Protocol (IP)](https://www.rfc-editor.org/rfc/rfc791)
- [RFC 768 — User Datagram Protocol (UDP)](https://www.rfc-editor.org/rfc/rfc768)
- [Python `hashlib` 文档](https://docs.python.org/3/library/hashlib.html)
- [Python `struct` 文档](https://docs.python.org/3/library/struct.html)
- [Linux `tc` / `netem` 文档](https://man7.org/linux/man-pages/man8/tc-netem.8.html)
