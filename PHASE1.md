# Phase 1 实现说明与测试指南

本文档详细说明 Phase 1 的实现内容、协议要求以及如何测试运行。

---

## 〇、作业要求符合性检查

| 要求 | 状态 | 实现位置 |
|------|------|----------|
| **Checksum**（无 pseudo header，检测损坏包） | ✅ 已实现 | `protocol.py`：`compute_checksum`、`verify_checksum`；`parse_srft_packet` 校验失败返回 None |
| **Sequence Numbers**（检测重复与乱序） | ✅ 已实现 | `receiver.py`：`received` 字典按 seq 去重；按 seq 排序重组 |
| **Cumulative ACK**（避免每包一 ACK） | ✅ 已实现 | `receiver.py`：发送 `highest_consec`，仅在新最高连续 seq 时发送 |
| **Retransmission due to timeout**（固定超时） | ✅ 已实现 | `mock_server.py` Phase1Sender、`config.TIMEOUT_SEC` |
| **Server 输出报告文件** | — | Server 非作业范围；mock_server 仅用于测试，不生成报告文件 |

---

## 一、Phase 1 协议要求

Phase 1 采用简化的可靠传输协议，**不包含 SYN_ACK/FIN 握手**，适合在 macOS 本地测试（无需 sudo）。

### 1.1 协议流程

```
Client                              Server
   |                                    |
   |  ---- REQUEST (filename) --------> |
   |                                    |
   |  <---- DATA (seq=1, file_size+chunk0) -- |
   |  <---- DATA (seq=2, chunk1) ------- |
   |  <---- DATA (seq=3, chunk2) ------- |
   |  ...                                |
   |                                    |
   |  ---- ACK (cumulative) ----------> |
   |  ---- ACK (cumulative) ----------> |
   |  ...                                |
   |                                    |
   [传输完成，无 FIN]
```

### 1.2 关键规范

| 项目 | 说明 |
|------|------|
| **REQUEST** | 客户端发送，payload 为文件名（UTF-8 编码） |
| **DATA seq** | 从 1 开始递增（base_seq=1） |
| **第一个 DATA** | payload = `file_size(4B big-endian)` + `chunk0` |
| **后续 DATA** | payload = 对应 chunk 数据 |
| **ACK** | 累积确认，ack 表示已收到 seq 1..ack 的所有包 |
| **无 SYN_ACK/FIN** | 不进行握手与结束信号，直接 REQUEST→DATA→ACK |

### 1.3 数据格式

- **第一个 DATA 包 (seq=1)**：`struct.pack("!I", file_size)` + `chunks[0]`
- **后续 DATA 包 (seq≥2)**：仅包含对应 chunk 的原始数据
- **CHUNK_SIZE**：1024 字节（来自 `config.py`）

---

## 二、今日添加/修改的内容

### 2.1 核心修复

#### ① TimeoutError 处理（`receiver.py`）

**问题**：`recv_loop` 中 `recvfrom()` 超时时抛出 `TimeoutError`，导致接收线程崩溃，后续无法再接收数据。

**修复**：在 `recv_loop` 中捕获 `TimeoutError` 和 `socket.timeout`，超时时继续循环而非退出：

```python
try:
    result = self._recv_srft_packet()
except (TimeoutError, socket.timeout):
    # 超时后继续等待，不退出线程
    ...
    continue
```

#### ② REQUEST 自动重传（`receiver.py`）

**问题**：若先启动 client、后启动 server，首次 REQUEST 会丢失，client 一直等待。

**修复**：在未收到任何 DATA 时，每 2 秒重发一次 REQUEST：

```python
if len(received) == 0 and time.time() - last_request_time[0] > 2.0:
    self._send_request(filename)
    last_request_time[0] = time.time()
    print("[RETRY] Resent REQUEST (is mock server running?)")
```

#### ③ Phase 1 统计修复（`receiver.py`）

**问题**：Phase 1 未正确更新 `stats`，导致 Duration 异常、Packets recvd 为 0。

**修复**：
- 在 Phase 1 开始时设置 `self.stats.start_time`
- 收到新包时增加 `self.stats.packets_received`
- 收到重复包时增加 `self.stats.duplicate_packets`

### 2.2 体验优化

- **移除调试输出**：删除 `[DEBUG] About to call recvfrom...` 等频繁打印
- **启动提示**：在 `UDPClient.py` 中，当使用 `--mock --phase1` 时，提示需先启动 mock server

---

## 三、涉及的文件与改动

### 3.1 Phase 1 整体改动

| 文件 | 改动 |
|------|------|
| `receiver.py` | 新增 Phase 1 逻辑（`_receive_phase1`）、macOS 兼容 |
| `UDPClient.py` | 新增 `--phase1` 参数 |
| `client.py` | 新增 `--phase1` 参数 |
| `mock_server.py` | 新增 Phase 1 支持（`Phase1Sender`、`--phase1`） |

### 3.2 今日补充修复（调试与健壮性）

| 文件 | 改动 |
|------|------|
| `receiver.py` | TimeoutError 处理、REQUEST 自动重传、stats 更新、移除调试输出 |
| `UDPClient.py` | 启动时 Phase 1 提示（需先启动 mock server） |

---

## 四、如何测试运行

### 4.1 环境要求

- Python 3.x
- 项目根目录：`/Users/joshliu/26Spring/5700/Final`（或你的项目路径）

### 4.2 测试文件

确保存在 `files/test.txt`：

```bash
ls files/test.txt
# 示例内容: "Hello World!"
```

### 4.3 启动顺序

**方式 A：先启动 Server（推荐）**

```bash
# 终端 1 - 启动 Mock Server
cd /Users/joshliu/26Spring/5700/Final
python3 mock_server.py --scenario normal --file files/test.txt --phase1
```

等待输出 `[MOCK SERVER] Waiting for REQUEST...` 后：

```bash
# 终端 2 - 启动 Client
cd /Users/joshliu/26Spring/5700/Final
python3 UDPClient.py --server 127.0.0.1 --file test.txt --output-dir received --mock --phase1
```

**方式 B：先启动 Client**

```bash
# 终端 1 - 先启动 Client（会每 2 秒重发 REQUEST）
python3 UDPClient.py --server 127.0.0.1 --file test.txt --output-dir received --mock --phase1

# 终端 2 - 再启动 Server
python3 mock_server.py --scenario normal --file files/test.txt --phase1
```

### 4.4 预期输出

**Client 成功时：**

```
==================================================
SRFT UDP Client
  Server     : 127.0.0.1:5000
  File       : test.txt
  Output dir : received
  Mode       : UDP (mock test)
  [Phase 1]  Ensure mock server is running first:
            python3 mock_server.py --scenario normal --file files/test.txt --phase1
==================================================
[REQUEST] Sent request for 'test.txt'

[DONE] File saved to: received/test.txt
[DONE] Duration      : 00:00:00
[DONE] Packets recvd : 1
[DONE] Duplicates    : 0
[DONE] Checksum fail : 0
```

**Server 成功时：**

```
[MOCK SERVER] Listening on port 5000, scenario='normal', file='files/test.txt', mode=Phase 1, loss=0%
[MOCK SERVER] 14 bytes, 1 chunks, MD5=...

[MOCK SERVER] Waiting for REQUEST...
[MOCK SERVER] REQUEST for 'test.txt' from ('127.0.0.1', 5001)
[PHASE1 SENDER] Done. last_ack=1/1, sent=1, retrans=0
[MOCK SERVER] Phase 1 transfer done.
```

### 4.5 验证结果

```bash
# 对比源文件与接收文件
cat files/test.txt
cat received/test.txt
# 内容应完全一致，例如: "Hello World!"
```

### 4.6 使用其他测试文件

```bash
# 生成随机测试文件（5 个 chunk）
python3 files/gen_test_file.py

# Server
python3 mock_server.py --scenario normal --file files/random.bin --phase1

# Client
python3 UDPClient.py --server 127.0.0.1 --file random.bin --output-dir received --mock --phase1
```

---

## 五、端口与配置

| 配置项 | 默认值 | 说明 |
|--------|--------|------|
| Server 端口 | 5000 | `config.DEFAULT_SERVER_PORT` |
| Client 端口 | 5001 | `config.DEFAULT_CLIENT_PORT` |
| CHUNK_SIZE | 1024 | 每个 DATA 包 payload 最大字节数 |
| TIMEOUT_SEC | 0.5 | 重传超时时间 |

---

## 六、常见问题

**Q: 客户端一直停在 `[REQUEST] Sent request...`？**  
A: 确认 mock server 已启动；若先启动 client，会每 2 秒自动重发 REQUEST。

**Q: `Address already in use`？**  
A: 端口被占用，可执行 `lsof -i :5000 -i :5001` 查看并结束旧进程。

**Q: 收到的文件为空或错误？**  
A: 检查 server 的 `--file` 与 client 的 `--file` 是否对应同一文件（client 的 `--file` 为请求的文件名，server 实际发送的是 `--file` 指定的文件内容）。
