

## 🏗 Client 相关的

项目采用了分层设计，将底层网络交互与上层重组逻辑分离：

* **`receiver.py` (逻辑层/Logic Layer)**: 核心业务逻辑。负责维护接收窗口、处理数据包重组、检测缺失分片（Loss Detection）以及计算最终文件的校验和。
* **`UDPClient.py` (接口层/Interface Layer)**: 程序的入口。负责解析命令行参数、初始化网络连接，并将底层的 UDP 数据包传递给 `receiver.py` 处理。
* **`mock_server.py` (模拟服务端)**: 用于压力测试和异常模拟。它可以模拟真实网络中的各种恶劣情况（丢包、乱序等），验证客户端的健壮性。

---

## 🚀 快速开始 (Mock 模式)

目前项目主要在 **Mock 模式**下进行开发和测试。该模式不需要 `sudo` 权限，适合在本地快速迭代。

### 1. 准备测试文件

如果你不想使用大文件，可以使用内置脚本生成一个结构化的测试文件（5 个 Chunk 大小，包含调试模式）：

```bash
python3 files/gen_test_file.py

```

* **输出**: 生成名为 `random.bin` 的文件。

### 2. 启动模拟服务端 (Mock Server)

你可以根据需要选择不同的网络场景进行测试：

| 场景 (Scenario) | 说明 | 运行命令 |
| --- | --- | --- |
| **正常** | 无干扰传输 | `python3 mock_server.py --scenario normal --file files/random.bin` |
| **丢包** | 模拟 3% 丢包 | `python3 mock_server.py --scenario loss --file files/random.bin --loss 0.03` |
| **乱序** | 模拟包到达顺序错乱 | `python3 mock_server.py --scenario reorder --file files/random.bin` |
| **重复** | 模拟收到重复包 | `python3 mock_server.py --scenario duplicate --file files/random.bin` |
| **损坏** | 模拟位翻转/数据损坏 | `python3 mock_server.py --scenario corrupt --file files/random.bin` |

### 3. 运行客户端 (UDPClient)

在另一个终端运行客户端来接收文件：
如果成功连接到模拟服务器并正确处理数据包，客户端会讲收集到的分片进行重组，并在 `received` 文件夹中生成最终文件。

```bash
# 使用 --mock 参数连接本地模拟服务器
python3 UDPClient.py --server 127.0.0.1 --file random.bin --output-dir received --mock

```

---

## 🛠 真实模式 (Real Mode)

当切换到真实物理环境（非本地模拟）时，由于使用了原始套接字 (`SOCK_RAW (Raw Socket)`)，需要管理员权限：

```bash
sudo python3 UDPClient.py --server [SERVER_IP] --file [FILENAME] --output-dir received

```

---

## ✅ 结果验证

传输完成后，系统会自动执行以下验证步骤：

1. **MD5 校验**: 客户端会计算接收到的文件分片组合后的 **MD5 Hash**。
2. **比对**: 将该 Hash 与 Sender 端原始文件的 MD5 进行比对。
3. **持久化**: 如果 Hash 一致（说明传输无误），文件将被正式写入 `received` 文件夹。

---

## 📝 调试流程示例 (Using `random.bin`)

如果你使用 `gen_test_file.py` 生成的小文件进行测试，标准流程如下：

1. **生成文件**: `python3 files/gen_test_file.py`。
2. **服务端发包**: 运行 `mock_server.py` 并指定 `--scenario loss`（或其他场景）。
3. **客户端接包**: 运行 `UDPClient.py --mock`。
4. **查看日志**: 观察 `receiver.py` 是否正确识别了缺失的序列号并触发重传/重组。
5. **检查结果**: 确认 `received/random.bin` 是否生成，并检查终端输出的 MD5 匹配信息。

---

