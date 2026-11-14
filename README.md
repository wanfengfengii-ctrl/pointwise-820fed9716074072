# PCAP 上传文件重组器

用 Python 标准库把录制的网络包（小端微秒经典 PCAP / Ethernet II / 无选项
IPv4+TCP，单条单向连接）还原为原始上传文件。

## 入口

```python
from reassemble import collect
n = collect("capture.pcap", "upload.bin")   # 成功返回写入字节数
```

成功时在目标同目录写临时文件并 `os.replace` 原子替换；任何失败都抛出
`ValueError` 且原目标保持不变，错误消息分别包含：

| 情况 | 消息关键词 |
| --- | --- |
| EOF 时缺 IP 分片、缺 TCP 段或缺 FIN（序列号缺口） | `gap` |
| 任意层重叠字节不一致（含迟到重传与已写前缀不符） | `conflict` |
| 捕获文件本身截断（头/记录/帧不完整，snaplen 异常） | `truncated` |

## 设计要点

- **流式解析**：PCAP 全局头/记录头逐条读取，64 KiB 缓冲，整流从不驻内存。
- **TCP 连续前缀落盘**：每处理一个包，只要补齐了连续前缀就立即追加到临时
  文件；乱序载荷以「相对偏移 → 字节串」字典暂存（目标负载下 ≤ 64 KiB），
  不做逐字节全流索引。
- **重传核对**：与已写前缀重叠的重传段，先 `seek` 临时文件逐块比对，字节
  相同才接纳，冲突即 `conflict`。
- **序列号回绕**：统一转为相对 ISN 的 32 位无符号偏移，跨度 < 2^31。
- **IPv4 分片**：按 `(src, dst, id)` 聚合，支持乱序、重复、重叠；重叠逐字节
  相同才接纳；只有完整数据报才交付 TCP；未完成的分片仅保存偏移字典
  （目标负载下待补齐数据 ≤ 64 KiB）。
- **内存预算**：32 MiB 上传场景下 `tracemalloc` 实测峰值约 100 KiB 量级，
  远低于 8 MiB 上限（见核验输出）。

## 复现

```bash
python3 -I tools/make_fixtures.py   # 生成 fixtures/ 下全部夹具（含 32 MiB）
python3 -I tools/fuzz.py            # 80 轮随机差分/冲突测试（朴素参考实现对比）
python3 -I tools/verify.py          # 业务核验 + 失败语义 + 资源实测
python3 -I tools/demo.py wrap       # 规格示例（SYN 2^32-2、乱序回绕）
python3 -I tools/demo.py full       # 32 MiB 真实演示
python3 -I tools/demo.py fail       # conflict 时保留原目标演示
```

## 文件

- `reassemble.py` — 交付的 `collect(pcap_path, out_path)` 实现
- `pcap_build.py` — 仅用于生成测试 PCAP 的极简构造器
- `tools/make_fixtures.py` — 夹具生成（功能、错误、32 MiB 资源场景）
- `tools/fuzz.py` — 随机化差分测试与冲突注入测试
- `tools/verify.py` — 可重跑的业务核验与内存实测
- `tools/demo.py` — 真实端到端演示
- `.pointwise-runtime.json` — 运行时入口描述
