# RSSP-II PCAP 分析与安全性检查（纯标准库）

该工具读取 libpcap pcap 文件中的 RSSP-II 安全消息（基于 UDP/TCP 原始负载），按可配置字段进行解析，输出统计学与安全性检查报告（Markdown）。不依赖第三方库，离线可用。

## 快速开始

```bash
python -m rssp2_analyzer --pcap your.pcap \
  --config rssp2_analyzer/config_example.json \
  --output out_dir
```

- `--pcap`: 输入 libpcap 格式文件（不支持 pcapng）
- `--config`: 分析配置（JSON）。未提供时使用内置默认配置
- `--output`: 输出目录（将生成 `report.md` 和可选 `charts/`）
- `--transport`: 覆盖协议过滤，`any|udp|tcp`
- `--ports`: 端口过滤，逗号分隔，例如 `30000,30001`

运行完成后，在 `out_dir/report.md` 查看报告。

## 报告包含内容

- 总包数、解析成功/失败计数
- 消息类型与 SPI 分布
- 每小时分布、到达间隔统计（ms），TTS 响应统计（原始协议时间单位）
- 每分钟速率采样（前 50）
- 安全性检查发现与计数器（反重放、序列跳变、时间戳异常、MAC 校验、L3/L4 异常等）

## RSSP-II 解析模型（可配置）

默认参考 R2 风格布局（可用配置开关兼容现场变体）：

1) 协议标识符：`protocol_id`（1..4 字节，默认 2）
2) 消息类型：`msg_type`（1 字节）
3) 安全参数索引：`spi`（4 或 8 字节，大端）
4) 序列号：`seq`（4 或 8 字节，大端）
5) 选项长度：`opts_len`（可选；默认 1 字节。若未启用该字段，则时间戳按固定长度直接跟随）
6) 选项：一般为 TTS（`t1,t2,t3`），长度 12（ms32）或 24（ns64）字节
7) 数据长度：`data_len`（可选；默认 2 字节）
8) 用户数据：变长
9) MAC：尾部固定长度（默认 16 字节，截断 HMAC）

重要配置项（来自 `rssp2_analyzer/config_example.json`）：

```json
{
  "schema": {
    "protocol_id_len": 2,
    "protocol_id_values": [21042],
    "msg_type_len": 1,
    "msg_type_values": [1],
    "spi_len": 4,
    "seq_len": 8,
    "timestamp": {"enabled": true, "len": 12, "layout": "TTS"},
    "opts_len_size": 1,
    "data_len_size": 2,
    "mac_len": 16
  },
  "security": {
    "anti_replay_window": 64,
    "max_seq_jump": 1000000,
    "timestamp_checks": {"enabled": true, "max_skew_seconds": 5.0, "max_latency_seconds": 3.0},
    "mac_verification": {"enabled": true, "algorithm": "HMAC-SHA256", "key_hex": "00112233445566778899aabbccddeeff"}
  },
  "report": {"include_charts": false, "timezone": "local", "rtt_detection_window_seconds": 2.0, "hourly_group": true}
}
```

提示：
- 如现场未携带 `opts_len`/`data_len`，可将 `opts_len_size|data_len_size` 设为 `0`，并用固定 `timestamp.len` 解析
- `protocol_id_values|msg_type_values` 留空表示不做值域校验
- 当前版本未实际绘图，`include_charts` 为预留；仍会创建空的 `charts/` 目录

## 安全性检查项（部分）

- 反重放窗口：重放/过旧序列（`replay|too_old`）
- 序列异常：回退、大跳变（阈值由 `max_seq_jump` 控制）
- 时间戳异常：非单调、负 RTT、过高 RTT（基于 TTS）
- MAC 校验：可选 HMAC-SHA256 截断校验（需配置十六进制密钥）
- L3/L4：IP/UDP 校验和错误、长度不一致
- 协议字段：`wrong_proto_id|msg_type_invalid|opts_len_mismatch|data_len_mismatch|missing_timestamp`

## 生成演示流量（generate_rssp2_pcap.py）

生成器使用纯标准库写出以太网/IPv4/UDP + RSSP-II-like PDU 的 PCAP 文件，可用于联动验证分析器。

常用参数：

```bash
python3 generate_rssp2_pcap.py --out out_valid.pcap \
  --mode valid --count 10 \
  --with-tts --tts-encoding ns64 --tts-endian be \
  --src-ip 10.0.0.2 --dst-ip 10.0.0.1 --src-port 60000 --dst-port 60001
```

无效场景列表（`--invalid-scenarios`，可多选逗号分隔）：

- wrong_mac, replay_seq, non_monotonic_seq, wrong_spi, wrong_proto_id, tampered_payload
- bad_udp_checksum, bad_ip_checksum, truncated_pdu, missing_timestamp
- data_len_mismatch_short, data_len_mismatch_long
- udp_length_short, udp_length_long, ip_total_length_short, ip_total_length_long
- seq_jump_large, seq_wrap, msg_type_invalid, opts_len_mismatch_short, opts_len_mismatch_long

示例：一次性注入多种无效场景并生成较大负载（便于触发长度校验）：

```bash
python3 /Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/generate_rssp2_pcap.py \
  --out /Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/example_pcaps/invalid_all_issues_agg.pcap \
  --mode invalid \
  --invalid-scenarios wrong_mac,replay_seq,non_monotonic_seq,wrong_spi,wrong_proto_id,tampered_payload,bad_udp_checksum,bad_ip_checksum,truncated_pdu,missing_timestamp,data_len_mismatch_short,data_len_mismatch_long,udp_length_short,udp_length_long,ip_total_length_short,ip_total_length_long,seq_jump_large,seq_wrap,msg_type_invalid,opts_len_mismatch_short,opts_len_mismatch_long \
  --count 10 --with-tts --tts-encoding ns64 --tts-endian be \
  --payload-size 900 --src-ip 10.0.0.2 --dst-ip 10.0.0.1 --src-port 60000 --dst-port 60001
```

将生成的 PCAP 交由分析器：

```bash
python -m rssp2_analyzer --pcap /Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/example_pcaps/invalid_all_issues_agg.pcap \
  --config /Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/rssp2_analyzer/config_example.json \
  --output /Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/example_pcaps_out/invalid_all_issues_agg_report
```

## 批量测试 example_pcaps 目录

遍历 `example_pcaps/*.pcap` 并为每个文件生成报告目录（zsh）：

```bash
mkdir -p /Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/example_pcaps_out && \
for p in /Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/example_pcaps/*.pcap(.N); do \
  name=${p:t:r}; \
  out="/Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/example_pcaps_out/${name}_report"; \
  python -m rssp2_analyzer --pcap "$p" \
    --config /Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/rssp2_analyzer/config_example.json \
    --output "$out"; \
  echo "生成: $out/report.md"; \
done
```

可追加过滤：`--transport udp --ports 30000,30001`

## 目录与示例

- `example_pcaps/`: 示例 PCAP（含有效与多种无效场景）
- `example_pcaps_out/`: 对应分析报告（每个输入一个子目录）
- `pcap_demo/`: 额外演示文件（pcap/pcapng）。注意：分析器当前仅支持 libpcap pcap

## 兼容性与限制

- 仅支持 libpcap（非 pcapng），链路类型要求以太网（DLT_EN10MB）
- 不绘制图表，统计以文本输出（零依赖）。仍会创建空的 `charts/` 目录
- 如需从 pcapng 转换：`editcap -F libpcap in.pcapng out.pcap`
- 生成器与分析器均为纯标准库实现，无额外依赖（`requirements.txt` 为空）

## 提示与校准

- RSSP-II 现场封装可能存在差异，请根据实际对 `schema` 做适配
- TTS 单位/含义依设备实现为准。统计中默认使用差值原样（如 ns64 可视作纳秒差值）

