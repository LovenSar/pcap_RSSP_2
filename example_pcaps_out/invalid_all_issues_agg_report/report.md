# RSSP-II PCAP 分析报告

输入文件: `/Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/example_pcaps/invalid_all_issues_agg.pcap`

## 统计学报告

- 总包数: 30
- 解析成功: 29
- 解析失败: 1

### 消息类型分布

- 1: 28
- 255: 1

### SPI 分布

- 287454020: 28
- 287454021: 1

### 每小时流量分布 (0-23)

- 0: 0
- 1: 0
- 2: 0
- 3: 0
- 4: 0
- 5: 0
- 6: 0
- 7: 0
- 8: 29
- 9: 0
- 10: 0
- 11: 0
- 12: 0
- 13: 0
- 14: 0
- 15: 0
- 16: 0
- 17: 0
- 18: 0
- 19: 0
- 20: 0
- 21: 0
- 22: 0
- 23: 0

### 到达间隔统计 (ms)

- p50_ms: 0.0
- p95_ms: 19.999980926513672
- min_ms: 0.0
- max_ms: 20.000219345092773

### TTS 响应统计 (协议时间单位)

- count: 27.0
- p50: 2000000.0
- p95: 2000000.0
- max: 5.937594564233013e+18

### 每分钟消息速率 (部分)

- 2025-10-25 08:56: 29

## 安全性检查报告

- [warning] timestamp_high_latency: TTS RTT 过高 2000000s (SPI=287454020) (x27)
- [high] mac_mismatch: MAC 校验失败，疑似篡改或密钥不匹配 (x6)
- [high] anti_replay_replay: 检测到 anti-replay 违规: replay (SPI=287454020, SEQ=9) (x13)
- [warning] seq_backward: 序列号回退 (SPI=287454020): 10 -> 9 (x3)
- [high] wrong_proto_id: 协议标识符不在允许列表 (x1)
- [high] bad_udp_checksum: 检测到 UDP 校验和错误 (x4)
- [high] bad_ip_checksum: 检测到 IPv4 头校验和错误 (x1)
- [warning] timestamp_non_monotonic: 时间戳非单调递增 (SPI=287454020) (x1)
- [warning] data_len_mismatch: 数据长度字段与实际不一致 (x8)
- [warning] udp_length_mismatch: UDP 长度字段与实际不一致 (x3)
- [warning] ip_total_length_mismatch: IPv4 总长度与实际长度不一致 (x1)
- [high] anti_replay_too_old: 检测到 anti-replay 违规: too_old (SPI=287454020, SEQ=0) (x4)
- [warning] msg_type_invalid: 消息类型不在允许列表 (x1)
- [warning] missing_timestamp: 缺失时间戳字段或长度为0 (x1)

### 计数器

- replay: 13
- too_old: 4
- seq_jump: 0
- mac_mismatch: 6
- spi_inconsistent_endpoint: 0
- timestamp_anomaly: 1
- bad_ip_checksum: 1
- bad_udp_checksum: 4
- udp_length_mismatch: 3
- ip_total_length_mismatch: 1
