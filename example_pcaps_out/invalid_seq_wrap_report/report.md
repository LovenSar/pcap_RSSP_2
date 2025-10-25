# RSSP-II PCAP 分析报告

输入文件: `/Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/example_pcaps/invalid_seq_wrap.pcap`

## 统计学报告

- 总包数: 5
- 解析成功: 5
- 解析失败: 0

### 消息类型分布

- 1: 5

### SPI 分布

- 287454020: 5

### 每小时流量分布 (0-23)

- 0: 0
- 1: 0
- 2: 0
- 3: 0
- 4: 0
- 5: 0
- 6: 0
- 7: 0
- 8: 5
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

- p50_ms: 19.999980926513672
- p95_ms: 20.000219345092773
- min_ms: 19.999980926513672
- max_ms: 20.000219345092773

### TTS 响应统计 (协议时间单位)

- count: 0.0
- p50: 0.0
- p95: 0.0
- max: 0.0

### 每分钟消息速率 (部分)

- 2025-10-25 08:49: 5

## 安全性检查报告

- [warning] missing_timestamp: 缺失时间戳字段或长度为0 (x5)
- [warning] seq_backward: 序列号回退 (SPI=287454020): 4 -> 0 (x1)

### 计数器

- replay: 0
- too_old: 0
- seq_jump: 0
- mac_mismatch: 0
- spi_inconsistent_endpoint: 0
- timestamp_anomaly: 0
- bad_ip_checksum: 0
- bad_udp_checksum: 0
- udp_length_mismatch: 0
- ip_total_length_mismatch: 0
