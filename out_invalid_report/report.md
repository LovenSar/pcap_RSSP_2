# RSSP-II PCAP 分析报告

输入文件: `/Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/out_invalid.pcap`

## 统计学报告

- 总包数: 12
- 解析成功: 11
- 解析失败: 1

### 消息类型分布

- 1: 11

### SPI 分布

- 287454020: 10
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
- 8: 0
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
- 23: 11

### 到达间隔统计 (ms)

- p50_ms: 0.0
- p95_ms: 19.999980926513672
- min_ms: 0.0
- max_ms: 19.999980926513672

### TTS 响应统计 (协议时间单位)

- count: 11.0
- p50: 2013265920.0
- p95: 2013265920.0
- max: 2013265920.0

### 每分钟消息速率 (部分)

- 2025-10-24 23:55: 11

## 安全性检查报告

- [warning] timestamp_high_latency: TTS RTT 过高 2013265920s (SPI=287454020) (x11)
- [high] anti_replay_replay: 检测到 anti-replay 违规: replay (SPI=287454020, SEQ=2) (x6)
- [warning] timestamp_non_monotonic: 时间戳非单调递增 (SPI=287454020) (x1)
- [warning] seq_backward: 序列号回退 (SPI=287454020): 2 -> 1 (x2)

### 计数器

- replay: 6
- too_old: 0
- seq_jump: 0
- mac_mismatch: 0
- spi_inconsistent_endpoint: 0
- timestamp_anomaly: 1
