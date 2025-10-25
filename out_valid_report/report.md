# RSSP-II PCAP 分析报告

输入文件: `/Users/lovensar/Workspace/auto_checklist/pcap_RSSP_2/pcap_demo/pcap_demo.pcap`

## 统计学报告

- 总包数: 25
- 解析成功: 10
- 解析失败: 15

### 消息类型分布

- 3: 6
- 196: 2
- 4: 2

### SPI 分布

- 4194304: 1
- 57999360: 1
- 18033549: 1
- 126431241: 2
- 29737322: 1
- 18868758: 2
- 28484641: 1
- 5787848: 1

### 每小时流量分布 (0-23)

- 0: 0
- 1: 0
- 2: 0
- 3: 0
- 4: 0
- 5: 0
- 6: 0
- 7: 0
- 8: 10
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

- p50_ms: 154.45399284362793
- p95_ms: 2470.8077907562256
- min_ms: 0.07700920104980469
- max_ms: 2470.8077907562256

### TTS 响应统计 (协议时间单位)

- count: 4.0
- p50: 1552717416.0
- p95: 1552717416.0
- max: 1552717416.0

### 每分钟消息速率 (部分)

- 2025-10-25 08:22: 8
- 2025-10-25 08:23: 2

## 安全性检查报告

- [warning] timestamp_high_latency: TTS RTT 过高 739495406s (SPI=4194304) (x4)
- [warning] timestamp_negative_rtt: TTS 计算得到负 RTT (SPI=57999360) (x6)
- [high] anti_replay_too_old: 检测到 anti-replay 违规: too_old (SPI=126431241, SEQ=1618199843669534792) (x1)
- [warning] seq_backward: 序列号回退 (SPI=126431241): 1618251393231203702 -> 1618199843669534792 (x1)
- [warning] spi_inconsistent_endpoint: 同一 SPI 绑定多个端点，疑似复用/重放或配置问题 (SPI=126431241) (x1)
- [high] anti_replay_replay: 检测到 anti-replay 违规: replay (SPI=18868758, SEQ=18154721335287856658) (x1)

### 计数器

- replay: 1
- too_old: 1
- seq_jump: 0
- mac_mismatch: 0
- spi_inconsistent_endpoint: 1
- timestamp_anomaly: 0
- bad_ip_checksum: 0
- bad_udp_checksum: 0
- udp_length_mismatch: 0
- ip_total_length_mismatch: 0
