from __future__ import annotations

from typing import List, Dict

from .stats import StatsResult
from .security import SecuritySummary
from .utils import epoch_to_local_str


def _fmt_kv(d: Dict) -> str:
    if not d:
        return "无"
    return "\n".join([f"- {k}: {v}" for k, v in d.items()])


def render_markdown(pcap_path: str, stats: StatsResult, sec: SecuritySummary) -> str:
    lines: List[str] = []
    lines.append(f"# RSSP-II PCAP 分析报告\n")
    lines.append(f"输入文件: `{pcap_path}`\n")

    lines.append("## 统计学报告\n")
    lines.append(f"- 总包数: {stats.total}")
    lines.append(f"- 解析成功: {stats.parsed}")
    lines.append(f"- 解析失败: {stats.errors}\n")

    lines.append("### 消息类型分布\n")
    lines.append(_fmt_kv(stats.by_msg_type) + "\n")

    lines.append("### SPI 分布\n")
    lines.append(_fmt_kv(stats.by_spi) + "\n")

    lines.append("### 每小时流量分布 (0-23)\n")
    lines.append(_fmt_kv(stats.hourly_counts) + "\n")

    lines.append("### 到达间隔统计 (ms)\n")
    lines.append(_fmt_kv(stats.inter_arrival_summary) + "\n")

    lines.append("### TTS 响应统计 (协议时间单位)\n")
    lines.append(_fmt_kv(stats.tts_summary) + "\n")

    if stats.rate_per_minute:
        lines.append("### 每分钟消息速率 (部分)\n")
        sample_items = list(stats.rate_per_minute.items())[:50]
        lines.append(_fmt_kv(dict(sample_items)) + "\n")

    if stats.charts:
        lines.append("### 图表\n")
        for p in stats.charts:
            lines.append(f"![]({p})\n")

    lines.append("## 安全性检查报告\n")
    if not sec.findings:
        lines.append("- 未发现明显异常\n")
    else:
        for f in sec.findings:
            lines.append(f"- [{f.severity}] {f.code}: {f.message} (x{f.count})")
        lines.append("")

    if sec.counters:
        lines.append("### 计数器\n")
        lines.append(_fmt_kv(sec.counters) + "\n")

    return "\n".join(lines)
