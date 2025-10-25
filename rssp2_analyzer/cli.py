from __future__ import annotations

import argparse
import os
from typing import List

from .utils import load_config, ensure_dir
from .parser import Rssp2Schema
from .pcap_reader import iter_pdus
from .stats import analyze_stats
from .security import analyze_security
from .report import render_markdown
from .csv_report import generate_csv_reports


def main(argv: List[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="RSSP-II PCAP 分析与安全检查（纯标准库版，支持 libpcap pcap 文件）")
    ap.add_argument("--pcap", required=True, help="输入 pcap 文件路径（libpcap）")
    ap.add_argument("--config", default=None, help="JSON 配置文件路径，不提供则使用内置默认配置")
    ap.add_argument("--output", default="output", help="输出目录")
    ap.add_argument("--transport", default=None, help="覆盖配置的传输协议 any|udp|tcp")
    ap.add_argument("--ports", default=None, help="覆盖配置的端口列表, 逗号分隔，例如 30000,30001")

    args = ap.parse_args(argv)

    cfg = load_config(args.config)

    transport = (args.transport or cfg.get("transport") or "any").lower()
    ports_cfg = cfg.get("ports") or []
    ports = [int(p.strip()) for p in (args.ports.split(",") if args.ports else ports_cfg)] if (args.ports or ports_cfg) else None

    schema = Rssp2Schema.from_config(cfg)

    ensure_dir(args.output)
    chart_dir = os.path.join(args.output, "charts")
    ensure_dir(chart_dir)

    records = [r for r in iter_pdus(args.pcap, schema, transport=transport, ports=ports)]

    stats = analyze_stats(records, out_dir=chart_dir, include_charts=cfg.get("report", {}).get("include_charts", False))
    sec = analyze_security(records, cfg)

    report_md = render_markdown(args.pcap, stats, sec)
    out_md = os.path.join(args.output, "report.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write(report_md)

    # 生成 CSV 报告
    csv_dir = os.path.join(args.output, "csv")
    csv_files = generate_csv_reports(records, stats, sec, cfg, csv_dir)

    print(f"报告已生成: {out_md}")
    print(f"CSV 已生成: {len(csv_files)} 个文件，目录: {csv_dir}")
    return 0
