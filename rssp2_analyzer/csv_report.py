from __future__ import annotations

from typing import Dict, List, Tuple, Iterable, Any
import os
import csv
import time

from .pcap_reader import Rssp2Record
from .stats import StatsResult
from .security import SecuritySummary
from .utils import ensure_dir, epoch_to_local_str


def _write_csv(path: str, header: List[str], rows: Iterable[Iterable[Any]]) -> None:
    ensure_dir(os.path.dirname(path))
    with open(path, "w", encoding="utf-8", newline="") as f:
        w = csv.writer(f)
        if header:
            w.writerow(header)
        for row in rows:
            w.writerow(row)


def _pick_percentile(sorted_values: List[float], p: float) -> float:
    n = len(sorted_values)
    if n == 0:
        return 0.0
    if n == 1:
        return float(sorted_values[0])
    idx = int(round((n - 1) * p))
    if idx < 0:
        idx = 0
    if idx >= n:
        idx = n - 1
    return float(sorted_values[idx])


def _percentiles(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"count": 0.0, "p50": 0.0, "p95": 0.0, "min": 0.0, "max": 0.0, "avg": 0.0}
    s = sorted(values)
    total = sum(s)
    return {
        "count": float(len(s)),
        "p50": _pick_percentile(s, 0.5),
        "p95": _pick_percentile(s, 0.95),
        "min": float(s[0]),
        "max": float(s[-1]),
        "avg": (total / float(len(s))) if s else 0.0,
    }


def _ratio(numer: int, denom: int) -> str:
    if denom <= 0:
        return "0.0000"
    return f"{(numer / float(denom)):.4f}"


def generate_csv_reports(
    records: List[Rssp2Record],
    stats: StatsResult,
    sec: SecuritySummary,
    cfg: Dict[str, Any],
    out_dir: str,
) -> List[str]:
    generated: List[str] = []
    ensure_dir(out_dir)

    # 概览
    overview_path = os.path.join(out_dir, "overview.csv")
    _write_csv(
        overview_path,
        ["metric", "value"],
        [
            ("total_packets", stats.total),
            ("parsed_pdus", stats.parsed),
            ("parse_errors", stats.errors),
        ],
    )
    generated.append(overview_path)

    # 消息类型分布
    by_msg_type_path = os.path.join(out_dir, "by_msg_type.csv")
    msg_items = sorted(stats.by_msg_type.items(), key=lambda x: x[0])
    _write_csv(
        by_msg_type_path,
        ["msg_type", "count", "ratio_parsed"],
        [(mt, c, _ratio(c, stats.parsed)) for mt, c in msg_items],
    )
    generated.append(by_msg_type_path)

    # SPI 分布
    by_spi_path = os.path.join(out_dir, "by_spi.csv")
    spi_items = sorted(stats.by_spi.items(), key=lambda x: x[0])
    _write_csv(
        by_spi_path,
        ["spi", "count", "ratio_parsed"],
        [(spi, c, _ratio(c, stats.parsed)) for spi, c in spi_items],
    )
    generated.append(by_spi_path)

    # 每小时分布
    hourly_path = os.path.join(out_dir, "hourly_counts.csv")
    hour_items = sorted(stats.hourly_counts.items(), key=lambda x: x[0])
    _write_csv(hourly_path, ["hour", "count"], hour_items)
    generated.append(hourly_path)

    # 到达间隔统计
    inter_summary_path = os.path.join(out_dir, "inter_arrival_summary.csv")
    _write_csv(
        inter_summary_path,
        ["metric", "value"],
        [(k, v) for k, v in stats.inter_arrival_summary.items()],
    )
    generated.append(inter_summary_path)

    # TTS 汇总
    tts_summary_path = os.path.join(out_dir, "tts_summary.csv")
    _write_csv(
        tts_summary_path,
        ["metric", "value"],
        [(k, v) for k, v in stats.tts_summary.items()],
    )
    generated.append(tts_summary_path)

    # 每分钟速率（完整）
    per_minute_path = os.path.join(out_dir, "rate_per_minute.csv")
    minute_items = sorted(stats.rate_per_minute.items(), key=lambda x: x[0])
    _write_csv(per_minute_path, ["minute", "count"], minute_items)
    generated.append(per_minute_path)

    # 安全发现
    findings_path = os.path.join(out_dir, "security_findings.csv")
    _write_csv(
        findings_path,
        ["severity", "code", "message", "count"],
        ((f.severity, f.code, f.message, f.count) for f in sorted(sec.findings, key=lambda x: (x.severity, x.code))),
    )
    generated.append(findings_path)

    # 安全计数器
    counters_path = os.path.join(out_dir, "security_counters.csv")
    _write_csv(
        counters_path,
        ["counter", "count"],
        sorted(sec.counters.items(), key=lambda x: x[0]),
    )
    generated.append(counters_path)

    # 传输层分布
    transport_counts: Dict[str, int] = {}
    for r in records:
        l4 = r.meta.l4
        transport_counts[l4] = transport_counts.get(l4, 0) + 1
    transport_path = os.path.join(out_dir, "transport_counts.csv")
    _write_csv(transport_path, ["l4", "count"], sorted(transport_counts.items(), key=lambda x: x[0]))
    generated.append(transport_path)

    # PDU issues 汇总
    pdu_issue_counts: Dict[str, int] = {}
    for r in records:
        if r.pdu:
            for iss in r.pdu.issues:
                pdu_issue_counts[iss] = pdu_issue_counts.get(iss, 0) + 1
    pdu_issues_path = os.path.join(out_dir, "pdu_issues.csv")
    _write_csv(pdu_issues_path, ["issue", "count"], sorted(pdu_issue_counts.items(), key=lambda x: x[0]))
    generated.append(pdu_issues_path)

    # SPI -> 端点集合
    spi_endpoints: Dict[int, set[Tuple[str, str, int, int]]] = {}
    for r in records:
        if not r.pdu:
            continue
        ep = (r.meta.src_ip, r.meta.dst_ip, r.meta.src_port, r.meta.dst_port)
        s = spi_endpoints.setdefault(r.pdu.spi, set())
        s.add(ep)
    spi_ep_path = os.path.join(out_dir, "endpoints_by_spi.csv")
    spi_ep_rows: List[Tuple[int, int, str]] = []
    for spi, eps in sorted(spi_endpoints.items(), key=lambda x: x[0]):
        eps_sorted = sorted(list(eps))
        eps_str = "|".join([f"{a}:{c}->{b}:{d}" for a, b, c, d in eps_sorted])
        spi_ep_rows.append((spi, len(eps_sorted), eps_str))
    _write_csv(spi_ep_path, ["spi", "num_endpoints", "endpoints"], spi_ep_rows)
    generated.append(spi_ep_path)

    # Flow 聚合（l4, sip, sport, dip, dport）
    flows: Dict[Tuple[str, str, int, str, int], Dict[str, float | int]] = {}
    for r in records:
        if not r.pdu:
            continue
        key = (r.meta.l4, r.meta.src_ip, r.meta.src_port, r.meta.dst_ip, r.meta.dst_port)
        v = flows.setdefault(key, {"count": 0, "first": r.meta.ts, "last": r.meta.ts})
        v["count"] = int(v.get("count", 0)) + 1
        if r.meta.ts < float(v["first"]):
            v["first"] = float(r.meta.ts)
        if r.meta.ts > float(v["last"]):
            v["last"] = float(r.meta.ts)
    flows_path = os.path.join(out_dir, "flows.csv")
    flow_rows: List[List[Any]] = []
    for (l4, sip, sport, dip, dport), v in sorted(flows.items(), key=lambda x: (-int(x[1]["count"]), x[0])):
        cnt = int(v["count"])  # type: ignore
        first = float(v["first"])  # type: ignore
        last = float(v["last"])  # type: ignore
        dur = max(0.0, last - first)
        pps = (cnt / dur) if dur > 0 else float(cnt)
        flow_rows.append([
            l4,
            sip,
            sport,
            dip,
            dport,
            cnt,
            epoch_to_local_str(first),
            epoch_to_local_str(last),
            f"{dur:.6f}",
            f"{pps:.6f}",
        ])
    _write_csv(
        flows_path,
        ["l4", "src_ip", "src_port", "dst_ip", "dst_port", "count", "first_ts", "last_ts", "duration_s", "pps"],
        flow_rows,
    )
    generated.append(flows_path)

    # 消息长度统计（整体 & 按类型）
    lens_all: List[float] = []
    lens_by_type: Dict[int, List[float]] = {}
    for r in records:
        if not r.pdu:
            continue
        ln = float(len(r.pdu.user_data))
        lens_all.append(ln)
        arr = lens_by_type.setdefault(r.pdu.msg_type, [])
        arr.append(ln)
    len_overall_path = os.path.join(out_dir, "msg_len_overall.csv")
    o = _percentiles(lens_all)
    _write_csv(
        len_overall_path,
        ["metric", "value"],
        [(k, v) for k, v in o.items()],
    )
    generated.append(len_overall_path)

    len_by_type_path = os.path.join(out_dir, "msg_len_by_type.csv")
    rows: List[List[Any]] = []
    for mt, arr in sorted(lens_by_type.items(), key=lambda x: x[0]):
        pp = _percentiles(arr)
        rows.append([
            mt,
            int(pp["count"]),
            f"{pp['min']:.6f}",
            f"{pp['p50']:.6f}",
            f"{pp['p95']:.6f}",
            f"{pp['max']:.6f}",
            f"{pp['avg']:.6f}",
        ])
    _write_csv(len_by_type_path, ["msg_type", "count", "min", "p50", "p95", "max", "avg"], rows)
    generated.append(len_by_type_path)

    # 分钟 × 消息类型
    msg_type_per_minute: Dict[Tuple[str, int], int] = {}
    for r in records:
        if not r.pdu:
            continue
        minute = int(r.meta.ts // 60)
        minute_key = time.strftime("%Y-%m-%d %H:%M", time.localtime(minute * 60))
        key = (minute_key, r.pdu.msg_type)
        msg_type_per_minute[key] = msg_type_per_minute.get(key, 0) + 1
    mtm_path = os.path.join(out_dir, "msg_type_per_minute.csv")
    _write_csv(mtm_path, ["minute", "msg_type", "count"], [(k[0], k[1], v) for k, v in sorted(msg_type_per_minute.items(), key=lambda x: (x[0][0], x[0][1]))])
    generated.append(mtm_path)

    # SPI 序列号分析
    max_jump = int((cfg.get("security", {}) or {}).get("max_seq_jump", 1000000))
    spi_seq: Dict[int, Dict[str, float | int]] = {}
    for r in records:
        if not r.pdu:
            continue
        spi = r.pdu.spi
        seq = int(r.pdu.seq)
        v = spi_seq.setdefault(spi, {"count": 0, "min_seq": seq, "max_seq": seq, "last_seq": None, "backward_count": 0, "max_positive_jump": 0, "large_jump_count": 0})
        v["count"] = int(v["count"]) + 1  # type: ignore
        if seq < int(v["min_seq"]):  # type: ignore
            v["min_seq"] = seq
        if seq > int(v["max_seq"]):  # type: ignore
            v["max_seq"] = seq
        last = v.get("last_seq")
        if last is not None:
            jump = seq - int(last)  # type: ignore
            if jump < 0:
                v["backward_count"] = int(v["backward_count"]) + 1  # type: ignore
            else:
                if jump > int(v["max_positive_jump"]):  # type: ignore
                    v["max_positive_jump"] = jump
                if jump > max_jump:
                    v["large_jump_count"] = int(v["large_jump_count"]) + 1  # type: ignore
        v["last_seq"] = seq
    spi_seq_path = os.path.join(out_dir, "spi_seq_analysis.csv")
    spi_seq_rows: List[List[Any]] = []
    for spi, v in sorted(spi_seq.items(), key=lambda x: x[0]):
        spi_seq_rows.append([
            spi,
            int(v["count"]),
            int(v["min_seq"]),
            int(v["max_seq"]),
            int(v["backward_count"]),
            int(v["max_positive_jump"]),
            int(v["large_jump_count"]),
        ])
    _write_csv(spi_seq_path, ["spi", "count", "min_seq", "max_seq", "backward_count", "max_positive_jump", "large_jump_count"], spi_seq_rows)
    generated.append(spi_seq_path)

    # SPI TTS 统计
    spi_tts: Dict[int, List[float]] = {}
    for r in records:
        if not r.pdu or not r.pdu.timestamp:
            continue
        tsf = r.pdu.timestamp
        if tsf.t1 is not None and tsf.t3 is not None:
            dt = float(tsf.t3 - tsf.t1)
            if dt >= 0:
                spi_tts.setdefault(r.pdu.spi, []).append(dt)
    spi_tts_path = os.path.join(out_dir, "spi_tts_stats.csv")
    tts_rows: List[List[Any]] = []
    for spi, arr in sorted(spi_tts.items(), key=lambda x: x[0]):
        pp = _percentiles(arr)
        tts_rows.append([spi, int(pp["count"]), f"{pp['p50']:.6f}", f"{pp['p95']:.6f}", f"{pp['max']:.6f}", f"{pp['avg']:.6f}"])
    _write_csv(spi_tts_path, ["spi", "count", "p50", "p95", "max", "avg"], tts_rows)
    generated.append(spi_tts_path)

    # (spi, msg_type) 组合分布
    spi_msg: Dict[Tuple[int, int], int] = {}
    for r in records:
        if not r.pdu:
            continue
        key = (r.pdu.spi, r.pdu.msg_type)
        spi_msg[key] = spi_msg.get(key, 0) + 1
    spi_msg_path = os.path.join(out_dir, "msg_type_by_spi.csv")
    _write_csv(spi_msg_path, ["spi", "msg_type", "count"], [(k[0], k[1], v) for k, v in sorted(spi_msg.items(), key=lambda x: (x[0][0], x[0][1]))])
    generated.append(spi_msg_path)

    # Top talkers
    src_ip_counts: Dict[str, int] = {}
    dst_ip_counts: Dict[str, int] = {}
    pair_counts: Dict[Tuple[str, str], int] = {}
    for r in records:
        if not r.pdu:
            continue
        src_ip_counts[r.meta.src_ip] = src_ip_counts.get(r.meta.src_ip, 0) + 1
        dst_ip_counts[r.meta.dst_ip] = dst_ip_counts.get(r.meta.dst_ip, 0) + 1
        key = (r.meta.src_ip, r.meta.dst_ip)
        pair_counts[key] = pair_counts.get(key, 0) + 1
    src_path = os.path.join(out_dir, "top_src_ip.csv")
    dst_path = os.path.join(out_dir, "top_dst_ip.csv")
    pair_path = os.path.join(out_dir, "top_src_dst_pair.csv")
    _write_csv(src_path, ["src_ip", "count"], sorted(src_ip_counts.items(), key=lambda x: (-x[1], x[0])))
    _write_csv(dst_path, ["dst_ip", "count"], sorted(dst_ip_counts.items(), key=lambda x: (-x[1], x[0])))
    _write_csv(pair_path, ["src_ip", "dst_ip", "count"], [(k[0], k[1], v) for k, v in sorted(pair_counts.items(), key=lambda x: (-x[1], x[0][0], x[0][1]))])
    generated.extend([src_path, dst_path, pair_path])

    # 到达间隔直方图（ms）
    ts_sorted = sorted([r.meta.ts for r in records if r.pdu])
    inter_ms: List[float] = []
    for i in range(1, len(ts_sorted)):
        inter_ms.append((ts_sorted[i] - ts_sorted[i - 1]) * 1000.0)
    buckets = [1, 5, 10, 50, 100, 500, 1000]
    labels: List[str] = []
    counts: List[int] = []
    prev = 0.0
    for b in buckets:
        labels.append(f"{int(prev)}-{b}ms")
        counts.append(0)
        prev = float(b)
    labels.append(">=1000ms")
    counts.append(0)
    for v in inter_ms:
        placed = False
        for i, b in enumerate(buckets):
            if v < b:
                counts[i] += 1
                placed = True
                break
        if not placed:
            counts[-1] += 1
    inter_hist_path = os.path.join(out_dir, "inter_arrival_histogram.csv")
    _write_csv(inter_hist_path, ["bucket", "count"], zip(labels, counts))
    generated.append(inter_hist_path)

    # 每分钟 UDP/TCP 计数
    minute_transport: Dict[str, Dict[str, int]] = {}
    for r in records:
        if not r.pdu:
            continue
        minute = int(r.meta.ts // 60)
        minute_key = time.strftime("%Y-%m-%d %H:%M", time.localtime(minute * 60))
        d = minute_transport.setdefault(minute_key, {"UDP": 0, "TCP": 0})
        if r.meta.l4 in ("UDP", "TCP"):
            d[r.meta.l4] = d.get(r.meta.l4, 0) + 1
    minute_transport_path = os.path.join(out_dir, "minute_transport_counts.csv")
    _write_csv(
        minute_transport_path,
        ["minute", "udp_count", "tcp_count"],
        [(k, v.get("UDP", 0), v.get("TCP", 0)) for k, v in sorted(minute_transport.items(), key=lambda x: x[0])],
    )
    generated.append(minute_transport_path)

    # PCAP 元信息
    parsed_records = [r for r in records if r.pdu]
    if parsed_records:
        start_ts = min(r.meta.ts for r in parsed_records)
        end_ts = max(r.meta.ts for r in parsed_records)
        duration = max(0.0, end_ts - start_ts)
        uniq_src = len({r.meta.src_ip for r in parsed_records})
        uniq_dst = len({r.meta.dst_ip for r in parsed_records})
        uniq_ports = len({r.meta.src_port for r in parsed_records} | {r.meta.dst_port for r in parsed_records})
    else:
        start_ts = 0.0
        end_ts = 0.0
        duration = 0.0
        uniq_src = 0
        uniq_dst = 0
        uniq_ports = 0
    pcap_meta_path = os.path.join(out_dir, "pcap_meta.csv")
    _write_csv(
        pcap_meta_path,
        ["metric", "value"],
        [
            ("start_ts", epoch_to_local_str(start_ts) if start_ts else "0"),
            ("end_ts", epoch_to_local_str(end_ts) if end_ts else "0"),
            ("duration_s", f"{duration:.6f}"),
            ("unique_src_ip", uniq_src),
            ("unique_dst_ip", uniq_dst),
            ("unique_ports", uniq_ports),
        ],
    )
    generated.append(pcap_meta_path)

    return generated


