from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List
import time

from .pcap_reader import Rssp2Record


@dataclass
class StatsResult:
    total: int
    parsed: int
    errors: int
    by_msg_type: Dict[int, int]
    by_spi: Dict[int, int]
    hourly_counts: Dict[int, int]
    inter_arrival_summary: Dict[str, float]
    tts_summary: Dict[str, float]
    rate_per_minute: Dict[str, int]
    charts: List[str]


def _compute_percentiles(values: List[float]) -> Dict[str, float]:
    if not values:
        return {"p50_ms": 0.0, "p95_ms": 0.0, "min_ms": 0.0, "max_ms": 0.0}
    values_sorted = sorted(values)
    n = len(values_sorted)
    def pick(p: float) -> float:
        if n == 1:
            return values_sorted[0]
        idx = int(round((n - 1) * p))
        if idx < 0:
            idx = 0
        if idx >= n:
            idx = n - 1
        return values_sorted[idx]
    return {
        "p50_ms": pick(0.5),
        "p95_ms": pick(0.95),
        "min_ms": values_sorted[0],
        "max_ms": values_sorted[-1],
    }


def analyze_stats(records: List[Rssp2Record], out_dir: str, include_charts: bool = False) -> StatsResult:
    total = len(records)
    parsed_records = [r for r in records if r.pdu is not None]
    errors = total - len(parsed_records)

    by_msg_type: Dict[int, int] = {}
    by_spi: Dict[int, int] = {}
    ts_list: List[float] = []

    for r in parsed_records:
        by_msg_type[r.pdu.msg_type] = by_msg_type.get(r.pdu.msg_type, 0) + 1
        by_spi[r.pdu.spi] = by_spi.get(r.pdu.spi, 0) + 1
        ts_list.append(r.meta.ts)

    ts_list.sort()

    hourly_counts = {h: 0 for h in range(24)}
    for r in parsed_records:
        hour = time.localtime(r.meta.ts).tm_hour
        hourly_counts[hour] += 1

    inter_ms: List[float] = []
    for i in range(1, len(ts_list)):
        inter_ms.append((ts_list[i] - ts_list[i - 1]) * 1000.0)
    inter_summary = _compute_percentiles(inter_ms)

    tts_values: List[float] = []
    for r in parsed_records:
        tsf = r.pdu.timestamp
        if tsf and tsf.t1 is not None and tsf.t3 is not None:
            dt = tsf.t3 - tsf.t1
            if dt >= 0:
                tts_values.append(float(dt))
    tts_values_sorted = sorted(tts_values)
    if tts_values_sorted:
        n = len(tts_values_sorted)
        tts_summary = {
            "count": float(n),
            "p50": tts_values_sorted[int(round((n - 1) * 0.5))],
            "p95": tts_values_sorted[int(round((n - 1) * 0.95))],
            "max": tts_values_sorted[-1],
        }
    else:
        tts_summary = {"count": 0.0, "p50": 0.0, "p95": 0.0, "max": 0.0}

    rate_per_minute: Dict[str, int] = {}
    for r in parsed_records:
        minute = int(r.meta.ts // 60)
        key = time.strftime("%Y-%m-%d %H:%M", time.localtime(minute * 60))
        rate_per_minute[key] = rate_per_minute.get(key, 0) + 1

    return StatsResult(
        total=total,
        parsed=len(parsed_records),
        errors=errors,
        by_msg_type=by_msg_type,
        by_spi=by_spi,
        hourly_counts=hourly_counts,
        inter_arrival_summary=inter_summary,
        tts_summary=tts_summary,
        rate_per_minute=rate_per_minute,
        charts=[],
    )
