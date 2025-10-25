from __future__ import annotations

from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

import hmac
import hashlib

from .pcap_reader import Rssp2Record


@dataclass
class SecurityFinding:
    severity: str  # info|warning|high|critical
    code: str
    message: str
    count: int = 1


@dataclass
class SecuritySummary:
    findings: List[SecurityFinding]
    counters: Dict[str, int]


class AntiReplayWindow:
    def __init__(self, window: int = 64):
        self.window = max(1, int(window))
        self.max_seq: Dict[int, int] = {}
        self.seen: Dict[int, set[int]] = {}

    def check(self, spi: int, seq: int) -> Tuple[bool, Optional[str]]:
        last_max = self.max_seq.get(spi)
        if last_max is None:
            self.max_seq[spi] = seq
            self.seen[spi] = {seq}
            return True, None
        if seq > last_max:
            if seq - last_max > self.window:
                self.seen[spi] = set()
            else:
                for old in range(last_max - self.window + 1, last_max + 1):
                    if old in self.seen[spi] and old < seq - self.window:
                        self.seen[spi].discard(old)
            self.max_seq[spi] = seq
            self.seen[spi].add(seq)
            return True, None
        if seq in self.seen[spi]:
            return False, "replay"
        if last_max - seq <= self.window:
            self.seen[spi].add(seq)
            return True, None
        return False, "too_old"


def analyze_security(records: List[Rssp2Record], cfg: Dict[str, Any]) -> SecuritySummary:
    findings: Dict[str, SecurityFinding] = {}
    counters: Dict[str, int] = {
        "replay": 0,
        "too_old": 0,
        "seq_jump": 0,
        "mac_mismatch": 0,
        "spi_inconsistent_endpoint": 0,
        "timestamp_anomaly": 0,
        # L3/L4
        "bad_ip_checksum": 0,
        "bad_udp_checksum": 0,
        "udp_length_mismatch": 0,
        "ip_total_length_mismatch": 0,
    }

    sec = cfg.get("security", {})
    window = int(sec.get("anti_replay_window", 64))
    max_jump = int(sec.get("max_seq_jump", 1000000))
    ts_cfg = sec.get("timestamp_checks", {"enabled": True, "max_skew_seconds": 5.0, "max_latency_seconds": 3.0})
    mac_cfg = sec.get("mac_verification", {"enabled": False})

    def add(code: str, severity: str, message: str):
        if code in findings:
            findings[code].count += 1
        else:
            findings[code] = SecurityFinding(severity=severity, code=code, message=message, count=1)

    aw = AntiReplayWindow(window)
    spi_endpoints: Dict[int, set[tuple[str, str, int, int]]] = {}
    last_seq: Dict[int, int] = {}
    last_t1: Dict[int, int] = {}

    for r in records:
        # 首先处理分组层面的异常（无论 PDU 是否成功解析）
        for iss in getattr(r.meta, "issues", []) or []:
            if iss == "bad_ip_checksum":
                counters["bad_ip_checksum"] += 1
                add("bad_ip_checksum", "high", "检测到 IPv4 头校验和错误")
            elif iss == "ip_total_length_mismatch":
                counters["ip_total_length_mismatch"] += 1
                add("ip_total_length_mismatch", "warning", "IPv4 总长度与实际长度不一致")
            elif iss == "udp_length_mismatch":
                counters["udp_length_mismatch"] += 1
                add("udp_length_mismatch", "warning", "UDP 长度字段与实际不一致")
            elif iss == "bad_udp_checksum":
                counters["bad_udp_checksum"] += 1
                add("bad_udp_checksum", "high", "检测到 UDP 校验和错误")

        if not r.pdu:
            continue
        spi = r.pdu.spi
        seq = r.pdu.seq

        ok, reason = aw.check(spi, seq)
        if not ok:
            counters[reason] += 1
            add(f"anti_replay_{reason}", "high", f"检测到 anti-replay 违规: {reason} (SPI={spi}, SEQ={seq})")

        if spi in last_seq:
            jump = seq - last_seq[spi]
            if jump < 0:
                add("seq_backward", "warning", f"序列号回退 (SPI={spi}): {last_seq[spi]} -> {seq}")
            elif jump > max_jump:
                counters["seq_jump"] += 1
                add("seq_large_jump", "warning", f"序列号跳变过大 {jump} (SPI={spi})")
        last_seq[spi] = seq

        ep = (r.meta.src_ip, r.meta.dst_ip, r.meta.src_port, r.meta.dst_port)
        s = spi_endpoints.setdefault(spi, set())
        s.add(ep)
        if len(s) > 1:
            counters["spi_inconsistent_endpoint"] += 1
            add("spi_inconsistent_endpoint", "warning", f"同一 SPI 绑定多个端点，疑似复用/重放或配置问题 (SPI={spi})")

        if ts_cfg.get("enabled", True) and r.pdu.timestamp and r.pdu.timestamp.t1 is not None:
            t1 = int(r.pdu.timestamp.t1)
            if spi in last_t1 and t1 < last_t1[spi]:
                counters["timestamp_anomaly"] += 1
                add("timestamp_non_monotonic", "warning", f"时间戳非单调递增 (SPI={spi})")
            last_t1[spi] = t1

            if r.pdu.timestamp.t3 is not None:
                rtt = int(r.pdu.timestamp.t3) - t1
                if rtt < 0:
                    add("timestamp_negative_rtt", "warning", f"TTS 计算得到负 RTT (SPI={spi})")
                elif rtt > ts_cfg.get("max_latency_seconds", 3.0):
                    add("timestamp_high_latency", "warning", f"TTS RTT 过高 {rtt}s (SPI={spi})")

        # 协议级 issues 聚合为安全发现
        for iss in getattr(r.pdu, "issues", []) or []:
            if iss == "wrong_proto_id":
                add("wrong_proto_id", "high", "协议标识符不在允许列表")
            elif iss == "msg_type_invalid":
                add("msg_type_invalid", "warning", "消息类型不在允许列表")
            elif iss == "opts_len_mismatch":
                add("opts_len_mismatch", "warning", "选项长度与实际不一致")
            elif iss == "data_len_mismatch":
                add("data_len_mismatch", "warning", "数据长度字段与实际不一致")
            elif iss == "missing_timestamp":
                add("missing_timestamp", "warning", "缺失时间戳字段或长度为0")

        if mac_cfg.get("enabled", False):
            key_hex = mac_cfg.get("key_hex", "")
            if not key_hex:
                add("mac_key_missing", "info", "启用了 MAC 校验但未提供密钥")
            else:
                try:
                    key = bytes.fromhex(key_hex)
                    calc = hmac.new(key, r.pdu.auth_region, hashlib.sha256).digest()
                    mac = r.pdu.mac
                    if len(calc) != len(mac):
                        calc = calc[: len(mac)]
                    if not hmac.compare_digest(calc, mac):
                        counters["mac_mismatch"] += 1
                        add("mac_mismatch", "high", "MAC 校验失败，疑似篡改或密钥不匹配")
                except Exception as e:
                    add("mac_error", "warning", f"MAC 校验异常: {e}")

    return SecuritySummary(findings=list(findings.values()), counters=counters)
