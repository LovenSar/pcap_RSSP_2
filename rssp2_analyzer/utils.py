from __future__ import annotations

import os
import time
import json
from typing import Any, Dict


def default_config() -> Dict[str, Any]:
    return {
        "transport": "any",
        "ports": [],
        "schema": {
            "protocol_id_len": 2,
            "protocol_id_values": [],
            "msg_type_len": 1,
            "spi_len": 4,
            "seq_len": 8,
            "timestamp": {"enabled": True, "len": 12, "layout": "TTS"},
            "length_field": {"enabled": False, "offset": 0, "size": 2, "endian": "big"},
            "mac_len": 16,
        },
        "security": {
            "anti_replay_window": 64,
            "max_seq_jump": 1000000,
            "timestamp_checks": {"enabled": True, "max_skew_seconds": 5.0, "max_latency_seconds": 3.0},
            "mac_verification": {"enabled": False, "algorithm": "HMAC-SHA256", "key_hex": ""},
        },
        "report": {"include_charts": False, "timezone": "local", "rtt_detection_window_seconds": 2.0, "hourly_group": True},
    }


def load_config(path: str | None) -> Dict[str, Any]:
    if not path:
        return default_config()
    if not os.path.exists(path):
        return default_config()
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        # 回退默认配置
        return default_config()


def ensure_dir(path: str) -> None:
    os.makedirs(path, exist_ok=True)


def epoch_to_local_str(ts: float) -> str:
    lt = time.localtime(ts)
    return time.strftime("%Y-%m-%d %H:%M:%S", lt)
