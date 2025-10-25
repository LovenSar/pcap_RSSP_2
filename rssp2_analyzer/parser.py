from __future__ import annotations

from dataclasses import dataclass
from typing import Optional, Dict, Any, Tuple, List


@dataclass
class TimestampFields:
    # 对应 TTS: t1,t2,t3，均为无符号 32 位（示例）
    t1: Optional[int] = None
    t2: Optional[int] = None
    t3: Optional[int] = None
    raw: bytes = b""


@dataclass
class Rssp2Schema:
    protocol_id_len: int = 2
    protocol_id_values: Optional[list[int]] = None  # 大端整数
    msg_type_len: int = 1
    msg_type_values: Optional[list[int]] = None
    spi_len: int = 4
    seq_len: int = 8
    timestamp_enabled: bool = True
    timestamp_len: int = 12
    timestamp_layout: str = "TTS"  # TTS|RAW
    timestamp_endian: str = "big"  # big|little
    length_field_enabled: bool = False
    length_field_offset: int = 0
    length_field_size: int = 2
    length_field_endian: str = "big"  # big|little
    opts_len_size: int = 0  # 0 表示无选项长度字段；R2 参考为 1
    data_len_size: int = 0  # 0 表示无数据长度字段；R2 参考为 2
    mac_len: int = 16

    @staticmethod
    def from_config(cfg: Dict[str, Any]) -> "Rssp2Schema":
        schema = cfg.get("schema", {})
        ts = schema.get("timestamp", {})
        lf = schema.get("length_field", {})
        return Rssp2Schema(
            protocol_id_len=int(schema.get("protocol_id_len", 2)),
            protocol_id_values=schema.get("protocol_id_values") or None,
            msg_type_len=int(schema.get("msg_type_len", 1)),
            msg_type_values=schema.get("msg_type_values") or None,
            spi_len=int(schema.get("spi_len", 4)),
            seq_len=int(schema.get("seq_len", 8)),
            timestamp_enabled=bool(ts.get("enabled", True)),
            timestamp_len=int(ts.get("len", 12)),
            timestamp_layout=str(ts.get("layout", "TTS")),
            timestamp_endian=str(ts.get("endian", "big")),
            length_field_enabled=bool(lf.get("enabled", False)),
            length_field_offset=int(lf.get("offset", 0)),
            length_field_size=int(lf.get("size", 2)),
            length_field_endian=str(lf.get("endian", "big")),
            opts_len_size=int(schema.get("opts_len_size", 0)),
            data_len_size=int(schema.get("data_len_size", 0)),
            mac_len=int(schema.get("mac_len", 16)),
        )


@dataclass
class Rssp2Pdu:
    protocol_id: bytes
    msg_type: int
    spi: int
    seq: int
    timestamp: Optional[TimestampFields]
    user_data: bytes
    mac: bytes
    raw: bytes
    auth_region: bytes  # 参与MAC计算的数据区域（已去除MAC尾部）
    issues: List[str]


class Rssp2ParseError(Exception):
    pass


def _read_int(b: bytes, endian: str = "big") -> int:
    return int.from_bytes(b, byteorder=endian, signed=False)


def _split_length_prefixed(payload: bytes, offset: int, size: int, endian: str) -> Tuple[int, int]:
    if len(payload) < offset + size:
        raise Rssp2ParseError("不足以读取长度字段")
    lb = payload[offset:offset + size]
    length = _read_int(lb, "big" if endian == "big" else "little")
    header_bytes = offset + size
    return length, header_bytes


def parse_pdu(payload: bytes, schema: Rssp2Schema) -> Rssp2Pdu:
    issues: List[str] = []
    if schema.length_field_enabled:
        total_len, hdr = _split_length_prefixed(payload, schema.length_field_offset, schema.length_field_size, schema.length_field_endian)
        if len(payload) < total_len:
            raise Rssp2ParseError("负载长度小于声明的 PDU 长度")
        working = payload[hdr:total_len]
        raw = payload[:total_len]
    else:
        working = payload
        raw = payload

    pos = 0

    # 协议标识符
    if len(working) < pos + schema.protocol_id_len:
        raise Rssp2ParseError("不足以读取协议标识符")
    protocol_id = working[pos:pos + schema.protocol_id_len]
    pos += schema.protocol_id_len

    if schema.protocol_id_values:
        pid_val = _read_int(protocol_id, "big")
        if pid_val not in schema.protocol_id_values:
            issues.append("wrong_proto_id")

    # 消息类型
    if len(working) < pos + schema.msg_type_len:
        raise Rssp2ParseError("不足以读取消息类型")
    msg_type = _read_int(working[pos:pos + schema.msg_type_len], "big")
    pos += schema.msg_type_len

    if schema.msg_type_values and msg_type not in schema.msg_type_values:
        issues.append("msg_type_invalid")

    # SPI
    if len(working) < pos + schema.spi_len:
        raise Rssp2ParseError("不足以读取 SPI")
    spi = _read_int(working[pos:pos + schema.spi_len], "big")
    pos += schema.spi_len

    # 序列号
    if len(working) < pos + schema.seq_len:
        raise Rssp2ParseError("不足以读取序列号")
    seq = _read_int(working[pos:pos + schema.seq_len], "big")
    pos += schema.seq_len

    # 时间戳
    ts_obj: Optional[TimestampFields] = None
    if schema.timestamp_enabled:
        # 兼容：若未配置 opts_len_size/data_len_size，则沿用旧布局直接读取固定长度时间戳
        if schema.opts_len_size <= 0:
            if len(working) < pos + schema.timestamp_len:
                raise Rssp2ParseError("不足以读取时间戳字段")
            ts_raw = working[pos:pos + schema.timestamp_len]
            pos += schema.timestamp_len
            if schema.timestamp_layout.upper() == "TTS" and schema.timestamp_len in (12, 24):
                if schema.timestamp_len == 12:
                    t1 = _read_int(ts_raw[0:4], "big")
                    t2 = _read_int(ts_raw[4:8], "big")
                    t3 = _read_int(ts_raw[8:12], "big")
                else:
                    t1 = _read_int(ts_raw[0:8], "big")
                    t2 = _read_int(ts_raw[8:16], "big")
                    t3 = _read_int(ts_raw[16:24], "big")
                ts_obj = TimestampFields(t1=t1, t2=t2, t3=t3, raw=ts_raw)
            else:
                ts_obj = TimestampFields(raw=ts_raw)
        else:
            # R2 风格：读 opts_len 与 opts，再读 data_len
            if len(working) < pos + schema.opts_len_size:
                raise Rssp2ParseError("不足以读取选项长度字段")
            opts_len = _read_int(working[pos:pos + schema.opts_len_size], "big")
            pos += schema.opts_len_size
            if len(working) < pos + opts_len:
                # 声称有选项但不足 —— 记为缺失时间戳/选项长度不符
                issues.append("opts_len_mismatch")
                issues.append("missing_timestamp")
                # 回退策略：视为无选项，不前移 pos（因为实际未携带 opts），继续按无选项解析
                opts_len = 0
                opts_raw = b""
            else:
                opts_raw = working[pos:pos + opts_len]
                pos += opts_len
            if schema.timestamp_layout.upper() == "TTS" and opts_len in (12, 24):
                # 仅当长度匹配常见 TTS 长度时尝试解析
                if opts_len == 12:
                    t1 = _read_int(opts_raw[0:4], "big")
                    t2 = _read_int(opts_raw[4:8], "big")
                    t3 = _read_int(opts_raw[8:12], "big")
                else:
                    t1 = _read_int(opts_raw[0:8], "big")
                    t2 = _read_int(opts_raw[8:16], "big")
                    t3 = _read_int(opts_raw[16:24], "big")
                ts_obj = TimestampFields(t1=t1, t2=t2, t3=t3, raw=opts_raw)
            elif opts_len == 0:
                issues.append("missing_timestamp")
                ts_obj = None
            else:
                # 非 TTS 或长度偏离
                ts_obj = TimestampFields(raw=opts_raw)

    # MAC 位于尾部固定长度
    if len(working) < schema.mac_len:
        raise Rssp2ParseError("数据长度小于 MAC 长度")
    mac = working[-schema.mac_len:]

    # 用户数据位于 [pos, len(working)-mac_len)
    if schema.data_len_size > 0:
        if len(working) < pos + schema.data_len_size:
            raise Rssp2ParseError("不足以读取数据长度字段")
        data_len = _read_int(working[pos:pos + schema.data_len_size], "big")
        pos += schema.data_len_size
        expected_end = pos + data_len
        actual_end = len(working) - schema.mac_len
        if expected_end != actual_end:
            issues.append("data_len_mismatch")
        user_data_end = min(expected_end, actual_end)
    else:
        user_data_end = len(working) - schema.mac_len
    if user_data_end < pos:
        raise Rssp2ParseError("头部字段超出允许范围，用户数据区间无效")
    user_data = working[pos:user_data_end]

    auth_region = working[:user_data_end]

    return Rssp2Pdu(
        protocol_id=protocol_id,
        msg_type=msg_type,
        spi=spi,
        seq=seq,
        timestamp=ts_obj,
        user_data=user_data,
        mac=mac,
        raw=raw,
        auth_region=auth_region,
        issues=issues,
    )
