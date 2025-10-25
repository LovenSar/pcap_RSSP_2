from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterator, Optional, List, Tuple, Dict
import struct
import ipaddress

from .parser import Rssp2Schema, parse_pdu, Rssp2Pdu, Rssp2ParseError


@dataclass
class PacketMeta:
    ts: float
    l4: str  # UDP|TCP
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    issues: List[str] = field(default_factory=list)


@dataclass
class Rssp2Record:
    meta: PacketMeta
    pdu: Optional[Rssp2Pdu]
    error: Optional[str]


# --- PCAP (libpcap) reader ---

class PcapReaderStd:
    def __init__(self, path: str):
        self.f = open(path, "rb")
        self.endian = ">"  # default big-endian for struct? We'll detect via magic
        self.ts_resolution = 1_000_000  # default usec
        self.network = 1  # DLT_EN10MB
        self._read_global_header()

    def _read_global_header(self):
        gh = self.f.read(24)
        if len(gh) < 24:
            raise EOFError("pcap 全局头不足 24 字节")
        magic_bytes = gh[0:4]
        if magic_bytes == b"\xa1\xb2\xc3\xd4":
            # big-endian, microsecond timestamps
            self.endian = ">"
            self.ts_resolution = 1_000_000
            fmt = ">IHHIIII"
        elif magic_bytes == b"\xd4\xc3\xb2\xa1":
            # little-endian, microsecond timestamps
            self.endian = "<"
            self.ts_resolution = 1_000_000
            fmt = "<IHHIIII"
        elif magic_bytes == b"\xa1\xb2\x3c\x4d":
            # big-endian, nanosecond timestamps
            self.endian = ">"
            self.ts_resolution = 1_000_000_000
            fmt = ">IHHIIII"
        elif magic_bytes == b"\x4d\x3c\xb2\xa1":
            # little-endian, nanosecond timestamps
            self.endian = "<"
            self.ts_resolution = 1_000_000_000
            fmt = "<IHHIIII"
        else:
            # not classic pcap
            raise ValueError("不支持的 PCAP magic，当前仅支持 libpcap 格式")
        _magic, ver_maj, ver_min, thiszone, sigfigs, snaplen, network = struct.unpack(fmt, gh)
        self.network = network

    def __iter__(self) -> Iterator[Tuple[float, bytes]]:
        hdr_fmt = f"{self.endian}IIII"
        while True:
            ph = self.f.read(16)
            if not ph:
                break
            if len(ph) < 16:
                break
            ts_sec, ts_sub, incl_len, orig_len = struct.unpack(hdr_fmt, ph)
            data = self.f.read(incl_len)
            if len(data) < incl_len:
                break
            ts = ts_sec + (ts_sub / float(self.ts_resolution))
            yield ts, data

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


class PcapNgReader:
    """最小可用 PCAPNG 读取器，支持 SHB/IDB/EPB/PB，产出 (ts, data, linktype)。"""

    BT_SECTION_HEADER = 0x0A0D0D0A
    BT_INTERFACE_DESC = 0x00000001
    BT_PACKET = 0x00000002
    BT_SIMPLE_PACKET = 0x00000003
    BT_ENHANCED_PACKET = 0x00000006

    BOM = b"\x1a\x2b\x3c\x4d"
    BOM_SWAPPED = b"\x4d\x3c\x2b\x1a"

    def __init__(self, path: str):
        self.f = open(path, "rb")
        self.endian = "<"  # 默认小端，遇到 SHB 后依据 BOM 设置
        # 接口列表：[{"linktype": int, "ts_res": float}]
        self.interfaces: List[Dict[str, float | int]] = []

    def __iter__(self) -> Iterator[Tuple[float, bytes, int]]:
        f = self.f
        endian = self.endian
        interfaces = self.interfaces

        while True:
            hdr = f.read(8)
            if not hdr or len(hdr) < 8:
                break
            # 先按当前端序读类型与长度（SHB 类型在大小端下字节序相同，0x0A0D0D0A）
            block_type_le = struct.unpack("<I", hdr[0:4])[0]
            block_type_be = struct.unpack(">I", hdr[0:4])[0]
            # 特判 SHB：后续 4 字节是 BOM，据此纠正端序
            if block_type_le == self.BT_SECTION_HEADER or block_type_be == self.BT_SECTION_HEADER:
                block_length = struct.unpack(endian + "I", hdr[4:8])[0]
                bom = f.read(4)
                if bom == self.BOM:
                    endian = ">"
                elif bom == self.BOM_SWAPPED:
                    endian = "<"
                else:
                    # 非法 SHB，终止
                    break
                # 读完本 SHB 余下部分（版本等 + 末尾长度）
                rest = f.read(block_length - 12)
                # 新节默认时间分辨率 10^-6
                interfaces.clear()
                self.endian = endian
                continue

            block_type = struct.unpack(endian + "I", hdr[0:4])[0]
            block_length = struct.unpack(endian + "I", hdr[4:8])[0]
            body_plus_tail = f.read(block_length - 8)
            if len(body_plus_tail) < (block_length - 8):
                break
            body = body_plus_tail[:-4]

            if block_type == self.BT_INTERFACE_DESC:
                # IDB: link_type(2) reserved(2) snaplen(4) options...
                if len(body) < 8:
                    continue
                link_type = struct.unpack(endian + "H", body[0:2])[0]
                # reserved = body[2:4]
                # snaplen = struct.unpack(endian + "I", body[4:8])[0]
                ts_res = 1e-6
                # 解析 if_tsresol 选项（code=9, len=1）
                pos = 8
                while pos + 4 <= len(body):
                    opt_code = struct.unpack(endian + "H", body[pos:pos+2])[0]
                    opt_len = struct.unpack(endian + "H", body[pos+2:pos+4])[0]
                    pos += 4
                    if opt_code == 0:
                        break
                    data = body[pos:pos+opt_len]
                    pos += opt_len
                    pad = (-opt_len) & 3
                    pos += pad
                    if opt_code == 9 and opt_len >= 1:
                        v = data[0]
                        if v & 0x80:
                            exp = (v & 0x7F)
                            ts_res = 1.0 / (2 ** exp)
                        else:
                            exp = (v & 0x7F)
                            ts_res = 10 ** (-exp)
                interfaces.append({"linktype": link_type, "ts_res": ts_res})
            elif block_type == self.BT_ENHANCED_PACKET:
                # EPB: iface_id(4) ts_high(4) ts_low(4) cap_len(4) orig_len(4) data...
                if len(body) < 20:
                    continue
                iface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(endian + "IIIII", body[0:20])
                pkt = body[20:20+cap_len]
                if iface_id < len(interfaces):
                    linktype = int(interfaces[iface_id]["linktype"])  # type: ignore
                    ts_res = float(interfaces[iface_id]["ts_res"])   # type: ignore
                else:
                    linktype = 1
                    ts_res = 1e-6
                ticks = (int(ts_high) << 32) | int(ts_low)
                ts = ticks * ts_res
                if len(pkt) == cap_len:
                    yield ts, pkt, linktype
            elif block_type == self.BT_PACKET:
                # 过时 PB：interface_id(2) drops(2) timestamp(8) cap_len(4) pkt_len(4) data...
                if len(body) < 20:
                    continue
                iface_id = struct.unpack(endian + "H", body[0:2])[0]
                ts_high, ts_low = struct.unpack(endian + "II", body[4:12])
                cap_len, pkt_len = struct.unpack(endian + "II", body[12:20])
                pkt = body[20:20+cap_len]
                if iface_id < len(interfaces):
                    linktype = int(interfaces[iface_id]["linktype"])  # type: ignore
                    ts_res = float(interfaces[iface_id]["ts_res"])   # type: ignore
                else:
                    linktype = 1
                    ts_res = 1e-6
                ticks = (int(ts_high) << 32) | int(ts_low)
                ts = ticks * ts_res
                if len(pkt) == cap_len:
                    yield ts, pkt, linktype
            else:
                # 其他块忽略
                continue

    def close(self):
        try:
            self.f.close()
        except Exception:
            pass


# --- L2/L3/L4 decoders ---

ETH_P_8021Q = 0x8100
ETH_P_IP = 0x0800
ETH_P_IPV6 = 0x86DD
DLT_EN10MB = 1
DLT_RAW = 101

PROTO_TCP = 6
PROTO_UDP = 17


def _parse_ethernet(frame: bytes) -> Tuple[int, bytes]:
    if len(frame) < 14:
        raise ValueError("以太网帧过短")
    eth_type = struct.unpack("!H", frame[12:14])[0]
    offset = 14
    if eth_type == ETH_P_8021Q:
        if len(frame) < 18:
            raise ValueError("VLAN 帧过短")
        eth_type = struct.unpack("!H", frame[16:18])[0]
        offset = 18
    return eth_type, frame[offset:]


def _parse_ipv4(payload: bytes) -> Tuple[int, str, str, bytes]:
    if len(payload) < 20:
        raise ValueError("IPv4 报文过短")
    v_ihl = payload[0]
    ihl = (v_ihl & 0x0F) * 4
    if len(payload) < ihl:
        raise ValueError("IPv4 头长度超出")
    proto = payload[9]
    src = ipaddress.IPv4Address(payload[12:16]).compressed
    dst = ipaddress.IPv4Address(payload[16:20]).compressed
    return proto, src, dst, payload[ihl:]


def _parse_ipv6(payload: bytes) -> Tuple[int, str, str, bytes]:
    if len(payload) < 40:
        raise ValueError("IPv6 报文过短")
    next_header = payload[6]
    src = ipaddress.IPv6Address(payload[8:24]).compressed
    dst = ipaddress.IPv6Address(payload[24:40]).compressed
    return next_header, src, dst, payload[40:]


def _parse_udp(payload: bytes) -> Tuple[int, int, bytes]:
    if len(payload) < 8:
        raise ValueError("UDP 报文过短")
    src_port, dst_port, length = struct.unpack("!HHH", payload[0:6])
    if len(payload) < length:
        length = len(payload)
    return src_port, dst_port, payload[8:length]


def _parse_tcp(payload: bytes) -> Tuple[int, int, bytes]:
    if len(payload) < 20:
        raise ValueError("TCP 报文过短")
    src_port, dst_port = struct.unpack("!HH", payload[0:4])
    data_offset = (payload[12] >> 4) * 4
    if len(payload) < data_offset:
        raise ValueError("TCP 头长度超出")
    return src_port, dst_port, payload[data_offset:]


def _iter_frames_any(path: str) -> Iterator[Tuple[float, bytes, int]]:
    # 根据文件魔数选择 PCAP 或 PCAPNG
    with open(path, "rb") as _f:
        head = _f.read(4)
    if head == b"\x0a\x0d\x0d\x0a":
        r = PcapNgReader(path)
        try:
            for ts, data, linktype in r:
                yield ts, data, linktype
        finally:
            r.close()
    else:
        r = PcapReaderStd(path)
        try:
            for ts, data in r:
                yield ts, data, r.network
        finally:
            r.close()


def iter_payloads(pcap_path: str, transport: str = "any", ports: Optional[List[int]] = None) -> Iterator[Tuple[bytes, PacketMeta]]:
    try:
        for ts, frame, linktype in _iter_frames_any(pcap_path):
            try:
                issues: List[str] = []
                # 以太网或 RAW IP
                if linktype == 1:  # DLT_EN10MB
                    eth_type, l3 = _parse_ethernet(frame)
                elif linktype == 101:  # DLT_RAW
                    l3 = frame
                    ver = (l3[0] >> 4) if l3 else 0
                    eth_type = ETH_P_IP if ver == 4 else (ETH_P_IPV6 if ver == 6 else 0)
                else:
                    continue

                if eth_type == ETH_P_IP:
                    # IPv4 基础解析
                    if len(l3) < 20:
                        continue
                    v_ihl = l3[0]
                    ihl = (v_ihl & 0x0F) * 4
                    if len(l3) < ihl:
                        continue
                    total_length = struct.unpack("!H", l3[2:4])[0]
                    stored_ip_csum = struct.unpack("!H", l3[10:12])[0]
                    proto = l3[9]
                    src_ip_bytes = l3[12:16]
                    dst_ip_bytes = l3[16:20]
                    src_ip = ipaddress.IPv4Address(src_ip_bytes).compressed
                    dst_ip = ipaddress.IPv4Address(dst_ip_bytes).compressed
                    # IPv4 头校验和校验
                    hdr_wo = l3[:10] + b"\x00\x00" + l3[12:ihl]
                    def _csum16(data: bytes) -> int:
                        if len(data) % 2 == 1:
                            data += b"\x00"
                        s = 0
                        for i in range(0, len(data), 2):
                            s += (data[i] << 8) + (data[i + 1])
                            s = (s & 0xFFFF) + (s >> 16)
                        return (~s) & 0xFFFF
                    calc_ip_csum = _csum16(hdr_wo)
                    if calc_ip_csum != stored_ip_csum:
                        issues.append("bad_ip_checksum")
                    # 按 total_length 截断，避免 L2 padding 干扰
                    l3_len = len(l3)
                    if total_length > l3_len:
                        issues.append("ip_total_length_mismatch")
                        ip_payload_len = max(0, l3_len - ihl)
                    else:
                        ip_payload_len = max(0, total_length - ihl)
                        if total_length < l3_len:
                            if linktype == 1:
                                issues.append("l2_padding")
                            else:
                                issues.append("ip_total_length_mismatch")
                    l4payload = l3[ihl:ihl + ip_payload_len]
                elif eth_type == ETH_P_IPV6:
                    proto, src_ip, dst_ip, l4payload = _parse_ipv6(l3)
                else:
                    continue

                if proto == PROTO_UDP and (transport in ("any", "udp")):
                    l4_name = "UDP"
                    if len(l4payload) < 8:
                        continue
                    sp, dp, app = _parse_udp(l4payload)
                    udp_len_field = struct.unpack("!H", l4payload[4:6])[0]
                    if udp_len_field != len(l4payload):
                        issues.append("udp_length_mismatch")
                    # 仅对 IPv4 执行 UDP 校验和校验
                    if eth_type == ETH_P_IP and len(l4payload) >= 8:
                        udp_stored_csum = struct.unpack("!H", l4payload[6:8])[0]
                        if 8 <= udp_len_field <= len(l4payload):
                            udp_segment = l4payload[:udp_len_field]
                        else:
                            udp_segment = l4payload
                            udp_len_field = len(l4payload)
                        udp_segment_wo_csum = udp_segment[:6] + b"\x00\x00" + udp_segment[8:]
                        pseudo = struct.pack(
                            "!4s4sBBH",
                            ipaddress.IPv4Address(src_ip).packed,
                            ipaddress.IPv4Address(dst_ip).packed,
                            0,
                            PROTO_UDP,
                            udp_len_field,
                        )
                        data_for_sum = pseudo + udp_segment_wo_csum
                        calc_udp_csum = _csum16(data_for_sum)
                        if calc_udp_csum != udp_stored_csum:
                            issues.append("bad_udp_checksum")
                elif proto == PROTO_TCP and (transport in ("any", "tcp")):
                    l4_name = "TCP"
                    sp, dp, app = _parse_tcp(l4payload)
                else:
                    continue

                if ports and (sp not in ports and dp not in ports):
                    continue
                if not app:
                    continue

                meta = PacketMeta(ts=float(ts), l4=l4_name, src_ip=src_ip, dst_ip=dst_ip, src_port=sp, dst_port=dp, issues=issues)
                yield app, meta
            except Exception:
                continue
    finally:
        pass


def iter_pdus(pcap_path: str, schema: Rssp2Schema, transport: str = "any", ports: Optional[List[int]] = None):
    for payload, meta in iter_payloads(pcap_path, transport, ports):
        try:
            pdu = parse_pdu(payload, schema)
            yield Rssp2Record(meta=meta, pdu=pdu, error=None)
        except Rssp2ParseError as e:
            yield Rssp2Record(meta=meta, pdu=None, error=str(e))
