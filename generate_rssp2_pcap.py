#!/usr/bin/env python3
import argparse
import hmac
import hashlib
import ipaddress
import os
import random
import struct
import sys
import time
from typing import Optional, Tuple, List


# ----------------------------- PCAP Writer -----------------------------


class PcapWriter:
    def __init__(self, file_path: str, snaplen: int = 1024):
        self.file_path = file_path
        self.snaplen = snaplen
        self._f = open(self.file_path, 'wb')
        # PCAP little-endian, microsecond timestamps
        # magic_number, version_major, version_minor, thiszone, sigfigs, snaplen, network
        global_header = struct.pack(
            '<IHHiiii',
            0xA1B2C3D4,  # magic number written in little-endian -> bytes d4 c3 b2 a1
            2,           # version major
            4,           # version minor
            0,           # thiszone
            0,           # sigfigs
            self.snaplen,
            1            # LINKTYPE_ETHERNET
        )
        self._f.write(global_header)

    def write_packet(self, payload: bytes, ts: Optional[float] = None) -> None:
        if ts is None:
            ts = time.time()
        ts_sec = int(ts)
        ts_usec = int((ts - ts_sec) * 1_000_000)
        incl_len = len(payload)
        orig_len = len(payload)
        pkt_header = struct.pack('<IIII', ts_sec, ts_usec, incl_len, orig_len)
        self._f.write(pkt_header)
        self._f.write(payload)

    def close(self) -> None:
        try:
            self._f.flush()
        finally:
            self._f.close()


# ----------------------------- Utilities -----------------------------


def parse_mac(mac: str) -> bytes:
    parts = mac.split(':')
    if len(parts) != 6:
        raise ValueError(f'Invalid MAC: {mac}')
    return bytes(int(p, 16) for p in parts)


def parse_ipv4(addr: str) -> bytes:
    return ipaddress.IPv4Address(addr).packed


def ip_checksum(header: bytes) -> int:
    if len(header) % 2 == 1:
        header += b'\x00'
    s = 0
    for i in range(0, len(header), 2):
        word = (header[i] << 8) + header[i + 1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def udp_checksum(src_ip: bytes, dst_ip: bytes, udp_header: bytes, payload: bytes, udp_length_override: Optional[int] = None) -> int:
    udp_len = udp_length_override if udp_length_override is not None else (len(udp_header) + len(payload))
    pseudo_header = struct.pack('!4s4sBBH', src_ip, dst_ip, 0, 17, udp_len)
    data = pseudo_header + udp_header + payload
    if len(data) % 2 == 1:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        word = (data[i] << 8) + data[i + 1]
        s += word
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def build_ethernet(src_mac: bytes, dst_mac: bytes, ethertype: int, payload: bytes) -> bytes:
    eth_header = dst_mac + src_mac + struct.pack('!H', ethertype)
    return eth_header + payload


def build_ipv4(src_ip: bytes, dst_ip: bytes, payload: bytes, ttl: int = 64, identification: int = 0, bad_checksum: bool = False, override_total_length: Optional[int] = None) -> bytes:
    version = 4
    ihl = 5
    ver_ihl = (version << 4) + ihl
    dscp_ecn = 0
    total_length = 20 + len(payload)
    if override_total_length is not None:
        total_length = override_total_length
    flags_fragment = 0
    ttl_value = ttl
    protocol = 17  # UDP
    header_checksum = 0
    ip_header_wo_checksum = struct.pack(
        '!BBHHHBBH4s4s',
        ver_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl_value,
        protocol,
        header_checksum,
        src_ip,
        dst_ip,
    )
    checksum = ip_checksum(ip_header_wo_checksum)
    if bad_checksum:
        checksum = checksum ^ 0xFFFF  # flip to force incorrect checksum
    ip_header = struct.pack(
        '!BBHHHBBH4s4s',
        ver_ihl,
        dscp_ecn,
        total_length,
        identification,
        flags_fragment,
        ttl_value,
        protocol,
        checksum,
        src_ip,
        dst_ip,
    )
    return ip_header + payload


def build_udp(src_ip: bytes, dst_ip: bytes, src_port: int, dst_port: int, payload: bytes, bad_checksum: bool = False, override_length: Optional[int] = None) -> bytes:
    length = 8 + len(payload)
    if override_length is not None:
        length = override_length
    checksum = 0
    udp_header = struct.pack('!HHHH', src_port, dst_port, length, checksum)
    checksum = udp_checksum(src_ip, dst_ip, udp_header, payload, udp_length_override=length)
    if bad_checksum:
        checksum = checksum ^ 0xFFFF
    udp_header = struct.pack('!HHHH', src_port, dst_port, length, checksum)
    return udp_header + payload


# ----------------------------- RSSP-II PDU Builder -----------------------------


class Rssp2PduBuilder:
    HASH_ALGOS = {
        'sha1': hashlib.sha1,
        'sha224': hashlib.sha224,
        'sha256': hashlib.sha256,
        'sha384': hashlib.sha384,
        'sha512': hashlib.sha512,
        'md5': hashlib.md5,
    }

    def __init__(
        self,
        key: bytes,
        spi: int = 0x11223344,
        protocol_id: bytes = b'R2',
        mac_len: int = 16,
        mac_algo: str = 'sha256',
        seq_bytes: int = 8,
        spi_bytes: int = 4,
        tts_encoding: str = 'ns64',  # ns64 or ms32
        tts_endian: str = 'be',      # be or le
    ):
        if not (8 <= mac_len <= 64):
            raise ValueError('mac_len must be between 8 and 64 bytes')
        if mac_algo not in self.HASH_ALGOS:
            raise ValueError(f'Unsupported mac_algo: {mac_algo}')
        if seq_bytes not in (4, 8):
            raise ValueError('seq_bytes must be 4 or 8')
        if spi_bytes not in (4, 8):
            raise ValueError('spi_bytes must be 4 or 8')
        if tts_encoding not in ('ns64', 'ms32'):
            raise ValueError('tts_encoding must be ns64 or ms32')
        if tts_endian not in ('be', 'le'):
            raise ValueError('tts_endian must be be or le')
        if not (1 <= len(protocol_id) <= 4):
            raise ValueError('protocol_id must be 1..4 bytes')
        self.key = key
        self.spi = spi
        self.protocol_id = protocol_id
        self.mac_len = mac_len
        self.mac_algo = mac_algo
        self.seq_bytes = seq_bytes
        self.spi_bytes = spi_bytes
        self.tts_encoding = tts_encoding
        self.tts_endian = tts_endian

    def _pack_u(self, value: int, size: int, endian: str = 'be') -> bytes:
        if size == 4:
            fmt = '>I' if endian == 'be' else '<I'
        elif size == 8:
            fmt = '>Q' if endian == 'be' else '<Q'
        elif size == 2:
            fmt = '>H' if endian == 'be' else '<H'
        elif size == 1:
            fmt = 'B'
        else:
            raise ValueError('Unsupported size')
        return struct.pack(fmt, value)

    def _encode_tts(self, tts: Tuple[int, int, int]) -> bytes:
        t1, t2, t3 = tts
        if self.tts_encoding == 'ns64':
            fmt = ('>QQQ' if self.tts_endian == 'be' else '<QQQ')
            return struct.pack(fmt, t1, t2, t3)
        elif self.tts_encoding == 'ms32':
            # convert ns to ms (floor)
            m1, m2, m3 = (t1 // 1_000_000, t2 // 1_000_000, t3 // 1_000_000)
            # wrap into 32-bit unsigned range to avoid overflow
            m1 &= 0xFFFFFFFF
            m2 &= 0xFFFFFFFF
            m3 &= 0xFFFFFFFF
            fmt = ('>III' if self.tts_endian == 'be' else '<III')
            return struct.pack(fmt, m1, m2, m3)
        else:
            raise ValueError('Unsupported tts_encoding')

    def _compute_mac(self, data: bytes) -> bytes:
        digestmod = self.HASH_ALGOS[self.mac_algo]
        tag = hmac.new(self.key, data, digestmod).digest()
        return tag[: self.mac_len]

    def build(
        self,
        *,
        message_type: int,
        sequence: int,
        user_data: bytes,
        tts: Optional[Tuple[int, int, int]] = None,
        override_protocol_id: Optional[bytes] = None,
        override_spi: Optional[int] = None,
        wrong_mac: bool = False,
        truncate_pdu: Optional[int] = None,
        omit_tts: bool = False,
        override_data_len: Optional[int] = None,
        override_opts_len: Optional[int] = None,
    ) -> bytes:
        proto = override_protocol_id if override_protocol_id is not None else self.protocol_id
        spi = override_spi if override_spi is not None else self.spi
        parts: List[bytes] = []
        parts.append(proto)
        parts.append(self._pack_u(message_type & 0xFF, 1))
        parts.append(self._pack_u(spi, self.spi_bytes))
        parts.append(self._pack_u(sequence, self.seq_bytes))

        opts = b''
        if tts and not omit_tts:
            opts = self._encode_tts(tts)
        opts_len_to_write = override_opts_len if override_opts_len is not None else len(opts)
        parts.append(self._pack_u(opts_len_to_write, 1))
        parts.append(opts)

        data_len_to_write = override_data_len if override_data_len is not None else len(user_data)
        parts.append(self._pack_u(data_len_to_write, 2))
        parts.append(user_data)

        pdu_wo_mac = b''.join(parts)

        mac = self._compute_mac(pdu_wo_mac)
        if wrong_mac:
            mac = bytearray(mac)
            if len(mac) > 0:
                mac[-1] ^= 0xFF
            mac = bytes(mac)

        pdu = pdu_wo_mac + mac
        if truncate_pdu is not None and 0 <= truncate_pdu < len(pdu):
            pdu = pdu[:truncate_pdu]
        return pdu


# ----------------------------- Scenario Logic -----------------------------


INVALID_SCENARIOS = {
    'wrong_mac',
    'replay_seq',
    'non_monotonic_seq',
    'wrong_spi',
    'wrong_proto_id',
    'tampered_payload',
    'bad_udp_checksum',
    'bad_ip_checksum',
    'truncated_pdu',
    'missing_timestamp',
    'data_len_mismatch_short',
    'data_len_mismatch_long',
    'udp_length_short',
    'udp_length_long',
    'ip_total_length_short',
    'ip_total_length_long',
    'seq_jump_large',
    'seq_wrap',
    'msg_type_invalid',
    'opts_len_mismatch_short',
    'opts_len_mismatch_long',
}


def rand_bytes(n: int) -> bytes:
    return os.urandom(n)


def parse_key(key_arg: str) -> bytes:
    if key_arg.startswith('hex:'):
        hex_part = key_arg[4:]
        return bytes.fromhex(hex_part)
    return key_arg.encode('utf-8')


def parse_bytes_arg(arg: str) -> bytes:
    if arg.startswith('hex:'):
        return bytes.fromhex(arg[4:])
    return arg.encode('utf-8')


def build_packet(
    *,
    pdu_builder: Rssp2PduBuilder,
    message_type: int,
    sequence: int,
    user_data: bytes,
    tts: Optional[Tuple[int, int, int]],
    src_mac: bytes,
    dst_mac: bytes,
    src_ip: bytes,
    dst_ip: bytes,
    src_port: int,
    dst_port: int,
    invalidate: Optional[str] = None,
    ip_id: int = 0,
    ip_ttl: int = 64,
    udp_override_length: Optional[int] = None,
    ip_override_total_length: Optional[int] = None,
    override_data_len: Optional[int] = None,
    override_opts_len: Optional[int] = None,
    message_type_override: Optional[int] = None,
) -> bytes:
    override_protocol_id = None
    override_spi = None
    wrong_mac = False
    truncate_pdu: Optional[int] = None
    omit_tts = False
    bad_udp = False
    bad_ip = False
    udp_len_override: Optional[int] = udp_override_length
    ip_total_len_override: Optional[int] = ip_override_total_length
    data_len_override = override_data_len
    opts_len_override = override_opts_len
    msg_type = message_type_override if message_type_override is not None else message_type

    # Invalid scenario tweaks at PDU-level
    seq_to_use = sequence
    payload_to_use = user_data
    if invalidate == 'wrong_proto_id':
        override_protocol_id = b'\x00\x00'
    elif invalidate == 'wrong_spi':
        override_spi = pdu_builder.spi ^ 0x00000001
    elif invalidate == 'wrong_mac':
        wrong_mac = True
    elif invalidate == 'tampered_payload':
        # compute correct MAC first (by building), then tamper after
        pass
    elif invalidate == 'replay_seq':
        # repeat previous sequence number (caller should arrange)
        seq_to_use = max(0, sequence - 1)
    elif invalidate == 'non_monotonic_seq':
        seq_to_use = max(0, sequence - 2)
    elif invalidate == 'seq_jump_large':
        seq_to_use = sequence + 1_000_000
    elif invalidate == 'seq_wrap':
        seq_to_use = 0
    elif invalidate == 'truncated_pdu':
        truncate_pdu = 8  # arbitrarily short to break parsing
    elif invalidate == 'missing_timestamp':
        # 声称有TTS但实际不携带，用长度造不一致
        omit_tts = True
        opts_len_override = 24 if pdu_builder.tts_encoding == 'ns64' else 12
    elif invalidate == 'bad_udp_checksum':
        bad_udp = True
    elif invalidate == 'bad_ip_checksum':
        bad_ip = True
    elif invalidate == 'data_len_mismatch_short':
        data_len_override = max(0, len(user_data) - 1)
    elif invalidate == 'data_len_mismatch_long':
        data_len_override = len(user_data) + 5
    elif invalidate == 'udp_length_short':
        udp_len_override = 8 + max(0, (len(user_data) // 2))
    elif invalidate == 'udp_length_long':
        udp_len_override = 8 + len(user_data) + 20
    elif invalidate == 'ip_total_length_short':
        ip_total_len_override = 20 + max(0, (8 + len(user_data)) // 2)
    elif invalidate == 'ip_total_length_long':
        ip_total_len_override = 20 + 8 + len(user_data) + 100
    elif invalidate == 'msg_type_invalid':
        msg_type = 0xFF
    elif invalidate == 'opts_len_mismatch_short':
        opts_len_override = 0
    elif invalidate == 'opts_len_mismatch_long':
        opts_len_override = 255

    # Build PDU
    pdu = pdu_builder.build(
        message_type=msg_type,
        sequence=seq_to_use,
        user_data=payload_to_use,
        tts=tts,
        override_protocol_id=override_protocol_id,
        override_spi=override_spi,
        wrong_mac=wrong_mac,
        truncate_pdu=truncate_pdu,
        omit_tts=omit_tts,
        override_data_len=data_len_override,
        override_opts_len=opts_len_override,
    )

    if invalidate == 'tampered_payload':
        # Flip one bit in user data inside the PDU before MAC field
        # PDU layout: [proto(2) | type(1) | spi(4) | seq(8) | opts_len(1) | opts | data_len(2) | data | mac]
        # parse offsets generically
        proto_len = len(override_protocol_id if override_protocol_id is not None else pdu_builder.protocol_id)
        idx = proto_len
        if len(pdu) > idx:
            idx += 1  # msg_type
        idx += pdu_builder.spi_bytes
        idx += pdu_builder.seq_bytes
        if len(pdu) > idx:
            opts_len = pdu[idx]
        else:
            opts_len = 0
        idx += 1 + max(0, opts_len)
        if idx + 2 <= len(pdu):
            data_len = struct.unpack('!H', pdu[idx:idx+2])[0]
        else:
            data_len = 0
        idx += 2
        if data_len > 0 and idx + data_len + pdu_builder.mac_len <= len(pdu):
            tampered = bytearray(pdu)
            tampered[idx] ^= 0x01
            pdu = bytes(tampered)

    # UDP over IPv4 over Ethernet
    udp_segment = build_udp(src_ip, dst_ip, src_port, dst_port, pdu, bad_checksum=bad_udp, override_length=udp_len_override)
    ip_packet = build_ipv4(src_ip, dst_ip, udp_segment, ttl=ip_ttl, identification=ip_id, bad_checksum=bad_ip, override_total_length=ip_total_len_override)
    frame = build_ethernet(src_mac, dst_mac, 0x0800, ip_packet)
    return frame


# ----------------------------- CLI -----------------------------


def main():
    parser = argparse.ArgumentParser(description='Generate RSSP-II-like PDU traffic into a PCAP file (UDP/IPv4/Ethernet)')
    parser.add_argument('--out', required=True, help='Output PCAP file path')
    parser.add_argument('--mode', choices=['valid', 'invalid'], default='valid', help='Generate valid or invalid PDUs')
    parser.add_argument('--invalid-scenarios', default='', help='Comma-separated invalid scenarios; if empty and mode=invalid, a random one is used')
    parser.add_argument('--invalid-at', type=int, default=-1, help='Inject invalid scenario at this packet index (0-based). Default last packet')
    parser.add_argument('--count', type=int, default=5, help='Number of packets to generate')
    parser.add_argument('--src-mac', default='02:00:00:00:00:02')
    parser.add_argument('--dst-mac', default='02:00:00:00:00:01')
    parser.add_argument('--src-ip', default='10.0.0.2')
    parser.add_argument('--dst-ip', default='10.0.0.1')
    parser.add_argument('--src-port', type=int, default=60000)
    parser.add_argument('--dst-port', type=int, default=60001)
    parser.add_argument('--spi', type=lambda x: int(x, 0), default='0x11223344')
    parser.add_argument('--spi-bytes', type=int, choices=[4, 8], default=4, help='SPI field size in bytes (4 or 8)')
    parser.add_argument('--seq-bytes', type=int, choices=[4, 8], default=8, help='Sequence field size in bytes (4 or 8)')
    parser.add_argument('--proto-id', default='R2', help='Protocol ID bytes; ascii or hex:...')
    parser.add_argument('--key', default='hex:00112233445566778899aabbccddeeff', help='Key bytes; use hex:... for hex, otherwise UTF-8')
    parser.add_argument('--mac-len', type=int, default=16, help='MAC tag length (8-64)')
    parser.add_argument('--mac-algo', choices=['sha1','sha224','sha256','sha384','sha512','md5'], default='sha256', help='HMAC digest algorithm')
    parser.add_argument('--msg-type', type=lambda x: int(x, 0), default='0x01')
    parser.add_argument('--seq-start', type=lambda x: int(x, 0), default='1')
    parser.add_argument('--with-tts', action='store_true', help='Include TTS triple timestamps')
    parser.add_argument('--tts', default='', help='Manual TTS three ints in ns: t1,t2,t3 (decimal). Overrides --with-tts random')
    parser.add_argument('--tts-encoding', choices=['ns64','ms32'], default='ns64', help='TTS element encoding')
    parser.add_argument('--tts-endian', choices=['be','le'], default='be', help='TTS endianness')
    parser.add_argument('--payload-hex', default='', help='Hex payload for user data; if empty, random')
    parser.add_argument('--payload-size', type=int, default=12, help='Random payload size if --payload-hex empty')
    parser.add_argument('--ip-ttl', type=int, default=64)
    parser.add_argument('--interval-us', type=int, default=20000, help='Inter-packet interval in microseconds for timestamps in PCAP')

    args = parser.parse_args()

    src_mac = parse_mac(args.src_mac)
    dst_mac = parse_mac(args.dst_mac)
    src_ip = parse_ipv4(args.src_ip)
    dst_ip = parse_ipv4(args.dst_ip)

    key_bytes = parse_key(args.key)
    proto_id_bytes = parse_bytes_arg(args.proto_id)
    pdu_builder = Rssp2PduBuilder(
        key=key_bytes,
        spi=args.spi,
        protocol_id=proto_id_bytes,
        mac_len=args.mac_len,
        mac_algo=args.mac_algo,
        seq_bytes=args.seq_bytes,
        spi_bytes=args.spi_bytes,
        tts_encoding=args.tts_encoding,
        tts_endian=args.tts_endian,
    )

    invalid_list: List[str] = []
    if args.invalid_scenarios.strip():
        for s in args.invalid_scenarios.split(','):
            s = s.strip()
            if s:
                if s not in INVALID_SCENARIOS:
                    parser.error(f'Unknown invalid scenario: {s}. Allowed: {sorted(INVALID_SCENARIOS)}')
                invalid_list.append(s)
    elif args.mode == 'invalid':
        invalid_list = [random.choice(sorted(list(INVALID_SCENARIOS)))]

    # Determine when to inject invalids
    inject_map = {}
    if args.mode == 'invalid' and invalid_list:
        idx = args.invalid_at if args.invalid_at >= 0 else (args.count - 1)
        if idx < 0 or idx >= args.count:
            parser.error('--invalid-at is out of range')
        inject_map[idx] = invalid_list

    # TTS selection
    tts: Optional[Tuple[int, int, int]] = None
    if args.tts:
        try:
            t1s, t2s, t3s = args.tts.split(',')
            tts = (int(t1s), int(t2s), int(t3s))
        except Exception as e:
            parser.error('--tts must be t1,t2,t3 in decimal nanoseconds')
    elif args.with_tts:
        base = int(time.time_ns())
        tts = (base, base + 1_000_000, base + 2_000_000)

    # Payload
    if args.payload_hex:
        try:
            user_data = bytes.fromhex(args.payload_hex)
        except ValueError:
            parser.error('--payload-hex is not valid hex')
    else:
        user_data = rand_bytes(max(0, args.payload_size))

    # Build and write PCAP
    writer = PcapWriter(args.out)

    try:
        base_ts = time.time()
        seq = args.seq_start
        ip_id = random.randint(0, 0xFFFF)
        for i in range(args.count):
            invalidate_for_this = None
            if i in inject_map:
                # If multiple scenarios requested, apply them sequentially by building multiple frames
                for scenario in inject_map[i]:
                    frame = build_packet(
                        pdu_builder=pdu_builder,
                        message_type=args.msg_type,
                        sequence=seq,
                        user_data=user_data,
                        tts=tts,
                        src_mac=src_mac,
                        dst_mac=dst_mac,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                        src_port=args.src_port,
                        dst_port=args.dst_port,
                        invalidate=scenario,
                        ip_id=ip_id,
                        ip_ttl=args.ip_ttl,
                    )
                    ts = base_ts + (i * args.interval_us) / 1_000_000.0
                    writer.write_packet(frame, ts=ts)
                    ip_id = (ip_id + 1) & 0xFFFF

                # For scenarios like replay/non_monotonic, keep seq unchanged intentionally
                seq += 1
                continue

            # Normal valid frame
            frame = build_packet(
                pdu_builder=pdu_builder,
                message_type=args.msg_type,
                sequence=seq,
                user_data=user_data,
                tts=tts,
                src_mac=src_mac,
                dst_mac=dst_mac,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=args.src_port,
                dst_port=args.dst_port,
                invalidate=None,
                ip_id=ip_id,
                ip_ttl=args.ip_ttl,
            )
            ts = base_ts + (i * args.interval_us) / 1_000_000.0
            writer.write_packet(frame, ts=ts)
            ip_id = (ip_id + 1) & 0xFFFF
            seq += 1
    finally:
        writer.close()

    print(f'PCAP written to: {args.out}')


if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        sys.exit(130)

