"""Minimal classic microsecond PCAP writer used to build test captures.

Only the structures needed by this task are emitted: little-endian global
header, Ethernet II frames, option-less IPv4 and TCP.  Checksums are left
zero because ``reassemble.collect`` does not validate them.
"""

import struct
import time

PCAP_MAGIC = 0xA1B2C3D4
ETH_P_IP = 0x0800
DST_MAC = b"\x02\x00\x00\x00\x00\x01"
SRC_MAC = b"\x02\x00\x00\x00\x00\x02"
SRC_IP = bytes([10, 0, 0, 1])
DST_IP = bytes([10, 0, 0, 2])
IPPROTO_TCP = 6
SPORT = 12345
DPORT = 8080

_GLOBAL = struct.Struct("<IHHiIII")
_RECORD = struct.Struct("<IIII")
_ETH = struct.Struct("!6s6sH")
_IP = struct.Struct("!BBHHHBBH4s4s")
_TCP = struct.Struct("!HHIIHHHH")


def global_header():
    return _GLOBAL.pack(PCAP_MAGIC, 2, 4, 0, 0, 65535, 1)


def tcp_segment(seq, payload=b"", syn=False, fin=False, ack=False):
    """Build an option-less TCP segment (header + payload)."""
    flags = ((1 if fin else 0) << 0) | ((1 if syn else 0) << 1) | \
        (0x10 if ack else 0)
    offset_flags = (5 << 12) | flags
    header = _TCP.pack(SPORT, DPORT, seq, 0, offset_flags, 65535, 0, 0)
    return header + payload


def ip_datagram(ip_id, tcp_bytes, df=False):
    """Wrap a TCP segment in one unfragmented IPv4 datagram."""
    total_len = 20 + len(tcp_bytes)
    flags_frag = (1 << 14) if df else 0
    header = _IP.pack(
        0x45, 0, total_len, ip_id, flags_frag, 64, IPPROTO_TCP, 0,
        SRC_IP, DST_IP,
    )
    return header + tcp_bytes


def ip_fragment(ip_id, frag_off, more, payload):
    """Build one IPv4 fragment carrying raw IP-level payload bytes."""
    total_len = 20 + len(payload)
    flags_frag = (1 << 13 if more else 0) | (frag_off & 0x1FFF)
    header = _IP.pack(
        0x45, 0, total_len, ip_id, flags_frag, 64, IPPROTO_TCP, 0,
        SRC_IP, DST_IP,
    )
    return header + payload


def fragment_frames(ip_id, datagram, mtu_payload=512):
    """Split a full IP datagram into Ethernet frames carrying 8-byte-aligned
    fragment payloads (except the last)."""
    inner = datagram[20:]  # IP datagram payload (the TCP segment)
    frames = []
    off = 0
    while off < len(inner):
        chunk = inner[off:off + mtu_payload]
        more = 1 if off + mtu_payload < len(inner) else 0
        frag = ip_fragment(ip_id, off // 8, more, chunk)
        frames.append(ethernet_frame(frag))
        off += mtu_payload
    return frames


def ethernet_frame(ip_packet):
    return _ETH.pack(DST_MAC, SRC_MAC, ETH_P_IP) + ip_packet


class PcapWriter:
    """Writes frames into a classic PCAP file with monotonic timestamps."""

    def __init__(self, path):
        self._f = open(path, "wb")
        self._f.write(global_header())
        self._t = int(time.time())
        self._n = 0

    def write_frame(self, frame):
        self._n += 1
        self._f.write(
            _RECORD.pack(self._t, self._n, len(frame), len(frame))
        )
        self._f.write(frame)

    def write_frames(self, frames):
        for frame in frames:
            self.write_frame(frame)

    def close(self):
        self._f.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
