"""Stream reassembly of an uploaded file from a classic microsecond PCAP.

The input is a little-endian, microsecond-resolution classic PCAP containing
Ethernet II / IPv4 / TCP frames from a single one-way connection.  Both IPv4
fragmentation (out-of-order, duplicated or overlapping fragments) and TCP
segment reordering / retransmission with 32-bit sequence-number wrap-around
are handled.

Only the standard library is used.  The design keeps no whole-stream buffer
in memory and no per-byte index:

* the contiguous, in-order prefix of the TCP stream is appended to a
  temporary file after *every* packet that extends it (including retransmitted
  bytes, which are checked against what was already written);
* incomplete IPv4 datagrams and out-of-order TCP payloads are kept in
  bounded dictionaries keyed by offset, each holding at most one segment per
  hole (at most 64 KiB of payload in each layer under the target workload);
* PCAP records are parsed one at a time through a small fixed-size read buffer.

On success the temporary file is atomically moved to ``out_path`` and the
number of payload bytes is returned.  Any failure leaves ``out_path``
untouched.  ``ValueError`` is raised on:

* a gap at EOF (missing fragment, missing segment or missing FIN)
  -- the message contains ``gap``;
* a byte-level conflict in any overlap -- the message contains ``conflict``;
* a truncated input file -- the message contains ``truncated``.
"""

import os
import struct
import tempfile

# ---- fixed protocol sizes / constants -------------------------------------

_PCAP_GLOBAL = struct.Struct("<IHHiIII")
_PCAP_RECORD = struct.Struct("<IIII")
_ETH_HDR = 14
_ETH_TYPE_IPV4 = 0x0800
_IP_MIN_HDR = 20
_TCP_MIN_HDR = 20
_TCP_FIN = 0x01
_TCP_SYN = 0x02
_READ_CHUNK = 65536


def _read_exact(buf, n, what):
    """Read exactly *n* bytes from the buffered reader or raise truncated."""
    data = buf.read(n)
    if len(data) != n:
        raise ValueError(
            "truncated input: %s needs %d more bytes" % (what, n - len(data))
        )
    return data


def _insert_chunk(chunks, start, data, layer):
    """Merge ``data`` covering ``[start, start+len(data))`` into ``chunks``.

    ``chunks`` maps an absolute offset to the contiguous payload beginning at
    that offset.  Overlaps must be byte-identical; otherwise a ``conflict``
    ValueError is raised.  Exactly identical pieces collapse to nothing.
    Returns True when at least one new byte was inserted.
    """
    if not data:
        return False
    end = start + len(data)
    # Check overlaps first: reject on the first differing byte.
    for off, piece in chunks.items():
        piece_end = off + len(piece)
        common = min(end, piece_end) - max(start, off)
        if common > 0:
            a = data[max(0, off - start):max(0, off - start) + common]
            b = piece[max(0, start - off):max(0, start - off) + common]
            if a != b:
                raise ValueError(
                    "%s overlap conflict at byte %d" % (layer, max(start, off))
                )
    # Absorb into an existing piece when we touch it (overlap guaranteed equal
    # above, or exact adjacency).
    for off, piece in list(chunks.items()):
        piece_end = off + len(piece)
        if off <= end and start <= piece_end:
            new_start = min(start, off)
            new_end = max(end, piece_end)
            merged = bytearray(new_end - new_start)
            merged[off - new_start:off - new_start + len(piece)] = piece
            merged[start - new_start:start - new_start + len(data)] = data
            chunks.pop(off)
            chunks[new_start] = bytes(merged)
            start, end, data = new_start, new_end, bytes(merged)
    # Drop any pieces fully contained in the (possibly grown) data range.
    for off in [off for off, piece in chunks.items()
                if start <= off and off + len(piece) <= end and off != start]:
        chunks.pop(off)
    if start not in chunks:
        chunks[start] = data
    return True


class _IpReassembler:
    """Reassembles IPv4 datagrams from fragments, per datagram id.

    The capture carries a single connection and datagram ids are never
    reused.  Because ids are 16-bit, completed datagrams are remembered in a
    fixed 65536-slot unsigned-short array (0 == never seen) rather than a
    growing dict, which keeps long-lived allocation flat regardless of the
    number of datagrams.  Only *incomplete* datagrams hold payload, in
    ``self._flows``.
    """

    def __init__(self):
        from array import array
        # ip id -> reassembled IP-payload length once complete, else 0
        self._done_len = array("H", [0]) * 65536
        # ip id -> {"total": int|None, "chunks": {offset: payload}}
        self._flows = {}

    def handle(self, src, dst, ip_id, more_frags, frag_off, payload):
        """Feed one fragment; return full datagram payload or None."""
        offset = frag_off * 8
        done_len = self._done_len[ip_id]

        if more_frags == 0 and frag_off == 0:
            # Unfragmented datagram: its full length is known immediately.
            if done_len or ip_id in self._flows:
                raise ValueError("conflict: reused IPv4 datagram id %d" % ip_id)
            self._done_len[ip_id] = len(payload)
            return payload

        if done_len:
            # Late fragment for an already delivered datagram.  Accept only a
            # byte position that actually existed in that datagram; a byte
            # beyond it cannot be a legitimate duplicate.
            if offset + len(payload) > done_len:
                raise ValueError(
                    "conflict: late fragment beyond datagram %d" % ip_id
                )
            return None

        flow = self._flows.get(ip_id)
        if flow is None:
            flow = {"total": None, "chunks": {}}
            self._flows[ip_id] = flow

        if more_frags == 0:
            total = offset + len(payload)
            if flow["total"] is not None and flow["total"] != total:
                raise ValueError(
                    "conflict: inconsistent datagram length for id %d" % ip_id
                )
            if total > 65535:
                raise ValueError("conflict: IPv4 datagram exceeds 65535 bytes")
            flow["total"] = total

        _insert_chunk(flow["chunks"], offset, payload, "IPv4 fragment")

        total = flow["total"]
        if total is None:
            return None

        # Full coverage means all holes are closed from 0 to total.
        if 0 not in flow["chunks"]:
            return None
        if len(flow["chunks"]) != 1:
            return None
        only = flow["chunks"][0]
        if len(only) != total:
            return None

        del self._flows[ip_id]
        self._done_len[ip_id] = total
        return only

    def open_count(self):
        return len(self._flows)


class _TcpStream:
    """Tracks the one TCP direction: ISN, prefix file, FIN and reordering.

    Coordinate convention: the SYN consumes relative offset 0, so the first
    payload byte lives at relative offset 1 and file index 0.  ``written`` is
    the number of payload bytes already on disk; the next expected payload
    offset is therefore ``written + 1``.
    """

    def __init__(self, tmp_file):
        self.isn = None                 # sequence number of the SYN
        self.written = 0                # contiguous payload bytes on disk
        self.fin_relative = None        # FIN sequence relative to ISN
        self.pending = {}               # relative offset -> payload bytes
        self.tmp = tmp_file             # open binary file holding the prefix

    @staticmethod
    def _rel(isn, seq):
        """Absolute sequence -> offset relative to the ISN, handling wrap."""
        return (seq - isn) & 0xFFFFFFFF

    def segment(self, seq, flags, payload):
        # SYN (no payload, per the contract) fixes the initial sequence number.
        if flags & _TCP_SYN:
            if payload:
                raise ValueError("conflict: SYN segment carries payload")
            if self.isn is not None and self.isn != seq:
                raise ValueError("conflict: duplicate SYN with new sequence")
            if self.isn is None:
                self.isn = seq
            return

        if self.isn is None:
            raise ValueError("conflict: data before SYN")

        rel = self._rel(self.isn, seq)
        length = len(payload)
        want = self.written + 1  # relative offset of the next needed byte

        if length and rel == 0:
            # Offset 0 belongs to the SYN; a payload cannot start there.
            raise ValueError("conflict: payload segment claims SYN sequence")

        if length:
            if rel >= want:
                # Entirely in the future (rel == want) or after a hole.
                _insert_chunk(self.pending, rel, payload, "TCP segment")
            else:
                # Starts inside the on-disk prefix: every overlapping byte of
                # a retransmission must equal what the file already holds.
                overlap = min(self.written + 1 - rel, length)
                self.tmp.seek(rel - 1)
                on_disk = self.tmp.read(overlap)
                if on_disk != payload[:overlap]:
                    raise ValueError(
                        "conflict: retransmission mismatch at byte %d" % rel
                    )
                self.tmp.seek(0, os.SEEK_END)
                if length > overlap:
                    # Tail is new; it begins exactly at the prefix edge.
                    _insert_chunk(
                        self.pending, want, payload[overlap:], "TCP segment"
                    )
            self._flush()

            if (self.fin_relative is not None
                    and rel + length > self.fin_relative):
                raise ValueError("conflict: data segment crosses FIN")

        if flags & _TCP_FIN:
            if length:
                raise ValueError("conflict: FIN segment carries payload")
            fin_rel = rel
            if self.fin_relative is not None and self.fin_relative != fin_rel:
                raise ValueError("conflict: FIN with inconsistent sequence")
            self.fin_relative = fin_rel
            # Data past the FIN position is impossible.
            if fin_rel < self.written + 1:
                raise ValueError("conflict: FIN before already written data")
            for off, piece in self.pending.items():
                if off + len(piece) > fin_rel:
                    raise ValueError("conflict: data segment crosses FIN")

    def _flush(self):
        """Append buffered pieces that continue the contiguous prefix.

        ``_insert_chunk`` coalesces adjacent/overlapping pieces, so a piece
        keyed at the wanted offset may already span several segments.
        """
        want = self.written + 1
        while want in self.pending:
            piece = self.pending.pop(want)
            self.tmp.write(piece)
            self.written += len(piece)
            want = self.written + 1

    def finish(self):
        """EOF validation. Raises on gaps / missing FIN; returns byte count."""
        if self.isn is None:
            raise ValueError("gap: no SYN observed")
        if self.fin_relative is None:
            raise ValueError("gap: no FIN observed before EOF")
        # FIN sits one sequence number beyond the last payload byte.
        missing = self.fin_relative - (self.written + 1)
        if missing != 0:
            raise ValueError(
                "gap: %d byte(s) missing between prefix and FIN" % missing
            )
        return self.written


def _process_frame(frame, ip_reasm, tcp):
    """Parse one Ethernet frame and feed the reassembly state machines."""
    if len(frame) < _ETH_HDR:
        raise ValueError("truncated input: Ethernet header incomplete")
    eth_type = struct.unpack_from(">H", frame, 12)[0]
    if eth_type != _ETH_TYPE_IPV4:
        return  # non-IPv4 traffic is ignored

    packet = frame[_ETH_HDR:]
    if len(packet) < _IP_MIN_HDR:
        raise ValueError("truncated input: IPv4 header incomplete")
    ver_ihl, tos, total_len, ip_id, flags_frag, ttl, proto, checksum = (
        struct.unpack_from(">BBHHHBBH", packet, 0)
    )
    if ver_ihl >> 4 != 4:
        raise ValueError("conflict: Ethernet type IPv4 but IP version != 4")
    ihl = (ver_ihl & 0x0F) * 4
    if ihl < _IP_MIN_HDR or len(packet) < ihl:
        raise ValueError("truncated input: IPv4 header length exceeds frame")
    src = packet[12:16]
    dst = packet[16:20]
    if len(packet) < total_len:
        raise ValueError("truncated input: IPv4 total length exceeds frame")
    ip_payload = packet[ihl:total_len]  # no Ethernet padding considered

    more_frags = (flags_frag >> 13) & 1
    frag_off = flags_frag & 0x1FFF

    datagram = ip_reasm.handle(
        src, dst, ip_id, more_frags, frag_off, ip_payload
    )
    if datagram is None:
        return  # datagram still incomplete
    if proto != 6:
        return  # only TCP carries the upload

    if len(datagram) < _TCP_MIN_HDR:
        raise ValueError("truncated input: TCP header incomplete")
    sport, dport, seq, ack, off_flags, win, check, urg = struct.unpack_from(
        ">HHIIHHHH", datagram, 0
    )
    data_off = (off_flags >> 12) * 4
    flags = off_flags & 0x01FF
    if data_off < _TCP_MIN_HDR or len(datagram) < data_off:
        raise ValueError("truncated input: TCP data offset exceeds segment")
    tcp_payload = datagram[data_off:]
    tcp.segment(seq, flags, tcp_payload)


def collect(pcap_path, out_path):
    """Reassemble the uploaded file from ``pcap_path`` into ``out_path``.

    Returns the number of payload bytes written.  Raises ValueError on any
    gap, overlap conflict or truncated capture; in every failure case the
    previous ``out_path`` (if any) is left untouched.
    """
    out_dir = os.path.dirname(os.path.abspath(out_path))
    tmp_fd, tmp_name = tempfile.mkstemp(
        prefix=".reassemble-", suffix=".tmp", dir=out_dir
    )
    tmp_file = os.fdopen(tmp_fd, "r+b", buffering=0)
    try:
        with open(pcap_path, "rb", buffering=_READ_CHUNK) as src:
            header = _read_exact(src, _PCAP_GLOBAL.size, "PCAP global header")
            magic, ver_major, ver_minor, tz, sigfigs, snaplen, linktype = (
                _PCAP_GLOBAL.unpack(header)
            )
            if magic != 0xA1B2C3D4:
                raise ValueError(
                    "conflict: unsupported PCAP magic 0x%08X "
                    "(little-endian microsecond classic PCAP required)" % magic
                )
            if linktype != 1:
                raise ValueError(
                    "conflict: linktype %d is not Ethernet (1)" % linktype
                )

            ip_reasm = _IpReassembler()
            tcp = _TcpStream(tmp_file)

            while True:
                rec = src.read(_PCAP_RECORD.size)
                if not rec:
                    break  # clean EOF
                if len(rec) != _PCAP_RECORD.size:
                    raise ValueError(
                        "truncated input: PCAP record header incomplete"
                    )
                ts_sec, ts_usec, incl_len, orig_len = _PCAP_RECORD.unpack(rec)
                if incl_len > orig_len:
                    raise ValueError(
                        "truncated input: captured length exceeds original"
                    )
                frame = _read_exact(src, incl_len, "PCAP frame payload")
                _process_frame(frame, ip_reasm, tcp)

            # ---- EOF: everything must be complete -------------------------
            if ip_reasm.open_count():
                raise ValueError(
                    "gap: %d IPv4 datagram(s) missing fragments at EOF"
                    % ip_reasm.open_count()
                )
            total = tcp.finish()  # raises gap on missing FIN / missing bytes

            tmp_file.flush()
            os.fsync(tmp_file.fileno())
        os.replace(tmp_name, out_path)  # atomic replacement
        tmp_name = None
        return total
    finally:
        try:
            tmp_file.close()
        except Exception:
            pass
        if tmp_name is not None and os.path.exists(tmp_name):
            try:
                os.unlink(tmp_name)
            except OSError:
                pass
