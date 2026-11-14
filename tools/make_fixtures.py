#!/usr/bin/env python3
"""Generate all PCAP fixtures and expected-output files used for verification.

Run with:  python3 -I tools/make_fixtures.py
All generated data goes into ./fixtures (created fresh), never next to code.
"""

import os
import shutil
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pcap_build as pb  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
FIX = os.path.join(ROOT, "fixtures")


def _path(name):
    return os.path.join(FIX, name)


def _writer(name):
    return pb.PcapWriter(_path(name))


def make_wrap():
    """Spec example: SYN seq 2^32-2; data seq 1 arrives before seq 2^32-1."""
    isn = 4294967294  # -2 mod 2^32
    with _writer("wrapsn.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        # First on the wire: relative offset 3 -> absolute seq 1 ('cd'),
        # buffered as a pending hole because rel 1 is missing.
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            2, pb.tcp_segment((isn + 3) & 0xFFFFFFFF, b"cd"))))
        # Then: relative offset 1 -> absolute seq 2^32-1 ('ab'); this fills
        # the hole and the whole prefix flushes in order -> b'abcd'.
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            3, pb.tcp_segment((isn + 1) & 0xFFFFFFFF, b"ab"))))
        # FIN at relative offset 5 (4 payload bytes occupy rel 1..4; the FIN
        # consumes its own sequence number); absolute seq is 3 after wrap
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            4, pb.tcp_segment((isn + 5) & 0xFFFFFFFF, fin=True))))
    with open(_path("wrapsn.expected"), "wb") as f:
        f.write(b"abcd")


def make_order():
    """Plain reordering plus a retransmission of already-written bytes."""
    isn = 1000
    payload = b"The quick brown fox jumps over the lazy dog. " * 4
    segs = [payload[i:i + 17] for i in range(0, len(payload), 17)]
    with _writer("order.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        order = list(range(len(segs)))
        order[1], order[2] = order[2], order[1]  # swap two middle segments
        for i in order:
            seq = (isn + 1 + 17 * i) & 0xFFFFFFFF
            w.write_frame(pb.ethernet_frame(pb.ip_datagram(
                10 + i, pb.tcp_segment(seq, segs[i]))))
        # late retransmission of the first 10 bytes, checked against the file
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            90, pb.tcp_segment((isn + 1) & 0xFFFFFFFF, payload[:10]))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            99, pb.tcp_segment((isn + 1 + len(payload)) & 0xFFFFFFFF,
                               fin=True))))
    with open(_path("order.expected"), "wb") as f:
        f.write(payload)


def make_frag_mix():
    """Fragmented datagrams: reordered fragments, duplicates and overlaps."""
    isn = 5000
    body = bytes(range(256)) * 12  # 3072 bytes, split over two datagrams
    part0, part1 = body[:1500], body[1500:]  # 1500 + 1572 = 3072
    with _writer("fragmix.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))

        # Datagram 7: first 1500 payload bytes, fragmented in 96-byte pieces,
        # sent in reverse order, plus an exact duplicate of a middle fragment.
        dgram0 = pb.ip_datagram(7, pb.tcp_segment(
            (isn + 1) & 0xFFFFFFFF, part0))
        frames0 = pb.fragment_frames(7, dgram0, mtu_payload=96)
        for frame in reversed(frames0):
            w.write_frame(frame)
        w.write_frame(frames0[1])  # exact duplicate

        # Datagram 8: the remaining 1572 payload bytes.  Full 88-byte-aligned
        # fragmentation, then an extra overlapping fragment whose bytes are
        # identical to the ones already covering that range.
        dgram1 = pb.ip_datagram(8, pb.tcp_segment(
            (isn + 1 + len(part0)) & 0xFFFFFFFF, part1))
        inner1 = dgram1[20:]
        step = 88
        pos = 0
        while pos < len(inner1):
            chunk = inner1[pos:pos + step]
            more = 1 if pos + step < len(inner1) else 0
            w.write_frame(pb.ethernet_frame(
                pb.ip_fragment(8, pos // 8, more, chunk)))
            pos += step
        # Extra fragment covering inner offsets [40, 88): every byte also
        # appears in the first two fragments, so the overlap must be accepted.
        w.write_frame(pb.ethernet_frame(
            pb.ip_fragment(8, 5, 1, inner1[40:88])))

        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            9, pb.tcp_segment(
                (isn + 1 + len(part0) + len(part1)) & 0xFFFFFFFF,
                fin=True))))
    with open(_path("fragmix.expected"), "wb") as f:
        f.write(body)


def make_conflicts():
    isn = 700
    good = b"0123456789ABCDEF"

    # TCP-level conflict (retransmission of written prefix with wrong bytes)
    with _writer("conflict_tcp.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            2, pb.tcp_segment((isn + 1) & 0xFFFFFFFF, good))))
        bad = b"XXXXXXXX" + good[8:]
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            3, pb.tcp_segment((isn + 1) & 0xFFFFFFFF, bad))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            4, pb.tcp_segment((isn + 17) & 0xFFFFFFFF, fin=True))))

    # TCP conflict entirely inside pending (out-of-order) segments
    with _writer("conflict_tcp_pending.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            2, pb.tcp_segment((isn + 11) & 0xFFFFFFFF, good[10:]))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            3, pb.tcp_segment((isn + 1) & 0xFFFFFFFF, b"WRONG BYTES!!"))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            4, pb.tcp_segment((isn + 17) & 0xFFFFFFFF, fin=True))))

    # IPv4 fragment overlap conflict
    dgram = pb.ip_datagram(5, pb.tcp_segment(
        (isn + 1) & 0xFFFFFFFF, good))
    inner = dgram[20:]
    with _writer("conflict_ip.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        w.write_frame(pb.ethernet_frame(pb.ip_fragment(
            5, 0, 1, inner[:12])))
        w.write_frame(pb.ethernet_frame(pb.ip_fragment(
            5, 1, 0, b"ZZZZ" + inner[12:])))  # offset 8, bytes 8-11 differ
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            6, pb.tcp_segment((isn + 17) & 0xFFFFFFFF, fin=True))))


def make_gap_frag():
    """One fragment of a datagram is never sent."""
    isn = 900
    dgram = pb.ip_datagram(7, pb.tcp_segment((isn + 1) & 0xFFFFFFFF, b"hi"))
    inner = dgram[20:]
    with _writer("gap_frag.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        w.write_frame(pb.ethernet_frame(pb.ip_fragment(7, 0, 1, inner[:8])))
        # middle/last fragment omitted
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            8, pb.tcp_segment((isn + 3) & 0xFFFFFFFF, fin=True))))


def make_gap_tcp():
    """A TCP segment is missing; prefix written, FIN beyond the hole."""
    isn = 1100
    with _writer("gap_tcp.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            2, pb.tcp_segment((isn + 1) & 0xFFFFFFFF, b"abc"))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            3, pb.tcp_segment((isn + 7) & 0xFFFFFFFF, b"gh"))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            4, pb.tcp_segment((isn + 9) & 0xFFFFFFFF, fin=True))))


def make_nofin():
    """Complete data but no FIN before EOF -> gap."""
    isn = 1300
    with _writer("nofin.pcap") as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            2, pb.tcp_segment((isn + 1) & 0xFFFFFFFF, b"payload"))))


def make_truncated():
    """Valid global header and one full record, then a cut-off record."""
    isn = 1500
    path = _path("truncated.pcap")
    with pb.PcapWriter(path) as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        w._f.write(pb._RECORD.pack(w._t, 99, 60, 60))  # header only, no frame
    # also a file cut off inside the global header
    with open(_path("truncated_header.pcap"), "wb") as f:
        f.write(pb.global_header()[:7])


def make_large():
    """32 MiB upload: reordered fragmented datagrams, duplicates, retransmits.

    Streamed to disk in small pieces; the generator itself never holds the
    whole 32 MiB.  Sequence numbers wrap around the 32-bit space.
    """
    size = 32 * 1024 * 1024
    isn = 0xFFFFFFF0  # wraps after 16 payload bytes
    seg_len = 1400         # TCP payload per segment (datagram count < 2^16,
                           # so IPv4 ids are never reused)
    mtu_payload = 96       # fragment payload (multiple of 8)

    def fill(chunk_no, n):
        # Deterministic, repeating 251-byte pattern (251 is prime, so offsets
        # are easy to verify independently).
        base = chunk_no * seg_len
        return bytes(((base + i) * 7 + 3) % 251 for i in range(n))

    nseg = (size + seg_len - 1) // seg_len
    path = _path("large32m.pcap")
    with pb.PcapWriter(path) as w:
        w.write_frame(pb.ethernet_frame(
            pb.ip_datagram(1, pb.tcp_segment(isn, syn=True))))
        ip_id = 100
        for group_start in range(0, nseg, 4):
            idxs = list(range(group_start, min(group_start + 4, nseg)))
            swapped = list(reversed(idxs))  # reverse each group of 4
            for i in swapped:
                offset = i * seg_len
                n = min(seg_len, size - offset)
                data = fill(i, n)
                seq = (isn + 1 + offset) & 0xFFFFFFFF
                dgram = pb.ip_datagram(ip_id, pb.tcp_segment(seq, data))
                ip_id += 1
                frames = pb.fragment_frames(ip_id - 1, dgram, mtu_payload)
                # swap the first two fragment frames when there are >= 2
                if len(frames) >= 2:
                    frames[0], frames[1] = frames[1], frames[0]
                w.write_frames(frames)
                # retransmit the first 32 bytes of the first segment in each
                # group once it is likely already on disk (previous groups)
                if i == idxs[0] and group_start > 0:
                    rt = fill(i, min(32, n))
                    w.write_frame(pb.ethernet_frame(pb.ip_datagram(
                        ip_id, pb.tcp_segment(seq, rt))))
                    ip_id += 1
        fin_seq = (isn + 1 + size) & 0xFFFFFFFF
        w.write_frame(pb.ethernet_frame(pb.ip_datagram(
            ip_id, pb.tcp_segment(fin_seq, fin=True))))

    # Expected output is also streamed, not materialised as one bytes object.
    with open(_path("large32m.expected"), "wb") as f:
        done = 0
        chunk_no = 0
        while done < size:
            n = min(seg_len, size - done)
            f.write(fill(chunk_no, n))
            done += n
            chunk_no += 1


def main():
    if os.path.exists(FIX):
        for name in sorted(os.listdir(FIX)):
            target = os.path.join(FIX, name)
            if os.path.isdir(target):
                shutil.rmtree(target)
            else:
                os.unlink(target)
    else:
        os.makedirs(FIX)
    make_wrap()
    make_order()
    make_frag_mix()
    make_conflicts()
    make_gap_frag()
    make_gap_tcp()
    make_nofin()
    make_truncated()
    make_large()
    for name in sorted(os.listdir(FIX)):
        st = os.stat(os.path.join(FIX, name))
        print("%-28s %10d bytes" % (name, st.st_size))


if __name__ == "__main__":
    main()
