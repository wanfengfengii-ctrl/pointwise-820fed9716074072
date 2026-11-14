#!/usr/bin/env python3
"""End-to-end demonstration of reassemble.collect on real generated captures.

Run with:  python3 -I tools/demo.py [wrap|full|fail]

  wrap  (default) the spec's sequence-wrap example, with a packet-by-packet
        trace showing how out-of-order bytes land before the prefix catches up
  full  reassemble the 32 MiB fragmented / reordered capture
  fail  show a conflict run preserving the pre-existing target file
"""

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import reassemble  # noqa: E402

FIX = os.path.join(ROOT, "fixtures")
RUN = os.path.join(FIX, "demo")
_TCP_SYN, _TCP_FIN = 0x02, 0x01


def _tcp_flags(pcap):
    """Lightweight scan yielding (seq, payload_len, flags) per TCP segment,
    waiting for complete IP datagrams like the real collector would.  Used
    only to print an understandable trace."""
    with open(pcap, "rb") as f:
        hdr = f.read(24)
        if len(hdr) != 24:
            return
        while True:
            rec = f.read(16)
            if len(rec) < 16:
                break
            _, _, incl, _ = struct.unpack("<IIII", rec)
            frame = f.read(incl)
            if len(frame) < 14 + 20:
                break
            ihl = (frame[14] & 0x0F) * 4
            flags_frag = struct.unpack_from(">H", frame, 14 + 6)[0]
            if flags_frag & 0x1FFF or (flags_frag >> 13) & 1:
                continue  # skip fragments in the demo trace
            ip = 14
            tcp = ip + ihl
            if len(frame) < tcp + 20:
                continue
            seq = struct.unpack_from(">I", frame, tcp + 4)[0]
            off_flags = struct.unpack_from(">H", frame, tcp + 12)[0]
            doff = (off_flags >> 12) * 4
            flags = off_flags & 0x1FF
            yield seq, len(frame) - (tcp + doff), flags


def demo_wrap():
    os.makedirs(RUN, exist_ok=True)
    pcap = os.path.join(FIX, "wrapsn.pcap")
    print("capture: fixtures/wrapsn.pcap (single connection, microsecond PCAP)")
    print("packet trace (fragments skipped; all datagrams are unfragmented):")
    for seq, plen, flags in _tcp_flags(pcap):
        kind = []
        if flags & _TCP_SYN:
            kind.append("SYN")
        if flags & _TCP_FIN:
            kind.append("FIN")
        kind.append("data=%d" % plen)
        print("  seq=%-10u %s" % (seq, " ".join(kind)))
    out = os.path.join(RUN, "upload.bin")
    if os.path.exists(out):
        os.unlink(out)
    n = reassemble.collect(pcap, out)
    with open(out, "rb") as f:
        content = f.read()
    print("collect() returned %d" % n)
    print("reassembled upload: %r" % content)
    assert n == 4 and content == b"abcd"


def demo_full():
    os.makedirs(RUN, exist_ok=True)
    pcap = os.path.join(FIX, "large32m.pcap")
    out = os.path.join(RUN, "upload32m.bin")
    if os.path.exists(out):
        os.unlink(out)
    size_in = os.path.getsize(pcap)
    print("capture: fixtures/large32m.pcap (%.1f MiB on the wire)"
          % (size_in / 1048576))
    n = reassemble.collect(pcap, out)
    print("collect() returned %d bytes (%.1f MiB upload)"
          % (n, n / 1048576))
    print("output:   %s" % out)
    with open(os.path.join(FIX, "large32m.expected"), "rb") as exp, \
            open(out, "rb") as got:
        ok = True
        while True:
            a, b = exp.read(65536), got.read(65536)
            if a != b:
                ok = False
                break
            if not a:
                break
    print("content matches streamed expected file: %s" % ok)
    assert ok and n == 32 * 1024 * 1024


def demo_fail():
    os.makedirs(RUN, exist_ok=True)
    pcap = os.path.join(FIX, "conflict_tcp.pcap")
    out = os.path.join(RUN, "protected.bin")
    with open(out, "wb") as f:
        f.write(b"pre-existing customer file - do not touch")
    before = os.stat(out)
    print("capture: fixtures/conflict_tcp.pcap (retransmitted bytes differ)")
    print("target before collect(): %r" % open(out, "rb").read())
    try:
        reassemble.collect(pcap, out)
    except ValueError as exc:
        print("collect() raised ValueError: %s" % exc)
    after = os.stat(out)
    print("target after  collect(): %r" % open(out, "rb").read())
    print("target inode unchanged (no replacement happened): %s"
          % (before.st_ino == after.st_ino))
    assert before.st_ino == after.st_ino


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else "wrap"
    if not os.path.isdir(FIX):
        print("fixtures missing -- run: python3 -I tools/make_fixtures.py")
        return 2
    print("=== reassemble.collect demo (%s) ===" % mode)
    if mode == "wrap":
        demo_wrap()
    elif mode == "full":
        demo_full()
    elif mode == "fail":
        demo_fail()
    else:
        print("unknown mode %r; choose wrap, full or fail" % mode)
        return 2
    print("demo OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
