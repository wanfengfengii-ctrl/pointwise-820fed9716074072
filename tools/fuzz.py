#!/usr/bin/env python3
"""Randomized differential test against a simple in-memory reference.

Each round builds a random upload, emits it as a fragmented/reordered PCAP,
and compares reassemble.collect with a naive reference that keeps every byte
in a dict and only succeeds when [1 .. last+1) is fully, consistently covered.
Run with: python3 -I tools/fuzz.py
"""

import os
import random
import shutil
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import pcap_build as pb  # noqa: E402
import reassemble  # noqa: E402

RUN = os.path.join(ROOT, "fixtures", "fuzz")


def reference(bytes_at, last_rel, seen_syn):
    """Naive reassembly: dict rel-offset -> byte. Returns bytes or raises."""
    if not seen_syn:
        raise ValueError("no syn")
    if last_rel is None:
        raise ValueError("no fin")
    out = bytearray()
    for rel in range(1, last_rel):
        if rel not in bytes_at:
            raise ValueError("gap at %d" % rel)
        out.append(bytes_at[rel])
    return bytes(out)


def one_round(rng, round_no):
    size = rng.randint(0, 4000)
    data = bytes(rng.randrange(256) for _ in range(size))
    isn = rng.randrange(1 << 32)
    # Split the upload into TCP segments of random lengths.
    bounds = [0]
    while bounds[-1] < size:
        bounds.append(min(size, bounds[-1] + rng.randint(1, 700)))
    segments = [(bounds[i], data[bounds[i]:bounds[i + 1]])
                for i in range(len(bounds) - 1)]

    frames = []
    ip_id = 1
    # SYN
    frames.append(pb.ethernet_frame(
        pb.ip_datagram(ip_id, pb.tcp_segment(isn, syn=True))))
    ip_id += 1

    bytes_at = {}
    emitted = list(segments)
    rng.shuffle(emitted)
    for off, chunk in emitted:
        cur_id = ip_id
        ip_id += 1
        seq = (isn + 1 + off) & 0xFFFFFFFF
        seg = pb.tcp_segment(seq, chunk)
        dgram = pb.ip_datagram(cur_id, seg)
        inner = dgram[20:]
        step = rng.choice([8, 24, 88, 256])
        if rng.random() < 0.5 and len(inner) > step:
            # Fragment this datagram with a random 8-aligned step.  Only do
            # so when it really yields >1 fragment; a lone (off=0, MF=0)
            # piece is indistinguishable from an unfragmented datagram.
            pos = 0
            frags = []
            while pos < len(inner):
                part = inner[pos:pos + step]
                more = 1 if pos + step < len(inner) else 0
                frags.append(pb.ethernet_frame(
                    pb.ip_fragment(cur_id, pos // 8, more, part)))
                pos += step
            rng.shuffle(frags)
            frames.extend(frags)
            if rng.random() < 0.3 and frags:
                frames.append(rng.choice(frags))  # exact duplicate fragment
        else:
            frames.append(pb.ethernet_frame(dgram))
        for i, byte in enumerate(chunk):
            rel = off + i + 1
            if rel in bytes_at and bytes_at[rel] != byte:
                raise AssertionError("test generator produced a conflict")
            bytes_at[rel] = byte
        if rng.random() < 0.2 and chunk:
            # Exact retransmission of a prefix of this segment.
            k = rng.randint(1, len(chunk))
            frames.append(pb.ethernet_frame(pb.ip_datagram(
                ip_id, pb.tcp_segment(seq, chunk[:k]))))
            ip_id += 1

    fin_seq = (isn + 1 + size) & 0xFFFFFFFF
    frames.append(pb.ethernet_frame(
        pb.ip_datagram(ip_id, pb.tcp_segment(fin_seq, fin=True))))

    pcap = os.path.join(RUN, "case.pcap")
    with pb.PcapWriter(pcap) as w:
        w.write_frames(frames)

    out = os.path.join(RUN, "case.out")
    if os.path.exists(out):
        os.unlink(out)
    got_n = reassemble.collect(pcap, out)
    with open(out, "rb") as f:
        got = f.read()
    expect = reference(bytes_at, size + 1, True)
    assert got == expect == data, "content mismatch round %d" % round_no
    assert got_n == size, "length mismatch round %d" % round_no


def one_conflict_round(rng, round_no):
    """Build a valid capture, then corrupt one overlapping byte; expect
    a ValueError containing 'conflict' and an untouched output target."""
    size = rng.randint(50, 1500)
    data = bytes(rng.randrange(256) for _ in range(size))
    isn = rng.randrange(1 << 32)
    frames = []
    ip_id = 1
    frames.append(pb.ethernet_frame(
        pb.ip_datagram(ip_id, pb.tcp_segment(isn, syn=True))))
    ip_id += 1

    # Two segments covering the whole upload, with an overlapping middle:
    # seg A covers [0, size), seg B covers [size//2, size//2+40) with one
    # byte flipped -> TCP-level conflict inside pending segments.
    seq_a = (isn + 1) & 0xFFFFFFFF
    frames.append(pb.ethernet_frame(pb.ip_datagram(
        ip_id, pb.tcp_segment(seq_a, data))))
    ip_id += 1
    overlap_off = size // 2
    bad = bytearray(data[overlap_off:overlap_off + 40])
    bad[0] ^= 0xFF
    seq_b = (isn + 1 + overlap_off) & 0xFFFFFFFF
    frames.append(pb.ethernet_frame(pb.ip_datagram(
        ip_id, pb.tcp_segment(seq_b, bytes(bad)))))
    ip_id += 1
    frames.append(pb.ethernet_frame(pb.ip_datagram(
        ip_id, pb.tcp_segment((isn + 1 + size) & 0xFFFFFFFF, fin=True))))

    pcap = os.path.join(RUN, "conflict.pcap")
    with pb.PcapWriter(pcap) as w:
        w.write_frames(frames)
    out = os.path.join(RUN, "conflict.out")
    sentinel = b"keep-me" * 8
    with open(out, "wb") as f:
        f.write(sentinel)
    try:
        reassemble.collect(pcap, out)
    except ValueError as exc:
        assert "conflict" in str(exc), str(exc)
        with open(out, "rb") as f:
            assert f.read() == sentinel
        return
    raise AssertionError("round %d expected conflict" % round_no)


def main():
    rng = random.Random(20261114)
    if os.path.exists(RUN):
        shutil.rmtree(RUN)
    os.makedirs(RUN)
    rounds = 60
    for r in range(rounds):
        one_round(rng, r)
    print("fuzz: %d randomized success rounds passed" % rounds)
    for r in range(20):
        one_conflict_round(rng, r)
    print("fuzz: 20 randomized conflict rounds passed")
    shutil.rmtree(RUN)


if __name__ == "__main__":
    main()
