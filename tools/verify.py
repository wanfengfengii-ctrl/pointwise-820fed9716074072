#!/usr/bin/env python3
"""Business verification and resource measurement for reassemble.collect.

Run with:  python3 -I tools/verify.py
Exit status is non-zero if any check fails.  All temporary outputs are
written under ./fixtures/run (created fresh); expected fixtures must already
exist (generate them first via tools/make_fixtures.py).
"""

import os
import shutil
import sys
import tracemalloc

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, ROOT)

import reassemble  # noqa: E402

FIX = os.path.join(ROOT, "fixtures")
RUN = os.path.join(FIX, "run")
MEM_LIMIT = 8 * 1024 * 1024
CHUNK = 64 * 1024

_failures = []


def check(condition, label):
    status = "ok  " if condition else "FAIL"
    print("[%s] %s" % (status, label))
    if not condition:
        _failures.append(label)


def expect_error(pcap, token, sentinel):
    """collect must raise ValueError containing *token* and keep the target."""
    out = os.path.join(RUN, "out_" + token + "_" + os.path.basename(pcap))
    with open(out, "wb") as f:
        f.write(sentinel)
    try:
        reassemble.collect(pcap, out)
    except ValueError as exc:
        good = token in str(exc)
        with open(out, "rb") as f:
            kept = f.read()
        check(good, "%s: ValueError mentions %r (%s)"
              % (os.path.basename(pcap), token, exc))
        check(kept == sentinel,
              "%s: original target preserved on failure"
              % os.path.basename(pcap))
        return
    check(False, "%s: expected ValueError(%s), got success"
          % (os.path.basename(pcap), token))


def compare_files(actual, expected):
    """Streaming byte comparison; returns True when identical."""
    with open(actual, "rb") as a, open(expected, "rb") as e:
        while True:
            ba, be = a.read(CHUNK), e.read(CHUNK)
            if ba != be:
                return False
            if not ba:
                return True


def run_ok(pcap_name, expected_name, label):
    pcap = os.path.join(FIX, pcap_name)
    expected = os.path.join(FIX, expected_name)
    out = os.path.join(RUN, "out_" + pcap_name + ".bin")
    if os.path.exists(out):
        os.unlink(out)
    n = reassemble.collect(pcap, out)
    exp_size = os.path.getsize(expected)
    check(n == exp_size, "%s: returned %d bytes (expected %d)"
          % (label, n, exp_size))
    check(compare_files(out, expected), "%s: output matches expected" % label)
    # idempotent re-run must atomically produce the same file
    before = os.stat(out).st_ino
    n2 = reassemble.collect(pcap, out)
    after = os.stat(out).st_ino
    check(n2 == n and compare_files(out, expected),
          "%s: re-run produces identical content" % label)
    check(before != after, "%s: re-run replaces target atomically" % label)
    return out


def main():
    if not os.path.isdir(FIX):
        print("fixtures missing -- run: python3 -I tools/make_fixtures.py")
        return 2
    if os.path.exists(RUN):
        shutil.rmtree(RUN)
    os.makedirs(RUN)

    print("== functional checks ==")
    # The exact example from the specification.
    pcap = os.path.join(FIX, "wrapsn.pcap")
    out = os.path.join(RUN, "out_wrapsn.bin")
    n = reassemble.collect(pcap, out)
    with open(out, "rb") as f:
        data = f.read()
    check(n == 4 and data == b"abcd",
          "spec example: SYN 2^32-2, reordered wrap -> b'abcd', returns 4")

    run_ok("order.pcap", "order.expected", "reorder + late retransmit")
    run_ok("fragmix.pcap", "fragmix.expected",
           "fragment reorder/duplicate/overlap")

    print("== error handling ==")
    sentinel = b"ORIGINAL-TARGET-MUST-SURVIVE" * 4
    expect_error(os.path.join(FIX, "conflict_tcp.pcap"), "conflict", sentinel)
    expect_error(os.path.join(FIX, "conflict_tcp_pending.pcap"),
                 "conflict", sentinel)
    expect_error(os.path.join(FIX, "conflict_ip.pcap"), "conflict", sentinel)
    expect_error(os.path.join(FIX, "gap_frag.pcap"), "gap", sentinel)
    expect_error(os.path.join(FIX, "gap_tcp.pcap"), "gap", sentinel)
    expect_error(os.path.join(FIX, "nofin.pcap"), "gap", sentinel)
    expect_error(os.path.join(FIX, "truncated.pcap"),
                 "truncated", sentinel)
    expect_error(os.path.join(FIX, "truncated_header.pcap"),
                 "truncated", sentinel)

    print("== 32 MiB end-to-end ==")
    large_out = run_ok("large32m.pcap", "large32m.expected",
                       "32 MiB fragmented, reordered, wrapped, retransmitted")

    print("== resource measurement ==")
    tracemalloc.start()
    n = reassemble.collect(os.path.join(FIX, "large32m.pcap"),
                           os.path.join(RUN, "out_mem.bin"))
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    print("    Python peak allocation (tracemalloc): %.2f KiB"
          % (peak / 1024))
    check(n == 32 * 1024 * 1024, "memory run still returned 32 MiB")
    check(peak <= MEM_LIMIT,
          "peak %.1f KiB <= 8192 KiB budget" % (peak / 1024))

    print()
    if _failures:
        print("%d check(s) FAILED:" % len(_failures))
        for label in _failures:
            print("  - " + label)
        return 1
    print("all checks passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
