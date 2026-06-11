#!/usr/bin/env python3
"""
Micro-benchmarks for the piqaso_sdk SWIG **Python** bindings.

Mirrors the labels used by the C bench_* programs so that
test/run_benchmarks.py can aggregate samples from C and wrapper runs in the
same table.

Each line of stdout is:

    BENCH <label> <ns>

Usage:
    python3 test/bench_bindings.py [iterations]   # default 1000
"""

from __future__ import annotations

import os
import sys
import time

_HERE  = os.path.dirname(os.path.abspath(__file__))
_BUILD = os.path.join(_HERE, "..", "build")
for _p in (_BUILD, os.path.join(_BUILD, "python")):
    if os.path.isdir(_p) and _p not in sys.path:
        sys.path.insert(0, _p)

import piqaso as p  # noqa: E402

NS = time.perf_counter_ns


def emit(label: str, ns: int) -> None:
    sys.stdout.write(f"BENCH py_{label} {ns}\n")


def bench_mldsa(n: int) -> None:
    msg = b"piqaso_sdk benchmark message"
    levels = [(p.MLDSA_LEVEL2, "level2"),
              (p.MLDSA_LEVEL3, "level3"),
              (p.MLDSA_LEVEL5, "level5")]
    for level, tag in levels:
        for _ in range(n):
            t = NS(); _, pk, sk = p.py_mldsa_keygen(level); emit(f"mldsa_{tag}_keygen", NS() - t)
            t = NS(); _, sig    = p.py_mldsa_sign(level, sk, msg); emit(f"mldsa_{tag}_sign", NS() - t)
            t = NS(); p.py_mldsa_verify(level, pk, msg, sig);      emit(f"mldsa_{tag}_verify", NS() - t)


def bench_mlkem(n: int) -> None:
    levels = [(p.MLKEM_LEVEL1, "level1"),
              (p.MLKEM_LEVEL3, "level3"),
              (p.MLKEM_LEVEL5, "level5")]
    for level, tag in levels:
        for _ in range(n):
            t = NS(); _, pk, sk = p.py_mlkem_keygen(level);     emit(f"mlkem_{tag}_keygen", NS() - t)
            t = NS(); _, ct, _  = p.py_mlkem_encaps(level, pk); emit(f"mlkem_{tag}_encaps", NS() - t)
            t = NS(); p.py_mlkem_decaps(level, sk, ct);         emit(f"mlkem_{tag}_decaps", NS() - t)


def bench_aes(n: int) -> None:
    pt  = b"piqaso_sdk AES benchmark plaintext payload of moderate length."
    aad = b"associated-bench-data"
    for keylen, tag in ((16, "128"), (24, "192"), (32, "256")):
        key = bytes(range(keylen))
        for _ in range(n):
            t = NS(); _, iv, ct, tg = p.py_aesgcm_encrypt(key, None, pt, aad); emit(f"aesgcm_{tag}_encrypt", NS() - t)
            t = NS(); p.py_aesgcm_decrypt(key, iv, ct, tg, aad);                emit(f"aesgcm_{tag}_decrypt", NS() - t)
    for keylen, tag in ((16, "128"), (32, "256")):
        key = bytes(range(keylen))
        for _ in range(n):
            t = NS(); _, iv, ct = p.py_aescbc_encrypt(key, None, pt); emit(f"aescbc_{tag}_encrypt", NS() - t)
            t = NS(); p.py_aescbc_decrypt(key, iv, ct);               emit(f"aescbc_{tag}_decrypt", NS() - t)


def bench_lms(n: int) -> None:
    parm = p.LMS_PARM_L1_H5_W2
    msg = b"piqaso_sdk LMS bench message"
    for _ in range(n):
        t = NS(); _, pk, sk = p.py_lms_keygen(parm);          emit("lms_L1_H5_W2_keygen", NS() - t)
        t = NS(); _, sig, _ = p.py_lms_sign(parm, sk, msg);   emit("lms_L1_H5_W2_sign",   NS() - t)
        t = NS(); p.py_lms_verify(parm, pk, msg, sig);        emit("lms_L1_H5_W2_verify", NS() - t)


def bench_xmss(n: int) -> None:
    param = "XMSS-SHA2_10_256"
    msg = b"piqaso_sdk XMSS bench message"
    for _ in range(n):
        t = NS(); _, pk, sk = p.py_xmss_keygen(param);         emit("xmss_SHA2_10_256_keygen", NS() - t)
        t = NS(); _, sig, _ = p.py_xmss_sign(param, sk, msg);  emit("xmss_SHA2_10_256_sign",   NS() - t)
        t = NS(); p.py_xmss_verify(param, pk, msg, sig);       emit("xmss_SHA2_10_256_verify", NS() - t)


def main() -> int:
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 1000
    only = set(sys.argv[2:]) or {"mldsa", "mlkem", "aes", "lms", "xmss"}
    if "mldsa" in only: bench_mldsa(n)
    if "mlkem" in only: bench_mlkem(n)
    if "aes"   in only: bench_aes(n)
    if "lms"   in only: bench_lms(n)
    if "xmss"  in only: bench_xmss(n)
    return 0


if __name__ == "__main__":
    sys.exit(main())
