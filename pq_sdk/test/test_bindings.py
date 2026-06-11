#!/usr/bin/env python3
"""
End-to-end smoke test for the SWIG Python bindings of piqaso_sdk.

Run after building with -DBUILD_BINDINGS=ON:

    cmake -S . -B build -DBUILD_BINDINGS=ON
    cmake --build build -j
    PYTHONPATH=build:build/python python3 test/test_bindings.py
"""

import os
import sys

# Allow running directly from the source tree without installing.
_HERE = os.path.dirname(os.path.abspath(__file__))
_BUILD = os.path.join(_HERE, "..", "build")
for p in (_BUILD, os.path.join(_BUILD, "python")):
    if os.path.isdir(p) and p not in sys.path:
        sys.path.insert(0, p)

import piqaso as p


def assert_eq(name, got, want):
    if got != want:
        raise AssertionError(f"{name}: got {got!r}, want {want!r}")


def check_rc(name, rc):
    if rc != p.PIQ_SUCCESS:
        raise AssertionError(f"{name} failed: rc={rc}")


def test_mldsa():
    for level in (p.MLDSA_LEVEL2, p.MLDSA_LEVEL3, p.MLDSA_LEVEL5):
        rc, pk, sk = p.py_mldsa_keygen(level)
        check_rc(f"mldsa_keygen L{level}", rc)
        msg = b"the quick brown fox jumps over the lazy dog"
        rc, sig = p.py_mldsa_sign(level, sk, msg)
        check_rc(f"mldsa_sign L{level}", rc)
        assert_eq(f"mldsa_verify L{level}",
                  p.py_mldsa_verify(level, pk, msg, sig), p.PIQ_SUCCESS)
        assert_eq(f"mldsa_verify tampered L{level}",
                  p.py_mldsa_verify(level, pk, b"tampered", sig),
                  p.PIQ_VERIFY_FAILED)
        print(f"  ML-DSA-L{level}: pk={len(pk)} sk={len(sk)} sig={len(sig)} OK")


def test_mlkem():
    for level in (p.MLKEM_LEVEL1, p.MLKEM_LEVEL3, p.MLKEM_LEVEL5):
        rc, pk, sk = p.py_mlkem_keygen(level)
        check_rc(f"mlkem_keygen L{level}", rc)
        rc, ct, ss1 = p.py_mlkem_encaps(level, pk)
        check_rc(f"mlkem_encaps L{level}", rc)
        rc, ss2 = p.py_mlkem_decaps(level, sk, ct)
        check_rc(f"mlkem_decaps L{level}", rc)
        assert_eq(f"shared secret L{level}", ss1, ss2)
        print(f"  ML-KEM-L{level}: pk={len(pk)} sk={len(sk)} ct={len(ct)} ss={len(ss1)} OK")


def test_aes_gcm():
    for keylen in (16, 24, 32):
        key = bytes(range(keylen))
        pt = b"AES-GCM plaintext payload of arbitrary length"
        aad = b"associated data"
        # Auto-generated IV
        rc, iv, ct, tag = p.py_aesgcm_encrypt(key, None, pt, aad)
        check_rc(f"aesgcm_encrypt key{keylen*8}", rc)
        assert_eq("gcm iv len", len(iv), p.AES_GCM_IV_SIZE)
        assert_eq("gcm tag len", len(tag), p.AES_GCM_TAG_SIZE)
        rc, dec = p.py_aesgcm_decrypt(key, iv, ct, tag, aad)
        check_rc(f"aesgcm_decrypt key{keylen*8}", rc)
        assert_eq("gcm round-trip", dec, pt)
        # Tampered tag must fail
        bad_tag = bytes(b ^ 0x01 for b in tag)
        assert_eq("gcm tampered tag",
                  p.py_aesgcm_decrypt(key, iv, ct, bad_tag, aad)[0],
                  p.PIQ_VERIFY_FAILED)
        print(f"  AES-{keylen*8}-GCM: ct={len(ct)} OK")


def test_aes_cbc():
    key = b"K" * 32
    for plen in (1, 15, 16, 17, 100):
        pt = bytes(range(plen))
        rc, iv, ct = p.py_aescbc_encrypt(key, None, pt)
        check_rc(f"aescbc_encrypt len={plen}", rc)
        assert_eq("cbc iv len", len(iv), p.AES_CBC_IV_SIZE)
        rc, dec = p.py_aescbc_decrypt(key, iv, ct)
        check_rc(f"aescbc_decrypt len={plen}", rc)
        assert_eq(f"cbc round-trip len={plen}", dec, pt)
    print("  AES-256-CBC: OK")


def test_lms():
    parm = p.LMS_PARM_L1_H5_W2
    rc, pk, sk = p.py_lms_keygen(parm)
    check_rc("lms_keygen", rc)
    # Sign three messages, threading the updated private key each time.
    for i, m in enumerate((b"m0", b"m1", b"m2")):
        rc, sig, sk = p.py_lms_sign(parm, sk, m)
        check_rc(f"lms_sign #{i}", rc)
        assert_eq(f"lms_verify #{i}",
                  p.py_lms_verify(parm, pk, m, sig), p.PIQ_SUCCESS)
    # Wrong message rejected
    assert_eq("lms_verify wrong-msg",
              p.py_lms_verify(parm, pk, b"other", sig), p.PIQ_VERIFY_FAILED)
    print(f"  LMS L1_H5_W2: pk={len(pk)} sig={len(sig)} OK")


def test_xmss():
    param = "XMSS-SHA2_10_256"
    rc, pk, sk = p.py_xmss_keygen(param)
    check_rc("xmss_keygen", rc)
    for i, m in enumerate((b"m0", b"m1", b"m2")):
        rc, sig, sk = p.py_xmss_sign(param, sk, m)
        check_rc(f"xmss_sign #{i}", rc)
        assert_eq(f"xmss_verify #{i}",
                  p.py_xmss_verify(param, pk, m, sig), p.PIQ_SUCCESS)
    assert_eq("xmss_verify wrong-msg",
              p.py_xmss_verify(param, pk, b"other", sig), p.PIQ_VERIFY_FAILED)
    print(f"  XMSS {param}: pk={len(pk)} sig={len(sig)} OK")


def main():
    print("== ML-DSA ==");  test_mldsa()
    print("== ML-KEM ==");  test_mlkem()
    print("== AES-GCM =="); test_aes_gcm()
    print("== AES-CBC =="); test_aes_cbc()
    print("== LMS ==");     test_lms()
    print("== XMSS ==");    test_xmss()
    print("\nAll piqaso_sdk Python binding tests passed.")


if __name__ == "__main__":
    main()
