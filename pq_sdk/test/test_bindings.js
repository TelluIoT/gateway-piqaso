#!/usr/bin/env node
/*
 * End-to-end smoke test for the SWIG JavaScript (Node.js N-API) bindings
 * of piqaso_sdk.
 *
 * Build first:
 *   (cd bindings/js && npm install)
 *   cmake -S . -B build-js -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=javascript
 *   cmake --build build-js -j
 *
 * Then run:
 *   node test/test_bindings.js
 *
 * The script auto-locates piqaso.node in ../build-js/ or ../build/ relative
 * to this file.
 */

'use strict';

const path = require('path');
const fs   = require('fs');

function loadAddon() {
    const here = __dirname;
    const candidates = [
        path.resolve(here, '..', 'build-js', 'piqaso.node'),
        path.resolve(here, '..', 'build',    'piqaso.node'),
    ];
    for (const c of candidates) {
        if (fs.existsSync(c)) return require(c);
    }
    throw new Error('piqaso.node not found. Tried:\n  ' + candidates.join('\n  '));
}

const p = loadAddon();

function bytesEq(a, b) {
    if (a.length !== b.length) return false;
    for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
    return true;
}

function assertEq(name, got, want) {
    const eq = (Buffer.isBuffer(got) && Buffer.isBuffer(want))
        ? bytesEq(got, want)
        : got === want;
    if (!eq) {
        throw new Error(`${name}: got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`);
    }
}

function checkRc(name, rc) {
    if (rc !== p.PIQ_SUCCESS) {
        throw new Error(`${name} failed: rc=${rc}`);
    }
}

function testMldsa() {
    for (const level of [p.MLDSA_LEVEL2, p.MLDSA_LEVEL3, p.MLDSA_LEVEL5]) {
        const [rc1, pk, sk] = p.py_mldsa_keygen(level);
        checkRc(`mldsa_keygen L${level}`, rc1);
        const msg = Buffer.from('the quick brown fox jumps over the lazy dog');
        const [rc2, sig] = p.py_mldsa_sign(level, sk, msg);
        checkRc(`mldsa_sign L${level}`, rc2);
        assertEq(`mldsa_verify L${level}`,
                 p.py_mldsa_verify(level, pk, msg, sig), p.PIQ_SUCCESS);
        assertEq(`mldsa_verify tampered L${level}`,
                 p.py_mldsa_verify(level, pk, Buffer.from('tampered'), sig),
                 p.PIQ_VERIFY_FAILED);
        console.log(`  ML-DSA-L${level}: pk=${pk.length} sk=${sk.length} sig=${sig.length} OK`);
    }
}

function testMlkem() {
    for (const level of [p.MLKEM_LEVEL1, p.MLKEM_LEVEL3, p.MLKEM_LEVEL5]) {
        const [rc1, pk, sk] = p.py_mlkem_keygen(level);
        checkRc(`mlkem_keygen L${level}`, rc1);
        const [rc2, ct, ss1] = p.py_mlkem_encaps(level, pk);
        checkRc(`mlkem_encaps L${level}`, rc2);
        const [rc3, ss2] = p.py_mlkem_decaps(level, sk, ct);
        checkRc(`mlkem_decaps L${level}`, rc3);
        assertEq(`shared secret L${level}`, ss1, ss2);
        console.log(`  ML-KEM-L${level}: pk=${pk.length} sk=${sk.length} ct=${ct.length} ss=${ss1.length} OK`);
    }
}

function testAesGcm() {
    for (const keylen of [16, 24, 32]) {
        const key = Buffer.alloc(keylen);
        for (let i = 0; i < keylen; i++) key[i] = i;
        const pt  = Buffer.from('AES-GCM plaintext payload of arbitrary length');
        const aad = Buffer.from('associated data');

        // Auto-generated IV
        const [rc1, iv, ct, tag] = p.py_aesgcm_encrypt(key, null, pt, aad);
        checkRc(`aesgcm_encrypt key${keylen * 8}`, rc1);
        assertEq('gcm iv len',  iv.length,  p.AES_GCM_IV_SIZE);
        assertEq('gcm tag len', tag.length, p.AES_GCM_TAG_SIZE);

        const [rc2, dec] = p.py_aesgcm_decrypt(key, iv, ct, tag, aad);
        checkRc(`aesgcm_decrypt key${keylen * 8}`, rc2);
        assertEq('gcm round-trip', dec, pt);

        // Tampered tag must fail
        const badTag = Buffer.from(tag);
        badTag[0] ^= 0x01;
        const [rc3] = p.py_aesgcm_decrypt(key, iv, ct, badTag, aad);
        assertEq('gcm tampered tag', rc3, p.PIQ_VERIFY_FAILED);

        console.log(`  AES-${keylen * 8}-GCM: ct=${ct.length} OK`);
    }
}

function testAesCbc() {
    const key = Buffer.alloc(32, 0x4b); // 'K'
    for (const plen of [1, 15, 16, 17, 100]) {
        const pt = Buffer.alloc(plen);
        for (let i = 0; i < plen; i++) pt[i] = i & 0xff;

        const [rc1, iv, ct] = p.py_aescbc_encrypt(key, null, pt);
        checkRc(`aescbc_encrypt len=${plen}`, rc1);
        assertEq('cbc iv len', iv.length, p.AES_CBC_IV_SIZE);

        const [rc2, dec] = p.py_aescbc_decrypt(key, iv, ct);
        checkRc(`aescbc_decrypt len=${plen}`, rc2);
        assertEq(`cbc round-trip len=${plen}`, dec, pt);
    }
    console.log('  AES-256-CBC: OK');
}

function testLms() {
    const parm = p.LMS_PARM_L1_H5_W2;
    let [rc1, pk, sk] = p.py_lms_keygen(parm);
    checkRc('lms_keygen', rc1);
    let sig;
    const msgs = [Buffer.from('m0'), Buffer.from('m1'), Buffer.from('m2')];
    for (let i = 0; i < msgs.length; i++) {
        const [rc2, sigOut, skUpdated] = p.py_lms_sign(parm, sk, msgs[i]);
        checkRc(`lms_sign #${i}`, rc2);
        sig = sigOut;
        sk  = skUpdated;
        assertEq(`lms_verify #${i}`,
                 p.py_lms_verify(parm, pk, msgs[i], sig), p.PIQ_SUCCESS);
    }
    assertEq('lms_verify wrong-msg',
             p.py_lms_verify(parm, pk, Buffer.from('other'), sig),
             p.PIQ_VERIFY_FAILED);
    console.log(`  LMS L1_H5_W2: pk=${pk.length} sig=${sig.length} OK`);
}

function testXmss() {
    const param = 'XMSS-SHA2_10_256';
    let [rc1, pk, sk] = p.py_xmss_keygen(param);
    checkRc('xmss_keygen', rc1);
    let sig;
    const msgs = [Buffer.from('m0'), Buffer.from('m1'), Buffer.from('m2')];
    for (let i = 0; i < msgs.length; i++) {
        const [rc2, sigOut, skUpdated] = p.py_xmss_sign(param, sk, msgs[i]);
        checkRc(`xmss_sign #${i}`, rc2);
        sig = sigOut;
        sk  = skUpdated;
        assertEq(`xmss_verify #${i}`,
                 p.py_xmss_verify(param, pk, msgs[i], sig), p.PIQ_SUCCESS);
    }
    assertEq('xmss_verify wrong-msg',
             p.py_xmss_verify(param, pk, Buffer.from('other'), sig),
             p.PIQ_VERIFY_FAILED);
    console.log(`  XMSS ${param}: pk=${pk.length} sig=${sig.length} OK`);
}

function main() {
    console.log('== ML-DSA ==');  testMldsa();
    console.log('== ML-KEM ==');  testMlkem();
    console.log('== AES-GCM =='); testAesGcm();
    console.log('== AES-CBC =='); testAesCbc();
    console.log('== LMS ==');     testLms();
    console.log('== XMSS ==');    testXmss();
    console.log('\nAll piqaso_sdk JavaScript binding tests passed.');
}

try {
    main();
} catch (e) {
    console.error('FAIL:', e.message);
    process.exit(1);
}
