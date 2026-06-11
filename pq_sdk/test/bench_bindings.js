#!/usr/bin/env node
/*
 * Micro-benchmarks for the piqaso_sdk SWIG **JavaScript / Node** bindings.
 *
 * Emits one "BENCH js_<label> <ns>" line per measurement so that
 * test/run_benchmarks.py can aggregate samples in its summary table.
 *
 * Usage:
 *   node test/bench_bindings.js [iterations] [only...]
 *   default iterations = 1000
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

function nowNs() {
    return Number(process.hrtime.bigint());
}

function emit(label, ns) {
    process.stdout.write(`BENCH js_${label} ${ns}\n`);
}

function benchMldsa(n) {
    const msg = Buffer.from('piqaso_sdk benchmark message');
    const levels = [[p.MLDSA_LEVEL2, 'level2'],
                    [p.MLDSA_LEVEL3, 'level3'],
                    [p.MLDSA_LEVEL5, 'level5']];
    for (const [level, tag] of levels) {
        for (let i = 0; i < n; i++) {
            let t = nowNs();
            const [, pk, sk] = p.py_mldsa_keygen(level);
            emit(`mldsa_${tag}_keygen`, nowNs() - t);

            t = nowNs();
            const [, sig] = p.py_mldsa_sign(level, sk, msg);
            emit(`mldsa_${tag}_sign`, nowNs() - t);

            t = nowNs();
            p.py_mldsa_verify(level, pk, msg, sig);
            emit(`mldsa_${tag}_verify`, nowNs() - t);
        }
    }
}

function benchMlkem(n) {
    const levels = [[p.MLKEM_LEVEL1, 'level1'],
                    [p.MLKEM_LEVEL3, 'level3'],
                    [p.MLKEM_LEVEL5, 'level5']];
    for (const [level, tag] of levels) {
        for (let i = 0; i < n; i++) {
            let t = nowNs();
            const [, pk, sk] = p.py_mlkem_keygen(level);
            emit(`mlkem_${tag}_keygen`, nowNs() - t);

            t = nowNs();
            const [, ct] = p.py_mlkem_encaps(level, pk);
            emit(`mlkem_${tag}_encaps`, nowNs() - t);

            t = nowNs();
            p.py_mlkem_decaps(level, sk, ct);
            emit(`mlkem_${tag}_decaps`, nowNs() - t);
        }
    }
}

function benchAes(n) {
    const pt  = Buffer.from('piqaso_sdk AES benchmark plaintext payload of moderate length.');
    const aad = Buffer.from('associated-bench-data');
    for (const [keylen, tag] of [[16,'128'], [24,'192'], [32,'256']]) {
        const key = Buffer.alloc(keylen);
        for (let i = 0; i < keylen; i++) key[i] = i;
        for (let i = 0; i < n; i++) {
            let t = nowNs();
            const [, iv, ct, tg] = p.py_aesgcm_encrypt(key, null, pt, aad);
            emit(`aesgcm_${tag}_encrypt`, nowNs() - t);

            t = nowNs();
            p.py_aesgcm_decrypt(key, iv, ct, tg, aad);
            emit(`aesgcm_${tag}_decrypt`, nowNs() - t);
        }
    }
    for (const [keylen, tag] of [[16,'128'], [32,'256']]) {
        const key = Buffer.alloc(keylen);
        for (let i = 0; i < keylen; i++) key[i] = i;
        for (let i = 0; i < n; i++) {
            let t = nowNs();
            const [, iv, ct] = p.py_aescbc_encrypt(key, null, pt);
            emit(`aescbc_${tag}_encrypt`, nowNs() - t);

            t = nowNs();
            p.py_aescbc_decrypt(key, iv, ct);
            emit(`aescbc_${tag}_decrypt`, nowNs() - t);
        }
    }
}

function benchLms(n) {
    const parm = p.LMS_PARM_L1_H5_W2;
    const msg = Buffer.from('piqaso_sdk LMS bench message');
    for (let i = 0; i < n; i++) {
        let t = nowNs();
        const [, pk, sk] = p.py_lms_keygen(parm);
        emit('lms_L1_H5_W2_keygen', nowNs() - t);

        t = nowNs();
        const [, sig] = p.py_lms_sign(parm, sk, msg);
        emit('lms_L1_H5_W2_sign', nowNs() - t);

        t = nowNs();
        p.py_lms_verify(parm, pk, msg, sig);
        emit('lms_L1_H5_W2_verify', nowNs() - t);
    }
}

function benchXmss(n) {
    const param = 'XMSS-SHA2_10_256';
    const msg = Buffer.from('piqaso_sdk XMSS bench message');
    for (let i = 0; i < n; i++) {
        let t = nowNs();
        const [, pk, sk] = p.py_xmss_keygen(param);
        emit('xmss_SHA2_10_256_keygen', nowNs() - t);

        t = nowNs();
        const [, sig] = p.py_xmss_sign(param, sk, msg);
        emit('xmss_SHA2_10_256_sign', nowNs() - t);

        t = nowNs();
        p.py_xmss_verify(param, pk, msg, sig);
        emit('xmss_SHA2_10_256_verify', nowNs() - t);
    }
}

function main() {
    const n = parseInt(process.argv[2] || '1000', 10);
    const rest = process.argv.slice(3);
    const only = new Set(rest.length ? rest : ['mldsa', 'mlkem', 'aes', 'lms', 'xmss']);
    if (only.has('mldsa')) benchMldsa(n);
    if (only.has('mlkem')) benchMlkem(n);
    if (only.has('aes'))   benchAes(n);
    if (only.has('lms'))   benchLms(n);
    if (only.has('xmss'))  benchXmss(n);
}

try {
    main();
} catch (e) {
    console.error('FAIL:', e.message);
    process.exit(1);
}
