/*
 * Micro-benchmarks for the piqaso_sdk SWIG **Java** bindings.
 *
 * Emits one "BENCH java_<label> <ns>" line per measurement so that
 * test/run_benchmarks.py can aggregate samples in its summary table.
 *
 * Build:
 *   cmake -S . -B build -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=java
 *   cmake --build build -j
 *   javac -cp build/piqaso.jar -d build/bench_classes test/BenchPiqaso.java
 *
 * Run (from project root):
 *   java -cp build/piqaso.jar:build/bench_classes \
 *        -Djava.library.path=build BenchPiqaso 1000
 */

import com.piqaso.piqaso;
import com.piqaso.piqasoConstants;

public class BenchPiqaso {

    static { System.loadLibrary("piqaso"); }

    static byte[][] out() { return new byte[1][]; }

    static long nowNs() { return System.nanoTime(); }

    static void emit(String label, long ns) {
        System.out.println("BENCH java_" + label + " " + ns);
    }

    static void benchMldsa(int n) {
        byte[] msg = "piqaso_sdk benchmark message".getBytes();
        int[]    levels = { piqasoConstants.MLDSA_LEVEL2,
                            piqasoConstants.MLDSA_LEVEL3,
                            piqasoConstants.MLDSA_LEVEL5 };
        String[] tags   = { "level2", "level3", "level5" };
        for (int li = 0; li < levels.length; li++) {
            int level = levels[li]; String tag = tags[li];
            for (int i = 0; i < n; i++) {
                byte[][] pk = out(), sk = out();
                long t = nowNs();
                piqaso.py_mldsa_keygen(level, pk, sk);
                emit("mldsa_" + tag + "_keygen", nowNs() - t);

                byte[][] sig = out();
                t = nowNs();
                piqaso.py_mldsa_sign(level, sk[0], msg, sig);
                emit("mldsa_" + tag + "_sign", nowNs() - t);

                t = nowNs();
                piqaso.py_mldsa_verify(level, pk[0], msg, sig[0]);
                emit("mldsa_" + tag + "_verify", nowNs() - t);
            }
        }
    }

    static void benchMlkem(int n) {
        int[]    levels = { piqasoConstants.MLKEM_LEVEL1,
                            piqasoConstants.MLKEM_LEVEL3,
                            piqasoConstants.MLKEM_LEVEL5 };
        String[] tags   = { "level1", "level3", "level5" };
        for (int li = 0; li < levels.length; li++) {
            int level = levels[li]; String tag = tags[li];
            for (int i = 0; i < n; i++) {
                byte[][] pk = out(), sk = out();
                long t = nowNs();
                piqaso.py_mlkem_keygen(level, pk, sk);
                emit("mlkem_" + tag + "_keygen", nowNs() - t);

                byte[][] ct = out(), ss1 = out();
                t = nowNs();
                piqaso.py_mlkem_encaps(level, pk[0], ct, ss1);
                emit("mlkem_" + tag + "_encaps", nowNs() - t);

                byte[][] ss2 = out();
                t = nowNs();
                piqaso.py_mlkem_decaps(level, sk[0], ct[0], ss2);
                emit("mlkem_" + tag + "_decaps", nowNs() - t);
            }
        }
    }

    static void benchAes(int n) {
        byte[] pt  = "piqaso_sdk AES benchmark plaintext payload of moderate length.".getBytes();
        byte[] aad = "associated-bench-data".getBytes();
        int[]    keyLens = { 16, 24, 32 };
        String[] gcmTags = { "128", "192", "256" };
        for (int ki = 0; ki < keyLens.length; ki++) {
            int kl = keyLens[ki]; String tag = gcmTags[ki];
            byte[] key = new byte[kl];
            for (int i = 0; i < kl; i++) key[i] = (byte) i;
            for (int i = 0; i < n; i++) {
                byte[][] iv = out(), ct = out(), tg = out();
                long t = nowNs();
                piqaso.py_aesgcm_encrypt(key, null, pt, aad, iv, ct, tg);
                emit("aesgcm_" + tag + "_encrypt", nowNs() - t);

                byte[][] dec = out();
                t = nowNs();
                piqaso.py_aesgcm_decrypt(key, iv[0], ct[0], tg[0], aad, dec);
                emit("aesgcm_" + tag + "_decrypt", nowNs() - t);
            }
        }
        int[]    cbcLens = { 16, 32 };
        String[] cbcTags = { "128", "256" };
        for (int ki = 0; ki < cbcLens.length; ki++) {
            int kl = cbcLens[ki]; String tag = cbcTags[ki];
            byte[] key = new byte[kl];
            for (int i = 0; i < kl; i++) key[i] = (byte) i;
            for (int i = 0; i < n; i++) {
                byte[][] iv = out(), ct = out();
                long t = nowNs();
                piqaso.py_aescbc_encrypt(key, null, pt, iv, ct);
                emit("aescbc_" + tag + "_encrypt", nowNs() - t);

                byte[][] dec = out();
                t = nowNs();
                piqaso.py_aescbc_decrypt(key, iv[0], ct[0], dec);
                emit("aescbc_" + tag + "_decrypt", nowNs() - t);
            }
        }
    }

    static void benchLms(int n) {
        int parm = piqasoConstants.LMS_PARM_L1_H5_W2;
        byte[] msg = "piqaso_sdk LMS bench message".getBytes();
        for (int i = 0; i < n; i++) {
            byte[][] pk = out(), sk = out();
            long t = nowNs();
            piqaso.py_lms_keygen(parm, pk, sk);
            emit("lms_L1_H5_W2_keygen", nowNs() - t);

            byte[][] sig = out(), sk2 = out();
            t = nowNs();
            piqaso.py_lms_sign(parm, sk[0], msg, sig, sk2);
            emit("lms_L1_H5_W2_sign", nowNs() - t);

            t = nowNs();
            piqaso.py_lms_verify(parm, pk[0], msg, sig[0]);
            emit("lms_L1_H5_W2_verify", nowNs() - t);
        }
    }

    static void benchXmss(int n) {
        String param = "XMSS-SHA2_10_256";
        byte[] msg = "piqaso_sdk XMSS bench message".getBytes();
        for (int i = 0; i < n; i++) {
            byte[][] pk = out(), sk = out();
            long t = nowNs();
            piqaso.py_xmss_keygen(param, pk, sk);
            emit("xmss_SHA2_10_256_keygen", nowNs() - t);

            byte[][] sig = out(), sk2 = out();
            t = nowNs();
            piqaso.py_xmss_sign(param, sk[0], msg, sig, sk2);
            emit("xmss_SHA2_10_256_sign", nowNs() - t);

            t = nowNs();
            piqaso.py_xmss_verify(param, pk[0], msg, sig[0]);
            emit("xmss_SHA2_10_256_verify", nowNs() - t);
        }
    }

    public static void main(String[] args) {
        int n = (args.length > 0) ? Integer.parseInt(args[0]) : 1000;
        java.util.Set<String> only = new java.util.HashSet<>();
        if (args.length > 1) {
            for (int i = 1; i < args.length; i++) only.add(args[i]);
        } else {
            only.add("mldsa"); only.add("mlkem"); only.add("aes");
            only.add("lms");   only.add("xmss");
        }
        if (only.contains("mldsa")) benchMldsa(n);
        if (only.contains("mlkem")) benchMlkem(n);
        if (only.contains("aes"))   benchAes(n);
        if (only.contains("lms"))   benchLms(n);
        if (only.contains("xmss"))  benchXmss(n);
    }
}
