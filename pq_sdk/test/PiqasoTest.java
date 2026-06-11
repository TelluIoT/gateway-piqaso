/*
 * End-to-end smoke test for the SWIG Java bindings of piqaso_sdk.
 *
 * Build:
 *   cmake -S . -B build -DBUILD_BINDINGS=ON -DBINDINGS_LANGUAGE=java
 *   cmake --build build -j
 *
 * Run (from the project root):
 *   javac -cp build/piqaso.jar -d build/test_classes test/PiqasoTest.java
 *   java -cp build/piqaso.jar:build/test_classes \
 *        -Djava.library.path=build PiqasoTest
 */

import com.piqaso.piqaso;
import com.piqaso.piqasoConstants;

import java.util.Arrays;

public class PiqasoTest {

    static {
        System.loadLibrary("piqaso");
    }

    static void check(String name, int rc) {
        if (rc != piqasoConstants.PIQ_SUCCESS) {
            throw new RuntimeException(name + " failed: rc=" + rc);
        }
    }

    static void assertEq(String name, int got, int want) {
        if (got != want) {
            throw new RuntimeException(name + ": got " + got + ", want " + want);
        }
    }

    static void assertBytesEq(String name, byte[] a, byte[] b) {
        if (!Arrays.equals(a, b)) {
            throw new RuntimeException(name + ": byte arrays differ");
        }
    }

    /* Convenience: holder factory. */
    static byte[][] out() { return new byte[1][]; }

    static void testMlDsa() {
        int[] levels = { piqasoConstants.MLDSA_LEVEL2,
                         piqasoConstants.MLDSA_LEVEL3,
                         piqasoConstants.MLDSA_LEVEL5 };
        for (int level : levels) {
            byte[][] pk = out(), sk = out();
            check("mldsa_keygen", piqaso.py_mldsa_keygen(level, pk, sk));

            byte[] msg = "the quick brown fox".getBytes();
            byte[][] sig = out();
            check("mldsa_sign", piqaso.py_mldsa_sign(level, sk[0], msg, sig));

            assertEq("mldsa_verify good",
                     piqaso.py_mldsa_verify(level, pk[0], msg, sig[0]),
                     piqasoConstants.PIQ_SUCCESS);
            assertEq("mldsa_verify bad",
                     piqaso.py_mldsa_verify(level, pk[0], "tampered".getBytes(), sig[0]),
                     piqasoConstants.PIQ_VERIFY_FAILED);
            System.out.printf("  ML-DSA-L%d: pk=%d sk=%d sig=%d OK%n",
                              level, pk[0].length, sk[0].length, sig[0].length);
        }
    }

    static void testMlKem() {
        int[] levels = { piqasoConstants.MLKEM_LEVEL1,
                         piqasoConstants.MLKEM_LEVEL3,
                         piqasoConstants.MLKEM_LEVEL5 };
        for (int level : levels) {
            byte[][] pk = out(), sk = out();
            check("mlkem_keygen", piqaso.py_mlkem_keygen(level, pk, sk));
            byte[][] ct = out(), ss1 = out();
            check("mlkem_encaps", piqaso.py_mlkem_encaps(level, pk[0], ct, ss1));
            byte[][] ss2 = out();
            check("mlkem_decaps", piqaso.py_mlkem_decaps(level, sk[0], ct[0], ss2));
            assertBytesEq("shared secret", ss1[0], ss2[0]);
            System.out.printf("  ML-KEM-L%d: pk=%d sk=%d ct=%d ss=%d OK%n",
                              level, pk[0].length, sk[0].length, ct[0].length, ss1[0].length);
        }
    }

    static void testAesGcm() {
        for (int keylen : new int[] { 16, 24, 32 }) {
            byte[] key = new byte[keylen];
            for (int i = 0; i < keylen; i++) key[i] = (byte) i;
            byte[] pt  = "AES-GCM plaintext".getBytes();
            byte[] aad = "associated data".getBytes();

            byte[][] iv = out(), ct = out(), tag = out();
            check("aesgcm_encrypt",
                  piqaso.py_aesgcm_encrypt(key, null, pt, aad, iv, ct, tag));
            assertEq("gcm iv len", iv[0].length, piqasoConstants.AES_GCM_IV_SIZE);
            assertEq("gcm tag len", tag[0].length, piqasoConstants.AES_GCM_TAG_SIZE);

            byte[][] dec = out();
            check("aesgcm_decrypt",
                  piqaso.py_aesgcm_decrypt(key, iv[0], ct[0], tag[0], aad, dec));
            assertBytesEq("gcm round-trip", dec[0], pt);

            byte[] badTag = tag[0].clone();
            badTag[0] ^= 0x01;
            assertEq("gcm tampered tag",
                     piqaso.py_aesgcm_decrypt(key, iv[0], ct[0], badTag, aad, out()),
                     piqasoConstants.PIQ_VERIFY_FAILED);
            System.out.printf("  AES-%d-GCM: ct=%d OK%n", keylen * 8, ct[0].length);
        }
    }

    static void testAesCbc() {
        byte[] key = new byte[32];
        Arrays.fill(key, (byte) 'K');
        for (int plen : new int[] { 1, 15, 16, 17, 100 }) {
            byte[] pt = new byte[plen];
            for (int i = 0; i < plen; i++) pt[i] = (byte) i;
            byte[][] iv = out(), ct = out();
            check("aescbc_encrypt", piqaso.py_aescbc_encrypt(key, null, pt, iv, ct));
            byte[][] dec = out();
            check("aescbc_decrypt", piqaso.py_aescbc_decrypt(key, iv[0], ct[0], dec));
            assertBytesEq("cbc round-trip len=" + plen, dec[0], pt);
        }
        System.out.println("  AES-256-CBC: OK");
    }

    static void testLms() {
        int parm = piqasoConstants.LMS_PARM_L1_H5_W2;
        byte[][] pk = out(), sk = out();
        check("lms_keygen", piqaso.py_lms_keygen(parm, pk, sk));

        byte[][] sig = out();
        byte[] m = null;
        for (int i = 0; i < 3; i++) {
            m = ("lms message #" + i).getBytes();
            byte[][] sk2 = out();
            sig = out();
            check("lms_sign #" + i, piqaso.py_lms_sign(parm, sk[0], m, sig, sk2));
            sk[0] = sk2[0];
            assertEq("lms_verify #" + i,
                     piqaso.py_lms_verify(parm, pk[0], m, sig[0]),
                     piqasoConstants.PIQ_SUCCESS);
        }
        assertEq("lms_verify wrong-msg",
                 piqaso.py_lms_verify(parm, pk[0], "other".getBytes(), sig[0]),
                 piqasoConstants.PIQ_VERIFY_FAILED);
        System.out.printf("  LMS L1_H5_W2: pk=%d sig=%d OK%n", pk[0].length, sig[0].length);
    }

    static void testXmss() {
        String param = "XMSS-SHA2_10_256";
        byte[][] pk = out(), sk = out();
        check("xmss_keygen", piqaso.py_xmss_keygen(param, pk, sk));

        byte[][] sig = out();
        for (int i = 0; i < 3; i++) {
            byte[] m = ("xmss message #" + i).getBytes();
            byte[][] sk2 = out();
            sig = out();
            check("xmss_sign #" + i, piqaso.py_xmss_sign(param, sk[0], m, sig, sk2));
            sk[0] = sk2[0];
            assertEq("xmss_verify #" + i,
                     piqaso.py_xmss_verify(param, pk[0], m, sig[0]),
                     piqasoConstants.PIQ_SUCCESS);
        }
        System.out.printf("  XMSS %s: pk=%d sig=%d OK%n", param, pk[0].length, sig[0].length);
    }

    public static void main(String[] args) {
        System.out.println("== ML-DSA ==");  testMlDsa();
        System.out.println("== ML-KEM ==");  testMlKem();
        System.out.println("== AES-GCM =="); testAesGcm();
        System.out.println("== AES-CBC =="); testAesCbc();
        System.out.println("== LMS ==");     testLms();
        System.out.println("== XMSS ==");    testXmss();
        System.out.println("\nAll piqaso_sdk Java binding tests passed.");
    }
}
