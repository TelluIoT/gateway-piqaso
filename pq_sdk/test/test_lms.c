#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <piqaso/lms.h>
#include <piqaso/errors.h>

#define TEST_MSG  "Hello from LMS test"
#define TEST_MSG2 "Message for second signature"

static int test_keygen_sign_verify(void)
{
    int ret;
    struct lms_keygen_in  kg_in  = { .parm = LMS_PARM_L1_H5_W2 };
    struct lms_keygen_out *kg_out = NULL;
    struct lms_sign_in    s1_in;
    struct lms_sign_out   *s1_out = NULL;
    struct lms_sign_in    s2_in;
    struct lms_sign_out   *s2_out = NULL;
    struct lms_verify_in  v_in;

    printf("  keygen (L1_H5_W2)... ");
    fflush(stdout);
    ret = lms_keygen(&kg_in, &kg_out);
    if (ret != PIQ_SUCCESS) {
        printf("FAIL (%d)\n", ret); return ret;
    }
    printf("OK  pub=%zu bytes  priv=%zu bytes\n",
           kg_out->public_key->buffer_len,
           kg_out->private_key->buffer_len);

    /* First signature */
    memset(&s1_in, 0, sizeof(s1_in));
    s1_in.parm        = LMS_PARM_L1_H5_W2;
    s1_in.private_key = kg_out->private_key;
    s1_in.message     = &(struct piq_buffer){
        .buffer     = (uint8_t *)TEST_MSG,
        .buffer_len = strlen(TEST_MSG)
    };

    printf("  sign #1... ");
    fflush(stdout);
    ret = lms_sign(&s1_in, &s1_out);
    if (ret != PIQ_SUCCESS) {
        printf("FAIL (%d)\n", ret);
        free_lms_keygen_out(kg_out);
        return ret;
    }
    printf("OK  sig=%zu bytes  updated_priv=%zu bytes\n",
           s1_out->signature->buffer_len,
           s1_out->updated_private_key->buffer_len);

    /* Verify first signature */
    memset(&v_in, 0, sizeof(v_in));
    v_in.parm      = LMS_PARM_L1_H5_W2;
    v_in.public_key = kg_out->public_key;
    v_in.message    = &(struct piq_buffer){
        .buffer     = (uint8_t *)TEST_MSG,
        .buffer_len = strlen(TEST_MSG)
    };
    v_in.signature  = s1_out->signature;

    printf("  verify #1... ");
    fflush(stdout);
    ret = lms_verify(&v_in);
    if (ret != PIQ_SUCCESS) {
        printf("FAIL (%d)\n", ret);
        free_lms_sign_out(s1_out);
        free_lms_keygen_out(kg_out);
        return ret;
    }
    printf("OK\n");

    /* Second signature using updated private key */
    memset(&s2_in, 0, sizeof(s2_in));
    s2_in.parm        = LMS_PARM_L1_H5_W2;
    s2_in.private_key = s1_out->updated_private_key;
    s2_in.message     = &(struct piq_buffer){
        .buffer     = (uint8_t *)TEST_MSG2,
        .buffer_len = strlen(TEST_MSG2)
    };

    printf("  sign #2... ");
    fflush(stdout);
    ret = lms_sign(&s2_in, &s2_out);
    if (ret != PIQ_SUCCESS) {
        printf("FAIL (%d)\n", ret);
        free_lms_sign_out(s1_out);
        free_lms_keygen_out(kg_out);
        return ret;
    }
    printf("OK\n");

    /* Verify second signature */
    v_in.message    = &(struct piq_buffer){
        .buffer     = (uint8_t *)TEST_MSG2,
        .buffer_len = strlen(TEST_MSG2)
    };
    v_in.signature  = s2_out->signature;

    printf("  verify #2... ");
    fflush(stdout);
    ret = lms_verify(&v_in);
    if (ret != PIQ_SUCCESS) {
        printf("FAIL (%d)\n", ret);
        free_lms_sign_out(s2_out);
        free_lms_sign_out(s1_out);
        free_lms_keygen_out(kg_out);
        return ret;
    }
    printf("OK\n");

    /* Tampered message should fail */
    v_in.message = &(struct piq_buffer){
        .buffer     = (uint8_t *)"tampered",
        .buffer_len = strlen("tampered")
    };

    printf("  verify tampered message (expect FAIL)... ");
    fflush(stdout);
    ret = lms_verify(&v_in);
    if (ret != PIQ_VERIFY_FAILED) {
        printf("FAIL — expected PIQ_VERIFY_FAILED, got %d\n", ret);
        free_lms_sign_out(s2_out);
        free_lms_sign_out(s1_out);
        free_lms_keygen_out(kg_out);
        return -1;
    }
    printf("OK (correctly rejected)\n");

    /* Tampered signature should fail */
    s2_out->signature->buffer[0] ^= 0xFF;
    v_in.message = &(struct piq_buffer){
        .buffer     = (uint8_t *)TEST_MSG2,
        .buffer_len = strlen(TEST_MSG2)
    };
    v_in.signature = s2_out->signature;

    printf("  verify tampered signature (expect FAIL)... ");
    fflush(stdout);
    ret = lms_verify(&v_in);
    if (ret != PIQ_VERIFY_FAILED) {
        printf("FAIL — expected PIQ_VERIFY_FAILED, got %d\n", ret);
        free_lms_sign_out(s2_out);
        free_lms_sign_out(s1_out);
        free_lms_keygen_out(kg_out);
        return -1;
    }
    printf("OK (correctly rejected)\n");

    free_lms_sign_out(s2_out);
    free_lms_sign_out(s1_out);
    free_lms_keygen_out(kg_out);
    return PIQ_SUCCESS;
}

int main(void)
{
    int failures = 0;

    printf("=== LMS / HSS tests ===\n");

    printf("\n[LMS L1_H5_W2: keygen + sign + verify]\n");
    if (test_keygen_sign_verify() != PIQ_SUCCESS) {
        printf("  -> FAILED\n");
        failures++;
    } else {
        printf("  -> PASSED\n");
    }

    printf("\n=== %s ===\n", failures == 0 ? "ALL PASS" : "SOME TESTS FAILED");
    return failures == 0 ? 0 : 1;
}
