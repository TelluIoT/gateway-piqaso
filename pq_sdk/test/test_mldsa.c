#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <piqaso/mldsa.h>
#include <piqaso/errors.h>

/* ------------------------------------------------------------------ */
/* Helpers                                                              */
/* ------------------------------------------------------------------ */

static const char *level_name(uint8_t level)
{
    switch (level) {
    case MLDSA_LEVEL2: return "ML-DSA-44 (level 2)";
    case MLDSA_LEVEL3: return "ML-DSA-65 (level 3)";
    case MLDSA_LEVEL5: return "ML-DSA-87 (level 5)";
    default:           return "unknown";
    }
}

static int check(const char *tag, int ret)
{
    if (ret != PIQ_SUCCESS) {
        fprintf(stderr, "  FAIL  %s  (ret=%d)\n", tag, ret);
        return 1;
    }
    printf("  PASS  %s\n", tag);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Per-level test                                                       */
/* ------------------------------------------------------------------ */

static int test_level(uint8_t level)
{
    int failures = 0;

    struct mldsa_keygen_in    kg_in   = { .level = level };
    struct mldsa_keygen_out  *kg_out  = NULL;

    struct mldsa_sign_in      sign_in;
    struct mldsa_sign_out    *sign_out = NULL;

    struct mldsa_verify_in    vfy_in;

    static const uint8_t msg[]      = "piqaso sdk ml-dsa test message";
    static const uint8_t bad_msg[]  = "tampered message";

    printf("\n[%s]\n", level_name(level));

    /* --- keygen -------------------------------------------------------- */
    failures += check("keygen", mldsa_keygen(&kg_in, &kg_out));
    if (!kg_out) {
        fprintf(stderr, "  keygen returned NULL output, aborting level test\n");
        return failures + 1;
    }

    printf("  pub_key  %zu bytes\n", kg_out->public_key->buffer_len);
    printf("  priv_key %zu bytes\n", kg_out->private_key->buffer_len);

    /* --- sign ---------------------------------------------------------- */
    memset(&sign_in, 0, sizeof(sign_in));
    sign_in.level       = level;
    sign_in.private_key = kg_out->private_key;

    /* Build a piq_buffer for the message (points into static storage) */
    struct piq_buffer msg_buf;
    msg_buf.buffer     = (uint8_t *)msg;
    msg_buf.buffer_len = sizeof(msg) - 1; /* exclude NUL */
    sign_in.message    = &msg_buf;

    failures += check("sign", mldsa_sign(&sign_in, &sign_out));
    if (!sign_out) {
        fprintf(stderr, "  sign returned NULL output, aborting level test\n");
        free_mldsa_keygen_out(kg_out);
        return failures + 1;
    }
    printf("  signature %zu bytes\n", sign_out->signature->buffer_len);

    /* --- verify (valid) ------------------------------------------------ */
    memset(&vfy_in, 0, sizeof(vfy_in));
    vfy_in.level      = level;
    vfy_in.public_key = kg_out->public_key;
    vfy_in.message    = &msg_buf;
    vfy_in.signature  = sign_out->signature;

    failures += check("verify (valid signature)", mldsa_verify(&vfy_in));

    /* --- verify (tampered message) ------------------------------------- */
    struct piq_buffer bad_buf;
    bad_buf.buffer     = (uint8_t *)bad_msg;
    bad_buf.buffer_len = sizeof(bad_msg) - 1;
    vfy_in.message     = &bad_buf;

    int ret = mldsa_verify(&vfy_in);
    if (ret == PIQ_VERIFY_FAILED) {
        printf("  PASS  verify (tampered message correctly rejected)\n");
    } else {
        fprintf(stderr, "  FAIL  verify (tampered message) expected PIQ_VERIFY_FAILED, got %d\n", ret);
        failures++;
    }

    /* --- cleanup ------------------------------------------------------- */
    free_mldsa_sign_out(sign_out);
    free_mldsa_keygen_out(kg_out);

    return failures;
}

/* ------------------------------------------------------------------ */
/* main                                                                 */
/* ------------------------------------------------------------------ */

int main(void)
{
    int total_failures = 0;
    uint8_t levels[]   = { MLDSA_LEVEL2, MLDSA_LEVEL3, MLDSA_LEVEL5 };
    size_t  n_levels   = sizeof(levels) / sizeof(levels[0]);

    printf("piqaso_sdk  ML-DSA test\n");
    printf("================================\n");

    for (size_t i = 0; i < n_levels; i++) {
        total_failures += test_level(levels[i]);
    }

    printf("\n================================\n");
    if (total_failures == 0) {
        printf("All tests PASSED\n");
    } else {
        printf("%d test(s) FAILED\n", total_failures);
    }

    return (total_failures == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
