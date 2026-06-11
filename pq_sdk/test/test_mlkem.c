#include <stdio.h>
#include <string.h>
#include <stdint.h>

#include <piqaso/mlkem.h>
#include <piqaso/errors.h>

static const char *level_name(uint8_t level)
{
    switch (level) {
    case MLKEM_LEVEL1: return "ML-KEM-512  (level 1)";
    case MLKEM_LEVEL3: return "ML-KEM-768  (level 3)";
    case MLKEM_LEVEL5: return "ML-KEM-1024 (level 5)";
    default:           return "unknown";
    }
}

static int run_level(uint8_t level)
{
    struct mlkem_keygen_in  kg_in  = { .level = level };
    struct mlkem_keygen_out *kg_out = NULL;

    struct mlkem_encaps_in  enc_in;
    struct mlkem_encaps_out *enc_out = NULL;

    struct mlkem_decaps_in  dec_in;
    struct mlkem_decaps_out *dec_out = NULL;

    int ret;

    printf("[%s]\n", level_name(level));

    /* --- Key generation --- */
    ret = mlkem_keygen(&kg_in, &kg_out);
    if (ret != PIQ_SUCCESS) {
        printf("  FAIL  keygen (ret=%d)\n", ret);
        return ret;
    }
    printf("  PASS  keygen\n");
    printf("  pub_key  %zu bytes\n", kg_out->public_key->buffer_len);
    printf("  priv_key %zu bytes\n", kg_out->private_key->buffer_len);

    /* --- Encapsulation --- */
    enc_in.level      = level;
    enc_in.public_key = kg_out->public_key;

    ret = mlkem_encaps(&enc_in, &enc_out);
    if (ret != PIQ_SUCCESS) {
        printf("  FAIL  encaps (ret=%d)\n", ret);
        free_mlkem_keygen_out(kg_out);
        return ret;
    }
    printf("  PASS  encaps\n");
    printf("  ciphertext    %zu bytes\n", enc_out->ciphertext->buffer_len);
    printf("  shared_secret %zu bytes\n", enc_out->shared_secret->buffer_len);

    /* --- Decapsulation --- */
    dec_in.level       = level;
    dec_in.private_key = kg_out->private_key;
    dec_in.ciphertext  = enc_out->ciphertext;

    ret = mlkem_decaps(&dec_in, &dec_out);
    if (ret != PIQ_SUCCESS) {
        printf("  FAIL  decaps (ret=%d)\n", ret);
        free_mlkem_keygen_out(kg_out);
        free_mlkem_encaps_out(enc_out);
        return ret;
    }
    printf("  PASS  decaps\n");

    /* --- Verify shared secrets match --- */
    if (enc_out->shared_secret->buffer_len != dec_out->shared_secret->buffer_len ||
        memcmp(enc_out->shared_secret->buffer,
               dec_out->shared_secret->buffer,
               enc_out->shared_secret->buffer_len) != 0) {
        printf("  FAIL  shared secrets do not match\n");
        free_mlkem_keygen_out(kg_out);
        free_mlkem_encaps_out(enc_out);
        free_mlkem_decaps_out(dec_out);
        return -1;
    }
    printf("  PASS  shared secrets match\n");

    /* --- Verify tampered ciphertext produces different secret --- */
    struct mlkem_decaps_in  bad_in;
    struct mlkem_decaps_out *bad_out = NULL;
    uint8_t *tampered = NULL;

    tampered = malloc(enc_out->ciphertext->buffer_len);
    if (tampered) {
        struct piq_buffer tampered_buf;
        memcpy(tampered, enc_out->ciphertext->buffer, enc_out->ciphertext->buffer_len);
        tampered[0] ^= 0xFF;  /* flip bits in first byte */
        tampered_buf.buffer     = tampered;
        tampered_buf.buffer_len = enc_out->ciphertext->buffer_len;

        bad_in.level       = level;
        bad_in.private_key = kg_out->private_key;
        bad_in.ciphertext  = &tampered_buf;

        ret = mlkem_decaps(&bad_in, &bad_out);
        /* ML-KEM decaps always succeeds (implicit rejection); verify secret differs */
        if (ret == PIQ_SUCCESS &&
            memcmp(bad_out->shared_secret->buffer,
                   enc_out->shared_secret->buffer,
                   enc_out->shared_secret->buffer_len) != 0) {
            printf("  PASS  tampered ciphertext yields different secret\n");
        } else {
            printf("  FAIL  tampered ciphertext not rejected correctly\n");
        }
        free_mlkem_decaps_out(bad_out);
        free(tampered);
    }

    free_mlkem_keygen_out(kg_out);
    free_mlkem_encaps_out(enc_out);
    free_mlkem_decaps_out(dec_out);
    printf("\n");
    return PIQ_SUCCESS;
}

int main(void)
{
    int failed = 0;

    printf("piqaso_sdk  ML-KEM test\n");
    printf("================================\n\n");

    static const uint8_t levels[] = { MLKEM_LEVEL1, MLKEM_LEVEL3, MLKEM_LEVEL5 };
    for (size_t i = 0; i < sizeof(levels); i++) {
        if (run_level(levels[i]) != PIQ_SUCCESS)
            failed++;
    }

    printf("================================\n");
    if (failed == 0)
        printf("All tests PASSED\n");
    else
        printf("%d test(s) FAILED\n", failed);

    return failed ? 1 : 0;
}
