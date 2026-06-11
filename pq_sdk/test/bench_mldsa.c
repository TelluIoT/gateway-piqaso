#include <string.h>
#include <piqaso/mldsa.h>
#include <piqaso/errors.h>
#include "bench_common.h"

static const uint8_t MSG[] = "piqaso_sdk benchmark message";

static void run_level(uint8_t level, const char *tag)
{
    char label[64];
    struct mldsa_keygen_in   kg_in  = { .level = level };
    struct mldsa_keygen_out *kg_out = NULL;
    struct mldsa_sign_in     sign_in;
    struct mldsa_sign_out   *sign_out = NULL;
    struct mldsa_verify_in   vfy_in;
    struct piq_buffer msg_buf = { (uint8_t *)MSG, sizeof MSG - 1 };

    snprintf(label, sizeof label, "mldsa_%s_keygen", tag);
    {
        BENCH_START();
        if (mldsa_keygen(&kg_in, &kg_out) != PIQ_SUCCESS) { fprintf(stderr, "keygen failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    memset(&sign_in, 0, sizeof sign_in);
    sign_in.level       = level;
    sign_in.private_key = kg_out->private_key;
    sign_in.message     = &msg_buf;

    snprintf(label, sizeof label, "mldsa_%s_sign", tag);
    {
        BENCH_START();
        if (mldsa_sign(&sign_in, &sign_out) != PIQ_SUCCESS) { fprintf(stderr, "sign failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    memset(&vfy_in, 0, sizeof vfy_in);
    vfy_in.level      = level;
    vfy_in.public_key = kg_out->public_key;
    vfy_in.message    = &msg_buf;
    vfy_in.signature  = sign_out->signature;

    snprintf(label, sizeof label, "mldsa_%s_verify", tag);
    {
        BENCH_START();
        if (mldsa_verify(&vfy_in) != PIQ_SUCCESS) { fprintf(stderr, "verify failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    free_mldsa_sign_out(sign_out);
    free_mldsa_keygen_out(kg_out);
}

int main(int argc, char **argv)
{
    int iters = bench_iters(argc, argv);
    for (int i = 0; i < iters; i++) {
        run_level(MLDSA_LEVEL2, "level2");
        run_level(MLDSA_LEVEL3, "level3");
        run_level(MLDSA_LEVEL5, "level5");
    }
    return 0;
}
