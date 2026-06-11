#include <string.h>
#include <piqaso/mlkem.h>
#include <piqaso/errors.h>
#include "bench_common.h"

static void run_level(uint8_t level, const char *tag)
{
    char label[64];
    struct mlkem_keygen_in  kg_in  = { .level = level };
    struct mlkem_keygen_out *kg_out = NULL;
    struct mlkem_encaps_in   enc_in;
    struct mlkem_encaps_out *enc_out = NULL;
    struct mlkem_decaps_in   dec_in;
    struct mlkem_decaps_out *dec_out = NULL;

    snprintf(label, sizeof label, "mlkem_%s_keygen", tag);
    {
        BENCH_START();
        if (mlkem_keygen(&kg_in, &kg_out) != PIQ_SUCCESS) { fprintf(stderr, "keygen failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    snprintf(label, sizeof label, "mlkem_%s_encaps", tag);
    enc_in.level = level;
    enc_in.public_key = kg_out->public_key;
    {
        BENCH_START();
        if (mlkem_encaps(&enc_in, &enc_out) != PIQ_SUCCESS) { fprintf(stderr, "encaps failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    snprintf(label, sizeof label, "mlkem_%s_decaps", tag);
    dec_in.level = level;
    dec_in.private_key = kg_out->private_key;
    dec_in.ciphertext  = enc_out->ciphertext;
    {
        BENCH_START();
        if (mlkem_decaps(&dec_in, &dec_out) != PIQ_SUCCESS) { fprintf(stderr, "decaps failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    free_mlkem_decaps_out(dec_out);
    free_mlkem_encaps_out(enc_out);
    free_mlkem_keygen_out(kg_out);
}

int main(int argc, char **argv)
{
    int iters = bench_iters(argc, argv);
    for (int i = 0; i < iters; i++) {
        run_level(MLKEM_LEVEL1, "level1");
        run_level(MLKEM_LEVEL3, "level3");
        run_level(MLKEM_LEVEL5, "level5");
    }
    return 0;
}
