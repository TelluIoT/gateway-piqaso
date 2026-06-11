#include <string.h>
#include <piqaso/aes.h>
#include <piqaso/errors.h>
#include "bench_common.h"

#define PT  "piqaso_sdk AES benchmark plaintext payload of moderate length."
#define AAD "associated-bench-data"

static void run_gcm(size_t key_len, const char *tag)
{
    char label[64];
    uint8_t key[32] = {0};
    for (size_t i = 0; i < key_len; i++) key[i] = (uint8_t)i;
    struct piq_buffer kbuf  = { key, key_len };
    struct piq_buffer pbuf  = { (uint8_t *)PT, sizeof(PT) - 1 };
    struct piq_buffer abuf  = { (uint8_t *)AAD, sizeof(AAD) - 1 };

    struct aesgcm_encrypt_in  ein  = { &kbuf, NULL, &pbuf, &abuf };
    struct aesgcm_encrypt_out *eout = NULL;

    snprintf(label, sizeof label, "aesgcm_%s_encrypt", tag);
    {
        BENCH_START();
        if (aesgcm_encrypt(&ein, &eout) != PIQ_SUCCESS) { fprintf(stderr, "gcm encrypt failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    struct aesgcm_decrypt_in  din  = { &kbuf, eout->iv, eout->ciphertext, eout->tag, &abuf };
    struct aesgcm_decrypt_out *dout = NULL;

    snprintf(label, sizeof label, "aesgcm_%s_decrypt", tag);
    {
        BENCH_START();
        if (aesgcm_decrypt(&din, &dout) != PIQ_SUCCESS) { fprintf(stderr, "gcm decrypt failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    free_aesgcm_decrypt_out(dout);
    free_aesgcm_encrypt_out(eout);
}

static void run_cbc(size_t key_len, const char *tag)
{
    char label[64];
    uint8_t key[32] = {0};
    for (size_t i = 0; i < key_len; i++) key[i] = (uint8_t)i;
    struct piq_buffer kbuf = { key, key_len };
    struct piq_buffer pbuf = { (uint8_t *)PT, sizeof(PT) - 1 };

    struct aescbc_encrypt_in  ein  = { &kbuf, NULL, &pbuf };
    struct aescbc_encrypt_out *eout = NULL;

    snprintf(label, sizeof label, "aescbc_%s_encrypt", tag);
    {
        BENCH_START();
        if (aescbc_encrypt(&ein, &eout) != PIQ_SUCCESS) { fprintf(stderr, "cbc encrypt failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    struct aescbc_decrypt_in  din  = { &kbuf, eout->iv, eout->ciphertext };
    struct aescbc_decrypt_out *dout = NULL;

    snprintf(label, sizeof label, "aescbc_%s_decrypt", tag);
    {
        BENCH_START();
        if (aescbc_decrypt(&din, &dout) != PIQ_SUCCESS) { fprintf(stderr, "cbc decrypt failed\n"); exit(1); }
        BENCH_STOP(label);
    }

    free_aescbc_decrypt_out(dout);
    free_aescbc_encrypt_out(eout);
}

int main(int argc, char **argv)
{
    int iters = bench_iters(argc, argv);
    for (int i = 0; i < iters; i++) {
        run_gcm(16, "128");
        run_gcm(24, "192");
        run_gcm(32, "256");
        run_cbc(16, "128");
        run_cbc(32, "256");
    }
    return 0;
}
