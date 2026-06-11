#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/dilithium.h>
#include <wolfssl/wolfcrypt/random.h>

#include <piqaso/mldsa.h>
#include <piqaso/errors.h>
#include <piqaso/structs.h>

/* Secure zero-fill that won't be optimised away.
 * explicit_bzero is available on glibc (Linux) and OP-TEE's libc. */
#ifndef OPTEE
#include <string.h>   /* explicit_bzero on Linux/glibc */
#else
/* OP-TEE: use TEE_MemFill equivalent — memset is fine; compiler won't
 * optimise it away in the trusted world with -fno-builtin absent, but
 * explicit_bzero is the safest.  OP-TEE libc provides it. */
#endif
#define piq_zero(p, n)  explicit_bzero((p), (n))

#ifdef OPTEE
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#endif

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static int mldsa_level_to_param(uint8_t level, int *param)
{
    switch (level) {
    case MLDSA_LEVEL2: *param = WC_ML_DSA_44; return PIQ_SUCCESS;
    case MLDSA_LEVEL3: *param = WC_ML_DSA_65; return PIQ_SUCCESS;
    case MLDSA_LEVEL5: *param = WC_ML_DSA_87; return PIQ_SUCCESS;
    default:                                    return PIQ_INVALID_PARAMS;
    }
}

static int mldsa_pub_key_len(uint8_t level, size_t *len)
{
    switch (level) {
    case MLDSA_LEVEL2: *len = DILITHIUM_LEVEL2_PUB_KEY_SIZE; return PIQ_SUCCESS;
    case MLDSA_LEVEL3: *len = DILITHIUM_LEVEL3_PUB_KEY_SIZE; return PIQ_SUCCESS;
    case MLDSA_LEVEL5: *len = DILITHIUM_LEVEL5_PUB_KEY_SIZE; return PIQ_SUCCESS;
    default:                                                    return PIQ_INVALID_PARAMS;
    }
}

static int mldsa_priv_key_len(uint8_t level, size_t *len)
{
    switch (level) {
    case MLDSA_LEVEL2: *len = DILITHIUM_LEVEL2_PRV_KEY_SIZE; return PIQ_SUCCESS;
    case MLDSA_LEVEL3: *len = DILITHIUM_LEVEL3_PRV_KEY_SIZE; return PIQ_SUCCESS;
    case MLDSA_LEVEL5: *len = DILITHIUM_LEVEL5_PRV_KEY_SIZE; return PIQ_SUCCESS;
    default:                                                    return PIQ_INVALID_PARAMS;
    }
}

static int mldsa_sig_len(uint8_t level, size_t *len)
{
    switch (level) {
    case MLDSA_LEVEL2: *len = DILITHIUM_LEVEL2_SIG_SIZE; return PIQ_SUCCESS;
    case MLDSA_LEVEL3: *len = DILITHIUM_LEVEL3_SIG_SIZE; return PIQ_SUCCESS;
    case MLDSA_LEVEL5: *len = DILITHIUM_LEVEL5_SIG_SIZE; return PIQ_SUCCESS;
    default:                                               return PIQ_INVALID_PARAMS;
    }
}

/*
 * Initialise a WolfSSL RNG.
 *
 * Inside OP-TEE there is no kernel entropy source available to WolfSSL,
 * so we seed the DRBG manually with bytes from TEE_GenerateRandom.
 * Outside OP-TEE we let WolfSSL collect entropy normally.
 */
static int rng_init(WC_RNG *rng)
{
#ifdef OPTEE
    uint8_t seed[48];
    int     ret;

    TEE_GenerateRandom(seed, sizeof(seed));
    ret = wc_InitRngNonce(rng, seed, (word32)sizeof(seed));
    piq_zero(seed, sizeof(seed));
    return ret;
#else
    return wc_InitRng(rng);
#endif
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

int mldsa_keygen(const struct mldsa_keygen_in *in,
                 struct mldsa_keygen_out **out)
{
    int      ret        = PIQ_SUCCESS;
    int      wc_ret;
    int      param      = 0;
    MlDsaKey key;
    WC_RNG   rng;
    uint8_t *pub_buf    = NULL;
    uint8_t *priv_buf   = NULL;
    size_t   pub_len    = 0;
    size_t   priv_len   = 0;
    word32   wc_pub_len;
    word32   wc_priv_len;
    int      key_inited = 0;
    int      rng_inited = 0;

    if (!in || !out) {
        return PIQ_INVALID_PARAMS;
    }

    if ((ret = mldsa_level_to_param(in->level, &param)) != PIQ_SUCCESS) {
        return ret;
    }
    if ((ret = mldsa_pub_key_len(in->level, &pub_len))   != PIQ_SUCCESS ||
        (ret = mldsa_priv_key_len(in->level, &priv_len)) != PIQ_SUCCESS) {
        return ret;
    }

    if ((wc_ret = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID)) != 0) {
        return PIQ_CRYPTO_ERROR;
    }
    key_inited = 1;

    if ((wc_ret = wc_MlDsaKey_SetParams(&key, param)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    if ((wc_ret = rng_init(&rng)) != 0) {
        ret = PIQ_RAND_ERROR;
        goto cleanup;
    }
    rng_inited = 1;

    if ((wc_ret = wc_MlDsaKey_MakeKey(&key, &rng)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    /* Allocate export buffers on the heap — key material is too large for TA stack */
    pub_buf = (uint8_t *)calloc(1, pub_len);
    if (!pub_buf) {
        ret = PIQ_MEM_ERROR;
        goto cleanup;
    }

    priv_buf = (uint8_t *)calloc(1, priv_len);
    if (!priv_buf) {
        ret = PIQ_MEM_ERROR;
        goto cleanup;
    }

    wc_pub_len  = (word32)pub_len;
    wc_priv_len = (word32)priv_len;

    if ((wc_ret = wc_MlDsaKey_ExportPubRaw(&key, pub_buf, &wc_pub_len)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    if ((wc_ret = wc_MlDsaKey_ExportPrivRaw(&key, priv_buf, &wc_priv_len)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    *out = (struct mldsa_keygen_out *)calloc(1, sizeof(struct mldsa_keygen_out));
    if (!*out) {
        ret = PIQ_MEM_ERROR;
        goto cleanup;
    }

    (*out)->public_key = (struct piq_buffer *)calloc(1, sizeof(struct piq_buffer));
    if (!(*out)->public_key) {
        free(*out);
        *out = NULL;
        ret  = PIQ_MEM_ERROR;
        goto cleanup;
    }

    (*out)->private_key = (struct piq_buffer *)calloc(1, sizeof(struct piq_buffer));
    if (!(*out)->private_key) {
        free((*out)->public_key);
        free(*out);
        *out = NULL;
        ret  = PIQ_MEM_ERROR;
        goto cleanup;
    }

    (*out)->public_key->buffer     = pub_buf;
    (*out)->public_key->buffer_len = (size_t)wc_pub_len;
    pub_buf                        = NULL; /* ownership transferred */

    (*out)->private_key->buffer     = priv_buf;
    (*out)->private_key->buffer_len = (size_t)wc_priv_len;
    priv_buf                        = NULL; /* ownership transferred */

cleanup:
    if (key_inited) {
        wc_MlDsaKey_Free(&key);
    }
    if (rng_inited) {
        wc_FreeRng(&rng);
    }
    if (pub_buf) {
        piq_zero(pub_buf, pub_len);
        free(pub_buf);
    }
    if (priv_buf) {
        piq_zero(priv_buf, priv_len);
        free(priv_buf);
    }
    return ret;
}

int free_mldsa_keygen_out(struct mldsa_keygen_out *out)
{
    if (!out) {
        return PIQ_SUCCESS;
    }
    if (out->public_key) {
        if (out->public_key->buffer) {
            free(out->public_key->buffer);
            out->public_key->buffer = NULL;
        }
        free(out->public_key);
        out->public_key = NULL;
    }
    if (out->private_key) {
        if (out->private_key->buffer) {
            piq_zero(out->private_key->buffer, out->private_key->buffer_len);
            free(out->private_key->buffer);
            out->private_key->buffer = NULL;
        }
        free(out->private_key);
        out->private_key = NULL;
    }
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

int mldsa_sign(const struct mldsa_sign_in *in,
               struct mldsa_sign_out **out)
{
    int      ret        = PIQ_SUCCESS;
    int      wc_ret;
    int      param      = 0;
    MlDsaKey key;
    WC_RNG   rng;
    uint8_t *sig_buf    = NULL;
    size_t   sig_max    = 0;
    word32   sig_len;
    int      key_inited = 0;
    int      rng_inited = 0;

    if (!in || !out ||
        !in->private_key || !in->private_key->buffer ||
        !in->message     || !in->message->buffer) {
        return PIQ_INVALID_PARAMS;
    }

    if ((ret = mldsa_level_to_param(in->level, &param)) != PIQ_SUCCESS) {
        return ret;
    }
    if ((ret = mldsa_sig_len(in->level, &sig_max)) != PIQ_SUCCESS) {
        return ret;
    }

    if ((wc_ret = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID)) != 0) {
        return PIQ_CRYPTO_ERROR;
    }
    key_inited = 1;

    if ((wc_ret = wc_MlDsaKey_SetParams(&key, param)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    if ((wc_ret = wc_MlDsaKey_ImportPrivRaw(&key,
                                             in->private_key->buffer,
                                             (word32)in->private_key->buffer_len)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    if ((wc_ret = rng_init(&rng)) != 0) {
        ret = PIQ_RAND_ERROR;
        goto cleanup;
    }
    rng_inited = 1;

    sig_buf = (uint8_t *)calloc(1, sig_max);
    if (!sig_buf) {
        ret = PIQ_MEM_ERROR;
        goto cleanup;
    }
    sig_len = (word32)sig_max;

    if ((wc_ret = wc_MlDsaKey_Sign(&key,
                                    sig_buf, &sig_len,
                                    in->message->buffer,
                                    (word32)in->message->buffer_len,
                                    &rng)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    *out = (struct mldsa_sign_out *)calloc(1, sizeof(struct mldsa_sign_out));
    if (!*out) {
        ret = PIQ_MEM_ERROR;
        goto cleanup;
    }

    (*out)->signature = (struct piq_buffer *)calloc(1, sizeof(struct piq_buffer));
    if (!(*out)->signature) {
        free(*out);
        *out = NULL;
        ret  = PIQ_MEM_ERROR;
        goto cleanup;
    }

    (*out)->signature->buffer     = sig_buf;
    (*out)->signature->buffer_len = (size_t)sig_len;
    sig_buf                       = NULL; /* ownership transferred */

cleanup:
    if (key_inited) {
        wc_MlDsaKey_Free(&key);
    }
    if (rng_inited) {
        wc_FreeRng(&rng);
    }
    if (sig_buf) {
        free(sig_buf);
    }
    return ret;
}

int free_mldsa_sign_out(struct mldsa_sign_out *out)
{
    if (!out) {
        return PIQ_SUCCESS;
    }
    if (out->signature) {
        if (out->signature->buffer) {
            free(out->signature->buffer);
            out->signature->buffer = NULL;
        }
        free(out->signature);
        out->signature = NULL;
    }
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

int mldsa_verify(const struct mldsa_verify_in *in)
{
    int      ret        = PIQ_SUCCESS;
    int      wc_ret;
    int      param      = 0;
    int      valid      = 0;
    MlDsaKey key;
    int      key_inited = 0;

    if (!in ||
        !in->public_key  || !in->public_key->buffer  ||
        !in->message     || !in->message->buffer      ||
        !in->signature   || !in->signature->buffer) {
        return PIQ_INVALID_PARAMS;
    }

    if ((ret = mldsa_level_to_param(in->level, &param)) != PIQ_SUCCESS) {
        return ret;
    }

    if ((wc_ret = wc_MlDsaKey_Init(&key, NULL, INVALID_DEVID)) != 0) {
        return PIQ_CRYPTO_ERROR;
    }
    key_inited = 1;

    if ((wc_ret = wc_MlDsaKey_SetParams(&key, param)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    if ((wc_ret = wc_MlDsaKey_ImportPubRaw(&key,
                                            in->public_key->buffer,
                                            (word32)in->public_key->buffer_len)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    if ((wc_ret = wc_MlDsaKey_Verify(&key,
                                      in->signature->buffer,
                                      (word32)in->signature->buffer_len,
                                      in->message->buffer,
                                      (word32)in->message->buffer_len,
                                      &valid)) != 0) {
        ret = PIQ_CRYPTO_ERROR;
        goto cleanup;
    }

    ret = (valid == 1) ? PIQ_SUCCESS : PIQ_VERIFY_FAILED;

cleanup:
    if (key_inited) {
        wc_MlDsaKey_Free(&key);
    }
    return ret;
}
