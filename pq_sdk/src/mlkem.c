#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/wc_kyber.h>
#include <wolfssl/wolfcrypt/random.h>

#include <piqaso/mlkem.h>
#include <piqaso/errors.h>
#include <piqaso/structs.h>

/* Secure zero-fill that won't be optimised away.
 * explicit_bzero is available on glibc (Linux) and OP-TEE's libc. */
#define piq_zero(p, n)  explicit_bzero((p), (n))

#ifdef OPTEE
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#endif

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

static int mlkem_level_to_type(uint8_t level, int *type)
{
    switch (level) {
    case MLKEM_LEVEL1: *type = WC_ML_KEM_512;  return PIQ_SUCCESS;
    case MLKEM_LEVEL3: *type = WC_ML_KEM_768;  return PIQ_SUCCESS;
    case MLKEM_LEVEL5: *type = WC_ML_KEM_1024; return PIQ_SUCCESS;
    default:                                     return PIQ_INVALID_PARAMS;
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

/* Allocate a piq_buffer and copy len bytes from src into it. */
static struct piq_buffer *make_buffer(const uint8_t *src, size_t len)
{
    struct piq_buffer *b = calloc(1, sizeof(*b));
    if (!b)
        return NULL;
    b->buffer = calloc(1, len);
    if (!b->buffer) {
        free(b);
        return NULL;
    }
    memcpy(b->buffer, src, len);
    b->buffer_len = len;
    return b;
}

static void free_buffer(struct piq_buffer *b)
{
    if (b) {
        free(b->buffer);
        free(b);
    }
}

static void free_buffer_secure(struct piq_buffer *b)
{
    if (b) {
        if (b->buffer)
            piq_zero(b->buffer, b->buffer_len);
        free(b->buffer);
        free(b);
    }
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

int mlkem_keygen(const struct mlkem_keygen_in *in,
                 struct mlkem_keygen_out **out)
{
    int      ret      = PIQ_SUCCESS;
    int      wc_ret;
    int      type     = 0;
    KyberKey key;
    WC_RNG   rng;
    int      rng_inited = 0;
    int      key_inited = 0;
    uint8_t *pub_buf  = NULL;
    uint8_t *priv_buf = NULL;
    word32   pub_len  = 0;
    word32   priv_len = 0;
    struct mlkem_keygen_out *result = NULL;

    if (!in || !out)
        return PIQ_INVALID_PARAMS;

    ret = mlkem_level_to_type(in->level, &type);
    if (ret != PIQ_SUCCESS)
        return ret;

    wc_ret = wc_KyberKey_Init(type, &key, NULL, INVALID_DEVID);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }
    key_inited = 1;

    wc_ret = rng_init(&rng);
    if (wc_ret != 0) { ret = PIQ_RAND_ERROR; goto cleanup; }
    rng_inited = 1;

    wc_ret = wc_KyberKey_MakeKey(&key, &rng);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_KyberKey_PublicKeySize(&key, &pub_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_KyberKey_PrivateKeySize(&key, &priv_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    pub_buf = calloc(1, pub_len);
    if (!pub_buf) { ret = PIQ_MEM_ERROR; goto cleanup; }

    priv_buf = calloc(1, priv_len);
    if (!priv_buf) { ret = PIQ_MEM_ERROR; goto cleanup; }

    wc_ret = wc_KyberKey_EncodePublicKey(&key, pub_buf, pub_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_KyberKey_EncodePrivateKey(&key, priv_buf, priv_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->public_key = make_buffer(pub_buf, pub_len);
    if (!result->public_key) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->private_key = make_buffer(priv_buf, priv_len);
    if (!result->private_key) { ret = PIQ_MEM_ERROR; goto cleanup; }

    *out = result;
    result = NULL;  /* ownership transferred */

cleanup:
    if (key_inited)  wc_KyberKey_Free(&key);
    if (rng_inited)  wc_FreeRng(&rng);
    if (pub_buf)  { piq_zero(pub_buf,  pub_len);  free(pub_buf); }
    if (priv_buf) { piq_zero(priv_buf, priv_len); free(priv_buf); }
    if (result) {
        free_buffer(result->public_key);
        free_buffer_secure(result->private_key);
        free(result);
    }
    return ret;
}

int free_mlkem_keygen_out(struct mlkem_keygen_out *out)
{
    if (!out)
        return PIQ_INVALID_PARAMS;
    free_buffer(out->public_key);
    free_buffer_secure(out->private_key);
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Encapsulation                                                        */
/* ------------------------------------------------------------------ */

int mlkem_encaps(const struct mlkem_encaps_in *in,
                 struct mlkem_encaps_out **out)
{
    int      ret      = PIQ_SUCCESS;
    int      wc_ret;
    int      type     = 0;
    KyberKey key;
    WC_RNG   rng;
    int      rng_inited = 0;
    int      key_inited = 0;
    uint8_t *ct_buf   = NULL;
    uint8_t *ss_buf   = NULL;
    word32   ct_len   = 0;
    word32   ss_len   = 0;
    struct mlkem_encaps_out *result = NULL;

    if (!in || !in->public_key || !in->public_key->buffer || !out)
        return PIQ_INVALID_PARAMS;

    ret = mlkem_level_to_type(in->level, &type);
    if (ret != PIQ_SUCCESS)
        return ret;

    wc_ret = wc_KyberKey_Init(type, &key, NULL, INVALID_DEVID);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }
    key_inited = 1;

    wc_ret = wc_KyberKey_DecodePublicKey(&key,
                 in->public_key->buffer,
                 (word32)in->public_key->buffer_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_KyberKey_CipherTextSize(&key, &ct_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_KyberKey_SharedSecretSize(&key, &ss_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    ct_buf = calloc(1, ct_len);
    if (!ct_buf) { ret = PIQ_MEM_ERROR; goto cleanup; }

    ss_buf = calloc(1, ss_len);
    if (!ss_buf) { ret = PIQ_MEM_ERROR; goto cleanup; }

    wc_ret = rng_init(&rng);
    if (wc_ret != 0) { ret = PIQ_RAND_ERROR; goto cleanup; }
    rng_inited = 1;

    wc_ret = wc_KyberKey_Encapsulate(&key, ct_buf, ss_buf, &rng);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->ciphertext = make_buffer(ct_buf, ct_len);
    if (!result->ciphertext) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->shared_secret = make_buffer(ss_buf, ss_len);
    if (!result->shared_secret) { ret = PIQ_MEM_ERROR; goto cleanup; }

    *out = result;
    result = NULL;

cleanup:
    if (key_inited)  wc_KyberKey_Free(&key);
    if (rng_inited)  wc_FreeRng(&rng);
    if (ct_buf) { free(ct_buf); }
    if (ss_buf) { piq_zero(ss_buf, ss_len); free(ss_buf); }
    if (result) {
        free_buffer(result->ciphertext);
        free_buffer_secure(result->shared_secret);
        free(result);
    }
    return ret;
}

int free_mlkem_encaps_out(struct mlkem_encaps_out *out)
{
    if (!out)
        return PIQ_INVALID_PARAMS;
    free_buffer(out->ciphertext);
    free_buffer_secure(out->shared_secret);
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Decapsulation                                                        */
/* ------------------------------------------------------------------ */

int mlkem_decaps(const struct mlkem_decaps_in *in,
                 struct mlkem_decaps_out **out)
{
    int      ret      = PIQ_SUCCESS;
    int      wc_ret;
    int      type     = 0;
    KyberKey key;
    int      key_inited = 0;
    uint8_t *ss_buf   = NULL;
    word32   ss_len   = 0;
    struct mlkem_decaps_out *result = NULL;

    if (!in || !in->private_key || !in->private_key->buffer ||
        !in->ciphertext || !in->ciphertext->buffer || !out)
        return PIQ_INVALID_PARAMS;

    ret = mlkem_level_to_type(in->level, &type);
    if (ret != PIQ_SUCCESS)
        return ret;

    wc_ret = wc_KyberKey_Init(type, &key, NULL, INVALID_DEVID);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }
    key_inited = 1;

    wc_ret = wc_KyberKey_DecodePrivateKey(&key,
                 in->private_key->buffer,
                 (word32)in->private_key->buffer_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_KyberKey_SharedSecretSize(&key, &ss_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    ss_buf = calloc(1, ss_len);
    if (!ss_buf) { ret = PIQ_MEM_ERROR; goto cleanup; }

    wc_ret = wc_KyberKey_Decapsulate(&key, ss_buf,
                 in->ciphertext->buffer,
                 (word32)in->ciphertext->buffer_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->shared_secret = make_buffer(ss_buf, ss_len);
    if (!result->shared_secret) { ret = PIQ_MEM_ERROR; goto cleanup; }

    *out = result;
    result = NULL;

cleanup:
    if (key_inited)  wc_KyberKey_Free(&key);
    if (ss_buf) { piq_zero(ss_buf, ss_len); free(ss_buf); }
    if (result) {
        free_buffer_secure(result->shared_secret);
        free(result);
    }
    return ret;
}

int free_mlkem_decaps_out(struct mlkem_decaps_out *out)
{
    if (!out)
        return PIQ_INVALID_PARAMS;
    free_buffer_secure(out->shared_secret);
    free(out);
    return PIQ_SUCCESS;
}
