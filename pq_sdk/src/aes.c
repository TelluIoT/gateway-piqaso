#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/aes.h>
#include <wolfssl/wolfcrypt/random.h>

#include <piqaso/aes.h>
#include <piqaso/errors.h>
#include <piqaso/structs.h>

#define piq_zero(p, n)  explicit_bzero((p), (n))

#ifdef OPTEE
#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#endif

/* ------------------------------------------------------------------ */
/* Internal helpers                                                     */
/* ------------------------------------------------------------------ */

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

static struct piq_buffer *make_buffer(const uint8_t *src, size_t len)
{
    struct piq_buffer *b = calloc(1, sizeof(*b));
    if (!b) return NULL;
    b->buffer = calloc(1, len);
    if (!b->buffer) { free(b); return NULL; }
    if (src) memcpy(b->buffer, src, len);
    b->buffer_len = len;
    return b;
}

static void free_buffer(struct piq_buffer *b)
{
    if (b) { free(b->buffer); free(b); }
}

static void free_buffer_secure(struct piq_buffer *b)
{
    if (b) {
        if (b->buffer) piq_zero(b->buffer, b->buffer_len);
        free(b->buffer);
        free(b);
    }
}

/* Generate random bytes into a fixed-size stack buffer. */
static int gen_random(uint8_t *buf, size_t len)
{
    WC_RNG rng;
    int    ret;

    ret = rng_init(&rng);
    if (ret != 0) return PIQ_RAND_ERROR;
    ret = wc_RNG_GenerateBlock(&rng, buf, (word32)len);
    wc_FreeRng(&rng);
    return (ret == 0) ? PIQ_SUCCESS : PIQ_RAND_ERROR;
}

/* ------------------------------------------------------------------ */
/* AES-GCM encrypt                                                     */
/* ------------------------------------------------------------------ */

int aesgcm_encrypt(const struct aesgcm_encrypt_in *in,
                   struct aesgcm_encrypt_out **out)
{
    int    ret = PIQ_SUCCESS;
    int    wc_ret;
    Aes    aes;
    int    aes_inited = 0;
    uint8_t iv_buf[AES_GCM_IV_SIZE];
    const uint8_t *iv_ptr;
    struct aesgcm_encrypt_out *result = NULL;

    if (!in || !in->key || !in->key->buffer ||
        !in->plaintext || !in->plaintext->buffer || !out)
        return PIQ_INVALID_PARAMS;

    /* Validate / obtain IV */
    if (in->iv) {
        if (in->iv->buffer_len != AES_GCM_IV_SIZE)
            return PIQ_INVALID_PARAMS;
        iv_ptr = in->iv->buffer;
    } else {
        ret = gen_random(iv_buf, sizeof(iv_buf));
        if (ret != PIQ_SUCCESS) return ret;
        iv_ptr = iv_buf;
    }

    wc_ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (wc_ret != 0) return PIQ_CRYPTO_ERROR;
    aes_inited = 1;

    wc_ret = wc_AesGcmSetKey(&aes,
                 in->key->buffer, (word32)in->key->buffer_len);
    if (wc_ret != 0) { ret = PIQ_INVALID_PARAMS; goto cleanup; }

    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->iv = make_buffer(iv_ptr, AES_GCM_IV_SIZE);
    if (!result->iv) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->ciphertext = make_buffer(NULL, in->plaintext->buffer_len);
    if (!result->ciphertext) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->tag = make_buffer(NULL, AES_GCM_TAG_SIZE);
    if (!result->tag) { ret = PIQ_MEM_ERROR; goto cleanup; }

    wc_ret = wc_AesGcmEncrypt(&aes,
                 result->ciphertext->buffer,
                 in->plaintext->buffer,
                 (word32)in->plaintext->buffer_len,
                 iv_ptr, AES_GCM_IV_SIZE,
                 result->tag->buffer, AES_GCM_TAG_SIZE,
                 in->aad ? in->aad->buffer : NULL,
                 in->aad ? (word32)in->aad->buffer_len : 0);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    *out = result;
    result = NULL;

cleanup:
    if (aes_inited) wc_AesFree(&aes);
    piq_zero(iv_buf, sizeof(iv_buf));
    if (result) {
        free_buffer(result->iv);
        free_buffer_secure(result->ciphertext);
        free_buffer_secure(result->tag);
        free(result);
    }
    return ret;
}

int free_aesgcm_encrypt_out(struct aesgcm_encrypt_out *out)
{
    if (!out) return PIQ_INVALID_PARAMS;
    free_buffer(out->iv);
    free_buffer_secure(out->ciphertext);
    free_buffer_secure(out->tag);
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* AES-GCM decrypt                                                     */
/* ------------------------------------------------------------------ */

int aesgcm_decrypt(const struct aesgcm_decrypt_in *in,
                   struct aesgcm_decrypt_out **out)
{
    int    ret = PIQ_SUCCESS;
    int    wc_ret;
    Aes    aes;
    int    aes_inited = 0;
    struct aesgcm_decrypt_out *result = NULL;

    if (!in || !in->key || !in->key->buffer ||
        !in->iv || !in->iv->buffer ||
        !in->ciphertext || !in->ciphertext->buffer ||
        !in->tag || !in->tag->buffer || !out)
        return PIQ_INVALID_PARAMS;

    if (in->iv->buffer_len != AES_GCM_IV_SIZE ||
        in->tag->buffer_len != AES_GCM_TAG_SIZE)
        return PIQ_INVALID_PARAMS;

    wc_ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (wc_ret != 0) return PIQ_CRYPTO_ERROR;
    aes_inited = 1;

    wc_ret = wc_AesGcmSetKey(&aes,
                 in->key->buffer, (word32)in->key->buffer_len);
    if (wc_ret != 0) { ret = PIQ_INVALID_PARAMS; goto cleanup; }

    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->plaintext = make_buffer(NULL, in->ciphertext->buffer_len);
    if (!result->plaintext) { ret = PIQ_MEM_ERROR; goto cleanup; }

    wc_ret = wc_AesGcmDecrypt(&aes,
                 result->plaintext->buffer,
                 in->ciphertext->buffer,
                 (word32)in->ciphertext->buffer_len,
                 in->iv->buffer, AES_GCM_IV_SIZE,
                 in->tag->buffer, AES_GCM_TAG_SIZE,
                 in->aad ? in->aad->buffer : NULL,
                 in->aad ? (word32)in->aad->buffer_len : 0);

    if (wc_ret != 0) {
        /* Zero the output before returning the error */
        piq_zero(result->plaintext->buffer, result->plaintext->buffer_len);
        ret = PIQ_VERIFY_FAILED;
        goto cleanup;
    }

    *out = result;
    result = NULL;

cleanup:
    if (aes_inited) wc_AesFree(&aes);
    if (result) {
        free_buffer_secure(result->plaintext);
        free(result);
    }
    return ret;
}

int free_aesgcm_decrypt_out(struct aesgcm_decrypt_out *out)
{
    if (!out) return PIQ_INVALID_PARAMS;
    free_buffer_secure(out->plaintext);
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* AES-CBC encrypt (PKCS #7 padding)                                   */
/* ------------------------------------------------------------------ */

/* Apply PKCS #7 padding into dst.  dst must be at least padded_len bytes. */
static size_t pkcs7_pad(const uint8_t *src, size_t src_len,
                        uint8_t *dst, size_t padded_len)
{
    uint8_t pad_byte = (uint8_t)(padded_len - src_len);
    memcpy(dst, src, src_len);
    memset(dst + src_len, pad_byte, (size_t)pad_byte);
    return padded_len;
}

int aescbc_encrypt(const struct aescbc_encrypt_in *in,
                   struct aescbc_encrypt_out **out)
{
    int     ret = PIQ_SUCCESS;
    int     wc_ret;
    Aes     aes;
    int     aes_inited = 0;
    uint8_t iv_buf[AES_CBC_IV_SIZE];
    const uint8_t *iv_ptr;
    size_t  pt_len, ct_len;
    uint8_t *padded = NULL;
    struct aescbc_encrypt_out *result = NULL;

    if (!in || !in->key || !in->key->buffer ||
        !in->plaintext || !in->plaintext->buffer || !out)
        return PIQ_INVALID_PARAMS;

    if (in->iv) {
        if (in->iv->buffer_len != AES_CBC_IV_SIZE)
            return PIQ_INVALID_PARAMS;
        iv_ptr = in->iv->buffer;
    } else {
        ret = gen_random(iv_buf, sizeof(iv_buf));
        if (ret != PIQ_SUCCESS) return ret;
        iv_ptr = iv_buf;
    }

    pt_len = in->plaintext->buffer_len;
    /* PKCS #7: pad to next multiple of 16 (always at least 1 byte of padding) */
    ct_len = pt_len + (AES_CBC_BLOCK_SIZE - (pt_len % AES_CBC_BLOCK_SIZE));

    padded = calloc(1, ct_len);
    if (!padded) return PIQ_MEM_ERROR;

    pkcs7_pad(in->plaintext->buffer, pt_len, padded, ct_len);

    wc_ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }
    aes_inited = 1;

    wc_ret = wc_AesSetKey(&aes,
                 in->key->buffer, (word32)in->key->buffer_len,
                 iv_ptr, AES_ENCRYPTION);
    if (wc_ret != 0) { ret = PIQ_INVALID_PARAMS; goto cleanup; }

    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->iv = make_buffer(iv_ptr, AES_CBC_IV_SIZE);
    if (!result->iv) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->ciphertext = make_buffer(NULL, ct_len);
    if (!result->ciphertext) { ret = PIQ_MEM_ERROR; goto cleanup; }

    wc_ret = wc_AesCbcEncrypt(&aes,
                 result->ciphertext->buffer,
                 padded, (word32)ct_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    *out = result;
    result = NULL;

cleanup:
    if (aes_inited) wc_AesFree(&aes);
    if (padded) { piq_zero(padded, ct_len); free(padded); }
    piq_zero(iv_buf, sizeof(iv_buf));
    if (result) {
        free_buffer(result->iv);
        free_buffer_secure(result->ciphertext);
        free(result);
    }
    return ret;
}

int free_aescbc_encrypt_out(struct aescbc_encrypt_out *out)
{
    if (!out) return PIQ_INVALID_PARAMS;
    free_buffer(out->iv);
    free_buffer_secure(out->ciphertext);
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* AES-CBC decrypt (PKCS #7 unpadding)                                 */
/* ------------------------------------------------------------------ */

int aescbc_decrypt(const struct aescbc_decrypt_in *in,
                   struct aescbc_decrypt_out **out)
{
    int     ret = PIQ_SUCCESS;
    int     wc_ret;
    Aes     aes;
    int     aes_inited = 0;
    uint8_t *dec = NULL;
    size_t  ct_len;
    uint8_t pad_byte;
    size_t  i, pt_len;
    struct aescbc_decrypt_out *result = NULL;

    if (!in || !in->key || !in->key->buffer ||
        !in->iv || !in->iv->buffer ||
        !in->ciphertext || !in->ciphertext->buffer || !out)
        return PIQ_INVALID_PARAMS;

    ct_len = in->ciphertext->buffer_len;
    if (ct_len == 0 || ct_len % AES_CBC_BLOCK_SIZE != 0 ||
        in->iv->buffer_len != AES_CBC_IV_SIZE)
        return PIQ_INVALID_PARAMS;

    dec = calloc(1, ct_len);
    if (!dec) return PIQ_MEM_ERROR;

    wc_ret = wc_AesInit(&aes, NULL, INVALID_DEVID);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }
    aes_inited = 1;

    wc_ret = wc_AesSetKey(&aes,
                 in->key->buffer, (word32)in->key->buffer_len,
                 in->iv->buffer, AES_DECRYPTION);
    if (wc_ret != 0) { ret = PIQ_INVALID_PARAMS; goto cleanup; }

    wc_ret = wc_AesCbcDecrypt(&aes, dec, in->ciphertext->buffer, (word32)ct_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    /* Validate and strip PKCS #7 padding */
    pad_byte = dec[ct_len - 1];
    if (pad_byte == 0 || pad_byte > AES_CBC_BLOCK_SIZE) {
        ret = PIQ_INVALID_PARAMS; goto cleanup;
    }
    for (i = ct_len - pad_byte; i < ct_len; i++) {
        if (dec[i] != pad_byte) { ret = PIQ_INVALID_PARAMS; goto cleanup; }
    }
    pt_len = ct_len - pad_byte;

    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->plaintext = make_buffer(dec, pt_len);
    if (!result->plaintext) { ret = PIQ_MEM_ERROR; goto cleanup; }

    *out = result;
    result = NULL;

cleanup:
    if (aes_inited) wc_AesFree(&aes);
    if (dec) { piq_zero(dec, ct_len); free(dec); }
    if (result) {
        free_buffer_secure(result->plaintext);
        free(result);
    }
    return ret;
}

int free_aescbc_decrypt_out(struct aescbc_decrypt_out *out)
{
    if (!out) return PIQ_INVALID_PARAMS;
    free_buffer_secure(out->plaintext);
    free(out);
    return PIQ_SUCCESS;
}
