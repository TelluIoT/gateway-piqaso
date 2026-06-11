#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <wolfssl/wolfcrypt/lms.h>
#include <wolfssl/wolfcrypt/wc_lms.h>
#include <wolfssl/wolfcrypt/random.h>

#include <piqaso/lms.h>
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
    memcpy(b->buffer, src, len);
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

/*
 * In-memory private key store used as the WolfSSL callback context.
 *
 * WolfSSL's LMS calls write_cb after every sign (the key counter advances).
 * read_cb is called when reloading an LmsKey from the persisted bytes.
 * Both callbacks receive a pointer to this struct as context.
 */
struct lms_key_store {
    uint8_t *data;
    word32   len;
    int      write_rc;  /* last write callback result, for error detection */
};

static int lms_write_cb(const byte *priv, word32 privSz, void *ctx)
{
    struct lms_key_store *store = (struct lms_key_store *)ctx;

    if (!priv || !store)
        return WC_LMS_RC_BAD_ARG;

    /* Grow or reallocate the store buffer if needed. */
    if (privSz > store->len) {
        uint8_t *tmp = calloc(1, privSz);
        if (!tmp) {
            store->write_rc = WC_LMS_RC_WRITE_FAIL;
            return WC_LMS_RC_WRITE_FAIL;
        }
        if (store->data)
            piq_zero(store->data, store->len);
        free(store->data);
        store->data = tmp;
        store->len  = privSz;
    }

    memcpy(store->data, priv, privSz);
    store->write_rc = WC_LMS_RC_NONE;
    return WC_LMS_RC_SAVED_TO_NV_MEMORY;
}

static int lms_read_cb(byte *priv, word32 privSz, void *ctx)
{
    struct lms_key_store *store = (struct lms_key_store *)ctx;

    if (!priv || !store || !store->data)
        return WC_LMS_RC_BAD_ARG;

    if (privSz != store->len)
        return WC_LMS_RC_READ_FAIL;

    memcpy(priv, store->data, privSz);
    return WC_LMS_RC_READ_TO_MEMORY;
}

static void lms_key_store_free(struct lms_key_store *s)
{
    if (s) {
        if (s->data) piq_zero(s->data, s->len);
        free(s->data);
        free(s);
    }
}

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

int lms_keygen(const struct lms_keygen_in *in,
               struct lms_keygen_out **out)
{
    int      ret       = PIQ_SUCCESS;
    int      wc_ret;
    LmsKey   key;
    WC_RNG   rng;
    int      key_inited = 0;
    int      rng_inited = 0;
    struct lms_key_store *store = NULL;
    uint8_t *pub_buf  = NULL;
    word32   pub_len  = 0;
    word32   priv_len = 0;
    struct lms_keygen_out *result = NULL;

    if (!in || !out)
        return PIQ_INVALID_PARAMS;

    store = calloc(1, sizeof(*store));
    if (!store) return PIQ_MEM_ERROR;

    wc_ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }
    key_inited = 1;

    wc_ret = wc_LmsKey_SetLmsParm(&key, (enum wc_LmsParm)in->parm);
    if (wc_ret != 0) { ret = PIQ_INVALID_PARAMS; goto cleanup; }

    wc_ret = wc_LmsKey_SetWriteCb(&key, lms_write_cb);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_LmsKey_SetReadCb(&key, lms_read_cb);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_LmsKey_SetContext(&key, store);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = rng_init(&rng);
    if (wc_ret != 0) { ret = PIQ_RAND_ERROR; goto cleanup; }
    rng_inited = 1;

    wc_ret = wc_LmsKey_MakeKey(&key, &rng);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    /* Export public key */
    wc_ret = wc_LmsKey_GetPubLen(&key, &pub_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    pub_buf = calloc(1, pub_len);
    if (!pub_buf) { ret = PIQ_MEM_ERROR; goto cleanup; }

    wc_ret = wc_LmsKey_ExportPubRaw(&key, pub_buf, &pub_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    /* Private key was persisted to store by MakeKey via write_cb */
    wc_ret = wc_LmsKey_GetPrivLen(&key, &priv_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    if (store->len != priv_len || !store->data) {
        ret = PIQ_CRYPTO_ERROR; goto cleanup;
    }

    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->public_key = make_buffer(pub_buf, pub_len);
    if (!result->public_key) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->private_key = make_buffer(store->data, store->len);
    if (!result->private_key) { ret = PIQ_MEM_ERROR; goto cleanup; }

    *out = result;
    result = NULL;

cleanup:
    if (key_inited) wc_LmsKey_Free(&key);
    if (rng_inited) wc_FreeRng(&rng);
    if (pub_buf) free(pub_buf);
    lms_key_store_free(store);
    if (result) {
        free_buffer(result->public_key);
        free_buffer_secure(result->private_key);
        free(result);
    }
    return ret;
}

int free_lms_keygen_out(struct lms_keygen_out *out)
{
    if (!out) return PIQ_INVALID_PARAMS;
    free_buffer(out->public_key);
    free_buffer_secure(out->private_key);
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

int lms_sign(const struct lms_sign_in *in,
             struct lms_sign_out **out)
{
    int      ret       = PIQ_SUCCESS;
    int      wc_ret;
    LmsKey   key;
    int      key_inited = 0;
    struct lms_key_store *store = NULL;
    uint8_t *sig_buf  = NULL;
    word32   sig_len  = 0;
    struct lms_sign_out *result = NULL;

    if (!in || !in->private_key || !in->private_key->buffer ||
        !in->message || !in->message->buffer || !out)
        return PIQ_INVALID_PARAMS;

    /* Populate the key store with the provided private key bytes */
    store = calloc(1, sizeof(*store));
    if (!store) return PIQ_MEM_ERROR;

    store->data = calloc(1, in->private_key->buffer_len);
    if (!store->data) { ret = PIQ_MEM_ERROR; goto cleanup; }
    memcpy(store->data, in->private_key->buffer, in->private_key->buffer_len);
    store->len = (word32)in->private_key->buffer_len;

    wc_ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }
    key_inited = 1;

    wc_ret = wc_LmsKey_SetLmsParm(&key, (enum wc_LmsParm)in->parm);
    if (wc_ret != 0) { ret = PIQ_INVALID_PARAMS; goto cleanup; }

    wc_ret = wc_LmsKey_SetWriteCb(&key, lms_write_cb);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_LmsKey_SetReadCb(&key, lms_read_cb);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_LmsKey_SetContext(&key, store);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    /* Reload key from the in-memory store */
    wc_ret = wc_LmsKey_Reload(&key);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_LmsKey_GetSigLen(&key, &sig_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    sig_buf = calloc(1, sig_len);
    if (!sig_buf) { ret = PIQ_MEM_ERROR; goto cleanup; }

    wc_ret = wc_LmsKey_Sign(&key, sig_buf, &sig_len,
                             in->message->buffer,
                             (int)in->message->buffer_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    /* After Sign, write_cb was called — store->data holds updated key */
    result = calloc(1, sizeof(*result));
    if (!result) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->signature = make_buffer(sig_buf, sig_len);
    if (!result->signature) { ret = PIQ_MEM_ERROR; goto cleanup; }

    result->updated_private_key = make_buffer(store->data, store->len);
    if (!result->updated_private_key) { ret = PIQ_MEM_ERROR; goto cleanup; }

    *out = result;
    result = NULL;

cleanup:
    if (key_inited) wc_LmsKey_Free(&key);
    if (sig_buf) free(sig_buf);
    lms_key_store_free(store);
    if (result) {
        free_buffer(result->signature);
        free_buffer_secure(result->updated_private_key);
        free(result);
    }
    return ret;
}

int free_lms_sign_out(struct lms_sign_out *out)
{
    if (!out) return PIQ_INVALID_PARAMS;
    free_buffer(out->signature);
    free_buffer_secure(out->updated_private_key);
    free(out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

int lms_verify(const struct lms_verify_in *in)
{
    int    ret       = PIQ_SUCCESS;
    int    wc_ret;
    LmsKey key;
    int    key_inited = 0;
    int    valid      = 0;

    if (!in || !in->public_key || !in->public_key->buffer ||
        !in->message || !in->message->buffer ||
        !in->signature || !in->signature->buffer)
        return PIQ_INVALID_PARAMS;

    wc_ret = wc_LmsKey_Init(&key, NULL, INVALID_DEVID);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }
    key_inited = 1;

    wc_ret = wc_LmsKey_SetLmsParm(&key, (enum wc_LmsParm)in->parm);
    if (wc_ret != 0) { ret = PIQ_INVALID_PARAMS; goto cleanup; }

    wc_ret = wc_LmsKey_ImportPubRaw(&key,
                 in->public_key->buffer,
                 (word32)in->public_key->buffer_len);
    if (wc_ret != 0) { ret = PIQ_CRYPTO_ERROR; goto cleanup; }

    wc_ret = wc_LmsKey_Verify(&key,
                 in->signature->buffer,
                 (word32)in->signature->buffer_len,
                 in->message->buffer,
                 (int)in->message->buffer_len);

    if (wc_ret == 0)
        valid = 1;

    if (!valid)
        ret = PIQ_VERIFY_FAILED;

cleanup:
    if (key_inited) wc_LmsKey_Free(&key);
    return ret;
}
