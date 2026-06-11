#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include <piqaso/aes.h>
#include <piqaso/errors.h>

#define PLAINTEXT  "Hello, piqaso AES! This is a test message of variable length."
#define AAD_DATA   "authenticated-but-not-encrypted"
#define KEY_256    "\x60\x3d\xeb\x10\x15\xca\x71\xbe" \
                   "\x2b\x73\xae\xf0\x85\x7d\x77\x81" \
                   "\x1f\x35\x2c\x07\x3b\x61\x08\xd7" \
                   "\x2d\x98\x10\xa3\x09\x14\xdf\xf4"
#define KEY_128    "\x2b\x7e\x15\x16\x28\xae\xd2\xa6" \
                   "\xab\xf7\x15\x88\x09\xcf\x4f\x3c"

/* ------------------------------------------------------------------ */
/* AES-GCM tests                                                       */
/* ------------------------------------------------------------------ */

static int test_aesgcm_roundtrip(const char *label,
                                 const uint8_t *key, size_t key_len,
                                 int with_aad)
{
    int ret;
    const char *pt = PLAINTEXT;
    struct piq_buffer key_buf  = { (uint8_t *)key, key_len };
    struct piq_buffer plain    = { (uint8_t *)pt, strlen(pt) };
    struct piq_buffer aad_buf  = { (uint8_t *)AAD_DATA, strlen(AAD_DATA) };

    struct aesgcm_encrypt_in  enc_in = {
        .key       = &key_buf,
        .iv        = NULL,          /* auto-generate */
        .plaintext = &plain,
        .aad       = with_aad ? &aad_buf : NULL,
    };
    struct aesgcm_encrypt_out *enc_out = NULL;
    struct aesgcm_decrypt_out *dec_out = NULL;

    printf("  [GCM %s%s] encrypt... ", label, with_aad ? " +AAD" : "");
    fflush(stdout);

    ret = aesgcm_encrypt(&enc_in, &enc_out);
    if (ret != PIQ_SUCCESS) { printf("FAIL (%d)\n", ret); return ret; }
    printf("OK  ct=%zu  tag=%zu  iv=%zu\n",
           enc_out->ciphertext->buffer_len,
           enc_out->tag->buffer_len,
           enc_out->iv->buffer_len);

    /* Decrypt */
    struct aesgcm_decrypt_in dec_in = {
        .key        = &key_buf,
        .iv         = enc_out->iv,
        .ciphertext = enc_out->ciphertext,
        .tag        = enc_out->tag,
        .aad        = with_aad ? &aad_buf : NULL,
    };

    printf("  [GCM %s%s] decrypt... ", label, with_aad ? " +AAD" : "");
    fflush(stdout);
    ret = aesgcm_decrypt(&dec_in, &dec_out);
    if (ret != PIQ_SUCCESS) {
        printf("FAIL (%d)\n", ret);
        free_aesgcm_encrypt_out(enc_out);
        return ret;
    }
    if (dec_out->plaintext->buffer_len != strlen(pt) ||
        memcmp(dec_out->plaintext->buffer, pt, strlen(pt)) != 0) {
        printf("FAIL (plaintext mismatch)\n");
        free_aesgcm_decrypt_out(dec_out);
        free_aesgcm_encrypt_out(enc_out);
        return -1;
    }
    printf("OK\n");

    /* Tamper tag → expect PIQ_VERIFY_FAILED */
    enc_out->tag->buffer[0] ^= 0xFF;
    struct aesgcm_decrypt_out *bad_out = NULL;
    printf("  [GCM %s] tampered tag (expect FAIL)... ", label);
    fflush(stdout);
    ret = aesgcm_decrypt(&dec_in, &bad_out);
    if (ret != PIQ_VERIFY_FAILED) {
        printf("FAIL — expected PIQ_VERIFY_FAILED, got %d\n", ret);
        free_aesgcm_decrypt_out(bad_out);
        free_aesgcm_decrypt_out(dec_out);
        free_aesgcm_encrypt_out(enc_out);
        return -1;
    }
    printf("OK (correctly rejected)\n");

    /* Tamper AAD → expect PIQ_VERIFY_FAILED (only when AAD was used) */
    if (with_aad) {
        enc_out->tag->buffer[0] ^= 0xFF;  /* restore tag */
        struct piq_buffer bad_aad = { (uint8_t *)"wrong-aad", 9 };
        dec_in.aad = &bad_aad;
        struct aesgcm_decrypt_out *bad_aad_out = NULL;
        printf("  [GCM %s] tampered AAD (expect FAIL)... ", label);
        fflush(stdout);
        ret = aesgcm_decrypt(&dec_in, &bad_aad_out);
        if (ret != PIQ_VERIFY_FAILED) {
            printf("FAIL — expected PIQ_VERIFY_FAILED, got %d\n", ret);
            free_aesgcm_decrypt_out(bad_aad_out);
            free_aesgcm_decrypt_out(dec_out);
            free_aesgcm_encrypt_out(enc_out);
            return -1;
        }
        printf("OK (correctly rejected)\n");
    }

    free_aesgcm_decrypt_out(dec_out);
    free_aesgcm_encrypt_out(enc_out);
    return PIQ_SUCCESS;
}

static int test_aesgcm_empty_plaintext(void)
{
    int ret;
    const uint8_t *key = (const uint8_t *)KEY_256;
    struct piq_buffer key_buf = { (uint8_t *)key, 32 };
    struct piq_buffer plain   = { (uint8_t *)"", 0 };
    struct piq_buffer aad     = { (uint8_t *)AAD_DATA, strlen(AAD_DATA) };

    struct aesgcm_encrypt_in  enc_in = { &key_buf, NULL, &plain, &aad };
    struct aesgcm_encrypt_out *enc_out = NULL;
    struct aesgcm_decrypt_out *dec_out = NULL;

    printf("  [GCM empty plaintext + AAD] encrypt... ");
    fflush(stdout);
    ret = aesgcm_encrypt(&enc_in, &enc_out);
    if (ret != PIQ_SUCCESS) { printf("FAIL (%d)\n", ret); return ret; }
    printf("OK  ct=%zu\n", enc_out->ciphertext->buffer_len);

    struct aesgcm_decrypt_in dec_in = {
        &key_buf, enc_out->iv, enc_out->ciphertext, enc_out->tag, &aad
    };
    printf("  [GCM empty plaintext + AAD] decrypt... ");
    fflush(stdout);
    ret = aesgcm_decrypt(&dec_in, &dec_out);
    if (ret != PIQ_SUCCESS) {
        printf("FAIL (%d)\n", ret);
        free_aesgcm_encrypt_out(enc_out);
        return ret;
    }
    printf("OK  pt_len=%zu\n", dec_out->plaintext->buffer_len);
    free_aesgcm_decrypt_out(dec_out);
    free_aesgcm_encrypt_out(enc_out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* AES-CBC tests                                                       */
/* ------------------------------------------------------------------ */

static int test_aescbc_roundtrip(const char *label,
                                 const uint8_t *key, size_t key_len,
                                 const char *plaintext)
{
    int ret;
    struct piq_buffer key_buf = { (uint8_t *)key, key_len };
    struct piq_buffer plain   = { (uint8_t *)plaintext, strlen(plaintext) };

    struct aescbc_encrypt_in  enc_in  = { &key_buf, NULL, &plain };
    struct aescbc_encrypt_out *enc_out = NULL;
    struct aescbc_decrypt_out *dec_out = NULL;

    printf("  [CBC %s] encrypt '%s'... ", label, plaintext);
    fflush(stdout);
    ret = aescbc_encrypt(&enc_in, &enc_out);
    if (ret != PIQ_SUCCESS) { printf("FAIL (%d)\n", ret); return ret; }
    printf("OK  pt=%zu  ct=%zu (padded)\n",
           strlen(plaintext), enc_out->ciphertext->buffer_len);

    struct aescbc_decrypt_in dec_in = {
        &key_buf, enc_out->iv, enc_out->ciphertext
    };
    printf("  [CBC %s] decrypt... ", label);
    fflush(stdout);
    ret = aescbc_decrypt(&dec_in, &dec_out);
    if (ret != PIQ_SUCCESS) {
        printf("FAIL (%d)\n", ret);
        free_aescbc_encrypt_out(enc_out);
        return ret;
    }
    if (dec_out->plaintext->buffer_len != strlen(plaintext) ||
        memcmp(dec_out->plaintext->buffer, plaintext, strlen(plaintext)) != 0) {
        printf("FAIL (plaintext mismatch, got %zu bytes)\n",
               dec_out->plaintext->buffer_len);
        free_aescbc_decrypt_out(dec_out);
        free_aescbc_encrypt_out(enc_out);
        return -1;
    }
    printf("OK\n");

    free_aescbc_decrypt_out(dec_out);
    free_aescbc_encrypt_out(enc_out);
    return PIQ_SUCCESS;
}

static int test_aescbc_bad_padding(void)
{
    int ret;
    const uint8_t *key = (const uint8_t *)KEY_256;
    struct piq_buffer key_buf = { (uint8_t *)key, 32 };
    const char *pt = "exactly 16 bytes";  /* 16 bytes — gets a full block of padding */
    struct piq_buffer plain = { (uint8_t *)pt, strlen(pt) };

    struct aescbc_encrypt_in  enc_in  = { &key_buf, NULL, &plain };
    struct aescbc_encrypt_out *enc_out = NULL;
    struct aescbc_decrypt_out *dec_out = NULL;

    ret = aescbc_encrypt(&enc_in, &enc_out);
    if (ret != PIQ_SUCCESS) return ret;

    /* Corrupt the last byte of ciphertext → garbles the padding block */
    enc_out->ciphertext->buffer[enc_out->ciphertext->buffer_len - 1] ^= 0x01;

    struct aescbc_decrypt_in dec_in = {
        &key_buf, enc_out->iv, enc_out->ciphertext
    };

    printf("  [CBC] bad padding (expect FAIL)... ");
    fflush(stdout);
    ret = aescbc_decrypt(&dec_in, &dec_out);
    if (ret == PIQ_SUCCESS) {
        printf("FAIL — expected error, got success\n");
        free_aescbc_decrypt_out(dec_out);
        free_aescbc_encrypt_out(enc_out);
        return -1;
    }
    printf("OK (correctly rejected, ret=%d)\n", ret);
    free_aescbc_encrypt_out(enc_out);
    return PIQ_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* main                                                                */
/* ------------------------------------------------------------------ */

int main(void)
{
    int failures = 0;
    const uint8_t *k256 = (const uint8_t *)KEY_256;
    const uint8_t *k128 = (const uint8_t *)KEY_128;

    printf("=== AES-GCM tests ===\n\n");

    if (test_aesgcm_roundtrip("AES-256", k256, 32, 0) != PIQ_SUCCESS) failures++;
    if (test_aesgcm_roundtrip("AES-256", k256, 32, 1) != PIQ_SUCCESS) failures++;
    if (test_aesgcm_roundtrip("AES-128", k128, 16, 0) != PIQ_SUCCESS) failures++;
    if (test_aesgcm_roundtrip("AES-128", k128, 16, 1) != PIQ_SUCCESS) failures++;
    if (test_aesgcm_empty_plaintext()                  != PIQ_SUCCESS) failures++;

    printf("\n=== AES-CBC tests ===\n\n");

    /* Various plaintext lengths to exercise padding */
    if (test_aescbc_roundtrip("AES-256 len=0",  k256, 32, "")             != PIQ_SUCCESS) failures++;
    if (test_aescbc_roundtrip("AES-256 len=1",  k256, 32, "A")            != PIQ_SUCCESS) failures++;
    if (test_aescbc_roundtrip("AES-256 len=15", k256, 32, "fifteen bytes!!")!= PIQ_SUCCESS) failures++;
    if (test_aescbc_roundtrip("AES-256 len=16", k256, 32, "exactly 16 bytes")!= PIQ_SUCCESS) failures++;
    if (test_aescbc_roundtrip("AES-256 long",   k256, 32, PLAINTEXT)      != PIQ_SUCCESS) failures++;
    if (test_aescbc_roundtrip("AES-128",         k128, 16, PLAINTEXT)     != PIQ_SUCCESS) failures++;
    if (test_aescbc_bad_padding()                                          != PIQ_SUCCESS) failures++;

    printf("\n=== %s ===\n", failures == 0 ? "ALL PASS" : "SOME TESTS FAILED");
    return failures == 0 ? 0 : 1;
}
