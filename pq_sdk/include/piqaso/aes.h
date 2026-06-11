#ifndef PIQASO_AES_H
#define PIQASO_AES_H

#include <stdint.h>
#include <stddef.h>
#include <piqaso/structs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * AES wrappers — GCM (authenticated) and CBC (conventional).
 *
 * Key sizes: 16 bytes (AES-128), 24 bytes (AES-192), 32 bytes (AES-256).
 * AES-256 (32-byte key) is recommended for use alongside PQC algorithms.
 *
 * IV / Nonce generation:
 *   Pass iv = NULL in the encrypt input structs to have the SDK generate a
 *   cryptographically random IV/nonce.  The used value is always returned in
 *   the output struct so the caller can transmit it with the ciphertext.
 *   IV / nonce must always be provided explicitly for decryption.
 *
 * AES-GCM IV size  : 12 bytes  (96-bit nonce, per NIST SP 800-38D)
 * AES-CBC IV size  : 16 bytes  (one AES block)
 * AES-GCM tag size : 16 bytes
 * AES-CBC padding  : PKCS #7 (plaintext length does NOT need to be block-aligned)
 */

/* ------------------------------------------------------------------ */
/* AES-GCM  (authenticated encryption with associated data)            */
/* ------------------------------------------------------------------ */

#define AES_GCM_IV_SIZE  12   /* bytes — NIST recommended nonce length */
#define AES_GCM_TAG_SIZE 16   /* bytes — full 128-bit authentication tag */

struct aesgcm_encrypt_in {
    struct piq_buffer *key;        /* 16 / 24 / 32 bytes                    */
    struct piq_buffer *iv;         /* 12 bytes, or NULL to auto-generate     */
    struct piq_buffer *plaintext;  /* Data to encrypt                        */
    struct piq_buffer *aad;        /* Additional authenticated data, or NULL */
};

struct aesgcm_encrypt_out {
    struct piq_buffer *iv;         /* IV used (caller-supplied or generated)  */
    struct piq_buffer *ciphertext; /* Encrypted data, same length as plaintext*/
    struct piq_buffer *tag;        /* 16-byte authentication tag              */
};

/*
 * Encrypt with AES-GCM.
 *
 * @in  [in]  Key, optional IV (generated if NULL), plaintext, optional AAD.
 * @out [out] Allocated IV + ciphertext + tag.
 *            Caller must free with free_aesgcm_encrypt_out().
 *
 * Returns PIQ_SUCCESS or negative PIQ error code.
 */
int aesgcm_encrypt(const struct aesgcm_encrypt_in *in,
                   struct aesgcm_encrypt_out **out);

int free_aesgcm_encrypt_out(struct aesgcm_encrypt_out *out);

struct aesgcm_decrypt_in {
    struct piq_buffer *key;        /* 16 / 24 / 32 bytes                    */
    struct piq_buffer *iv;         /* 12-byte nonce used during encryption   */
    struct piq_buffer *ciphertext; /* Data to decrypt                        */
    struct piq_buffer *tag;        /* 16-byte authentication tag             */
    struct piq_buffer *aad;        /* Additional authenticated data, or NULL */
};

struct aesgcm_decrypt_out {
    struct piq_buffer *plaintext;  /* Decrypted data (only valid if auth OK) */
};

/*
 * Decrypt with AES-GCM.
 *
 * Authentication is verified before plaintext is returned.
 * If the tag does not match, the output plaintext buffer is zeroed and
 * PIQ_VERIFY_FAILED is returned.
 *
 * @in  [in]  Key, IV, ciphertext, tag, optional AAD.
 * @out [out] Allocated plaintext (on success).
 *            Caller must free with free_aesgcm_decrypt_out().
 *
 * Returns PIQ_SUCCESS, PIQ_VERIFY_FAILED, or other negative PIQ error code.
 */
int aesgcm_decrypt(const struct aesgcm_decrypt_in *in,
                   struct aesgcm_decrypt_out **out);

int free_aesgcm_decrypt_out(struct aesgcm_decrypt_out *out);

/* ------------------------------------------------------------------ */
/* AES-CBC  (PKCS #7 padding)                                          */
/* ------------------------------------------------------------------ */

#define AES_CBC_IV_SIZE    16   /* bytes — one AES block */
#define AES_CBC_BLOCK_SIZE 16   /* bytes */

struct aescbc_encrypt_in {
    struct piq_buffer *key;        /* 16 / 24 / 32 bytes                    */
    struct piq_buffer *iv;         /* 16 bytes, or NULL to auto-generate     */
    struct piq_buffer *plaintext;  /* Data to encrypt (any length)           */
};

struct aescbc_encrypt_out {
    struct piq_buffer *iv;         /* IV used (caller-supplied or generated)  */
    struct piq_buffer *ciphertext; /* PKCS #7 padded and encrypted data       */
};

/*
 * Encrypt with AES-CBC (PKCS #7 padding).
 *
 * @in  [in]  Key, optional IV (generated if NULL), plaintext.
 * @out [out] Allocated IV + ciphertext.
 *            Caller must free with free_aescbc_encrypt_out().
 *
 * Returns PIQ_SUCCESS or negative PIQ error code.
 */
int aescbc_encrypt(const struct aescbc_encrypt_in *in,
                   struct aescbc_encrypt_out **out);

int free_aescbc_encrypt_out(struct aescbc_encrypt_out *out);

struct aescbc_decrypt_in {
    struct piq_buffer *key;        /* 16 / 24 / 32 bytes                    */
    struct piq_buffer *iv;         /* 16-byte IV used during encryption      */
    struct piq_buffer *ciphertext; /* PKCS #7 padded ciphertext              */
};

struct aescbc_decrypt_out {
    struct piq_buffer *plaintext;  /* Decrypted and unpadded data            */
};

/*
 * Decrypt with AES-CBC and remove PKCS #7 padding.
 *
 * Returns PIQ_SUCCESS, PIQ_INVALID_PARAMS (bad padding), or other error code.
 *
 * @in  [in]  Key, IV, ciphertext.
 * @out [out] Allocated plaintext.
 *            Caller must free with free_aescbc_decrypt_out().
 */
int aescbc_decrypt(const struct aescbc_decrypt_in *in,
                   struct aescbc_decrypt_out **out);

int free_aescbc_decrypt_out(struct aescbc_decrypt_out *out);

#ifdef __cplusplus
}
#endif

#endif /* PIQASO_AES_H */
