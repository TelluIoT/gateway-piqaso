#ifndef PIQASO_MLDSA_H
#define PIQASO_MLDSA_H

#include <stdint.h>
#include <stddef.h>
#include <piqaso/structs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ML-DSA security level (FIPS 204).
 *   MLDSA_LEVEL2  -> ML-DSA-44  (CRYSTALS-Dilithium2)
 *   MLDSA_LEVEL3  -> ML-DSA-65  (CRYSTALS-Dilithium3)
 *   MLDSA_LEVEL5  -> ML-DSA-87  (CRYSTALS-Dilithium5)
 */
#define MLDSA_LEVEL2  2
#define MLDSA_LEVEL3  3
#define MLDSA_LEVEL5  5

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

struct mldsa_keygen_in {
    uint8_t level;          /* MLDSA_LEVEL2 / 3 / 5 */
};

struct mldsa_keygen_out {
    struct piq_buffer *public_key;
    struct piq_buffer *private_key;
};

/*
 * Generate an ML-DSA key pair.
 *
 * @in  [in]  Security level.
 * @out [out] Allocated key pair. Caller must free with free_mldsa_keygen_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int mldsa_keygen(const struct mldsa_keygen_in *in,
                 struct mldsa_keygen_out **out);

int free_mldsa_keygen_out(struct mldsa_keygen_out *out);

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

struct mldsa_sign_in {
    uint8_t            level;       /* MLDSA_LEVEL2 / 3 / 5 */
    struct piq_buffer *private_key; /* Raw private key bytes from mldsa_keygen */
    struct piq_buffer *message;     /* Message to sign */
};

struct mldsa_sign_out {
    struct piq_buffer *signature;
};

/*
 * Sign a message with an ML-DSA private key.
 *
 * @in  [in]  Level, private key bytes, and message.
 * @out [out] Allocated signature. Caller must free with free_mldsa_sign_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int mldsa_sign(const struct mldsa_sign_in *in,
               struct mldsa_sign_out **out);

int free_mldsa_sign_out(struct mldsa_sign_out *out);

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

struct mldsa_verify_in {
    uint8_t            level;       /* MLDSA_LEVEL2 / 3 / 5 */
    struct piq_buffer *public_key;  /* Raw public key bytes from mldsa_keygen */
    struct piq_buffer *message;     /* Original message */
    struct piq_buffer *signature;   /* Signature to verify */
};

/*
 * Verify an ML-DSA signature.
 *
 * Returns PIQ_SUCCESS        if the signature is valid,
 *         PIQ_VERIFY_FAILED  if the signature is invalid,
 *         other negative PIQ error code on operational failure.
 */
int mldsa_verify(const struct mldsa_verify_in *in);

#ifdef __cplusplus
}
#endif

#endif /* PIQASO_MLDSA_H */
