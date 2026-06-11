#ifndef PIQASO_MLKEM_H
#define PIQASO_MLKEM_H

#include <stdint.h>
#include <stddef.h>
#include <piqaso/structs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * ML-KEM security level (FIPS 203).
 *   MLKEM_LEVEL1  -> ML-KEM-512   (CRYSTALS-Kyber512)
 *   MLKEM_LEVEL3  -> ML-KEM-768   (CRYSTALS-Kyber768)
 *   MLKEM_LEVEL5  -> ML-KEM-1024  (CRYSTALS-Kyber1024)
 */
#define MLKEM_LEVEL1  1
#define MLKEM_LEVEL3  3
#define MLKEM_LEVEL5  5

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

struct mlkem_keygen_in {
    uint8_t level;          /* MLKEM_LEVEL1 / 3 / 5 */
};

struct mlkem_keygen_out {
    struct piq_buffer *public_key;   /* encapsulation key  */
    struct piq_buffer *private_key;  /* decapsulation key  */
};

/*
 * Generate an ML-KEM key pair.
 *
 * @in  [in]  Security level.
 * @out [out] Allocated key pair. Caller must free with free_mlkem_keygen_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int mlkem_keygen(const struct mlkem_keygen_in *in,
                 struct mlkem_keygen_out **out);

int free_mlkem_keygen_out(struct mlkem_keygen_out *out);

/* ------------------------------------------------------------------ */
/* Encapsulation                                                        */
/* ------------------------------------------------------------------ */

struct mlkem_encaps_in {
    uint8_t            level;      /* MLKEM_LEVEL1 / 3 / 5 */
    struct piq_buffer *public_key; /* encapsulation key from mlkem_keygen */
};

struct mlkem_encaps_out {
    struct piq_buffer *ciphertext;     /* to be sent to the decapsulating party */
    struct piq_buffer *shared_secret;  /* 32-byte shared secret */
};

/*
 * Encapsulate: generate a ciphertext and shared secret using the public key.
 *
 * @in  [in]  Level and public key bytes.
 * @out [out] Allocated ciphertext + shared secret.
 *            Caller must free with free_mlkem_encaps_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int mlkem_encaps(const struct mlkem_encaps_in *in,
                 struct mlkem_encaps_out **out);

int free_mlkem_encaps_out(struct mlkem_encaps_out *out);

/* ------------------------------------------------------------------ */
/* Decapsulation                                                        */
/* ------------------------------------------------------------------ */

struct mlkem_decaps_in {
    uint8_t            level;       /* MLKEM_LEVEL1 / 3 / 5 */
    struct piq_buffer *private_key; /* decapsulation key from mlkem_keygen */
    struct piq_buffer *ciphertext;  /* ciphertext from mlkem_encaps */
};

struct mlkem_decaps_out {
    struct piq_buffer *shared_secret;  /* 32-byte shared secret */
};

/*
 * Decapsulate: recover the shared secret from a ciphertext using the private key.
 *
 * @in  [in]  Level, private key bytes, and ciphertext.
 * @out [out] Allocated shared secret.
 *            Caller must free with free_mlkem_decaps_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int mlkem_decaps(const struct mlkem_decaps_in *in,
                 struct mlkem_decaps_out **out);

int free_mlkem_decaps_out(struct mlkem_decaps_out *out);

#ifdef __cplusplus
}
#endif

#endif /* PIQASO_MLKEM_H */
