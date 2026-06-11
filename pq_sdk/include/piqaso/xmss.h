#ifndef PIQASO_XMSS_H
#define PIQASO_XMSS_H

#include <stdint.h>
#include <stddef.h>
#include <piqaso/structs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * XMSS / XMSS^MT (eXtended Merkle Signature Scheme) — NIST SP 800-208 / RFC 8391
 *
 * XMSS is a stateful hash-based signature scheme. Each call to xmss_sign()
 * advances an internal one-time key counter and updates the private key.
 * The caller is responsible for persisting the updated private key returned
 * in xmss_sign_out.updated_private_key before the next signing operation.
 * Double-use of a private key state is a catastrophic security failure.
 *
 * Parameter set strings (xmss_param_str):
 *   XMSS single-tree:
 *     "XMSS-SHA2_10_256"     — 2^10 = 1024 signatures
 *     "XMSS-SHA2_16_256"     — 2^16 = 65536 signatures
 *     "XMSS-SHA2_20_256"     — 2^20 ~= 1M signatures
 *
 *   XMSS^MT multi-tree (levels/total_height):
 *     "XMSSMT-SHA2_20/2_256" — 20-height, 2 levels
 *     "XMSSMT-SHA2_20/4_256" — 20-height, 4 levels
 *     "XMSSMT-SHA2_40/2_256" — 40-height, 2 levels
 *     "XMSSMT-SHA2_40/4_256" — 40-height, 4 levels
 *     "XMSSMT-SHA2_40/8_256" — 40-height, 8 levels
 *     "XMSSMT-SHA2_60/3_256" — 60-height, 3 levels
 *     "XMSSMT-SHA2_60/6_256" — 60-height, 6 levels
 *     "XMSSMT-SHA2_60/12_256"— 60-height, 12 levels
 */

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

struct xmss_keygen_in {
    const char *param_str;  /* e.g. "XMSS-SHA2_10_256" */
};

struct xmss_keygen_out {
    struct piq_buffer *public_key;   /* Raw XMSS public key bytes */
    struct piq_buffer *private_key;  /* Initial private key state — MUST be
                                      * stored and updated after every sign */
};

/*
 * Generate an XMSS key pair.
 *
 * The returned private_key is the initial state of the OTS key tree.
 * It must be persisted before calling xmss_sign() and replaced by the
 * updated_private_key returned from every sign call.
 *
 * @in  [in]  XMSS parameter string.
 * @out [out] Allocated key pair. Caller must free with free_xmss_keygen_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int xmss_keygen(const struct xmss_keygen_in *in,
                struct xmss_keygen_out **out);

int free_xmss_keygen_out(struct xmss_keygen_out *out);

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

struct xmss_sign_in {
    const char        *param_str;   /* XMSS parameter string               */
    struct piq_buffer *private_key; /* Current private key state            */
    struct piq_buffer *message;     /* Message to sign                      */
};

struct xmss_sign_out {
    struct piq_buffer *signature;           /* Detached signature bytes     */
    struct piq_buffer *updated_private_key; /* Next private key state —
                                             * persist this immediately!    */
};

/*
 * Sign a message with an XMSS private key.
 *
 * The private key state advances after each signing.  The caller MUST
 * store updated_private_key and pass it as private_key in subsequent calls.
 * Failing to do so results in double-signing and catastrophic key compromise.
 *
 * @in  [in]  Parameter string, current private key, and message.
 * @out [out] Allocated signature + updated key state.
 *            Caller must free with free_xmss_sign_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int xmss_sign(const struct xmss_sign_in *in,
              struct xmss_sign_out **out);

int free_xmss_sign_out(struct xmss_sign_out *out);

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

struct xmss_verify_in {
    const char        *param_str;  /* XMSS parameter string                 */
    struct piq_buffer *public_key; /* Raw XMSS public key bytes              */
    struct piq_buffer *message;    /* Original signed message                */
    struct piq_buffer *signature;  /* Signature to verify                    */
};

/*
 * Verify an XMSS signature.
 *
 * @in  [in]  Parameter string, public key, message, and signature.
 *
 * Returns PIQ_SUCCESS on successful verification,
 *         PIQ_VERIFY_FAILED if the signature is invalid,
 *         other negative PIQ error code on error.
 */
int xmss_verify(const struct xmss_verify_in *in);

#ifdef __cplusplus
}
#endif

#endif /* PIQASO_XMSS_H */
