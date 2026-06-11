#ifndef PIQASO_LMS_H
#define PIQASO_LMS_H

#include <stdint.h>
#include <stddef.h>
#include <piqaso/structs.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * LMS (Leighton-Micali Signatures) / HSS — NIST SP 800-208
 *
 * LMS is a stateful hash-based signature scheme. Each call to lms_sign()
 * advances an internal counter and updates the private key.  The caller is
 * responsible for persisting the updated private key (returned in
 * lms_sign_out.updated_private_key) before the next signing operation.
 * Re-use of a private key state causes double-signing and breaks security.
 *
 * Parameter set selector (lms_parm):
 *   Use the LMS_PARM_* constants below.  They encode (levels, height,
 *   Winternitz parameter) and directly correspond to enum wc_LmsParm values.
 */

/* Compact parameter-set identifiers forwarded from WolfSSL's wc_LmsParm. */
#define LMS_PARM_L1_H5_W2    2   /* 1 level, height 5, w=2  — 32 signatures */
#define LMS_PARM_L1_H10_W2   5   /* 1 level, height 10, w=2 — 1024 signatures */
#define LMS_PARM_L2_H5_W2    14  /* 2 levels, height 5, w=2 — 1024 signatures */
#define LMS_PARM_L2_H10_W2   17  /* 2 levels, height 10, w=2 — ~1M signatures */

/* ------------------------------------------------------------------ */
/* Key generation                                                       */
/* ------------------------------------------------------------------ */

struct lms_keygen_in {
    int parm;   /* LMS_PARM_* constant — selects levels/height/Winternitz */
};

struct lms_keygen_out {
    struct piq_buffer *public_key;   /* Raw HSS public key bytes  */
    struct piq_buffer *private_key;  /* Initial private key state — MUST be
                                      * stored and updated after every sign */
};

/*
 * Generate an LMS/HSS key pair.
 *
 * The returned private_key is the initial state of the OTS key tree.
 * It must be persisted before calling lms_sign() and replaced by the
 * updated_private_key returned from every sign call.
 *
 * @in  [in]  Parameter set.
 * @out [out] Allocated key pair. Caller must free with free_lms_keygen_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int lms_keygen(const struct lms_keygen_in *in,
               struct lms_keygen_out **out);

int free_lms_keygen_out(struct lms_keygen_out *out);

/* ------------------------------------------------------------------ */
/* Signing                                                              */
/* ------------------------------------------------------------------ */

struct lms_sign_in {
    int                parm;        /* LMS_PARM_* — must match keygen parm  */
    struct piq_buffer *private_key; /* Current private key state             */
    struct piq_buffer *message;     /* Message to sign                       */
};

struct lms_sign_out {
    struct piq_buffer *signature;          /* Detached signature bytes  */
    struct piq_buffer *updated_private_key; /* Next private key state —
                                             * persist this immediately! */
};

/*
 * Sign a message with an LMS private key.
 *
 * The private key state advances after each signing.  The caller MUST
 * store updated_private_key and pass it as private_key in subsequent calls.
 * Failing to do so results in double-signing and catastrophic key compromise.
 *
 * @in  [in]  Parameter set, current private key, and message.
 * @out [out] Allocated signature + updated key state.
 *            Caller must free with free_lms_sign_out().
 *
 * Returns PIQ_SUCCESS on success, negative PIQ error code otherwise.
 */
int lms_sign(const struct lms_sign_in *in,
             struct lms_sign_out **out);

int free_lms_sign_out(struct lms_sign_out *out);

/* ------------------------------------------------------------------ */
/* Verification                                                         */
/* ------------------------------------------------------------------ */

struct lms_verify_in {
    int                parm;       /* LMS_PARM_* — must match signing parm  */
    struct piq_buffer *public_key; /* Raw HSS public key bytes               */
    struct piq_buffer *message;    /* Original signed message                */
    struct piq_buffer *signature;  /* Signature to verify                    */
};

/*
 * Verify an LMS signature.
 *
 * @in  [in]  Parameter set, public key, message, and signature.
 *
 * Returns PIQ_SUCCESS on successful verification,
 *         PIQ_VERIFY_FAILED if the signature is invalid,
 *         other negative PIQ error code on error.
 */
int lms_verify(const struct lms_verify_in *in);

#ifdef __cplusplus
}
#endif

#endif /* PIQASO_LMS_H */
