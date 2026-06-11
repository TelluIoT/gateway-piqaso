/* user_settings.h — piqaso_sdk WolfSSL configuration
 *
 * Included by wolfssl/wolfcrypt/settings.h when WOLFSSL_USER_SETTINGS is
 * defined.  Used by both the host CMake build (FetchContent) and the OP-TEE
 * sub.mk build.
 *
 * Keep this file minimal: only enable what piqaso_sdk actually uses so that
 * the WolfSSL build stays small enough for a Trusted Application.
 */

#ifndef PIQASO_USER_SETTINGS_H
#define PIQASO_USER_SETTINGS_H

#include <stdbool.h>  /* wolfssl falcon.h / sphincs.h use bool without including this */

/* ------------------------------------------------------------------ */
/* Core settings                                                        */
/* ------------------------------------------------------------------ */
#define NO_FILESYSTEM           /* TAs have no filesystem                    */
#define SINGLE_THREADED         /* TAs are single-threaded                   */
#define WOLFSSL_SMALL_STACK     /* reduce stack usage (important for TAs)    */

/* Timing-resistance / side-channel hardening */
#define TFM_TIMING_RESISTANT
#define ECC_TIMING_RESISTANT
#define WC_RSA_BLINDING

/* ------------------------------------------------------------------ */
/* Post-Quantum Cryptography                                            */
/* ------------------------------------------------------------------ */

/* ML-DSA / CRYSTALS-Dilithium (FIPS 204) */
#define HAVE_DILITHIUM
#define WOLFSSL_WC_DILITHIUM             /* use native wolfCrypt (non-liboqs) implementation */
#define WOLFSSL_DILITHIUM_FIPS204_DRAFT  /* enable FIPS 204 draft variants   */
#define WOLFSSL_DILITHIUM_SIGN_SMALL     /* trade speed for smaller code size */

/* ML-KEM / CRYSTALS-Kyber */
#define WOLFSSL_HAVE_KYBER
#define WOLFSSL_WC_KYBER
#define WOLFSSL_KYBER512
#define WOLFSSL_KYBER768
#define WOLFSSL_KYBER1024
#define WOLFSSL_EXPERIMENTAL    /* required by Kyber in this WolfSSL version */



/* SLH-DSA / SPHINCS+ — same issue as FALCON; disabled for now */
/* #define HAVE_SPHINCS */

/* LMS / XMSS — hash-based stateful signatures */
#define WOLFSSL_HAVE_LMS
#define WOLFSSL_WC_LMS
#define WOLFSSL_LMS_SHA256_M24_H5_W2

#define WOLFSSL_HAVE_XMSS
#define WOLFSSL_WC_XMSS
#define WOLFSSL_XMSS_SHA256

/* ------------------------------------------------------------------ */
/* Symmetric / hash primitives required by the PQC schemes             */
/* ------------------------------------------------------------------ */
#define HAVE_AES_CBC
#define HAVE_AESGCM
#define NO_RC4
#define NO_DES3
#define HAVE_SHA256
#define HAVE_SHA384
#define HAVE_SHA512
#define HAVE_SHA3
#define WOLFSSL_SHA3
#define WOLFSSL_SHAKE128    /* required by ML-KEM / ML-DSA */
#define WOLFSSL_SHAKE256    /* required by ML-KEM / ML-DSA */
#define HAVE_HKDF

/* ------------------------------------------------------------------ */
/* ECC (needed by WolfSSL internals even if we don't use it directly)  */
/* ------------------------------------------------------------------ */
#define HAVE_ECC
#define ECC_SHAMIR
#define WOLFSSL_STATIC_RSA

/* ------------------------------------------------------------------ */
/* Disable unused protocols to keep binary size down                   */
/* ------------------------------------------------------------------ */
#define NO_OLD_TLS
#define NO_PSK
#define NO_MD4
#define NO_RC2

#endif /* PIQASO_USER_SETTINGS_H */
