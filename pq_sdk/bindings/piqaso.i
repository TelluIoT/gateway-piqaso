/*
 * SWIG interface for piqaso_sdk.
 *
 * Exposes a thin facade over the SDK's pointer-to-pointer / piq_buffer
 * API.  Each high-level operation becomes a function whose inputs are
 * raw byte buffers and whose outputs are also raw byte buffers, which
 * SWIG's standard typemaps then map onto native bytes/string types in
 * the target language (Python: bytes, Java: byte[], etc.).
 *
 * The original C API is also exposed (errors.h constants, level macros)
 * but the recommended entry points are the wrappers defined below.
 */
%module piqaso

%{
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdlib.h>

#include "piqaso/errors.h"
#include "piqaso/structs.h"
#include "piqaso/mldsa.h"
#include "piqaso/mlkem.h"
#include "piqaso/lms.h"
#include "piqaso/xmss.h"
#include "piqaso/aes.h"
%}

/* ------------------------------------------------------------------ */
/* Standard typemap libraries                                          */
/* ------------------------------------------------------------------ */
%include <stdint.i>
%include <cstring.i>
%include <exception.i>

/*
 * Input typemap: any (const char *DATA, size_t LEN) pair becomes a
 * single bytes-like argument in the target language.
 *
 * Python: bytes / bytearray / memoryview / None
 */
#if defined(SWIGPYTHON)
%typemap(in) (const char *DATA, size_t LEN) (Py_buffer view, int got_buffer = 0) {
    if ($input == Py_None) {
        $1 = NULL;
        $2 = 0;
    } else {
        if (PyObject_GetBuffer($input, &view, PyBUF_SIMPLE) != 0) {
            SWIG_exception_fail(SWIG_TypeError, "expected bytes-like object or None");
        }
        got_buffer = 1;
        $1 = (char *)view.buf;
        $2 = (size_t)view.len;
    }
}
%typemap(freearg) (const char *DATA, size_t LEN) {
    if (got_buffer$argnum) PyBuffer_Release(&view$argnum);
}

/* Apply the same in / freearg typemaps to every (DATAn, LENn) pair we use. */
%apply (const char *DATA, size_t LEN) {
    (const char *DATA1, size_t LEN1),
    (const char *DATA2, size_t LEN2),
    (const char *DATA3, size_t LEN3),
    (const char *DATA4, size_t LEN4)
};
#endif

/* ------------------------------------------------------------------ */
/* Java input typemap: byte[] (or null) -> (const char *DATA, size_t LEN)
 * ------------------------------------------------------------------ */
#if defined(SWIGJAVA)
%typemap(jni)    (const char *DATA, size_t LEN) "jbyteArray"
%typemap(jtype)  (const char *DATA, size_t LEN) "byte[]"
%typemap(jstype) (const char *DATA, size_t LEN) "byte[]"
%typemap(javain) (const char *DATA, size_t LEN) "$javainput"
%typemap(in,numinputs=1) (const char *DATA, size_t LEN) {
    if ($input == NULL) {
        $1 = NULL;
        $2 = 0;
    } else {
        $1 = (char *)JCALL2(GetByteArrayElements, jenv, $input, 0);
        $2 = (size_t)JCALL1(GetArrayLength,       jenv, $input);
    }
}
%typemap(freearg) (const char *DATA, size_t LEN) {
    if ($input != NULL) {
        JCALL3(ReleaseByteArrayElements, jenv, $input, (jbyte *)$1, JNI_ABORT);
    }
}
%apply (const char *DATA, size_t LEN) {
    (const char *DATA1, size_t LEN1),
    (const char *DATA2, size_t LEN2),
    (const char *DATA3, size_t LEN3),
    (const char *DATA4, size_t LEN4)
};
#endif

/* ------------------------------------------------------------------ */
/* JavaScript (Node.js N-API) input typemap:
 *   Buffer | Uint8Array | null  ->  (const char *DATA, size_t LEN)
 * ------------------------------------------------------------------ */
#if defined(SWIGJAVASCRIPT)
%typemap(in) (const char *DATA, size_t LEN) {
    if ($input.IsNull() || $input.IsUndefined()) {
        $1 = NULL;
        $2 = 0;
    } else if ($input.IsBuffer()) {
        Napi::Buffer<char> b = $input.As<Napi::Buffer<char>>();
        $1 = b.Data();
        $2 = b.ByteLength();
    } else if ($input.IsTypedArray()) {
        Napi::TypedArray ta = $input.As<Napi::TypedArray>();
        Napi::ArrayBuffer ab = ta.ArrayBuffer();
        $1 = static_cast<char *>(ab.Data()) + ta.ByteOffset();
        $2 = ta.ByteLength();
    } else {
        SWIG_exception_fail(SWIG_TypeError,
            "expected Buffer, Uint8Array or null");
    }
}
%apply (const char *DATA, size_t LEN) {
    (const char *DATA1, size_t LEN1),
    (const char *DATA2, size_t LEN2),
    (const char *DATA3, size_t LEN3),
    (const char *DATA4, size_t LEN4)
};
#endif

/*
 * Output: the wrapper helpers return data via (char **OUT, size_t *OUTLEN).
 * We produce a Python `bytes` object (not str) so the buffer can be passed
 * back into other binding calls via the buffer-protocol input typemap.
 */
#if defined(SWIGPYTHON)
%typemap(in, numinputs=0) (char **OUT, size_t *OUTLEN) (char *tmp = NULL, size_t tmplen = 0) {
    $1 = &tmp;
    $2 = &tmplen;
}
%typemap(argout) (char **OUT, size_t *OUTLEN) {
    PyObject *o = (*$1 == NULL)
                  ? (Py_INCREF(Py_None), Py_None)
                  : PyBytes_FromStringAndSize(*$1, *$2);
    $result = SWIG_Python_AppendOutput($result, o);
    if (*$1 != NULL) free(*$1);
}
%apply (char **OUT, size_t *OUTLEN) {
    (char **OUT1, size_t *OUTLEN1),
    (char **OUT2, size_t *OUTLEN2),
    (char **OUT3, size_t *OUTLEN3)
};
#elif defined(SWIGJAVA)
/* Java output: byte[][] holder of length >= 1.  On return holder[0] holds
 * the newly-allocated byte[] (or null if the SDK returned no buffer). */
%typemap(jni)    (char **OUT, size_t *OUTLEN) "jobjectArray"
%typemap(jtype)  (char **OUT, size_t *OUTLEN) "byte[][]"
%typemap(jstype) (char **OUT, size_t *OUTLEN) "byte[][]"
%typemap(javain) (char **OUT, size_t *OUTLEN) "$javainput"
%typemap(in)     (char **OUT, size_t *OUTLEN) (char *tmp = NULL, size_t tmplen = 0) {
    if ($input == NULL || JCALL1(GetArrayLength, jenv, $input) < 1) {
        SWIG_JavaThrowException(jenv, SWIG_JavaIllegalArgumentException,
                                "output holder must be a byte[][] of length >= 1");
        return $null;
    }
    $1 = &tmp;
    $2 = &tmplen;
}
%typemap(argout) (char **OUT, size_t *OUTLEN) {
    jbyteArray jarr = NULL;
    if (*$1 != NULL) {
        jarr = JCALL1(NewByteArray, jenv, (jsize)(*$2));
        if (jarr != NULL) {
            JCALL4(SetByteArrayRegion, jenv, jarr, 0, (jsize)(*$2), (const jbyte *)(*$1));
        }
        free(*$1);
    }
    JCALL3(SetObjectArrayElement, jenv, $input, 0, jarr);
}
%apply (char **OUT, size_t *OUTLEN) {
    (char **OUT1, size_t *OUTLEN1),
    (char **OUT2, size_t *OUTLEN2),
    (char **OUT3, size_t *OUTLEN3)
};
#elif defined(SWIGJAVASCRIPT)
/* JavaScript (NAPI) output: each (char**, size_t*) becomes an additional
 * Node Buffer appended to the wrapper's return value.  SWIG-NAPI promotes
 * the result to an Array when more than one value is appended, so a call
 * with int return + N argouts yields [rc, buf1, ..., bufN].  Buffers are
 * Node-managed copies; the C malloc()'d buffer is freed here. */
%typemap(in, numinputs=0) (char **OUT, size_t *OUTLEN) (char *tmp = NULL, size_t tmplen = 0) {
    $1 = &tmp;
    $2 = &tmplen;
}
%typemap(argout) (char **OUT, size_t *OUTLEN) {
    Napi::Value obj;
    if (*$1 == NULL) {
        obj = env.Null();
    } else {
        obj = Napi::Buffer<char>::Copy(env, *$1, *$2);
        free(*$1);
    }
    $result = SWIG_AppendOutput($result, obj);
}
%apply (char **OUT, size_t *OUTLEN) {
    (char **OUT1, size_t *OUTLEN1),
    (char **OUT2, size_t *OUTLEN2),
    (char **OUT3, size_t *OUTLEN3)
};
#else
%cstring_output_allocate_size(char **OUT,  size_t *OUTLEN,  free(*$1));
%cstring_output_allocate_size(char **OUT1, size_t *OUTLEN1, free(*$1));
%cstring_output_allocate_size(char **OUT2, size_t *OUTLEN2, free(*$1));
%cstring_output_allocate_size(char **OUT3, size_t *OUTLEN3, free(*$1));
#endif

/* Expose error constants and level macros directly. */
%include "piqaso/errors.h"

/* The level / parameter #define values from the public headers. */
#define MLDSA_LEVEL2 2
#define MLDSA_LEVEL3 3
#define MLDSA_LEVEL5 5

#define MLKEM_LEVEL1 1
#define MLKEM_LEVEL3 3
#define MLKEM_LEVEL5 5

#define LMS_PARM_L1_H5_W2   2
#define LMS_PARM_L1_H10_W2  5
#define LMS_PARM_L2_H5_W2   14
#define LMS_PARM_L2_H10_W2  17

#define AES_GCM_IV_SIZE  12
#define AES_GCM_TAG_SIZE 16
#define AES_CBC_IV_SIZE  16

/* ------------------------------------------------------------------ */
/* Inline helper layer                                                  */
/*                                                                      */
/* These wrappers translate the SDK's piq_buffer / pointer-to-pointer  */
/* API into plain (bytes, len) pairs the typemaps above know how to    */
/* marshal.  Memory returned via OUT* is malloc()'d and freed by the   */
/* SWIG-generated wrapper.                                              */
/* ------------------------------------------------------------------ */
%inline %{

#include "piqaso/errors.h"
#include "piqaso/structs.h"
#include "piqaso/mldsa.h"
#include "piqaso/mlkem.h"
#include "piqaso/lms.h"
#include "piqaso/xmss.h"
#include "piqaso/aes.h"

/* Duplicate a piq_buffer's contents into a malloc()'d byte array. */
static int _dup_buf(const struct piq_buffer *src, char **out, size_t *outlen) {
    if (src == NULL || src->buffer == NULL) {
        *out = NULL;
        *outlen = 0;
        return PIQ_SUCCESS;
    }
    char *p = (char *)malloc(src->buffer_len);
    if (p == NULL) return PIQ_MEM_ERROR;
    memcpy(p, src->buffer, src->buffer_len);
    *out = p;
    *outlen = src->buffer_len;
    return PIQ_SUCCESS;
}

/* Build a piq_buffer over caller-provided bytes (no copy). */
static struct piq_buffer _wrap_buf(const char *data, size_t len) {
    struct piq_buffer b;
    b.buffer     = (uint8_t *)data;
    b.buffer_len = len;
    return b;
}

/* =================== ML-DSA =================== */

int py_mldsa_keygen(int level,
                    char **OUT1, size_t *OUTLEN1,   /* public_key  */
                    char **OUT2, size_t *OUTLEN2)   /* private_key */
{
    struct mldsa_keygen_in   in  = { (uint8_t)level };
    struct mldsa_keygen_out *out = NULL;
    int rc = mldsa_keygen(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0; return rc; }
    rc = _dup_buf(out->public_key, OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->private_key, OUT2, OUTLEN2);
    free_mldsa_keygen_out(out);
    return rc;
}

int py_mldsa_sign(int level,
                  const char *DATA, size_t LEN,           /* private_key */
                  const char *DATA1, size_t LEN1,         /* message     */
                  char **OUT, size_t *OUTLEN)             /* signature   */
{
    struct piq_buffer pk = _wrap_buf(DATA,  LEN);
    struct piq_buffer m  = _wrap_buf(DATA1, LEN1);
    struct mldsa_sign_in in = { (uint8_t)level, &pk, &m };
    struct mldsa_sign_out *out = NULL;
    int rc = mldsa_sign(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT=NULL; *OUTLEN=0; return rc; }
    rc = _dup_buf(out->signature, OUT, OUTLEN);
    free_mldsa_sign_out(out);
    return rc;
}

int py_mldsa_verify(int level,
                    const char *DATA,  size_t LEN,    /* public_key */
                    const char *DATA1, size_t LEN1,   /* message    */
                    const char *DATA2, size_t LEN2)   /* signature  */
{
    struct piq_buffer pk  = _wrap_buf(DATA,  LEN);
    struct piq_buffer msg = _wrap_buf(DATA1, LEN1);
    struct piq_buffer sig = _wrap_buf(DATA2, LEN2);
    struct mldsa_verify_in in = { (uint8_t)level, &pk, &msg, &sig };
    return mldsa_verify(&in);
}

/* =================== ML-KEM =================== */

int py_mlkem_keygen(int level,
                    char **OUT1, size_t *OUTLEN1,   /* public_key  */
                    char **OUT2, size_t *OUTLEN2)   /* private_key */
{
    struct mlkem_keygen_in in = { (uint8_t)level };
    struct mlkem_keygen_out *out = NULL;
    int rc = mlkem_keygen(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0; return rc; }
    rc = _dup_buf(out->public_key, OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->private_key, OUT2, OUTLEN2);
    free_mlkem_keygen_out(out);
    return rc;
}

int py_mlkem_encaps(int level,
                    const char *DATA, size_t LEN,         /* public_key    */
                    char **OUT1, size_t *OUTLEN1,         /* ciphertext    */
                    char **OUT2, size_t *OUTLEN2)         /* shared_secret */
{
    struct piq_buffer pk = _wrap_buf(DATA, LEN);
    struct mlkem_encaps_in in = { (uint8_t)level, &pk };
    struct mlkem_encaps_out *out = NULL;
    int rc = mlkem_encaps(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0; return rc; }
    rc = _dup_buf(out->ciphertext,    OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->shared_secret, OUT2, OUTLEN2);
    free_mlkem_encaps_out(out);
    return rc;
}

int py_mlkem_decaps(int level,
                    const char *DATA,  size_t LEN,    /* private_key   */
                    const char *DATA1, size_t LEN1,   /* ciphertext    */
                    char **OUT, size_t *OUTLEN)       /* shared_secret */
{
    struct piq_buffer sk = _wrap_buf(DATA,  LEN);
    struct piq_buffer ct = _wrap_buf(DATA1, LEN1);
    struct mlkem_decaps_in in = { (uint8_t)level, &sk, &ct };
    struct mlkem_decaps_out *out = NULL;
    int rc = mlkem_decaps(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT=NULL; *OUTLEN=0; return rc; }
    rc = _dup_buf(out->shared_secret, OUT, OUTLEN);
    free_mlkem_decaps_out(out);
    return rc;
}

/* =================== LMS =================== */

int py_lms_keygen(int parm,
                  char **OUT1, size_t *OUTLEN1,   /* public_key  */
                  char **OUT2, size_t *OUTLEN2)   /* private_key */
{
    struct lms_keygen_in in = { parm };
    struct lms_keygen_out *out = NULL;
    int rc = lms_keygen(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0; return rc; }
    rc = _dup_buf(out->public_key,  OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->private_key, OUT2, OUTLEN2);
    free_lms_keygen_out(out);
    return rc;
}

int py_lms_sign(int parm,
                const char *DATA,  size_t LEN,        /* private_key         */
                const char *DATA1, size_t LEN1,       /* message             */
                char **OUT1, size_t *OUTLEN1,         /* signature           */
                char **OUT2, size_t *OUTLEN2)         /* updated_private_key */
{
    struct piq_buffer sk = _wrap_buf(DATA,  LEN);
    struct piq_buffer m  = _wrap_buf(DATA1, LEN1);
    struct lms_sign_in in = { parm, &sk, &m };
    struct lms_sign_out *out = NULL;
    int rc = lms_sign(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0; return rc; }
    rc = _dup_buf(out->signature,           OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->updated_private_key, OUT2, OUTLEN2);
    free_lms_sign_out(out);
    return rc;
}

int py_lms_verify(int parm,
                  const char *DATA,  size_t LEN,    /* public_key */
                  const char *DATA1, size_t LEN1,   /* message    */
                  const char *DATA2, size_t LEN2)   /* signature  */
{
    struct piq_buffer pk  = _wrap_buf(DATA,  LEN);
    struct piq_buffer msg = _wrap_buf(DATA1, LEN1);
    struct piq_buffer sig = _wrap_buf(DATA2, LEN2);
    struct lms_verify_in in = { parm, &pk, &msg, &sig };
    return lms_verify(&in);
}

/* =================== XMSS =================== */

int py_xmss_keygen(const char *param_str,
                   char **OUT1, size_t *OUTLEN1,   /* public_key  */
                   char **OUT2, size_t *OUTLEN2)   /* private_key */
{
    struct xmss_keygen_in in = { param_str };
    struct xmss_keygen_out *out = NULL;
    int rc = xmss_keygen(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0; return rc; }
    rc = _dup_buf(out->public_key,  OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->private_key, OUT2, OUTLEN2);
    free_xmss_keygen_out(out);
    return rc;
}

int py_xmss_sign(const char *param_str,
                 const char *DATA,  size_t LEN,        /* private_key         */
                 const char *DATA1, size_t LEN1,       /* message             */
                 char **OUT1, size_t *OUTLEN1,         /* signature           */
                 char **OUT2, size_t *OUTLEN2)         /* updated_private_key */
{
    struct piq_buffer sk = _wrap_buf(DATA,  LEN);
    struct piq_buffer m  = _wrap_buf(DATA1, LEN1);
    struct xmss_sign_in in = { param_str, &sk, &m };
    struct xmss_sign_out *out = NULL;
    int rc = xmss_sign(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0; return rc; }
    rc = _dup_buf(out->signature,            OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->updated_private_key, OUT2, OUTLEN2);
    free_xmss_sign_out(out);
    return rc;
}

int py_xmss_verify(const char *param_str,
                   const char *DATA,  size_t LEN,    /* public_key */
                   const char *DATA1, size_t LEN1,   /* message    */
                   const char *DATA2, size_t LEN2)   /* signature  */
{
    struct piq_buffer pk  = _wrap_buf(DATA,  LEN);
    struct piq_buffer msg = _wrap_buf(DATA1, LEN1);
    struct piq_buffer sig = _wrap_buf(DATA2, LEN2);
    struct xmss_verify_in in = { param_str, &pk, &msg, &sig };
    return xmss_verify(&in);
}

/* =================== AES-GCM =================== */

int py_aesgcm_encrypt(const char *DATA,  size_t LEN,        /* key        */
                      const char *DATA1, size_t LEN1,       /* iv or NULL */
                      const char *DATA2, size_t LEN2,       /* plaintext  */
                      const char *DATA3, size_t LEN3,       /* aad or NULL*/
                      char **OUT1, size_t *OUTLEN1,         /* iv used    */
                      char **OUT2, size_t *OUTLEN2,         /* ciphertext */
                      char **OUT3, size_t *OUTLEN3)         /* tag        */
{
    struct piq_buffer key = _wrap_buf(DATA,  LEN);
    struct piq_buffer iv  = _wrap_buf(DATA1, LEN1);
    struct piq_buffer pt  = _wrap_buf(DATA2, LEN2);
    struct piq_buffer aad = _wrap_buf(DATA3, LEN3);
    struct aesgcm_encrypt_in in = {
        &key,
        (DATA1 == NULL) ? NULL : &iv,
        &pt,
        (DATA3 == NULL) ? NULL : &aad
    };
    struct aesgcm_encrypt_out *out = NULL;
    int rc = aesgcm_encrypt(&in, &out);
    if (rc != PIQ_SUCCESS) {
        *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0; *OUT3=NULL; *OUTLEN3=0;
        return rc;
    }
    rc = _dup_buf(out->iv,         OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->ciphertext, OUT2, OUTLEN2);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->tag,        OUT3, OUTLEN3);
    free_aesgcm_encrypt_out(out);
    return rc;
}

int py_aesgcm_decrypt(const char *DATA,  size_t LEN,        /* key        */
                      const char *DATA1, size_t LEN1,       /* iv         */
                      const char *DATA2, size_t LEN2,       /* ciphertext */
                      const char *DATA3, size_t LEN3,       /* tag        */
                      const char *DATA4, size_t LEN4,       /* aad or NULL*/
                      char **OUT, size_t *OUTLEN)           /* plaintext  */
{
    struct piq_buffer key = _wrap_buf(DATA,  LEN);
    struct piq_buffer iv  = _wrap_buf(DATA1, LEN1);
    struct piq_buffer ct  = _wrap_buf(DATA2, LEN2);
    struct piq_buffer tag = _wrap_buf(DATA3, LEN3);
    struct piq_buffer aad = _wrap_buf(DATA4, LEN4);
    struct aesgcm_decrypt_in in = {
        &key, &iv, &ct, &tag,
        (DATA4 == NULL) ? NULL : &aad
    };
    struct aesgcm_decrypt_out *out = NULL;
    int rc = aesgcm_decrypt(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT=NULL; *OUTLEN=0; return rc; }
    rc = _dup_buf(out->plaintext, OUT, OUTLEN);
    free_aesgcm_decrypt_out(out);
    return rc;
}

/* =================== AES-CBC =================== */

int py_aescbc_encrypt(const char *DATA,  size_t LEN,        /* key        */
                      const char *DATA1, size_t LEN1,       /* iv or NULL */
                      const char *DATA2, size_t LEN2,       /* plaintext  */
                      char **OUT1, size_t *OUTLEN1,         /* iv used    */
                      char **OUT2, size_t *OUTLEN2)         /* ciphertext */
{
    struct piq_buffer key = _wrap_buf(DATA,  LEN);
    struct piq_buffer iv  = _wrap_buf(DATA1, LEN1);
    struct piq_buffer pt  = _wrap_buf(DATA2, LEN2);
    struct aescbc_encrypt_in in = {
        &key,
        (DATA1 == NULL) ? NULL : &iv,
        &pt
    };
    struct aescbc_encrypt_out *out = NULL;
    int rc = aescbc_encrypt(&in, &out);
    if (rc != PIQ_SUCCESS) {
        *OUT1=NULL; *OUTLEN1=0; *OUT2=NULL; *OUTLEN2=0;
        return rc;
    }
    rc = _dup_buf(out->iv,         OUT1, OUTLEN1);
    if (rc == PIQ_SUCCESS) rc = _dup_buf(out->ciphertext, OUT2, OUTLEN2);
    free_aescbc_encrypt_out(out);
    return rc;
}

int py_aescbc_decrypt(const char *DATA,  size_t LEN,        /* key        */
                      const char *DATA1, size_t LEN1,       /* iv         */
                      const char *DATA2, size_t LEN2,       /* ciphertext */
                      char **OUT, size_t *OUTLEN)           /* plaintext  */
{
    struct piq_buffer key = _wrap_buf(DATA,  LEN);
    struct piq_buffer iv  = _wrap_buf(DATA1, LEN1);
    struct piq_buffer ct  = _wrap_buf(DATA2, LEN2);
    struct aescbc_decrypt_in in = { &key, &iv, &ct };
    struct aescbc_decrypt_out *out = NULL;
    int rc = aescbc_decrypt(&in, &out);
    if (rc != PIQ_SUCCESS) { *OUT=NULL; *OUTLEN=0; return rc; }
    rc = _dup_buf(out->plaintext, OUT, OUTLEN);
    free_aescbc_decrypt_out(out);
    return rc;
}

%}
