#include <string.h>
#include <piqaso/lms.h>
#include <piqaso/errors.h>
#include "bench_common.h"

#define LMS_BENCH_PARM LMS_PARM_L1_H5_W2
#define LMS_BENCH_TAG  "L1_H5_W2"

static const uint8_t MSG[] = "piqaso_sdk LMS bench message";

static void run_once(void)
{
    struct lms_keygen_in   kg_in  = { .parm = LMS_BENCH_PARM };
    struct lms_keygen_out *kg_out = NULL;
    struct lms_sign_in     s_in;
    struct lms_sign_out   *s_out = NULL;
    struct lms_verify_in   v_in;
    struct piq_buffer msg_buf = { (uint8_t *)MSG, sizeof MSG - 1 };

    {
        BENCH_START();
        if (lms_keygen(&kg_in, &kg_out) != PIQ_SUCCESS) { fprintf(stderr, "keygen failed\n"); exit(1); }
        BENCH_STOP("lms_" LMS_BENCH_TAG "_keygen");
    }

    memset(&s_in, 0, sizeof s_in);
    s_in.parm        = LMS_BENCH_PARM;
    s_in.private_key = kg_out->private_key;
    s_in.message     = &msg_buf;
    {
        BENCH_START();
        if (lms_sign(&s_in, &s_out) != PIQ_SUCCESS) { fprintf(stderr, "sign failed\n"); exit(1); }
        BENCH_STOP("lms_" LMS_BENCH_TAG "_sign");
    }

    memset(&v_in, 0, sizeof v_in);
    v_in.parm       = LMS_BENCH_PARM;
    v_in.public_key = kg_out->public_key;
    v_in.message    = &msg_buf;
    v_in.signature  = s_out->signature;
    {
        BENCH_START();
        if (lms_verify(&v_in) != PIQ_SUCCESS) { fprintf(stderr, "verify failed\n"); exit(1); }
        BENCH_STOP("lms_" LMS_BENCH_TAG "_verify");
    }

    free_lms_sign_out(s_out);
    free_lms_keygen_out(kg_out);
}

int main(int argc, char **argv)
{
    int iters = bench_iters(argc, argv);
    for (int i = 0; i < iters; i++) run_once();
    return 0;
}
