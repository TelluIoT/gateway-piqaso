#include <string.h>
#include <piqaso/xmss.h>
#include <piqaso/errors.h>
#include "bench_common.h"

#define XMSS_BENCH_PARAM "XMSS-SHA2_10_256"
#define XMSS_BENCH_TAG   "SHA2_10_256"

static const uint8_t MSG[] = "piqaso_sdk XMSS bench message";

static void run_once(void)
{
    struct xmss_keygen_in   kg_in  = { .param_str = XMSS_BENCH_PARAM };
    struct xmss_keygen_out *kg_out = NULL;
    struct xmss_sign_in     s_in;
    struct xmss_sign_out   *s_out = NULL;
    struct xmss_verify_in   v_in;
    struct piq_buffer msg_buf = { (uint8_t *)MSG, sizeof MSG - 1 };

    {
        BENCH_START();
        if (xmss_keygen(&kg_in, &kg_out) != PIQ_SUCCESS) { fprintf(stderr, "keygen failed\n"); exit(1); }
        BENCH_STOP("xmss_" XMSS_BENCH_TAG "_keygen");
    }

    memset(&s_in, 0, sizeof s_in);
    s_in.param_str   = XMSS_BENCH_PARAM;
    s_in.private_key = kg_out->private_key;
    s_in.message     = &msg_buf;
    {
        BENCH_START();
        if (xmss_sign(&s_in, &s_out) != PIQ_SUCCESS) { fprintf(stderr, "sign failed\n"); exit(1); }
        BENCH_STOP("xmss_" XMSS_BENCH_TAG "_sign");
    }

    memset(&v_in, 0, sizeof v_in);
    v_in.param_str  = XMSS_BENCH_PARAM;
    v_in.public_key = kg_out->public_key;
    v_in.message    = &msg_buf;
    v_in.signature  = s_out->signature;
    {
        BENCH_START();
        if (xmss_verify(&v_in) != PIQ_SUCCESS) { fprintf(stderr, "verify failed\n"); exit(1); }
        BENCH_STOP("xmss_" XMSS_BENCH_TAG "_verify");
    }

    free_xmss_sign_out(s_out);
    free_xmss_keygen_out(kg_out);
}

int main(int argc, char **argv)
{
    int iters = bench_iters(argc, argv);
    for (int i = 0; i < iters; i++) run_once();
    return 0;
}
