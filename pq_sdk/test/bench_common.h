/*
 * Shared helpers for piqaso_sdk micro-benchmarks.
 *
 * Each bench_<algo> program prints one line per measurement in the form:
 *
 *     BENCH <label> <ns>
 *
 * where <label> uniquely identifies the operation (e.g. "mlkem_level1_keygen")
 * and <ns> is the wall-clock duration of that single operation in
 * nanoseconds, measured with CLOCK_MONOTONIC.
 *
 * The companion Python script test/run_benchmarks.py parses these lines.
 */
#ifndef PIQASO_BENCH_COMMON_H
#define PIQASO_BENCH_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <time.h>

static inline uint64_t bench_now_ns(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

#define BENCH_START()  uint64_t _bench_t0 = bench_now_ns()
#define BENCH_STOP(label)                                                    \
    do {                                                                     \
        uint64_t _bench_t1 = bench_now_ns();                                 \
        printf("BENCH %s %llu\n",                                            \
               (label), (unsigned long long)(_bench_t1 - _bench_t0));        \
        fflush(stdout);                                                      \
    } while (0)

/* Parse iteration count from argv[1]; default to 1. */
static inline int bench_iters(int argc, char **argv)
{
    if (argc < 2) return 1;
    int n = atoi(argv[1]);
    return (n > 0) ? n : 1;
}

#endif /* PIQASO_BENCH_COMMON_H */
