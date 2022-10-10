
#include "crypto_scalarmult_curve25519.h"
#include "private/common.h"
#include "private/ed25519_ref10.h"
#include "private/implementations.h"
#include "scalarmult_curve25519.h"
#include "runtime.h"
#include "utils.h"

#ifdef HAVE_AVX_ASM
# include "sandy2x/curve25519_sandy2x.h"
#endif
#include "ref10/x25519_ref10.h"
static const crypto_scalarmult_curve25519_implementation *implementation =
    &crypto_scalarmult_curve25519_ref10_implementation;

static void
clamp(unsigned char *cn, const unsigned char *n)
{
    size_t i;

    for (i = 0; i < 32; i++) {
        cn[i] = n[i];
    }
    cn[0] &= 248;
    cn[31] &= 127;
    cn[31] |= 64;
}

/*
 * Reject small order points early to mitigate the implications of
 * unexpected optimizations that would affect the ref10 code.
 * See https://eprint.iacr.org/2017/806.pdf for reference.
 */
static int
has_small_order(const unsigned char s[32])
{
    CRYPTO_ALIGN(16)
    static const unsigned char blocklist[][32] = {
        /* 0 (order 4) */
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /* 1 (order 1) */
        { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        /* 325606250916557431795983626356110631294008115727848805560023387167927233504
           (order 8) */
        { 0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
          0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
          0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00 },
        /* 39382357235489614581723060781553021112529911719440698176882885853963445705823
           (order 8) */
        { 0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1,
          0x55, 0x9c, 0x83, 0xef, 0x5b, 0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c,
          0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57 },
        /* p-1 (order 2) */
        { 0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        /* p (=0, order 4) */
        { 0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f },
        /* p+1 (=1, order 1) */
        { 0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
          0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f }
    };
    unsigned char c[7] = { 0 };
    unsigned int  k;
    size_t        i, j;

    COMPILER_ASSERT(7 == sizeof blocklist / sizeof blocklist[0]);
    for (j = 0; j < 31; j++) {
        for (i = 0; i < sizeof blocklist / sizeof blocklist[0]; i++) {
            c[i] |= s[j] ^ blocklist[i][j];
        }
    }
    for (i = 0; i < sizeof blocklist / sizeof blocklist[0]; i++) {
        c[i] |= (s[j] & 0x7f) ^ blocklist[i][j];
    }
    k = 0;
    for (i = 0; i < sizeof blocklist / sizeof blocklist[0]; i++) {
        k |= (c[i] - 1);
    }
    return (int) ((k >> 8) & 1);
}

int
crypto_scalarmult_curve25519_noclamp(unsigned char *q, const unsigned char *n,
                                     const unsigned char *p)
{
    if (has_small_order(p)) {
        return -1;
    }
    if (implementation->mult(q, n, p, 256) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    if (has_small_order(q)) {
        return -1;
    }
    return 0;
}

int
crypto_scalarmult_curve25519(unsigned char *q, const unsigned char *n,
                             const unsigned char *p)
{
    unsigned char          t[crypto_scalarmult_curve25519_SCALARBYTES];
    size_t                 i;
    volatile unsigned char d = 0;

    if (has_small_order(p)) {
        return -1;
    }
    COMPILER_ASSERT(crypto_scalarmult_curve25519_SCALARBYTES ==
                    crypto_scalarmult_curve25519_BYTES);
    clamp(t, n);
    if (implementation->mult(q, t, p, 255) != 0) {
        return -1; /* LCOV_EXCL_LINE */
    }
    sodium_memzero(t, sizeof t);
    for (i = 0; i < crypto_scalarmult_curve25519_BYTES; i++) {
        d |= q[i];
    }
    return -(1 & ((d - 1) >> 8));
}

int
crypto_scalarmult_curve25519_base_noclamp(unsigned char *q, const unsigned char *n)
{
    unsigned char t[64];
    int           ret;

    COMPILER_ASSERT(crypto_scalarmult_curve25519_SCALARBYTES <= 64);
    COMPILER_ASSERT(crypto_scalarmult_curve25519_SCALARBYTES ==
                    crypto_scalarmult_curve25519_BYTES);
    memcpy(t, n, crypto_scalarmult_curve25519_SCALARBYTES);
    memset(t + crypto_scalarmult_curve25519_SCALARBYTES, 0,
           64 - crypto_scalarmult_curve25519_SCALARBYTES);
    sc25519_reduce(t);

    ret = crypto_scalarmult_curve25519_ref10_implementation
        .mult_base(q, t);
    sodium_memzero(t, sizeof t);

    return ret;
}

int
crypto_scalarmult_curve25519_base(unsigned char *q, const unsigned char *n)
{
    COMPILER_ASSERT(crypto_scalarmult_curve25519_SCALARBYTES ==
                    crypto_scalarmult_curve25519_BYTES);
    clamp(q, n);

    return crypto_scalarmult_curve25519_ref10_implementation
        .mult_base(q, q);
}

size_t
crypto_scalarmult_curve25519_bytes(void)
{
    return crypto_scalarmult_curve25519_BYTES;
}

size_t
crypto_scalarmult_curve25519_scalarbytes(void)
{
    return crypto_scalarmult_curve25519_SCALARBYTES;
}

int
_crypto_scalarmult_curve25519_pick_best_implementation(void)
{
    implementation = &crypto_scalarmult_curve25519_ref10_implementation;

#ifdef HAVE_AVX_ASM
    if (sodium_runtime_has_avx()) {
        implementation = &crypto_scalarmult_curve25519_sandy2x_implementation;
    }
#endif
    return 0;
}
