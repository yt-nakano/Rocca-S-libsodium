
#include <stddef.h>
#include <stdint.h>

#include "../scalarmult_curve25519.h"
#include "export.h"
#include "private/ed25519_ref10.h"
#include "utils.h"
#include "x25519_ref10.h"

static int
crypto_scalarmult_curve25519_ref10(unsigned char *q,
                                   const unsigned char *n,
                                   const unsigned char *p,
                                   const int bits)
{
    unsigned char *t = q;
    unsigned int   i;
    fe25519        x1, x2, x3, z2, z3;
    fe25519        a, b, aa, bb, e, da, cb;
    int            pos;
    unsigned int   swap;
    unsigned int   bit;

    fe25519_frombytes(x1, p);
    fe25519_1(x2);
    fe25519_0(z2);
    fe25519_copy(x3, x1);
    fe25519_1(z3);

    swap = 0;
    for (pos = bits - 1; pos >= 0; --pos) {
        bit = n[pos / 8] >> (pos & 7);
        bit &= 1;
        swap ^= bit;
        fe25519_cswap(x2, x3, swap);
        fe25519_cswap(z2, z3, swap);
        swap = bit;
        fe25519_add(a, x2, z2);
        fe25519_sub(b, x2, z2);
        fe25519_sq(aa, a);
        fe25519_sq(bb, b);
        fe25519_mul(x2, aa, bb);
        fe25519_sub(e, aa, bb);
        fe25519_sub(da, x3, z3);
        fe25519_mul(da, da, a);
        fe25519_add(cb, x3, z3);
        fe25519_mul(cb, cb, b);
        fe25519_add(x3, da, cb);
        fe25519_sq(x3, x3);
        fe25519_sub(z3, da, cb);
        fe25519_sq(z3, z3);
        fe25519_mul(z3, z3, x1);
        fe25519_mul32(z2, e, 121666);
        fe25519_add(z2, z2, bb);
        fe25519_mul(z2, z2, e);
    }
    fe25519_cswap(x2, x3, swap);
    fe25519_cswap(z2, z3, swap);

    fe25519_invert(z2, z2);
    fe25519_mul(x2, x2, z2);
    fe25519_tobytes(q, x2);

    return 0;
}

static void
edwards_to_montgomery(fe25519 montgomeryX, const fe25519 edwardsY, const fe25519 edwardsZ)
{
    fe25519 tempX;
    fe25519 tempZ;

    fe25519_add(tempX, edwardsZ, edwardsY);
    fe25519_sub(tempZ, edwardsZ, edwardsY);
    fe25519_invert(tempZ, tempZ);
    fe25519_mul(montgomeryX, tempX, tempZ);
}

static int
crypto_scalarmult_curve25519_ref10_base(unsigned char *q,
                                        const unsigned char *n)
{
    ge25519_p3     A;
    fe25519        pk;
    unsigned int   i;

    ge25519_scalarmult_base(&A, n);
    edwards_to_montgomery(pk, A.Y, A.Z);
    fe25519_tobytes(q, pk);

    return 0;
}

struct crypto_scalarmult_curve25519_implementation
    crypto_scalarmult_curve25519_ref10_implementation = {
        SODIUM_C99(.mult =) crypto_scalarmult_curve25519_ref10,
        SODIUM_C99(.mult_base =) crypto_scalarmult_curve25519_ref10_base
    };
