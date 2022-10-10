#define TEST_NAME "scalarmult_noclamp"
#include "cmptest.h"

static const unsigned char B[32] = {
    0x09, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
};

/* order 8 */
static const unsigned char low_order[32] = {
    0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3,
    0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32,
    0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00
};

int
main(void)
{
    unsigned char *n, *n2, *n3, *p, *q, *q2;

    n = (unsigned char *) sodium_malloc(crypto_scalarmult_curve25519_SCALARBYTES);
    n2 = (unsigned char *) sodium_malloc(crypto_scalarmult_curve25519_SCALARBYTES);
    n3 = (unsigned char *) sodium_malloc(crypto_scalarmult_curve25519_SCALARBYTES);
    p = (unsigned char *) sodium_malloc(crypto_scalarmult_curve25519_BYTES);
    q = (unsigned char *) sodium_malloc(crypto_scalarmult_curve25519_BYTES);
    q2 = (unsigned char *) sodium_malloc(crypto_scalarmult_curve25519_BYTES);

    memset(n, 0, crypto_scalarmult_curve25519_SCALARBYTES);
    memcpy(p, B, crypto_scalarmult_ed25519_BYTES);

    if (crypto_scalarmult_curve25519_base(q, n) != -1) {
        printf("crypto_scalarmult_curve25519_base(0) passed\n");
    }
    if (crypto_scalarmult_curve25519(q2, n, p) != -1) {
        printf("crypto_scalarmult_curve25519(0) passed\n");
    }
    if (crypto_scalarmult_curve25519_noclamp(q2, n, p) != -1) {
        printf("crypto_scalarmult_curve25519_noclamp(0) passed\n");
    }

    n[0] = 1;
    if (crypto_scalarmult_curve25519_base(q, n) != 0) {
        printf("crypto_scalarmult_curve25519_base() failed\n");
    }
    if (crypto_scalarmult_curve25519(q2, n, p) != 0) {
        printf("crypto_scalarmult_curve25519() failed\n");
    }
    if (crypto_scalarmult_curve25519_noclamp(q2, n, p) != 0) {
        printf("crypto_scalarmult_curve25519_noclamp() failed\n");
    }

    n[0] = 9;
    if (crypto_scalarmult_curve25519(q, n, p) != 0) {
        printf("crypto_scalarmult_curve25519() failed\n");
    }
    if (crypto_scalarmult_curve25519_noclamp(q2, n, p) != 0) {
        printf("crypto_scalarmult_curve25519_noclamp() failed\n");
    }
    if (memcmp(q, q2, crypto_scalarmult_curve25519_BYTES) == 0) {
        printf("clamping not applied\n");
    }

    n[0] = 9;
    if (crypto_scalarmult_curve25519_base(q, n) != 0) {
        printf("crypto_scalarmult_curve25519_base() failed\n");
    }
    if (crypto_scalarmult_curve25519_base_noclamp(q2, n) != 0) {
        printf("crypto_scalarmult_curve25519_base_noclamp() failed\n");
    }
    if (memcmp(q, q2, crypto_scalarmult_curve25519_BYTES) == 0) {
        printf("clamping not applied\n");
    }

    n[0] = 8;
    n[31] = 64;
    if (crypto_scalarmult_curve25519_noclamp(q2, n, p) != 0) {
        printf("crypto_scalarmult_curve25519_base_noclamp() failed\n");
    }
    if (memcmp(q, q2, crypto_scalarmult_curve25519_BYTES) != 0) {
        printf("inconsistent clamping\n");
    }

    memset(p, 0, crypto_scalarmult_curve25519_BYTES);
    if (crypto_scalarmult_curve25519(q, n, p) != -1) {
        printf("crypto_scalarmult_curve25519() didn't fail\n");
    }
    if (crypto_scalarmult_curve25519_noclamp(q, n, p) != -1) {
        printf("crypto_scalarmult_curve25519_noclamp() didn't fail\n");
    }

    n[0] = 8;
    if (crypto_scalarmult_curve25519(q, n, p) != -1) {
        printf("crypto_scalarmult_curve25519() didn't fail\n");
    }
    if (crypto_scalarmult_curve25519_noclamp(q, n, p) != -1) {
        printf("crypto_scalarmult_curve25519_noclamp() didn't fail\n");
    }

    crypto_core_ed25519_scalar_random(n);
    crypto_core_ed25519_scalar_random(n2);
    crypto_core_ed25519_scalar_mul(n3, n, n2);

    if (crypto_scalarmult_curve25519_base_noclamp(q, n) != 0) {
        printf("crypto_scalarmult_curve25519_noclamp(n) failed\n");
    }
    if (crypto_scalarmult_curve25519_noclamp(q, n2, q) != 0) {
        printf("crypto_scalarmult_curve25519_noclamp(n2) failed\n");
    }
    if (crypto_scalarmult_curve25519_base_noclamp(q2, n3) != 0) {
        printf("crypto_scalarmult_curve25519_noclamp(n3) failed\n");
    }
    if (memcmp(q, q2, crypto_scalarmult_curve25519_BYTES) != 0) {
        printf("unclamped scalarmult broken\n");
    }

    randombytes_buf(n, crypto_scalarmult_curve25519_SCALARBYTES);
    n[31] |= 128;
    if (crypto_scalarmult_curve25519_base_noclamp(q, n) != 0) {
        printf("crypto_scalarmult_curve25519_base_noclamp(n) failed\n");
    }
    n[31] &= 127;
    if (crypto_scalarmult_curve25519_base_noclamp(q2, n) != 0) {
        printf("crypto_scalarmult_curve25519_base_noclamp(n) failed\n");
    }
    if (memcmp(q, q2, crypto_scalarmult_curve25519_BYTES) == 0) {
        printf("unclamped scalarmult_base ignores the top bit\n");
    }

    memcpy(p, B, crypto_scalarmult_curve25519_BYTES);
    randombytes_buf(n, crypto_scalarmult_curve25519_SCALARBYTES);
    n[31] |= 128;
    if (crypto_scalarmult_curve25519_noclamp(q, n, p) != 0) {
        printf("crypto_scalarmult_curve25519_noclamp(n) failed\n");
    }
    n[31] &= 127;
    if (crypto_scalarmult_curve25519_noclamp(q2, n, p) != 0) {
        printf("crypto_scalarmult_curve25519_noclamp(n) failed\n");
    }
    if (memcmp(q, q2, crypto_scalarmult_curve25519_BYTES) == 0) {
        printf("unclamped scalarmult ignores the top bit\n");
    }

    if (crypto_scalarmult_curve25519_noclamp(q, n, low_order) != -1 ||
        crypto_scalarmult_curve25519_noclamp(q, n2, low_order) != -1 ||
        crypto_scalarmult_curve25519_noclamp(q, n3, low_order) != -1) {
        printf("crypto_scalarmult_curve25519_noclamp() didn't fail with a low-order point\n");
    }

    sodium_free(q2);
    sodium_free(q);
    sodium_free(p);
    sodium_free(n3);
    sodium_free(n2);
    sodium_free(n);

    assert(crypto_scalarmult_curve25519_BYTES == crypto_scalarmult_curve25519_bytes());
    assert(crypto_scalarmult_curve25519_SCALARBYTES == crypto_scalarmult_curve25519_scalarbytes());

    assert(crypto_scalarmult_curve25519_BYTES == crypto_scalarmult_bytes());
    assert(crypto_scalarmult_curve25519_SCALARBYTES == crypto_scalarmult_scalarbytes());

    printf("OK\n");

    return 0;
}
