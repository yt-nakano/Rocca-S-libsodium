/*
 * Copyright (c) 2024 KDDI CORPORATION. All Rights Reserved.
 */

#ifndef crypto_aead_rocca_H
#define crypto_aead_rocca_H

#include <stddef.h>

#include "export.h"

#ifdef __cplusplus
#ifdef __GNUC__
#pragma GCC diagnostic ignored "-Wlong-long"
#endif
extern "C" {
#endif

#define crypto_aead_roccas_KEYBYTES 32U
SODIUM_EXPORT
size_t crypto_aead_roccas_keybytes(void);

#define crypto_aead_roccas_NSECBYTES 0U
SODIUM_EXPORT
size_t crypto_aead_roccas_nsecbytes(void);

#define crypto_aead_roccas_NPUBBYTES 16U
SODIUM_EXPORT
size_t crypto_aead_roccas_npubbytes(void);

#define crypto_aead_roccas_ABYTES 32U
SODIUM_EXPORT
size_t crypto_aead_roccas_abytes(void);

#define crypto_aead_roccas_MESSAGEBYTES_MAX \
    SODIUM_MIN(SODIUM_SIZE_MAX - crypto_aead_roccas_ABYTES, (1ULL << 61) - 1)
SODIUM_EXPORT
size_t crypto_aead_roccas_messagebytes_max(void);

SODIUM_EXPORT
int crypto_aead_roccas_encrypt(unsigned char       *c,
                               unsigned long long  *clen_p,
                               const unsigned char *m,
                               unsigned long long   mlen,
                               const unsigned char *ad,
                               unsigned long long   adlen,
                               const unsigned char *nsec,
                               const unsigned char *npub,
                               const unsigned char *k) __attribute__((nonnull(1, 8, 9)));

SODIUM_EXPORT
int crypto_aead_roccas_decrypt(unsigned char       *m,
                               unsigned long long  *mlen_p,
                               unsigned char       *nsec,
                               const unsigned char *c,
                               unsigned long long   clen,
                               const unsigned char *ad,
                               unsigned long long   adlen,
                               const unsigned char *npub,
                               const unsigned char *k) __attribute__((warn_unused_result))
__attribute__((nonnull(4, 8, 9)));

SODIUM_EXPORT
int crypto_aead_roccas_encrypt_detached(unsigned char       *c,
                                        unsigned char       *mac,
                                        unsigned long long  *maclen_p,
                                        const unsigned char *m,
                                        unsigned long long   mlen,
                                        const unsigned char *ad,
                                        unsigned long long   adlen,
                                        const unsigned char *nsec,
                                        const unsigned char *npub,
                                        const unsigned char *k)
    __attribute__((nonnull(1, 2, 9, 10)));

SODIUM_EXPORT
int crypto_aead_roccas_decrypt_detached(unsigned char       *m,
                                        unsigned char       *nsec,
                                        const unsigned char *c,
                                        unsigned long long   clen,
                                        const unsigned char *mac,
                                        const unsigned char *ad,
                                        unsigned long long   adlen,
                                        const unsigned char *npub,
                                        const unsigned char *k)
    __attribute__((warn_unused_result)) __attribute__((nonnull(3, 5, 8, 9)));

SODIUM_EXPORT
void crypto_aead_roccas_keygen(unsigned char k[crypto_aead_roccas_KEYBYTES])
    __attribute__((nonnull));

#ifdef __cplusplus
}
#endif

#endif