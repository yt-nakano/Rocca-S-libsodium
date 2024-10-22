/*
 * Copyright (c) 2024 KDDI CORPORATION. All Rights Reserved.
 */

#include <errno.h>
#include <stdlib.h>

#include "core.h"
#include "crypto_aead_roccas.h"
#include "crypto_verify_32.h"
#include "private/common.h"
#include "private/implementations.h"
#include "randombytes.h"
#include "private/rocca.h"
#include "runtime.h"
#include "utils.h"

size_t
crypto_aead_roccas_keybytes(void)
{
    return crypto_aead_roccas_KEYBYTES;
}

size_t
crypto_aead_roccas_nsecbytes(void)
{
    return crypto_aead_roccas_NSECBYTES;
}

size_t
crypto_aead_roccas_npubbytes(void)
{
    return crypto_aead_roccas_NPUBBYTES;
}

size_t
crypto_aead_roccas_abytes(void)
{
    return crypto_aead_roccas_ABYTES;
}

size_t
crypto_aead_roccas_messagebytes_max(void)
{
    return crypto_aead_roccas_MESSAGEBYTES_MAX;
}

void
crypto_aead_roccas_keygen(unsigned char k[crypto_aead_roccas_KEYBYTES])
{
    randombytes_buf(k, crypto_aead_roccas_KEYBYTES);
}

int
crypto_aead_roccas_encrypt(unsigned char *c, unsigned long long *clen_p, const unsigned char *m,
                           unsigned long long mlen, const unsigned char *ad,
                           unsigned long long adlen, const unsigned char *nsec,
                           const unsigned char *npub, const unsigned char *k)
{
    unsigned long long clen = 0ULL;
    int                ret;

    ret =
        crypto_aead_roccas_encrypt_detached(c, c + mlen, NULL, m, mlen, ad, adlen, nsec, npub, k);
    if (clen_p != NULL) {
        if (ret == 0) {
            clen = mlen + crypto_aead_roccas_ABYTES;
        }
        *clen_p = clen;
    }
    return ret;
}

int
crypto_aead_roccas_decrypt(unsigned char *m, unsigned long long *mlen_p, unsigned char *nsec,
                           const unsigned char *c, unsigned long long clen,
                           const unsigned char *ad, unsigned long long adlen,
                           const unsigned char *npub, const unsigned char *k)
{
    unsigned long long mlen = 0ULL;
    int                ret  = -1;

    if (clen >= crypto_aead_roccas_ABYTES) {
        ret = crypto_aead_roccas_decrypt_detached(m, nsec, c, clen - crypto_aead_roccas_ABYTES,
                                                 c + clen - crypto_aead_roccas_ABYTES, ad,
                                                 adlen, npub, k);
    }
    if (mlen_p != NULL) {
        if (ret == 0) {
            mlen = clen - crypto_aead_roccas_ABYTES;
        }
        *mlen_p = mlen;
    }
    return ret;
}

int
crypto_aead_roccas_encrypt_detached(unsigned char *c, unsigned char *mac,
                                      unsigned long long *maclen_p, const unsigned char *m,
                                      unsigned long long mlen, const unsigned char *ad,
                                      unsigned long long adlen, const unsigned char *nsec,
                                      const unsigned char *npub, const unsigned char *k)
{
    rocca_context ctx;

    const size_t maclen = crypto_aead_roccas_ABYTES;

    if( m == NULL ){
        if( mlen > 0 ){
            return -1;
        }
    }
    if( ad == NULL ){
        if( adlen > 0 ){
            return -1;
        }
    }

    if (maclen_p != NULL) {
        *maclen_p = maclen;
    }
    if (mlen > crypto_aead_roccas_MESSAGEBYTES_MAX ||
        adlen > crypto_aead_roccas_MESSAGEBYTES_MAX) {
        sodium_misuse();
    }

    rocca_init(&ctx, k, npub);
    rocca_add_ad(&ctx, ad, adlen);
    rocca_encrypt(&ctx, c, m, mlen);
    rocca_tag(&ctx, mac);
	rocca_creanup(&ctx);

    return 0;

}

int
crypto_aead_roccas_decrypt_detached(unsigned char *m, unsigned char *nsec, const unsigned char *c,
                                      unsigned long long clen, const unsigned char *mac,
                                      const unsigned char *ad, unsigned long long adlen,
                                      const unsigned char *npub, const unsigned char *k)
{
    rocca_context ctx;
    unsigned char computed_mac[crypto_aead_roccas_ABYTES];
    int           ret;

    if (clen > crypto_aead_roccas_MESSAGEBYTES_MAX ||
        adlen > crypto_aead_roccas_MESSAGEBYTES_MAX) {
        return -1;
    }
    if( mac == NULL ){
        return -1;
    }
    if( c == NULL ){
        if( clen > 0 ){
            return -1;
        }
    }
    if( ad == NULL ){
        if( adlen > 0 ){
            return -1;
        }
    }

    if( npub == NULL ){
        return -1;
    }
    if( k == NULL ){
        return -1;
    }

    rocca_init(&ctx, k, npub);
    rocca_add_ad(&ctx, ad, adlen);
    if(m == NULL ) {
        uint8_t plan[ROCCA_MSG_BLOCK_SIZE];
        uint8_t *pct = (uint8_t*)c;
        size_t  ct_size = (size_t)clen;

        while( ct_size >= ROCCA_MSG_BLOCK_SIZE ){
            rocca_decrypt( &ctx, plan, pct, ROCCA_MSG_BLOCK_SIZE );
            pct += ROCCA_MSG_BLOCK_SIZE;
            ct_size -= ROCCA_MSG_BLOCK_SIZE;
        }
        rocca_decrypt( &ctx, plan, pct, ct_size );
    }else{
        rocca_decrypt(&ctx, m, c, clen);
    }
    rocca_tag(&ctx, computed_mac);
    ret = crypto_verify_32(computed_mac, mac);
    sodium_memzero(computed_mac, sizeof computed_mac);
    if (ret != 0) {
        if( m != NULL ){
            memset(m, 0, clen);
        }
        return -1;
    }
	rocca_creanup(&ctx);

    return 0;
}

