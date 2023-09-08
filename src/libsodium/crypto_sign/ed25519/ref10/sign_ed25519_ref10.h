#ifndef sign_ed25519_ref10_H
#define sign_ed25519_ref10_H

#include "private/quirks.h"

void _crypto_sign_ed25519_ref10_hinit(crypto_hash_sha512_state *hs,
                                      const char *ctx, unsigned char ctxlen_u8,
                                      unsigned char prehashed);

int _crypto_sign_ed25519_detached(unsigned char *sig,
                                  unsigned long long *siglen_p,
                                  const unsigned char *m,
                                  unsigned long long mlen,
                                  const unsigned char *sk,
                                  const char *ctx, size_t ctxlen,
                                  unsigned char prehashed);

int _crypto_sign_ed25519_verify_detached(const unsigned char *sig,
                                         const unsigned char *m,
                                         unsigned long long   mlen,
                                         const unsigned char *pk,
                                         const char *ctx, size_t ctxlen,
                                         unsigned char prehashed);
#endif
