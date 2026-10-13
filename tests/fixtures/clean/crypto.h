#ifndef CRYPTO_H
#define CRYPTO_H
#include <stdint.h>
#include <stddef.h>

#define HAVE_HW_TRNG          /* flag-style macro: existence IS the meaning */
#define USE_PARANOID_CHECKS 1

#ifdef HAVE_HW_TRNG
void trng_fill(uint8_t *buf, size_t len);
#endif

#if USE_PARANOID_CHECKS
void entropy_selftest(void);
#endif

#if defined(__ARM_ARCH) && defined(HAVE_HW_TRNG)
#define ENTROPY_SOURCE "trng"
#endif
#endif /* CRYPTO_H */
