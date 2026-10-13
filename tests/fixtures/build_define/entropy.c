#include <stdint.h>
#include <stddef.h>
extern void hw_trng_read(uint8_t *, size_t);
extern void sw_drbg_read(uint8_t *, size_t);
void entropy_read(uint8_t *b, size_t n) {
#if defined(USE_HW_RNG)
    hw_trng_read(b, n);
#else
    sw_drbg_read(b, n);
#endif
}
