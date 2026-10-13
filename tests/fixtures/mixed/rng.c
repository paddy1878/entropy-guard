#include "rng_config.h"
void rng_init(void) {
#if RNG_STRICT
    /* strict entropy health tests */
#endif
}
void rng_reseed(void) {
#ifdef RNG_STRICT
    /* reseed from trng */
#endif
}
