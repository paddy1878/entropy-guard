/* Minimal reproduction of the 2026 Coldcard entropy bug class.
 * The guard asks "is RNG_USE_SOFTWARE_FALLBACK defined?" when it means
 * "is it enabled?". board_config.h sets it to 0, which still counts as
 * defined, so seed generation runs on a deterministic software PRNG.
 */
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include "board_config.h"

#if RNG_USE_SOFTWARE_FALLBACK
/* Software fallback for boards without a TRNG. Deterministic by design. */
static uint32_t sw_state = 0x2545F491u;
static uint32_t sw_next(void) {
    sw_state ^= sw_state << 13;
    sw_state ^= sw_state >> 17;
    sw_state ^= sw_state << 5;
    return sw_state;
}
static void rng_fill(uint8_t *out, size_t n) {
    for (size_t i = 0; i < n; i++) out[i] = (uint8_t)sw_next();
}
#else
/* Hardware TRNG path (emulated here with the OS CSPRNG). */
static void rng_fill(uint8_t *out, size_t n) {
    FILE *f = fopen("/dev/urandom", "rb");
    if (!f || fread(out, 1, n, f) != n) { perror("trng"); return; }
    fclose(f);
}
#endif

int main(void) {
    uint8_t entropy[32];           /* 256 bits -> 24-word mnemonic */
    rng_fill(entropy, sizeof entropy);
    for (size_t i = 0; i < sizeof entropy; i++) printf("%02x", entropy[i]);
    printf("\n");
    return 0;
}
