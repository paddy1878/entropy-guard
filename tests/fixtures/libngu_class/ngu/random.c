// random - RNG stuff: TRNG, whitening, pick new privkeys
#ifdef MICROPY_PY_STM
extern unsigned rng_get(void);
# define CHIP_TRNG_32()  rng_get()
# ifndef MICROPY_HW_ENABLE_RNG
# error "get a HW TRNG plz"
# endif
#endif

#ifdef __linux__
# define CHIP_TRNG_32()         random()
#endif
