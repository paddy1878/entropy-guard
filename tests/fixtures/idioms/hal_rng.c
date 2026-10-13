/* HAL-style guarded value test on the trng driver */
#define USE_HAL_RNG_REGISTER_CALLBACKS 0
#ifndef RNG_POOL_CONFIG
  /* must be configured explicitly */
  #error "set RNG_POOL_CONFIG to 0 or 1"
#endif
#if defined (USE_HAL_RNG_REGISTER_CALLBACKS) && (USE_HAL_RNG_REGISTER_CALLBACKS == 1U)
void rng_register_callback(void);
#endif
