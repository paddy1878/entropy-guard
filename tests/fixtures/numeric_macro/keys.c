#include "layout.h"
/* key slots for the trng-backed secret store */
#ifdef SECRET_MASTER_KEY_SLOT
int master_slot = SECRET_MASTER_KEY_SLOT;
#endif
#ifndef RNG_HEALTH_DEFAULT
#define RNG_HEALTH_DEFAULT 0
#endif
#ifdef RNG_HEALTH_DEFAULT
int health = 1;
#endif
