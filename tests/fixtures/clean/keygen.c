#include "crypto.h"
#include <sys/random.h>
/* generate_key: 32 bytes of entropy from the OS CSPRNG. Not rand(). */
int generate_key(uint8_t out[32]) {
    // never use random() here
    return getrandom(out, 32, 0) == 32 ? 0 : -1;
}
