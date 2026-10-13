#include <stdlib.h>
#include <time.h>
#include <stdint.h>
/* entropy pool init for the secure element bring-up */
void pool_init(uint8_t *pool) {
    srand(time(NULL));
    for (int i = 0; i < 32; i++) pool[i] = (uint8_t)rand();
}
