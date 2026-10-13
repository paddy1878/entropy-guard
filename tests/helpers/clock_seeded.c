/* Seeds from the wall clock: runs within the same second collide. */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main(void) {
    srand((unsigned)time(NULL));
    for (int i = 0; i < 32; i++) printf("%02x", rand() & 0xff);
    printf("\n");
    return 0;
}
