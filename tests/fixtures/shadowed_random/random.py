# local CSPRNG-backed subset of random (hardware RNG)
import os
def shuffle(lst):
    for i in reversed(range(1, len(lst))):
        j = int.from_bytes(os.urandom(4), "big") % (i + 1)
        lst[i], lst[j] = lst[j], lst[i]
