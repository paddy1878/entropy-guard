import random

def verify_entropy(dev):
    entropy_check_count = random.randint(2, 8)
    for _ in range(entropy_check_count):
        dev.check()
