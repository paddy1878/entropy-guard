"""Generate a BIP39 mnemonic entropy blob (deliberately broken)."""
import random
from random import choice

WORDS = ["abandon", "ability", "able"]


def make_entropy(bits=256):
    return random.getrandbits(bits).to_bytes(bits // 8, "big")


def random_mnemonic_word():
    return choice(WORDS)
