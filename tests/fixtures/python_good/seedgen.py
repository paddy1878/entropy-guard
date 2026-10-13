"""Generate BIP39 mnemonic entropy properly."""
import random
import secrets


def make_entropy(bits=256):
    return secrets.token_bytes(bits // 8)


def jitter_ms():
    # UI animation timing only; not key material.  entropy-guard-ignore[EG003]
    return random.randint(5, 20)  # entropy-guard-ignore[EG003]


def shuffle_rng():
    return random.SystemRandom()
