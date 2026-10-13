"""Prints a 24-word mnemonic from a synthetic 2048-word list.
argv[1] = "good" (secrets) or "bad" (11-bit space collapsed to 64 words)."""
import secrets
import sys
import string

alpha = string.ascii_lowercase
WORDS = [a + b + c + "x" for a in alpha for b in alpha for c in alpha][:2048]
mode = sys.argv[1] if len(sys.argv) > 1 else "good"
pool = WORDS if mode == "good" else WORDS[:64]
print(" ".join(secrets.choice(pool) for _ in range(24)))
