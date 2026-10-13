# entropy-guard

A GitHub Action and CLI that catches the entropy-path bugs that drain wallets — before they ship.

The day after Coldcard's July 2026 entropy disclosure, the fix that landed in its crypto library
(libngu) changed one line: `#ifndef MICROPY_HW_ENABLE_RNG` became `#if MICROPY_HW_ENABLE_RNG == 0`.
The old guard asked whether the hardware-RNG flag **existed**, not whether it was **enabled**.
MicroPython's stm32 port defines that flag as `(0)` by default, and when it is 0, `rng_get()` is a
software pseudo-RNG. A macro defined as 0 still counts as defined, so the `#error` meant to stop
the build never fired. That matches [BlockSec's root-cause write-up](https://blocksec.com/blog/web3-security-coldcard-entropy-lula-exploits)
(an existence check where an enabled check was needed) for a bug that lived from 2021 to 2026 and
cost users over $100M.

entropy-guard flags that pattern statically, flags weak PRNGs on key/seed paths, and can run your
seed generator N times in CI to prove it isn't deterministic.

```
libngu/ngu/random.c:30: ERROR EG001: [entropy path] `#ifndef MICROPY_HW_ENABLE_RNG / #error` is meant
to stop the build when MICROPY_HW_ENABLE_RNG is off, but MICROPY_HW_ENABLE_RNG is defined as '(0)' at
micropython/ports/stm32/mpconfigboard_common.h:57. Defined-as-0 passes an #ifndef, so the build
continues without the feature.
```

That is real output against libngu at the commit before the upstream fix
([`e9d5e80`](https://github.com/switck/libngu/commit/e9d5e8034c90edc1bce791a0fff43ac0877b925f),
"Enforce HW TRNG"). Against the fixed tree it reports nothing.

## Quick start

```yaml
# .github/workflows/entropy.yml
name: entropy-guard
on: [push, pull_request]
permissions:
  contents: read
  security-events: write   # only needed for upload-sarif
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: recursive   # macro definitions often live in submodules
      - uses: paddy1878/entropy-guard@v0
        with:
          fail-on: error
          upload-sarif: "true"
          # optional: build your keygen first, then prove it isn't deterministic
          # smoke-cmd: ./build/print_new_seed
```

Locally:

```bash
python3 -m entropy_guard scan path/to/firmware
python3 -m entropy_guard smoke --cmd ./print_new_seed --runs 200
```

No dependencies beyond Python 3.9+.

## Rules

| Rule  | Catches | Default severity |
|-------|---------|------------------|
| EG001 | `#ifdef X`, `defined(X)` or `#ifndef X`/`#error` on a flag that is defined as `0` somewhere in scope, or tested both ways. Header defines are global; `-D` flags from Makefiles/CMake apply only to the trees that build file compiles. | error on the entropy path, note elsewhere |
| EG002 | `rand()`, `random()`, `srand(time(...))`, `srand(const)`, `std::mt19937` in C/C++ files on the key/seed path — including inside `#define` bodies. | error / warning |
| EG003 | Python `random` feeding keys, seeds, mnemonics, dice or coin-flip entropy. Judged per function, not per file. Skipped when a sibling `random.py` shadows the stdlib. | error when it feeds an entropy-named value, warning otherwise |
| EG004 | `Math.random()` in JS/TS on the key/seed path. | error |

Findings under `tests/`, `fuzz*/`, `examples/` are downgraded one level, not hidden.

Suppress a reviewed line with `// entropy-guard-ignore[EG002]` (or `# ...` in Python).

## Smoke test

`smoke` runs a command that prints one seed per run (hex ≥ 32 chars, or a 12–24 word mnemonic) and checks:

- **unique-outputs**: any repeat fails. Catches deterministic fallbacks and clock seeding.
- **monobit / byte chi-square / consecutive Hamming**: gross bias in hex output.
- **first-word / vocabulary spread**: mnemonics drawn from a collapsed space.

It is a CI tripwire, not a certification. Use NIST SP 800-22 or dieharder for that.

```
$ entropy-guard smoke --cmd ./rng_coldcard_class --runs 100
  [FAIL] unique-outputs: 1/100 distinct — 99 repeat(s).
  [FAIL] consecutive-hamming: mean 0.000 of bits differ between consecutive runs (expect ~0.5)
RESULT: FAIL
```

## Validation

| Target | Files | Errors | Warnings | Notes | Time |
|---|---|---|---|---|---|
| libngu, pre-fix (`e9d5e80^`) + MicroPython stm32 config | 56 | 1 (the real bug) | 1 (`random()` as Linux TRNG, also fixed upstream in `edda981`) | 0 | <1s |
| libngu, current | 57 | 0 | 0 | 0 | <1s |
| trezor-firmware `e6ae73d` | 2,544 | 0 | 2 | 8 | 9.6s |
| Blockstream Jade `9432657` | 488 | 0 | 4 | 5 | 2.2s |
| Coldcard firmware `f28e1b2` | 490 | 0 | 2 | 6 | 4.6s |

The first version of the rules produced 23 errors on trezor-firmware and 4 on Coldcard, all false
positives. Each false-positive class now has a regression test in `tests/`.

## What it won't catch

- **Hardware supply-chain attacks** like the October 2026 CryptoBilis/Ledger implant. That device
  ran genuine firmware; the attack was physical. No source scanner helps there.
- Bugs where the bad definition lives outside the scanned tree (check out submodules), or is
  computed by the build system at configure time.
- RNGs that are cryptographically broken in subtler ways (bad whitening, reused DRBG state).
  EG001/EG002 catch the loud failures, not all of them.

## Licence

MIT
