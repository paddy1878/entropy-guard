"""Runtime entropy smoke test.

Runs a seed/key-generating command many times and checks the outputs. This is
not a randomness certification (use NIST SP 800-22 / dieharder for that); it is
a cheap CI tripwire for the failures that actually drained wallets:
  * the same seed coming out twice (deterministic or clock-seeded fallback)
  * outputs that are visibly biased at the bit or byte level
  * mnemonics whose words cluster far below what 2048-word entropy predicts
"""
from __future__ import annotations

import math
import re
import shlex
import subprocess
from dataclasses import dataclass, field

HEX_RE = re.compile(r"\b(?:0x)?([0-9a-fA-F]{32,})\b")
WORD_LINE_RE = re.compile(r"^\s*((?:[a-z]{3,8}\s+){11,23}[a-z]{3,8})\s*$", re.MULTILINE)


@dataclass
class SmokeResult:
    ok: bool
    kind: str
    runs: int
    samples: int
    checks: list = field(default_factory=list)  # (name, passed, detail)

    def to_dict(self):
        return {"ok": self.ok, "kind": self.kind, "runs": self.runs, "samples": self.samples,
                "checks": [{"name": n, "passed": p, "detail": d} for n, p, d in self.checks]}


def extract(output, kind="auto"):
    """Return (kind, sample) from one run's stdout, or (kind, None)."""
    if kind in ("auto", "mnemonic"):
        m = WORD_LINE_RE.search(output)
        if m:
            return "mnemonic", " ".join(m.group(1).split())
        if kind == "mnemonic":
            return kind, None
    if kind in ("auto", "hex"):
        hits = HEX_RE.findall(output)
        if hits:
            return "hex", max(hits, key=len).lower()
        return "hex", None
    if kind == "raw":
        s = output.strip()
        return "raw", s or None
    return kind, None


def _normal_sf(z):
    return 0.5 * math.erfc(z / math.sqrt(2))


def _chi2_sf(x, k):
    """Upper tail of chi-square via Wilson–Hilferty (fine for k >= 30)."""
    if k <= 0:
        return 1.0
    z = ((x / k) ** (1 / 3) - (1 - 2 / (9 * k))) / math.sqrt(2 / (9 * k))
    return _normal_sf(z)


def analyse(samples, kind, alpha=1e-4):
    checks = []
    n = len(samples)
    distinct = len(set(samples))
    dupes = n - distinct
    checks.append(("unique-outputs", dupes == 0,
                   f"{distinct}/{n} distinct" + ("" if dupes == 0 else
                   f" — {dupes} repeat(s). Repeated seeds mean the generator is deterministic "
                   f"or seeded from something guessable.")))

    if kind == "hex":
        data = b"".join(bytes.fromhex(s if len(s) % 2 == 0 else s[:-1]) for s in samples)
        bits = len(data) * 8
        if bits:
            ones = sum(bin(b).count("1") for b in data)
            z = abs(ones - bits / 2) / math.sqrt(bits / 4)
            p = 2 * _normal_sf(z)
            checks.append(("monobit", p >= alpha,
                           f"{ones}/{bits} ones, z={z:.2f}, p={p:.2e}"))
        if len(data) >= 256 * 5:
            counts = [0] * 256
            for b in data:
                counts[b] += 1
            exp = len(data) / 256
            chi = sum((c - exp) ** 2 / exp for c in counts)
            p = _chi2_sf(chi, 255)
            checks.append(("byte-chi-square", p >= alpha, f"chi2={chi:.1f} (df=255), p={p:.2e}"))
        else:
            checks.append(("byte-chi-square", True,
                           f"skipped: {len(data)} bytes < 1280 needed; raise --runs"))
        if n >= 2:
            # Pairwise Hamming distance between consecutive outputs should be ~50%.
            ds = []
            for a, b in zip(samples, samples[1:]):
                if len(a) == len(b):
                    x = int(a, 16) ^ int(b, 16)
                    ds.append(bin(x).count("1") / (len(a) * 4))
            if ds:
                mean = sum(ds) / len(ds)
                checks.append(("consecutive-hamming", 0.40 <= mean <= 0.60,
                               f"mean {mean:.3f} of bits differ between consecutive runs (expect ~0.5)"))

    elif kind == "mnemonic":
        words = [s.split() for s in samples]
        first = [w[0] for w in words if w]
        seen_first = len(set(first))
        expected = 2048 * (1 - (1 - 1 / 2048) ** len(first))
        checks.append(("first-word-spread", seen_first >= 0.6 * expected,
                       f"{seen_first} distinct first words over {len(first)} runs "
                       f"(expected ≈{expected:.0f} for 11 bits of entropy)"))
        allw = [x for w in words for x in w]
        uniq = len(set(allw))
        exp_all = 2048 * (1 - (1 - 1 / 2048) ** len(allw))
        checks.append(("vocabulary-spread", uniq >= 0.6 * exp_all,
                       f"{uniq} distinct words across {len(allw)} drawn (expected ≈{exp_all:.0f})"))

    ok = all(p for _, p, _ in checks)
    return checks, ok


def run(cmd, runs=100, kind="auto", timeout=30, shell=False, alpha=1e-4):
    samples = []
    detected = None
    errors = 0
    argv = cmd if shell else shlex.split(cmd)
    for _ in range(runs):
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, shell=shell)
        except subprocess.TimeoutExpired:
            errors += 1
            continue
        if proc.returncode != 0:
            errors += 1
            continue
        k, sample = extract(proc.stdout, kind if detected is None else detected)
        if sample is not None:
            detected = detected or k
            samples.append(sample)
    if not samples:
        return SmokeResult(False, kind, runs, 0,
                           [("extract", False, f"no seed/key found in output ({errors} failed runs). "
                             f"Command must print a hex string (>=32 hex chars) or a 12–24 word mnemonic.")])
    checks, ok = analyse(samples, detected, alpha=alpha)
    if errors:
        checks.insert(0, ("command-errors", errors == 0, f"{errors}/{runs} runs failed or timed out"))
        ok = False
    return SmokeResult(ok, detected, runs, len(samples), checks)
