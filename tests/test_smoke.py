import os
import subprocess
import sys

import pytest

from entropy_guard import smoke

HERE = os.path.dirname(__file__)
FIX = os.path.join(HERE, "fixtures")
HELP = os.path.join(HERE, "helpers")


def _cc(src, out):
    subprocess.run(["gcc", "-O2", "-o", out, src], check=True)
    return out


@pytest.fixture(scope="module")
def bins(tmp_path_factory):
    d = tmp_path_factory.mktemp("bins")
    return {
        "bad": _cc(os.path.join(FIX, "coldcard_class", "rng.c"), str(d / "bad")),
        "fixed": _cc(os.path.join(FIX, "coldcard_fixed", "rng.c"), str(d / "fixed")),
        "clock": _cc(os.path.join(HELP, "clock_seeded.c"), str(d / "clock")),
    }


def _names(res, passed):
    return {n for n, p, _ in res.checks if p is passed}


def test_coldcard_repro_fails(bins):
    r = smoke.run(bins["bad"], runs=50)
    assert not r.ok and r.kind == "hex"
    assert "unique-outputs" in _names(r, False)


def test_fixed_build_passes(bins):
    r = smoke.run(bins["fixed"], runs=200)
    assert r.ok, r.checks


def test_clock_seeded_collides(bins):
    r = smoke.run(bins["clock"], runs=50)
    assert not r.ok
    assert "unique-outputs" in _names(r, False)


def test_mnemonic_good_passes():
    r = smoke.run(f"{sys.executable} {os.path.join(HELP, 'mnemonic_gen.py')} good", runs=150)
    assert r.kind == "mnemonic" and r.ok, r.checks


def test_mnemonic_collapsed_space_fails():
    r = smoke.run(f"{sys.executable} {os.path.join(HELP, 'mnemonic_gen.py')} bad", runs=150)
    assert r.kind == "mnemonic" and not r.ok
    assert "vocabulary-spread" in _names(r, False)


def test_no_extractable_output():
    r = smoke.run("echo hello", runs=3)
    assert not r.ok and r.samples == 0


def test_extract_prefers_mnemonic_then_hex():
    words = " ".join(["abandon"] * 11 + ["about"])
    assert smoke.extract(f"seed:\n{words}\n")[0] == "mnemonic"
    assert smoke.extract("key=0x" + "ab" * 32)[0] == "hex"
