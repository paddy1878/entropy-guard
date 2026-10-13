import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _run(*args):
    return subprocess.run([sys.executable, "-m", "entropy_guard", *args], cwd=ROOT,
                          capture_output=True, text=True)


def test_annotation_paths_are_repo_relative():
    r = _run("scan", "tests/fixtures/coldcard_class", "--format", "github")
    assert r.returncode == 1
    assert "::error file=tests/fixtures/coldcard_class/rng.c,line=11," in r.stdout


def test_related_and_sarif_paths_are_repo_relative(tmp_path):
    out = tmp_path / "eg.json"
    _run("scan", "tests/fixtures/coldcard_class", "--format", "json", "-o", str(out), "--fail-on", "never")
    f = [x for x in json.loads(out.read_text())["findings"] if x["rule"] == "EG001"][0]
    assert f["file"] == "tests/fixtures/coldcard_class/rng.c"
    assert f["related"] == [{"file": "tests/fixtures/coldcard_class/board_config.h", "line": 5}]


def test_scan_root_relative_flag():
    r = _run("scan", "tests/fixtures/coldcard_class", "--relative-to-scan-root", "--format", "github")
    assert "::error file=rng.c,line=11," in r.stdout
