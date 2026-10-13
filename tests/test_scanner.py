import json
import os

from entropy_guard import report, scanner

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


def scan(name):
    findings, _ = scanner.scan(os.path.join(FIX, name))
    return findings


def rules(findings, sev=None):
    return sorted((f.rule, f.file, f.line) for f in findings if sev is None or f.severity == sev)


def test_coldcard_class_ifdef_on_zero_macro_is_error():
    f = [x for x in scan("coldcard_class") if x.rule == "EG001"]
    assert len(f) == 1
    assert f[0].severity == "error"
    assert f[0].file == "rng.c" and f[0].line == 11
    assert f[0].related == [{"file": "board_config.h", "line": 5}]


def test_coldcard_fix_is_clean():
    assert scan("coldcard_fixed") == []


def test_clean_tree_has_no_findings():
    # include guards, flag-style macros, proper #if, getrandom()
    assert scan("clean") == []


def test_clock_seeded_c_prng():
    f = [x for x in scan("coldcard_class") if x.rule == "EG002"]
    assert [(x.line, x.severity) for x in f] == [(6, "error"), (7, "warning")]


def test_build_flag_zero_with_defined():
    f = scan("build_define")
    assert rules(f, "error") == [("EG001", "entropy.c", 6)]
    assert "Makefile:1" in f[0].message


def test_mixed_semantics_is_warning_on_entropy_path():
    f = scan("mixed")
    assert [(x.rule, x.severity, x.line) for x in f] == [("EG001", "warning", 8)]


def test_python_random_in_key_path():
    f = scan("python_bad")
    prod = [x for x in f if not x.file.startswith(("tests/", "fuzzer/"))]
    assert [(x.line, x.severity) for x in prod] == [(9, "error"), (13, "error")]
    # test files are downgraded, not hidden
    assert {x.severity for x in f if x.file.startswith("tests/")} == {"warning", "note"}


def test_python_secrets_systemrandom_and_suppression():
    assert scan("python_good") == []


def test_js_math_random():
    assert rules(scan("js_bad")) == [("EG004", "wallet.js", 4)]


def test_exclude_glob():
    findings, _ = scanner.scan(os.path.join(FIX, "python_bad"), excludes=["tests/*"])
    assert all(not f.file.startswith("tests/") for f in findings)


def test_sarif_is_well_formed():
    findings, files = scanner.scan(os.path.join(FIX, "coldcard_class"))
    doc = json.loads(report.sarif(findings, files))
    assert doc["version"] == "2.1.0"
    res = doc["runs"][0]["results"]
    assert {r["ruleId"] for r in res} == {"EG001", "EG002"}
    ids = {r["id"] for r in doc["runs"][0]["tool"]["driver"]["rules"]}
    assert {r["ruleId"] for r in res} <= ids


def test_github_annotations():
    findings, files = scanner.scan(os.path.join(FIX, "coldcard_class"))
    out = report.github(findings, files)
    assert "::error file=rng.c,line=11,title=entropy-guard EG001::" in out


def test_local_random_module_shadows_stdlib():
    assert scan("shadowed_random") == []


def test_python_context_is_per_function():
    # file mentions entropy, but the random call builds a message id
    assert scan("msg_ids") == []


def test_build_define_scoped_to_build_tree():
    f = scan("scoped_build")
    hits = sorted(x.file for x in f if x.rule == "EG001")
    # legacy/ and the -I'd shared/ dir are compiled with =0; core/ is not
    assert hits == ["legacy/rng_legacy.c", "shared/rng_shared.c"]


def test_numeric_macros_and_default_idiom():
    f = scan("numeric_macro")
    # slot index 0 is a number, not OFF; the #ifndef default line is fine,
    # but the later #ifdef on the defaulted-to-0 flag is the real bug
    assert [(x.rule, x.line, x.severity) for x in f] == [("EG001", 9, "error")]


def test_fuzzer_paths_are_downgraded():
    f = [x for x in scan("python_bad") if x.file.startswith("fuzzer/")]
    assert [(x.rule, x.severity) for x in f] == [("EG002", "warning")]


def test_guarded_value_tests_and_must_configure_idiom():
    # defined(X) && X == 1, and #ifndef X / #error, are both correct
    f = scan("idioms")
    assert [x for x in f if x.rule == "EG001"] == []


def test_counter_named_after_entropy_is_not_entropy():
    f = [x for x in scan("idioms") if x.rule == "EG003"]
    assert [x.severity for x in f] == ["warning"]


def test_libngu_class_ifndef_error_defeated_by_zero():
    # Structure of the real pre-fix libngu guard (fixed upstream in e9d5e80 as
    # "#if MICROPY_HW_ENABLE_RNG == 0"). With the port default of 0 in scope it
    # is an error; scanning the library alone still raises a warning.
    f = [x for x in scan("libngu_class") if x.rule == "EG001"]
    weak = [x for x in scan("libngu_class") if x.rule == "EG002"]
    # pre-fix libngu also mapped the Linux "TRNG" to glibc random() (fixed in edda981)
    assert [(x.file, x.line) for x in weak] == [("ngu/random.c", 11)]
    assert [(x.file, x.line, x.severity) for x in f] == [("ngu/random.c", 5, "error")]
    alone, _ = scanner.scan(os.path.join(FIX, "libngu_class", "ngu"))
    assert [(x.rule, x.line, x.severity) for x in alone] == [("EG001", 5, "warning"), ("EG002", 11, "warning")]
