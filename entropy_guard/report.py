"""Output formats: text, json, sarif, github (workflow annotations)."""
from __future__ import annotations

import json

from . import __version__

RULES = {
    "EG001": ("existence-check-on-value-macro",
              "Build guard checks whether a macro is defined, not whether it is enabled",
              "A macro defined as 0 is still 'defined'. #ifdef / defined() will take the "
              "enabled branch. On the entropy path this silently swaps the hardware RNG for a "
              "software fallback (Coldcard, 2026). Use #if FLAG, or #if defined(FLAG) && FLAG."),
    "EG002": ("weak-prng-in-entropy-path-c",
              "Non-cryptographic PRNG in a C/C++ entropy or key path",
              "rand(), random(), srand(time()) and std::mt19937 are predictable. Seeds and keys "
              "must come from the hardware TRNG or the OS CSPRNG (getrandom, /dev/urandom)."),
    "EG003": ("python-random-in-entropy-path",
              "Python `random` module used for key, seed or mnemonic material",
              "random is Mersenne Twister; 624 outputs reveal its full state. Use secrets or os.urandom."),
    "EG004": ("js-math-random-in-entropy-path",
              "Math.random() used for key, seed or mnemonic material",
              "Math.random() is not a CSPRNG. Use crypto.getRandomValues() / crypto.randomBytes()."),
}

SARIF_LEVEL = {"error": "error", "warning": "warning", "note": "note"}


def text(findings, files):
    if not findings:
        return f"entropy-guard: scanned {files} files, no findings.\n"
    out = []
    for f in findings:
        out.append(f"{f.file}:{f.line}: {f.severity.upper()} {f.rule}: {f.message}")
        if f.snippet:
            out.append(f"    | {f.snippet}")
    counts = {s: sum(1 for f in findings if f.severity == s) for s in ("error", "warning", "note")}
    out.append(f"\nentropy-guard: scanned {files} files — "
               f"{counts['error']} error(s), {counts['warning']} warning(s), {counts['note']} note(s).")
    return "\n".join(out) + "\n"


def as_json(findings, files):
    return json.dumps({"tool": "entropy-guard", "version": __version__, "files_scanned": files,
                       "findings": [f.to_dict() for f in findings]}, indent=2) + "\n"


def sarif(findings, files):
    rules = [{"id": rid, "name": name, "shortDescription": {"text": short},
              "fullDescription": {"text": full},
              "helpUri": "https://github.com/paddy1878/entropy-guard#rules",
              "properties": {"tags": ["security", "cryptography", "entropy"]}}
             for rid, (name, short, full) in RULES.items()]
    results = []
    for f in findings:
        r = {"ruleId": f.rule, "level": SARIF_LEVEL[f.severity],
             "message": {"text": f.message},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": f.file},
                                                 "region": {"startLine": f.line}}}]}
        if f.related:
            r["relatedLocations"] = [
                {"id": i, "physicalLocation": {"artifactLocation": {"uri": x["file"]},
                                               "region": {"startLine": x["line"]}}}
                for i, x in enumerate(f.related)]
        results.append(r)
    doc = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
           "runs": [{"tool": {"driver": {"name": "entropy-guard", "version": __version__,
                                         "informationUri": "https://github.com/paddy1878/entropy-guard",
                                         "rules": rules}},
                     "results": results}]}
    return json.dumps(doc, indent=2) + "\n"


def _esc(s):
    return s.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def github(findings, files):
    out = []
    for f in findings:
        level = {"error": "error", "warning": "warning", "note": "notice"}[f.severity]
        out.append(f"::{level} file={f.file},line={f.line},title=entropy-guard {f.rule}::{_esc(f.message)}")
    out.append(text(findings, files).rstrip())
    return "\n".join(out) + "\n"


FORMATS = {"text": text, "json": as_json, "sarif": sarif, "github": github}
