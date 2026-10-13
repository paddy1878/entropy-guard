"""Static rules for the entropy-path bug classes behind recent wallet failures.

EG001  Existence check on a value macro (#ifdef / defined() on a macro that is
       defined with a value such as 0, or is value-tested elsewhere). This is
       the Coldcard 2026 class: a build guard asked "is it defined?" when it
       should have asked "is it enabled?", silently routing seed generation to
       a software fallback.
EG002  Weak / deterministic PRNG in a C/C++ entropy or key-generation path.
EG003  Python `random` module used where keys, seeds or mnemonics are made.
EG004  JavaScript Math.random() used where keys, seeds or mnemonics are made.
"""
from __future__ import annotations

import ast
import fnmatch
import os
import posixpath
import re
from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"note": 0, "warning": 1, "error": 2}

C_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx", ".inc"}
BUILD_NAMES = {"makefile", "gnumakefile", "cmakelists.txt", "meson.build",
               "sconstruct", "sconscript", "kconfig", "build.ninja"}
BUILD_EXT = {".mk", ".cmake", ".mak", ".ninja"}
PY_EXT = {".py"}
JS_EXT = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx"}

DEFAULT_EXCLUDES = [".git", "node_modules", "build", "dist", "out", ".venv",
                    "venv", "__pycache__", ".tox", "target"]

# Words that mark a file or block as sitting on the entropy / key path.
KEY_CONTEXT = re.compile(
    r"(mnemonic|bip[_ ]?39|bip[_ ]?32|entropy|private[_ ]?key|privkey|secret[_ ]?key|"
    r"keygen|gen(erate)?[_ ]?key|trng|hw[_ ]?rng|hwrng|csprng|drbg|seed[_ ]?phrase|"
    r"seedphrase|xprv|random_buffer|getrandom|urandom)",
    re.IGNORECASE,
)
RNG_NAME = re.compile(r"(rng|random|entropy|trng|seed|drbg|noise)", re.IGNORECASE)
TEST_PATH = re.compile(r"(^|[/\\])(tests?|testing|unittests?|fuzz(er|ing)?|examples?|mocks?|bench(mark)?s?)([/\\]|$)|"
                       r"(^|[/\\_])test_[^/\\]*$|_test\.[a-z]+$", re.IGNORECASE)
SUPPRESS = re.compile(r"(entropy-guard|eg)-ignore(\[(?P<rules>[A-Z0-9, ]+)\])?", re.IGNORECASE)

FALSEY = {"0", "false", "FALSE", "0u", "0U", "(0)", "OFF", "off", "no", "NO", "n"}


@dataclass
class Finding:
    rule: str
    severity: str
    file: str
    line: int
    message: str
    snippet: str = ""
    related: list = field(default_factory=list)

    def to_dict(self):
        return asdict(self)


# ---------------------------------------------------------------- utilities

def _iter_files(root, excludes):
    root = os.path.abspath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        dirnames[:] = [d for d in dirnames
                       if d not in DEFAULT_EXCLUDES
                       and not any(fnmatch.fnmatch(os.path.normpath(os.path.join(rel_dir, d)), g)
                                   or fnmatch.fnmatch(d, g) for g in excludes)]
        for name in filenames:
            rel = os.path.normpath(os.path.join(rel_dir, name))
            if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(name, g) for g in excludes):
                continue
            yield os.path.join(dirpath, name), rel


def _read(path, limit=2_000_000):
    try:
        if os.path.getsize(path) > limit:
            return None
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def _suppressed(line, rule):
    m = SUPPRESS.search(line)
    if not m:
        return False
    rules = m.group("rules")
    return rules is None or rule in [r.strip().upper() for r in rules.split(",")]


def _strip_c_comment(s):
    s = re.sub(r"/\*.*?\*/", " ", s)
    return s.split("//", 1)[0].strip()


def _logical_lines(text):
    """Join backslash-continued preprocessor lines; yield (lineno, text)."""
    lines = text.splitlines()
    i = 0
    while i < len(lines):
        start = i
        buf = lines[i]
        while buf.endswith("\\") and i + 1 < len(lines):
            i += 1
            buf = buf[:-1] + " " + lines[i]
        yield start + 1, buf
        i += 1


def _downgrade(sev):
    return {"error": "warning", "warning": "note", "note": "note"}[sev]


# ---------------------------------------------------------------- EG001

DEFINE_RE = re.compile(r"^\s*#\s*define\s+([A-Za-z_]\w*)(\([^)]*\))?(?:\s+(.*))?$")
UNDEF_RE = re.compile(r"^\s*#\s*undef\s+([A-Za-z_]\w*)")
IFDEF_RE = re.compile(r"^\s*#\s*(ifdef|ifndef)\s+([A-Za-z_]\w*)")
IF_RE = re.compile(r"^\s*#\s*(if|elif)\b(.*)$")
DEFINED_RE = re.compile(r"\bdefined\s*(?:\(\s*([A-Za-z_]\w*)\s*\)|([A-Za-z_]\w*))")
IDENT_RE = re.compile(r"\b([A-Za-z_]\w*)\b")
BUILD_D_RE = re.compile(r"(?:^|[\s\"'(])-D\s*([A-Za-z_]\w*)(?:=([^\s\"')]+))?")
CMAKE_DEFS_RE = re.compile(r"compile_definitions\s*\(([^)]*)\)", re.IGNORECASE | re.DOTALL)
CMAKE_KV_RE = re.compile(r"\b([A-Z_][A-Z0-9_]*)=([^\s\")]+)")
C_KEYWORDS = {"defined", "if", "elif", "else", "endif", "true", "false", "__has_include",
              "__has_attribute", "__has_builtin", "__has_feature", "__GNUC__", "__clang__"}


class _MacroFacts:
    def __init__(self):
        self.defs = {}         # name -> list[(rel, line, value)]
        self.value_tests = {}  # name -> list[(rel, line)]
        self.exist_tests = []  # (name, rel, line, raw, directive, rng_ctx)

    def add_def(self, name, rel, line, value, scope=None):
        # scope: None = global (header #define); else list of dir prefixes the
        # build file compiles (its own dir plus relative dirs it references).
        self.defs.setdefault(name, []).append((rel, line, value, scope))


def _ifndef_kind(lines, idx, name):
    """Classify '#ifndef X': 'provide' (#define X follows: a default/guard, fine),
    'assert' (#error follows: meant to stop the build when X is off), or None."""
    for _, raw in lines[idx + 1: idx + 8]:
        ln = _strip_c_comment(raw)
        if not ln:
            continue
        if re.match(r"^\s*#\s*(else|elif|endif)\b", ln):
            return None
        dm = DEFINE_RE.match(ln)
        if dm and dm.group(1) == name:
            return "provide"
        if re.match(r"^\s*#\s*error\b", ln):
            return "assert"
    return None


def _collect_c(rel, text, facts):
    lines = list(_logical_lines(text))
    raw_lines = text.splitlines()
    file_rng = bool(RNG_NAME.search(rel)) or bool(KEY_CONTEXT.search(text))
    for idx, (lineno, raw) in enumerate(lines):
        line = _strip_c_comment(raw)
        if not line.startswith("#") and not line.lstrip().startswith("#"):
            continue
        m = DEFINE_RE.match(line)
        if m:
            name, params, value = m.group(1), m.group(2), (m.group(3) or "").strip()
            if params is None:
                facts.add_def(name, rel, lineno, value)
            continue
        m = IFDEF_RE.match(line)
        if m:
            directive, name = m.group(1), m.group(2)
            # Include guard or default-provision idiom: "#ifndef X" then "#define X [v]".
            # The #ifndef itself is correct; a later #ifdef X is still checked.
            kind = _ifndef_kind(lines, idx, name) if directive == "ifndef" else None
            if kind == "provide":
                continue
            if kind == "assert":
                directive = "ifndef+error"
            window = "\n".join(raw_lines[lineno - 1: lineno + 25])
            rng_ctx = bool(RNG_NAME.search(name)) or (file_rng and bool(RNG_NAME.search(window)))
            facts.exist_tests.append((name, rel, lineno, raw.strip(), "#" + directive, rng_ctx))
            continue
        m = IF_RE.match(line)
        if m:
            expr = m.group(2)
            window = "\n".join(raw_lines[lineno - 1: lineno + 25])
            bare_ids = {im.group(1) for im in IDENT_RE.finditer(DEFINED_RE.sub(" ", expr))}
            for dm in DEFINED_RE.finditer(expr):
                name = dm.group(1) or dm.group(2)
                if name in bare_ids:
                    continue  # "defined(X) && X" — existence AND value: correct
                rng_ctx = bool(RNG_NAME.search(name)) or (file_rng and bool(RNG_NAME.search(window)))
                facts.exist_tests.append((name, rel, lineno, raw.strip(), "defined()", rng_ctx))
            bare = DEFINED_RE.sub(" ", expr)
            for im in IDENT_RE.finditer(bare):
                ident = im.group(1)
                if ident in C_KEYWORDS or ident[0].isdigit():
                    continue
                facts.value_tests.setdefault(ident, []).append((rel, lineno))


REL_PATH_RE = re.compile(r"(?:-I\s*|(?<![\w$)}/.]))((?:\.\./|\./)?[A-Za-z0-9_.\-]+(?:/[A-Za-z0-9_.\-]+)+)")


def _build_scope(rel, text):
    base = posixpath.dirname(rel)
    scope = {base}
    for m in REL_PATH_RE.finditer(text):
        cand = posixpath.normpath(posixpath.join(base, m.group(1)))
        if cand.startswith("..") or cand == ".":
            continue
        # keep the directory part (paths often name files: ../crypto/bip39.o)
        if "." in posixpath.basename(cand):
            cand = posixpath.dirname(cand)
        if cand:
            scope.add(cand)
    return sorted(scope)


def _in_scope(rel, scope):
    if scope is None:
        return True
    return any(p in ("", ".") or rel == p or rel.startswith(p + "/") for p in scope)


def _collect_build(rel, text, facts):
    scope = _build_scope(rel, text)
    for lineno, raw in enumerate(text.splitlines(), 1):
        for m in BUILD_D_RE.finditer(raw):
            facts.add_def(m.group(1), rel, lineno, (m.group(2) or "").strip(), scope)
    for m in CMAKE_DEFS_RE.finditer(text):
        start_line = text.count("\n", 0, m.start()) + 1
        for kv in CMAKE_KV_RE.finditer(m.group(1)):
            facts.add_def(kv.group(1), rel, start_line, kv.group(2), scope)


INDEX_NAME = re.compile(r"(SLOT|INDEX|IDX|OFFSET|ADDR|ADDRESS|SIZE|LEN|LENGTH|COUNT|NUM|_ID|PIN|PORT|"
                        r"CHANNEL|_BIT|MASK|SHIFT|BASE|LEVEL|VERSION|MODE|TYPE|ID)$")
NUMERIC = re.compile(r"^\(?\s*-?(0x[0-9a-fA-F]+|\d+)[uUlL]*\s*\)?$")


def _is_numeric_macro(name, defs):
    """True when 0 is a legitimate number for this macro, not an OFF switch."""
    if INDEX_NAME.search(name.upper()):
        return True
    for d in defs:
        m = NUMERIC.match(d[2].strip())
        if m and m.group(1) not in ("0", "1", "0x0", "0x1", "0x00", "0x01"):
            return True
    return False


BOOL_FLAG = re.compile(r"(^|_)(ENABLE|ENABLED|USE|HAVE|HAS|WITH|FEATURE|SUPPORT|EN)(_|$)")


def _is_falsey(value):
    v = value.strip().strip("()").strip()
    return v in FALSEY or value.strip() in FALSEY


def _eg001(facts, lines_by_file):
    out = []
    for name, rel, lineno, raw, directive, rng_ctx in facts.exist_tests:
        defs = [d for d in facts.defs.get(name, []) if _in_scope(rel, d[3])]
        if _is_numeric_macro(name, defs):
            continue
        falsey = [d for d in defs if _is_falsey(d[2])]
        valued = [d for d in defs if d[2] != ""]
        vtests = facts.value_tests.get(name, [])
        sev = None
        check = {"defined()": f"defined({name})",
                 "#ifndef+error": f"#ifndef {name} / #error"}.get(directive, f"{directive} {name}")
        if falsey and directive == "#ifndef+error":
            locs = ", ".join(f"{d[0]}:{d[1]}" for d in falsey[:3])
            msg = (f"`{check}` is meant to stop the build when {name} is off, but {name} is "
                   f"defined as {falsey[0][2]!r} at {locs}. Defined-as-0 passes an #ifndef, so "
                   f"the build continues without the feature. Use `#if !{name}` / `#error`.")
            sev = "error" if rng_ctx else "note"
            related = [{"file": d[0], "line": d[1]} for d in falsey[:5]]
        elif directive == "#ifndef+error" and not defs and rng_ctx and BOOL_FLAG.search(name):
            msg = (f"`{check}` only checks that {name} exists. Its definition is not in this "
                   f"tree (it comes from a dependency or build system). If it is ever defined as "
                   f"0, this guard passes and the build silently continues without it. Prefer "
                   f"`#if !{name}` / `#error`.")
            sev = "warning"
            related = []
        elif falsey:
            locs = ", ".join(f"{d[0]}:{d[1]}" for d in falsey[:3])
            msg = (f"`{check}` checks whether {name} exists, but it is defined "
                   f"as {falsey[0][2]!r} at {locs}. A macro set to 0 still counts as defined, "
                   f"so this branch is taken when the flag is meant to be OFF. "
                   f"Use `#if {name}` instead.")
            sev = "error" if rng_ctx else "note"
            related = [{"file": d[0], "line": d[1]} for d in falsey[:5]]
        elif valued and vtests:
            locs = ", ".join(f"{r}:{l}" for r, l in vtests[:3])
            msg = (f"`{check}` uses existence semantics, but {name} is also "
                   f"tested by value (`#if {name}`) at {locs}. Mixed semantics on one flag "
                   f"is how a 0 gets treated as ON. Pick one.")
            sev = "warning" if rng_ctx else "note"
            related = [{"file": r, "line": l} for r, l in vtests[:5]]
        if sev is None:
            continue
        if not rng_ctx and sev == "note" and not falsey:
            # Mixed semantics outside the entropy path is too noisy to report.
            continue
        if TEST_PATH.search(rel):
            sev = _downgrade(sev)
        line_text = lines_by_file.get(rel, [""] * lineno)
        src = line_text[lineno - 1] if 0 < lineno <= len(line_text) else raw
        if _suppressed(src, "EG001"):
            continue
        if rng_ctx:
            msg = "[entropy path] " + msg
        out.append(Finding("EG001", sev, rel, lineno, msg, raw, related))
    return out


# ---------------------------------------------------------------- EG002 (C)

WEAK_C = [
    (re.compile(r"\bsrand\s*\(\s*(0|1|[0-9]+u?|0x[0-9a-fA-F]+)\s*\)"), "error",
     "srand() seeded with a constant: every run produces the same sequence."),
    (re.compile(r"\bsrand\s*\(\s*\(?\s*(unsigned\s*(int)?\s*\)?\s*)?time\s*\(\s*(NULL|0|nullptr)?\s*\)"), "error",
     "srand(time(...)): the seed is the clock, guessable to within seconds."),
    (re.compile(r"(?<![\w.>])(rand|random|rand_r|drand48|lrand48|mrand48)\s*\(\s*[^)]*\)"), "warning",
     "libc PRNG ({fn}) is not cryptographically secure."),
    (re.compile(r"\bstd::(mt19937(_64)?|minstd_rand0?|default_random_engine|ranlux\w*|knuth_b)\b"), "warning",
     "std::{fn} is a statistical PRNG, not a CSPRNG."),
]


def _eg002(rel, text):
    if not KEY_CONTEXT.search(text) and not RNG_NAME.search(os.path.basename(rel)):
        return []
    out = []
    in_block = False
    for lineno, raw in enumerate(text.splitlines(), 1):
        code = raw
        if in_block:
            if "*/" in code:
                code = code.split("*/", 1)[1]
                in_block = False
            else:
                continue
        code = re.sub(r"/\*.*?\*/", " ", code)
        if "/*" in code:
            code, in_block = code.split("/*", 1)[0], True
        code = code.split("//", 1)[0]
        code = re.sub(r'"(\\.|[^"\\])*"', '""', code)
        if not code.strip():
            continue
        if code.lstrip().startswith("#"):
            # Only #define bodies can call a PRNG (e.g. #define CHIP_TRNG_32() random()).
            dm = re.match(r"^\s*#\s*define\s+\w+(\([^)]*\))?\s+(.*)$", code)
            if not dm:
                continue
            code = " " + dm.group(2)
        for rx, sev, tmpl in WEAK_C:
            m = rx.search(code)
            if not m:
                continue
            fn = m.group(1) if m.lastindex else ""
            # skip declarations/definitions of our own helpers named random(...)
            if re.search(r"\b(static|extern|void|int|uint\w*|size_t)\s+" + re.escape(fn or "rand") + r"\s*\(", code):
                continue
            if _suppressed(raw, "EG002"):
                break
            s = sev if not TEST_PATH.search(rel) else _downgrade(sev)
            out.append(Finding("EG002", s, rel, lineno,
                               "[entropy path] " + tmpl.format(fn=fn) +
                               " Key and seed material must come from the hardware TRNG or an OS CSPRNG.",
                               raw.strip()))
            break
    return out


# ---------------------------------------------------------------- EG003 (Python)

PY_WEAK_ATTRS = {"random", "randint", "randrange", "choice", "choices", "sample", "shuffle",
                 "getrandbits", "randbytes", "uniform", "seed"}


ENTROPY_TARGET = re.compile(r"(entropy|seed|mnemonic|privkey|private_key|secret|key_?bytes|xprv|"
                            r"dice|rolls?|coin_?flips?)", re.IGNORECASE)
# counters and indices named after entropy are not entropy themselves
NOT_ENTROPY_TARGET = re.compile(r"(count|cnt|len|length|size|idx|index|num|_id|_n|attempts|tries)$",
                                re.IGNORECASE)
RAW_BYTES_ATTRS = {"getrandbits", "randbytes"}
# functions whose job is to produce key material (vs. merely mention it)
KEYGEN_FN = re.compile(r"(gen(erate)?|make|create|new|derive|random)_?\w*(key|seed|entropy|mnemonic|"
                       r"secret|xprv|words?)|keygen", re.IGNORECASE)


def _eg003(rel, text, abspath=None):
    if not KEY_CONTEXT.search(text):
        return []
    # A sibling random.py shadows the stdlib (e.g. Coldcard's CSPRNG-backed module).
    if abspath and os.path.basename(abspath) != "random.py" and \
            os.path.exists(os.path.join(os.path.dirname(abspath), "random.py")):
        return []
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return []
    aliases, direct = set(), {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                if a.name == "random":
                    aliases.add(a.asname or "random")
        elif isinstance(node, ast.ImportFrom) and node.module == "random":
            for a in node.names:
                if a.name in PY_WEAK_ATTRS:
                    direct[a.asname or a.name] = a.name
    if not aliases and not direct:
        return []
    lines = text.splitlines()

    # Map each call to its innermost enclosing function (or module) and the
    # assignment target it feeds, so context is judged locally, not per file.
    scopes = []  # (start, end, name, body_text)
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            end = getattr(node, "end_lineno", node.lineno)
            scopes.append((node.lineno, end, node.name, "\n".join(lines[node.lineno - 1:end])))
    targets = {}
    for node in ast.walk(tree):
        if isinstance(node, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
            tgts = node.targets if isinstance(node, ast.Assign) else [node.target]
            names = [t.id if isinstance(t, ast.Name) else getattr(t, "attr", "") for t in tgts]
            for sub in ast.walk(node.value) if node.value is not None else []:
                if isinstance(sub, ast.Call):
                    targets.setdefault(sub.lineno, []).extend(n for n in names if n)

    def scope_for(ln):
        best = None
        for st, en, name, body in scopes:
            if st <= ln <= en and (best is None or st >= best[0]):
                best = (st, en, name, body)
        if best:
            return best[2], best[3]
        # module level: only module-level statements, not function bodies
        mod = [l for i, l in enumerate(lines, 1) if not any(st <= i <= en for st, en, _, _ in scopes)]
        return "<module>", "\n".join(mod)

    out, seen = [], set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        f = node.func
        attr = None
        if isinstance(f, ast.Attribute) and isinstance(f.value, ast.Name) and f.value.id in aliases:
            attr = f.attr
        elif isinstance(f, ast.Name) and f.id in direct:
            attr = direct[f.id]
        if attr is None or attr not in PY_WEAK_ATTRS:
            continue
        ln = node.lineno
        if ln in seen:
            continue
        fname, body = scope_for(ln)
        if not KEY_CONTEXT.search(body) and not KEY_CONTEXT.search(fname):
            continue
        seen.add(ln)
        src = lines[ln - 1] if ln <= len(lines) else ""
        if _suppressed(src, "EG003"):
            continue
        feeds = [t for t in targets.get(ln, []) if ENTROPY_TARGET.search(t)
                 and not NOT_ENTROPY_TARGET.search(t)]
        if attr in RAW_BYTES_ATTRS or feeds or KEYGEN_FN.search(fname):
            sev = "error"
        else:
            sev = "warning"
        if TEST_PATH.search(rel):
            sev = _downgrade(sev)
        where = f" (assigned to `{feeds[0]}`)" if feeds else ""
        out.append(Finding("EG003", sev, rel, ln,
                           f"[entropy path] random.{attr}(){where} is Mersenne Twister: its state "
                           f"can be recovered from output. Use `secrets` or `os.urandom` for anything "
                           f"that feeds keys, seeds or mnemonics.", src.strip()))
    return out


# ---------------------------------------------------------------- EG004 (JS)

JS_MATH_RANDOM = re.compile(r"\bMath\.random\s*\(")


def _eg004(rel, text):
    if not KEY_CONTEXT.search(text):
        return []
    out = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        code = raw.split("//", 1)[0]
        if JS_MATH_RANDOM.search(code) and not _suppressed(raw, "EG004"):
            sev = "error" if not TEST_PATH.search(rel) else "warning"
            out.append(Finding("EG004", sev, rel, lineno,
                               "[entropy path] Math.random() is not a CSPRNG. Use "
                               "crypto.getRandomValues() or crypto.randomBytes().", raw.strip()))
    return out


# ---------------------------------------------------------------- driver

def scan(root, excludes=None):
    excludes = list(excludes or [])
    facts = _MacroFacts()
    findings = []
    c_lines = {}
    files = 0
    for path, rel in _iter_files(root, excludes):
        name = os.path.basename(path).lower()
        ext = os.path.splitext(name)[1]
        is_c = ext in C_EXT
        is_build = name in BUILD_NAMES or ext in BUILD_EXT
        is_py = ext in PY_EXT
        is_js = ext in JS_EXT
        if not (is_c or is_build or is_py or is_js):
            continue
        text = _read(path)
        if text is None:
            continue
        files += 1
        rel = rel.replace(os.sep, "/")
        if is_c:
            c_lines[rel] = text.splitlines()
            _collect_c(rel, text, facts)
            findings += _eg002(rel, text)
        if is_build:
            _collect_build(rel, text, facts)
        if is_py:
            findings += _eg003(rel, text, path)
            if name in {"setup.py", "conanfile.py"} or "sconstruct" in name:
                _collect_build(rel, text, facts)
        if is_js:
            findings += _eg004(rel, text)
    findings += _eg001(facts, c_lines)
    findings.sort(key=lambda f: (-SEVERITY_ORDER[f.severity], f.file, f.line))
    return findings, files
