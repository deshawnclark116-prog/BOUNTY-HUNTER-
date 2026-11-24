"""Offline, first-party Python digest policy review.

Flags explicit legacy digest algorithm selection, not exploitability.
No importing or execution of inspected code, network, or target discovery.
"""
import ast
import json
import os
import pathlib
import stat
import sys
from collections import defaultdict

MAX_BYTES = 2 * 1024 * 1024
MAX_FILES = 2000
LEGACY = {"md5", "sha1", "md4", "md2"}
DIRECT = {
    "hashlib.md5": "md5", "hashlib.sha1": "sha1",
    "cryptography.hazmat.primitives.hashes.MD5": "md5",
    "cryptography.hazmat.primitives.hashes.SHA1": "sha1",
    **{f"{package}.Hash.{algorithm.upper()}.new": algorithm
       for package in ("Crypto", "Cryptodome") for algorithm in LEGACY},
}

def inspect_source(source):
    tree = ast.parse(source)
    aliases = defaultdict(set)
    bindings = defaultdict(int)
    # Conservative whole-file name binding index: shadowed or reassigned imports
    # are not resolved. This sacrifices coverage rather than guessing provenance.
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                local = a.asname or a.name.split(".")[0]
                aliases[local].add(a.name if a.asname else local)
                bindings[local] += 1
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            for a in node.names:
                if a.name != "*":
                    local = a.asname or a.name
                    aliases[local].add(node.module + "." + a.name)
                    bindings[local] += 1
        elif isinstance(node, ast.Name) and isinstance(node.ctx, (ast.Store, ast.Del)):
            bindings[node.id] += 1
        elif isinstance(node, ast.arg):
            bindings[node.arg] += 1
        elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings[node.name] += 1
        elif isinstance(node, ast.ExceptHandler) and node.name:
            bindings[node.name] += 1
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            bindings[node.name] += 1
        elif isinstance(node, ast.MatchMapping) and node.rest:
            bindings[node.rest] += 1
    def qualified(node):
        if isinstance(node, ast.Name):
            candidates = aliases.get(node.id, ())
            return next(iter(candidates)) if len(candidates) == 1 and bindings[node.id] == 1 else None
        if isinstance(node, ast.Attribute):
            parent = qualified(node.value)
            return parent + "." + node.attr if parent else None
        return None
    findings = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        q = qualified(node.func)
        if not q:
            continue
        algorithm = DIRECT.get(q)
        if q == "hashlib.new":
            name = node.args[0] if node.args else next((x.value for x in node.keywords if x.arg == "name"), None)
            if isinstance(name, ast.Constant) and isinstance(name.value, str):
                candidate = name.value.lower().replace("-", "")
                if candidate in LEGACY:
                    algorithm = candidate
        if not algorithm:
            continue
        if q.startswith("hashlib.") and any(
            k.arg == "usedforsecurity" and isinstance(k.value, ast.Constant) and k.value.value is False
            for k in node.keywords
        ):
            continue
        findings.append({"line": node.lineno, "algorithm": algorithm, "cwe": 328,
                         "status": "legacy_digest_requires_context_review"})
    return sorted(findings, key=lambda x: (x["line"], x["algorithm"]))

def local_read(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_BYTES:
            raise ValueError("Unsupported file")
        with os.fdopen(fd, "rb", closefd=False) as f:
            data = f.read(MAX_BYTES + 1)
        if len(data) > MAX_BYTES:
            raise ValueError("File exceeds limit")
        return data
    finally:
        os.close(fd)

def review_files(paths):
    if not 1 <= len(paths) <= MAX_FILES:
        raise ValueError("Invalid file count")
    results, errors, metrics = [], [], {}
    for p in paths:
        p = pathlib.Path(p)
        try:
            findings = inspect_source(local_read(p))
            metrics[str(p)] = {}
            for f in findings:
                results.append({"filename": str(p), "line_number": f["line"],
                                "issue_cwe": {"id": f["cwe"]}, "algorithm": f["algorithm"],
                                "status": f["status"]})
        except (OSError, ValueError, SyntaxError, RecursionError, UnicodeError):
            errors.append({"filename": str(p)})
    return {"metrics": metrics, "results": results, "errors": errors,
            "notice": "Legacy digest policy observations only. No finding is a confirmed vulnerability. Other code and security properties are not assessed."}

def selftest():
    examples = [
        ("import hashlib\nhashlib.md5(b'x')", 1),
        ("import hashlib as h\nh.sha1(b'x')", 1),
        ("from hashlib import md5 as digest\ndigest(b'x')", 1),
        ("from hashlib import new\nnew('SHA-1')", 1),
        ("import hashlib\nhashlib.new(name='md5')", 1),
        ("import hashlib\nhashlib.sha256(b'x')", 0),
        ("import hashlib\nhashlib.md5(b'x', usedforsecurity=False)", 0),
        ("import hashlib\nhashlib.new('sha1', usedforsecurity=False)", 0),
        ("import hashlib as h\nh=other\nh.md5(b'x')", 0),
        ("import hashlib\ndef f(hashlib):\n return hashlib.md5(b'x')", 0),
        ("def md5(x): return x\nmd5(b'x')", 0),
        ("from cryptography.hazmat.primitives import hashes\nhashes.SHA1()", 1),
        ("from Crypto.Hash import MD5\nMD5.new(b'x')", 1),
        ("import hashlib\nname='sha1'\nhashlib.new(name)", 0),
        ("# hashlib.md5(b'x')\nx='hashlib.md5()'", 0),
        ("import hashlib\nhashlib.blake2b(b'x')", 0),
    ]
    for source, expected in examples:
        assert len(inspect_source(source)) == expected, source
    print(json.dumps({"passed": len(examples), "scope": "authored digest-policy regression tests"}))

if __name__ == "__main__":
    if sys.argv[1:] == ["test"]:
        selftest()
    elif len(sys.argv) == 4 and sys.argv[1] == "review" and sys.argv[3] == "--authorized-local":
        p = pathlib.Path(sys.argv[2])
        paths = sorted(p.glob("*.py")) if p.is_dir() else [p]
        print(json.dumps(review_files(paths), indent=2))
    else:
        raise SystemExit("Usage: python digest-review.py test | review FILE_OR_DIRECTORY --authorized-local")
