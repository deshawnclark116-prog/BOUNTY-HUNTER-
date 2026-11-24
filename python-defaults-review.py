"""First-party offline review of explicit Python security configuration choices.

Only parses source. No application import, execution, network, or target discovery.
Findings require owner context; a clean result is not a security assessment.
"""
import ast
import json
import pathlib
import runpy
import sys
from collections import defaultdict

# Reuse only the bounded file reader from our own previously reviewed module.
_local_read = runpy.run_path(str(pathlib.Path(__file__).with_name("digest-review.py")))["local_read"]
RESPONSES = {
    "flask.Response", "flask.make_response", "flask.wrappers.Response",
    "werkzeug.wrappers.Response", "django.http.HttpResponse",
    "django.http.JsonResponse", "django.http.HttpResponseRedirect",
}
TLS_CALLS = {
    *("requests." + m for m in ("get", "post", "put", "patch", "delete", "head", "options", "request")),
    *("httpx." + m for m in ("get", "post", "put", "patch", "delete", "head", "options", "request", "Client", "AsyncClient")),
}
UNKNOWN = object()

def inspect_source(source):
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    bindings = defaultdict(int)
    aliases = defaultdict(set)
    assignments = defaultdict(list)
    for n in nodes:
        if isinstance(n, ast.Import):
            for a in n.names:
                local = a.asname or a.name.split(".")[0]
                bindings[local] += 1
                aliases[local].add(a.name if a.asname else local)
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name != "*":
                    local = a.asname or a.name
                    bindings[local] += 1
                    if n.level == 0 and n.module:
                        aliases[local].add(n.module + "." + a.name)
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            bindings[n.id] += 1
        elif isinstance(n, ast.arg):
            bindings[n.arg] += 1
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            bindings[n.name] += 1
        elif isinstance(n, ast.ExceptHandler) and n.name:
            bindings[n.name] += 1
        elif isinstance(n, (ast.MatchAs, ast.MatchStar)) and n.name:
            bindings[n.name] += 1
        elif isinstance(n, ast.MatchMapping) and n.rest:
            bindings[n.rest] += 1
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            assignments[n.targets[0].id].append(n.value)
        elif isinstance(n, ast.AnnAssign) and isinstance(n.target, ast.Name) and n.value is not None:
            assignments[n.target.id].append(n.value)

    def qualified(n):
        if isinstance(n, ast.Name):
            values = aliases.get(n.id, ())
            return next(iter(values)) if bindings[n.id] == 1 and len(values) == 1 else None
        if isinstance(n, ast.Attribute):
            parent = qualified(n.value)
            return parent + "." + n.attr if parent else None
        return None

    def constructor(n):
        if isinstance(n, ast.Call):
            return qualified(n.func)
        if isinstance(n, ast.Name) and bindings[n.id] == 1 and len(assignments[n.id]) == 1:
            value = assignments[n.id][0]
            if isinstance(value, ast.Call):
                return qualified(value.func)
        return None

    def keyword(n, key, default=UNKNOWN):
        # Dynamic keyword expansion, duplicate keywords or starred arguments
        # prevent a reliable statement about the selected configuration.
        if any(k.arg is None for k in n.keywords) or any(isinstance(a, ast.Starred) for a in n.args):
            return UNKNOWN
        found = [k.value for k in n.keywords if k.arg == key]
        if not found:
            return default
        if len(found) == 1 and isinstance(found[0], ast.Constant):
            return found[0].value
        return UNKNOWN

    findings = []
    def add(n, cwe, rule, remediation):
        findings.append({"line": n.lineno, "cwe": cwe, "rule": rule,
                         "status": "configuration_requires_context_review",
                         "remediation": remediation})
    for n in nodes:
        if not isinstance(n, ast.Call):
            continue
        q = qualified(n.func)
        if q in TLS_CALLS and keyword(n, "verify") is False:
            add(n, 295, "explicit_tls_verification_disabled",
                "Keep certificate verification enabled; use an approved trust store.")
        if q == "ssl._create_unverified_context":
            add(n, 295, "unverified_tls_context_selected",
                "Use a verified TLS context appropriate to the connection.")
        if isinstance(n.func, ast.Attribute) and n.func.attr == "set_cookie" and constructor(n.func.value) in RESPONSES:
            # Do not infer positional options beyond name/value. Cookie sensitivity
            # and the deployment's actual transport policy still require review.
            if len(n.args) <= 2 and keyword(n, "secure", False) is False:
                add(n, 614, "cookie_secure_not_enabled",
                    "For cookies carrying sensitive state, set Secure and require HTTPS.")
    return sorted(findings, key=lambda f: (f["line"], f["rule"]))

def review_files(paths):
    if not 1 <= len(paths) <= 2000:
        raise ValueError("Invalid file count")
    results, errors, metrics = [], [], {}
    for p in paths:
        p = pathlib.Path(p)
        try:
            findings = inspect_source(_local_read(p))
            metrics[str(p)] = {}
            for f in findings:
                results.append({"filename": str(p), "line_number": f["line"],
                                "issue_cwe": {"id": f["cwe"]}, "rule": f["rule"],
                                "status": f["status"], "remediation": f["remediation"]})
        except (OSError, ValueError, SyntaxError, RecursionError, UnicodeError):
            errors.append({"filename": str(p)})
    return {"metrics": metrics, "results": results, "errors": errors,
            "notice": "Bounded configuration observations only; context and runtime impact are unverified."}

def selftest():
    cases = [
        ("import requests\nrequests.get(url, verify=False)", [295]),
        ("import requests as r\nr.get(url, verify=True)", []),
        ("from requests import get\nget(url, verify=False)", [295]),
        ("import requests\nrequests.get(url, **opts)", []),
        ("import requests\nrequests = other\nrequests.get(url, verify=False)", []),
        ("import httpx\nhttpx.Client(verify=False)", [295]),
        ("import ssl\nssl._create_unverified_context()", [295]),
        ("from ssl import create_default_context\ncreate_default_context()", []),
        ("from flask import make_response\nr=make_response('ok')\nr.set_cookie('id','x')", [614]),
        ("from flask import Response\nResponse().set_cookie('id','x',secure=False)", [614]),
        ("from flask import Response\nr=Response()\nr.set_cookie('id','x',secure=True)", []),
        ("from django.http import HttpResponse\nr=HttpResponse()\nr.set_cookie('id','x')", [614]),
        ("from werkzeug.wrappers import Response\nr=Response()\nr.set_cookie('id','x',**opts)", []),
        ("r=unknown()\nr.set_cookie('id','x')", []),
        ("from flask import Response\nr=Response()\nr=unknown()\nr.set_cookie('id','x')", []),
        ("from flask import Response\nr=Response()\nr.set_cookie('id','x',42)", []),
        ("from flask import Response\nr=Response()\nr.set_cookie('id','x',secure=setting)", []),
        ("from flask import Response\n# Response().set_cookie('id','x')", []),
    ]
    for source, expected in cases:
        assert [f["cwe"] for f in inspect_source(source)] == expected, source
    print(json.dumps({"passed": len(cases), "scope": "authored configuration review tests"}))

if __name__ == "__main__":
    if sys.argv[1:] == ["test"]:
        selftest()
    elif len(sys.argv) == 4 and sys.argv[1] == "review" and sys.argv[3] == "--authorized-local":
        p = pathlib.Path(sys.argv[2])
        print(json.dumps(review_files(sorted(p.glob("*.py")) if p.is_dir() else [p]), indent=2))
    else:
        raise SystemExit("Usage: python python-defaults-review.py test | review FILE_OR_DIRECTORY --authorized-local")
