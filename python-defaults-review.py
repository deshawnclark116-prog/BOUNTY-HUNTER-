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
observation_calls = runpy.run_path(str(pathlib.Path(__file__).with_name("source-policy.py")))["observation_calls"]
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

def direct_cookie_observations(tree):
    """Bounded lexical, straight-line review of response construction."""
    def local_bindings(body, args=None):
        counts = defaultdict(int)
        class Bindings(ast.NodeVisitor):
            def visit_Name(self, node):
                if isinstance(node.ctx, (ast.Store, ast.Del)):
                    counts[node.id] += 1
            def visit_Import(self, node):
                for a in node.names:
                    counts[a.asname or a.name.split(".")[0]] += 1
            def visit_ImportFrom(self, node):
                for a in node.names:
                    counts[a.asname or a.name] += 1
            def visit_FunctionDef(self, node):
                counts[node.name] += 1
            visit_AsyncFunctionDef = visit_FunctionDef
            visit_ClassDef = visit_FunctionDef
            def visit_Lambda(self, node):
                pass
            def visit_ExceptHandler(self, node):
                if node.name:
                    counts[node.name] += 1
                self.generic_visit(node)
            def visit_MatchAs(self, node):
                if node.name:
                    counts[node.name] += 1
                self.generic_visit(node)
            visit_MatchStar = visit_MatchAs
            def visit_MatchMapping(self, node):
                if node.rest:
                    counts[node.rest] += 1
                self.generic_visit(node)
        visitor = Bindings()
        for statement in body:
            visitor.visit(statement)
        if args:
            for a in [*args.posonlyargs, *args.args, *args.kwonlyargs, args.vararg, args.kwarg]:
                if a:
                    counts[a.arg] += 1
        return counts

    def qname(node, imports):
        if isinstance(node, ast.Name):
            return imports.get(node.id)
        if isinstance(node, ast.Attribute):
            parent = qname(node.value, imports)
            return parent + "." + node.attr if parent else None
        return None

    def response(node, imports, values):
        if isinstance(node, ast.Name):
            return values.get(node.id)
        if isinstance(node, ast.Call):
            return qname(node.func, imports)
        return None

    def explicit_cookie(call, imports, values):
        if not isinstance(call, ast.Call) or not isinstance(call.func, ast.Attribute):
            return False
        if call.func.attr != "set_cookie" or response(call.func.value, imports, values) not in RESPONSES:
            return False
        if len(call.args) > 2 or any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
            return False
        keys = [k.value for k in call.keywords if k.arg == "secure"]
        return not keys or (len(keys) == 1 and isinstance(keys[0], ast.Constant) and keys[0].value is False)

    findings = []
    def walk(body, inherited, args=None):
        counts = local_bindings(body, args)
        imports = {k:v for k,v in inherited.items() if k not in counts}
        values = {}
        if any(isinstance(n, (ast.Global, ast.Nonlocal)) or
               isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
               for s in body for n in ast.walk(s)):
            return
        for s in body:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                stable = {k:v for k,v in imports.items() if counts.get(k, 0) <= 1}
                walk(s.body, stable, s.args)
                imports.pop(s.name, None)
                values.pop(s.name, None)
                continue
            if isinstance(s, (ast.Import, ast.ImportFrom)):
                for a in s.names:
                    k = a.asname or (a.name.split(".")[0] if isinstance(s, ast.Import) else a.name)
                    values.pop(k, None)
                    if isinstance(s, ast.Import):
                        imports[k] = a.name if a.asname else k
                    elif s.level == 0 and s.module:
                        imports[k] = s.module + "." + a.name
                    else:
                        imports.pop(k, None)
                continue
            if isinstance(s, (ast.Expr, ast.Return)):
                if explicit_cookie(s.value, imports, values):
                    findings.append(s.value)
                if isinstance(s, ast.Return):
                    break
                continue
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                k = s.targets[0].id
                resolved = response(s.value, imports, values)
                imports.pop(k, None)
                values.pop(k, None)
                if isinstance(s.value, ast.Call) and resolved in RESPONSES:
                    values[k] = resolved
                continue
            values.clear()
            for k in local_bindings([s]):
                imports.pop(k, None)
            if any(isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)) for n in ast.walk(s)):
                imports.clear()
    walk(tree.body, {})
    return findings

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
    allowed_calls = observation_calls(tree)
    for n in allowed_calls:
        if not isinstance(n, ast.Call):
            continue
        q = qualified(n.func)
        if q in TLS_CALLS and keyword(n, "verify") is False:
            add(n, 295, "explicit_tls_verification_disabled",
                "Keep certificate verification enabled; use an approved trust store.")
        if q == "ssl._create_unverified_context":
            add(n, 295, "unverified_tls_context_selected",
                "Use a verified TLS context appropriate to the connection.")
    for n in direct_cookie_observations(tree):
        if n not in allowed_calls:
            continue
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
    cases.extend([
        ("from flask import make_response\n"
         "def build():\n from flask import make_response\n response=''\n"
         " response=make_response(response)\n response.set_cookie('id','x',secure=False)", [614]),
        ("from flask import Response\ndef build(Response):\n r=Response()\n r.set_cookie('id','x')", []),
        ("from flask import Response\ndef build():\n r=Response()\n if cond: r=other()\n r.set_cookie('id','x')", []),
    ])
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
