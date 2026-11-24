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
    "pyramid.response.Response", "pyramid.httpexceptions.HTTPFound",
    "pyramid.httpexceptions.HTTPSeeOther", "pyramid.httpexceptions.HTTPTemporaryRedirect",
}
TLS_CALLS = {
    *("requests." + m for m in ("get", "post", "put", "patch", "delete", "head", "options", "request")),
    *("httpx." + m for m in ("get", "post", "put", "patch", "delete", "head", "options", "request", "Client", "AsyncClient")),
}
CERT_CALLS = {
    "urllib3.PoolManager", "urllib3.ProxyManager", "urllib3.HTTPSConnectionPool",
    "urllib3.connectionpool.HTTPSConnectionPool", "urllib3.connection_from_url",
    "urllib3.proxy_from_url", "urllib3.poolmanager.PoolManager",
    "urllib3.poolmanager.ProxyManager", "urllib3.poolmanager.proxy_from_url",
}
UNKNOWN = object()

def recognized_cookie_calls(tree, include_framework_inference=False):
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
        if include_framework_inference and isinstance(node, ast.Attribute) and node.attr == "response" and isinstance(node.value, ast.Name):
            if values.get(node.value.id) == "pyramid.request.Request":
                return "pyramid.response.Response"
        return None

    def recognized_cookie(call, imports, values):
        return (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute)
                and call.func.attr == "set_cookie"
                and response(call.func.value, imports, values) in RESPONSES)

    findings = []
    def walk(body, inherited, args=None, request_param=None):
        counts = local_bindings(body, args)
        imports = {k:v for k,v in inherited.items() if k not in counts}
        values = {}
        if request_param is not None and counts.get(request_param, 0) == 1:
            values[request_param] = "pyramid.request.Request"
        if any(isinstance(n, (ast.Global, ast.Nonlocal)) or
               isinstance(n, ast.ImportFrom) and any(a.name == "*" for a in n.names)
               for s in body for n in ast.walk(s)):
            return
        for s in body:
            if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)):
                stable = {k:v for k,v in imports.items() if counts.get(k, 0) <= 1}
                request_param = None
                if include_framework_inference:
                    decorators = [d.func if isinstance(d, ast.Call) else d for d in s.decorator_list]
                    positional = [*s.args.posonlyargs, *s.args.args]
                    if len(positional) == 1 and not s.args.vararg and not s.args.kwarg and not s.args.kwonlyargs and not s.args.defaults:
                        if any(qname(d, imports) == "pyramid.view.view_config" for d in decorators):
                            request_param = positional[0].arg
                walk(s.body, stable, s.args, request_param)
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
                if recognized_cookie(s.value, imports, values):
                    findings.append(s.value)
                if isinstance(s, ast.Return):
                    break
                continue
            if isinstance(s, ast.Assign) and len(s.targets) == 1 and isinstance(s.targets[0], ast.Name):
                k = s.targets[0].id
                resolved = response(s.value, imports, values)
                imports.pop(k, None)
                values.pop(k, None)
                if resolved in RESPONSES and (isinstance(s.value, ast.Call) or include_framework_inference and isinstance(s.value, (ast.Attribute, ast.Name))):
                    values[k] = resolved
                continue
            values.clear()
            for k in local_bindings([s]):
                imports.pop(k, None)
            if any(isinstance(n, ast.Attribute) and isinstance(n.ctx, (ast.Store, ast.Del)) for n in ast.walk(s)):
                imports.clear()
    walk(tree.body, {})
    return findings

def cookie_setting(call, key):
    # Only name/value positional arguments are supported. Expanded or ambiguous
    # arguments are explicitly unassessed, not assumed to be secure.
    if len(call.args) > 2 or any(isinstance(a, ast.Starred) for a in call.args) or any(k.arg is None for k in call.keywords):
        return "unknown"
    values = [k.value for k in call.keywords if k.arg == key]
    if not values:
        return "not_explicit"
    if len(values) != 1 or not isinstance(values[0], ast.Constant):
        return "unknown"
    v = values[0].value
    if key in {"secure", "httponly"}:
        return "enabled" if v is True else "disabled" if v is False else "unknown"
    if key == "samesite":
        if v is None:
            return "disabled"
        if isinstance(v, str):
            normalized = v.lower()
            if normalized in {"strict", "lax"}:
                return "restrictive"
            if normalized == "none":
                return "cross_site"
    return "unknown"

def cookie_control_observations(source):
    tree = ast.parse(source)
    allowed = observation_calls(tree)
    direct = set(recognized_cookie_calls(tree))
    return sorted([
        {"line": call.lineno, "end_line": call.end_lineno,
         "provenance": "direct_constructor" if call in direct else "framework_or_alias_inference",
         "secure": cookie_setting(call, "secure"),
         "httponly": cookie_setting(call, "httponly"),
         "samesite": cookie_setting(call, "samesite")}
        for call in recognized_cookie_calls(tree, include_framework_inference=True) if call in allowed
    ], key=lambda row: row["line"])

def direct_cookie_observations(tree):
    return [call for call in recognized_cookie_calls(tree)
            if cookie_setting(call, "secure") in {"disabled", "not_explicit"}]

def inspect_source(source):
    tree = ast.parse(source)
    nodes = list(ast.walk(tree))
    bindings = defaultdict(int)
    aliases = defaultdict(set)
    assignments = defaultdict(list)
    import_counts = defaultdict(int)
    for n in nodes:
        if isinstance(n, ast.Import):
            for a in n.names:
                local = a.asname or a.name.split(".")[0]
                bindings[local] += 1
                aliases[local].add(a.name if a.asname else local)
                import_counts[local] += 1
        elif isinstance(n, ast.ImportFrom):
            for a in n.names:
                if a.name != "*":
                    local = a.asname or a.name
                    bindings[local] += 1
                    if n.level == 0 and n.module:
                        aliases[local].add(n.module + "." + a.name)
                        import_counts[local] += 1
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
            return next(iter(values)) if bindings[n.id] == import_counts[n.id] and len(values) == 1 else None
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
        if q in CERT_CALLS and not any(k.arg is None for k in n.keywords) and not any(isinstance(a, ast.Starred) for a in n.args):
            cert = [k.value for k in n.keywords if k.arg == "cert_reqs"]
            if len(cert) == 1:
                literal = cert[0]
                weak = qualified(literal) in {"ssl.CERT_NONE", "ssl.CERT_OPTIONAL"}
                if isinstance(literal, ast.Constant):
                    weak = weak or (isinstance(literal.value, str) and literal.value in {"NONE", "OPTIONAL", "CERT_NONE", "CERT_OPTIONAL"})
                    weak = weak or (type(literal.value) is int and literal.value in {0, 1})
                if weak:
                    add(n, 295, "certificate_requirement_not_required",
                        "Require server certificate verification for HTTPS connections.")
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
    cases.extend([
        ("import urllib3 as u\nimport ssl\nu.PoolManager(cert_reqs=ssl.CERT_NONE)", [295]),
        ("import urllib3\nimport ssl\nurllib3.PoolManager(cert_reqs=ssl.CERT_REQUIRED)", []),
        ("from urllib3 import ProxyManager\nProxyManager('local',cert_reqs='NONE')", [295]),
        ("from urllib3 import PoolManager\nPoolManager(cert_reqs=0)", [295]),
        ("from urllib3 import PoolManager\nPoolManager(cert_reqs=None)", []),
        ("from urllib3 import PoolManager\nPoolManager(cert_reqs='NONE',**opts)", []),
        ("import ssl\nimport ssl\nimport urllib3\nurllib3.PoolManager(cert_reqs=ssl.CERT_OPTIONAL)", [295]),
        ("import ssl\nssl=other\nimport urllib3\nurllib3.PoolManager(cert_reqs=ssl.CERT_NONE)", []),
        ("from pyramid.response import Response\nr=Response()\nr.set_cookie('id','x',secure=False)", [614]),
        ("from pyramid import httpexceptions as exc\nr=exc.HTTPFound()\nr.set_cookie('id','x',secure=True)", []),
    ])
    control_cases = [
        ("from flask import Response\nr=Response()\nr.set_cookie('id','x',secure=True,httponly=True,samesite='Strict')",
         ("enabled","enabled","restrictive")),
        ("from flask import Response\nResponse().set_cookie('id','x',secure=False,httponly=False,samesite=None)",
         ("disabled","disabled","disabled")),
        ("from flask import Response\nResponse().set_cookie('id','x')",
         ("not_explicit","not_explicit","not_explicit")),
        ("from flask import Response\nResponse().set_cookie('id','x',secure=flag,httponly=True,samesite='None')",
         ("unknown","enabled","cross_site")),
        ("from flask import Response\nResponse().set_cookie('id','x',**opts)",
         ("unknown","unknown","unknown")),
        ("from pyramid.response import Response\nResponse().set_cookie('id','x',secure=True,httponly=False,samesite='Lax')",
         ("enabled","disabled","restrictive")),
    ]
    inferred_cases = [
        ("from pyramid.view import view_config\n@view_config(route_name='demo')\ndef view(req):\n r=req.response\n r.set_cookie('demo','x',httponly=False)", 1),
        ("from pyramid.view import view_config as v\n@v()\ndef view(req):\n r=req.response\n copy=r\n copy.set_cookie('demo','x')", 1),
        ("def view(req):\n r=req.response\n r.set_cookie('demo','x')", 0),
        ("from pyramid.view import view_config\n@view_config()\ndef view(req):\n req=other\n r=req.response\n r.set_cookie('demo','x')", 0),
        ("from pyramid.view import view_config\n@view_config()\ndef view(req, other):\n req.response.set_cookie('demo','x')", 0),
    ]
    for source, expected in inferred_cases:
        rows = cookie_control_observations(source)
        assert len(rows) == expected, source
        assert all(row["provenance"]=="framework_or_alias_inference" for row in rows)
        assert not inspect_source(source), "Do not silently promote inferred provenance into legacy vulnerability labels"
    for source, expected in control_cases:
        rows = cookie_control_observations(source)
        assert len(rows) == 1
        assert tuple(rows[0][k] for k in ("secure","httponly","samesite")) == expected
    for source, expected in cases:
        assert [f["cwe"] for f in inspect_source(source)] == expected, source
    print(json.dumps({"passed": len(cases)+len(control_cases)+len(inferred_cases), "scope": "authored configuration review tests"}))

if __name__ == "__main__":
    if sys.argv[1:] == ["test"]:
        selftest()
    elif len(sys.argv) == 4 and sys.argv[1] == "cookie-controls" and sys.argv[3] == "--authorized-local":
        p = pathlib.Path(sys.argv[2])
        rows = cookie_control_observations(_local_read(p))
        print(json.dumps({"observations":rows, "notice":"Explicit settings only. Missing or unknown settings and unrecognized calls require review. Cookie sensitivity and deployment behavior are not established."},indent=2))
    elif len(sys.argv) == 4 and sys.argv[1] == "review" and sys.argv[3] == "--authorized-local":
        p = pathlib.Path(sys.argv[2])
        print(json.dumps(review_files(sorted(p.glob("*.py")) if p.is_dir() else [p]), indent=2))
    else:
        raise SystemExit("Usage: python python-defaults-review.py test | review FILE_OR_DIRECTORY --authorized-local | cookie-controls FILE --authorized-local")
