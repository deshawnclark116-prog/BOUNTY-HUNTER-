"""Offline, first-party authorization-gap review for Python web route handlers.

Reads source through the AST without importing or running it. Flags review leads
for (A) state-changing or sensitive routes with no visible authentication and
(B) routes that load an object by a caller-supplied identifier with no visible
ownership or permission check. Flask/Quart/FastAPI/Starlette-style decorators only.
Known gaps: identifiers not named like id/pk/uuid/slug/key (e.g. /files/<name>), Django class-based views, and ORM calls through custom helpers are not modeled. A lead is a prompt for human review, not a confirmed vulnerability. A clean result
is not an assurance: global middleware, helper indirection, and framework features
not modeled here can hide or supply checks. No network, execution or target discovery.
"""
import ast
import json
import os
import pathlib
import re
import stat
import sys

MAX_BYTES = 2 * 1024 * 1024
MAX_FILES = 2000
HTTP = {"get", "post", "put", "patch", "delete"}
MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
AUTH_DECORATOR_HINTS = ("login", "auth", "permission", "jwt", "token_required", "roles_", "role_required",
                        "admin_required", "protected", "require_user", "requires_user")
AUTH_DEPENDENCY_HINTS = ("current_user", "get_current", "require_user", "authenticate", "verify_token",
                         "get_user", "auth", "oauth2", "bearer", "api_key", "security")
IDENTITY_TOKENS = ("current_user", "request.user", "g.user", "get_jwt_identity", "get_jwt(", "session[",
                   "session.get(", "token_data", "principal")
AUTHZ_CALL_HINTS = ("authorize", "permission", "owner", "can_", "has_access", "check_access", "policy",
                    "ensure_", "verify_", "require_", "assert_", "is_allowed", "acl")
AUTH_CALL_HINTS = ("verify_jwt", "verify_token", "decode_token", "check_auth", "authenticate", "validate_token",
                   "login_check", "require_login", "check_session")
LOOKUP_ATTRS = {"get", "get_or_404", "first_or_404", "filter_by", "filter", "find_one", "find", "fetch_one",
                "fetchone", "execute", "one", "first", "delete", "one_or_none", "scalar", "scalars"}
LOOKUP_FUNCS = {"get_object_or_404", "get_or_404", "get_list_or_404"}
PUBLIC_PATH = re.compile(r"login|logout|signin|sign-in|signup|sign-up|register|health|ping|static|public|"
                         r"webhook|callback|reset|forgot|verify|oauth|docs|openapi|favicon|robots|^/?$|metrics", re.I)
SENSITIVE_PATH = re.compile(r"admin|user|account|order|invoice|profile|setting|export|delete|key|token|payment|"
                            r"billing|message|document|file|upload|download|report|secret|member|tenant|org", re.I)
ID_NAME = re.compile(r"(^id$|_id$|^pk$|^uuid$|_uuid$|^slug$|^key$)", re.I)


def dotted(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = dotted(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    if isinstance(node, ast.Call):
        return dotted(node.func)
    return ""


def text(node):
    try:
        return ast.unparse(node)
    except Exception:
        return ""


def route_info(func):
    """Return (methods, path) for the first route-like decorator, else None."""
    for dec in func.decorator_list:
        if not isinstance(dec, ast.Call) or not isinstance(dec.func, ast.Attribute):
            continue
        attr = dec.func.attr
        path = ""
        if dec.args and isinstance(dec.args[0], ast.Constant) and isinstance(dec.args[0].value, str):
            path = dec.args[0].value
        for kw in dec.keywords:
            if kw.arg == "path" and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                path = kw.value.value
        if attr in HTTP:
            return {attr.upper()}, path
        if attr in ("route", "api_route", "websocket_route"):
            methods = {"GET"}
            for kw in dec.keywords:
                if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                    found = {e.value.upper() for e in kw.value.elts
                             if isinstance(e, ast.Constant) and isinstance(e.value, str)}
                    if found:
                        methods = found
            return methods, path
    return None


def decorator_auth(func):
    for dec in func.decorator_list:
        name = dotted(dec).lower()
        if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute) and \
                dec.func.attr in HTTP | {"route", "api_route"}:
            for kw in dec.keywords:  # FastAPI route-level dependencies=[Depends(...)]
                if kw.arg == "dependencies" and any(h in text(kw.value).lower() for h in AUTH_DEPENDENCY_HINTS):
                    return True
            continue
        if any(h in name for h in AUTH_DECORATOR_HINTS):
            return True
    return False


def privileged_decorator(func):
    """Role/admin gates make 'any object' access intended, so object-level ownership is not expected."""
    return any(any(h in dotted(d).lower() for h in ("admin", "roles_", "role_required", "superuser", "staff"))
               for d in func.decorator_list)


def dependency_params(func):
    """Names of parameters filled by an authentication-looking Depends/Security, plus any dependency params."""
    auth, dep = set(), set()
    args = func.args
    pos = args.posonlyargs + args.args
    defaults = [None] * (len(pos) - len(args.defaults)) + list(args.defaults)
    pairs = list(zip(pos, defaults)) + list(zip(args.kwonlyargs, args.kw_defaults))
    for arg, default in pairs:
        blob = text(default) if default is not None else ""
        blob += " " + (text(arg.annotation) if arg.annotation is not None else "")
        if re.search(r"\b(Depends|Security)\s*\(", blob):
            dep.add(arg.arg)
            if any(h in blob.lower() for h in AUTH_DEPENDENCY_HINTS):
                auth.add(arg.arg)
    return auth, dep


def id_params(func, path, dep):
    names = set(re.findall(r"[<{](?:[a-z_]+:)?([A-Za-z_][A-Za-z0-9_]*)[>}]", path or ""))
    for arg in func.args.posonlyargs + func.args.args + func.args.kwonlyargs:
        if arg.arg in ("self", "cls") or arg.arg in dep:
            continue
        if ID_NAME.search(arg.arg) and (arg.arg in names or not names):
            names.add(arg.arg)
    return {n for n in names if ID_NAME.search(n)}


def inspect_handler(func, file_flags):
    route = route_info(func)
    if route is None:
        return []
    methods, path = route
    auth_params, dep_params = dependency_params(func)
    identity = tuple(IDENTITY_TOKENS) + tuple(auth_params)
    body_nodes = [n for stmt in func.body for n in ast.walk(stmt)]
    helper_auth = any(isinstance(n, ast.Call) and any(h in dotted(n.func).lower() for h in AUTH_CALL_HINTS)
                      for n in body_nodes)
    authenticated = decorator_auth(func) or bool(auth_params) or helper_auth or \
        any(any(t in text(n) for t in IDENTITY_TOKENS) for n in body_nodes if isinstance(n, (ast.Attribute, ast.Subscript)))
    findings = []
    public = bool(PUBLIC_PATH.search(path or ""))

    # Rule A: missing authentication on state-changing or sensitive route.
    if not authenticated and not public and (methods & MUTATING or SENSITIVE_PATH.search(path or "")):
        status = "needs_review_global_auth_possible" if file_flags["global_auth"] else "lead"
        findings.append({"rule": "missing_authentication", "status": status, "line": func.lineno,
                         "function": func.name,
                         "message": "Route changes state or looks sensitive but no authentication check is visible "
                                    "in decorators, dependencies or body. Confirm whether a global control applies."})

    # Rule B: object loaded by caller-supplied id with no visible ownership/permission check.
    ids = id_params(func, path, dep_params)
    if ids and not privileged_decorator(func):
        lookups = []
        for n in body_nodes:
            if not isinstance(n, ast.Call):
                continue
            fname = dotted(n.func)
            last = fname.rsplit(".", 1)[-1]
            receiver = fname.rsplit(".", 1)[0] if "." in fname else ""
            if last == "get" and receiver.isupper():  # constant mapping, not a datastore
                continue
            if last in LOOKUP_ATTRS or last in LOOKUP_FUNCS:
                names_in = {m.id for a in list(n.args) + [k.value for k in n.keywords] for m in ast.walk(a)
                            if isinstance(m, ast.Name)}
                if names_in & ids:
                    lookups.append(n)
        if lookups:
            checked = False
            for n in body_nodes:
                if isinstance(n, ast.Compare) and any(t in text(n) for t in identity):
                    checked = True
                if isinstance(n, (ast.If, ast.IfExp, ast.Assert)) and any(t in text(n.test if hasattr(n, "test") else n)
                                                                           for t in identity):
                    checked = True
                if isinstance(n, ast.Call):
                    fn = dotted(n.func).lower()
                    if any(h in fn for h in AUTHZ_CALL_HINTS):
                        checked = True
                    if fn.endswith(("abort", "httpexception", "forbidden")) and "403" in text(n):
                        checked = True
            for n in lookups:
                if any(t in text(a) for a in list(n.args) + [k.value for k in n.keywords] for t in identity):
                    checked = True
            if not checked:
                findings.append({"rule": "missing_object_authorization", "status": "lead", "line": func.lineno,
                                 "function": func.name,
                                 "message": "Object is loaded using a caller-supplied identifier and no ownership, "
                                            "tenant or permission comparison is visible. Verify by hand whether one "
                                            "caller can reach another caller's object."})
    return findings


def inspect_source(source):
    tree = ast.parse(source)
    whole = text(tree).lower()
    global_auth = ("before_request" in whole or "add_middleware" in whole or "dependencies=[" in whole or
                   "authenticationmiddleware" in whole or "dependencies=(" in whole)
    flags = {"global_auth": global_auth}
    findings, handlers = [], 0
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and route_info(node) is not None:
            handlers += 1
            findings.extend(inspect_handler(node, flags))
    return handlers, findings


def review_files(paths):
    results, errors, handlers, total = [], [], 0, 0
    for p in paths[:MAX_FILES]:
        try:
            info = os.lstat(p)
            if not stat.S_ISREG(info.st_mode) or info.st_size > MAX_BYTES:
                raise ValueError
            h, f = inspect_source(pathlib.Path(p).read_text(encoding="utf-8"))
            handlers += h
            total += len(f)
            if f:
                results.append({"filename": str(p), "findings": f})
        except Exception:
            errors.append({"filename": str(p)})
    return {"metrics": {"files": len(paths[:MAX_FILES]), "route_handlers": handlers, "leads": total,
                        "errors": len(errors)},
            "results": results, "errors": errors,
            "notice": "Authorization-gap review leads only. Not confirmed vulnerabilities, not exploitability "
                      "and not a security rating. Global middleware, helpers and unmodeled frameworks are not "
                      "resolved. A clean result is not an assurance."}


FIXTURES = [
    # (name, source, expected set of (function, rule))
    ("unauth delete", "from flask import Flask\napp=Flask(__name__)\n@app.route('/orders/<int:order_id>',methods=['DELETE'])\ndef rm(order_id):\n    Order.query.filter_by(id=order_id).delete()\n",
     {("rm", "missing_authentication"), ("rm", "missing_object_authorization")}),
    ("idor flask", "@app.route('/invoice/<int:invoice_id>')\n@login_required\ndef show(invoice_id):\n    inv = Invoice.query.get(invoice_id)\n    return render(inv)\n",
     {("show", "missing_object_authorization")}),
    ("idor fastapi", "@router.get('/files/{file_id}')\nasync def f(file_id: int, user=Depends(get_current_user)):\n    return await db.get(File, file_id)\n",
     {("f", "missing_object_authorization")}),
    ("unauth fastapi post", "@router.post('/users')\nasync def create(body: UserIn):\n    return await save(body)\n",
     {("create", "missing_authentication")}),
    ("unauth sensitive get", "@app.get('/admin/export')\ndef export():\n    return dump_all()\n",
     {("export", "missing_authentication")}),
    ("django-style get_object_or_404 idor", "@app.route('/doc/<int:pk>')\n@login_required\ndef doc(pk):\n    d = get_object_or_404(Doc, pk=pk)\n    return d.body\n",
     {("doc", "missing_object_authorization")}),
    ("no ownership check but session read only for display", "@app.route('/note/<int:note_id>')\n@login_required\ndef note(note_id):\n    n = Note.query.get(note_id)\n    return render(n, who=current_user.name)\n",
     {("note", "missing_object_authorization")}),
    ("unauth mass endpoint post", "@app.route('/settings',methods=['POST'])\ndef s():\n    set_all(request.json)\n",
     {("s", "missing_authentication")}),
    # negatives
    ("owner compare", "@app.route('/invoice/<int:invoice_id>')\n@login_required\ndef show(invoice_id):\n    inv = Invoice.query.get(invoice_id)\n    if inv.owner_id != current_user.id:\n        abort(403)\n    return render(inv)\n", set()),
    ("scoped query", "@app.route('/invoice/<int:invoice_id>')\n@login_required\ndef show(invoice_id):\n    return Invoice.query.filter_by(id=invoice_id, owner_id=current_user.id).first_or_404()\n", set()),
    ("fastapi scoped", "@router.get('/files/{file_id}')\nasync def f(file_id: int, user=Depends(get_current_user)):\n    return await db.get(File, file_id, owner=user.id)\n", set()),
    ("authz helper", "@app.route('/doc/<int:pk>')\n@login_required\ndef doc(pk):\n    d = get_object_or_404(Doc, pk=pk)\n    ensure_can_view(current_user, d)\n    return d.body\n", set()),
    ("login public", "@app.route('/login',methods=['POST'])\ndef login():\n    return check(request.form)\n", set()),
    ("health public", "@app.get('/health')\ndef h():\n    return 'ok'\n", set()),
    ("public get nonsensitive", "@app.get('/about')\ndef about():\n    return 'hi'\n", set()),
    ("auth via dependency", "@router.post('/users')\nasync def create(body: UserIn, me=Depends(get_current_user)):\n    return await save(body)\n", set()),
    ("route-level dependencies", "@router.post('/users', dependencies=[Depends(require_user)])\nasync def create(body: UserIn):\n    return await save(body)\n", set()),
    ("decorator auth", "@app.route('/settings',methods=['POST'])\n@login_required\ndef s():\n    set_all(request.json)\n", set()),
    ("not a route", "def helper(order_id):\n    return Order.query.get(order_id)\n", set()),
    ("webhook public", "@app.post('/webhook/stripe')\ndef hook():\n    return 'ok'\n", set()),
    # ambiguous: global auth exists, so missing-auth is flagged for review, not as a lead
    ("admin role gate", "@app.route('/admin/x/<int:x_id>',methods=['POST'])\n@admin_required\ndef g(x_id):\n    X.query.get(x_id).run()\n", set()),
    ("constant mapping get", "@app.route('/c/<int:cat_id>')\n@login_required\ndef g(cat_id):\n    return CATS.get(cat_id)\n", set()),
    ("session auth but no owner check", "@app.route('/msg/<int:msg_id>')\ndef g(msg_id):\n    if 'uid' not in session: return redirect('/x')\n    return Msg.query.get(msg_id).body\n",
     {("g", "missing_object_authorization")}),
    ("helper verifies token", "@app.route('/fetch',methods=['POST'])\ndef f():\n    if not verify_jwt(request.headers['Authorization']):\n        return 'no',401\n    return data()\n", set()),
    ("global before_request", "@app.before_request\ndef gate():\n    check_session()\n@app.route('/settings',methods=['POST'])\ndef s():\n    set_all(request.json)\n",
     {("s", "missing_authentication")}),
]


def selftest():
    tp = fp = fn = tn = 0
    for name, source, expected in FIXTURES:
        _, found = inspect_source(source)
        got = {(f["function"], f["rule"]) for f in found}
        if name == "global before_request":
            assert {f["status"] for f in found} == {"needs_review_global_auth_possible"}, name
        tp += len(got & expected)
        fp += len(got - expected)
        fn += len(expected - got)
        tn += 1 if not expected and not got else 0
        assert got == expected, f"{name}: expected {sorted(expected)} got {sorted(got)}"
    # malformed input must not pass silently
    out = review_files([pathlib.Path("/nonexistent/x.py")])
    assert out["metrics"]["errors"] == 1
    try:
        inspect_source("def (:")
        raise SystemExit("syntax error was accepted")
    except SyntaxError:
        pass
    print(json.dumps({"passed": len(FIXTURES) + 2, "fixtures": len(FIXTURES), "true_positive_leads": tp,
                      "false_positive_leads": fp, "missed_leads": fn, "clean_negative_cases": tn,
                      "scope": "authored regression fixtures, not independent holdout; G2 unmet"}))


def main(argv):
    if argv == ["test"]:
        selftest()
        return 0
    if len(argv) == 3 and argv[0] == "review" and argv[2] == "--authorized-local":
        p = pathlib.Path(argv[1])
        paths = sorted(p.rglob("*.py")) if p.is_dir() else [p]
        out = review_files([x for x in paths if not any(part in ("node_modules", ".git", "venv", ".venv")
                                                        for part in x.parts)])
        print(json.dumps(out, indent=2))
        if out["metrics"]["errors"]:
            return 1
        return 3 if out["metrics"]["leads"] else 0
    raise SystemExit("Usage: python authz-review.py test | review FILE_OR_DIRECTORY --authorized-local")


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
