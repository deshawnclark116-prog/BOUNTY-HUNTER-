"""Bounded, nonexecuting resolution of scalar configuration expressions.

Only literals, simple local aliases and branch joins are understood. No eval,
imports of inspected code, dynamic dispatch, or runtime claims.
"""
import ast

UNKNOWN_VALUE = object()
MAX_TEXT = 1024

def scalar(node, env):
    if isinstance(node, ast.Constant):
        v = node.value
        if v is None or type(v) is bool or (type(v) is str and len(v) <= MAX_TEXT):
            return v
    if isinstance(node, ast.Name):
        return env.get(node.id, UNKNOWN_VALUE)
    return UNKNOWN_VALUE

def same(a, b):
    return type(a) is type(b) and a == b

def merge(left, right):
    return {k:v for k,v in left.items() if k in right and same(v,right[k])}

def configuration_keywords(tree):
    """Map direct call AST nodes to known scalar keyword values.

    Scope-local assignments only; no inherited globals or closure assumptions.
    Unmodeled statements forget facts. Module calls forget facts after use.
    For unknown simple branches, retain only identical facts on both exits.
    """
    observations = {}

    def record(call, env):
        if not isinstance(call, ast.Call):
            return
        if any(k.arg is None for k in call.keywords):
            return
        # Do not derive aliases across arbitrary argument evaluation.
        if any(not isinstance(x, (ast.Constant, ast.Name)) for x in call.args):
            return
        if any(not isinstance(k.value, (ast.Constant, ast.Name)) for k in call.keywords):
            return
        if len({k.arg for k in call.keywords}) != len(call.keywords):
            return
        observations[call] = {k.arg: v for k in call.keywords
                              if (v := scalar(k.value, env)) is not UNKNOWN_VALUE}

    def block(body, initial, module=False):
        env = initial.copy()
        for stmt in body:
            if isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # No outer bindings imported; nonlocal/global are unsupported.
                if not any(isinstance(n,(ast.Global,ast.Nonlocal)) for n in ast.walk(stmt)):
                    block(stmt.body, {}, False)
                env.pop(stmt.name, None)
                if module:
                    env.clear()
            elif isinstance(stmt, ast.Assign) and len(stmt.targets)==1 and isinstance(stmt.targets[0], ast.Name):
                k=stmt.targets[0].id
                v=scalar(stmt.value, env)
                record(stmt.value, env)
                if module and v is UNKNOWN_VALUE:
                    env.clear()
                env.pop(k,None)
                if v is not UNKNOWN_VALUE:
                    env[k]=v
            elif isinstance(stmt, (ast.Expr, ast.Return)):
                record(stmt.value, env)
                if isinstance(stmt, ast.Return):
                    return env, False
                if module or not isinstance(stmt.value,(ast.Constant,ast.Name,ast.Call)):
                    env.clear()
            elif isinstance(stmt, ast.If) and isinstance(stmt.test,(ast.Constant,ast.Name)):
                test=scalar(stmt.test,env)
                if type(test) is bool:
                    env,falls=block(stmt.body if test else stmt.orelse,env,module)
                    if not falls:
                        return env, False
                else:
                    branch_env = {} if module else env
                    left,lf=block(stmt.body,branch_env,module)
                    right,rf=block(stmt.orelse,branch_env,module)
                    if not lf and not rf:
                        return {},False
                    env=merge(left,right) if lf and rf else left if lf else right
            elif isinstance(stmt,(ast.Raise,ast.Break,ast.Continue)):
                return {},False
            else:
                env.clear()
        return env,True

    block(tree.body,{},True)
    return observations
