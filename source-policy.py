"""Shared defensive static observation filters.

Only obvious literal dead branches and direct statement termination are modeled.
Uncertain attribute mutation suppresses a provenance claim rather than inventing
a runtime result. This is not a general Python interpreter or reachability proof.
"""
import ast

def root_name(node):
    while isinstance(node, (ast.Attribute, ast.Subscript)):
        node = node.value
    return node.id if isinstance(node, ast.Name) else None

def observation_calls(tree):
    mutable_roots = {
        root_name(node) for node in ast.walk(tree)
        if isinstance(node, (ast.Attribute, ast.Subscript)) and
        isinstance(node.ctx, (ast.Store, ast.Del))
    }
    mutable_roots.discard(None)
    calls = set()

    def block(body):
        for statement in body:
            visit(statement)
            if isinstance(statement, (ast.Return, ast.Raise, ast.Break, ast.Continue)):
                break

    def visit(node):
        if isinstance(node, ast.Call):
            if root_name(node.func) not in mutable_roots:
                calls.add(node)
        if isinstance(node, (ast.If, ast.While)):
            visit(node.test)
            if isinstance(node.test, ast.Constant) and type(node.test.value) is bool:
                if node.test.value:
                    block(node.body)
                    # While-else may execute when the loop completes.
                    if isinstance(node, ast.While):
                        block(node.orelse)
                else:
                    block(node.orelse)
            else:
                block(node.body)
                block(node.orelse)
            return
        for field, child in ast.iter_fields(node):
            if isinstance(child, ast.AST):
                visit(child)
            elif isinstance(child, list):
                if child and all(isinstance(x, ast.stmt) for x in child):
                    block(child)
                else:
                    for item in child:
                        if isinstance(item, ast.AST):
                            visit(item)

    visit(tree)
    return calls
