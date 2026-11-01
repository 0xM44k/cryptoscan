"""Python-only context pass: which source lines are constant definitions?

The line rules in rules.py cannot tell *using* an algorithm from *naming* it.
For Python files this module parses the source with `ast` and returns the line
numbers that belong to a declaration rather than to executable use:

* docstrings and other bare string statements;
* import statements, including every line of a parenthesised multi-line import;
* members of Enum/Flag classes (``class Version(IntEnum): TLSv1 = _ssl.PROTO_TLSv1``);
* module- or class-level assignments to UPPER_CASE names whose value is only
  literals, containers of literals/names (lookup tables), or a re-export of
  the same name (``PROTOCOL_TLSv1 = _SSLMethod.PROTOCOL_TLSv1``).

Anything inside a function body, any call, and any lower-case assignment is
treated as use, because hiding a real use would be worse than keeping a false
positive. A file that does not parse yields no information (empty set), so its
hits stay at normal confidence.
"""
from __future__ import annotations

import ast
import re
import warnings

_UPPER = re.compile(r"^_*[A-Z][A-Z0-9_]*$")


def _is_literal(node, in_container=False):
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.UnaryOp):
        return _is_literal(node.operand, in_container)
    if isinstance(node, (ast.Tuple, ast.List, ast.Set)):
        return all(_is_literal(e, True) for e in node.elts)
    if isinstance(node, ast.Dict):
        return all(k is not None and _is_literal(k, True) and _is_literal(v, True) for k, v in zip(node.keys, node.values))
    if in_container and isinstance(node, (ast.Name, ast.Attribute)):
        return True
    return False


def _tail(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _target_names(stmt):
    targets = stmt.targets if isinstance(stmt, ast.Assign) else [stmt.target]
    names = []
    for t in targets:
        if not isinstance(t, ast.Name):
            return None
        names.append(t.id)
    return names


_ENUM_BASES = ("Enum", "IntEnum", "StrEnum", "Flag", "IntFlag", "ReprEnum")


def _is_enum_class(node):
    return any((_tail(b) or "").lstrip("_").endswith(_ENUM_BASES) for b in node.bases)


def _enum_member(stmt):
    if not isinstance(stmt, ast.Assign) or len(stmt.targets) != 1 or not isinstance(stmt.targets[0], ast.Name):
        return False
    return _is_literal(stmt.value, in_container=True) and not isinstance(stmt.value, ast.Call)


def _definition_stmt(stmt):
    if isinstance(stmt, ast.Expr) and isinstance(stmt.value, ast.Constant) and isinstance(stmt.value.value, str):
        return True
    if isinstance(stmt, (ast.Assign, ast.AnnAssign)) and stmt.value is not None:
        names = _target_names(stmt)
        if not names or not all(_UPPER.match(n) for n in names):
            return False
        if _is_literal(stmt.value):
            return True
        tail = _tail(stmt.value)
        return tail is not None and all(tail.upper() == n.lstrip("_").upper() or tail.upper() == n.upper() for n in names)
    return False


def definition_lines(text):
    """Return {line_number: reason} for lines inside definition-like statements."""
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")      # e.g. invalid escape sequences in the scanned file are not our concern
            tree = ast.parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return {}
    out = {}

    def visit(body):
        for stmt in body:
            if _definition_stmt(stmt):
                reason = "docstring or bare string" if isinstance(stmt, ast.Expr) else "constant definition"
                for ln in range(stmt.lineno, (stmt.end_lineno or stmt.lineno) + 1):
                    out[ln] = reason
            elif isinstance(stmt, ast.ClassDef):
                if _is_enum_class(stmt):
                    for member in stmt.body:
                        if _enum_member(member):
                            for ln in range(member.lineno, (member.end_lineno or member.lineno) + 1):
                                out[ln] = "enum member"
                visit(stmt.body)
            elif isinstance(stmt, ast.Expr) is False and isinstance(stmt, (ast.If, ast.Try)):
                visit(stmt.body)
                visit(getattr(stmt, "orelse", []))
                for h in getattr(stmt, "handlers", []):
                    visit(h.body)
            # Function and async function bodies are deliberately not visited:
            # code inside them is use, not declaration.

    visit(tree.body)
    for node in ast.walk(tree):
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for ln in range(node.lineno, (node.end_lineno or node.lineno) + 1):
                out[ln] = "import"
    # Docstrings of functions and classes are also declarations, not use.
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Module)) and node.body:
            first = node.body[0]
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant) and isinstance(first.value.value, str):
                for ln in range(first.lineno, (first.end_lineno or first.lineno) + 1):
                    out[ln] = "docstring or bare string"
    return out
