"""Python-specific MCP tool detection for Phase 2.

Uses the stdlib :mod:`ast` module so we never evaluate target code. Handles
the three idioms that cover ~all real-world Python MCP servers we've seen:

1. **FastMCP decorator pattern** — ``@mcp.tool(...)`` / ``@mcp.tool``
   over a top-level function. The docstring doubles as the description
   unless an explicit ``description=`` kwarg is supplied.

2. **Explicit registration calls** — ``server.add_tool(Tool(...))`` or
   ``server.register_tool(name=..., description=...)``.

3. **Low-level ``Server`` API** — ``Tool(name=..., description=...,
   inputSchema=...)`` literals returned from a function wrapped with
   ``@server.list_tools()``. Names commonly come from a string-Enum
   (``GitTools.STATUS``); we resolve those by pre-scanning the module for
   ``class X(str, Enum):`` definitions.

Anything we can't parse deterministically we skip — Phase 2 is signal, not
ground truth.
"""

from __future__ import annotations

import ast
from pathlib import Path
from typing import Final

from mcp_audit.schemas import Entrypoint, ToolDefinition

from ._patterns import ENTRYPOINT_CONSTRUCTOR_NAMES

#: Decorator attribute names that identify MCP tool registration. Matches
#: ``@mcp.tool(...)``, ``@server.tool(...)``, ``@app.tool_decorator(...)``,
#: etc.
_TOOL_DECORATOR_ATTRS: Final[frozenset[str]] = frozenset({"tool", "register_tool", "add_tool"})

#: Methods on a server object used for non-decorator registration.
_TOOL_REGISTRATION_METHODS: Final[frozenset[str]] = frozenset(
    {"register_tool", "add_tool", "set_tool", "tool"}
)

#: Class names that, when constructed, represent a single MCP tool record.
#: Only ``Tool`` is standard (MCP Python SDK); the others are defensive.
_TOOL_CLASS_NAMES: Final[frozenset[str]] = frozenset({"Tool", "ToolDefinition"})


def _extract_string(node: ast.AST) -> str | None:
    """Return the value of ``node`` if it is a string literal, else None."""
    if isinstance(node, ast.Constant) and isinstance(node.value, str):
        return node.value
    return None


def _kwarg_string(keywords: list[ast.keyword], name: str) -> str | None:
    for kw in keywords:
        if kw.arg == name:
            return _extract_string(kw.value)
    return None


def _build_input_schema(func: ast.FunctionDef | ast.AsyncFunctionDef) -> dict[str, object] | None:
    """Synthesize a very rough JSON Schema from a function's signature.

    We don't call any runtime code; we only inspect ``ast.arg.annotation``
    nodes. Unknown / complex annotations are represented as ``{}`` so the
    resulting schema is still valid JSON Schema even if fuzzy.
    """
    args = func.args
    positional = [a for a in args.args if a.arg != "self"]
    if not positional and not args.kwonlyargs:
        return None
    properties: dict[str, dict[str, object]] = {}
    required: list[str] = []
    for arg in positional + args.kwonlyargs:
        properties[arg.arg] = _annotation_to_schema(arg.annotation)
        # Any arg without a default is required. defaults apply to the tail
        # of args.args; kw-only defaults are args.kw_defaults (None == required).
        if arg in args.args:
            defaults = args.defaults
            idx = args.args.index(arg)
            has_default = idx >= len(args.args) - len(defaults)
            if not has_default:
                required.append(arg.arg)
        else:
            # kw-only
            idx = args.kwonlyargs.index(arg)
            if args.kw_defaults[idx] is None:
                required.append(arg.arg)
    schema: dict[str, object] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return schema


def _annotation_to_schema(node: ast.expr | None) -> dict[str, object]:
    """Best-effort mapping of a Python annotation AST to JSON Schema."""
    if node is None:
        return {}
    if isinstance(node, ast.Name):
        return _primitive_schema(node.id)
    if isinstance(node, ast.Subscript):
        # list[str], dict[str, int], Optional[...]
        value = node.value
        if isinstance(value, ast.Name):
            return _primitive_schema(value.id)
        if isinstance(value, ast.Attribute):
            return _primitive_schema(value.attr)
    if isinstance(node, ast.Attribute):
        return _primitive_schema(node.attr)
    return {}


def _primitive_schema(type_name: str) -> dict[str, object]:
    mapping = {
        "str": {"type": "string"},
        "int": {"type": "integer"},
        "float": {"type": "number"},
        "bool": {"type": "boolean"},
        "bytes": {"type": "string"},
        "list": {"type": "array"},
        "List": {"type": "array"},
        "tuple": {"type": "array"},
        "Tuple": {"type": "array"},
        "dict": {"type": "object"},
        "Dict": {"type": "object"},
        "Mapping": {"type": "object"},
        "Any": {},
    }
    return dict(mapping.get(type_name, {}))


def _decorator_is_tool(deco: ast.expr) -> tuple[bool, ast.Call | None]:
    """Does this decorator look like a tool registration?

    Returns ``(matched, call_or_none)``. The call is the ``ast.Call`` node
    that holds keyword args, if the decorator was called (``@x.tool(...)``).
    Bare attribute decorators (``@x.tool`` without parens) also count.
    """
    func = deco.func if isinstance(deco, ast.Call) else deco
    # Accept `mcp.tool` / `mcp.register_tool` / `mcp.add_tool`.
    if isinstance(func, ast.Attribute) and func.attr in _TOOL_DECORATOR_ATTRS:
        return True, deco if isinstance(deco, ast.Call) else None
    return False, None


def _docstring_first_line(node: ast.FunctionDef | ast.AsyncFunctionDef) -> str:
    doc = ast.get_docstring(node) or ""
    if not doc:
        return ""
    return doc.strip().splitlines()[0].strip()


def _collect_str_enums(tree: ast.Module) -> dict[str, dict[str, str]]:
    """Return ``{EnumName: {MemberName: "value"}}`` for every string-valued
    enum declared at module top-level.

    We accept any class whose base-list contains ``Enum`` or ``StrEnum``
    (with ``str`` in the base list as a sibling — the classic ``(str, Enum)``
    idiom — or alone). Members must be plain ``NAME = "literal"``
    assignments; anything more exotic is skipped.
    """
    out: dict[str, dict[str, str]] = {}
    for node in tree.body:
        if not isinstance(node, ast.ClassDef):
            continue
        base_names = {
            b.id if isinstance(b, ast.Name) else b.attr if isinstance(b, ast.Attribute) else None
            for b in node.bases
        }
        if not ({"Enum", "StrEnum", "IntEnum"} & base_names):
            continue
        members: dict[str, str] = {}
        for stmt in node.body:
            if isinstance(stmt, ast.Assign) and len(stmt.targets) == 1:
                target = stmt.targets[0]
                if isinstance(target, ast.Name):
                    val = _extract_string(stmt.value)
                    if val is not None:
                        members[target.id] = val
        if members:
            out[node.name] = members
    return out


class _DiscoveryVisitor(ast.NodeVisitor):
    """Walks a Python module looking for MCP entrypoints and tools.

    Results are collected in :attr:`entrypoints` and :attr:`tools`. The
    visitor is stateless across files; construct one per file.
    """

    def __init__(
        self, repo_relative_path: str, enum_map: dict[str, dict[str, str]] | None = None
    ) -> None:
        self.file = repo_relative_path
        self.entrypoints: list[Entrypoint] = []
        self.tools: list[ToolDefinition] = []
        self.enum_map = enum_map or {}

    def _resolve_string_like(self, node: ast.expr | None) -> str | None:
        """Resolve ``node`` to a string, following ``EnumClass.MEMBER`` lookups."""
        if node is None:
            return None
        s = _extract_string(node)
        if s is not None:
            return s
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            members = self.enum_map.get(node.value.id)
            if members and node.attr in members:
                return members[node.attr]
        return None

    def _resolve_kwarg_string(self, keywords: list[ast.keyword], name: str) -> str | None:
        for kw in keywords:
            if kw.arg == name:
                return self._resolve_string_like(kw.value)
        return None

    # -------- entrypoints --------

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        ctor_name: str | None = None
        if isinstance(func, ast.Name) and func.id in ENTRYPOINT_CONSTRUCTOR_NAMES:
            ctor_name = func.id
        elif isinstance(func, ast.Attribute) and func.attr in ENTRYPOINT_CONSTRUCTOR_NAMES:
            ctor_name = func.attr

        if ctor_name is not None:
            server_name: str | None = None
            if node.args:
                server_name = _extract_string(node.args[0])
            if server_name is None:
                server_name = _kwarg_string(node.keywords, "name") or _kwarg_string(
                    node.keywords, "server_name"
                )
            self.entrypoints.append(
                Entrypoint(
                    file=self.file,
                    line=node.lineno,
                    constructor=ctor_name,
                    server_name=server_name,
                )
            )

        # Detect Tool(name=..., description=..., inputSchema=...) literals.
        self._maybe_record_tool_literal(node)
        # Detect explicit server.register_tool / add_tool calls (with kwargs).
        self._maybe_record_registration_call(node)
        self.generic_visit(node)

    def _maybe_record_tool_literal(self, node: ast.Call) -> None:
        func = node.func
        class_name: str | None = None
        if isinstance(func, ast.Name) and func.id in _TOOL_CLASS_NAMES:
            class_name = func.id
        elif isinstance(func, ast.Attribute) and func.attr in _TOOL_CLASS_NAMES:
            class_name = func.attr
        if class_name is None:
            return
        name = self._resolve_kwarg_string(node.keywords, "name")
        if name is None and node.args:
            name = self._resolve_string_like(node.args[0])
        if name is None:
            return
        description = (
            self._resolve_kwarg_string(node.keywords, "description")
            or self._resolve_kwarg_string(node.keywords, "title")
            or ""
        )
        input_schema = _best_effort_dict(
            _find_kwarg(node.keywords, "inputSchema")
        ) or _best_effort_dict(_find_kwarg(node.keywords, "input_schema"))
        try:
            self.tools.append(
                ToolDefinition(
                    name=name,
                    description=description,
                    input_schema=input_schema,
                    source_file=self.file,
                    source_line=node.lineno,
                )
            )
        except ValueError:
            return

    def _maybe_record_registration_call(self, node: ast.Call) -> None:
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        if func.attr not in _TOOL_REGISTRATION_METHODS:
            return
        name = _kwarg_string(node.keywords, "name")
        if name is None and node.args:
            name = _extract_string(node.args[0])
        if name is None:
            return
        description = _kwarg_string(node.keywords, "description") or ""
        # input_schema kwarg may be a dict literal — best effort
        input_schema = _best_effort_dict(_find_kwarg(node.keywords, "input_schema"))
        self.tools.append(
            ToolDefinition(
                name=name,
                description=description,
                input_schema=input_schema,
                source_file=self.file,
                source_line=node.lineno,
            )
        )

    # -------- decorator-style tools --------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._maybe_record_decorated_tool(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._maybe_record_decorated_tool(node)
        self.generic_visit(node)

    def _maybe_record_decorated_tool(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for deco in node.decorator_list:
            matched, call = _decorator_is_tool(deco)
            if not matched:
                continue
            name: str | None = None
            description: str | None = None
            input_schema_node: ast.expr | None = None
            if call is not None:
                # First positional string literal, if any, is the tool name.
                if call.args:
                    name = _extract_string(call.args[0])
                name = name or _kwarg_string(call.keywords, "name")
                description = _kwarg_string(call.keywords, "description")
                input_schema_node = _find_kwarg(call.keywords, "input_schema")
            name = name or node.name
            description = (description or _docstring_first_line(node) or "").strip()
            input_schema = _best_effort_dict(input_schema_node) or _build_input_schema(node)
            try:
                self.tools.append(
                    ToolDefinition(
                        name=name,
                        description=description,
                        input_schema=input_schema,
                        source_file=self.file,
                        source_line=node.lineno,
                    )
                )
            except ValueError:
                # Invalid tool name per schema regex — skip silently; Phase
                # 2 is best-effort, we don't blow up the whole discovery.
                continue
            return  # don't double-record if multiple decorators match


def _find_kwarg(keywords: list[ast.keyword], name: str) -> ast.expr | None:
    for kw in keywords:
        if kw.arg == name:
            return kw.value
    return None


def _best_effort_dict(node: ast.expr | None) -> dict[str, object] | None:
    """Try to evaluate ``node`` as a literal dict; return None on anything
    non-trivial. We never exec user code."""
    if node is None:
        return None
    try:
        value = ast.literal_eval(node)
    except (ValueError, SyntaxError):
        return None
    if isinstance(value, dict):
        return value
    return None


def analyze_python_file(
    source_path: Path, repo_root: Path
) -> tuple[list[Entrypoint], list[ToolDefinition]]:
    """Return ``(entrypoints, tools)`` found in ``source_path``.

    Silent on parse errors: if the file won't ``ast.parse()`` we return
    empty lists rather than aborting the whole discovery.
    """
    try:
        src = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], []
    try:
        tree = ast.parse(src, filename=str(source_path))
    except SyntaxError:
        return [], []
    rel = source_path.relative_to(repo_root).as_posix()
    enum_map = _collect_str_enums(tree)
    visitor = _DiscoveryVisitor(rel, enum_map=enum_map)
    visitor.visit(tree)
    return visitor.entrypoints, visitor.tools


__all__ = ["analyze_python_file"]
