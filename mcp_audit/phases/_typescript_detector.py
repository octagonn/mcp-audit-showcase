"""TypeScript / JavaScript MCP tool detection for Phase 2.

Regex-based. We deliberately do *not* stand up a TypeScript compiler for
Phase 2 — that doubles the dependency weight for a marginal quality gain.
The regex rules here are tuned against the idioms used by the reference
servers in ``modelcontextprotocol/servers`` and a handful of community
servers; if a project uses an unusual registration pattern the discover
command will simply return fewer tools (a visible Phase 2 iteration #2
TODO).

Three tool-declaration idioms are covered:

1. **Method call with literal** — ``server.tool("name", "description", ...)``
   or ``server.registerTool("name", {...})``.
2. **Object literal in array / config** — ``tools: [{ name: "foo",
   description: "..." }]``.
3. **Setter config** — ``setRequestHandler(ListToolsRequestSchema, ...)``
   followed by a returned ``tools`` array. We currently catch only the
   object-literal form inside that body.
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Final

from mcp_audit.schemas import Entrypoint, ToolDefinition

from ._patterns import ENTRYPOINT_CALL_RE

# ---------------------------------------------------------------------------
# Regexes
# ---------------------------------------------------------------------------

#: Method-call style: server.tool("name", "description", ...) or
#: server.registerTool("name", { ... }). We match the ``.tool(`` /
#: ``.registerTool(`` / ``.addTool(`` variants.
_METHOD_CALL_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    \.\s*(?:tool|registerTool|addTool|setTool)\s*\(   # method name
    \s*(?P<name_q>['"`])(?P<name>[^'"`]+)(?P=name_q)  # first string arg — name
    (?:\s*,\s*(?P<desc_q>['"`])(?P<description>[^'"`]*)(?P=desc_q))? # optional desc
    """,
    re.VERBOSE,
)

#: Object-literal style: { name: "x", description: "y", ... }. Requires
#: both name and description at the top level of the object.
_OBJECT_LITERAL_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    \{\s*
    (?:[^{}]*?)                                          # prefix clutter
    name\s*:\s*(?P<name_q>['"`])(?P<name>[^'"`]+)(?P=name_q)\s*,
    (?:[^{}]*?)                                          # middle clutter
    description\s*:\s*(?P<desc_q>['"`])(?P<description>[^'"`]*)(?P=desc_q)
    """,
    re.VERBOSE | re.DOTALL,
)


def _line_of(pos: int, text: str) -> int:
    """Return the 1-indexed line number of character offset ``pos``."""
    return text.count("\n", 0, pos) + 1


def analyze_typescript_file(
    source_path: Path, repo_root: Path
) -> tuple[list[Entrypoint], list[ToolDefinition]]:
    """Return ``(entrypoints, tools)`` found in ``source_path``.

    Runs against both ``.ts``/``.tsx`` and ``.js``/``.mjs`` files.
    """
    try:
        src = source_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return [], []

    rel = source_path.relative_to(repo_root).as_posix()

    entrypoints: list[Entrypoint] = []
    for m in ENTRYPOINT_CALL_RE.finditer(src):
        ctor = m.group("ctor")
        raw_name = m.group("name")
        server_name = raw_name.strip("'\"") if raw_name else None
        entrypoints.append(
            Entrypoint(
                file=rel,
                line=_line_of(m.start(), src),
                constructor=ctor,
                server_name=server_name,
            )
        )

    tools: list[ToolDefinition] = []
    seen: set[tuple[str, int]] = set()

    for m in _METHOD_CALL_RE.finditer(src):
        name = m.group("name")
        description = m.group("description") or ""
        line = _line_of(m.start(), src)
        key = (name, line)
        if key in seen:
            continue
        seen.add(key)
        try:
            tools.append(
                ToolDefinition(
                    name=name,
                    description=description,
                    source_file=rel,
                    source_line=line,
                )
            )
        except ValueError:
            continue

    for m in _OBJECT_LITERAL_RE.finditer(src):
        name = m.group("name")
        description = m.group("description") or ""
        line = _line_of(m.start(), src)
        key = (name, line)
        if key in seen:
            continue
        # Skip if already captured (same name, different line is fine).
        if any(t.name == name and t.source_file == rel for t in tools):
            # Upgrade description if we now have one and didn't before.
            existing = next(t for t in tools if t.name == name and t.source_file == rel)
            if not existing.description and description:
                existing.description = description
            continue
        seen.add(key)
        try:
            tools.append(
                ToolDefinition(
                    name=name,
                    description=description,
                    source_file=rel,
                    source_line=line,
                )
            )
        except ValueError:
            continue

    return entrypoints, tools


__all__ = ["analyze_typescript_file"]
