"""Regex patterns and constant tables shared by the Phase 2 detectors.

Grouped here so the Python and TypeScript detectors can draw from the same
source of truth and so that patterns are easy to audit and update.
"""

from __future__ import annotations

import re
from typing import Final

from mcp_audit.schemas import AttackClass, Transport

# ---------------------------------------------------------------------------
# Entrypoints — matched as textual clues across both Python and TS sources.
# ---------------------------------------------------------------------------

#: Substring clues that mark a file as likely-containing an MCP server entrypoint.
ENTRYPOINT_CONSTRUCTOR_NAMES: Final[tuple[str, ...]] = (
    "FastMCP",
    "Server",
    "createServer",
    "McpServer",
)

#: Regex that captures any of the recognised constructor calls. Group 'ctor'
#: yields the constructor name, 'name' (optional) the first string literal
#: argument, which is typically the server display name.
ENTRYPOINT_CALL_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    \b(?P<ctor>FastMCP|McpServer|Server|createServer)   # constructor
    \s*\(                                                # opening paren
    \s*(?P<name>['"][^'"]+['"])?                         # optional name literal
    """,
    re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Transports
# ---------------------------------------------------------------------------

#: Map transport → list of source substrings that indicate its presence.
TRANSPORT_CLUES: Final[dict[Transport, tuple[str, ...]]] = {
    Transport.STDIO: (
        "StdioServerTransport",
        "stdio_server",
        "stdio.server",
        "stdio_transport",
        "run_stdio_async",
    ),
    Transport.HTTP: (
        "StreamableHTTPServerTransport",
        "HttpServerTransport",
        "streamable_http",
        "FastAPI",
        "express()",
        "Fastify(",
    ),
    Transport.SSE: (
        "SseServerTransport",
        "sse_server",
        "sse_transport",
        "EventSource",
    ),
    Transport.WEBSOCKET: (
        "WebSocketServerTransport",
        "websocket_server",
        "WebSocketServer",
    ),
}

# ---------------------------------------------------------------------------
# Risk heuristics
# ---------------------------------------------------------------------------

#: Tool names that are inherently high risk (execution / eval / shell).
DANGEROUS_TOOL_NAMES: Final[frozenset[str]] = frozenset(
    {
        "exec",
        "execute",
        "eval",
        "shell",
        "sh",
        "bash",
        "cmd",
        "system",
        "run",
        "run_command",
        "run_shell",
        "runshell",
        "spawn",
        "subprocess",
        "kernel_exec",
        "python_exec",
        "evaluate",
    }
)

#: Case-insensitive regex catching instruction-like phrasing in tool
#: descriptions. Matches are *signals*; Phase 3 / the human reviewer decide
#: whether they are real prompt injections.
#:
#: Two families of patterns are detected:
#:
#: 1. Direct override ("ignore previous", "system prompt", role-play framing).
#: 2. **Context rewriting** — language that claims prior model restrictions no
#:    longer apply. This is the canonical @modelcontextprotocol/fetch pattern
#:    ("originally you did not have internet access... this tool now grants
#:    you internet access"), which is benign-looking at the phrase level but
#:    exists specifically to overwrite the model's refusal behaviour. Regressed
#:    caught by ``test_patterns.py::test_fetch_mcp_injection_is_detected``.
INSTRUCTION_LIKE_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    (?:
        \byou\s+must\b
      | \byou\s+should\b
      | \bignore\s+(?:all\s+)?(?:previous|prior|above)\b
      | \bdisregard\s+(?:all\s+)?(?:previous|prior|above)\b
      | \bnow\s+act\s+as\b
      | \bpretend\s+to\s+be\b
      | \boverride\s+(?:the\s+)?system\s+prompt\b
      | \bsystem\s+prompt\b
      | \balways\s+respond\s+with\b
      | \bnever\s+(?:refuse|decline|reveal)\b
      | <\s*system\s*>
      | \[\s*system\s*\]
      # --- context-rewriting family (refusal override) ---
      | \boriginally\s+you\b
      | \byou\s+were\s+(?:told|advised|instructed|trained)\b
      | \bwere\s+advised\s+to\s+refuse\b
      | \bthis\s+tool\s+now\s+(?:grants|gives|provides|allows|enables)\b
      | \bnow\s+you\s+(?:can|may|are\s+(?:able|allowed))\b
    )
    """,
    re.IGNORECASE | re.VERBOSE,
)

#: Hidden / control Unicode characters that should never appear in a tool
#: description. Covers the zero-width + bidi / invisible block.
HIDDEN_UNICODE_RE: Final[re.Pattern[str]] = re.compile(
    r"[\u0000-\u0008\u000b\u000c\u000e-\u001f\u200b-\u200f\u202a-\u202e\u2066-\u2069\ufeff]"
)

# ---------------------------------------------------------------------------
# OAuth scope detection
# ---------------------------------------------------------------------------

#: Keyword → provider mapping used to assign a provider label to a scope
#: string. Ordered: first match wins.
OAUTH_PROVIDER_KEYWORDS: Final[tuple[tuple[str, str], ...]] = (
    ("github.com", "github"),
    ("gitlab.com", "gitlab"),
    ("googleapis.com/auth/gmail", "gmail"),
    ("googleapis.com", "google"),
    ("graph.microsoft.com", "microsoft"),
    ("login.microsoftonline.com", "microsoft"),
    ("slack.com", "slack"),
    ("atlassian.com", "atlassian"),
    ("jira", "jira"),
    ("notion", "notion"),
    ("linear.app", "linear"),
    ("gmail", "gmail"),
    ("drive.readonly", "google"),
    ("repo:", "github"),
    ("repo,", "github"),
    ("admin:", "github"),
    ("read:org", "github"),
    ("write:org", "github"),
)

#: Regex matching what looks like an OAuth scope literal. We match scopes in
#: two shapes: colon-delimited (e.g. 'repo:read') and slash-delimited URLs
#: (e.g. 'https://www.googleapis.com/auth/gmail.readonly').
OAUTH_SCOPE_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    (?P<scope>
        https?://[^\s'"]+/auth/[^\s'"]+
      | \b[a-z]+:[a-z_]+(?::[a-z_]+)?\b
    )
    """,
    re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Secret detection (basic — Phase 3 will add `trufflehog`/`detect-secrets`).
# ---------------------------------------------------------------------------

#: Very conservative secret-shape detector. False positives are accepted;
#: this is a *signal* for a reviewer.
POTENTIAL_SECRET_RE: Final[re.Pattern[str]] = re.compile(
    r"""
    (?:
        (?:AKIA|ASIA)[0-9A-Z]{16}                        # AWS access key
      | sk-(?:live|test)?-?[A-Za-z0-9]{20,}              # OpenAI / Stripe-ish
      | xox[baprs]-[A-Za-z0-9-]{10,}                     # Slack token
      | ghp_[A-Za-z0-9]{20,}                             # GitHub personal token
      | github_pat_[A-Za-z0-9_]{20,}                     # GitHub fine-grained
      | AIza[0-9A-Za-z_-]{35}                            # Google API
    )
    """,
    re.VERBOSE,
)

# ---------------------------------------------------------------------------
# Directory filters
# ---------------------------------------------------------------------------

#: Directory names we refuse to descend into during source scanning.
SKIP_DIRS: Final[frozenset[str]] = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "env",
        ".mypy_cache",
        ".ruff_cache",
        ".pytest_cache",
        "dist",
        "build",
        ".next",
        ".turbo",
        ".cache",
        "coverage",
        ".tox",
    }
)

# ---------------------------------------------------------------------------
# Attack class → concrete probe keyword mapping
# (Not used by Phase 2 directly, but co-locating keeps the taxonomy in one place.)
# ---------------------------------------------------------------------------

ATTACK_CLASS_KEYWORDS: Final[dict[AttackClass, tuple[str, ...]]] = {
    AttackClass.COMMAND_INJECTION: ("subprocess.run", "os.system", "shell=True", "child_process"),
    AttackClass.PATH_TRAVERSAL: ("..", "/..", "../"),
    AttackClass.SECRETS_EXFILTRATION: ("getenv", "process.env", "os.environ"),
}


__all__ = [
    "ATTACK_CLASS_KEYWORDS",
    "DANGEROUS_TOOL_NAMES",
    "ENTRYPOINT_CALL_RE",
    "ENTRYPOINT_CONSTRUCTOR_NAMES",
    "HIDDEN_UNICODE_RE",
    "INSTRUCTION_LIKE_RE",
    "OAUTH_PROVIDER_KEYWORDS",
    "OAUTH_SCOPE_RE",
    "POTENTIAL_SECRET_RE",
    "SKIP_DIRS",
    "TRANSPORT_CLUES",
]
