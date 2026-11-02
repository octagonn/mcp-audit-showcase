"""Pydantic v2 schemas shared across pipeline phases.

Every JSON artifact the pipeline produces between phases is modeled here so
phases can only exchange typed data (CLAUDE.md § Coding conventions: "All
pipeline I/O between phases goes through Pydantic models").

Currently covered:

- Phase 1 — :class:`Scope`
- Phase 2 — :class:`AuditTarget`, :class:`ToolDefinition`, and friends
- Phase 3 — :class:`StaticScanResult`, :class:`Finding`, :class:`Evidence`

Later phases (dynamic probing, triage, report) will extend further.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import PurePosixPath
from typing import Annotated, Any

from pydantic import (
    AnyHttpUrl,
    BaseModel,
    ConfigDict,
    Field,
    StringConstraints,
    field_validator,
)

# ---------------------------------------------------------------------------
# Primitive / alias types
# ---------------------------------------------------------------------------

#: A non-empty, stripped string.
NonEmptyStr = Annotated[str, StringConstraints(strip_whitespace=True, min_length=1)]

#: A semver-ish audit identifier. Not strictly semver — just ASCII-safe.
AuditId = Annotated[
    str,
    StringConstraints(
        strip_whitespace=True, min_length=1, max_length=120, pattern=r"^[A-Za-z0-9._-]+$"
    ),
]


def _utcnow() -> datetime:
    """Timezone-aware UTC ``now`` — used as default for timestamp fields."""
    return datetime.now(UTC)


class _StrictModel(BaseModel):
    """Base model: forbid unknown fields, populate by name, freeze on dump.

    We opt for ``extra='forbid'`` because every JSON artifact here is a
    contract between pipeline phases; silently dropping or ignoring fields
    hides bugs. If you genuinely need forward compatibility, version the
    schema explicitly.
    """

    model_config = ConfigDict(
        extra="forbid",
        str_strip_whitespace=True,
        validate_assignment=True,
        frozen=False,
    )


# ---------------------------------------------------------------------------
# Enumerations
# ---------------------------------------------------------------------------


class Language(StrEnum):
    """Detected source language of an MCP server.

    Only languages we can actually parse in Phase 2 are listed. ``UNKNOWN``
    is used when nothing matches and we fall back to regex-only analysis.
    """

    PYTHON = "python"
    TYPESCRIPT = "typescript"
    JAVASCRIPT = "javascript"
    UNKNOWN = "unknown"


class Transport(StrEnum):
    """MCP transport protocols recognised by the discovery phase."""

    STDIO = "stdio"
    HTTP = "http"
    SSE = "sse"
    WEBSOCKET = "websocket"


class AttackClass(StrEnum):
    """Attack classes recognised by the pipeline. Referenced from
    :attr:`Scope.allowed_attack_classes` and from later-phase findings.

    The list is intentionally small for now and will grow as Phase 4 lands.
    """

    PROMPT_INJECTION = "prompt_injection"
    TOOL_ABUSE = "tool_abuse"
    CONFUSED_DEPUTY = "confused_deputy"
    TOKEN_SCOPE = "token_scope"
    MEMORY_POISONING = "memory_poisoning"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    SECRETS_EXFILTRATION = "secrets_exfiltration"
    # Destructive — opt-in only. See Scope.allow_destructive.
    DOS = "dos"
    DATA_MODIFICATION = "data_modification"
    CREDENTIAL_BRUTE_FORCE = "credential_brute_force"


#: Attack classes that are always destructive. These require
#: ``Scope.allow_destructive=True`` before the probe runner will execute them.
DESTRUCTIVE_ATTACK_CLASSES: frozenset[AttackClass] = frozenset(
    {
        AttackClass.DOS,
        AttackClass.DATA_MODIFICATION,
        AttackClass.CREDENTIAL_BRUTE_FORCE,
    }
)


class RiskFlagKind(StrEnum):
    """Kinds of deterministic risk signals Phase 2 can raise.

    These are *signals*, not findings. They feed Phase 3 triage; nothing
    client-facing is produced from these alone.
    """

    #: Tool description contains instruction-like text that could be prompt injection.
    INSTRUCTION_LIKE_DESCRIPTION = "instruction_like_description"
    #: Tool name matches a high-risk verb (execute, shell, run, eval, exec, ...).
    DANGEROUS_TOOL_NAME = "dangerous_tool_name"
    #: Tool description contains non-printable / hidden Unicode characters.
    HIDDEN_UNICODE = "hidden_unicode"
    #: Repo has no LICENSE, no README, or only skeleton metadata — low signal of maintenance.
    LOW_MAINTENANCE_SIGNAL = "low_maintenance_signal"
    #: Hard-coded secrets / API keys spotted by regex.
    POTENTIAL_SECRET = "potential_secret"


# ---------------------------------------------------------------------------
# Supporting models
# ---------------------------------------------------------------------------


class ClientMetadata(_StrictModel):
    """Metadata about the client commissioning the audit.

    Populated during Phase 1 (intake) and carried through to the final
    report.
    """

    name: NonEmptyStr = Field(description="Client organisation or individual name.")
    contact_email: NonEmptyStr = Field(description="Primary contact email for this engagement.")
    engagement_id: NonEmptyStr | None = Field(
        default=None,
        description="Optional client-side engagement/PO identifier, if provided.",
    )


class OAuthScope(_StrictModel):
    """A single OAuth scope requested by the server."""

    provider: NonEmptyStr = Field(
        description="OAuth provider identifier (e.g. 'github', 'google', 'slack').",
    )
    scope: NonEmptyStr = Field(
        description="Raw scope string as requested (e.g. 'repo:read', 'https://www.googleapis.com/auth/gmail.readonly').",
    )


class Dependency(_StrictModel):
    """A third-party package dependency declared by the target repo.

    Phase 2 only records what the manifest says; Phase 3 will enrich with
    CVE data via deterministic lookup.
    """

    name: NonEmptyStr
    version_spec: NonEmptyStr | None = Field(
        default=None,
        description="Raw version constraint string from the manifest (e.g. '>=1.2,<2.0'). None if unpinned.",
    )
    source: NonEmptyStr = Field(
        description="Manifest that declared the dep (e.g. 'pyproject.toml', 'package.json', 'requirements.txt').",
    )


class Entrypoint(_StrictModel):
    """A detected MCP server entrypoint.

    A repo may have more than one (e.g. the official ``servers`` monorepo
    exposes dozens); Phase 2 records all of them.
    """

    file: NonEmptyStr = Field(
        description="Repo-relative POSIX path to the file declaring the entrypoint.",
    )
    line: int = Field(
        ge=1,
        description="1-indexed line number where the entrypoint was matched.",
    )
    constructor: NonEmptyStr = Field(
        description="Constructor function/class matched (e.g. 'FastMCP', 'Server', 'createServer').",
    )
    server_name: NonEmptyStr | None = Field(
        default=None,
        description="Server display name if the constructor call revealed it, else None.",
    )

    @field_validator("file")
    @classmethod
    def _normalise_path(cls, v: str) -> str:
        """Force POSIX-style paths in the artifact so output is OS-independent."""
        return str(PurePosixPath(v.replace("\\", "/")))


class RiskFlag(_StrictModel):
    """A deterministic risk signal raised by Phase 2.

    ``RiskFlag`` is intentionally separate from the richer ``StaticFinding``
    /``ConfirmedFinding`` types that later phases will define: Phase 2's job
    is to surface *signals*, not to triage them.
    """

    kind: RiskFlagKind
    subject: NonEmptyStr = Field(
        description="Human-readable identifier of what this flag is about (e.g. a tool name or file path).",
    )
    evidence: NonEmptyStr = Field(
        description="The actual string or snippet that triggered the flag.",
    )
    location: NonEmptyStr | None = Field(
        default=None,
        description="Repo-relative file:line of the evidence, when known.",
    )


class ToolDefinition(_StrictModel):
    """A single MCP tool exposed by the server."""

    name: NonEmptyStr = Field(description="Tool name as it appears in the MCP protocol.")
    description: str = Field(
        default="",
        description="Human-readable description as declared by the server. Empty string if absent.",
    )
    input_schema: dict[str, Any] | None = Field(
        default=None,
        description="JSON Schema for the tool's input, as parsed from the source. None if not found.",
    )
    output_schema: dict[str, Any] | None = Field(
        default=None,
        description="JSON Schema for the tool's output, when declared. Often None — MCP does not require it.",
    )
    source_file: NonEmptyStr | None = Field(
        default=None,
        description="Repo-relative POSIX path to the file declaring this tool.",
    )
    source_line: int | None = Field(
        default=None,
        ge=1,
        description="1-indexed line where the tool is declared.",
    )
    risk_flags: list[RiskFlag] = Field(
        default_factory=list,
        description="Deterministic risk signals raised for this tool during Phase 2.",
    )

    @field_validator("name")
    @classmethod
    def _validate_tool_name(cls, v: str) -> str:
        """MCP tool names must be simple identifiers. We accept the permissive
        set commonly seen in the wild (letters, digits, underscore, dash)."""
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_.-]*", v):
            raise ValueError(
                f"tool name {v!r} is not a valid MCP identifier (letters/digits/_/-/. only)"
            )
        return v

    @field_validator("source_file")
    @classmethod
    def _normalise_source_file(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return str(PurePosixPath(v.replace("\\", "/")))


# ---------------------------------------------------------------------------
# Phase 1 artifact: Scope
# ---------------------------------------------------------------------------


class Scope(_StrictModel):
    """Phase 1 artifact — the audit scope, as declared in ``scope.yaml``.

    The probe runner (Phase 4) refuses to execute any attack class not in
    :attr:`allowed_attack_classes`. Destructive classes additionally
    require :attr:`allow_destructive` to be ``True``.
    """

    audit_id: AuditId = Field(
        description="Stable identifier for this audit (used as the working directory name).",
    )
    target: NonEmptyStr = Field(
        description="Target reference: either a git URL or an absolute/relative local path.",
    )
    client: ClientMetadata
    allowed_attack_classes: list[AttackClass] = Field(
        default_factory=list,
        description="Attack classes the probe runner is permitted to execute.",
    )
    out_of_scope_paths: list[NonEmptyStr] = Field(
        default_factory=list,
        description="Glob or path patterns (POSIX) that must not be touched, even if in-scope attack classes would otherwise cover them.",
    )
    allow_destructive: bool = Field(
        default=False,
        description="If False (default), destructive attack classes (DOS, data-modification, credential brute-force) are rejected even if listed in allowed_attack_classes.",
    )
    notes: str = Field(
        default="",
        description="Free-form notes from the engagement letter.",
    )
    created_at: datetime = Field(default_factory=_utcnow)

    @field_validator("allowed_attack_classes")
    @classmethod
    def _dedupe_allowed(cls, v: list[AttackClass]) -> list[AttackClass]:
        # Preserve declaration order but drop duplicates.
        seen: set[AttackClass] = set()
        out: list[AttackClass] = []
        for item in v:
            if item not in seen:
                seen.add(item)
                out.append(item)
        return out

    def attack_class_is_permitted(self, ac: AttackClass) -> bool:
        """Return ``True`` iff ``ac`` may be executed under this scope.

        Destructive classes require both whitelist membership *and*
        :attr:`allow_destructive` — this mirrors the security rule in
        ``CLAUDE.md`` § "No destructive attacks by default".
        """
        if ac not in self.allowed_attack_classes:
            return False
        return not (ac in DESTRUCTIVE_ATTACK_CLASSES and not self.allow_destructive)


# ---------------------------------------------------------------------------
# Phase 2 artifact: AuditTarget
# ---------------------------------------------------------------------------


class AuditTarget(_StrictModel):
    """Phase 2 artifact — machine-readable inventory of the MCP server.

    This is the contract between Phase 2 (discovery) and Phase 3 (static
    analysis). Every field here must be producible deterministically; no
    LLM calls are permitted in Phase 2.
    """

    schema_version: int = Field(
        default=1,
        description="Monotonically increasing integer; bump on breaking changes.",
    )
    audit_id: AuditId
    source_url: AnyHttpUrl | None = Field(
        default=None,
        description="Git URL if the target was a remote; None if a local path was supplied.",
    )
    source_path: NonEmptyStr | None = Field(
        default=None,
        description="Absolute local path the target was cloned to (tmp dir) or supplied from.",
    )
    commit_sha: NonEmptyStr | None = Field(
        default=None,
        description="Git commit SHA of the analysed tree, when known.",
    )
    language: Language
    entrypoints: list[Entrypoint] = Field(default_factory=list)
    tools: list[ToolDefinition] = Field(default_factory=list)
    transports: list[Transport] = Field(default_factory=list)
    oauth_scopes: list[OAuthScope] = Field(default_factory=list)
    dependencies: list[Dependency] = Field(default_factory=list)
    risk_flags: list[RiskFlag] = Field(
        default_factory=list,
        description="Repo-level risk flags (not tied to a single tool).",
    )
    discovered_at: datetime = Field(default_factory=_utcnow)

    @field_validator("transports")
    @classmethod
    def _dedupe_transports(cls, v: list[Transport]) -> list[Transport]:
        seen: set[Transport] = set()
        out: list[Transport] = []
        for t in v:
            if t not in seen:
                seen.add(t)
                out.append(t)
        return out

    @field_validator("source_path")
    @classmethod
    def _source_path_not_empty(cls, v: str | None) -> str | None:
        if v is None:
            return None
        return v

    def tool_by_name(self, name: str) -> ToolDefinition | None:
        """Return the tool with the given name, or ``None`` if not present."""
        for t in self.tools:
            if t.name == name:
                return t
        return None


# ---------------------------------------------------------------------------
# Phase 3 artifact: StaticScanResult
# ---------------------------------------------------------------------------


class Severity(StrEnum):
    """Finding severity. Scanners may output their own strings; we normalise.

    Aligned with CVSS-style buckets so Phase 6 (exploit validation) can
    score without translation. Treat the numeric order (INFO < LOW < ...)
    as stable — downstream code compares severities.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


#: Lexical ordering helper — ``SEVERITY_ORDER[s]`` is monotone.
SEVERITY_ORDER: dict[Severity, int] = {
    Severity.INFO: 0,
    Severity.LOW: 1,
    Severity.MEDIUM: 2,
    Severity.HIGH: 3,
    Severity.CRITICAL: 4,
}


class FindingConfidence(StrEnum):
    """How confident the producing tool is that this is a real issue.

    Separate from :class:`Severity`: a HIGH-severity finding can still be
    LOW-confidence (e.g. a Semgrep pattern that matches often but has
    historical false-positive rate). Phase 5 triage uses both.
    """

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class FindingSource(StrEnum):
    """Where a finding came from.

    Only the sources Phase 3 iteration #1 actually consumes are listed.
    Adding a source requires updating the OWASP mapping and the scanner
    runner set — keep it honest.
    """

    SEMGREP = "semgrep"
    BANDIT = "bandit"
    #: Carried over from Phase 2 risk flags so every candidate lives in one list.
    DISCOVERY = "discovery"
    #: Hand-authored by the auditor — docs review, threat model, or any
    #: closed-source / remote target where automated scanners can't reach.
    #: These findings flow through the same triage/validate/report gates
    #: as automated ones; the report just notes the source honestly.
    MANUAL_REVIEW = "manual_review"


class OwaspMcpCategory(StrEnum):
    """Working OWASP-MCP-Top-10 mapping used by Phase 3.

    OWASP does not yet publish an official MCP Top 10; this set is derived
    from the OWASP LLM Top 10 (2025) with MCP-specific categories folded
    in. Treat as versioned: bump :attr:`StaticScanResult.schema_version`
    when this list changes meaningfully.
    """

    PROMPT_INJECTION = "prompt_injection"
    TOOL_POISONING = "tool_poisoning"
    EXCESSIVE_AGENCY = "excessive_agency"
    COMMAND_INJECTION = "command_injection"
    PATH_TRAVERSAL = "path_traversal"
    INSECURE_DESERIALIZATION = "insecure_deserialization"
    SECRETS_LEAKAGE = "secrets_leakage"
    INSECURE_AUTH = "insecure_auth"
    INSECURE_TRANSPORT = "insecure_transport"
    VULNERABLE_DEPENDENCY = "vulnerable_dependency"
    CONFUSED_DEPUTY = "confused_deputy"
    #: Catch-all for findings the mapping table does not recognise.
    OTHER = "other"


class Evidence(_StrictModel):
    """Concrete, line-level evidence for a finding.

    ``file`` is repo-relative POSIX; ``line`` is 1-indexed. ``snippet`` is
    short (≤ 400 chars) — full code context belongs in the report, not
    every finding record.
    """

    file: NonEmptyStr = Field(description="Repo-relative POSIX path.")
    line: int = Field(ge=1)
    end_line: int | None = Field(default=None, ge=1)
    snippet: str = Field(
        default="",
        max_length=400,
        description="Short code excerpt (truncated to 400 chars).",
    )

    @field_validator("file")
    @classmethod
    def _normalise_file(cls, v: str) -> str:
        return str(PurePosixPath(v.replace("\\", "/")))


class Finding(_StrictModel):
    """A single static-analysis candidate.

    Phase 3 produces these; Phase 5 triages them into
    ``ConfirmedFinding``. No LLM narrative here — only scanner output
    plus deterministic mapping.
    """

    id: NonEmptyStr = Field(
        description="Deterministic dedupe key: '{source}:{rule_id}:{file}:{line}'.",
    )
    source: FindingSource
    rule_id: NonEmptyStr = Field(
        description="Rule identifier from the producing tool (e.g. 'B602', 'python.lang.security.dangerous-subprocess-use').",
    )
    title: NonEmptyStr = Field(description="Short human-readable summary.")
    message: str = Field(default="", description="Scanner's raw message, verbatim.")
    severity: Severity
    confidence: FindingConfidence
    owasp_category: OwaspMcpCategory
    evidence: Evidence
    cwe: NonEmptyStr | None = Field(
        default=None,
        description="CWE identifier if the source tool reported one (e.g. 'CWE-78').",
    )
    raw: dict[str, Any] | None = Field(
        default=None,
        description="Untouched scanner output for this finding — preserved for audit trail.",
    )
    cluster_id: NonEmptyStr | None = Field(
        default=None,
        description="Deterministic cluster key grouping likely-duplicate findings (same file, close line, same OWASP category).",
    )
    triage_rationale: str = Field(
        default="",
        max_length=800,
        description="One-sentence Haiku-generated rationale attached during Phase 3 iter #2 triage. Empty when triage is disabled.",
    )
    discovered_at: datetime = Field(default_factory=_utcnow)


class StaticScanResult(_StrictModel):
    """Phase 3 artifact — aggregated static-scan findings for one audit."""

    schema_version: int = Field(default=2)
    audit_id: AuditId
    target_source_path: NonEmptyStr = Field(
        description="Absolute path to the scanned tree (carried from AuditTarget.source_path).",
    )
    findings: list[Finding] = Field(default_factory=list)
    tools_run: list[NonEmptyStr] = Field(
        default_factory=list,
        description="Names of scanners that actually executed in this run.",
    )
    tools_missing: list[NonEmptyStr] = Field(
        default_factory=list,
        description="Scanners that were skipped because the binary / module wasn't available.",
    )
    tools_skipped: list[NonEmptyStr] = Field(
        default_factory=list,
        description=(
            "Scanners that are installed but did not apply to this target "
            "(e.g. Bandit on a TypeScript-only repo). Distinct from "
            "``tools_missing`` so operators don't chase install errors for "
            "tools that simply didn't apply."
        ),
    )
    scanned_at: datetime = Field(default_factory=_utcnow)

    def findings_by_severity(self, sev: Severity) -> list[Finding]:
        return [f for f in self.findings if f.severity == sev]

    def counts_by_severity(self) -> dict[Severity, int]:
        out: dict[Severity, int] = dict.fromkeys(Severity, 0)
        for f in self.findings:
            out[f.severity] += 1
        return out


# ---------------------------------------------------------------------------
# Phase 4 artifact: DynamicScanResult
# ---------------------------------------------------------------------------


class AttackOutcome(StrEnum):
    """How an :class:`AttackScenario` resolved at runtime.

    - ``triggered`` — the ``expected_signal`` regex matched the server's
      response. Produces a :class:`DynamicFinding`.
    - ``clean`` — the scenario ran and the signal did not match. Safe.
    - ``skipped_scope`` — scope.yaml forbade the attack class.
    - ``skipped_no_tool`` — the target has no tool matching the scenario's
      ``target_tool_hints`` — we refuse to invent a target.
    - ``error`` — the harness or the target errored out. Captured for
      operator review; never treated as a finding.
    """

    TRIGGERED = "triggered"
    CLEAN = "clean"
    SKIPPED_SCOPE = "skipped_scope"
    SKIPPED_NO_TOOL = "skipped_no_tool"
    ERROR = "error"


class AttackScenario(_StrictModel):
    """A single adversarial test case loaded from the ``scenarios/`` library.

    Scenario files live as YAML under the repo's ``scenarios/`` directory.
    Each file produces one :class:`AttackScenario`; the orchestrator runs
    only those whose ``attack_class`` is present in
    :attr:`Scope.allowed_attack_classes`.
    """

    id: NonEmptyStr = Field(
        description="Scenario id — must be unique across the library (e.g. 'pi-001', 'ci-003').",
        pattern=r"^[a-z]{2,4}-\d{3}$",
    )
    attack_class: AttackClass
    title: NonEmptyStr = Field(max_length=200)
    description: str = Field(default="", max_length=2000)
    target_tool_hints: list[NonEmptyStr] = Field(
        default_factory=list,
        description=(
            "Substrings matched (case-insensitive) against tool names on the target server. "
            "Empty list means the scenario is not tool-specific and runs against the "
            "first available tool."
        ),
    )
    tool_input_argument: NonEmptyStr | None = Field(
        default=None,
        description=(
            "Name of the tool input argument to inject the payload into. When None, "
            "the harness picks the first string-typed argument in the tool's input schema."
        ),
    )
    payload: NonEmptyStr = Field(
        max_length=8000,
        description="The adversarial string sent as the tool argument value.",
    )
    expected_signal: NonEmptyStr = Field(
        max_length=500,
        description=(
            "Python-regex string. If this matches the response's text content "
            "(case-insensitive, DOTALL), the attack is recorded as TRIGGERED."
        ),
    )
    owasp_category: OwaspMcpCategory
    severity_if_triggered: Severity = Severity.HIGH
    references: list[NonEmptyStr] = Field(
        default_factory=list,
        description="Optional URLs or CVE/CWE references backing the scenario.",
    )


class AttackExecution(_StrictModel):
    """Runtime record of one scenario invocation against one target tool.

    This is *the* audit trail for a dynamic probe. Every request/response
    pair is also written line-by-line to a JSONL session log on disk; this
    model is the summary row.
    """

    scenario_id: NonEmptyStr
    tool_name: NonEmptyStr | None = Field(
        default=None,
        description="Tool the scenario was invoked against. None when skipped pre-invocation.",
    )
    outcome: AttackOutcome
    session_log: NonEmptyStr | None = Field(
        default=None,
        description="Repo-relative POSIX path to the JSONL transcript for this execution.",
    )
    error: str = Field(
        default="",
        max_length=2000,
        description="Error message when outcome is ERROR. Empty otherwise.",
    )
    latency_ms: int | None = Field(default=None, ge=0)
    response_excerpt: str = Field(
        default="",
        max_length=1000,
        description="Tool response text, clipped. Populated on TRIGGERED and CLEAN outcomes.",
    )
    executed_at: datetime = Field(default_factory=_utcnow)


class DynamicFinding(_StrictModel):
    """A confirmed adversarial behaviour observed on the running target.

    Deliberately shaped similarly to :class:`Finding` so Phase 5 triage,
    Phase 6 validation and Phase 7 reports can treat static and dynamic
    findings uniformly where sensible.
    """

    id: NonEmptyStr = Field(
        description="Deterministic id: 'dynamic:{scenario_id}:{tool_name}'.",
    )
    scenario_id: NonEmptyStr
    tool_name: NonEmptyStr
    attack_class: AttackClass
    owasp_category: OwaspMcpCategory
    severity: Severity
    title: NonEmptyStr = Field(max_length=200)
    evidence: Evidence
    expected_signal: NonEmptyStr
    matched_signal: str = Field(
        default="",
        max_length=500,
        description="The substring of the response that matched expected_signal.",
    )
    execution: AttackExecution
    discovered_at: datetime = Field(default_factory=_utcnow)


class DynamicScanResult(_StrictModel):
    """Phase 4 artifact — aggregated dynamic-probe output for one audit."""

    schema_version: int = Field(default=1)
    audit_id: AuditId
    target_source_path: NonEmptyStr = Field(
        description="Absolute path to the probed target tree (carried from AuditTarget).",
    )
    findings: list[DynamicFinding] = Field(default_factory=list)
    executions: list[AttackExecution] = Field(
        default_factory=list,
        description="Every scenario invocation, including CLEAN and SKIPPED_* outcomes.",
    )
    scope_digest: str = Field(
        default="",
        max_length=200,
        description="Short textual summary of the Scope gate applied (attack classes etc.).",
    )
    scanned_at: datetime = Field(default_factory=_utcnow)

    def counts_by_outcome(self) -> dict[AttackOutcome, int]:
        counts: dict[AttackOutcome, int] = dict.fromkeys(AttackOutcome, 0)
        for ex in self.executions:
            counts[ex.outcome] += 1
        return counts


# ---------------------------------------------------------------------------
# Phase 5 artifact: TriageReview
# ---------------------------------------------------------------------------


class ReviewDecision(StrEnum):
    """Outcome of a human triage decision for one finding.

    - ``approved`` — the finding is real; carry it to Phase 6.
    - ``rejected`` — a false positive; drop from the report.
    - ``edited`` — reviewer approved with edits (severity, title, etc).
    - ``needs_more_info`` — bounced back to the operator pending clarification.
    """

    APPROVED = "approved"
    REJECTED = "rejected"
    EDITED = "edited"
    NEEDS_MORE_INFO = "needs_more_info"


class FindingOrigin(StrEnum):
    """Which upstream artifact a :class:`ReviewedFinding` came from."""

    STATIC = "static"
    DYNAMIC = "dynamic"


class ReviewedFinding(_StrictModel):
    """One human-triaged finding.

    Captures the original finding (by id, so the provenance is cheap to
    look up) plus the reviewer's decision and any edits applied. Edits
    are narrow on purpose — a reviewer can rewrite the title/summary and
    change severity, but the evidence location and rule id are immutable
    (that's the whole point of the audit trail).
    """

    finding_id: NonEmptyStr
    origin: FindingOrigin
    decision: ReviewDecision
    edited_severity: Severity | None = Field(
        default=None,
        description="If the reviewer overrode severity, the new value. None means 'keep original'.",
    )
    edited_title: str = Field(
        default="",
        max_length=200,
        description="Reviewer-supplied title override. Empty means 'keep original'.",
    )
    reviewer_notes: str = Field(
        default="",
        max_length=2000,
        description="Free-form reviewer commentary carried into the final report narrative.",
    )
    reviewer: NonEmptyStr = Field(description="Human reviewer's name or handle.")
    reviewed_at: datetime = Field(default_factory=_utcnow)


class TriageReview(_StrictModel):
    """Phase 5 artifact — the complete human review over one audit."""

    schema_version: int = Field(default=1)
    audit_id: AuditId
    reviewer: NonEmptyStr
    reviews: list[ReviewedFinding] = Field(default_factory=list)
    started_at: datetime = Field(default_factory=_utcnow)
    completed_at: datetime | None = Field(
        default=None,
        description="Set when the reviewer flips the 'done' switch in the UI.",
    )

    def approved_ids(self) -> list[str]:
        """Ids of findings that should carry forward (approved + edited)."""
        return [
            r.finding_id
            for r in self.reviews
            if r.decision in (ReviewDecision.APPROVED, ReviewDecision.EDITED)
        ]

    def decision_for(self, finding_id: str) -> ReviewedFinding | None:
        for r in self.reviews:
            if r.finding_id == finding_id:
                return r
        return None

    def counts_by_decision(self) -> dict[ReviewDecision, int]:
        out: dict[ReviewDecision, int] = dict.fromkeys(ReviewDecision, 0)
        for r in self.reviews:
            out[r.decision] += 1
        return out


# ---------------------------------------------------------------------------
# Phase 6 artifact: ValidationReport
# ---------------------------------------------------------------------------


class ValidationStatus(StrEnum):
    """Outcome of re-validating one approved finding.

    - ``reproduced`` — the exploit path still fires (dynamic replay matched
      the same signal, or the static scanner still flagged the same
      rule+location).
    - ``not_reproduced`` — the path did not fire on re-run. Severity is
      auto-demoted to MEDIUM when the original was HIGH+ (see
      :meth:`ValidationResult.demote_if_unreproduced`).
    - ``validation_error`` — the harness or the scanner errored out. The
      operator must decide what to do; severity is preserved so we never
      silently bury a real issue on infra flakes.
    - ``skipped`` — validation wasn't attempted (e.g. static rescan
      disabled, scope forbade the attack class, or the manifest said so).
    """

    REPRODUCED = "reproduced"
    NOT_REPRODUCED = "not_reproduced"
    VALIDATION_ERROR = "validation_error"
    SKIPPED = "skipped"


class ValidationMethod(StrEnum):
    """How a :class:`ValidationResult` was obtained."""

    DYNAMIC_REPLAY = "dynamic_replay"
    STATIC_RESCAN = "static_rescan"
    MANUAL_MANIFEST = "manual_manifest"
    NONE = "none"


class ValidationResult(_StrictModel):
    """Per-finding validation outcome for Phase 6.

    ``effective_severity`` is what the Phase 7 report should show — same
    as ``original_severity`` unless we auto-demoted a failed reproduction.
    ``evidence_path`` points at the per-finding PoC folder on disk so the
    reviewer (and the final report) can cite it.
    """

    finding_id: NonEmptyStr
    origin: FindingOrigin
    status: ValidationStatus
    method: ValidationMethod
    original_severity: Severity
    effective_severity: Severity
    evidence_path: NonEmptyStr | None = Field(
        default=None,
        description="Repo-relative POSIX path to the per-finding PoC directory.",
    )
    notes: str = Field(
        default="",
        max_length=2000,
        description="Human-readable validation log — signal that matched, error text, etc.",
    )
    validated_at: datetime = Field(default_factory=_utcnow)


class ValidationReport(_StrictModel):
    """Phase 6 artifact — the complete validation pass for one audit."""

    schema_version: int = Field(default=1)
    audit_id: AuditId
    results: list[ValidationResult] = Field(default_factory=list)
    validated_at: datetime = Field(default_factory=_utcnow)

    def reproduced_ids(self) -> list[str]:
        return [r.finding_id for r in self.results if r.status == ValidationStatus.REPRODUCED]

    def counts_by_status(self) -> dict[ValidationStatus, int]:
        out: dict[ValidationStatus, int] = dict.fromkeys(ValidationStatus, 0)
        for r in self.results:
            out[r.status] += 1
        return out

    def result_for(self, finding_id: str) -> ValidationResult | None:
        for r in self.results:
            if r.finding_id == finding_id:
                return r
        return None


# ---------------------------------------------------------------------------
# Phase 7 artifact: ReportBundle
# ---------------------------------------------------------------------------


class ReportFinding(_StrictModel):
    """Single finding, flattened and enriched for report rendering.

    Collapses Phase 3/4 origin-specific shapes into one uniform row so
    the Jinja template doesn't have to branch on origin for common
    fields. Narratives come either from the LLM (Sonnet, optional) or
    from deterministic placeholders — in either case they are plain
    prose, never containing TODO-style markers.
    """

    finding_id: NonEmptyStr
    origin: FindingOrigin
    severity: Severity = Field(description="Effective severity after validation demotion.")
    original_severity: Severity = Field(
        description="Severity the reviewer approved; equal to severity unless validation demoted it.",
    )
    title: NonEmptyStr = Field(max_length=200)
    owasp_category: OwaspMcpCategory
    location: NonEmptyStr = Field(
        description="Human-readable location: 'file:line' for static, 'tool (scenario)' for dynamic.",
    )
    snippet: str = Field(
        default="",
        max_length=800,
        description="Code excerpt (static) or matched-signal snippet (dynamic). Clipped.",
    )
    message: str = Field(
        default="",
        max_length=4000,
        description=(
            "Analyst-authored 'why this matters + recommendation' prose, carried "
            "forward from the underlying Finding/DynamicFinding. The report "
            "narrator uses this as the primary source for Impact/Remediation — "
            "dropping it produces generic boilerplate."
        ),
    )
    rule_id: NonEmptyStr | None = Field(
        default=None,
        description="Scanner rule id (static findings only).",
    )
    scenario_id: NonEmptyStr | None = Field(
        default=None,
        description="Dynamic scenario id (dynamic findings only).",
    )
    validation_status: ValidationStatus
    validation_method: ValidationMethod
    validation_notes: str = Field(default="", max_length=2000)
    evidence_path: NonEmptyStr | None = Field(
        default=None,
        description="Repo-relative POSIX path to the PoC folder for this finding.",
    )
    reviewer_notes: str = Field(default="", max_length=2000)
    cwe: NonEmptyStr | None = Field(default=None)
    impact_narrative: str = Field(
        default="",
        max_length=4000,
        description="Per-finding impact prose. Deterministic fallback when LLM is off.",
    )
    remediation_narrative: str = Field(
        default="",
        max_length=4000,
        description="Per-finding remediation prose. Deterministic fallback when LLM is off.",
    )


class ReportBundle(_StrictModel):
    """Phase 7 artifact — the complete, renderable audit report payload.

    Serialisable to JSON so the report renderer is a pure function over
    this bundle: Phase 7 can be re-rendered offline without replaying
    the pipeline, and the JSON doubles as an audit trail of exactly
    what was communicated to the client.
    """

    schema_version: int = Field(default=1)
    audit_id: AuditId
    client_name: NonEmptyStr
    target: NonEmptyStr
    commit_sha: str = Field(default="", max_length=80)
    generated_at: datetime = Field(default_factory=_utcnow)
    findings: list[ReportFinding] = Field(default_factory=list)
    severity_counts: dict[Severity, int] = Field(default_factory=dict)
    status_counts: dict[ValidationStatus, int] = Field(default_factory=dict)
    executive_summary: str = Field(default="", max_length=8000)
    methodology_notes: str = Field(default="", max_length=4000)
    tools_run: list[NonEmptyStr] = Field(default_factory=list)
    tools_missing: list[NonEmptyStr] = Field(default_factory=list)
    entrypoint_count: int = Field(default=0, ge=0)
    tool_count: int = Field(default=0, ge=0)
    transports: list[NonEmptyStr] = Field(default_factory=list)
    scope_attack_classes: list[NonEmptyStr] = Field(default_factory=list)
    scope_out_of_scope: list[NonEmptyStr] = Field(default_factory=list)
    scope_allow_destructive: bool = Field(default=False)
    scope_checksum: str = Field(
        default="",
        max_length=80,
        description="SHA-256 of scope.yaml bytes at report-build time; mirrored in Appendix B.",
    )

    def highest_severity(self) -> Severity | None:
        if not self.findings:
            return None
        return max((f.severity for f in self.findings), key=lambda s: SEVERITY_ORDER[s])


class RetestEntry(_StrictModel):
    """One row of the Phase 9 retest diff.

    Carries just enough about a finding to render the 1-page retest report;
    the full audit payload still lives in ``static_findings.json``.
    """

    finding_id: NonEmptyStr
    title: NonEmptyStr
    severity: Severity
    owasp_category: OwaspMcpCategory
    location: NonEmptyStr


class RetestReport(_StrictModel):
    """Phase 9 artifact — diff of a fresh static scan vs the original audit.

    Status categories (see ``docs/COMPLETION_PLAN.md`` WP-7):

    * ``closed`` — finding present in the original audit but absent from the
      new scan; the fix landed.
    * ``still_open`` — finding present in both; remediation has not shipped.
    * ``new`` — finding that appeared only in the new scan; a regression or a
      fresh regression introduced while fixing other findings.
    """

    schema_version: int = Field(default=1)
    audit_id: AuditId
    original_commit_sha: str = Field(default="", max_length=80)
    new_commit_sha: str = Field(default="", max_length=80)
    new_source_path: NonEmptyStr = Field(
        description="Absolute path to the tree scanned for the retest.",
    )
    generated_at: datetime = Field(default_factory=_utcnow)
    closed: list[RetestEntry] = Field(default_factory=list)
    still_open: list[RetestEntry] = Field(default_factory=list)
    new: list[RetestEntry] = Field(default_factory=list)

    def total(self) -> int:
        return len(self.closed) + len(self.still_open) + len(self.new)


class DeliveryManifest(_StrictModel):
    """Phase 9 artifact — inventory of what was packaged for a client handoff."""

    schema_version: int = Field(default=1)
    audit_id: AuditId
    client_name: NonEmptyStr
    generated_at: datetime = Field(default_factory=_utcnow)
    archive_path: NonEmptyStr
    files: list[NonEmptyStr] = Field(default_factory=list)
    remediation_pr_path: NonEmptyStr


__all__ = [
    "DESTRUCTIVE_ATTACK_CLASSES",
    "SEVERITY_ORDER",
    "AttackClass",
    "AttackExecution",
    "AttackOutcome",
    "AttackScenario",
    "AuditId",
    "AuditTarget",
    "ClientMetadata",
    "DeliveryManifest",
    "Dependency",
    "DynamicFinding",
    "DynamicScanResult",
    "Entrypoint",
    "Evidence",
    "Finding",
    "FindingConfidence",
    "FindingOrigin",
    "FindingSource",
    "Language",
    "NonEmptyStr",
    "OAuthScope",
    "OwaspMcpCategory",
    "ReportBundle",
    "ReportFinding",
    "RetestEntry",
    "RetestReport",
    "ReviewDecision",
    "ReviewedFinding",
    "RiskFlag",
    "RiskFlagKind",
    "Scope",
    "Severity",
    "StaticScanResult",
    "ToolDefinition",
    "Transport",
    "TriageReview",
    "ValidationMethod",
    "ValidationReport",
    "ValidationResult",
    "ValidationStatus",
]
