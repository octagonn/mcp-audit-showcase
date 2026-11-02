"""Unit tests for the Pydantic schemas (``mcp_audit.schemas``)."""

from __future__ import annotations

import json

import pytest
from pydantic import ValidationError

from mcp_audit.schemas import (
    AttackClass,
    AuditTarget,
    ClientMetadata,
    Dependency,
    Entrypoint,
    Language,
    OAuthScope,
    RiskFlag,
    RiskFlagKind,
    Scope,
    ToolDefinition,
    Transport,
)

# ---------------------------------------------------------------------------
# ToolDefinition
# ---------------------------------------------------------------------------


class TestToolDefinition:
    def test_minimal_valid(self) -> None:
        t = ToolDefinition(name="read_file")
        assert t.name == "read_file"
        assert t.description == ""
        assert t.input_schema is None
        assert t.risk_flags == []

    def test_full_valid(self) -> None:
        t = ToolDefinition(
            name="read_file",
            description="Read a file from disk.",
            input_schema={"type": "object", "properties": {"path": {"type": "string"}}},
            source_file="src/server.py",
            source_line=42,
            risk_flags=[
                RiskFlag(
                    kind=RiskFlagKind.DANGEROUS_TOOL_NAME,
                    subject="read_file",
                    evidence="Tool named like file access",
                )
            ],
        )
        assert t.source_line == 42
        assert len(t.risk_flags) == 1

    def test_rejects_invalid_name(self) -> None:
        with pytest.raises(ValidationError):
            ToolDefinition(name="1bad-start")

    def test_rejects_spaces_in_name(self) -> None:
        with pytest.raises(ValidationError):
            ToolDefinition(name="has spaces")

    def test_accepts_dotted_and_dashed_names(self) -> None:
        ToolDefinition(name="namespace.tool-name_v2")

    def test_rejects_zero_source_line(self) -> None:
        with pytest.raises(ValidationError):
            ToolDefinition(name="t", source_line=0)

    def test_source_file_normalised_to_posix(self) -> None:
        t = ToolDefinition(name="t", source_file="src\\server.py")
        assert t.source_file == "src/server.py"

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            ToolDefinition.model_validate({"name": "t", "bogus": 1})


# ---------------------------------------------------------------------------
# Scope
# ---------------------------------------------------------------------------


class TestScope:
    def _client(self) -> ClientMetadata:
        return ClientMetadata(name="Acme AI", contact_email="security@acme.ai")

    def test_minimal(self) -> None:
        s = Scope(
            audit_id="acme-2026-04",
            target="https://github.com/acme/mcp-server",
            client=self._client(),
        )
        assert s.allowed_attack_classes == []
        assert s.allow_destructive is False

    def test_rejects_empty_audit_id(self) -> None:
        with pytest.raises(ValidationError):
            Scope(audit_id="", target="/tmp/x", client=self._client())

    def test_rejects_audit_id_with_slashes(self) -> None:
        with pytest.raises(ValidationError):
            Scope(audit_id="a/b", target="/tmp/x", client=self._client())

    def test_dedupes_allowed_attack_classes(self) -> None:
        s = Scope(
            audit_id="a",
            target="/tmp/x",
            client=self._client(),
            allowed_attack_classes=[
                AttackClass.PROMPT_INJECTION,
                AttackClass.PROMPT_INJECTION,
                AttackClass.TOOL_ABUSE,
            ],
        )
        assert s.allowed_attack_classes == [AttackClass.PROMPT_INJECTION, AttackClass.TOOL_ABUSE]

    def test_nondestructive_attack_permitted_when_allowed(self) -> None:
        s = Scope(
            audit_id="a",
            target="/tmp/x",
            client=self._client(),
            allowed_attack_classes=[AttackClass.PROMPT_INJECTION],
        )
        assert s.attack_class_is_permitted(AttackClass.PROMPT_INJECTION)
        assert not s.attack_class_is_permitted(AttackClass.TOOL_ABUSE)

    def test_destructive_requires_opt_in(self) -> None:
        s = Scope(
            audit_id="a",
            target="/tmp/x",
            client=self._client(),
            allowed_attack_classes=[AttackClass.DOS],
            allow_destructive=False,
        )
        assert not s.attack_class_is_permitted(AttackClass.DOS), (
            "destructive attack must be denied when allow_destructive=False, even if whitelisted"
        )

    def test_destructive_with_opt_in(self) -> None:
        s = Scope(
            audit_id="a",
            target="/tmp/x",
            client=self._client(),
            allowed_attack_classes=[AttackClass.DOS],
            allow_destructive=True,
        )
        assert s.attack_class_is_permitted(AttackClass.DOS)


# ---------------------------------------------------------------------------
# AuditTarget
# ---------------------------------------------------------------------------


class TestAuditTarget:
    def test_minimal(self) -> None:
        at = AuditTarget(audit_id="demo", language=Language.PYTHON)
        assert at.schema_version == 1
        assert at.tools == []
        assert at.source_url is None

    def test_source_url_validation(self) -> None:
        at = AuditTarget(
            audit_id="demo",
            language=Language.PYTHON,
            source_url="https://github.com/foo/bar",  # type: ignore[arg-type]
        )
        assert str(at.source_url).startswith("https://github.com/")

    def test_rejects_bad_source_url(self) -> None:
        with pytest.raises(ValidationError):
            AuditTarget(
                audit_id="demo",
                language=Language.PYTHON,
                source_url="not-a-url",  # type: ignore[arg-type]
            )

    def test_transports_deduped(self) -> None:
        at = AuditTarget(
            audit_id="demo",
            language=Language.PYTHON,
            transports=[Transport.STDIO, Transport.STDIO, Transport.HTTP],
        )
        assert at.transports == [Transport.STDIO, Transport.HTTP]

    def test_tool_by_name(self) -> None:
        at = AuditTarget(
            audit_id="demo",
            language=Language.PYTHON,
            tools=[ToolDefinition(name="a"), ToolDefinition(name="b")],
        )
        found = at.tool_by_name("b")
        assert found is not None
        assert found.name == "b"
        assert at.tool_by_name("zzz") is None

    def test_round_trip_json(self) -> None:
        at = AuditTarget(
            audit_id="demo",
            language=Language.TYPESCRIPT,
            source_url="https://github.com/foo/bar",  # type: ignore[arg-type]
            entrypoints=[
                Entrypoint(
                    file="src/index.ts",
                    line=10,
                    constructor="createServer",
                    server_name="demo-server",
                )
            ],
            tools=[
                ToolDefinition(
                    name="hello",
                    description="Say hello.",
                    input_schema={"type": "object"},
                    source_file="src/tools/hello.ts",
                    source_line=5,
                    risk_flags=[
                        RiskFlag(
                            kind=RiskFlagKind.INSTRUCTION_LIKE_DESCRIPTION,
                            subject="hello",
                            evidence="you must greet warmly",
                        )
                    ],
                )
            ],
            transports=[Transport.STDIO, Transport.SSE],
            oauth_scopes=[OAuthScope(provider="github", scope="repo:read")],
            dependencies=[Dependency(name="axios", version_spec="^1.0", source="package.json")],
        )
        raw = at.model_dump_json()
        parsed = json.loads(raw)
        assert parsed["language"] == "typescript"

        rebuilt = AuditTarget.model_validate_json(raw)
        assert rebuilt == at
        assert rebuilt.tools[0].risk_flags[0].kind == RiskFlagKind.INSTRUCTION_LIKE_DESCRIPTION

    def test_extra_fields_rejected(self) -> None:
        with pytest.raises(ValidationError):
            AuditTarget.model_validate({"audit_id": "demo", "language": "python", "bogus": True})


# ---------------------------------------------------------------------------
# Entrypoint / small types
# ---------------------------------------------------------------------------


class TestSmallTypes:
    def test_entrypoint_path_normalised(self) -> None:
        e = Entrypoint(file="src\\a\\b.py", line=1, constructor="FastMCP")
        assert e.file == "src/a/b.py"

    def test_entrypoint_rejects_line_zero(self) -> None:
        with pytest.raises(ValidationError):
            Entrypoint(file="x.py", line=0, constructor="FastMCP")

    def test_client_metadata_requires_email(self) -> None:
        with pytest.raises(ValidationError):
            ClientMetadata(name="X", contact_email="")  # type: ignore[arg-type]
