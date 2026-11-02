# MCP Audit Showcase

Selected source from a private Python MCP security-audit pipeline. This public
edition includes the original Python AST tool detector, TypeScript/JavaScript
heuristic detector, shared patterns, and Pydantic artifact schemas, plus schema
tests. It demonstrates deterministic analysis without importing target code.

## Run the example

```sh
python -m pip install -r requirements-dev.txt
python demo.py
python -m pytest tests -q
```

The demo prints structured JSON for two fictional MCP tools. No API keys,
network access, external repositories, or running MCP server are required.
`demo.py` and the fictional fixture were added for publication; the detectors
and contracts are extracted from the existing pipeline.

## The larger project

The private implementation organizes discovery, static analysis, scoped
probing, human review, validation, reporting, preflight, and packaging as
rerunnable stages exchanging JSON artifacts. It also has a persistent LLM cost
ledger and an operator review UI. Those components and business documentation
are intentionally not included in this showcase.

The resume's 324-test figure refers to the private project snapshot, not this
smaller public subset. The public CI result reports the tests available here.
No client audit data, real-target results, or claims of paid engagements are
included.

## Limitations

Tool discovery is not a security assessment. Python analysis handles literal
registrations and decorators; TypeScript detection is heuristic and can miss
dynamic or unusual registrations. The output must be reviewed by a person.
