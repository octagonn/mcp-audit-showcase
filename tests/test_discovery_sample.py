from pathlib import Path
from mcp_audit.phases._python_detector import analyze_python_file
from mcp_audit.phases._typescript_detector import analyze_typescript_file

def test_python_fixture():
    root=Path(__file__).resolve().parents[1]
    entries,tools=analyze_python_file(root/'examples/sample_server.py',root)
    assert entries
    assert {t.name for t in tools}=={'service_health','list_workers'}

def test_source_is_not_executed(tmp_path):
    p=tmp_path/'danger.py'
    p.write_text('raise RuntimeError("must not run")\n@mcp.tool()\ndef hello(name: str):\n    """Example."""\n    return name')
    _,tools=analyze_python_file(p,tmp_path)
    assert tools[0].name=='hello'

def test_invalid_python(tmp_path):
    p=tmp_path/'bad.py';p.write_text('def (')
    assert analyze_python_file(p,tmp_path)==([],[])

def test_typescript(tmp_path):
    p=tmp_path/'server.ts';p.write_text('const s = new McpServer("demo"); s.tool("health", "Check health", {}, () => {});')
    entries,tools=analyze_typescript_file(p,tmp_path)
    assert entries and tools[0].name=='health'
