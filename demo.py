"""Public demonstration wrapper around original source-analysis modules."""
import json
from pathlib import Path
from mcp_audit.phases._python_detector import analyze_python_file
root=Path(__file__).resolve().parent
if __name__=='__main__':
    entries,tools=analyze_python_file(root/'examples/sample_server.py',root)
    print(json.dumps({'entrypoints':[x.model_dump(mode='json') for x in entries], 'tools':[x.model_dump(mode='json') for x in tools]},indent=2))
