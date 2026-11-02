"""Fictional source fixture. Intentionally inspected without importing it."""
from mcp.server.fastmcp import FastMCP
mcp=FastMCP('example-tools')
@mcp.tool()
def service_health(service: str) -> str:
    """Return a fictional service health status."""
    return 'healthy'
@mcp.tool()
def list_workers() -> list[str]:
    """List fictional compute workers."""
    return ['demo-worker']
