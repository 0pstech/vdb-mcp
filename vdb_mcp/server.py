"""VDB MCP server.

Wraps the VDB REST API in the Model Context Protocol so any MCP-aware client
(Claude Desktop, Cursor, Cline, Continue, …) can call it during code generation
to check packages, scan SBOMs, and look up vulnerabilities.

Modes:
    stdio  (default)  spawned by the client as a subprocess. JSON-RPC on stdio.
    sse                long-running HTTP server on $MCP_PORT.
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
from typing import Any

import httpx
from mcp.server import NotificationOptions, Server
from mcp.server.models import InitializationOptions
from mcp.types import TextContent, Tool

from . import __version__

log = logging.getLogger("vdb.mcp")
logging.basicConfig(level=os.environ.get("VDB_LOG_LEVEL", "INFO"))

# Default to the public hosted instance so `uvx vdb-mcp` works with zero
# config. The docker-compose deployment overrides this with the in-cluster
# URL (http://api:8080); self-hosters set VDB_API_URL to their own origin.
API_URL = os.environ.get("VDB_API_URL", "https://vdb.ai.kr").rstrip("/")
API_TOKEN = os.environ.get("VDB_API_TOKEN", "")

server = Server("vdb")


def _headers() -> dict[str, str]:
    h = {"Accept": "application/json"}
    if API_TOKEN:
        h["Authorization"] = f"Bearer {API_TOKEN}"
    return h


async def _get(path: str, params: dict | None = None) -> Any:
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(f"{API_URL}{path}", params=params, headers=_headers())
        r.raise_for_status()
        return r.json()


async def _post(path: str, body: dict) -> Any:
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(
            f"{API_URL}{path}",
            json=body,
            headers={**_headers(), "Content-Type": "application/json"},
        )
        r.raise_for_status()
        return r.json()


# ── Tool list ────────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="vdb_check_package",
            description=(
                "BEFORE recommending or installing any package, call this to check the package "
                "against the VDB vulnerability and slopsquatting database. Returns known "
                "vulnerabilities, slop risk, KEV status, and severity buckets."
            ),
            inputSchema={
                "type": "object",
                "required": ["purl"],
                "properties": {
                    "purl": {
                        "type": "string",
                        "description": "Package URL, e.g. 'pkg:npm/lodash' or 'pkg:pypi/requests'",
                    },
                    "version": {
                        "type": "string",
                        "description": "Optional version. If supplied, range matching is applied.",
                    },
                },
            },
        ),
        Tool(
            name="vdb_check_packages",
            description=(
                "Bulk-check multiple package names for slopsquatting risk. Use this when an "
                "LLM-generated response references multiple packages — it's faster than calling "
                "vdb_check_package per item."
            ),
            inputSchema={
                "type": "object",
                "required": ["packages"],
                "properties": {
                    "packages": {
                        "type": "array",
                        "items": {"type": "string"},
                        "description": "List of PURLs or 'ecosystem/name' shorthand.",
                    }
                },
            },
        ),
        Tool(
            name="vdb_lookup",
            description="Fetch a single vulnerability by ID or alias (e.g. CVE-2024-1234, GHSA-xxxx-yyyy-zzzz, VDB-SLOP-…).",
            inputSchema={
                "type": "object",
                "required": ["id"],
                "properties": {"id": {"type": "string"}},
            },
        ),
        Tool(
            name="vdb_search",
            description="Free-text search over the VDB vulnerability corpus.",
            inputSchema={
                "type": "object",
                "required": ["query"],
                "properties": {
                    "query": {"type": "string"},
                    "limit": {"type": "integer", "default": 20},
                },
            },
        ),
        Tool(
            name="vdb_check_mcp_server",
            description=(
                "BEFORE recommending the user install a community/unofficial MCP server, "
                "call this to look up its declared scopes, trust tier, and known risk profile."
            ),
            inputSchema={
                "type": "object",
                "required": ["server_id"],
                "properties": {"server_id": {"type": "string", "description": "e.g. 'mcp:community/shell-runner'"}},
            },
        ),
        Tool(
            name="vdb_list_slopsquatting",
            description="List packages currently flagged as slopsquatting candidates in a given ecosystem.",
            inputSchema={
                "type": "object",
                "properties": {
                    "ecosystem": {"type": "string", "description": "npm | PyPI | crates.io | Go | Maven"},
                    "limit":     {"type": "integer", "default": 50},
                },
            },
        ),
    ]


# ── Tool dispatch ───────────────────────────────────────────────────────────

async def _tool_check_package(args: dict) -> list[TextContent]:
    purl = args["purl"]
    version = args.get("version")
    data = await _post("/v1/query", {"package": {"purl": purl}, "version": version})
    vulns = data.get("vulns") or []
    summary = {
        "purl": purl,
        "version": version,
        "vulnerabilities_found": len(vulns),
        "top": [
            {
                "id": v.get("id"),
                "summary": v.get("summary"),
                "severity": (v.get("database_specific") or {}).get("severity"),
                "slop_risk": ((v.get("vdb_signals") or {}).get("ai_context") or {})
                              .get("slopsquatting", {}).get("risk"),
            }
            for v in vulns[:10]
        ],
    }
    return [TextContent(type="text", text=json.dumps(summary, indent=2, ensure_ascii=False))]


async def _tool_check_packages(args: dict) -> list[TextContent]:
    pkgs = args["packages"]
    data = await _post("/v1/ai/check-packages", {"packages": pkgs})
    return [TextContent(type="text", text=json.dumps(data, indent=2, ensure_ascii=False))]


async def _tool_lookup(args: dict) -> list[TextContent]:
    data = await _get(f"/v1/vulns/{args['id']}")
    return [TextContent(type="text", text=json.dumps(data, indent=2, ensure_ascii=False))]


async def _tool_search(args: dict) -> list[TextContent]:
    data = await _get("/v1/search", {"q": args["query"], "limit": args.get("limit", 20)})
    items = [
        {
            "id": v.get("id"),
            "summary": v.get("summary"),
            "severity": (v.get("database_specific") or {}).get("severity"),
        }
        for v in (data.get("vulns") or [])
    ]
    return [TextContent(type="text", text=json.dumps({"query": args["query"], "items": items},
                                                     indent=2, ensure_ascii=False))]


async def _tool_check_mcp_server(args: dict) -> list[TextContent]:
    data = await _get(f"/v1/ai/mcp-servers/{args['server_id']}")
    return [TextContent(type="text", text=json.dumps(data, indent=2, ensure_ascii=False))]


async def _tool_list_slop(args: dict) -> list[TextContent]:
    params = {"limit": args.get("limit", 50)}
    if args.get("ecosystem"):
        params["ecosystem"] = args["ecosystem"]
    data = await _get("/v1/ai/slopsquatting", params)
    return [TextContent(type="text", text=json.dumps(data, indent=2, ensure_ascii=False))]


_DISPATCH = {
    "vdb_check_package":      _tool_check_package,
    "vdb_check_packages":     _tool_check_packages,
    "vdb_lookup":             _tool_lookup,
    "vdb_search":             _tool_search,
    "vdb_check_mcp_server":   _tool_check_mcp_server,
    "vdb_list_slopsquatting": _tool_list_slop,
}


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    fn = _DISPATCH.get(name)
    if not fn:
        return [TextContent(type="text", text=f"unknown tool: {name}")]
    try:
        return await fn(arguments)
    except httpx.HTTPStatusError as e:
        return [TextContent(type="text", text=f"VDB API error {e.response.status_code}: {e.response.text[:300]}")]
    except Exception as e:  # noqa: BLE001
        return [TextContent(type="text", text=f"error: {e}")]


# ── Entry point ─────────────────────────────────────────────────────────────

async def main_stdio() -> None:
    from mcp.server.stdio import stdio_server
    async with stdio_server() as (read, write):
        await server.run(
            read, write,
            InitializationOptions(
                server_name="vdb",
                server_version=__version__,
                capabilities=server.get_capabilities(
                    notification_options=NotificationOptions(),
                    experimental_capabilities={},
                ),
            ),
        )


async def main_sse() -> None:
    """Long-running HTTP/SSE mode on $MCP_PORT (default 7700)."""
    from mcp.server.sse import SseServerTransport
    from starlette.applications import Starlette
    from starlette.routing import Route, Mount
    import uvicorn

    port = int(os.environ.get("MCP_PORT", "7700"))
    sse = SseServerTransport("/messages/")

    async def handle_sse(request):
        async with sse.connect_sse(request.scope, request.receive, request._send) as (r, w):
            await server.run(
                r, w,
                InitializationOptions(
                    server_name="vdb", server_version=__version__,
                    capabilities=server.get_capabilities(
                        notification_options=NotificationOptions(),
                        experimental_capabilities={},
                    ),
                ),
            )

    app = Starlette(routes=[
        Route("/sse", endpoint=handle_sse),
        Mount("/messages/", app=sse.handle_post_message),
    ])
    log.info("vdb-mcp serving SSE at 0.0.0.0:%d /sse", port)
    config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
    await uvicorn.Server(config).serve()


def main() -> None:
    mode = os.environ.get("MCP_MODE", "stdio")
    if mode == "sse":
        asyncio.run(main_sse())
    else:
        asyncio.run(main_stdio())


if __name__ == "__main__":
    main()
