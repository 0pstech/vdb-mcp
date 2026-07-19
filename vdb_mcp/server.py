"""VDB MCP server.

Wraps the VDB REST API in the Model Context Protocol so any MCP-aware client
(Claude Desktop, Cursor, Cline, Continue, …) can call it during code generation
to check packages, scan SBOMs, and look up vulnerabilities.

Modes:
    stdio  (default)  spawned by the client as a subprocess. JSON-RPC on stdio.
    http               streamable HTTP at /mcp on $PORT — the transport
                       Smithery hosting and remote MCP clients expect.
                       Auto-selected when $PORT is set and MCP_MODE isn't.
    sse                legacy SSE server on $MCP_PORT (docker-compose profile).
"""

from __future__ import annotations

import asyncio
import contextvars
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

# version= flows into serverInfo for ALL transports — without it the
# streamable-http path reports the mcp SDK version instead of ours.
server = Server("vdb", version=__version__)

# Per-request session config (http mode). Smithery-hosted deployments pass
# the user's config as query parameters on every /mcp request; the ASGI
# wrapper stashes them here so concurrent sessions with different tokens
# don't clobber each other. Empty in stdio/sse modes → env defaults apply.
_request_cfg: contextvars.ContextVar[dict] = contextvars.ContextVar(
    "vdb_request_cfg", default={}
)


def _resolved() -> tuple[str, str]:
    """(api_url, token) for the CURRENT request: session config > env."""
    cfg = _request_cfg.get()
    url = (cfg.get("vdbApiUrl") or API_URL).rstrip("/")
    token = cfg.get("vdbApiToken") or API_TOKEN
    return url, token


def _headers() -> dict[str, str]:
    _, token = _resolved()
    h = {"Accept": "application/json"}
    if token:
        h["Authorization"] = f"Bearer {token}"
    return h


async def _get(path: str, params: dict | None = None) -> Any:
    url, _ = _resolved()
    async with httpx.AsyncClient(timeout=15) as c:
        r = await c.get(f"{url}{path}", params=params, headers=_headers())
        r.raise_for_status()
        return r.json()


async def _post(path: str, body: dict) -> Any:
    url, _ = _resolved()
    async with httpx.AsyncClient(timeout=30) as c:
        r = await c.post(
            f"{url}{path}",
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


async def main_http() -> None:
    """Streamable HTTP at /mcp — what Smithery hosting and remote MCP
    clients speak. Listens on $PORT (Smithery sets 8081), falls back to
    $MCP_PORT/7700 for manual runs. Stateless: each request carries its
    own session config as query parameters."""
    from urllib.parse import parse_qs

    import uvicorn
    from mcp.server.streamable_http_manager import StreamableHTTPSessionManager
    from starlette.applications import Starlette
    from starlette.middleware.cors import CORSMiddleware
    from starlette.routing import Mount

    port = int(os.environ.get("PORT", os.environ.get("MCP_PORT", "7700")))
    session_manager = StreamableHTTPSessionManager(app=server, stateless=True)

    async def handle(scope, receive, send):
        # Stash per-request config (Smithery passes user config as query
        # params) so tool calls resolve the right API URL/token.
        cfg = {}
        if scope.get("type") == "http":
            qs = parse_qs((scope.get("query_string") or b"").decode())
            cfg = {k: v[0] for k, v in qs.items() if v}
        tok = _request_cfg.set(cfg)
        try:
            await session_manager.handle_request(scope, receive, send)
        finally:
            _request_cfg.reset(tok)

    app = Starlette(routes=[Mount("/mcp", app=handle)])
    # Browser-based MCP clients need CORS; expose the session header.
    app = CORSMiddleware(
        app,
        allow_origins=["*"],
        allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
        allow_headers=["*"],
        expose_headers=["mcp-session-id", "mcp-protocol-version"],
    )
    log.info("vdb-mcp serving streamable HTTP at 0.0.0.0:%d /mcp", port)
    async with session_manager.run():
        config = uvicorn.Config(app, host="0.0.0.0", port=port, log_level="info")
        await uvicorn.Server(config).serve()


def main() -> None:
    mode = os.environ.get("MCP_MODE", "").lower()
    if not mode:
        # Smithery (and most container hosts) inject PORT and expect an
        # HTTP server; a plain `vdb-mcp` launch stays stdio.
        mode = "http" if os.environ.get("PORT") else "stdio"
    if mode == "http":
        asyncio.run(main_http())
    elif mode == "sse":
        asyncio.run(main_sse())
    else:
        asyncio.run(main_stdio())


if __name__ == "__main__":
    main()
