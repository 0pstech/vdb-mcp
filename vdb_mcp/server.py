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

# Self-reported client label for VDB's admin traffic breakdown (X-VDB-Client).
# Defaults to "vdb-mcp" for the local `uvx vdb-mcp` path; the hosted remote
# endpoint's container overrides VDB_CLIENT=vdb-mcp-remote so the two show up
# as distinct distribution channels in the dashboard.
CLIENT_TAG = os.environ.get("VDB_CLIENT", "vdb-mcp")
_UA = f"vdb-mcp/{__version__}"

# Local mode = the server process runs on the developer's own machine (stdio,
# i.e. `uvx vdb-mcp`). Only there can a file path mean the caller's file, and
# only there can we abstract source without it leaving the host. On the hosted
# remote endpoint the paths would be OURS, and shipping source to us would
# break the exact privacy promise the harden feature is built on — so the tool
# is not offered at all rather than offered in a degraded form.
def _is_local() -> bool:
    mode = os.environ.get("MCP_MODE", "").lower()
    if mode:
        return mode == "stdio"
    return not os.environ.get("PORT")

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
    # X-VDB-Client + a real User-Agent so this traffic is attributable to the
    # MCP channel in the admin dashboard even if a proxy strips one of them.
    h = {"Accept": "application/json", "X-VDB-Client": CLIENT_TAG, "User-Agent": _UA}
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


async def _post_file(path: str, filename: str, content: bytes) -> Any:
    url, _ = _resolved()
    async with httpx.AsyncClient(timeout=60) as c:
        r = await c.post(
            f"{url}{path}",
            files={"file": (filename, content)},
            headers=_headers(),
        )
        r.raise_for_status()
        return r.json()


def _json(payload: Any) -> list[TextContent]:
    return [TextContent(type="text",
                        text=json.dumps(payload, indent=2, ensure_ascii=False))]


# ── Tool list ────────────────────────────────────────────────────────────────

@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="vdb_check_package",
            description=(
                "BEFORE recommending or installing any package, check it here. "
                "The response carries `agent_action`: REFUSE (do not add it — "
                "relay the `because` text to the user), CONFIRM (ask the user "
                "first), or PROCEED. A failed or rate-limited call also answers "
                "REFUSE; never proceed unchecked. Also returns the underlying "
                "advisories, slop risk, and KEV status as supporting data."
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
                "Bulk-check several packages in one call — always prefer this "
                "over repeated vdb_check_package. Each result carries its own "
                "`agent_action` (REFUSE / CONFIRM / PROCEED) plus a top-level "
                "`agent_action` for the batch. Follow them; relay `because` "
                "when refusing. Send names EXACTLY as written — do not correct "
                "a typo first, the call is the typo test."
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
            name="vdb_scan_lockfile",
            description=(
                "BEFORE merging, scan the resolved lockfile. Checking the "
                "packages someone chose misses the transitive ones nobody "
                "did — which is usually where the risk is. Pass the file "
                "contents (package-lock.json, requirements.txt, uv.lock, "
                "go.sum, Cargo.lock, a CycloneDX SBOM, …). Returns "
                "`agent_action`: REFUSE means do not merge."
            ),
            inputSchema={
                "type": "object",
                "required": ["filename"],
                "properties": {
                    "filename": {"type": "string",
                                 "description": "e.g. 'package-lock.json' — the format is detected from it"},
                    "content":  {"type": "string", "description": "The file's text."},
                    "path":     {"type": "string",
                                 "description": "Local runs only (uvx vdb-mcp): read the file here instead of passing content."},
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
                "BEFORE recommending a community/unofficial MCP server, check "
                "it here. Scope risk is evaluated independently of advisory "
                "risk — an unvetted publisher asking for shell or filesystem "
                "access is refused even with a clean record. Follow the "
                "returned `agent_action`."
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
    ] + ([
        Tool(
            name="vdb_harden",
            description=(
                "Decide whether attacker-controlled data can reach a dangerous "
                "operation through this file's transitive dependencies — with "
                "no CVE required. Use it on code that passes user input into a "
                "third-party API. The file is abstracted LOCALLY first "
                "(identifiers renamed, literals reduced to shapes, bodies "
                "dropped); only that abstraction and the lockfile are sent, "
                "never source text. Returns decided paths, a call-site fix "
                "that does not modify the dependency, and the residual risk "
                "the fix does not cover."
            ),
            inputSchema={
                "type": "object",
                "required": ["path", "manifest_path"],
                "properties": {
                    "path": {"type": "string",
                             "description": "Python file to analyze."},
                    "manifest_path": {"type": "string",
                                      "description": "uv.lock / poetry.lock / Pipfile.lock / requirements.txt / CycloneDX. Version ranges cannot be analyzed — the answer differs per resolved version."},
                },
            },
        ),
        Tool(
            name="vdb_harden_verify",
            description=(
                "After applying a fix returned by vdb_harden, re-abstract the "
                "local file and verify the originally issued path. Returns a "
                "signed evidence payload bound to the original analysis, the "
                "fixed IR fingerprint, and the dependency graph. This proves "
                "VDB's decision over the submitted abstraction, not that the "
                "abstraction matches a deployed binary."
            ),
            inputSchema={
                "type": "object",
                "required": ["path", "manifest_path", "path_id"],
                "properties": {
                    "path": {"type": "string", "description": "Fixed Python file."},
                    "manifest_path": {"type": "string", "description": "The same resolved manifest used for vdb_harden."},
                    "path_id": {"type": "string", "description": "Path id issued by vdb_harden."},
                },
            },
        ),
        Tool(
            name="vdb_vex",
            description=(
                "Given a project directory and its lockfile, work out which of "
                "its known advisories can actually be reached by "
                "attacker-controlled data, and return an OpenVEX document plus "
                "a shareable URL. Use this when a scan produced more findings "
                "than anyone can triage. Point `path` at the SOURCE TREE, not "
                "one file: a not_affected determination is only as wide as the "
                "code behind it, and a single-file run withholds them all. "
                "Reachability is decided at package granularity from static "
                "summaries — good for triage order, not proof of "
                "non-exploitability."
            ),
            inputSchema={
                "type": "object",
                "required": ["path", "manifest_path"],
                "properties": {
                    "path": {"type": "string",
                             "description": "Project source directory."},
                    "manifest_path": {"type": "string",
                                      "description": "Resolved lockfile for the same project."},
                },
            },
        ),
    ] if _is_local() else [])


# ── Tool dispatch ───────────────────────────────────────────────────────────

async def _tool_check_package(args: dict) -> list[TextContent]:
    """One package, same gate as the bulk tool.

    This used to call /v1/query, which returns raw advisories and no verdict.
    An agent then had to re-derive the policy itself — the exact thing the
    decision layer exists to stop — and the two tools disagreed about what a
    check even means. Both go through /v1/ai/check-packages now.
    """
    purl = args["purl"]
    version = args.get("version")
    if version and "@" not in purl.rsplit("/", 1)[-1]:
        purl = f"{purl}@{version}"
    data = await _post("/v1/ai/check-packages", {"packages": [purl]})
    results = data.get("results") or []
    return _json(results[0] if len(results) == 1 else data)


async def _tool_check_packages(args: dict) -> list[TextContent]:
    pkgs = args["packages"]
    data = await _post("/v1/ai/check-packages", {"packages": pkgs})
    return _json(data)


async def _tool_scan_lockfile(args: dict) -> list[TextContent]:
    """The merge gate. Direct checks miss transitives; this is the only tool
    that sees the dependency nobody chose."""
    filename = args.get("filename") or ""
    content = args.get("content")
    path = args.get("path")
    if content is None and path:
        # Only meaningful in stdio mode, where the server runs on the machine
        # that owns the file. In hosted mode the path is ours, not theirs, so
        # the agent must pass `content` instead.
        with open(path, "rb") as fh:
            content = fh.read().decode("utf-8", "replace")
        filename = filename or os.path.basename(path)
    if content is None:
        return _json({"error": "pass either `content` or (in local mode) `path`"})
    data = await _post_file("/v1/sbom/scan", filename or "lockfile.txt",
                            content.encode())
    # Findings can run to hundreds; the verdict and the worst offenders are
    # what a merge decision needs. The full list stays one API call away.
    return _json({
        "agent_action":      data.get("agent_action"),
        "because":           data.get("because"),
        "sbom_format":       data.get("sbom_format"),
        "components_total":  data.get("components_total"),
        "summary":           data.get("summary"),
        "top_findings":      (data.get("vulnerabilities") or [])[:20],
        "findings_total":    len(data.get("vulnerabilities") or []),
    })


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
    """Routed through the gate so scope risk produces a verdict, not a record.

    An MCP server VDB has no record of returns REFUSE rather than CONFIRM —
    installing one grants it tool access, so unverifiable is not acceptable
    here the way it is for an ordinary library.
    """
    sid = args["server_id"]
    purl = sid if sid.startswith("pkg:mcp/") else f"pkg:mcp/{sid.removeprefix('mcp:')}"
    data = await _post("/v1/ai/check-packages", {"packages": [purl]})
    results = data.get("results") or []
    return _json(results[0] if len(results) == 1 else data)


async def _tool_list_slop(args: dict) -> list[TextContent]:
    params = {"limit": args.get("limit", 50)}
    if args.get("ecosystem"):
        params["ecosystem"] = args["ecosystem"]
    data = await _get("/v1/ai/slopsquatting", params)
    return [TextContent(type="text", text=json.dumps(data, indent=2, ensure_ascii=False))]


async def _tool_harden(args: dict) -> list[TextContent]:
    """Abstract locally, then send only the abstraction.

    The import is deliberately inside the function: the vendored modules are
    pure stdlib, but keeping them off the hosted server's import path makes
    the local-only boundary structural rather than a matter of remembering.
    """
    from .harden.ir import build_ir_from_file

    path = args["path"]
    manifest_path = args["manifest_path"]
    ir = build_ir_from_file(path)
    if not ir.callsites:
        return _json({
            "paths": [],
            "note": "no third-party call sites found in this file — nothing to "
                    "decide. Point it at code that passes input into a "
                    "dependency's API.",
        })
    with open(manifest_path, "rb") as fh:
        manifest = fh.read().decode("utf-8", "replace")
    data = await _post("/v1/harden/analyze", {
        "ir": ir.to_dict(),
        "manifest": manifest,
        "manifest_filename": os.path.basename(manifest_path),
    })
    return _json({
        "paths":      data.get("paths"),
        "hardenings": data.get("hardenings"),
        "cached":     data.get("cached"),
        "analysis_complete": data.get("analysis_complete"),
        "summaries_missing": data.get("summaries_missing"),
        "analysis_notes": data.get("notes"),
        "note": ("Analysis is incomplete; an empty path list is not a safety "
                 "determination. Re-run after summaries are available."
                 if data.get("incomplete") else
                 "Paths are decided from the dependency graph, independently "
                 "of whether any CVE exists. Apply the fix at the CALL SITE — "
                 "the dependency is never modified. Verify the issued path "
                 "with vdb_harden_verify after applying it."),
    })


async def _tool_harden_verify(args: dict) -> list[TextContent]:
    """Re-abstract a fixed local file and verify an issued path."""
    from .harden.ir import build_ir_from_file

    path = args["path"]
    manifest_path = args["manifest_path"]
    ir = build_ir_from_file(path)
    with open(manifest_path, "rb") as fh:
        manifest = fh.read().decode("utf-8", "replace")
    data = await _post("/v1/harden/verify", {
        "ir": ir.to_dict(),
        "manifest": manifest,
        "manifest_filename": os.path.basename(manifest_path),
        "path_id": args["path_id"],
    })
    return _json(data)


async def _tool_vex(args: dict) -> list[TextContent]:
    """Scan, then subtract. Local-only for the same reason as vdb_harden —
    the abstraction runs on the machine that owns the source."""
    from .harden.ir import build_ir_from_tree

    path = args["path"]
    manifest_path = args["manifest_path"]
    if not os.path.isdir(path):
        return _json({"error": "path must be a directory — a not_affected "
                               "determination derived from one file would be "
                               "wrong for every other file that imports the "
                               "same package"})
    ir = build_ir_from_tree(path)
    if not ir.files:
        return _json({"error": f"no Python files under {path}"})

    with open(manifest_path, "rb") as fh:
        manifest = fh.read().decode("utf-8", "replace")
    scan = await _post_file("/v1/sbom/scan", os.path.basename(manifest_path),
                            manifest.encode())
    doc = await _post("/v1/vex", {
        "ir": ir.to_dict(),
        "manifest": manifest,
        "manifest_filename": os.path.basename(manifest_path),
        "findings": scan.get("vulnerabilities") or [],
    })
    meta = doc.get("_vdb", {})
    # The statements a human still has to act on, plus the scope the whole
    # thing rests on. The full document is behind share_url; pasting several
    # hundred statements into the transcript would bury the answer.
    return _json({
        "share_url":   meta.get("share_url"),
        "total":       len(doc.get("statements", [])),
        "counts":      meta.get("counts", {}),
        "needs_triage": [
            {"id": st["vulnerability"]["name"], "product": st["products"][0]["@id"]}
            for st in doc.get("statements", [])
            if st.get("status") == "under_investigation"
        ],
        "files_analyzed": meta.get("files_analyzed_count"),
        "scope_note":     meta.get("scope_note"),
    })


_DISPATCH = {
    "vdb_check_package":      _tool_check_package,
    "vdb_check_packages":     _tool_check_packages,
    "vdb_scan_lockfile":      _tool_scan_lockfile,
    "vdb_harden":             _tool_harden,
    "vdb_harden_verify":      _tool_harden_verify,
    "vdb_vex":                _tool_vex,
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
        # 401/429 bodies carry agent_action=REFUSE plus recovery instructions.
        # Flattening that into a string would bury the verdict in prose and
        # leave fail-closed depending on the model reading an error message
        # carefully — which is exactly the failure mode we removed elsewhere.
        try:
            body = e.response.json()
            detail = body.get("detail", body) if isinstance(body, dict) else body
        except Exception:  # noqa: BLE001
            detail = {"message": e.response.text[:400]}
        if isinstance(detail, dict):
            detail.setdefault("agent_action", "REFUSE")
            detail.setdefault("because", "the check did not complete; "
                                         "proceeding unchecked is not safe")
        return _json({"http_status": e.response.status_code, **(
            detail if isinstance(detail, dict) else {"detail": detail})})
    except Exception as e:  # noqa: BLE001
        # Transport failures are refusals too — a check that never happened
        # must never read as a check that passed.
        return _json({
            "agent_action": "REFUSE",
            "because": f"the check could not be completed ({type(e).__name__}); "
                       f"proceeding unchecked is not safe",
            "error": str(e)[:300],
        })


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

    # Mount at root, not at "/mcp": Starlette's Mount("/mcp") 307-redirects
    # a bare "/mcp" to "/mcp/", which behind a trailing-slash-normalizing
    # proxy (our Caddy) becomes an infinite redirect loop. The session
    # manager keys on the JSON-RPC body, not the path, so serving every
    # path is fine — Caddy only ever routes /mcp* here anyway.
    app = Starlette(routes=[Mount("/", app=handle)])
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
