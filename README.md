# vdb-mcp
<<<<<<< HEAD
mcp for vdb
=======

mcp-name: kr.ai.vdb/vdb

MCP (Model Context Protocol) server for **[VDB](https://vdb.ai.kr)** — the
AI-aware vulnerability database. Lets Claude Desktop, Claude Code, Cursor,
Cline, Continue, and any MCP client check packages **while generating code**:
known CVEs, slopsquatting (LLM-hallucinated package names an attacker may have
registered), CISA KEV status, MCP-server trust profiles, and more.

## Quick start

```bash
uvx vdb-mcp          # or: pipx run vdb-mcp
```

Claude Desktop (`claude_desktop_config.json`) / Cursor (`.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "vdb": { "command": "uvx", "args": ["vdb-mcp"] }
  }
}
```

That's it — the server talks to the hosted instance at `https://vdb.ai.kr`
by default. Anonymous use gets a free per-IP trial; add an API key for
unmetered access (free at <https://vdb.ai.kr/signup>):

```json
{
  "mcpServers": {
    "vdb": {
      "command": "uvx",
      "args": ["vdb-mcp"],
      "env": { "VDB_API_TOKEN": "vdb_..." }
    }
  }
}
```

## Tools

| Tool | What it does |
|---|---|
| `vdb_check_package` | Check one package (purl + optional version) for vulnerabilities, slop risk, KEV |
| `vdb_check_packages` | Bulk slopsquatting / risk check for a list of packages |
| `vdb_lookup` | Fetch one advisory by ID (CVE-…, GHSA-…, VDB-SLOP-…) |
| `vdb_search` | Free-text search over the vulnerability corpus |
| `vdb_check_mcp_server` | Trust tier + permission scopes of a community MCP server |
| `vdb_list_slopsquatting` | Current slopsquatting candidates per ecosystem |

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `VDB_API_URL` | `https://vdb.ai.kr` | VDB instance to query (set for self-hosted) |
| `VDB_API_TOKEN` | *(empty)* | `vdb_…` API key — unmetered, per-account quota |
| `MCP_MODE` | `stdio` | `stdio` or `sse` (long-running HTTP server) |
| `MCP_PORT` | `7700` | SSE port |

## Why

LLMs hallucinate package names; attackers register them (slopsquatting).
LLMs also happily recommend packages with known RCEs. VDB gives your agent a
guardrail: one tool call before `npm install` / `pip install`. See
<https://vdb.ai.kr/connect> for the one-line prompt variant that needs no MCP
at all.

## License

[Elastic License 2.0](https://www.elastic.co/licensing/elastic-license) —
free to use, including inside commercial organizations and CI. The only
restrictions: you may not offer this software to third parties as a hosted
or managed service, or resell it as a product. Commercial licensing beyond
that: <dev@egdee.com>. API usage is governed by the VDB service terms
regardless of how you call it.
>>>>>>> 0d5f3f3 (v0.1.1 — VDB MCP server (public release mirror))
