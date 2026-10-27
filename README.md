# vdb-mcp

mcp-name: kr.ai.vdb/vdb

MCP (Model Context Protocol) server for **[VDB](https://vdb.ai.kr)** — the
AI-aware vulnerability database. Lets Claude Desktop, Claude Code, Cursor,
Cline, Continue, and any MCP client check packages **while generating code**:
known CVEs, slopsquatting (LLM-hallucinated package names an attacker may have
registered), CISA KEV status, MCP-server trust profiles, and more.

## Quick start

> **Where this works:** Runs where your code is: an agent on your machine with the project folder (Claude Code, Cursor, Cline, Codex CLI). A chat-only web AI cannot use it — its sandbox has no outbound network, and it cannot see your files.

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

**No install at all** — point any streamable-HTTP MCP client at the hosted
endpoint:

```json
{
  "mcpServers": {
    "vdb": {
      "url": "https://vdb.ai.kr/mcp",
      "headers": { "Authorization": "Bearer vdb_..." }
    }
  }
}
```

Claude Code: `claude mcp add --transport http vdb https://vdb.ai.kr/mcp --header "Authorization: Bearer $VDB_API_KEY"`.
The hosted endpoint reads the key from that header (0.2.3+; the
`vdbApiToken` query parameter Smithery sets still works and takes precedence).

That's it — the server talks to the hosted instance at `https://vdb.ai.kr`
by default. The package gate (`vdb_check_package`, `vdb_check_packages`,
`vdb_list_slopsquatting`) and the hardening tools (`vdb_harden`,
`vdb_harden_remediate`, `vdb_harden_verify`, `vdb_vex`) answer **without a
key** on a per-address allowance (0.2.8+; 100 packages an hour, 3 analyses
an hour and 10 a day, projects up to 200 dependencies, nothing stored). The
other tools need a free API key (<https://vdb.ai.kr/signup>, or the agent can
request one by email itself: without a key those tools answer
`agent_action: REFUSE` with a `request_key_url`). A key is currently unmetered
beyond abuse protection:

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
| `vdb_scan_lockfile` | Merge verdict for a whole lockfile / SBOM (transitives included) |
| `vdb_lookup` | Fetch one advisory by ID (CVE-…, GHSA-…, VDB-SLOP-…) |
| `vdb_search` | Free-text search over the vulnerability corpus |
| `vdb_check_mcp_server` | Trust tier + permission scopes of a community MCP server |
| `vdb_list_slopsquatting` | Current slopsquatting candidates per ecosystem |
| `vdb_harden` *(local only)* | Call-site hardening: can attacker data reach a dangerous sink through your dependencies? Source never leaves the machine |
| `vdb_harden_verify` *(local only)* | Re-analyze after a fix and get signed evidence the path is closed (without a key: pass `original_path`, the pre-fix file; the decision comes back unsigned) |
| `vdb_harden_remediate` *(local only)* | Rank what to fix first: upgrade / harden / remove / policy candidates by project risk removed per cost, plus the combination that reaches a target (0.2.7+) |
| `vdb_vex` *(local only)* | OpenVEX document: which advisories cannot be reached |

The four local-only tools need your files, so the hosted endpoint does not
offer them — seven tools remote, eleven with `uvx vdb-mcp`.

## The `vdb harden` command

The same package installs the CLI behind the local tools, for use without an
MCP client (0.2.2 or newer):

```bash
uvx --from vdb-mcp vdb harden app.py --manifest uv.lock   # analyze a call site
uvx --from vdb-mcp vdb harden --doctor                     # which of network / key / service is at fault
uvx --from vdb-mcp vdb harden ./src --manifest uv.lock --vex
uvx --from vdb-mcp vdb harden app.py --manifest uv.lock --remediate --target 0.2   # what to fix first
uvx --from vdb-mcp vdb harden ./src --manifest requirements.txt --exclude tests --exclude "*-fixtures"
uvx --from vdb-mcp vdb harden app.py --manifest uv.lock --verify P-… --original /tmp/before/app.py  # keyless re-verification
```

It works without a key (0.2.8+): three analyses an hour and ten a day per
address, nothing stored, upgrades estimated. `VDB_API_KEY` keeps the project,
re-scores it when a package on a path changes, and signs the evidence.

Where PyPI is unreachable, `https://vdb.ai.kr/v1/harden/client.pyz` is the
same CLI as one stdlib-only file (hash at `/v1/harden/client.sha256`):
`python3 client.pyz --doctor`. Nothing to install.

## Environment

| Variable | Default | Meaning |
|---|---|---|
| `VDB_API_URL` | `https://vdb.ai.kr` | VDB instance to query (set for self-hosted) |
| `VDB_API_TOKEN` | *(empty)* | `vdb_…` API key — lifts the keyless limits; required for lookup, search and SBOM scanning |
| `VDB_PROXY_TOKEN` | *(empty)* | Hosted endpoint only (0.2.9+): a secret shared with the API so it believes the visitor address this server forwards, and keyless visitors are counted each as themselves. Grants nothing else; leave unset locally |
| `VDB_API_ADDR` | `144.202.127.83` | Where VDB lives when this machine's DNS cannot say — see below |
| `MCP_MODE` | `stdio` | `stdio` or `sse` (long-running HTTP server) |
| `MCP_PORT` | `7700` | SSE port |

### No outbound DNS?

Sandboxes often allow egress but not name resolution. When — and only when —
resolving `vdb.ai.kr` fails, the server retries against `VDB_API_ADDR`. That
bypasses DNS and nothing else: the TLS handshake still presents the real
hostname and validates its certificate, so a pinned connection is exactly as
authenticated as a resolved one. HTTP errors, refused connections and
timeouts are never retried — the name resolved, so the address would be the
same box.

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
