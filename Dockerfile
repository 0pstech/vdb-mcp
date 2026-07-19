# ─────────────────────────────────────────────────────────────────────────────
#  vdb-mcp — MCP server that wraps the VDB REST API.
#
#  Usage (stdio mode, for Claude Desktop / Cursor):
#      docker run -i --rm \
#          -e VDB_API_URL=http://host.docker.internal:8080 \
#          vdb/mcp:dev
#
#  Usage (HTTP/SSE mode, for remote clients):
#      docker run -d -p 7700:7700 -e MCP_MODE=sse vdb/mcp:dev
# ─────────────────────────────────────────────────────────────────────────────

FROM python:3.12-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates tini \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
RUN pip install --no-cache-dir "mcp>=1.0.0" "httpx>=0.27.0"

COPY vdb_mcp /app/vdb_mcp

ENV VDB_API_URL=http://api:8080 \
    MCP_MODE=stdio \
    MCP_PORT=7700

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["python", "-m", "vdb_mcp.server"]
