"""Vendored copy of the local-abstraction half of vdb.harden.

Why a copy and not an import: `vdb-mcp` ships to PyPI on its own, and the
abstraction MUST run on the developer's machine — that is the whole privacy
property of the feature (only the IR and the lockfile leave the host, never
source text). Depending on the server package would drag psycopg, FastAPI and
the rest of the API in for these stdlib-only modules.

Source of truth is docker/app/vdb/harden/. `./vendor-harden.sh` refreshes these, and
tests/test_vendored_harden.py fails loudly if they drift — a stale abstraction
here would quietly send a DIFFERENT IR than the CLI does, and the analysis
cache is keyed on that IR's fingerprint.
"""
