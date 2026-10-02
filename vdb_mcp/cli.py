"""`vdb` — the command-line entry point of the vdb-mcp package.

Every page and document says `vdb harden ...`, and until 0.2.2 no package
installed a `vdb` command: the wheel's only entry point was `vdb-mcp`. Two
independent evaluations ran `uvx --from vdb-mcp vdb harden --doctor` and
would have failed on that alone, had their sandbox let them get that far.

`harden` is the only subcommand. It dispatches to the vendored CLI, which
is the same file the monorepo's `bin/vdb harden` runs.
"""

from __future__ import annotations

import sys

from . import __version__

_USAGE = (
    "usage: vdb harden <file.py|dir> [--manifest <lock>] "
    "[--patch|--rules|--emit-ir|--verify <path_id>|--vex|--json]\n"
    "       vdb harden --doctor\n"
    "       vdb --version\n"
)


def main(argv: list[str] | None = None) -> int:
    args = list(sys.argv[1:] if argv is None else argv)
    if args and args[0] in {"--version", "-V"}:
        print(f"vdb-mcp {__version__}")
        return 0
    if not args or args[0] in {"-h", "--help"}:
        sys.stdout.write(_USAGE)
        return 0 if args else 2
    if args[0] != "harden":
        sys.stderr.write(f"vdb: unknown command {args[0]!r}\n{_USAGE}")
        return 2
    from .harden.cli import main as harden_main
    return harden_main(args[1:])


if __name__ == "__main__":
    sys.exit(main())
