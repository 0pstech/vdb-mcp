"""`vdb harden --apply` — 합성된 수정안(151)을 사용자 소스에 실제로 써 넣는다.

지금까지 CLI 는 패치를 **출력**만 했다. 래퍼 함수와 호출부 힌트를 사람이 옮겨
적어야 했고, 옮겨 적는 과정에서 래퍼 본문이 한 글자라도 달라지면 재검증(170)이
닫힘을 인정하지 않는다(synth.identify_trusted_wrapper 는 AST 완전 일치만 본다).
그래서 이 모듈이 그 옮겨 적기를 기계적으로 한다:

  1. 모듈에 래퍼 함수(_PY_WRAPPERS[sink])를 한 번 넣는다 — 같은 이름의 함수가
     이미 있으면 건드리지 않는다.
  2. 콜사이트의 오염 인자를 `vdb_safe_xxx(<원래 식>, kw=CONST)` 로 감싼다.
     synth.py 의 호출 힌트가 쓰는 키워드 자리표시자(allowed / allowed_hosts /
     schema)는 사람이 값을 채워야 하므로 모듈 상단의 상수로 뺀다 —
     `VDB_ALLOWED_HOSTS_<PATHID> = (...)  # TODO(vdb): fill in`. 파일은 그대로
     import 되고, 재검증은 래퍼가 적용된 것을 본다.
  3. 나머지 서식은 손대지 않는다 — libcst 는 주석·공백까지 왕복 보존한다.

libcst 는 이 모듈 안에서만, 함수 안에서 import 한다. 추상화 모듈(ir/sinks/
depgraph/synth/cli)은 표준 라이브러리만 써야 하고(client.pyz 가 그 위에 서
있다), --apply 를 쓰지 않는 사람이 설치를 요구받아서는 안 된다.
"""

from __future__ import annotations

import ast
import difflib
import re
from dataclasses import dataclass, field
from typing import Any

from .sinks import CMD_EXEC, DESERIALIZE, GLOBAL_STATE, NET_REQUEST
from .synth import _PY_WRAPPERS, _WRAPPER_NAME, identify_trusted_wrapper

# The keyword placeholders synth.py puts in its call hint, per sink:
# (keyword, constant prefix, placeholder value). The value is the one the
# hint shows, so a reader of the diff and a reader of --patch see the same.
_PLACEHOLDERS: dict[str, list[tuple[str, str, str]]] = {
    CMD_EXEC:     [("allowed", "VDB_ALLOWED", '{"expected-value"}')],
    DESERIALIZE:  [("schema", "VDB_SCHEMA", "dict")],
    NET_REQUEST:  [("allowed_hosts", "VDB_ALLOWED_HOSTS", '("api.example.com",)')],
    GLOBAL_STATE: [("allowed", "VDB_ALLOWED", '{"expected-key"}')],
}
TODO_MARK = "# TODO(vdb): fill in"

_INSTALL_HINT = ("--apply rewrites the file with libcst, which is not installed: "
                 "`pip install libcst` (the vdb-mcp package brings it along)")


class ApplyError(ValueError):
    """The fix could not be placed. The message is for the terminal."""


def constant_name(prefix: str, path_id: str) -> str:
    """`VDB_ALLOWED_HOSTS` + `P-2ceb4a35350f-net_request` → an identifier.

    The path id is in the name so two paths into different sinks in one
    module get their own value, and so a grep for the id finds the TODO."""
    return f"{prefix}_{re.sub(r'[^A-Za-z0-9]+', '_', path_id).strip('_').upper()}"


@dataclass
class ApplyResult:
    source: str                       # the rewritten module
    wrapper: str                      # vdb_safe_xxx
    changed: bool = False             # anything differs from the input
    call_rewritten: bool = False      # the argument was wrapped in this run
    already_applied: bool = False     # the argument was wrapped before this run
    wrapper_added: bool = False
    wrapper_trusted: bool = True      # the def in the file IS VDB's (AST match)
    constants_added: list[str] = field(default_factory=list)

    def diff(self, original: str, name: str) -> str:
        return "".join(difflib.unified_diff(
            original.splitlines(keepends=True), self.source.splitlines(keepends=True),
            fromfile=f"a/{name}", tofile=f"b/{name}"))

    def to_dict(self) -> dict[str, Any]:
        return {"wrapper": self.wrapper, "changed": self.changed,
                "call_rewritten": self.call_rewritten,
                "already_applied": self.already_applied,
                "wrapper_added": self.wrapper_added,
                "wrapper_trusted": self.wrapper_trusted,
                "constants_added": list(self.constants_added)}


def apply_fix(source: str, *, line: int, api: str, arg: str, sink: str,
              path_id: str) -> ApplyResult:
    """Place the fix for one path: wrapper def, constants, wrapped argument.

    `line`/`api`/`arg` come from the IR call site the path was decided on
    (CallSite.line, CallSite.api, PathHop.arg — a positional index as a
    string, or the keyword name). Running it on an already-fixed module
    changes nothing and reports `already_applied`.
    """
    try:
        import libcst as cst
        from libcst.metadata import MetadataWrapper, PositionProvider
    except ImportError:                     # pragma: no cover — environment
        raise ApplyError(_INSTALL_HINT) from None

    wrapper_src = _PY_WRAPPERS.get(sink)
    wname = _WRAPPER_NAME.get(sink)
    if not wrapper_src or not wname:
        raise ApplyError(f"no call-site wrapper is synthesized for the {sink} sink")
    kwargs = [(kw, constant_name(prefix, path_id), value)
              for kw, prefix, value in _PLACEHOLDERS.get(sink, [])]

    try:
        module = cst.parse_module(source)
    except cst.ParserSyntaxError as e:
        raise ApplyError(f"the file does not parse: {e}") from None

    # ── 2. the call-site argument ─────────────────────────────────────────
    # A template call carries the keyword formatting (`kw=CONST`, no spaces),
    # so the rewrite only has to drop the original expression into slot 0.
    template = cst.parse_expression(
        f"{wname}(__vdb__" + "".join(f", {kw}={const}" for kw, const, _ in kwargs) + ")")

    class Rewrite(cst.CSTTransformer):
        METADATA_DEPENDENCIES = (PositionProvider,)

        def __init__(self) -> None:
            super().__init__()
            self.found = False
            self.touched = False
            self.already = False

        def leave_Call(self, original: cst.Call, updated: cst.Call) -> cst.BaseExpression:
            if self.found:
                return updated
            if self.get_metadata(PositionProvider, original).start.line != line:
                return updated
            if not _call_is(original.func, api):
                return updated
            idx = _arg_index(updated.args, arg)
            if idx is None:
                return updated
            self.found = True
            a = updated.args[idx]
            value, touched, already = _wrap(a.value, wname, template)
            self.touched, self.already = touched, already
            if not touched:
                return updated
            args = list(updated.args)
            args[idx] = a.with_changes(value=value)
            return updated.with_changes(args=args)

    rewrite = Rewrite()
    module = MetadataWrapper(module, unsafe_skip_copy=True).visit(rewrite)
    if not rewrite.found:
        raise ApplyError(
            f"no call to {api} taking argument {arg!r} starts on line {line}: "
            "the file changed since the analysis — re-run without --apply first")
    res = ApplyResult(source=source, wrapper=wname,
                      call_rewritten=rewrite.touched, already_applied=rewrite.already)

    # ── 1. + placeholders: module-level insertions ────────────────────────
    body = list(module.body)
    have_def = {s.name.value for s in body if isinstance(s, cst.FunctionDef)}
    have_const = {
        t.target.value
        for s in body if isinstance(s, cst.SimpleStatementLine)
        for st in s.body if isinstance(st, cst.Assign)
        for t in st.targets if isinstance(t.target, cst.Name)
    }
    insert: list[cst.BaseStatement] = []
    for kw, const, value in kwargs:
        if const in have_const:
            continue
        stmt = cst.parse_statement(f"{const} = {value}  {TODO_MARK}\n")
        if not insert:
            stmt = stmt.with_changes(leading_lines=[cst.EmptyLine()])
        insert.append(stmt)
        res.constants_added.append(const)
    if wname not in have_def:
        fn = cst.parse_module(wrapper_src).body[0]
        insert.append(fn.with_changes(leading_lines=[cst.EmptyLine(), cst.EmptyLine()]))
        res.wrapper_added = True
    if insert:
        at = _insertion_point(body)
        if at < len(body):
            # Two blank lines after a def, as the next statement's leading
            # lines; one is enough after a constant.
            want = 2 if res.wrapper_added else 1
            nxt = body[at]
            blanks = sum(1 for ln in nxt.leading_lines if not ln.comment)
            if blanks < want:
                nxt = nxt.with_changes(
                    leading_lines=[cst.EmptyLine()] * (want - blanks) + list(nxt.leading_lines))
                body[at] = nxt
        body[at:at] = insert
        module = module.with_changes(body=body)

    res.source = module.code
    res.changed = res.source != source
    if not res.wrapper_added:
        # A def by that name was already there. Only VDB's exact wrapper is
        # credited at re-verification, so say now whether this one will be.
        res.wrapper_trusted = any(
            isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) and n.name == wname
            and bool(identify_trusted_wrapper(n))
            for n in ast.parse(res.source).body)
    return res


# ── helpers ────────────────────────────────────────────────────────────────

def _call_is(func, api: str) -> bool:
    """`requests.get` / `get` / `s.get` all answer to the IR's `get`; an
    object method is recorded as `Session.get`, so the last segment is
    what the call shows."""
    import libcst as cst
    want = api.split(".")[-1]
    if isinstance(func, cst.Name):
        return func.value == want
    if isinstance(func, cst.Attribute):
        return func.attr.value == want
    return False


def _arg_index(args, arg: str) -> int | None:
    import libcst as cst
    if arg.isdigit():
        n = int(arg)
        pos = 0
        for i, a in enumerate(args):
            if a.keyword is not None:
                continue
            if a.star:                       # *x / **x: positions past it are unknowable
                return None
            if pos == n:
                return i
            pos += 1
        return None
    for i, a in enumerate(args):
        if a.keyword is not None and isinstance(a.keyword, cst.Name) and a.keyword.value == arg:
            return i
    return None


def _is_wrapped(node, wname: str) -> bool:
    import libcst as cst
    return (isinstance(node, cst.Call) and isinstance(node.func, cst.Name)
            and node.func.value == wname)


def _is_literal(node) -> bool:
    import libcst as cst
    if isinstance(node, (cst.SimpleString, cst.ConcatenatedString, cst.Integer,
                         cst.Float, cst.Imaginary)):
        return True
    return isinstance(node, cst.Name) and node.value in ("True", "False", "None")


def _wrap(value, wname: str, template):
    """(new value, touched, already wrapped).

    `subprocess.run([user_input])` passes a list: the allowlist belongs on
    the element, not on the list's repr, so a List/Tuple/Set literal gets
    each non-literal element wrapped and anything else is wrapped whole.
    """
    import libcst as cst

    def wrap_one(expr):
        args = list(template.args)
        args[0] = args[0].with_changes(value=expr)
        return template.with_changes(args=args)

    if isinstance(value, (cst.List, cst.Tuple, cst.Set)):
        elements = []
        touched = already = False
        for el in value.elements:
            inner = el.value
            if isinstance(el, cst.StarredElement) or _is_literal(inner):
                elements.append(el)
            elif _is_wrapped(inner, wname):
                already = True
                elements.append(el)
            else:
                touched = True
                elements.append(el.with_changes(value=wrap_one(inner)))
        if not touched:
            return value, False, already
        return value.with_changes(elements=elements), True, False
    if _is_wrapped(value, wname):
        return value, False, True
    return wrap_one(value), True, False


def _insertion_point(body) -> int:
    """After the last fix this tool already placed (a second path's wrapper
    goes below the first, in the order they were applied), else after the
    last top-level import, else after the docstring, else 0 — `from
    __future__` is never displaced from the top."""
    import libcst as cst
    last_import = last_vdb = -1
    for i, s in enumerate(body):
        if isinstance(s, cst.FunctionDef) and s.name.value in _WRAPPER_NAME.values():
            last_vdb = i
        elif isinstance(s, cst.SimpleStatementLine):
            if any(isinstance(st, (cst.Import, cst.ImportFrom)) for st in s.body):
                last_import = i
            elif any(isinstance(st, cst.Assign) and any(
                    isinstance(t.target, cst.Name) and t.target.value.startswith("VDB_")
                    for t in st.targets) for st in s.body):
                last_vdb = i
    if last_vdb >= 0:
        return last_vdb + 1
    if last_import >= 0:
        return last_import + 1
    if body and isinstance(body[0], cst.SimpleStatementLine) and body[0].body and \
            isinstance(body[0].body[0], cst.Expr) and \
            isinstance(body[0].body[0].value, (cst.SimpleString, cst.ConcatenatedString)):
        return 1
    return 0
