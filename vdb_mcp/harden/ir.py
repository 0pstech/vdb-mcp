"""추상화 인테이크부(110) — 원본 코드 → 추상화된 코드 표현(32). 도 4.

명세 【0044】~【0048】 및 청구항 7 그대로:

  S410 파싱          언어별 파서로 AST
  S420 식별자 정규화  변수 `fname` → `v1`, 호출 대상 → `f1#pkgA.resize`
                     (스코프 깊이·선언 순서 조합으로 결정적)
  S430 리터럴 마스킹  "acme-2026" → STR<len:9, [a-z0-9-]>  (역산 불가)
  S440 상수 제거     모듈 최상위 상수·설정 임포트 → CONST (값 미전송)
  S450 IR 생성       할당·연결·함수 호출 인자 전달·반환값 전파는 **보존**

핵심 성질: 이 함수는 **클라이언트에서 돈다**. 서버로 나가는 것은 IR 뿐이고
식별자 원문·리터럴 값·비즈니스 상수는 프로세스를 떠나지 않는다(【0106】).

부가로, 콜사이트 인자에 적용된 **정화 함수(sanitizer)**를 탐지해 함께 싣는다.
재검증(170)에서 "경로가 닫혔는지"를 판정하려면 경계에 무엇이 적용됐는지를
알아야 하는데, 그 정보는 사용자 코드 안에만 있기 때문이다.
"""

from __future__ import annotations

import ast
import hashlib
import os
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .sinks import CONCAT, IDENTITY, classify_call_transform, merge_transform

IR_VERSION = 1

# 오염 소스로 보는 것들 — 명세 미기재(설계 자유도). 함수 파라미터를 기본
# 소스로 두고(가장 흔한 신뢰 불가 입력 경로), 명시적인 외부 입력도 포함한다.
_SOURCE_CALLS = ("input", "sys.argv", "os.environ", "request.args", "request.form",
                 "request.json", "request.files", "flask.request", "os.getenv",
                 "request.query_params", "request.GET", "request.POST",
                 "request.headers", "request.cookies", "request.data")


def _reads_external_input(expr: ast.AST) -> bool:
    """Does this expression read one of the known request/environment sources?

    Half of the names above are containers, not functions, and the way a web
    handler actually reads them is with brackets:

        request.args["avatar_url"]      # Flask
        request.GET["next"]             # Django
        os.environ["UPSTREAM"]

    Only `ast.Call` used to count, so the single most common shape of the
    single most common source went unrecognised and the whole analysis
    started from nothing. Attribute and subscript reads count now, and the
    prefix is matched on dotted components so `myrequest.argsfoo` cannot.
    """
    for n in ast.walk(expr):
        dotted = ""
        if isinstance(n, ast.Call):
            dotted = _dotted(n.func)
        elif isinstance(n, ast.Subscript):
            dotted = _dotted(n.value)
        elif isinstance(n, ast.Attribute):
            dotted = _dotted(n)
        if not dotted:
            continue
        for p in _SOURCE_CALLS:
            if dotted == p or dotted.endswith("." + p):
                return True
    return False

@dataclass
class CallSiteArg:
    index: int
    name: str                 # 키워드면 이름, 위치면 str(index)
    symbol: str               # 정규화된 심볼 (v1 / CONST / STR<...>)
    tainted: bool
    transform: str = IDENTITY
    sanitizers: list[str] = field(default_factory=list)   # 적용된 정화 연산 식별자

    def to_dict(self) -> dict[str, Any]:
        return {"index": self.index, "name": self.name, "symbol": self.symbol,
                "tainted": self.tainted, "transform": self.transform,
                "sanitizers": self.sanitizers}


@dataclass
class CallSite:
    """대상 애플리케이션이 제1 패키지를 호출하는 지점(15)."""
    id: str
    module: str               # import 된 모듈명 (= 제1 패키지 후보)
    api: str                  # 호출한 함수/메서드 이름
    symbol: str               # f1#module.api
    line: int
    args: list[CallSiteArg] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {"id": self.id, "module": self.module, "api": self.api,
                "symbol": self.symbol, "line": self.line,
                "args": [a.to_dict() for a in self.args]}


@dataclass
class CodeIR:
    """추상화된 코드 표현(32)."""
    version: int = IR_VERSION
    language: str = "python"
    # Opaque file ids this IR was built from. Paths and project names never
    # leave the client; only the count and deterministic per-run ids travel.
    #
    # This exists because of VEX. A "no attacker-controlled data reaches this
    # package" claim is only as wide as the code it was derived from: assert it
    # from one file while the rest of the tree calls the same package, and the
    # attestation is simply false. The document has to be able to state its own
    # scope, so the IR has to carry it.
    files: list[str] = field(default_factory=list)
    # Files under the analysis root that could not be parsed. Coverage gaps
    # are the difference between an honest not_affected and a false one, so
    # they travel with the IR instead of being swallowed.
    unparsed: list[str] = field(default_factory=list)
    sources: list[dict[str, Any]] = field(default_factory=list)
    flows: list[dict[str, Any]] = field(default_factory=list)      # 할당/연결 보존
    callsites: list[CallSite] = field(default_factory=list)
    masked_literals: int = 0
    removed_constants: int = 0
    # 추상화 손실도 — 확신도 산출(S740)의 세 번째 인자. 명세는 정의를 두지 않아
    # "해석하지 못한 호출 / 전체 호출" 비율로 정한다(설계 자유도).
    loss: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "language": self.language,
                "files": self.files, "unparsed": self.unparsed,
                "sources": self.sources, "flows": self.flows,
                "callsites": [c.to_dict() for c in self.callsites],
                "masked_literals": self.masked_literals,
                "removed_constants": self.removed_constants,
                "loss": round(self.loss, 3)}

    def fingerprint(self) -> str:
        """코드 지문 — 2-티어 캐시 키의 절반(【0056】)."""
        body = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(body.encode()).hexdigest()


# ── S430: 리터럴 마스킹 ────────────────────────────────────────────────────

def mask_literal(v: Any) -> str:
    """형태 정보만 남기고 값은 버린다. 원본으로 역산할 수 없어야 한다."""
    if isinstance(v, str):
        cls = []
        if re.search(r"[a-z]", v):
            cls.append("a-z")
        if re.search(r"[A-Z]", v):
            cls.append("A-Z")
        if re.search(r"\d", v):
            cls.append("0-9")
        if re.search(r"[-_./\\]", v):
            cls.append("-_./")
        return f"STR<len:{len(v)}, [{''.join(cls) or 'other'}]>"
    if isinstance(v, bool):
        return "BOOL"
    if isinstance(v, (int, float)):
        sign = "-" if v < 0 else "+"
        return f"NUM<digits:{len(str(abs(v)).replace('.', ''))}, sign:{sign}>"
    if v is None:
        return "NONE"
    return "LIT"


def _dotted(node: ast.AST) -> str:
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return ".".join(reversed(parts))


class _Abstractor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.ir = CodeIR()
        self.symbols: dict[tuple[str, str], str] = {}
        self.tainted: dict[str, str] = {}     # 심볼 → 변형 클래스
        self.sanitizers_applied: dict[str, list[str]] = {}   # 심볼 → 적용된 연산
        self.imports: dict[str, str] = {}     # alias → 모듈 최상위 이름
        self.module_consts: set[str] = set()
        self.local_funcs: dict[str, list[str]] = {}   # 지역 함수 → 정화 연산 목록
        self.scope = "module"
        self.local_names: set[str] = set()
        # Locals bound to an object constructed from a dependency:
        #   s = requests.Session()   ->  {"s": ("requests", "Session")}
        # Without this, `s.get(url)` has a head that is not an import, so the
        # call site is dropped entirely and the tainted argument never reaches
        # the composer. Session/Client objects are the documented way to reuse
        # connections in requests, httpx, boto3 and most of their peers, so
        # this is not an edge case — it is how the libraries are meant to be
        # used.
        self.obj_of: dict[str, tuple[str, str]] = {}
        self._n = 0
        self._calls_total = 0
        self._calls_unresolved = 0

    # S420 — 스코프 내 등장 순서로 결정적 심볼 부여
    def sym(self, name: str) -> str:
        key = (self.scope, name)
        if key not in self.symbols:
            self._n += 1
            self.symbols[key] = f"v{self._n}"
        return self.symbols[key]

    def _lookup_sym(self, name: str) -> str | None:
        return (self.symbols.get((self.scope, name))
                or self.symbols.get(("module", name)))

    # ── 준비: 모듈 최상위 상수와 지역 함수(정화 후보) 수집 ──────────────
    def prepare(self, tree: ast.Module, src: str) -> None:
        for stmt in tree.body:
            if isinstance(stmt, ast.Assign):
                try:
                    ast.literal_eval(stmt.value)
                    static_value = True
                except (ValueError, TypeError):
                    static_value = False
                if static_value:
                    for t in stmt.targets:
                        if isinstance(t, ast.Name):
                            self.module_consts.add(t.id)
            elif isinstance(stmt, ast.Import):
                for a in stmt.names:
                    self.imports[a.asname or a.name.split(".")[0]] = a.name.split(".")[0]
            elif isinstance(stmt, ast.ImportFrom) and stmt.module:
                top = stmt.module.split(".")[0]
                for a in stmt.names:
                    self.imports[a.asname or a.name] = top
                    # `from x import CONFIG` 형태의 설정 임포트도 상수로 본다.
                    if a.name.isupper():
                        self.module_consts.add(a.asname or a.name)
            elif isinstance(stmt, (ast.FunctionDef, ast.AsyncFunctionDef)):
                # Only byte-for-byte structural matches to VDB's reviewed
                # wrappers are credited. Regexes over an entire function used
                # to treat dead or unrelated checks as applied defenses.
                from .synth import identify_trusted_wrapper
                ops = identify_trusted_wrapper(stmt)
                if ops:
                    self.local_funcs[stmt.name] = ops

    # ── 식의 오염 상태 ──────────────────────────────────────────────────
    def taint_of(self, expr: ast.AST) -> tuple[bool, str, list[str], str]:
        """(오염됨, 변형, 적용된 정화 연산, 심볼)"""
        tainted = False
        transform = IDENTITY
        sanit: list[str] = []
        symbol = "LIT"

        for n in ast.walk(expr):
            if isinstance(n, ast.Name):
                s = self._lookup_sym(n.id)
                if n.id in self.module_consts and n.id not in self.local_names:
                    symbol = "CONST"
                    self.ir.removed_constants += 1
                elif s and s in self.tainted:
                    tainted = True
                    transform = merge_transform(transform, self.tainted[s])
                    symbol = s
                    sanit.extend(self.sanitizers_applied.get(s, []))
            elif isinstance(n, ast.Constant):
                symbol = mask_literal(n.value)
                self.ir.masked_literals += 1
            elif isinstance(n, (ast.JoinedStr,)):
                transform = merge_transform(transform, CONCAT)
            elif isinstance(n, ast.BinOp) and isinstance(n.op, (ast.Add, ast.Mod)):
                transform = merge_transform(transform, CONCAT)
            elif isinstance(n, ast.Call):
                name = _dotted(n.func)
                c = classify_call_transform(name)
                if c:
                    transform = merge_transform(transform, c)
                # 지역 정화 함수를 거쳤는가 — 경계에 무엇이 적용됐는지의 근거
                base = name.split(".")[-1]
                if base in self.local_funcs:
                    sanit.extend(self.local_funcs[base])
        # A request/environment read is a source wherever it appears, not only
        # when it is first assigned to a name. `requests.get(request.args["u"])`
        # is one line of real Flask and used to abstract to a clean call.
        if not tainted and _reads_external_input(expr):
            tainted = True
            if not symbol.startswith("v"):
                symbol = "EXT"
        return tainted, transform, sorted(set(sanit)), symbol

    # ── 방문 ────────────────────────────────────────────────────────────
    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        old_scope, old_locals = self.scope, self.local_names
        old_tainted, old_sanitizers = self.tainted, self.sanitizers_applied
        old_obj_of = self.obj_of
        self.scope = f"fn:{getattr(node, 'lineno', 0)}:{node.name}"
        self.local_names = {
            n.id for n in ast.walk(node)
            if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)
        }
        self.local_names.update(
            a.arg for a in list(node.args.posonlyargs) + list(node.args.args)
            + list(node.args.kwonlyargs))
        # Module-level inputs remain visible inside functions, while a local
        # assignment gets its own scoped symbol and therefore shadows them.
        self.tainted = dict(old_tainted)
        self.sanitizers_applied = {
            key: list(value) for key, value in old_sanitizers.items()
        }
        # Module-level dependency objects remain visible, but objects created
        # in one function must not leak into the next function's scope.
        self.obj_of = dict(old_obj_of)
        # 함수 파라미터 = 기본 오염 소스
        for a in list(node.args.posonlyargs) + list(node.args.args) + list(node.args.kwonlyargs):
            if a.arg in ("self", "cls"):
                continue
            s = self.sym(a.arg)
            self.tainted[s] = IDENTITY
            self.ir.sources.append({"symbol": s, "kind": "param"})
        self.generic_visit(node)
        self.scope, self.local_names = old_scope, old_locals
        self.tainted, self.sanitizers_applied = old_tainted, old_sanitizers
        self.obj_of = old_obj_of

    visit_AsyncFunctionDef = visit_FunctionDef  # type: ignore[assignment]

    def visit_With(self, node: ast.With) -> None:
        # `with httpx.Client() as c:` — the context-manager form is the one
        # the docs actually recommend, so it must bind too.
        for item in node.items:
            if item.optional_vars is not None:
                self._bind_object(item.optional_vars, item.context_expr)
        self.generic_visit(node)

    visit_AsyncWith = visit_With

    def visit_Assign(self, node: ast.Assign) -> None:
        for t in node.targets:
            self._bind_object(t, node.value)
        tainted, transform, sanit, src_sym = self.taint_of(node.value)
        # 명시적 외부 입력도 소스로 승격
        if _reads_external_input(node.value):
            tainted = True
        for t in node.targets:
            if isinstance(t, ast.Name):
                dst = self.sym(t.id)
                if tainted:
                    self.tainted[dst] = transform
                    if sanit:
                        self.sanitizers_applied[dst] = sanit
                    source_symbol = src_sym if src_sym.startswith("v") else dst
                    if not any(s["symbol"] == source_symbol for s in self.ir.sources):
                        self.ir.sources.append({"symbol": source_symbol, "kind": "input"})
                else:
                    self.tainted.pop(dst, None)
                    self.sanitizers_applied.pop(dst, None)
                # 할당 관계는 IR 에 보존한다(청구항 7).
                self.ir.flows.append({"from": src_sym, "to": dst,
                                      "transform": transform, "kind": "assign"})
        self.generic_visit(node)

    def _bind_object(self, target: ast.AST, value: ast.AST) -> None:
        """`x = dep.Thing(...)` — remember that x is a dep.Thing."""
        def bound_names(node: ast.AST) -> list[str]:
            if isinstance(node, ast.Name):
                return [node.id]
            if isinstance(node, ast.Starred):
                return bound_names(node.value)
            if isinstance(node, (ast.Tuple, ast.List)):
                return [
                    name for element in node.elts
                    for name in bound_names(element)
                ]
            return []

        names = bound_names(target)
        # A straight-line reassignment invalidates the previous receiver type.
        # Keeping it would turn `x = requests.Session(); x = local(); x.get()`
        # into a fabricated dependency call.
        for name in names:
            self.obj_of.pop(name, None)
        if not isinstance(value, ast.Call):
            return
        d = _dotted(value.func)
        if not d or "." not in d:
            return
        head, _, rest = d.partition(".")
        mod = self.imports.get(head)
        # Constructors are Capitalised by near-universal convention. Binding
        # every call result would make `x = requests.get(u)` look like an
        # object and attach later `x.<anything>` calls to the wrong API.
        if not mod or not rest.split(".")[-1][:1].isupper():
            return
        for name in names:
            self.obj_of[name] = (mod, rest)

    def visit_Call(self, node: ast.Call) -> None:
        self._calls_total += 1
        dotted = _dotted(node.func)
        head = dotted.split(".")[0]
        api = dotted.split(".")[-1]
        module = self.imports.get(head)
        if module is None and head in self.obj_of:
            # Method on a dependency object. Report it under the class so the
            # summary side can match `requests.Session.get` rather than a bare
            # `get` that could be anything.
            mod, cls = self.obj_of[head]
            module, api = mod, f"{cls}.{api}" if api != head else cls
        if module is None:
            self._calls_unresolved += 1
        else:
            cs = CallSite(
                id=f"c{len(self.ir.callsites) + 1}",
                module=module, api=api,
                symbol=f"f{len(self.ir.callsites) + 1}#{module}.{api}",
                line=getattr(node, "lineno", 0),
            )
            for i, a in enumerate(node.args):
                t, tf, sn, sym = self.taint_of(a)
                cs.args.append(CallSiteArg(i, str(i), sym, t, tf, sn))
            for k in node.keywords:
                if k.arg:
                    t, tf, sn, sym = self.taint_of(k.value)
                    cs.args.append(CallSiteArg(-1, k.arg, sym, t, tf, sn))
            self.ir.callsites.append(cs)
        self.generic_visit(node)


def build_ir(source: str) -> CodeIR:
    """S410~S450 — 원본 코드 문자열에서 추상화된 코드 표현을 만든다."""
    tree = ast.parse(source)
    ab = _Abstractor()
    ab.prepare(tree, source)
    ab.visit(tree)
    total = max(1, ab._calls_total)
    ab.ir.loss = round(ab._calls_unresolved / total, 3)
    return ab.ir


def build_ir_from_file(path: str) -> CodeIR:
    with open(path, encoding="utf-8", errors="ignore") as fh:
        ir = build_ir(fh.read())
    ir.files = ["F0001"]
    return ir


# Directories that are not application entry points. Analysing them would
# inflate the reachable set with call sites no deployed code executes, which
# makes a not_affected claim *weaker*, not stronger.
_SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".tox",
              ".mypy_cache", ".pytest_cache", "build", "dist", ".eggs",
              "site-packages", "tests", "test"}


def build_ir_from_tree(root: str, max_files: int = 2000) -> CodeIR:
    """Abstract every Python file under `root` into ONE representation.

    Per-file analysis cannot support a not_affected claim: "nothing reaches
    urllib3" derived from app.py says nothing about the other forty modules
    that also import it. VEX statements are only as wide as the code behind
    them, so the whole tree goes in and `files` records exactly what that was.

    A file that fails to parse is skipped and named in `unparsed` rather than
    failing the run — one syntax error in a scratch file should not block the
    analysis — but it also means coverage is incomplete, and the caller has to
    be able to see that before attesting to anything.
    """
    merged = CodeIR()
    unparsed: list[str] = []
    losses: list[float] = []
    seen_callsite_ids: set[str] = set()

    paths: list[str] = []
    total_python_files = 0
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in _SKIP_DIRS and not d.startswith(".")
        )
        for fn in sorted(filenames):
            if fn.endswith(".py"):
                total_python_files += 1
                if len(paths) < max_files:
                    paths.append(os.path.join(dirpath, fn))

    ordered = sorted(paths)
    if total_python_files > max_files:
        unparsed.append(f"LIMITED:{total_python_files - max_files}")

    def scoped_symbol(symbol: str, opaque: str) -> str:
        # vN/fN identifiers are allocated independently by every per-file
        # abstractor. Prefix them before merging so flows and call arguments
        # cannot accidentally refer to a symbol from another file.
        if re.match(r"^[vf]\d+(?:#|$)", symbol):
            return f"{opaque}:{symbol}"
        return symbol

    for file_index, path in enumerate(ordered, start=1):
        opaque = f"F{file_index:04d}"
        try:
            with open(path, encoding="utf-8", errors="ignore") as fh:
                one = build_ir(fh.read())
        except (SyntaxError, ValueError, OSError):
            unparsed.append(opaque)
            continue
        merged.files.append(opaque)
        losses.append(one.loss)
        merged.masked_literals += one.masked_literals
        merged.removed_constants += one.removed_constants
        for source in one.sources:
            copied = dict(source)
            copied["symbol"] = scoped_symbol(str(copied["symbol"]), opaque)
            merged.sources.append(copied)
        for flow in one.flows:
            copied = dict(flow)
            copied["from"] = scoped_symbol(str(copied["from"]), opaque)
            copied["to"] = scoped_symbol(str(copied["to"]), opaque)
            merged.flows.append(copied)
        for cs in one.callsites:
            # Symbol ids are per-file (`c1`, `c2`, …); prefix them so two files
            # do not collide into one call site and silently drop a path.
            cs.id = f"{opaque}:{cs.id}"
            cs.symbol = scoped_symbol(cs.symbol, opaque)
            for arg in cs.args:
                arg.symbol = scoped_symbol(arg.symbol, opaque)
            if cs.id in seen_callsite_ids:
                continue
            seen_callsite_ids.add(cs.id)
            merged.callsites.append(cs)

    merged.loss = round(sum(losses) / len(losses), 3) if losses else 0.0
    merged.unparsed = unparsed
    return merged
