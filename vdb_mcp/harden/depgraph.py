"""의존성 그래프 해석부(120) — 락파일/SBOM → 버전이 해석된 전이 의존성 그래프.

명세 【0034】: "노드가 (패키지, 버전) 쌍으로, 간선이 의존 관계로 표현되는 방향
그래프" 이며 "락파일 또는 SBOM으로부터 버전이 고정된 결정적 그래프를 구성하므로,
레지스트리에 대한 실시간 조회 없이도 정확한 버전 정보에 기초한 판정이 가능".

지원 입력(간선 보유 여부):
    uv.lock          ✓ 간선 O — [[package]].dependencies = [{name=…}]
    poetry.lock      ✓ 간선 O — [package.dependencies] 테이블
    CycloneDX(JSON)  ✓ 간선 O — dependencies[].dependsOn  (없으면 평면으로 강등)
    Pipfile.lock     ✗ 평면   — 잠금 버전만, 간선 없음
    requirements.txt ✗ 평면   — 직접 의존성만

간선이 없는 입력도 거부하지 않는다. 우리 자체 SBOM(vdb.cdx.json)이 그렇듯 평면
SBOM은 현실에 흔하고, 그런 노드는 합성 단계에서 청구항 5의 보수적 통과 가정으로
흡수되며 그 사실이 확신도에 반영된다(전개는 되지만 확신도가 낮아진다).
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Optional


class GraphParseError(ValueError):
    """입력을 그래프로 해석할 수 없음. 호출자는 400으로 변환한다."""


# ── 이름 정규화 ─────────────────────────────────────────────────────────────
# PEP 503: 배포 이름 비교는 [-_.] 연속을 '-' 하나로 접고 소문자화한 형태로 한다.
# 락파일마다 표기가 달라(zope.interface / zope-interface) 정규화 없이는 같은
# 패키지가 다른 노드로 갈라진다.
_NORM_RE = re.compile(r"[-_.]+")


def normalize_name(name: str) -> str:
    return _NORM_RE.sub("-", (name or "").strip()).lower()


@dataclass(frozen=True)
class DepNode:
    """그래프의 노드 = (패키지, 버전) 쌍."""

    name: str          # 정규화된 배포 이름
    version: str       # 락파일이 고정한 구체 버전 ("" = 미해석)
    ecosystem: str = "pypi"

    @property
    def id(self) -> str:
        # PyPI ids retain the historic compact spelling because the Python
        # analyzer and stored recompose index use it.  Other ecosystems carry
        # an explicit prefix so a mixed CycloneDX document cannot collapse
        # `pkg:npm/foo@1` and `pkg:pypi/foo@1` into the same dictionary key.
        base = f"{self.name}@{self.version}" if self.version else self.name
        return base if self.ecosystem == "pypi" else f"{self.ecosystem}:{base}"

    @property
    def purl(self) -> str:
        base = f"pkg:{self.ecosystem}/{self.name}"
        return f"{base}@{self.version}" if self.version else base


@dataclass
class DepGraph:
    """버전이 해석된 전이 의존성 그래프."""

    fmt: str                                   # 입력 포맷 태그
    nodes: dict[str, DepNode] = field(default_factory=dict)   # id -> node
    edges: set[tuple[str, str]] = field(default_factory=set)  # (from_id, to_id)
    roots: list[str] = field(default_factory=list)            # 직접 의존성 노드 id
    # 이름이 여러 버전으로 잠긴 경우(마커별 해석 등) 간선을 모든 버전으로 잇고
    # 여기에 기록한다 — 보수적(경로를 놓치지 않음) 선택이며, 확신도 산출에서
    # 참조할 수 있도록 노출한다.
    ambiguous_names: set[str] = field(default_factory=set)

    # ── 조회 ────────────────────────────────────────────────────────────
    @property
    def has_edges(self) -> bool:
        return bool(self.edges)

    def ids_for(self, name: str) -> list[str]:
        n = normalize_name(name)
        return sorted(i for i, node in self.nodes.items() if node.name == n)

    def find(self, name: str) -> Optional[str]:
        """이름으로 노드 id 하나를 찾는다(여러 버전이면 가장 낮은 id)."""
        ids = self.ids_for(name)
        return ids[0] if ids else None

    def successors(self, node_id: str) -> list[str]:
        return sorted(dst for src, dst in self.edges if src == node_id)

    def reachable_from(self, node_id: str) -> "DepGraph":
        """제1 패키지에서 도달 가능한 부분그래프.

        합성 엔진은 콜사이트가 부르는 제1 패키지에서 시작해 간선을 따라 전개하므로
        (명세 S610~S630), 그 시점에 필요한 것은 전체 그래프가 아니라 이 부분그래프다.
        순환 의존성이 있어도 방문 집합으로 유한 종료한다.
        """
        if node_id not in self.nodes:
            raise KeyError(node_id)
        seen: set[str] = set()
        stack = [node_id]
        while stack:
            cur = stack.pop()
            if cur in seen:
                continue
            seen.add(cur)
            stack.extend(self.successors(cur))
        return DepGraph(
            fmt=self.fmt,
            nodes={i: n for i, n in self.nodes.items() if i in seen},
            edges={(a, b) for a, b in self.edges if a in seen and b in seen},
            roots=[node_id],
            ambiguous_names=set(self.ambiguous_names),
        )

    # ── 해시 ────────────────────────────────────────────────────────────
    def graph_hash(self) -> str:
        """명세 【0056】의 "의존성 그래프 해시" — 노드·간선 구성 전체의 일방향 해시.

        2-티어 캐시 키의 절반이자 검증 증적(191)의 구성 요소이므로, 같은 그래프는
        입력 파일의 표기 순서가 달라도 항상 같은 값이어야 한다 → 정렬 후 해시.
        """
        h = hashlib.sha256()
        for nid, node in sorted(self.nodes.items()):
            h.update(nid.encode())
            h.update(b"\x00")
            h.update(node.purl.encode())
            h.update(b"\x00")
        h.update(b"\x01")
        for a, b in sorted(self.edges):
            h.update(f"{a}->{b}".encode())
            h.update(b"\x00")
        h.update(b"\x02")
        for root in sorted(self.roots):
            h.update(root.encode())
            h.update(b"\x00")
        h.update(b"\x03")
        for name in sorted(self.ambiguous_names):
            h.update(name.encode())
            h.update(b"\x00")
        return h.hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": self.fmt,
            "graph_hash": self.graph_hash(),
            "has_edges": self.has_edges,
            "node_count": len(self.nodes),
            "edge_count": len(self.edges),
            "roots": list(self.roots),
            "nodes": [
                {"id": n.id, "name": n.name, "version": n.version, "purl": n.purl}
                for n in sorted(self.nodes.values(), key=lambda x: x.id)
            ],
            "edges": [{"from": a, "to": b} for a, b in sorted(self.edges)],
            "ambiguous_names": sorted(self.ambiguous_names),
        }


# ── 공통 헬퍼 ───────────────────────────────────────────────────────────────

def _load_toml(raw: bytes) -> dict:
    try:
        import tomllib  # py3.11+
    except ImportError:  # pragma: no cover - py<3.11 fallback
        import tomli as tomllib  # type: ignore
    try:
        return tomllib.loads(raw.decode("utf-8", "ignore"))
    except Exception as e:  # noqa: BLE001
        raise GraphParseError(f"invalid TOML: {e}")


def _link(g: DepGraph, src_id: str, dep_name: str, by_name: dict[str, list[str]]) -> None:
    """이름으로 지정된 의존성을 그래프 간선으로 잇는다.

    락파일은 의존성을 (이름만)으로 적고 버전은 별도 [[package]] 항목에 있으므로
    이름→노드 해석이 필요하다. 같은 이름이 여러 버전으로 잠겨 있으면(환경 마커별
    해석) 어느 쪽인지 확정할 수 없으므로 전부 잇고 ambiguous로 표시한다 —
    경로를 놓치는 쪽(미탐)보다 과다 연결(오탐)이 안전하다.
    """
    targets = by_name.get(normalize_name(dep_name), [])
    if len(targets) > 1:
        g.ambiguous_names.add(normalize_name(dep_name))
    for t in targets:
        if t != src_id:
            g.edges.add((src_id, t))


def _index_by_name(g: DepGraph) -> dict[str, list[str]]:
    idx: dict[str, list[str]] = {}
    for nid, node in g.nodes.items():
        idx.setdefault(node.name, []).append(nid)
    return idx


# ── uv.lock ────────────────────────────────────────────────────────────────

def parse_uv_lock(raw: bytes) -> DepGraph:
    doc = _load_toml(raw)
    pkgs = doc.get("package") or []
    if not isinstance(pkgs, list) or not pkgs:
        raise GraphParseError("uv.lock has no [[package]] entries")

    g = DepGraph(fmt="uv.lock")
    root_ids: list[str] = []
    for p in pkgs:
        name = normalize_name(p.get("name", ""))
        ver = str(p.get("version", "") or "")
        if not name:
            continue
        node = DepNode(name=name, version=ver)
        g.nodes[node.id] = node
        # 프로젝트 자신( virtual / editable 소스 )은 그래프의 루트이며 라이브러리가
        # 아니다. 그 dependencies가 애플리케이션의 직접 의존성이 된다.
        src = p.get("source") or {}
        if isinstance(src, dict) and ("virtual" in src or "editable" in src):
            root_ids.append(node.id)

    by_name = _index_by_name(g)
    for p in pkgs:
        name = normalize_name(p.get("name", ""))
        ver = str(p.get("version", "") or "")
        if not name:
            continue
        src_id = DepNode(name=name, version=ver).id
        for dep in p.get("dependencies") or []:
            if isinstance(dep, dict) and dep.get("name"):
                _link(g, src_id, dep["name"], by_name)
        # optional-dependencies / dev-dependencies 는 그룹별 테이블
        for group in ("optional-dependencies", "dev-dependencies"):
            grp = p.get(group) or {}
            if isinstance(grp, dict):
                for deps in grp.values():
                    for dep in deps or []:
                        if isinstance(dep, dict) and dep.get("name"):
                            _link(g, src_id, dep["name"], by_name)

    if root_ids:
        # 루트 프로젝트 노드는 패키지가 아니므로 그래프에서 제거하고, 그 자식을
        # 직접 의존성(roots)으로 승격한다.
        direct: list[str] = []
        for rid in root_ids:
            direct.extend(g.successors(rid))
            g.nodes.pop(rid, None)
            g.edges = {(a, b) for a, b in g.edges if a != rid and b != rid}
        g.roots = sorted(set(direct))
    else:
        g.roots = sorted(g.nodes)
    return g


# ── poetry.lock ────────────────────────────────────────────────────────────

def parse_poetry_lock(raw: bytes) -> DepGraph:
    doc = _load_toml(raw)
    pkgs = doc.get("package") or []
    if not isinstance(pkgs, list) or not pkgs:
        raise GraphParseError("poetry.lock has no [[package]] entries")

    g = DepGraph(fmt="poetry.lock")
    for p in pkgs:
        name = normalize_name(p.get("name", ""))
        ver = str(p.get("version", "") or "")
        if name:
            node = DepNode(name=name, version=ver)
            g.nodes[node.id] = node

    by_name = _index_by_name(g)
    for p in pkgs:
        name = normalize_name(p.get("name", ""))
        if not name:
            continue
        src_id = DepNode(name=name, version=str(p.get("version", "") or "")).id
        deps = p.get("dependencies") or {}
        if isinstance(deps, dict):
            for dep_name in deps:
                _link(g, src_id, dep_name, by_name)

    # poetry.lock 단독으로는 어느 것이 직접 의존성인지 알 수 없다(그건 pyproject
    # 쪽 정보다). 들어오는 간선이 없는 노드를 직접 의존성으로 근사한다.
    incoming = {b for _, b in g.edges}
    g.roots = sorted(i for i in g.nodes if i not in incoming) or sorted(g.nodes)
    return g


# ── CycloneDX ──────────────────────────────────────────────────────────────

def _purl_to_node(purl: str) -> Optional[DepNode]:
    if not purl.startswith("pkg:"):
        return None
    body = purl[4:].split("?")[0].split("#")[0]
    eco, _, rest = body.partition("/")
    if not rest:
        return None
    at = rest.rfind("@")
    if at > 0:
        return DepNode(normalize_name(rest[:at]), rest[at + 1:], eco.lower())
    return DepNode(normalize_name(rest), "", eco.lower())


def parse_cyclonedx(raw: bytes) -> DepGraph:
    try:
        doc = json.loads(raw.decode("utf-8", "ignore"))
    except Exception as e:  # noqa: BLE001
        raise GraphParseError(f"invalid JSON: {e}")
    comps = doc.get("components")
    if not isinstance(comps, list):
        raise GraphParseError("CycloneDX document has no components[]")

    g = DepGraph(fmt="cyclonedx")
    ref_to_id: dict[str, str] = {}
    for c in comps:
        if not isinstance(c, dict):
            continue
        node = _purl_to_node(c.get("purl") or "")
        if node is None:
            name = normalize_name(c.get("name") or "")
            if not name:
                continue
            node = DepNode(name, str(c.get("version") or ""))
        g.nodes[node.id] = node
        for ref in (c.get("bom-ref"), c.get("purl")):
            if ref:
                ref_to_id[str(ref)] = node.id

    root_ref = ((doc.get("metadata") or {}).get("component") or {}).get("bom-ref")
    for d in doc.get("dependencies") or []:
        if not isinstance(d, dict):
            continue
        src = ref_to_id.get(str(d.get("ref")))
        for dst_ref in d.get("dependsOn") or []:
            dst = ref_to_id.get(str(dst_ref))
            if dst and src and src != dst:
                g.edges.add((src, dst))
            elif dst and str(d.get("ref")) == str(root_ref):
                g.roots.append(dst)

    if not g.roots:
        incoming = {b for _, b in g.edges}
        g.roots = sorted(i for i in g.nodes if i not in incoming) or sorted(g.nodes)
    else:
        g.roots = sorted(set(g.roots))
    return g


# ── 간선 없는 포맷(평면) ───────────────────────────────────────────────────

def parse_pipfile_lock(raw: bytes) -> DepGraph:
    try:
        doc = json.loads(raw.decode("utf-8", "ignore"))
    except Exception as e:  # noqa: BLE001
        raise GraphParseError(f"invalid JSON: {e}")
    g = DepGraph(fmt="Pipfile.lock")
    for section in ("default", "develop"):
        for name, meta in (doc.get(section) or {}).items():
            ver = ""
            if isinstance(meta, dict):
                ver = str(meta.get("version") or "").lstrip("=")
            node = DepNode(normalize_name(name), ver)
            g.nodes[node.id] = node
    if not g.nodes:
        raise GraphParseError("Pipfile.lock has no packages")
    g.roots = sorted(g.nodes)
    return g


_REQ_RE = re.compile(r"^\s*([A-Za-z0-9._-]+)\s*(?:\[[^\]]*\])?\s*==\s*([A-Za-z0-9.\-+!]+)")


def parse_requirements(raw: bytes) -> DepGraph:
    g = DepGraph(fmt="requirements.txt")
    unresolved: list[str] = []
    for line in raw.decode("utf-8", "ignore").splitlines():
        line = line.split("#")[0].strip()
        if not line or line.startswith("-"):
            continue
        m = _REQ_RE.match(line)
        if m:
            node = DepNode(normalize_name(m.group(1)), m.group(2))
        else:
            unresolved.append(line)
            continue
        g.nodes[node.id] = node
    if unresolved:
        sample = ", ".join(unresolved[:3])
        raise GraphParseError(
            "requirements.txt must pin every package with ==; "
            f"unresolved requirement(s): {sample}")
    if not g.nodes:
        raise GraphParseError("requirements.txt has no pinned packages")
    g.roots = sorted(g.nodes)
    return g


# ── 진입점 ─────────────────────────────────────────────────────────────────

def build_graph(raw: bytes, filename: str = "") -> DepGraph:
    """의존성 명세(13) → 버전이 해석된 전이 의존성 그래프.

    파일명 힌트를 먼저 쓰고, 없으면 내용으로 추정한다.
    """
    name = (filename or "").lower().rsplit("/", 1)[-1]
    if name == "uv.lock":
        return parse_uv_lock(raw)
    if name == "poetry.lock":
        return parse_poetry_lock(raw)
    if name == "pipfile.lock":
        return parse_pipfile_lock(raw)
    if name.endswith((".cdx.json", ".spdx.json")) or name in ("bom.json", "sbom.json"):
        return parse_cyclonedx(raw)
    if name.startswith("requirements") and name.endswith(".txt"):
        return parse_requirements(raw)

    head = raw[:4096].decode("utf-8", "ignore")
    if '"bomFormat"' in head or '"components"' in head:
        return parse_cyclonedx(raw)
    if '"_meta"' in head or '"default"' in head:
        return parse_pipfile_lock(raw)
    if "[[package]]" in head:
        # uv.lock 은 dependencies 가 인라인 테이블 배열, poetry.lock 은 별도 섹션.
        return parse_uv_lock(raw) if "[package.metadata]" in raw.decode(
            "utf-8", "ignore") or "source = { virtual" in head else parse_poetry_lock(raw)
    raise GraphParseError(f"unsupported dependency manifest: {filename or '<unnamed>'}")
