"""경계 강화 합성부(150) + 잔여 위험 라벨러(160) — 도 8.

판정된 경로(45)를 받아 **의존 패키지의 코드를 수정하지 않고** 대상 애플리케이션의
콜사이트 경계에만 적용되는 수정안을 만든다(【0037】). 산출 형태는 네 가지:

  151 코드 패치 모드   직접 사용자용 래퍼 함수 — 도 8 의 safeName 예시 형태
  152 에이전트 규칙    AI 코딩 에이전트가 기계적으로 해석·적용하는 규칙 객체
      정책 선언        샌드박스/권한 제한 — 소스 수정 권한이 없는 배포 환경용
      자연어 지시      자동 반영 주체가 없을 때 사람이 읽고 적용

그리고 잔여 위험 표지(161)를 **항상 함께** 붙인다(청구항 1). 방어하는 위협과
방어하지 못하는 위협을 명시적으로 갈라 적어, 산출물의 방어 범위에 대한 과신을
막는다(【0077】).
"""

from __future__ import annotations

import ast
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from .sinks import (
    CMD_EXEC, DESERIALIZE, GLOBAL_STATE, NET_REQUEST, PATH_OP, REGEX_EVAL,
)

if TYPE_CHECKING:
    from .compose import DataflowPath

# 방어 패턴 카탈로그 — 명세가 드는 식별자(상위 디렉터리 시퀀스 제거, 문자
# 정규화, 스키마 검증, 화이트리스트 대조)를 싱크 클래스별로 확장했다.
# 에이전트 규칙(152)의 `require` 에는 이 식별자만 나가고, 구체 구현은
# 에이전트가 자기 코드 생성 규칙에 따라 채운다(【0075】).
DEFENSE_CATALOG: dict[str, list[str]] = {
    PATH_OP:      ["strip-parent-dir-seq", "strip-path-separators", "unicode-normalize"],
    CMD_EXEC:     ["allowlist-check"],
    DESERIALIZE:  ["safe-loader", "schema-validate"],
    NET_REQUEST:  ["scheme-allowlist", "host-allowlist", "block-internal-ranges"],
    REGEX_EVAL:   ["literal-escape", "length-cap"],
    GLOBAL_STATE: ["key-allowlist"],
}

# Human-readable sink names (used in the natural-language instruction and
# in the residual-risk label).
SINK_LABEL: dict[str, str] = {
    PATH_OP: "file path operation", CMD_EXEC: "command execution",
    DESERIALIZE: "deserialization", NET_REQUEST: "network request",
    REGEX_EVAL: "regular-expression evaluation",
    GLOBAL_STATE: "global state mutation",
}

# 이 방식이 구조적으로 방어하지 못하는 위협 — 명세 【0077】이 열거하는 3종.
# 콜사이트 경계 강화는 "내 입력이 위험 지점으로 흐르는 것"만 막으므로, 내 코드가
# 호출하기도 전에 실행되거나(설치 스크립트) 내 데이터플로 밖에서 벌어지는 일은
# 원리적으로 막지 못한다. 이걸 적어두지 않으면 산출물이 과신을 유발한다.
ALWAYS_UNDEFENDED: list[dict[str, str]] = [
    {"class": "install-script-malware", "label": "install-script malware",
     "why": "runs before your code ever calls the package"},
    {"class": "background-exfiltration", "label": "background data exfiltration",
     "why": "happens outside your input path, so a call-site boundary never sees it"},
    {"class": "unanalyzed-dynamic-load", "label": "unanalyzed dynamic loading",
     "why": "reflection and dynamic imports cannot be resolved statically"},
]

# 합성기 버전. 수정안 코드(_PY_WRAPPERS)나 DEFENSE_CATALOG 가 바뀌면 **반드시**
# 올린다. 분석 캐시 키에 이 값이 들어가기 때문이다 — 올리지 않으면 이미 분석한
# 사용자는 결함이 고쳐진 뒤에도 옛 수정안을 계속 돌려받는다. 실제로 SSRF 를
# 통과시키는 vdb_safe_url 이 캐시에서 그대로 다시 나왔다.
SYNTH_VERSION = "vdb-synth/0.3.1"

_PY_WRAPPERS: dict[str, str] = {
    PATH_OP: '''def vdb_safe_path(value):
    """Call-site boundary wrapper: strip parent-dir sequences/separators, normalize."""
    import os, unicodedata
    v = unicodedata.normalize("NFC", str(value))
    # 고정점까지 반복한다. 한 번만 지우면 "....//" 가 "../" 를 새로 만들어 낸다.
    while True:
        stripped = v.replace("../", "").replace("..\\\\", "")
        if stripped == v:
            break
        v = stripped
    v = v.replace("/", "").replace("\\\\", "").replace("\\0", "")
    v = os.path.basename(v)
    # 남은 것이 상위 참조나 빈 이름이면 이름이 아니다. 조용히 통과시키면
    # join(base, "..") 이 되어 업로드 디렉터리 밖으로 나간다.
    if v in ("", ".", ".."):
        raise ValueError("path resolves to no safe name")
    return v''',
    CMD_EXEC: '''def vdb_safe_arg(value, allowed):
    """Accept only an explicitly enumerated command argument."""
    v = str(value)
    if not allowed:
        raise ValueError("a non-empty command allowlist is required")
    if v not in allowed or "\\0" in v:
        raise ValueError("command argument not in allowlist")
    return v''',
    DESERIALIZE: '''def vdb_safe_load(value, schema=None):
    """Refuse arbitrary object reconstruction; validate against a schema when given."""
    import json
    obj = json.loads(value) if isinstance(value, (str, bytes)) else value
    if schema is None:
        raise ValueError("an explicit schema type is required")
    if not isinstance(obj, schema):
        raise ValueError("payload does not match expected schema")
    return obj''',
    NET_REQUEST: '''def vdb_safe_url(value, allowed_hosts=()):
    """Scheme/host allowlist plus internal-range blocking."""
    import ipaddress, socket
    from urllib.parse import urlparse
    u = urlparse(str(value))
    if u.scheme not in ("http", "https"):
        raise ValueError("scheme not allowed")
    if not allowed_hosts:
        raise ValueError("a non-empty host allowlist is required")
    if u.hostname not in allowed_hosts:
        raise ValueError("host not in allowlist")
    try:
        addresses = {row[4][0] for row in socket.getaddrinfo(
            u.hostname or "", u.port or (443 if u.scheme == "https" else 80),
            type=socket.SOCK_STREAM)}
    except (socket.gaierror, UnicodeError):
        raise ValueError("host does not resolve")
    def _unwrap(ip):
        # An IPv6 address can carry an IPv4 one inside it. Checking only the
        # outer form let 6to4 through: 2002:7f00:0001:: is 127.0.0.1 wearing
        # an address family that answers is_global with True.
        if ip.version == 6:
            if ip.ipv4_mapped:
                return ip.ipv4_mapped
            if ip.sixtofour:
                return ip.sixtofour
            if ip.teredo:
                return ip.teredo[1]
        return ip
    for addr in addresses:
        ip = _unwrap(ipaddress.ip_address(addr))
        # is_global is the allowlist, not is_private the blocklist. The old
        # flag list missed carrier-grade NAT (100.64.0.0/10) entirely, which
        # is routable inside an ISP or a cloud tenancy and is exactly where a
        # neighbour's metadata service lives.
        if not ip.is_global or ip.is_multicast:
            raise ValueError("non-public address blocked")
    return value''',
    REGEX_EVAL: '''def vdb_safe_pattern(value, max_len=200):
    """Keep user input from becoming a regex: cap length and escape it."""
    v = str(value)
    if len(v) > max_len:
        raise ValueError("pattern too long")
    return __import__("re").escape(v)''',
    GLOBAL_STATE: '''def vdb_safe_key(value, allowed):
    """Restrict global/attribute keys to an allowlist; always refuse magic keys."""
    v = str(value)
    if not allowed:
        raise ValueError("a non-empty key allowlist is required")
    if v not in allowed:
        raise ValueError("key not in allowlist")
    # 허용목록을 건네지 않는 호출부가 대부분이다. 그때 이 래퍼가 아무 일도
    # 하지 않으면 이름만 방어인 코드가 된다 — 마법 키는 목록과 무관하게 막는다.
    if (v.startswith("__") and v.endswith("__")) or v in (
            "__proto__", "prototype", "constructor"):
        raise ValueError("magic key not allowed")
    return v''',
}

_TRUSTED_WRAPPER_OPS: dict[str, list[str]] = {
    "vdb_safe_path": DEFENSE_CATALOG[PATH_OP],
    "vdb_safe_arg": DEFENSE_CATALOG[CMD_EXEC],
    "vdb_safe_load": DEFENSE_CATALOG[DESERIALIZE],
    "vdb_safe_url": DEFENSE_CATALOG[NET_REQUEST],
    "vdb_safe_pattern": DEFENSE_CATALOG[REGEX_EVAL],
    "vdb_safe_key": DEFENSE_CATALOG[GLOBAL_STATE],
}


def identify_trusted_wrapper(node: ast.AST) -> list[str]:
    """Return defenses only when a local helper matches our reviewed AST.

    Function-name or body-regex matching is intentionally insufficient: a
    dead `if False` check or an unrelated `allowed_foo` variable used to be
    enough to mint closure evidence.
    """
    name = getattr(node, "name", "")
    expected = _TRUSTED_WRAPPER_OPS.get(name)
    if not expected:
        return []
    for source in _PY_WRAPPERS.values():
        candidate = ast.parse(source).body[0]
        if getattr(candidate, "name", "") != name:
            continue
        if ast.dump(candidate, include_attributes=False) == ast.dump(
                node, include_attributes=False):
            return list(expected)
    return []

_WRAPPER_NAME = {
    PATH_OP: "vdb_safe_path", CMD_EXEC: "vdb_safe_arg",
    DESERIALIZE: "vdb_safe_load", NET_REQUEST: "vdb_safe_url",
    REGEX_EVAL: "vdb_safe_pattern", GLOBAL_STATE: "vdb_safe_key",
}


@dataclass
class Hardening:
    """산출물(190)의 한 항목 — 하나의 경로에 대한 수정안 + 잔여 위험 표지."""
    path_id: str
    sink: str
    target: str                       # 적용 대상: pkg.api#argN
    code_patch: str                   # 151
    agent_rule: dict[str, Any]        # 152
    policy: dict[str, Any]            # 실행 정책 선언
    instruction: str                  # natural-language instruction
    residual_risk: dict[str, Any]     # 161
    confidence: float
    low_confidence: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "path_id": self.path_id, "sink": self.sink, "target": self.target,
            "code_patch": self.code_patch, "agent_rule": self.agent_rule,
            "policy": self.policy, "instruction": self.instruction,
            "residual_risk": self.residual_risk,
            "confidence": round(self.confidence, 3),
            "low_confidence": self.low_confidence,
        }


def _policy_for(sink: str, path: DataflowPath) -> dict[str, Any]:
    """실행 정책 선언 — 소스 수정 없이 배포 환경 설정으로 적용 가능한 형태."""
    base = {"path_id": path.path_id, "applies_to": path.sink_package}
    if sink == PATH_OP:
        return {**base, "filesystem": {"write": ["${APP_DATA_DIR}"], "read": ["${APP_DATA_DIR}"]}}
    if sink == CMD_EXEC:
        return {**base, "process": {"spawn": False}}
    if sink == NET_REQUEST:
        return {**base, "network": {"egress": "deny-by-default", "allow": []}}
    if sink == DESERIALIZE:
        return {**base, "process": {"spawn": False}, "filesystem": {"write": []}}
    return {**base, "note": "no runtime policy applies; code-level defense only"}


def _residual(path: DataflowPath, required: list[str]) -> dict[str, Any]:
    """잔여 위험 표지(161) — 방어 / 미방어를 명시적으로 가른다."""
    undefended = [dict(x) for x in ALWAYS_UNDEFENDED]
    if path.conservative_hops:
        undefended.append({
            "class": "unsummarized-hops", "label": "assumed propagation through unsummarized hops",
            "why": (f"the conservative pass-through assumption was applied at "
                    f"{path.conservative_hops} node(s) on this path"),
        })
    if path.dynamic:
        undefended.append({
            "class": "dynamic-dispatch", "label": "dynamic dispatch on the path",
            "why": "the call target is chosen at run time and cannot be pinned statically",
        })
    if path.sink == NET_REQUEST:
        undefended.append({
            "class": "dns-rebinding-window",
            "label": "DNS can change between validation and connection",
            "why": "use a transport that pins the validated address for high-assurance SSRF defense",
        })
        undefended.append({
            "class": "redirect-following",
            "label": "redirects are not re-validated",
            "why": ("the wrapper checks the URL you pass, not where a 3xx sends "
                    "the client afterwards — disable redirects at the call site "
                    "or re-check each hop"),
        })
    return {
        "defended": [{"class": path.sink,
                      "label": SINK_LABEL.get(path.sink, path.sink),
                      "by": required}],
        "undefended": undefended,
        "note": ("This fix blocks only the 'defended' item above. Everything else "
                 "needs runtime isolation, least privilege, or continuous watch."),
    }


def synthesize(path: DataflowPath, language: str = "python") -> Hardening:
    """경로 하나 → 강화 수정안 + 잔여 위험 표지."""
    if language != "python":
        raise ValueError("call-site patch synthesis currently supports Python only")
    required = DEFENSE_CATALOG.get(path.sink, ["schema-validate"])
    first = path.hops[0] if path.hops else None
    target = f"{first.package}.{first.api}#arg{first.arg}" if first else path.sink_package

    wrapper = _PY_WRAPPERS.get(path.sink, "")
    wname = _WRAPPER_NAME.get(path.sink, "vdb_safe_value")
    wrapper_args = {
        CMD_EXEC: f"{path.source_symbol}, allowed={{\"expected-value\"}}",
        DESERIALIZE: f"{path.source_symbol}, schema=dict",
        NET_REQUEST: f"{path.source_symbol}, allowed_hosts=(\"api.example.com\",)",
        GLOBAL_STATE: f"{path.source_symbol}, allowed={{\"expected-key\"}}",
    }.get(path.sink, path.source_symbol)
    call_hint = (f"{first.api}({wname}({wrapper_args}), ...)"
                 if first else f"{wname}({wrapper_args})")
    code_patch = (f"{wrapper}\n\n# At the call site: wrap the argument "
                  f"(the dependency itself is never modified)\n# {call_hint}")

    rule = {
        "rule": "harden-callsite",
        "target": target,
        "path_id": path.path_id,
        "require": required,
        "verify_after_apply": True,
    }
    label = SINK_LABEL.get(path.sink, path.sink)
    chain = " -> ".join(f"{h.package}@{h.version}" for h in path.hops) if path.hops else ""
    instruction = (
        f"{path.source_symbol} (user input) reaches a {label} sink through {chain}. "
        f"Do not modify the dependency: wrap the argument at the call site with "
        f"a helper that applies {', '.join(required)}."
    )
    return Hardening(
        path_id=path.path_id, sink=path.sink, target=target,
        code_patch=code_patch, agent_rule=rule,
        policy=_policy_for(path.sink, path), instruction=instruction,
        residual_risk=_residual(path, required),
        confidence=path.confidence, low_confidence=path.low_confidence,
    )


def synthesize_all(paths: list[DataflowPath], language: str = "python"
                   ) -> list[Hardening]:
    out: list[Hardening] = []
    seen: set[str] = set()
    for p in paths:
        if p.path_id in seen:
            continue
        seen.add(p.path_id)
        out.append(synthesize(p, language))
    return out


# ── 재검증(170) 판정 ───────────────────────────────────────────────────────

def path_closed(path: DataflowPath, required: list[str]) -> tuple[bool, str]:
    """수정안 적용 후 재분석에서 경로가 닫혔는지 판정한다.

    경로가 남아 있는 경우, VDB가 제공한 검토 완료 래퍼와 AST가 정확히 일치하고
    해당 래퍼가 콜사이트 인자에 실제 적용된 경우만 닫힘을 인정한다. 함수 이름이나
    일반적인 `allowlist` 단어만으로는 증적을 만들지 않는다.
    """
    applied = set(path.applied_sanitizers or [])
    if not applied:
        return False, "no-sanitizer-at-boundary"
    missing = [r for r in required if r not in applied]
    if not missing:
        return True, f"sanitizer-applied:{','.join(sorted(set(required)))}"
    # 일부만 적용된 상태를 '닫힘'으로 부르지 않는다 — 스킴만 보고 내부 대역을
    # 열어두는 식의 반쪽 방어가 통과되면 증적이 거짓말을 하게 된다.
    return False, f"sanitizer-incomplete:missing={','.join(missing)}"
