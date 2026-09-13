"""위험 싱크 카탈로그 + 변형 클래스.

명세는 싱크를 6클래스로만 못박고(청구항 8) 언어별 실제 함수명은 기재하지 않는다
— 카탈로그 구성은 설계 자유도. 아래는 Python 매핑이며, 생태계가 늘면 같은
6클래스에 각 언어의 함수명을 붙이는 방식으로 확장한다.

싱크 판정은 "정규화된 점 표기 이름"에 대해 이루어진다. `subprocess.run`,
`os.system` 처럼 모듈 경로가 붙은 형태와 `eval` 처럼 빌트인 단독 형태를 모두
받는다.
"""

from __future__ import annotations

import re
from typing import Optional

# ── 싱크 6클래스 (청구항 8) ────────────────────────────────────────────────
CMD_EXEC     = "cmd_exec"        # 명령 실행
DESERIALIZE  = "deserialize"     # 역직렬화
PATH_OP      = "path_op"         # 파일 경로 연산
NET_REQUEST  = "net_request"     # 네트워크 요청 생성
REGEX_EVAL   = "regex_eval"      # 정규식 평가
GLOBAL_STATE = "global_state"    # 프로토타입 또는 전역 상태 변경

SINK_CLASSES = (CMD_EXEC, DESERIALIZE, PATH_OP, NET_REQUEST, REGEX_EVAL, GLOBAL_STATE)

# 접미 일치(suffix match)로 판정한다. `os.system` 은 `system` 만 남은 형태로도,
# `foo.os.system` 형태로도 잡혀야 하기 때문.
_SINK_PATTERNS: tuple[tuple[str, str], ...] = (
    # 명령 실행 — 인자가 셸/실행 파일로 흘러가는 지점
    ("subprocess.run", CMD_EXEC), ("subprocess.call", CMD_EXEC),
    ("subprocess.check_call", CMD_EXEC), ("subprocess.check_output", CMD_EXEC),
    ("subprocess.popen", CMD_EXEC), ("os.system", CMD_EXEC),
    ("os.popen", CMD_EXEC), ("os.execv", CMD_EXEC), ("os.execve", CMD_EXEC),
    ("os.spawnv", CMD_EXEC), ("pty.spawn", CMD_EXEC),
    # 역직렬화 — 신뢰 불가 바이트가 객체 그래프로 복원되는 지점
    ("pickle.load", DESERIALIZE), ("pickle.loads", DESERIALIZE),
    ("cpickle.load", DESERIALIZE), ("cpickle.loads", DESERIALIZE),
    ("marshal.load", DESERIALIZE), ("marshal.loads", DESERIALIZE),
    ("dill.load", DESERIALIZE), ("dill.loads", DESERIALIZE),
    ("shelve.open", DESERIALIZE), ("jsonpickle.decode", DESERIALIZE),
    ("yaml.unsafe_load", DESERIALIZE), ("yaml.full_load", DESERIALIZE),
    # 파일 경로 연산
    ("os.path.join", PATH_OP), ("os.path.abspath", PATH_OP),
    ("os.path.realpath", PATH_OP), ("os.path.exists", PATH_OP),
    ("os.path.split", PATH_OP), ("os.path.splitext", PATH_OP),
    ("os.open", PATH_OP), ("os.remove", PATH_OP), ("os.unlink", PATH_OP),
    ("os.rename", PATH_OP), ("os.makedirs", PATH_OP), ("os.mkdir", PATH_OP),
    ("os.listdir", PATH_OP), ("os.rmdir", PATH_OP), ("os.chmod", PATH_OP),
    ("shutil.copy", PATH_OP), ("shutil.copyfile", PATH_OP),
    ("shutil.move", PATH_OP), ("shutil.rmtree", PATH_OP),
    ("io.open", PATH_OP),
    ("pathlib.path", PATH_OP), ("path.joinpath", PATH_OP),
    # 네트워크 요청 생성
    ("urllib.request.urlopen", NET_REQUEST), ("urlopen", NET_REQUEST),
    ("socket.create_connection", NET_REQUEST), ("socket.connect", NET_REQUEST),
    # Real code calls these on a socket OBJECT or a backend abstraction, not
    # through the `socket.` module, so the dotted patterns above never fire on
    # it — httpcore's actual network write is `sock.sendall(...)`. These names
    # are socket-specific enough to match bare; deliberately NOT including
    # `connect` or `write`, which belong to databases and files just as often.
    ("sendall", NET_REQUEST), ("sendto", NET_REQUEST),
    # ── Library APIs that ARE the dangerous operation ──────────────────
    # Everything above bottoms out in a stdlib primitive, which is how the
    # analyzer normally discovers danger: chase the dataflow until it reaches
    # `os.system`. Some operations never bottom out that way. paramiko's
    # exec_command runs a command on a REMOTE host, so inside paramiko there
    # is nothing but socket writes — no amount of chasing finds a sink,
    # because the dangerous thing is the API itself. Jinja2 is the same shape:
    # a template compiled from attacker text is server-side template
    # injection, and the compilation is the operation.
    #
    # Keep this list short and specific. A generic name here (`render`,
    # `execute`, `run`) would fire on unrelated libraries and manufacture
    # findings, which costs more than the miss.
    ("connect_tcp", NET_REQUEST), ("connect_unix", NET_REQUEST),
    ("open_connection", NET_REQUEST), ("create_unix_connection", NET_REQUEST),
    ("httpconnection", NET_REQUEST), ("httpsconnection", NET_REQUEST),
    ("http.client.httpconnection", NET_REQUEST),
    ("requests.get", NET_REQUEST), ("requests.post", NET_REQUEST),
    ("requests.request", NET_REQUEST), ("session.request", NET_REQUEST),
    # 정규식 평가 — ReDoS 는 패턴이 오염될 때 성립한다
    ("re.compile", REGEX_EVAL), ("re.match", REGEX_EVAL), ("re.search", REGEX_EVAL),
    ("re.sub", REGEX_EVAL), ("re.findall", REGEX_EVAL), ("re.finditer", REGEX_EVAL),
    ("re.fullmatch", REGEX_EVAL), ("re.split", REGEX_EVAL),
    # 전역 상태 변경
    ("os.environ.setdefault", GLOBAL_STATE), ("os.putenv", GLOBAL_STATE),
    ("sys.modules", GLOBAL_STATE),
)

# 점 없는 빌트인 — 정확히 일치할 때만 싱크로 본다.
# Library APIs whose danger is the call itself, checked against the CALLER'S
# call site rather than found inside a package. See the note in
# _SINK_PATTERNS: these never reach a stdlib primitive locally, so dataflow
# chasing cannot classify them.
LIBRARY_API_SINKS: tuple[tuple[str, str, str], ...] = (
    # Distribution + caller-visible API must both match. Bare suffixes made
    # every dependency's `exec_command` a confidence-1.0 command sink.
    ("paramiko", "sshclient.exec_command", CMD_EXEC),
    ("paramiko", "channel.exec_command", CMD_EXEC),
    ("paramiko", "sshclient.invoke_shell", CMD_EXEC),
    ("paramiko", "channel.invoke_shell", CMD_EXEC),
    ("jinja2", "template", CMD_EXEC),
    ("jinja2", "environment.from_string", CMD_EXEC),
)


def classify_library_api(module: str, api: str) -> Optional[str]:
    """Sink class for a dependency API the caller invokes directly.

    Matching is EXACT on the (distribution, caller-visible API) pair. Two
    looser rules have already cost precision here and both failed the same
    way — a generic verb matched a method that merely shares its name:

      * a bare suffix (`exec_command`) matched every distribution;
      * a suffix scoped to one distribution (`httpx` + `.get`) matched
        `httpx.Headers.get`, `QueryParams.get` and `Cookies.get`, which are
        dictionary lookups, and reported each as a network sink at
        confidence 1.0 — with no summary behind it.

    A finding produced here skips dataflow entirely, so it carries full
    confidence and there is nothing downstream to catch a mistake. That is
    the whole reason this list must stay small, exact, and reserved for
    operations that genuinely never touch a local primitive. Anything the
    analysis can reach on its own belongs to the analysis: HTTPX is absent
    below because composition already finds its socket write in httpcore.
    """
    module_name = module.lower().replace("_", "-")
    api_name = api.lower()
    for expected_module, expected_api, sink in LIBRARY_API_SINKS:
        if module_name == expected_module and api_name == expected_api:
            return sink
    return None


_BUILTIN_SINKS: dict[str, str] = {
    # 코드 실행은 명세의 6클래스에 별도 항목이 없어 명령 실행으로 접는다.
    "eval": CMD_EXEC, "exec": CMD_EXEC, "compile": CMD_EXEC,
    "__import__": CMD_EXEC,
    "open": PATH_OP,
    "setattr": GLOBAL_STATE, "delattr": GLOBAL_STATE, "globals": GLOBAL_STATE,
}


def classify_sink(dotted: str) -> str | None:
    """점 표기 호출 이름 → 싱크 클래스. 싱크가 아니면 None."""
    if not dotted:
        return None
    d = dotted.lower()
    # 점 표기(모듈 경로가 있는) 패턴을 먼저 본다 — re.compile 은 정규식 평가이지
    # 빌트인 compile 이 아니다.
    for pat, cls in _SINK_PATTERNS:
        if d == pat or d.endswith("." + pat):
            return cls
    return _BUILTIN_SINKS.get(d)


# ── 동적 기능 (【0094】) ───────────────────────────────────────────────────
# 정적으로 도달 지점을 확정할 수 없게 만드는 호출들. 요약에 경유 사실을 표시하고
# 확신도 산출(S740)에서 -0.2 감산 인자로 참조한다.
_DYNAMIC = (
    "eval", "exec", "compile", "__import__", "importlib.import_module",
    "getattr", "setattr", "globals", "locals", "vars",
    "importlib.util.spec_from_file_location", "types.functiontype",
)


def is_dynamic(dotted: str) -> bool:
    if not dotted:
        return False
    d = dotted.lower()
    return any(d == p or d.endswith("." + p) for p in _DYNAMIC)


# ── 변형 클래스 (【0051】) ─────────────────────────────────────────────────
# 명세가 드는 값: 무변형 · 문자열 연결 · 인코딩 · 형변환 ("등"으로 개방).
IDENTITY = "identity"     # 무변형
CONCAT   = "concat"       # 문자열 연결
ENCODE   = "encode"       # 인코딩
CAST     = "cast"         # 형변환

TRANSFORM_CLASSES = (IDENTITY, CONCAT, ENCODE, CAST)

_ENCODE_FNS = re.compile(
    r"(^|\.)(encode|decode|b64encode|b64decode|urlencode|quote|quote_plus|"
    r"unquote|hexlify|unhexlify|dumps)$", re.I
)
_CAST_FNS = re.compile(r"^(str|bytes|int|float|bool|list|dict|tuple|set|repr)$", re.I)


def classify_call_transform(dotted: str) -> str | None:
    """호출 자체가 값을 변형하는 종류라면 그 변형 클래스."""
    if not dotted:
        return None
    if _CAST_FNS.match(dotted):
        return CAST
    if _ENCODE_FNS.search(dotted):
        return ENCODE
    return None


def merge_transform(a: str, b: str) -> str:
    """경로 상에서 변형이 누적될 때의 결합 규칙.

    무변형은 항등원. 서로 다른 변형이 겹치면 더 '멀리 간' 쪽(연결 > 인코딩 >
    형변환 순으로 원본에서 멀어진다고 본다)을 취해, 합성 결과가 방어 패턴 선택에
    쓰일 때 과소평가되지 않게 한다.
    """
    if a == IDENTITY:
        return b
    if b == IDENTITY:
        return a
    if a == b:
        return a
    rank = {CAST: 1, ENCODE: 2, CONCAT: 3}
    return a if rank.get(a, 0) >= rank.get(b, 0) else b
