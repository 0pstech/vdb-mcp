"""`vdb harden` — 클라이언트(10)의 사용자 단말(11) 구현.

로컬에서 **추상화된 코드 표현(32)을 만들고**, 그것과 의존성 명세만 서버로 보낸다.
소스코드 원문·식별자·리터럴·비즈니스 상수는 이 프로세스를 떠나지 않는다(【0106】).

    python3 -m vdb.harden.cli app.py --manifest uv.lock
    python3 -m vdb.harden.cli app.py --emit-ir          # 나가는 내용 그대로 확인
    python3 -m vdb.harden.cli app.py --verify P-xxxx    # 수정 후 재검증

표준 라이브러리만 쓴다 — 개발자 머신에 아무것도 설치하지 않고 돌아야 하기 때문.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import json
import os
import socket
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request

from .ir import build_ir_from_file, build_ir_from_tree

DEFAULT_API = os.environ.get("VDB_API_URL", "https://vdb.ai.kr")
_MANIFESTS = ("uv.lock", "poetry.lock", "Pipfile.lock", "requirements.txt",
              "sbom.cdx.json", "bom.json")


def _validate_api_url(url: str) -> None:
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise SystemExit("VDB API URL must use http or https and include a host")


def _find_manifest(start: str) -> str | None:
    d = os.path.dirname(os.path.abspath(start)) or "."
    for _ in range(4):
        for name in _MANIFESTS:
            p = os.path.join(d, name)
            if os.path.exists(p):
                return p
        parent = os.path.dirname(d)
        if parent == d:
            break
        d = parent
    return None


# Where VDB actually lives, for when the caller's DNS cannot say. Two
# independent evaluations died at name resolution inside a sandbox with no
# outbound DNS, and the tool they had been told to delegate to could do
# nothing about it. Egress to the address itself is often open even when DNS
# is not — so the client keeps the address, and uses it ONLY when resolution
# fails.
#
# This bypasses DNS and nothing else. The TLS handshake still presents the
# real hostname and the certificate is still validated against it, so a
# pinned connection is exactly as authenticated as a resolved one. Override
# with VDB_API_ADDR (comma-separated) if the service moves before a release.
FALLBACK_ADDRS: tuple[str, ...] = tuple(
    a.strip() for a in os.environ.get("VDB_API_ADDR", "144.202.127.83").split(",")
    if a.strip())


class _PinnedHTTPSConnection(http.client.HTTPSConnection):
    """Connect to a fixed address while presenting the real hostname for TLS."""

    def __init__(self, host: str, *a, pinned_addr: str = "", **kw) -> None:
        super().__init__(host, *a, **kw)
        self._pinned_addr = pinned_addr

    def connect(self) -> None:
        sock = socket.create_connection(
            (self._pinned_addr, self.port), self.timeout, self.source_address)
        # server_hostname is the REAL host: SNI and certificate validation
        # both happen against it, not against the address we dialled.
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


class _PinnedHTTPSHandler(urllib.request.HTTPSHandler):
    def __init__(self, pinned_addr: str) -> None:
        super().__init__(context=ssl.create_default_context())
        self._pinned_addr = pinned_addr

    def https_open(self, req):
        def conn(host, **kw):
            return _PinnedHTTPSConnection(host, pinned_addr=self._pinned_addr, **kw)
        return self.do_open(conn, req, context=self._context)


def _is_name_failure(err: BaseException) -> bool:
    return isinstance(getattr(err, "reason", err), socket.gaierror)


def _open(req: urllib.request.Request, timeout: float):
    """urlopen, falling back to the pinned address when — and only when —
    the failure is name resolution. Any other error, including every HTTP
    status, propagates untouched."""
    try:
        return urllib.request.urlopen(req, timeout=timeout)  # nosec B310
    except urllib.error.URLError as e:
        if isinstance(e, urllib.error.HTTPError) or not _is_name_failure(e):
            raise
        if urllib.parse.urlsplit(req.full_url).scheme != "https":
            raise
        last: BaseException = e
        for addr in FALLBACK_ADDRS:
            try:
                return urllib.request.build_opener(
                    _PinnedHTTPSHandler(addr)).open(req, timeout=timeout)
            except urllib.error.HTTPError:
                raise                      # the server answered; that is the answer
            except urllib.error.URLError as e2:
                last = e2
        raise last


def _diagnose(base: str, token: str, timeout: float = 10.0) -> int:
    """Name which of three things is wrong, instead of one flat sentence.

    Two independent evaluations of VDB ended with "detection could not be
    assessed at all" because the container they ran in had no outbound DNS.
    What this client told them was `cannot reach the VDB API: <reason>` — the
    same sentence it prints for a rejected key, an unreachable host and an
    outage. Both teams wrote their own harness, then hedged carefully about
    whose fault it was. A less careful reader would have written "VDB is
    broken" and stopped there.

    So the four stages are reported separately, and the verdict says which of
    your-network / your-key / our-service it is.
    """
    parts = urllib.parse.urlsplit(base)
    host, scheme = parts.hostname or "", parts.scheme or "https"
    port = parts.port or (443 if scheme == "https" else 80)
    print(f"vdb doctor — target {base}")

    if scheme not in {"http", "https"} or not host:
        print("  [1/4] url          FAIL  not an http(s) URL with a host")
        print("\nverdict: the --api-url value is malformed. Nothing was contacted.")
        return 3
    print(f"  [1/4] url           ok   host={host} port={port}")

    try:
        addrs = sorted({r[4][0] for r in socket.getaddrinfo(
            host, port, type=socket.SOCK_STREAM)})
    except socket.gaierror as e:
        print(f"  [2/4] dns          FAIL  {e}")
        # DNS is dead, but egress to the address itself may not be. Try the
        # pinned address with the real hostname for TLS — if that works, the
        # client uses it on its own and nobody has to open a ticket.
        pinned = ""
        for addr in FALLBACK_ADDRS:
            try:
                sock = socket.create_connection((addr, port), timeout=timeout)
                if scheme == "https":
                    with ssl.create_default_context().wrap_socket(
                            sock, server_hostname=host):
                        pass
                else:
                    sock.close()
                pinned = addr
                break
            except OSError:
                continue
        if pinned:
            print(f"        fallback      ok   {pinned} reachable with TLS for {host}")
            print("        the client uses this automatically when DNS fails; "
                  "override with VDB_API_ADDR")
            addrs = [pinned]
        else:
            # Resolving something else separates "this host has no DNS" from
            # "only we fail to resolve", which have different owners.
            try:
                socket.getaddrinfo("pypi.org", 443, type=socket.SOCK_STREAM)
                others = "pypi.org resolves, so DNS works here but not for this host"
            except socket.gaierror:
                others = "pypi.org does not resolve either — this host has no working DNS"
            print(f"\nverdict: YOUR NETWORK. {others}, and the pinned address")
            print(f"         {', '.join(FALLBACK_ADDRS)} is not reachable either — egress")
            print("         is blocked, not just DNS. This is not an authentication failure")
            print("         and says nothing about your key or whether VDB is up.")
            return 3
    else:
        print(f"  [2/4] dns           ok   {', '.join(addrs[:3])}")

    try:
        # Dial what stage 2 settled on — the resolved address, or the pinned
        # one — rather than resolving the name a second time.
        sock = socket.create_connection((addrs[0], port), timeout=timeout)
        if scheme == "https":
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(sock, server_hostname=host):
                pass
        else:
            sock.close()
    except ssl.SSLError as e:
        print(f"  [3/4] tls          FAIL  {e}")
        print("\nverdict: YOUR NETWORK. The TLS handshake failed — usually an")
        print("         intercepting proxy or a missing CA bundle on this host.")
        return 3
    except OSError as e:
        print(f"  [3/4] connect      FAIL  {e}")
        print("\nverdict: YOUR NETWORK or OUR SERVICE. The name resolves but the")
        print("         port refuses or times out. A firewall that allows DNS but")
        print("         blocks egress looks exactly like this.")
        return 3
    print("  [3/4] connect+tls   ok")

    req = urllib.request.Request(f"{base}/v1/auth/me", method="GET")
    req.add_header("X-VDB-Client", "vdb-harden-cli")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with _open(req, timeout) as r:
            who = json.loads(r.read().decode())
        print(f"  [4/4] auth          ok   {who.get('email') or who.get('user_id') or 'authenticated'}")
        # Name the build, so a report can say which one it evaluated without
        # a separate curl — the CLI otherwise discards response headers.
        build = (r.headers.get("X-VDB-Build") if hasattr(r, "headers") else None) or "unknown"
        print(f"        build         {build}")
        print("\nverdict: everything works. The API is reachable and the key is valid.")
        return 0
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            print(f"  [4/4] auth         FAIL  HTTP {e.code}")
            print("\nverdict: YOUR KEY. VDB answered, so the network and the service")
            print("         are fine — the key is missing, wrong, or revoked.")
            print("         Pass --token, set VDB_API_KEY, or get one at /signup.")
            return 3
        print(f"  [4/4] auth         FAIL  HTTP {e.code}")
        print("\nverdict: OUR SERVICE. The host answered with an unexpected status.")
        return 3
    except urllib.error.URLError as e:
        print(f"  [4/4] auth         FAIL  {e.reason}")
        print("\nverdict: OUR SERVICE or YOUR NETWORK — the socket opened but the")
        print("         request did not complete.")
        return 3


def _post(url: str, body: dict, token: str, timeout: float = 60.0) -> dict:
    _validate_api_url(url)
    data = json.dumps(body).encode()
    req = urllib.request.Request(url, data=data, method="POST")
    req.add_header("Content-Type", "application/json")
    req.add_header("X-VDB-Client", "vdb-harden-cli")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with _open(req, timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        detail = e.read().decode()[:600]
        raise SystemExit(f"VDB API {e.code}: {detail}")
    except urllib.error.URLError as e:
        raise SystemExit(
            f"cannot reach the VDB API: {e.reason}\n"
            "run `vdb harden --doctor` to see which of network / key / service "
            "is at fault")


def _coverage_line(out: dict) -> str:
    """What was looked at, in the one place a human reads.

    The server already knows all of this and the JSON carries it; the text
    report said only how many paths came back. Nine findings about one line
    of code read as "a scanner found nine things" when the truthful summary
    was "seventeen dependencies were analysed, taint reached three of them,
    and one call site is worth your attention". The second sentence is both
    more reassuring and more useful, and it was being thrown away.
    """
    hit = out.get("summaries_hit")
    miss = out.get("summaries_missing", 0) or 0
    reached = out.get("reached_nodes") or []
    if hit is None:
        return ""
    total = hit + miss
    bits = [f"{total} dependenc{'y' if total == 1 else 'ies'} on the graph",
            f"{hit} analysed"]
    if miss:
        bits.append(f"{miss} without a summary yet")
    if reached:
        bits.append(f"taint reached {len(reached)}")
    return " · ".join(bits)


def _print_report(out: dict, callsites: dict | None = None,
                  filename: str | None = None) -> int:
    paths = out.get("paths") or []
    hard = {h["path_id"]: h for h in (out.get("hardenings") or [])}
    coverage = _coverage_line(out)
    if not paths:
        incomplete = bool(out.get("incomplete") or not out.get("analysis_complete", True))
        print("No risky dataflow path was decided." if incomplete
              else "No risky dataflow path found.")
        miss = out.get("summaries_missing", 0)
        if miss:
            print(f"  ({miss} node(s) have no summary yet — queued for building. "
                  f"Re-run shortly for a sharper answer.)")
        if coverage:
            print(f"  {coverage}")
        if incomplete:
            print("  Analysis is incomplete; absence is not a safety determination.")
            return 2
        return 0

    # One call site that takes three tainted arguments and reaches three sink
    # kinds produced nine identical-looking blocks. The unit a reader acts on
    # is the call site — they go and edit one line — so that is the unit the
    # report is built from.
    sites: dict[str, dict] = {}
    for p in paths:
        site = sites.setdefault(p.get("callsite_id") or p["path_id"],
                                {"sinks": {}, "api": p["sink_api"],
                                 "pkg": p["sink_package"], "ver": p["sink_version"]})
        bucket = site["sinks"].setdefault(p["sink"], [])
        bucket.append(p)

    n_sites = len(sites)
    print(f"{n_sites} call site(s) with a decided dataflow path "
          f"({len(paths)} path(s) in total, independently of whether any CVE exists)")
    if coverage:
        print(coverage)
    print()

    for site_id, site in sites.items():
        where = ""
        cs = (callsites or {}).get(site_id)
        if cs and cs.get("line"):
            where = f"{filename or 'line'}:{cs['line']}  " if filename else f"line {cs['line']}  "
        print(f"* {where}{site['api']}  [{site['pkg']}@{site['ver']}]")
        for sink, group in sorted(site["sinks"].items()):
            _print_sink_group(sink, group, hard)
        print()
    return 1


def _print_sink_group(sink: str, group: list, hard: dict) -> None:
    """One sink kind at one call site, however many arguments reach it."""
    p = group[0]
    h = hard.get(p["path_id"], {})
    flag = " [low confidence]" if p.get("low_confidence") else ""
    # The LAST hop names the parameter at the sink ("endpoint"); the first
    # names it at the call site, where it may be a positional index ("0").
    # The reader is deciding what to wrap, so the named one is the useful one.
    args = sorted({g["hops"][-1].get("arg") for g in group
                   if g.get("hops") and g["hops"][-1].get("arg")})
    detail = f" · {len(group)} argument(s)" if len(group) > 1 else ""
    print(f"   {sink}  confidence {p['confidence']}{flag}{detail}")
    if args:
        print(f"     args     : {', '.join(str(a) for a in args)}")
    rule = (h.get("agent_rule") or {})
    if rule.get("require"):
        print(f"     fix      : {', '.join(rule['require'])}")
    if p.get("conservative_hops"):
        print(f"     note     : conservative pass-through assumed at "
              f"{p['conservative_hops']} unsummarized hop(s)")
    if p.get("applied_sanitizers"):
        print(f"     applied  : {', '.join(sorted(p['applied_sanitizers']))} "
              f"— already here; --verify {p['path_id']} for evidence")
    rr = h.get("residual_risk") or {}
    if rr.get("undefended"):
        print(f"     residual : {', '.join(d['label'] for d in rr['undefended'])}")
    ids = ", ".join(g["path_id"] for g in group[:2])
    more = f" (+{len(group) - 2} more)" if len(group) > 2 else ""
    print(f"     path_id  : {ids}{more}")


def _post_file(url: str, filename: str, content: bytes, token: str,
               timeout: float = 120.0) -> dict:
    """multipart/form-data upload, stdlib only (no requests dependency)."""
    _validate_api_url(url)
    boundary = "----vdbharden" + hashlib.sha256(content[:4096]).hexdigest()[:16]
    body = b"".join([
        f"--{boundary}\r\n".encode(),
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'.encode(),
        b"Content-Type: application/octet-stream\r\n\r\n",
        content, b"\r\n",
        f"--{boundary}--\r\n".encode(),
    ])
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("X-VDB-Client", "vdb-harden-cli")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    try:
        with _open(req, timeout) as r:
            return json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        raise SystemExit(f"VDB API {e.code}: {e.read().decode()[:600]}")
    except urllib.error.URLError as e:
        raise SystemExit(f"cannot reach the VDB API: {e.reason}")


def _run_vex(base: str, payload: dict, manifest: str, manifest_text: str,
             args) -> int:
    """Scan, then subtract. Two calls, one command — the advisory matcher
    lives in the scan endpoint and must not be duplicated here."""
    scan = _post_file(f"{base}/v1/sbom/scan", os.path.basename(manifest),
                      manifest_text.encode(), args.token)
    findings = scan.get("vulnerabilities") or []
    if not findings:
        # A clean lockfile is an answer, not an error. The server refuses an
        # empty findings list because that usually means the scan was skipped
        # — here it was not, so say what the scan said and stop, instead of
        # relaying a 400 that tells the user to do what they just did.
        total = scan.get("components_total", 0)
        unknown = scan.get("components_unknown", 0)
        sys.stderr.write(
            f"0 advisory finding(s) in {os.path.basename(manifest)} across "
            f"{total} component(s) — nothing to subtract, no VEX document to emit.\n")
        if unknown:
            sys.stderr.write(
                f"  note: {unknown} of {total} component(s) are not covered by "
                f"VDB; absence is not a clean bill for those.\n")
        return 0
    # A 30-finding VEX took the server 60.17 s on a real project and the
    # default 60 s client timeout cut it off at the read. Give it room.
    doc = _post(f"{base}/v1/vex",
                {**payload, "findings": findings,
                 "share": bool(getattr(args, "share", False))},
                args.token, timeout=240.0)

    if args.json:
        print(json.dumps(doc, indent=2, ensure_ascii=False))
        return 0

    meta = doc.get("_vdb", {})
    counts = meta.get("counts", {})
    total = len(doc.get("statements", []))
    na = counts.get("not_affected", 0)
    ui = counts.get("under_investigation", 0)
    print(f"{total} advisory finding(s) in {os.path.basename(manifest)}")
    print(f"  not_affected        {na}")
    print(f"  under_investigation {ui}")
    print()
    print(f"  analyzed {meta.get('files_analyzed_count', 0)} file(s) · "
          f"ecosystems: {', '.join(meta.get('ecosystems_analyzed') or ['—'])}")
    print(f"  {meta.get('scope_note', '')}")
    if ui:
        # Split the queue. Everything here is "we could not rule it out", but
        # a decided tainted path and a mere inability to exclude are not the
        # same work item, and printing them as one flat list throws away the
        # only ordering the analysis actually earned.
        openq = [st for st in doc.get("statements", [])
                 if st["status"] == "under_investigation"]
        reached = [st for st in openq
                   if (st.get("impact_statement") or "").startswith("REACHED")]
        rest = [st for st in openq if st not in reached]
        if reached:
            print()
            print(f"  Reached by attacker-controlled data — triage first ({len(reached)}):")
            for st in reached:
                print(f"    {st['vulnerability']['name']:24s} {st['products'][0]['@id']}")
        if rest:
            print()
            print(f"  Could not be ruled out ({len(rest)}):")
            for st in rest:
                print(f"    {st['vulnerability']['name']:24s} {st['products'][0]['@id']}")
    print()
    print("  Full document: re-run with --json  (OpenVEX v0.2.0)")
    return 0


def _project_name(target: str, manifest: str) -> str:
    """The folder the user pointed at, or the one holding the lockfile.

    New risk paths are mailed once per project. Every run used to be its own
    record, so one project got the same alert from each run."""
    root = target if os.path.isdir(target) else os.path.dirname(os.path.abspath(manifest))
    return os.path.basename(os.path.abspath(root)) or "project"


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="vdb harden", description=__doc__)
    ap.add_argument("file", nargs="?",
                    help="source file holding the call-site, or a directory "
                         "to analyze whole (required for --vex)")
    ap.add_argument("--manifest", help="lockfile/SBOM path (auto-detected when omitted)")
    ap.add_argument("--project",
                    help="project name for risk-path mail (default: the folder name)")
    ap.add_argument("--api-url", default=DEFAULT_API)
    # Both names: /connect tells MCP users VDB_API_TOKEN, this CLI said
    # VDB_API_KEY, and the same package installs both entry points. A
    # re-test hit 401 on --doctor for exactly that reason.
    ap.add_argument("--token", default=os.environ.get("VDB_API_KEY")
                    or os.environ.get("VDB_API_TOKEN", ""))
    ap.add_argument("--emit-ir", action="store_true",
                    help="print exactly what would leave this machine, then exit")
    ap.add_argument("--patch", action="store_true", help="print the wrapper code patch")
    ap.add_argument("--rules", action="store_true",
                    help="print only the agent rules (JSON), for AI coding agents")
    ap.add_argument("--verify", metavar="PATH_ID", help="re-verify that the path is closed after applying the fix")
    ap.add_argument("--vex", action="store_true",
                    help="emit an OpenVEX document: which advisories in the "
                         "lockfile cannot be reached by attacker-controlled "
                         "data. Point it at your source tree, not one file — "
                         "a not_affected claim is only as wide as the code "
                         "behind it.")
    ap.add_argument("--json", action="store_true", help="raw JSON output")
    ap.add_argument("--share", action="store_true",
                    help="with --vex: also publish the document at a public "
                         "URL (default: keep it local — the document lists "
                         "your components and versions)")
    ap.add_argument("--doctor", action="store_true",
                    help="check DNS, TLS and auth, and say which of "
                         "network / key / service is at fault")
    args = ap.parse_args(argv)

    # Before anything that needs a source tree: someone who cannot reach the
    # API has no use for a manifest error, and that is exactly the state two
    # evaluations got stuck in.
    if args.doctor:
        return _diagnose(args.api_url.rstrip("/"), args.token)

    if not args.file:
        raise SystemExit("a file or directory is required (or use --doctor)")
    if not os.path.exists(args.file):
        raise SystemExit(f"no such file: {args.file}")
    if os.path.isdir(args.file):
        ir = build_ir_from_tree(args.file)
        if not ir.files:
            raise SystemExit(f"no Python files under {args.file}")
    else:
        ir = build_ir_from_file(args.file)

    if args.emit_ir:
        print(json.dumps(ir.to_dict(), indent=2, ensure_ascii=False))
        return 0

    manifest = args.manifest or _find_manifest(args.file)
    if not manifest:
        raise SystemExit("no dependency manifest found; pass --manifest "
                         f"(looked for: {', '.join(_MANIFESTS)})")
    with open(manifest, encoding="utf-8", errors="ignore") as fh:
        manifest_text = fh.read()

    base = args.api_url.rstrip("/")
    payload = {
        "ir": ir.to_dict(),
        "manifest": manifest_text,
        "manifest_filename": os.path.basename(manifest),
        "project": args.project or _project_name(args.file, manifest),
    }
    if args.vex:
        return _run_vex(base, payload, manifest, manifest_text, args)

    if args.verify:
        payload["path_id"] = args.verify
        out = _post(f"{base}/v1/harden/verify", payload, args.token)
        ev = out["evidence"]
        mark = "CLOSED" if ev["closed"] else "OPEN"
        print(f"path {ev['path_id']} -> {mark} ({ev['method']})")
        print(f"  graph hash : {ev['graph_hash'][:16]}...")
        print(f"  decided at : {ev['decided_at']}")
        print(f"  signature  : {ev['signature'][:24]}...")
        print(f"  note       : {out['note']}")
        return 0 if ev["closed"] else 1

    # 60s was the default for every call. A large project's first analysis
    # takes longer than that on the server, so the client gave up, the server
    # finished anyway and cached the answer, and the SECOND run succeeded
    # instantly — a tool that fails once and then works reads as flaky, and
    # the abandoned run held a worker the whole time. Match --vex.
    out = _post(f"{base}/v1/harden/analyze", payload, args.token,
                timeout=float(os.environ.get("VDB_HARDEN_TIMEOUT", "240")))
    if args.json:
        print(json.dumps(out, indent=2, ensure_ascii=False))
        return 0
    if args.rules:
        print(json.dumps([h["agent_rule"] for h in out.get("hardenings", [])],
                         indent=2, ensure_ascii=False))
        return 0
    if args.patch:
        for h in out.get("hardenings", []):
            print(f"# ── {h['path_id']} ({h['sink']}) ──")
            print(h["code_patch"])
            print()
        return 0
    # The IR never leaves without the call sites; the report may as well say
    # which line to open.
    cs_map = {c["id"]: c for c in ir.to_dict().get("callsites", [])}
    where = None if os.path.isdir(args.file) else args.file
    return _print_report(out, cs_map, where)


if __name__ == "__main__":
    sys.exit(main())
