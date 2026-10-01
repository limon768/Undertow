"""Stage 2 — Alive Host + IP Discovery for UNDERTOW.

  httpx -l all_domain.txt -p <expanded port list> -title -sc -ip
      -> subdomain/alive_domain.txt   ("host [status] [title] [ip]")
  grep -i "login|admin" on titles
      -> subdomain/login_endpoints.txt  (metadata only, not its own stage)

httpx's own stdout write is not used directly: we run it with -json so every
field can be parsed and re-emitted in the exact "host [status] [title] [ip]"
line format the rest of the pipeline (and the report) expects.
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import runner
from .runner import StageResult, ToolResult

# Expanded web port list: standard 80/443 plus the common alt-http(s)/admin
# ports actually seen fronting client web apps.
EXPANDED_WEB_PORTS = "80,81,443,591,2082,2087,2095,3000,8000,8008,8080,8081,8088,8443,8834,8888,9000,9090,9443,10000"

LOGIN_TITLE_KEYWORDS = ("login", "admin")


def _format_alive_line(host: str, status: str, title: str, ip: str) -> str:
    return f"{host} [{status}] [{title}] [{ip}]"


def run_stage2(all_domain_file: Path, engagement_root: Path, *, timeout: int = 300) -> StageResult:
    """Probe every host in all_domain.txt and write alive_domain.txt + login_endpoints.txt."""
    outdir = engagement_root / "subdomain"
    outdir.mkdir(parents=True, exist_ok=True)
    alive_file = outdir / "alive_domain.txt"
    login_file = outdir / "login_endpoints.txt"

    stage = StageResult(stage="Stage 2 — Alive Host + IP Discovery")
    hosts = runner.read_lines(all_domain_file)

    if not hosts:
        stage.add(ToolResult(tool="httpx", ran=False, error="all_domain.txt is empty, nothing to probe"))
        return stage

    if not runner.have("httpx"):
        stage.add(ToolResult(tool="httpx", ran=False, error="not installed"))
        return stage

    try:
        proc = subprocess.run(
            [
                "httpx", "-p", EXPANDED_WEB_PORTS, "-title", "-sc", "-ip", "-json", "-silent",
                "-timeout", "5", "-retries", "0", "-threads", "100",
            ],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        stage.add(ToolResult(tool="httpx", ran=True, error=f"timeout after {timeout}s"))
        return stage

    alive_lines = []
    login_lines = []
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        host = data.get("host", data.get("input", "")).strip()
        status = str(data.get("status_code", ""))
        title = data.get("title", "")
        ip = data.get("host_ip") or data.get("ip", "") or ""
        if not host:
            continue
        alive_lines.append(_format_alive_line(host, status, title, ip))
        if any(kw in title.lower() for kw in LOGIN_TITLE_KEYWORDS):
            login_lines.append(_format_alive_line(host, status, title, ip))

    runner.write_lines(alive_file, sorted(alive_lines))
    result = ToolResult(
        tool="httpx",
        ran=True,
        returncode=proc.returncode,
        outfile=alive_file,
        lines=len(alive_lines),
    )
    stage.add(result)
    stage.outputs["alive_domain"] = alive_file

    if login_lines:
        runner.write_lines(login_file, sorted(login_lines))
        stage.outputs["login_endpoints"] = login_file

    return stage


# --------------------------------------------------------------------------
# Legacy quick-pipeline helper. Kept only for undertow.py's old generic `run()`
# path until that pipeline is replaced by run_stage2() end to end. Do not
# extend this — build onto run_stage2() instead.

def probe_hosts(hosts: list, timeout: int = 120) -> list:
    results = _run_httpx_legacy(hosts, timeout)
    if results:
        return results
    return _fallback_probe(hosts, timeout=5)


def _run_httpx_legacy(hosts: list, timeout: int) -> list:
    if not runner.have("httpx") or not hosts:
        return []
    try:
        proc = subprocess.run(
            ["httpx", "-silent", "-json", "-title", "-status-code", "-tech-detect", "-web-server", "-follow-redirects"],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return []

    results = []
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        results.append(
            {
                "url": data.get("url", ""),
                "host": data.get("host", ""),
                "status_code": data.get("status_code", ""),
                "title": data.get("title", ""),
                "webserver": data.get("webserver", ""),
                "tech": data.get("tech", []),
            }
        )
    return results


def _fallback_probe(hosts: list, timeout: int) -> list:
    import requests

    results = []
    for host in hosts:
        for scheme in ("https", "http"):
            url = f"{scheme}://{host}"
            try:
                resp = requests.get(url, timeout=timeout, allow_redirects=True)
                results.append(
                    {
                        "url": resp.url,
                        "host": host,
                        "status_code": resp.status_code,
                        "title": "",
                        "webserver": resp.headers.get("Server", ""),
                        "tech": [],
                    }
                )
                break
            except requests.RequestException:
                continue
    return results
