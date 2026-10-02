"""Stage 4 — Port Scan for UNDERTOW.

Reads only INSCOPE_subdomain_ip.txt (Stage 3's locked scope gate output) —
Rule 2, everything from here on touches in-scope IPs only.

  naabu (fast triage)                           -> nmap/naabu.txt
  nmap -sV -p<targeted ports> -iL ...           -> nmap/nmap.txt
  smap (Shodan-backed, zero-packet, nmap-compat) -> nmap/smap.txt
  shodan host / InternetDB lookup per in-scope IP -> nmap/shodan.txt

No full `-p-` 65535-port pass — a targeted port list + naabu + smap/Shodan
already covers what matters, per docs/workflow_v2.html.
"""
from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import requests

from . import runner
from .runner import StageResult, ToolResult

# Targeted port list (not a full -p- sweep) — common services + the usual
# web/db/admin ports seen fronting client apps.
DEFAULT_PORTS = "21,22,23,25,53,80,110,111,135,139,143,443,445,465,587,993,995,1433,1723,3306,3389,5432,5900,8080,8443"

VULN_LINE_RE = re.compile(r"^Vulnerabilities:\s*(.+)$")
ORG_LINE_RE = re.compile(r"^Organization:\s*(.+)$")
ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


def _extract_ips(inscope_ip_file: Path) -> list[str]:
    """INSCOPE_subdomain_ip.txt is "host -> ip" per line; dedupe to unique IPs."""
    ips = set()
    for line in runner.read_lines(inscope_ip_file):
        if " -> " in line:
            ips.add(line.split(" -> ", 1)[1].strip())
    return sorted(ips)


def _sort_ip(ip: str):
    parts = ip.split(".")
    if len(parts) == 4 and all(p.isdigit() for p in parts):
        return tuple(int(p) for p in parts)
    return (ip,)


# --------------------------------------------------------------------- naabu

def _run_naabu(ip_file: Path, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not runner.have("naabu"):
        return ToolResult(tool="naabu", ran=False, error="not installed")
    try:
        proc = subprocess.run(
            ["naabu", "-l", str(ip_file), "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="naabu", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    lines = sorted({ln.strip() for ln in proc.stdout.splitlines() if ln.strip()})
    runner.write_lines(outfile, lines)
    return ToolResult(tool="naabu", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


# ---------------------------------------------------------------------- nmap

def _parse_nmap_xml(xml_text: str) -> dict:
    """Return {ip: [{"port","protocol","service","product","version"}, ...]}."""
    import xml.etree.ElementTree as ET

    hosts_ports: dict = {}
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return hosts_ports

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        entries = []
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            entries.append(
                {
                    "port": port_el.get("portid", ""),
                    "protocol": port_el.get("protocol", "tcp"),
                    "service": service_el.get("name", "") if service_el is not None else "",
                    "product": service_el.get("product", "") if service_el is not None else "",
                    "version": service_el.get("version", "") if service_el is not None else "",
                }
            )
        if entries:
            hosts_ports[ip] = entries
    return hosts_ports


def _render_nmap_blocks(hosts_ports: dict) -> str:
    blocks = []
    for ip in sorted(hosts_ports, key=_sort_ip):
        entries = hosts_ports[ip]
        port_strs = [f"{e['port']}/{e['protocol']}" for e in entries]
        port_pad = max((len(s) for s in port_strs), default=0) + 1
        svc_pad = max((len(e["service"]) for e in entries), default=0) + 1
        lines = [f"Nmap scan report for {ip}"]
        for e, ps in zip(entries, port_strs):
            version = " ".join(x for x in (e["product"], e["version"]) if x)
            line = f"{ps.ljust(port_pad)}open  {e['service'].ljust(svc_pad)}{version}".rstrip()
            lines.append(line)
        blocks.append("\n".join(lines))
    return ("\n\n".join(blocks) + "\n") if blocks else ""


def _run_nmap(ip_file: Path, outfile: Path, ports: str, timeout: int, engagement_root: Path) -> ToolResult:
    if not runner.have("nmap"):
        return ToolResult(tool="nmap", ran=False, error="not installed")
    try:
        proc = subprocess.run(
            ["nmap", "-Pn", "-sV", "-p", ports, "-iL", str(ip_file), "-oX", "-"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="nmap", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    if not proc.stdout.strip():
        return ToolResult(tool="nmap", ran=True, error=(proc.stderr or "no output").strip()[:200])

    hosts_ports = _parse_nmap_xml(proc.stdout)
    outfile.parent.mkdir(parents=True, exist_ok=True)
    outfile.write_text(_render_nmap_blocks(hosts_ports))

    # Internal-only cache (not a Rule-1 visible output): Stage 7 feeds this
    # straight to `eyewitness -x` to screenshot nmap's HTTP(S) services
    # without re-scanning the same hosts a second time.
    (outfile.parent / ".nmap_raw.xml").write_text(proc.stdout)

    total_ports = sum(len(v) for v in hosts_ports.values())
    return ToolResult(tool="nmap", ran=True, returncode=proc.returncode, outfile=outfile, lines=total_ports)


# ---------------------------------------------------------------------- smap

def _run_smap(ip_file: Path, outdir: Path, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not runner.have("smap"):
        return ToolResult(tool="smap", ran=False, error="not installed")

    json_tmp = outdir / ".smap_native.json"
    try:
        proc = subprocess.run(
            ["smap", "-iL", str(ip_file), "-oJ", str(json_tmp)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        json_tmp.unlink(missing_ok=True)
        return ToolResult(tool="smap", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    if not json_tmp.exists():
        return ToolResult(tool="smap", ran=True, error=(proc.stderr or "no output").strip()[:200])

    try:
        hosts = json.loads(json_tmp.read_text())
    except ValueError as exc:
        json_tmp.unlink(missing_ok=True)
        return ToolResult(tool="smap", ran=True, returncode=proc.returncode, error=f"JSON parse error: {exc}")
    json_tmp.unlink(missing_ok=True)

    lines = []
    for entry in sorted(hosts, key=lambda h: _sort_ip(h.get("ip", ""))):
        ip = entry.get("ip", "")
        ports = entry.get("ports") or []
        if not ip or not ports:
            continue
        port_strs = [f"{p.get('port')}/{(p.get('service') or '').rstrip('?') or p.get('protocol', '')}" for p in ports]
        lines.append(f"{ip} -> {', '.join(port_strs)} (Shodan-indexed, zero packets sent)")

    runner.write_lines(outfile, lines)
    return ToolResult(tool="smap", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


# -------------------------------------------------------------------- shodan

def _shodan_internetdb(ip: str, timeout: int) -> dict | None:
    """No-auth fallback: https://internetdb.shodan.io/<ip>."""
    try:
        resp = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
    except requests.RequestException:
        return None
    if resp.status_code == 404:
        return {"ip": ip, "org": "", "vulns": []}
    if not resp.ok:
        return None
    try:
        data = resp.json()
    except ValueError:
        return None
    return {"ip": ip, "org": "", "vulns": data.get("vulns", [])}


def _shodan_cli_host(ip: str, timeout: int, engagement_root: Path) -> dict | None:
    """Prefer the already-authenticated `shodan` CLI (gives org + vulns) when present."""
    if not runner.have("shodan"):
        return None
    try:
        proc = subprocess.run(["shodan", "host", ip], capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, f"shodan_{ip}.txt", exc.stdout or "", exc.stderr or "")
        return None
    runner.save_raw(engagement_root, f"shodan_{ip}.txt", proc.stdout, proc.stderr)
    if proc.returncode != 0:
        return None  # e.g. "no information available" for this IP — not an error worth surfacing

    org = ""
    vulns: list[str] = []
    for line in proc.stdout.splitlines():
        line = ANSI_RE.sub("", line)
        m = ORG_LINE_RE.match(line)
        if m:
            org = m.group(1).strip()
            continue
        m = VULN_LINE_RE.match(line)
        if m:
            vulns = [v.strip() for v in m.group(1).split("\t") if v.strip()]
    return {"ip": ip, "org": org, "vulns": vulns}


def _run_shodan(ips: list[str], outfile: Path, timeout: int, engagement_root: Path, *, use_cli: bool = False) -> ToolResult:
    """use_cli=True spends one `shodan host` API query credit per IP (gets org +
    CVEs). Default is the free, no-auth InternetDB endpoint — same CVE/port data,
    no `org` field, no quota cost. Large scopes can easily exceed a free-tier
    query balance if use_cli defaults on, so callers must opt in explicitly.
    """
    if not ips:
        return ToolResult(tool="shodan", ran=False, error="no in-scope IPs to look up")

    lines = []
    any_lookup_ok = False
    for ip in ips:
        result = (_shodan_cli_host(ip, timeout, engagement_root) if use_cli else None) or _shodan_internetdb(ip, timeout)
        if result is None:
            continue
        any_lookup_ok = True
        org = result["org"] or "unknown"
        vulns = ", ".join(result["vulns"]) if result["vulns"] else "none indexed"
        lines.append(f"{ip} | org: {org} | vulns: {vulns}")

    if not any_lookup_ok:
        return ToolResult(tool="shodan", ran=True, error="no shodan CLI or InternetDB reachable")

    runner.write_lines(outfile, lines)
    return ToolResult(tool="shodan", ran=True, returncode=0, outfile=outfile, lines=len(lines))


# --------------------------------------------------------------- orchestrate

def run_stage4(
    inscope_ip_file: Path,
    engagement_root: Path,
    *,
    ports: str = DEFAULT_PORTS,
    timeout: int = 300,
    shodan_use_cli: bool = False,
) -> StageResult:
    outdir = engagement_root / "nmap"
    outdir.mkdir(parents=True, exist_ok=True)

    stage = StageResult(stage="Stage 4 — Port Scan")

    ips = _extract_ips(inscope_ip_file)
    if not ips:
        stage.add(ToolResult(tool="portscan", ran=False, error="INSCOPE_subdomain_ip.txt has no IPs — nothing to scan"))
        return stage

    ip_file = outdir / ".inscope_ips.txt"
    runner.write_lines(ip_file, ips)

    try:
        stage.add(_run_naabu(ip_file, outdir / "naabu.txt", timeout, engagement_root))
        stage.add(_run_nmap(ip_file, outdir / "nmap.txt", ports, timeout, engagement_root))
        stage.add(_run_smap(ip_file, outdir, outdir / "smap.txt", timeout, engagement_root))
        stage.add(_run_shodan(ips, outdir / "shodan.txt", timeout, engagement_root, use_cli=shodan_use_cli))
    finally:
        ip_file.unlink(missing_ok=True)

    for key, fname in (
        ("naabu", "naabu.txt"),
        ("nmap", "nmap.txt"),
        ("smap", "smap.txt"),
        ("shodan", "shodan.txt"),
    ):
        candidate = outdir / fname
        if candidate.exists():
            stage.outputs[key] = candidate

    return stage
