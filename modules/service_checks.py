"""Stage 9 — Service / Vulnerability Checks for UNDERTOW.

Moved to end, in-scope only (absolute rule 6) — everything here is
intrusive/active, the same caution tier as the credential-spray stage that
was removed entirely. nuclei/nikto specifically are opt-in behind
`--vuln-scan`, never default.

  wpscan (only if WordPress actually detected)       -> wpscan/<host>.txt
  sslscan (hosts with 443/8443 open, from Stage 4's
  cached nmap XML)                                    -> MISC/sslscan.txt
  testssl.sh (same host set)                          -> MISC/testssl.txt
  ssh-audit (hosts with 22 open, from Stage 4)        -> MISC/ssh-audit.txt
  ike-scan (every in-scope IP — Stage 4 never scans
  UDP/500, so this is its own active probe, not
  gated by a prior "port open" signal)                -> MISC/ike-scan.txt
  subzy (subdomain takeover, every in-scope host)     -> MISC/subzy.txt
  socialhunter (broken social links)                  -> MISC/socialhunter.txt
  git exposure check (/.git/HEAD)                     -> MISC/git_exposure.txt
  clickjack PoC generation (X-Frame-Options/CSP)      -> MISC/clickjack_poc.html
  nuclei (opt-in --vuln-scan)                         -> MISC/nuclei.txt
  nikto (opt-in --vuln-scan)                          -> MISC/nikto_<host>.txt

Dropped: nmap ssl-enum-ciphers — redundant with sslscan+testssl.sh (same
redundant-tool-cut pattern used throughout this pipeline); it's also not a
separately named file in output/example_engagement's mock layout.

Table shapes below match CLAUDE.md's Stage 9 column-shape mandate exactly:
WPScan (Plugin/Theme, Version, Vulnerable-to), SSL/TLS (IP/FQDN, TLS1.0,
TLS1.1), IKE (Asset, Hash found?), Subzy (Subdomain, Likelihood %), SocialHunter
(Asset, Broken link), Clickjack (Asset, Vulnerable Yes/No).
"""
from __future__ import annotations

import re
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path

import requests

from . import runner
from .runner import StageResult, ToolResult

ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")


# ------------------------------------------------------------------ shared

def _resolve_base_url(host: str, timeout: int) -> str | None:
    """Scheme resolution for checks that need a real URL, not just a
    hostname — alive_domain.txt (Stage 2) doesn't retain which scheme/port
    actually responded, so this re-probes https then http, same convention
    EyeWitness's --prepend-https effectively does for Stage 7.
    """
    for scheme in ("https", "http"):
        try:
            resp = requests.head(f"{scheme}://{host}/", timeout=min(timeout, 10), allow_redirects=True)
            if resp.status_code < 500:
                return f"{scheme}://{host}"
        except requests.RequestException:
            continue
    return None


def _hosts_with_port(nmap_xml_path: Path, ports: set[str]) -> list[str]:
    """IPs from Stage 4's cached nmap XML with any of the given ports open."""
    if not nmap_xml_path.exists():
        return []
    try:
        root = ET.fromstring(nmap_xml_path.read_text())
    except ET.ParseError:
        return []
    hosts = []
    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        for port_el in host_el.findall(".//port"):
            if port_el.get("portid") not in ports:
                continue
            state_el = port_el.find("state")
            if state_el is not None and state_el.get("state") == "open":
                hosts.append(ip)
                break
    return sorted(set(hosts))


# ------------------------------------------------------------------- wpscan

def _run_wpscan(hosts: list[str], outdir: Path, timeout: int) -> list[ToolResult]:
    if not runner.have("wpscan"):
        return [ToolResult(tool="wpscan", ran=False, error="not installed")]

    results = []
    any_run = False
    for host in hosts:
        url = _resolve_base_url(host, timeout)
        if not url:
            continue
        any_run = True
        try:
            proc = subprocess.run(
                ["wpscan", "--url", url, "--random-user-agent", "--disable-tls-checks",
                 "--no-update", "-e", "vp,u", "--format", "cli-no-color"],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            results.append(ToolResult(tool="wpscan", ran=True, error=f"{host}: timeout after {timeout}s"))
            continue

        output = proc.stdout
        if "WordPress version" not in output and "is running WordPress" not in output.lower():
            continue  # not a WordPress site — no file, per the spec's "(if WordPress detected)"

        findings = [ln.strip() for ln in output.splitlines() if ln.strip().startswith("[+]")]
        outfile = outdir / f"{host}.txt"
        runner.write_lines(outfile, findings)
        results.append(ToolResult(tool="wpscan", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(findings), detail=host))

    if not any_run:
        return [ToolResult(tool="wpscan", ran=False, error="no in-scope host resolved over http(s)")]
    return results or [ToolResult(tool="wpscan", ran=True, lines=0, detail="no WordPress sites detected")]


# ------------------------------------------------------------------ SSL/TLS

def _run_sslscan(ip: str, timeout: int) -> tuple[str, str]:
    """Returns (tls1.0 Yes/No, tls1.1 Yes/No) for one host, 'n/a' on failure."""
    try:
        proc = subprocess.run(
            ["sslscan", "--no-colour", ip], capture_output=True, text=True, timeout=min(timeout, 60),
        )
    except subprocess.TimeoutExpired:
        return "n/a", "n/a"
    out = proc.stdout
    tls10 = "Yes" if re.search(r"^TLSv1\.0\s+enabled", out, re.MULTILINE) else "No"
    tls11 = "Yes" if re.search(r"^TLSv1\.1\s+enabled", out, re.MULTILINE) else "No"
    return tls10, tls11


def _run_ssl_checks(tls_hosts: list[str], outdir: Path, timeout: int) -> list[ToolResult]:
    results = []

    if not tls_hosts:
        return [ToolResult(tool="sslscan", ran=False, error="no in-scope hosts with 443/8443 open")]

    if runner.have("sslscan"):
        rows = ["# IP/FQDN                          TLS1.0   TLS1.1"]
        for ip in tls_hosts:
            tls10, tls11 = _run_sslscan(ip, timeout)
            rows.append(f"{ip:<35}{tls10:<9}{tls11}")
        outfile = outdir / "sslscan.txt"
        runner.write_lines(outfile, rows)
        results.append(ToolResult(tool="sslscan", ran=True, returncode=0, outfile=outfile, lines=len(tls_hosts)))
    else:
        results.append(ToolResult(tool="sslscan", ran=False, error="not installed"))

    if runner.have("testssl.sh"):
        lines = []
        for ip in tls_hosts:
            try:
                proc = subprocess.run(
                    ["testssl.sh", "--quiet", "--color", "0", ip],
                    capture_output=True, text=True, timeout=min(timeout, 120),
                )
            except subprocess.TimeoutExpired:
                lines.append(f"{ip} -> timeout after {min(timeout, 120)}s")
                continue
            issues = [
                ANSI_RE.sub("", ln).strip()
                for ln in proc.stdout.splitlines()
                if re.search(r"VULNERABLE|NOT ok|missing", ln, re.IGNORECASE)
            ]
            summary = ", ".join(issues[:5]) if issues else "no notable issues flagged"
            lines.append(f"{ip} -> {summary}")
        outfile = outdir / "testssl.txt"
        runner.write_lines(outfile, lines)
        results.append(ToolResult(tool="testssl.sh", ran=True, returncode=0, outfile=outfile, lines=len(lines)))
    else:
        results.append(ToolResult(tool="testssl.sh", ran=False, error="not installed"))

    return results


# ----------------------------------------------------------------- ssh-audit

def _run_ssh_audit(ssh_hosts: list[str], outdir: Path, timeout: int) -> ToolResult:
    if not ssh_hosts:
        return ToolResult(tool="ssh-audit", ran=False, error="no in-scope hosts with 22 open")
    if not runner.have("ssh-audit"):
        return ToolResult(tool="ssh-audit", ran=False, error="not installed")

    lines = []
    for ip in ssh_hosts:
        try:
            proc = subprocess.run(
                ["ssh-audit", ip], capture_output=True, text=True, timeout=min(timeout, 30),
            )
        except subprocess.TimeoutExpired:
            lines.append(f"{ip}:22 -> timeout after {min(timeout, 30)}s")
            continue
        out = ANSI_RE.sub("", proc.stdout)
        banner_m = re.search(r"banner:\s*(.+)", out)
        banner = banner_m.group(1).strip() if banner_m else "unknown banner"
        warn_count = len(re.findall(r"\(warn\)|\(fail\)", out))
        summary = "no weak algorithms detected" if warn_count == 0 else f"{warn_count} weak algorithm(s) flagged"
        lines.append(f"{ip}:22 -> {banner}, {summary}")

    outfile = outdir / "ssh-audit.txt"
    runner.write_lines(outfile, lines)
    return ToolResult(tool="ssh-audit", ran=True, returncode=0, outfile=outfile, lines=len(lines))


# ------------------------------------------------------------------ ike-scan

def _run_ike_scan(ips: list[str], outdir: Path, timeout: int) -> ToolResult:
    if not ips:
        return ToolResult(tool="ike-scan", ran=False, error="no in-scope IPs")
    if not runner.have("ike-scan"):
        return ToolResult(tool="ike-scan", ran=False, error="not installed")

    rows = ["# Asset                    Hash found?   Detail"]
    found_any = False
    for ip in ips:
        try:
            proc = subprocess.run(
                ["ike-scan", "--aggressive", "--id=test", ip],
                capture_output=True, text=True, timeout=min(timeout, 30),
            )
        except subprocess.TimeoutExpired:
            continue
        out = proc.stdout
        # ike-scan never prints a literal "no response" per host — a silent
        # target just gets no result line at all, and the real signal is the
        # run's summary ("N returned handshake; M returned notify"). Checking
        # for non-empty stdout alone is wrong: the start/end banner lines are
        # always present even with zero responses (confirmed live).
        summary_m = re.search(r"(\d+) returned handshake; (\d+) returned notify", out)
        if not summary_m or (int(summary_m.group(1)) == 0 and int(summary_m.group(2)) == 0):
            continue  # no IKE service here — don't pad the report with negatives
        hash_found = "Yes" if re.search(r"HASH|SA=", out) else "No"
        detail = "Aggressive mode enabled - PSK hash retrievable" if hash_found == "Yes" else "responded, no PSK hash extracted"
        rows.append(f"{ip}:500/udp{'':<15}{hash_found:<13} {detail}")
        found_any = True

    if not found_any:
        return ToolResult(tool="ike-scan", ran=True, returncode=0, lines=0, detail="no IKE/VPN gateways responded")

    outfile = outdir / "ike-scan.txt"
    runner.write_lines(outfile, rows)
    return ToolResult(tool="ike-scan", ran=True, returncode=0, outfile=outfile, lines=len(rows) - 1)


# --------------------------------------------------------------------- subzy

def _run_subzy(inscope_domain_file: Path, outdir: Path, timeout: int) -> ToolResult:
    if not runner.have("subzy"):
        return ToolResult(tool="subzy", ran=False, error="not installed")
    hosts = runner.read_lines(inscope_domain_file)
    if not hosts:
        return ToolResult(tool="subzy", ran=False, error="INSCOPE_domain.txt is empty")

    def _one_pass(extra_args: list[str]) -> dict[str, str]:
        """Returns {subdomain: VERDICT}."""
        try:
            proc = subprocess.run(
                ["subzy", "run", "--targets", str(inscope_domain_file), "--concurrency", "20",
                 "--timeout", str(min(timeout, 20)), *extra_args],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {}
        verdicts = {}
        for line in proc.stdout.splitlines():
            line = ANSI_RE.sub("", line)
            m = re.match(r"^\[\s*(.+?)\s*\]\s*-\s*(\S.+)$", line.strip())
            if m:
                verdicts[m.group(2).strip()] = m.group(1).strip().upper()
        return verdicts

    # subzy's --https is a single on/off switch, not "try both": a plain run
    # defaults to http and reports HTTP ERROR for any https-only host (real
    # bug hit on real data — confirmed every VPN/Citrix-style host in this
    # engagement failed this way without it). Running both passes and
    # preferring whichever actually got a real verdict covers both cases
    # without assuming every future engagement is https-only too.
    http_verdicts = _one_pass([])
    https_verdicts = _one_pass(["--https"])
    if not http_verdicts and not https_verdicts:
        return ToolResult(tool="subzy", ran=True, error="no output from either http or https pass")

    rows = ["# Subdomain                                    Likelihood   Detail"]
    for subdomain in sorted(set(http_verdicts) | set(https_verdicts)):
        verdict = http_verdicts.get(subdomain, "HTTP ERROR")
        if verdict == "HTTP ERROR":
            verdict = https_verdicts.get(subdomain, verdict)
        if verdict == "VULNERABLE":
            likelihood, detail = "100%", "fingerprint match — possible unclaimed resource, verify manually"
        elif verdict == "NOT VULNERABLE":
            likelihood, detail = "0%", "no fingerprint match"
        else:
            likelihood, detail = "n/a", verdict.lower()
        rows.append(f"{subdomain:<45} {likelihood:<12} {detail}")

    outfile = outdir / "subzy.txt"
    runner.write_lines(outfile, rows)
    return ToolResult(tool="subzy", ran=True, returncode=0, outfile=outfile, lines=len(rows) - 1)


# --------------------------------------------------------------- socialhunter

def _run_socialhunter(urls: list[str], outdir: Path, timeout: int) -> ToolResult:
    if not urls:
        return ToolResult(tool="socialhunter", ran=False, error="no resolvable in-scope URLs")
    if not runner.have("socialhunter"):
        return ToolResult(tool="socialhunter", ran=False, error="not installed")

    url_file = outdir / ".socialhunter_urls.txt"
    runner.write_lines(url_file, urls)
    try:
        proc = subprocess.run(
            ["socialhunter", "-f", str(url_file)], capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        url_file.unlink(missing_ok=True)
        return ToolResult(tool="socialhunter", ran=True, error=f"timeout after {timeout}s")
    url_file.unlink(missing_ok=True)

    rows = ["# Asset               Broken link                          Detail"]
    for line in proc.stdout.splitlines():
        line = ANSI_RE.sub("", line).strip()
        if not line or "broken" not in line.lower():
            continue
        rows.append(line)

    if len(rows) == 1:
        return ToolResult(tool="socialhunter", ran=True, returncode=proc.returncode, lines=0, detail="no broken social links found")

    outfile = outdir / "socialhunter.txt"
    runner.write_lines(outfile, rows)
    return ToolResult(tool="socialhunter", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(rows) - 1)


# ------------------------------------------------------------------ git exposure

def _run_git_exposure(hosts: list[str], outdir: Path, timeout: int) -> ToolResult:
    if not hosts:
        return ToolResult(tool="git-exposure", ran=False, error="no in-scope hosts")

    lines = []
    for host in hosts:
        url = _resolve_base_url(host, timeout)
        if not url:
            continue
        try:
            resp = requests.get(f"{url}/.git/HEAD", timeout=min(timeout, 10))
        except requests.RequestException:
            continue
        # A real git HEAD file is tiny and matches one rigid format exactly:
        # "ref: refs/heads/<branch>\n" or a bare 40-char SHA1. A loose
        # substring check for "HEAD"/"ref:" false-positives constantly on
        # soft-404 apps that return 200 + their normal HTML for any path
        # (confirmed live: a 25KB HTML page containing "<head>" was wrongly
        # flagged as exposed git ref data).
        body = resp.text.strip()
        is_real_git_head = resp.status_code == 200 and len(body) < 200 and (
            re.match(r"^ref:\s*refs/", body) or re.fullmatch(r"[0-9a-f]{40}", body)
        )
        if is_real_git_head:
            lines.append(f"{host}/.git/ -> 200 (EXPOSED — ref data readable)")
        else:
            lines.append(f"{host}/.git/ -> {resp.status_code} (not exposed)")

    if not lines:
        return ToolResult(tool="git-exposure", ran=True, lines=0, detail="no hosts reachable for check")

    outfile = outdir / "git_exposure.txt"
    runner.write_lines(outfile, lines)
    return ToolResult(tool="git-exposure", ran=True, returncode=0, outfile=outfile, lines=len(lines))


# -------------------------------------------------------------------- clickjack

def _run_clickjack(hosts: list[str], outdir: Path, timeout: int) -> ToolResult:
    if not hosts:
        return ToolResult(tool="clickjack", ran=False, error="no in-scope hosts")

    verdicts: list[tuple[str, bool, str]] = []
    for host in hosts:
        url = _resolve_base_url(host, timeout)
        if not url:
            continue
        try:
            resp = requests.get(url, timeout=min(timeout, 10))
        except requests.RequestException:
            continue
        xfo = resp.headers.get("X-Frame-Options", "")
        csp = resp.headers.get("Content-Security-Policy", "")
        protected = bool(xfo) or "frame-ancestors" in csp.lower()
        reason = f"X-Frame-Options: {xfo}" if xfo else (
            "frame-ancestors CSP present" if protected else "no X-Frame-Options/CSP frame-ancestors"
        )
        verdicts.append((host, not protected, reason))

    if not verdicts:
        return ToolResult(tool="clickjack", ran=True, lines=0, detail="no hosts reachable for check")

    vulnerable = [host for host, is_vuln, _ in verdicts if is_vuln]
    iframes = "\n".join(f'<iframe src="{_resolve_base_url(h, 1) or h}"></iframe>' for h in vulnerable[:5])
    comments = "\n".join(
        f'<!-- {host}: Vulnerable={"Yes" if is_vuln else "No"} ({reason}) -->' for host, is_vuln, reason in verdicts
    )
    html = f"<!doctype html><html><body>\n{iframes}\n</body></html>\n{comments}\n"

    outfile = outdir / "clickjack_poc.html"
    outfile.write_text(html)
    return ToolResult(tool="clickjack", ran=True, returncode=0, outfile=outfile, lines=len(verdicts))


# --------------------------------------------------------- nuclei/nikto (opt-in)

def _run_nuclei(inscope_domain_file: Path, outfile: Path, timeout: int) -> ToolResult:
    if not runner.have("nuclei"):
        return ToolResult(tool="nuclei", ran=False, error="not installed")
    hosts = runner.read_lines(inscope_domain_file)
    if not hosts:
        return ToolResult(tool="nuclei", ran=False, error="INSCOPE_domain.txt is empty")
    try:
        proc = subprocess.run(
            ["nuclei", "-l", str(inscope_domain_file), "-t", "http/cves/", "-t", "dns/", "-silent"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool="nuclei", ran=True, error=f"timeout after {timeout}s")
    lines = [ln.rstrip() for ln in proc.stdout.splitlines() if ln.strip()]
    runner.write_lines(outfile, lines)
    return ToolResult(tool="nuclei", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


def _run_nikto(hosts: list[str], outdir: Path, timeout: int) -> list[ToolResult]:
    if not runner.have("nikto"):
        return [ToolResult(tool="nikto", ran=False, error="not installed")]
    results = []
    for host in hosts:
        url = _resolve_base_url(host, timeout)
        if not url:
            continue
        outfile = outdir / f"nikto_{host}.txt"
        try:
            proc = subprocess.run(
                ["nikto", "-host", url, "-output", str(outfile), "-Format", "txt"],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            results.append(ToolResult(tool="nikto", ran=True, error=f"{host}: timeout after {timeout}s"))
            continue
        lines = runner.count_lines(outfile)
        results.append(ToolResult(tool="nikto", ran=True, returncode=proc.returncode, outfile=outfile, lines=lines, detail=host))
    return results or [ToolResult(tool="nikto", ran=False, error="no in-scope host resolved over http(s)")]


# --------------------------------------------------------------- orchestrate

def run_stage9(
    inscope_domain_file: Path,
    inscope_ip_file: Path,
    engagement_root: Path,
    *,
    timeout: int = 180,
    vuln_scan: bool = False,
) -> StageResult:
    stage = StageResult(stage="Stage 9 — Service / Vulnerability Checks")

    hosts = runner.read_lines(inscope_domain_file)
    ips = sorted({line.split(" -> ", 1)[1] for line in runner.read_lines(inscope_ip_file) if " -> " in line})
    if not hosts and not ips:
        stage.add(ToolResult(tool="service_checks", ran=False, error="no in-scope hosts/IPs"))
        return stage

    misc_dir = engagement_root / "MISC"
    misc_dir.mkdir(parents=True, exist_ok=True)
    wpscan_dir = engagement_root / "wpscan"
    wpscan_dir.mkdir(parents=True, exist_ok=True)
    nmap_xml = engagement_root / "nmap" / ".nmap_raw.xml"

    for r in _run_wpscan(hosts, wpscan_dir, timeout):
        stage.add(r)

    tls_hosts = _hosts_with_port(nmap_xml, {"443", "8443"})
    for r in _run_ssl_checks(tls_hosts, misc_dir, timeout):
        stage.add(r)

    ssh_hosts = _hosts_with_port(nmap_xml, {"22"})
    stage.add(_run_ssh_audit(ssh_hosts, misc_dir, timeout))

    stage.add(_run_ike_scan(ips, misc_dir, timeout))
    stage.add(_run_subzy(inscope_domain_file, misc_dir, timeout))

    resolved_urls = [u for h in hosts if (u := _resolve_base_url(h, timeout))]
    stage.add(_run_socialhunter(resolved_urls, misc_dir, timeout))

    stage.add(_run_git_exposure(hosts, misc_dir, timeout))
    stage.add(_run_clickjack(hosts, misc_dir, timeout))

    if vuln_scan:
        stage.add(_run_nuclei(inscope_domain_file, misc_dir / "nuclei.txt", timeout))
        for r in _run_nikto(hosts, misc_dir, timeout):
            stage.add(r)

    return stage
