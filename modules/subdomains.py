"""Stage 1 — Subdomain Enumeration for UNDERTOW.

Mirrors docs/workflow_v2.html exactly:

  1A · passive (parallel): subscraper -m all, amass enum -passive, subfinder,
       urlscan.io API, optional github-subdomains (needs a GitHub token)
       -> merge/dedupe -> all_passive_domain.txt

  1B · active: amass enum -active -norecursive, dnsx -ptr over scope.txt's
       CIDRs/IPs, optional puredns+dnsgen permutation bruteforce (--wordlist)
       -> merge/dedupe -> all_activeScan_domain.txt

  1A + 1B merged/deduped -> all_domain.txt

Rule 1 (one named output file per tool that actually runs) is enforced by
`runner.run_tool`: a file for a given tool only appears if that tool actually
ran. A tool that is missing or skipped (no scope file, no wordlist, no GitHub
token) is reported in the StageResult but leaves no file behind.
"""
from __future__ import annotations

import ipaddress
import json
import re
import subprocess
from pathlib import Path

import requests

from . import runner
from .runner import StageResult, ToolResult
from .toolcheck import SUBSCRAPER_PY, VENV_PYTHON, subscraper_available

HOSTNAME_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$")

# Reverse-DNS sweeps are capped per network so a client handing over a huge
# CIDR in scope.txt doesn't turn Stage 1 into an unbounded scan.
MAX_PTR_HOSTS_PER_NET = 4096


def _clean_subdomains(lines: list[str], domain: str) -> set[str]:
    out = set()
    for line in lines:
        name = line.strip().lower().lstrip("*.").rstrip(".")
        if name and HOSTNAME_RE.match(name) and (name == domain or name.endswith("." + domain)):
            out.add(name)
    return out


# ---------------------------------------------------------------- 1A passive

def _run_subscraper(domain: str, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not subscraper_available():
        return ToolResult(tool="subscraper", ran=False, error="not installed")
    # subscraper defaults -o to ./sub_report.txt in whatever cwd it's launched
    # from, regardless of -silent. Pin it into outfile's own directory as a
    # throwaway so repeated runs never leak a stray file into the cwd.
    native_report = outfile.parent / ".subscraper_native_report.txt"
    try:
        proc = subprocess.run(
            [str(VENV_PYTHON), str(SUBSCRAPER_PY), "-d", domain, "-m", "all", "-silent", "-o", str(native_report)],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        native_report.unlink(missing_ok=True)
        return ToolResult(tool="subscraper", ran=True, error=f"timeout after {timeout}s")
    except OSError as exc:
        native_report.unlink(missing_ok=True)
        return ToolResult(tool="subscraper", ran=True, error=str(exc))

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    found = _clean_subdomains(proc.stdout.splitlines(), domain)
    native_report.unlink(missing_ok=True)
    runner.write_lines(outfile, sorted(found))
    return ToolResult(tool="subscraper", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(found))


def _run_amass_to_file(domain: str, outfile: Path, mode: str, timeout: int, engagement_root: Path) -> ToolResult:
    """mode is 'passive' or 'active'."""
    argv = ["amass", "enum", f"-{mode}", "-d", domain]
    if mode == "active":
        argv.append("-norecursive")
    if not runner.have("amass"):
        return ToolResult(tool="amass", ran=False, error="not installed")
    timeout = runner.effective_timeout("amass", timeout)
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="amass", ran=True, error=f"timeout after {timeout}s")
    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    found = _clean_subdomains(proc.stdout.splitlines(), domain)
    runner.write_lines(outfile, sorted(found))
    return ToolResult(tool="amass", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(found))


def _run_subfinder(domain: str, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not runner.have("subfinder"):
        return ToolResult(tool="subfinder", ran=False, error="not installed")
    try:
        proc = subprocess.run(
            ["subfinder", "-d", domain, "-all", "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="subfinder", ran=True, error=f"timeout after {timeout}s")
    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    found = _clean_subdomains(proc.stdout.splitlines(), domain)
    runner.write_lines(outfile, sorted(found))
    return ToolResult(tool="subfinder", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(found))


def _run_urlscan(domain: str, outfile: Path, timeout: int) -> ToolResult:
    """urlscan.io has no CLI binary; query its public search API directly."""
    try:
        resp = requests.get(
            "https://urlscan.io/api/v1/search/",
            params={"q": f"domain:{domain}", "size": 10000},
            timeout=timeout,
        )
    except requests.RequestException as exc:
        return ToolResult(tool="urlscan", ran=True, error=str(exc)[:200])
    if not resp.ok:
        return ToolResult(tool="urlscan", ran=True, returncode=resp.status_code, error=resp.text[:200])
    try:
        results = resp.json().get("results", [])
    except ValueError as exc:
        return ToolResult(tool="urlscan", ran=True, error=str(exc)[:200])
    names = [((entry.get("page") or {}).get("domain") or "") for entry in results]
    found = _clean_subdomains(names, domain)
    runner.write_lines(outfile, sorted(found))
    return ToolResult(tool="urlscan", ran=True, returncode=0, outfile=outfile, lines=len(found))


def _run_github_subdomains(domain: str, outfile: Path, timeout: int, github_token: str | None, engagement_root: Path) -> ToolResult:
    if not github_token:
        return ToolResult(tool="github-subdomains", ran=False, error="optional — no GitHub token provided")
    if not runner.have("github-subdomains"):
        return ToolResult(tool="github-subdomains", ran=False, error="not installed")
    try:
        proc = subprocess.run(
            ["github-subdomains", "-d", domain, "-t", github_token],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="github-subdomains", ran=True, error=f"timeout after {timeout}s")
    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    found = _clean_subdomains(proc.stdout.splitlines(), domain)
    runner.write_lines(outfile, sorted(found))
    return ToolResult(tool="github-subdomains", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(found))


# ----------------------------------------------------------------- 1B active

def _expand_scope_ips(scope_file: Path) -> list[str]:
    """Expand scope.txt's IPs/CIDRs into individual host IPs for dnsx -ptr.

    Each network is capped at MAX_PTR_HOSTS_PER_NET hosts so a /16 or larger
    in scope.txt doesn't turn Stage 1 into an unbounded reverse-DNS sweep.
    """
    ips: list[str] = []
    for line in runner.read_lines(scope_file):
        try:
            net = ipaddress.ip_network(line, strict=False)
        except ValueError:
            continue
        hosts = list(net.hosts()) if net.num_addresses > 1 else [net.network_address]
        ips.extend(str(h) for h in hosts[:MAX_PTR_HOSTS_PER_NET])
    return ips


def _run_dnsx_ptr(scope_file: Path, outdir: Path, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not scope_file.exists() or not runner.read_lines(scope_file):
        return ToolResult(tool="dnsx", ran=False, error="no scope.txt IPs/CIDRs to reverse")
    if not runner.have("dnsx"):
        return ToolResult(tool="dnsx", ran=False, error="not installed")

    ip_list = _expand_scope_ips(scope_file)
    if not ip_list:
        return ToolResult(tool="dnsx", ran=False, error="scope.txt has no parseable IP/CIDR entries")

    ip_file = outdir / ".dnsx_ptr_input.txt"
    runner.write_lines(ip_file, ip_list)

    try:
        proc = subprocess.run(
            ["dnsx", "-l", str(ip_file), "-ptr", "-resp-only", "-json", "-silent"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="dnsx", ran=True, error=f"timeout after {timeout}s")
    finally:
        ip_file.unlink(missing_ok=True)

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    pairs = set()
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        host_ip = data.get("host", "")
        for ptr in data.get("ptr") or []:
            pairs.add(f"{host_ip} -> {ptr.rstrip('.')}")

    runner.write_lines(outfile, sorted(pairs))
    return ToolResult(tool="dnsx", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(pairs))


def _run_bruteforce(domain: str, wordlist: Path | None, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    """puredns + dnsgen permutation bruteforce — opt-in, only with --wordlist."""
    if wordlist is None:
        return ToolResult(tool="puredns", ran=False, error="optional — no --wordlist given")
    if not wordlist.exists():
        return ToolResult(tool="puredns", ran=False, error=f"wordlist not found: {wordlist}")
    if not runner.have("puredns") or not runner.have("dnsgen"):
        return ToolResult(tool="puredns", ran=False, error="puredns/dnsgen not installed")
    try:
        brute = subprocess.run(
            ["puredns", "bruteforce", str(wordlist), domain],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="puredns", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, outfile.name, brute.stdout, brute.stderr)
    found = _clean_subdomains(brute.stdout.splitlines(), domain)
    if found:
        try:
            perm = subprocess.run(
                ["dnsgen", "-"],
                input="\n".join(sorted(found)),
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            runner.save_raw(engagement_root, f"dnsgen_{outfile.name}", perm.stdout, perm.stderr)
            perm_candidates = [l.strip() for l in perm.stdout.splitlines() if l.strip()]
            if perm_candidates:
                resolved = subprocess.run(
                    ["puredns", "resolve"],
                    input="\n".join(perm_candidates),
                    capture_output=True,
                    text=True,
                    timeout=timeout,
                )
                runner.save_raw(engagement_root, f"puredns_resolve_{outfile.name}", resolved.stdout, resolved.stderr)
                found |= _clean_subdomains(resolved.stdout.splitlines(), domain)
        except subprocess.TimeoutExpired as exc:
            runner.save_raw(engagement_root, f"dnsgen_{outfile.name}", exc.stdout or "", exc.stderr or "")

    runner.write_lines(outfile, sorted(found))
    return ToolResult(tool="puredns", ran=True, returncode=brute.returncode, outfile=outfile, lines=len(found))


# --------------------------------------------------------------- orchestrate

def run_stage1(
    domain: str,
    engagement_root: Path,
    *,
    timeout: int = 180,
    github_token: str | None = None,
    wordlist: Path | None = None,
) -> StageResult:
    """Run Stage 1 end to end and write every file in subdomain/ per the spec.

    `engagement_root` is the engagement directory (containing scope.txt). Its
    `subdomain/` subdirectory is created if missing.
    """
    outdir = engagement_root / "subdomain"
    outdir.mkdir(parents=True, exist_ok=True)
    scope_file = engagement_root / "scope.txt"

    stage = StageResult(stage="Stage 1 — Subdomain Enumeration")

    # 1A passive (would run in parallel in a threaded driver; sequential here
    # keeps each ToolResult's error handling simple and explicit)
    passive_results = [
        stage.add(_run_subscraper(domain, outdir / "subscraper.txt", timeout, engagement_root)),
        stage.add(_run_amass_to_file(domain, outdir / "amass_passive.txt", "passive", timeout, engagement_root)),
        stage.add(_run_subfinder(domain, outdir / "subfinder.txt", timeout, engagement_root)),
        stage.add(_run_urlscan(domain, outdir / "urlscan_subs.txt", timeout)),
        stage.add(_run_github_subdomains(domain, outdir / "github_subs.txt", timeout, github_token, engagement_root)),
    ]
    passive_sources = [r.outfile for r in passive_results if r.outfile]
    all_passive = runner.merge_dedupe(passive_sources, outdir / "all_passive_domain.txt")
    stage.outputs["all_passive_domain"] = all_passive

    # 1B active
    active_results = [
        stage.add(_run_amass_to_file(domain, outdir / "amass_active.txt", "active", timeout, engagement_root)),
        stage.add(_run_dnsx_ptr(scope_file, outdir, outdir / "reverse_dns.txt", timeout, engagement_root)),
        stage.add(_run_bruteforce(domain, wordlist, outdir / "bruteforce_domain.txt", timeout, engagement_root)),
    ]
    # reverse_dns.txt is "ip -> hostname"; pull just the hostnames into the merge
    active_sources = [r.outfile for r in active_results if r.outfile and r.tool != "dnsx"]
    reverse_dns_file = outdir / "reverse_dns.txt"
    if reverse_dns_file.exists():
        hostnames = []
        for line in runner.read_lines(reverse_dns_file):
            if " -> " in line:
                hostnames.append(line.split(" -> ", 1)[1])
        if hostnames:
            tmp = outdir / ".reverse_dns_hosts.txt"
            runner.write_lines(tmp, sorted(set(hostnames)))
            active_sources.append(tmp)

    all_active = runner.merge_dedupe(active_sources, outdir / "all_activeScan_domain.txt")
    tmp_hosts = outdir / ".reverse_dns_hosts.txt"
    tmp_hosts.unlink(missing_ok=True)
    stage.outputs["all_activeScan_domain"] = all_active

    # 1A + 1B merged
    all_domain = runner.merge_dedupe([all_passive, all_active], outdir / "all_domain.txt")
    stage.outputs["all_domain"] = all_domain

    return stage


# --------------------------------------------------------------------------
# Legacy quick-pipeline helper. Kept only for undertow.py's old generic `run()`
# path (subfinder + crt.sh, no scope awareness) until that pipeline is
# replaced by run_stage1() end to end. Do not extend this — build onto
# run_stage1() instead.

def enumerate_subdomains(domain: str, timeout: int = 60) -> list:
    found: set[str] = set()
    if runner.have("subfinder"):
        try:
            proc = subprocess.run(
                ["subfinder", "-d", domain, "-silent"],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            found |= {l.strip() for l in proc.stdout.splitlines() if l.strip()}
        except subprocess.TimeoutExpired:
            pass
    try:
        resp = requests.get(f"https://crt.sh/?q=%25.{domain}&output=json", timeout=30)
        if resp.ok:
            for entry in resp.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.").lower()
                    if (name == domain or name.endswith("." + domain)) and HOSTNAME_RE.match(name):
                        found.add(name)
    except (requests.RequestException, ValueError):
        pass
    found.discard(domain)
    return sorted(found)
