"""Stage 5 — Web / URL / Param Discovery for UNDERTOW.

Reads only INSCOPE_domain.txt (Stage 3's locked scope gate output).

  katana (active crawl, sole default)        -> Loot/katana.txt
  gau (archive/passive, sole default)        -> Loot/gau.txt
  merge + dedupe                             -> Loot/urls.txt
  arjun (params, sole default)               -> Loot/arjun.txt
  ffuf (content discovery, sole default)     -> dirbrute/ffuf_<host>.txt (one per host)
  cariddi                                    -> Loot/cariddi.txt
  WAF + 403 detection on in-scope hosts      -> subdomain/nowaf_subs.txt, subdomain/403_subs.txt

  5.1 gf vuln-candidate triage — manual-verification checklist only. Per
  absolute rule 5, these are candidates, never auto-exploited and never shown
  on the graded Attack Vectors report tab:
      sqli/xss/lfi/ssrf/redirect/idor/rce/ssti/debug_logic
      -> Loot/vuln_candidates/<category>.txt
"""
from __future__ import annotations

import json
import subprocess
from pathlib import Path

from . import runner
from .runner import StageResult, ToolResult

DEFAULT_FFUF_WORDLIST = Path("/usr/share/seclists/Discovery/Web-Content/common.txt")
GF_CATEGORIES = ("sqli", "xss", "lfi", "ssrf", "redirect", "idor", "rce", "ssti", "debug_logic")


# --------------------------------------------------------------- 5 · crawl + archive

def _run_katana(inscope_file: Path, outfile: Path, timeout: int) -> ToolResult:
    if not runner.have("katana"):
        return ToolResult(tool="katana", ran=False, error="not installed")
    try:
        proc = subprocess.run(
            ["katana", "-list", str(inscope_file), "-silent", "-d", "3"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool="katana", ran=True, error=f"timeout after {timeout}s")

    lines = sorted({ln.strip() for ln in proc.stdout.splitlines() if ln.strip()})
    runner.write_lines(outfile, lines)
    return ToolResult(tool="katana", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


def _run_gau(inscope_file: Path, outfile: Path, timeout: int) -> ToolResult:
    if not runner.have("gau"):
        return ToolResult(tool="gau", ran=False, error="not installed")
    hosts = runner.read_lines(inscope_file)
    try:
        proc = subprocess.run(
            ["gau", "--threads", "5"],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool="gau", ran=True, error=f"timeout after {timeout}s")

    lines = sorted({ln.strip() for ln in proc.stdout.splitlines() if ln.strip()})
    runner.write_lines(outfile, lines)
    return ToolResult(tool="gau", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


# -------------------------------------------------------------------- params

def _run_arjun(urls_file: Path, outfile: Path, timeout: int) -> ToolResult:
    if not runner.have("arjun"):
        return ToolResult(tool="arjun", ran=False, error="not installed (pipx install arjun)")
    json_tmp = outfile.parent / ".arjun_native.json"
    try:
        proc = subprocess.run(
            ["arjun", "-i", str(urls_file), "-oJ", str(json_tmp), "-t", "5"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        json_tmp.unlink(missing_ok=True)
        return ToolResult(tool="arjun", ran=True, error=f"timeout after {timeout}s")

    if not json_tmp.exists():
        return ToolResult(tool="arjun", ran=True, returncode=proc.returncode, error=(proc.stderr or "no output").strip()[:200])

    try:
        data = json.loads(json_tmp.read_text())
    except ValueError as exc:
        json_tmp.unlink(missing_ok=True)
        return ToolResult(tool="arjun", ran=True, returncode=proc.returncode, error=f"JSON parse error: {exc}")
    json_tmp.unlink(missing_ok=True)

    lines = []
    # arjun's -oJ schema is {"<url>": {"params": [...], ...}, ...}
    for url, info in sorted(data.items()):
        params = info.get("params", info) if isinstance(info, dict) else info
        if params:
            lines.append(f"{url} -> params: {', '.join(params)}")

    runner.write_lines(outfile, lines)
    return ToolResult(tool="arjun", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


# ---------------------------------------------------------- content discovery

def _run_ffuf_host(host: str, wordlist: Path, outfile: Path, timeout: int) -> ToolResult:
    json_tmp = outfile.parent / f".ffuf_native_{host}.json"
    try:
        proc = subprocess.run(
            [
                "ffuf", "-u", f"https://{host}/FUZZ", "-w", str(wordlist),
                "-mc", "200,204,301,302,307,401,403",
                "-ac", "-s", "-of", "json", "-o", str(json_tmp),
            ],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        json_tmp.unlink(missing_ok=True)
        return ToolResult(tool="ffuf", ran=True, error=f"timeout after {timeout}s ({host})")

    if not json_tmp.exists():
        return ToolResult(tool="ffuf", ran=True, returncode=proc.returncode, error=f"no output for {host}")

    try:
        data = json.loads(json_tmp.read_text())
    except ValueError as exc:
        json_tmp.unlink(missing_ok=True)
        return ToolResult(tool="ffuf", ran=True, returncode=proc.returncode, error=f"JSON parse error ({host}): {exc}")
    json_tmp.unlink(missing_ok=True)

    lines = []
    for r in data.get("results", []):
        word = (r.get("input", {}) or {}).get("FUZZ", "")
        status = r.get("status", "")
        lines.append(f"/{word} [{status}]")

    runner.write_lines(outfile, sorted(set(lines)))
    return ToolResult(tool="ffuf", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines), detail=host)


def _run_ffuf(hosts: list[str], outdir: Path, wordlist: Path | None, timeout: int) -> list[ToolResult]:
    wl = wordlist or DEFAULT_FFUF_WORDLIST
    if not runner.have("ffuf"):
        return [ToolResult(tool="ffuf", ran=False, error="not installed")]
    if not wl.exists():
        return [ToolResult(tool="ffuf", ran=False, error=f"wordlist not found: {wl}")]

    outdir.mkdir(parents=True, exist_ok=True)
    return [_run_ffuf_host(host, wl, outdir / f"ffuf_{host}.txt", timeout) for host in hosts]


# ------------------------------------------------------------------- cariddi

def _run_cariddi(inscope_file: Path, outfile: Path, timeout: int) -> ToolResult:
    if not runner.have("cariddi"):
        return ToolResult(tool="cariddi", ran=False, error="not installed")
    hosts = runner.read_lines(inscope_file)
    try:
        proc = subprocess.run(
            ["cariddi", "-e", "-err"],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool="cariddi", ran=True, error=f"timeout after {timeout}s")

    lines = [ln.rstrip() for ln in proc.stdout.splitlines() if ln.strip()]
    runner.write_lines(outfile, lines)
    return ToolResult(tool="cariddi", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


# ------------------------------------------------------------------ WAF/403

def _run_waf_403_split(inscope_file: Path, outdir: Path, timeout: int) -> list[ToolResult]:
    if not runner.have("httpx"):
        return [ToolResult(tool="httpx-waf", ran=False, error="not installed")]
    hosts = runner.read_lines(inscope_file)
    try:
        proc = subprocess.run(
            ["httpx", "-cdn", "-sc", "-json", "-silent", "-timeout", "5", "-retries", "0"],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return [ToolResult(tool="httpx-waf", ran=True, error=f"timeout after {timeout}s")]

    nowaf, has_403 = [], []
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        host = data.get("host", data.get("input", "")).strip()
        if not host:
            continue
        if str(data.get("status_code", "")) == "403":
            has_403.append(host)
        if not data.get("cdn", False):
            nowaf.append(host)

    nowaf_file = outdir / "nowaf_subs.txt"
    sub403_file = outdir / "403_subs.txt"
    runner.write_lines(nowaf_file, sorted(set(nowaf)))
    runner.write_lines(sub403_file, sorted(set(has_403)))
    return [
        ToolResult(tool="httpx-waf", ran=True, returncode=proc.returncode, outfile=nowaf_file, lines=len(set(nowaf))),
        ToolResult(tool="httpx-403", ran=True, returncode=proc.returncode, outfile=sub403_file, lines=len(set(has_403))),
    ]


# --------------------------------------------------------- 5.1 gf vuln triage

def _run_gf(category: str, urls_file: Path, outfile: Path, timeout: int) -> ToolResult:
    if not runner.have("gf"):
        return ToolResult(tool=f"gf-{category}", ran=False, error="not installed")
    urls = runner.read_lines(urls_file)
    try:
        proc = subprocess.run(
            ["gf", category],
            input="\n".join(urls),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool=f"gf-{category}", ran=True, error=f"timeout after {timeout}s")

    lines = sorted({ln.strip() for ln in proc.stdout.splitlines() if ln.strip()})
    runner.write_lines(outfile, lines)
    return ToolResult(tool=f"gf-{category}", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


# --------------------------------------------------------------- orchestrate

def run_stage5(
    inscope_domain_file: Path,
    engagement_root: Path,
    *,
    timeout: int = 300,
    ffuf_wordlist: Path | None = None,
) -> StageResult:
    loot_dir = engagement_root / "Loot"
    dirbrute_dir = engagement_root / "dirbrute"
    subdomain_dir = engagement_root / "subdomain"
    loot_dir.mkdir(parents=True, exist_ok=True)

    stage = StageResult(stage="Stage 5 — Web/URL/Param Discovery")

    hosts = runner.read_lines(inscope_domain_file)
    if not hosts:
        stage.add(ToolResult(tool="web_discovery", ran=False, error="INSCOPE_domain.txt is empty — nothing to crawl"))
        return stage

    katana_r = stage.add(_run_katana(inscope_domain_file, loot_dir / "katana.txt", timeout))
    gau_r = stage.add(_run_gau(inscope_domain_file, loot_dir / "gau.txt", timeout))

    url_sources = [r.outfile for r in (katana_r, gau_r) if r.outfile]
    urls_file = runner.merge_dedupe(url_sources, loot_dir / "urls.txt")
    stage.outputs["urls"] = urls_file

    stage.add(_run_arjun(urls_file, loot_dir / "arjun.txt", timeout))

    for r in _run_ffuf(hosts, dirbrute_dir, ffuf_wordlist, timeout):
        stage.add(r)

    stage.add(_run_cariddi(inscope_domain_file, loot_dir / "cariddi.txt", timeout))

    for r in _run_waf_403_split(inscope_domain_file, subdomain_dir, timeout):
        stage.add(r)

    vuln_dir = loot_dir / "vuln_candidates"
    vuln_dir.mkdir(parents=True, exist_ok=True)
    for category in GF_CATEGORIES:
        stage.add(_run_gf(category, urls_file, vuln_dir / f"{category}.txt", timeout))

    return stage
