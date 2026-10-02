"""Stage 7 — Screenshots for UNDERTOW.

Two separate EyeWitness runs, matching setup.py's pre-scaffolded directories:

  eyewitness --web -f INSCOPE_domain.txt        -> subdomain/eyewitness/
  eyewitness --web -x <nmap raw XML>             -> nmap/eyewitness/
  (Stage 4's HTTP(S) services, fed as nmap XML so EyeWitness itself decides
  which ports are web — no custom port-sniffing logic needed here)

Chosen over gowitness: not installed on this box, and EyeWitness's `-x`
nmap-XML ingestion solves the second input source for free; gowitness would
need custom nmap-result parsing plus a different output layout than the
screens/source convention setup.py already scaffolds.

Reads only INSCOPE_domain.txt + Stage 4's nmap output — same hard-gate
discipline as every other post-Stage-3 module.
"""
from __future__ import annotations

import subprocess
from pathlib import Path

from . import runner
from .runner import StageResult, ToolResult


def _run_eyewitness(argv_input: list[str], outdir: Path, timeout: int, label: str, engagement_root: Path) -> ToolResult:
    if not runner.have("eyewitness"):
        return ToolResult(tool=f"eyewitness-{label}", ran=False, error="not installed")

    outdir.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            ["eyewitness", "--web", *argv_input, "--no-prompt", "--prepend-https", "-d", str(outdir), "--timeout", "15"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, f"eyewitness_{label}.txt", exc.stdout or "", exc.stderr or "")
        return ToolResult(tool=f"eyewitness-{label}", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, f"eyewitness_{label}.txt", proc.stdout, proc.stderr)
    screens_dir = outdir / "screens"
    shot_count = len(list(screens_dir.glob("*.png"))) if screens_dir.exists() else 0
    report = outdir / "report.html"

    if not report.exists() and shot_count == 0:
        return ToolResult(
            tool=f"eyewitness-{label}", ran=True, returncode=proc.returncode,
            error=(proc.stderr or proc.stdout or "no report/screenshots produced").strip()[-200:],
        )

    return ToolResult(
        tool=f"eyewitness-{label}", ran=True, returncode=proc.returncode,
        outfile=report if report.exists() else outdir, lines=shot_count,
    )


def run_stage7(
    inscope_domain_file: Path,
    engagement_root: Path,
    *,
    timeout: int = 600,
) -> StageResult:
    stage = StageResult(stage="Stage 7 — Screenshots")

    hosts = runner.read_lines(inscope_domain_file)
    if not hosts:
        stage.add(ToolResult(tool="eyewitness", ran=False, error="INSCOPE_domain.txt is empty — nothing to screenshot"))
        return stage

    sub_outdir = engagement_root / "subdomain" / "eyewitness"
    stage.add(_run_eyewitness(["-f", str(inscope_domain_file)], sub_outdir, timeout, label="subdomain", engagement_root=engagement_root))

    nmap_xml = engagement_root / "nmap" / ".nmap_raw.xml"
    nmap_outdir = engagement_root / "nmap" / "eyewitness"
    if nmap_xml.exists():
        stage.add(_run_eyewitness(["-x", str(nmap_xml)], nmap_outdir, timeout, label="nmap", engagement_root=engagement_root))
    else:
        stage.add(ToolResult(tool="eyewitness-nmap", ran=False, error="no Stage 4 nmap results to screenshot (run Stage 4 first)"))

    return stage
