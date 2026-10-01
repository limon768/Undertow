"""Stage 10 — OSINT / Email Gathering for UNDERTOW.

  metagoofil (downloads public docs matching the domain, then author/creator
  metadata is pulled via exiftool — this version of metagoofil only searches
  + downloads, it no longer does metadata extraction itself)
      -> email/metagoofil.txt
  crosslinked (LinkedIn employee-name enumeration via search-engine
  scraping, no LinkedIn login/API needed)
      -> email/crosslinked.txt
  bridgekeeper (same search-engine-scrape approach, independent fingerprint/
  name-transform engine — kept alongside crosslinked exactly like the
  existing subscraper+amass+subfinder redundancy pattern: different sources,
  same target, merged and deduped downstream)
      -> email/bridgekeeper.txt
  merge + dedupe -> email/All_Emails.txt

Dehashed was explicitly removed per user request (passive breach-data lookup
dropped). All_Emails.txt feeds the user's own manual password-spray process
(CredMaster etc.), run entirely outside this tool — absolute rule 4.

metagoofil and crosslinked both depend on live Google/Bing scraping, which is
inherently CAPTCHA/rate-limit fragile — the same caveat already noted in
docs/workflow_v2.html for manual Google dorking. An empty result from either
may reflect that, not a bug in the wrapper.

Stage 10 needs a company/brand name for crosslinked/bridgekeeper, same as
Stage 8's cloud_enum — a required explicit `--company-name`, never guessed
from the domain.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

from . import runner, toolcheck
from .runner import StageResult, ToolResult

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}")


def _extract_emails(text: str) -> set[str]:
    return {e.lower() for e in EMAIL_RE.findall(text)}


# ----------------------------------------------------------------- metagoofil

def _run_metagoofil(domain: str, outdir: Path, timeout: int) -> ToolResult:
    if not runner.have("metagoofil"):
        return ToolResult(tool="metagoofil", ran=False, error="not installed")

    dl_dir = outdir / ".metagoofil_downloads"
    dl_dir.mkdir(parents=True, exist_ok=True)
    try:
        proc = subprocess.run(
            # -e: delay between per-filetype searches (default 30s — with 7
            # filetypes that's 210s+ before any downloading even starts).
            # 5s is a reasonable tradeoff for automation; still polite enough
            # not to guarantee an instant block.
            ["metagoofil", "-d", domain, "-t", "pdf,doc,docx,xls,xlsx,ppt,pptx",
             "-l", "20", "-n", "10", "-o", str(dl_dir), "-e", "5", "-w"],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(dl_dir, ignore_errors=True)
        return ToolResult(tool="metagoofil", ran=True, error=f"timeout after {timeout}s")

    emails: set[str] = set()
    downloaded = any(dl_dir.iterdir()) if dl_dir.exists() else False
    if downloaded and runner.have("exiftool"):
        try:
            ex_proc = subprocess.run(
                ["exiftool", "-Author", "-Creator", "-LastModifiedBy", "-r", str(dl_dir)],
                capture_output=True, text=True, timeout=min(timeout, 60),
            )
            emails = _extract_emails(ex_proc.stdout)
        except subprocess.TimeoutExpired:
            pass
    shutil.rmtree(dl_dir, ignore_errors=True)

    outfile = outdir / "metagoofil.txt"
    runner.write_lines(outfile, sorted(emails))
    detail = "" if downloaded else "no documents found (Google scraping is fragile/CAPTCHA-prone)"
    return ToolResult(tool="metagoofil", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(emails), detail=detail)


# ---------------------------------------------------------------- crosslinked

def _run_crosslinked(company_name: str, domain: str, outdir: Path, timeout: int) -> ToolResult:
    if not toolcheck.crosslinked_available():
        return ToolResult(tool="crosslinked", ran=False, error="not installed")

    outfile_base = outdir / ".crosslinked_native"
    nformat = f"{{first}}.{{last}}@{domain}"
    try:
        proc = subprocess.run(
            [str(toolcheck.VENV_PYTHON), str(toolcheck.CROSSLINKED_PY),
             "-f", nformat, "-o", str(outfile_base), company_name],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool="crosslinked", ran=True, error=f"timeout after {timeout}s")

    emails: set[str] = set()
    native_txt = outfile_base.with_suffix(".txt")
    if native_txt.exists():
        emails = _extract_emails(native_txt.read_text(errors="replace"))
        native_txt.unlink(missing_ok=True)
    outfile_base.with_suffix(".csv").unlink(missing_ok=True)

    outfile = outdir / "crosslinked.txt"
    runner.write_lines(outfile, sorted(emails))
    return ToolResult(tool="crosslinked", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(emails))


# --------------------------------------------------------------- bridgekeeper

def _run_bridgekeeper(company_name: str, domain: str, outdir: Path, timeout: int) -> ToolResult:
    if not toolcheck.bridgekeeper_available():
        return ToolResult(tool="bridgekeeper", ran=False, error="not installed")

    bk_outdir = outdir / ".bridgekeeper_native"
    nformat = f"{{f}}{{last}}@{domain}"
    try:
        proc = subprocess.run(
            [str(toolcheck.VENV_PYTHON), str(toolcheck.BRIDGEKEEPER_PY),
             "-c", company_name, "-f", nformat, "-d", domain, "-o", str(bk_outdir)],
            capture_output=True, text=True, timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        shutil.rmtree(bk_outdir, ignore_errors=True)
        return ToolResult(tool="bridgekeeper", ran=True, error=f"timeout after {timeout}s")

    emails: set[str] = set()
    if bk_outdir.exists():
        for f in bk_outdir.rglob("*"):
            if f.is_file():
                emails |= _extract_emails(f.read_text(errors="replace"))
        shutil.rmtree(bk_outdir, ignore_errors=True)

    outfile = outdir / "bridgekeeper.txt"
    runner.write_lines(outfile, sorted(emails))
    return ToolResult(tool="bridgekeeper", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(emails))


# --------------------------------------------------------------- orchestrate

def run_stage10(
    domain: str,
    company_name: str | None,
    engagement_root: Path,
    *,
    timeout: int = 300,
) -> StageResult:
    outdir = engagement_root / "email"
    outdir.mkdir(parents=True, exist_ok=True)

    stage = StageResult(stage="Stage 10 — OSINT / Email Gathering")

    results = [stage.add(_run_metagoofil(domain, outdir, timeout))]

    if company_name:
        results.append(stage.add(_run_crosslinked(company_name, domain, outdir, timeout)))
        results.append(stage.add(_run_bridgekeeper(company_name, domain, outdir, timeout)))
    else:
        stage.add(ToolResult(
            tool="crosslinked+bridgekeeper", ran=False,
            error="no --company-name given — never guessed from the domain",
        ))

    sources = [r.outfile for r in results if r.outfile]
    all_emails = runner.merge_dedupe(sources, outdir / "All_Emails.txt")
    stage.outputs["all_emails"] = all_emails

    return stage
