"""Stage 3 — hard scope gate for UNDERTOW (absolute rule 2).

Reads subdomain/alive_domain.txt ("host [status] [title] [ip]" lines from
Stage 2), classifies every host+IP pair with scope.Scope, and writes:

  INSCOPE_domain.txt          - in-scope hostnames only, one per line
  INSCOPE_subdomain_ip.txt    - "host -> ip" for in-scope hosts
  OUT_OF_SCOPE_domain.txt     - "host -> ip  (reason)", audit record only

Everything from Stage 4 onward reads only the two INSCOPE_* files.
OUT_OF_SCOPE_domain.txt is never read again downstream — no exceptions.
"""
from __future__ import annotations

import re
from pathlib import Path

from . import runner
from .runner import StageResult, ToolResult
from .scope import Scope

ALIVE_LINE_RE = re.compile(
    r"^(?P<host>\S+)\s+\[(?P<status>[^\]]*)\]\s+\[(?P<title>[^\]]*)\]\s+\[(?P<ip>[^\]]*)\]$"
)

OOS_HEADER = "# archived only — never read downstream"


def _parse_alive_domain(path: Path) -> list[tuple[str, str]]:
    """Return [(host, ip), ...] parsed from alive_domain.txt lines."""
    pairs = []
    for line in runner.read_lines(path):
        m = ALIVE_LINE_RE.match(line)
        if not m:
            continue
        pairs.append((m.group("host"), m.group("ip")))
    return pairs


def run_stage3(alive_domain_file: Path, engagement_root: Path) -> StageResult:
    """Run the Stage 3 scope gate and write INSCOPE_*/OUT_OF_SCOPE_* files."""
    outdir = engagement_root / "subdomain"
    outdir.mkdir(parents=True, exist_ok=True)

    stage = StageResult(stage="Stage 3 — Scope Gate")

    scope = Scope.from_engagement(engagement_root)
    if not scope.has_any:
        stage.add(
            ToolResult(
                tool="scope_gate",
                ran=False,
                error="no scope.txt / web_scope.txt entries — nothing to gate against, refusing to run",
            )
        )
        return stage

    pairs = _parse_alive_domain(alive_domain_file)
    if not pairs:
        stage.add(ToolResult(tool="scope_gate", ran=True, error="alive_domain.txt empty or unparseable"))
        return stage

    inscope_hosts: set[str] = set()
    inscope_pairs: list[str] = []
    oos_lines: list[str] = []

    for host, ip in pairs:
        in_scope, reason = scope.classify(host, ip)
        if in_scope:
            inscope_hosts.add(host)
            inscope_pairs.append(f"{host} -> {ip}")
        else:
            oos_lines.append(f"{host} -> {ip}  ({reason})")

    inscope_domain_file = outdir / "INSCOPE_domain.txt"
    inscope_ip_file = outdir / "INSCOPE_subdomain_ip.txt"
    oos_file = outdir / "OUT_OF_SCOPE_domain.txt"

    runner.write_lines(inscope_domain_file, sorted(inscope_hosts))
    runner.write_lines(inscope_ip_file, sorted(set(inscope_pairs)))
    oos_file.parent.mkdir(parents=True, exist_ok=True)
    oos_file.write_text(OOS_HEADER + "\n" + "\n".join(sorted(set(oos_lines))) + ("\n" if oos_lines else ""))

    stage.add(
        ToolResult(
            tool="scope_gate",
            ran=True,
            returncode=0,
            outfile=inscope_domain_file,
            lines=len(inscope_hosts),
        )
    )
    stage.outputs["inscope_domain"] = inscope_domain_file
    stage.outputs["inscope_subdomain_ip"] = inscope_ip_file
    stage.outputs["out_of_scope_domain"] = oos_file

    return stage
