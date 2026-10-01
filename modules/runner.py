"""Shared subprocess + file helpers for UNDERTOW stage modules.

Rule 1 (one named output file per tool that actually runs) is enforced here: a
wrapper calls `have()` first and only writes the tool's output file when the tool
is actually present and runs. A missing tool is reported as skipped and leaves no
empty file behind.
"""
from __future__ import annotations

import shutil
import subprocess
from dataclasses import dataclass, field
from pathlib import Path


@dataclass
class ToolResult:
    tool: str
    ran: bool
    returncode: int | None = None
    outfile: Path | None = None
    lines: int = 0
    error: str | None = None
    detail: str = ""


@dataclass
class StageResult:
    stage: str
    tools: list[ToolResult] = field(default_factory=list)
    outputs: dict[str, Path] = field(default_factory=dict)

    def add(self, result: ToolResult) -> ToolResult:
        self.tools.append(result)
        return result


def have(tool: str) -> bool:
    return shutil.which(tool) is not None


def run_tool(
    tool: str,
    argv: list[str],
    outfile: Path | None = None,
    *,
    timeout: int = 600,
    stdin_text: str | None = None,
    input_file: Path | None = None,
    append: bool = False,
) -> ToolResult:
    """Run one external tool. Writes stdout to `outfile` only if the tool ran.

    Passing `input_file` streams that file to the process stdin.
    """
    if not have(tool):
        return ToolResult(tool=tool, ran=False, error="not installed")

    stdin_data = stdin_text
    if input_file is not None and input_file.exists():
        stdin_data = input_file.read_text(errors="replace")

    try:
        proc = subprocess.run(
            argv,
            input=stdin_data,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired:
        return ToolResult(tool=tool, ran=True, error=f"timeout after {timeout}s")
    except (OSError, ValueError) as exc:
        return ToolResult(tool=tool, ran=True, error=str(exc))

    stdout = proc.stdout or ""
    result = ToolResult(tool=tool, ran=True, returncode=proc.returncode)

    if outfile is not None:
        outfile.parent.mkdir(parents=True, exist_ok=True)
        mode = "a" if append else "w"
        with outfile.open(mode) as fh:
            fh.write(stdout)
        result.outfile = outfile
        result.lines = count_lines(outfile)
    else:
        result.lines = len([ln for ln in stdout.splitlines() if ln.strip()])

    if proc.returncode != 0 and not stdout.strip():
        result.error = (proc.stderr or "").strip()[:200] or f"exit {proc.returncode}"
    return result


def read_lines(path: Path) -> list[str]:
    if not path.exists():
        return []
    out = []
    for line in path.read_text(errors="replace").splitlines():
        s = line.strip()
        if s and not s.startswith("#"):
            out.append(s)
    return out


def write_lines(path: Path, lines: list[str]) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines) + ("\n" if lines else ""))
    return path


def count_lines(path: Path) -> int:
    if not path.exists():
        return 0
    return sum(1 for ln in path.read_text(errors="replace").splitlines() if ln.strip())


def merge_dedupe(sources: list[Path], out: Path) -> Path:
    """Union non-empty, non-comment lines from sources, sorted, into `out`."""
    seen: set[str] = set()
    for src in sources:
        for line in read_lines(src):
            seen.add(line)
    return write_lines(out, sorted(seen))
