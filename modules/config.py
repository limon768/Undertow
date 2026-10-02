"""Token config file for UNDERTOW — keeps secrets out of shell history/`ps`.

Passing `--github-token ghp_...` etc. on the CLI puts the raw token in shell
history and in every other process's `ps aux` output for the run's duration.
Instead, tokens can be dropped into a plain KEY=VALUE file and loaded here;
CLI flags still work and take precedence, for one-off overrides.
"""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).parent.parent

# Looked up in the repo root itself (next to undertow.py) rather than the
# user's home dir, so the token file travels with a given checkout/engagement
# box instead of being a separate dotfile to remember.
DEFAULT_CONFIG_PATHS = [
    REPO_ROOT / ".undertow.config",
]

# Recognized keys. Add new tool tokens here as they're wired in.
KNOWN_KEYS = {"GITHUB_TOKEN", "WPSCAN_API_TOKEN"}


def load_config(path: Path | None = None) -> dict[str, str]:
    """Reads KEY=VALUE lines (# comments and blank lines ignored) from an
    explicit `path`, or the first default location that exists. Returns {}
    if nothing is found. Never logs or echoes the values it reads.
    """
    candidates = [path] if path else DEFAULT_CONFIG_PATHS
    for candidate in candidates:
        if candidate and candidate.exists():
            out: dict[str, str] = {}
            for line in candidate.read_text(errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, _, val = line.partition("=")
                out[key.strip().upper()] = val.strip().strip('"').strip("'")
            return out
    return {}
