import shutil
import subprocess
from pathlib import Path

TOOLS_DIR = Path(__file__).parent.parent / "tools"
SUBSCRAPER_DIR = TOOLS_DIR / "subscraper"
SUBSCRAPER_PY = SUBSCRAPER_DIR / "subscraper.py"
VENV_PYTHON = Path(__file__).parent.parent / ".venv" / "bin" / "python"

CROSSLINKED_DIR = TOOLS_DIR / "crosslinked"
CROSSLINKED_PY = CROSSLINKED_DIR / "crosslinked.py"
BRIDGEKEEPER_DIR = TOOLS_DIR / "bridgekeeper"
BRIDGEKEEPER_PY = BRIDGEKEEPER_DIR / "bridgekeeper.py"

# Stage 0 dependency registry. Each tool declares how it *can* be auto-installed;
# tools with no installer (e.g. private/custom scripts) are flagged manual-only.
TOOLS = {
    "amass":      {"install": ("apt", "amass")},
    "subfinder":  {"install": ("go", "github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest")},
    "httpx":      {"install": ("go", "github.com/projectdiscovery/httpx/cmd/httpx@latest")},
    "grepcidr":   {"install": ("apt", "grepcidr")},
    "cariddi":    {"install": ("go", "github.com/edoardottt/cariddi/cmd/cariddi@latest")},
    "whois":      {"install": ("apt", "whois")},
    "nmap":       {"install": ("apt", "nmap")},
    "wpscan":     {"install": ("apt", "wpscan")},
    "eyewitness": {"install": ("apt", "eyewitness")},
    "gobuster":   {"install": ("apt", "gobuster")},
    "ffuf":       {"install": ("apt", "ffuf")},
    "smap":       {"install": ("go", "github.com/s0md3v/smap/cmd/smap@latest")},
    "naabu":      {"install": ("go", "github.com/projectdiscovery/naabu/v2/cmd/naabu@latest")},
    "dnsx":       {"install": ("go", "github.com/projectdiscovery/dnsx/cmd/dnsx@latest")},
    "shodan":     {"install": None, "note": "pip-installed `shodan` CLI, needs `shodan init <API key>` run manually once"},
    "katana":     {"install": ("go", "github.com/projectdiscovery/katana/cmd/katana@latest")},
    "gau":        {"install": ("go", "github.com/lc/gau/v2/cmd/gau@latest")},
    "github-subdomains": {
        "install": ("go", "github.com/gwen001/github-subdomains@latest"),
        "note": "optional Stage 1 passive source, needs GITHUB_TOKEN in .undertow.config "
                "(or --github-token)",
    },
    "gf":         {
        "install": ("go", "github.com/tomnomnom/gf@latest"),
        "note": "also needs a pattern pack in ~/.gf — the binary ships with zero patterns "
                "(this box has github.com/1ndianl33t/Gf-Patterns installed already)",
    },
    "arjun":      {"install": ("pipx", "arjun"), "note": "Kali blocks system pip installs — pipx is the supported path"},
    "jsleak":     {"install": ("go", "github.com/channyein1337/jsleak@latest")},
    "trufflehog": {"install": ("apt", "trufflehog")},
    "nuclei":     {"install": ("go", "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")},
    "semgrep":    {"install": ("pipx", "semgrep"), "note": "opt-in, Stage 6 --js-semgrep only — weak fit for minified JS"},
    "js-beautify": {"install": ("pipx", "jsbeautifier"), "note": "Stage 6 fallback for minified JS with no recoverable source map"},
    "cloud_enum":  {"install": ("apt", "cloud-enum")},
    "testssl.sh":  {"install": None, "note": "not in apt; clone github.com/drwetter/testssl.sh and symlink into PATH"},
    "ssh-audit":   {"install": ("pipx", "ssh-audit")},
    "sslscan":     {"install": ("apt", "sslscan")},
    "ike-scan":    {"install": ("apt", "ike-scan")},
    "subzy":       {"install": ("go", "github.com/LukaSikic/subzy@latest")},
    "socialhunter": {"install": ("go", "github.com/utkusen/socialhunter@latest")},
    "nikto":       {"install": ("apt", "nikto")},
    "metagoofil":  {"install": ("apt", "metagoofil")},
    "exiftool":    {"install": ("apt", "libimage-exiftool-perl")},
    "subscraper": {"install": ("git", "https://github.com/m8sec/subscraper"), "note": "cloned into tools/subscraper, deps in .venv"},
    "crosslinked": {"install": ("git", "https://github.com/m8sec/CrossLinked"), "note": "cloned into tools/crosslinked, deps in .venv"},
    "bridgekeeper": {"install": ("git", "https://github.com/0xZDH/BridgeKeeper"), "note": "cloned into tools/bridgekeeper, deps in .venv"},
}


def subscraper_available() -> bool:
    return SUBSCRAPER_PY.exists() and VENV_PYTHON.exists()


def crosslinked_available() -> bool:
    return CROSSLINKED_PY.exists() and VENV_PYTHON.exists()


def bridgekeeper_available() -> bool:
    return BRIDGEKEEPER_PY.exists() and VENV_PYTHON.exists()


def _ensure_venv() -> bool:
    venv_dir = VENV_PYTHON.parent.parent
    if VENV_PYTHON.exists():
        return True
    try:
        subprocess.run(["python3", "-m", "venv", str(venv_dir)], check=True, timeout=60)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def _install_cloned_py_tool(repo_url: str, dest_dir: Path, requirements_name: str = "requirements.txt") -> bool:
    """Shared clone-into-tools/+shared-venv pattern used by subscraper,
    crosslinked, and bridgekeeper — all small single-file-ish Python OSINT
    scripts with their own requirements.txt, none pip-installable system-wide
    (Kali blocks that) and none substantial enough to warrant their own venv.
    """
    if not dest_dir.exists():
        try:
            subprocess.run(
                ["git", "clone", "--depth", "1", repo_url, str(dest_dir)], check=True, timeout=120,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
            return False

    if not _ensure_venv():
        return False

    req_file = dest_dir / requirements_name
    if req_file.exists():
        try:
            subprocess.run(
                [str(VENV_PYTHON), "-m", "pip", "install", "-q", "-r", str(req_file)],
                check=True, timeout=180,
            )
        except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
            return False
    return True


def _install_subscraper() -> bool:
    ok = _install_cloned_py_tool("https://github.com/m8sec/subscraper", SUBSCRAPER_DIR)
    return ok and subscraper_available()


def _install_crosslinked() -> bool:
    ok = _install_cloned_py_tool("https://github.com/m8sec/CrossLinked", CROSSLINKED_DIR)
    return ok and crosslinked_available()


def _install_bridgekeeper() -> bool:
    ok = _install_cloned_py_tool("https://github.com/0xZDH/BridgeKeeper", BRIDGEKEEPER_DIR)
    return ok and bridgekeeper_available()


def _install_apt(package: str) -> bool:
    try:
        subprocess.run(["sudo", "apt-get", "install", "-y", package], check=True, timeout=300)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired, FileNotFoundError):
        return False


def _install_go(module: str) -> bool:
    if not shutil.which("go"):
        return False
    try:
        subprocess.run(["go", "install", module], check=True, timeout=300)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def _install_pipx(package: str) -> bool:
    if not shutil.which("pipx"):
        return False
    try:
        subprocess.run(["pipx", "install", package], check=True, timeout=180)
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def check_tools(names: list, auto_install: bool = False) -> dict:
    status = {}
    for name in names:
        tool = TOOLS.get(name)
        if tool is None:
            status[name] = "unknown"
            continue

        if name in ("subscraper", "crosslinked", "bridgekeeper"):
            available_fn, install_fn = {
                "subscraper": (subscraper_available, _install_subscraper),
                "crosslinked": (crosslinked_available, _install_crosslinked),
                "bridgekeeper": (bridgekeeper_available, _install_bridgekeeper),
            }[name]
            if available_fn():
                status[name] = "found"
            elif auto_install and install_fn():
                status[name] = "installed"
            elif auto_install:
                status[name] = "failed"
            else:
                status[name] = "missing"
            continue

        if shutil.which(name):
            status[name] = "found"
            continue

        if not auto_install:
            status[name] = "missing"
            continue

        if tool["install"] is None:
            status[name] = "manual"
            continue

        method, target = tool["install"]
        installers = {"apt": _install_apt, "go": _install_go, "pipx": _install_pipx}
        installed = installers[method](target)
        if installed and shutil.which(name):
            status[name] = "installed"
        else:
            status[name] = "failed"

    return status


def print_status(status: dict):
    icons = {
        "found": "[OK]",
        "installed": "[INSTALLED]",
        "missing": "[MISSING]",
        "failed": "[FAILED]",
        "manual": "[MANUAL]",
        "unknown": "[UNKNOWN]",
    }
    for name, state in status.items():
        note = TOOLS.get(name, {}).get("note", "")
        line = f"  {icons.get(state, '[?]'):<12} {name}"
        if state in ("manual", "missing", "failed") and note:
            line += f" — {note}"
        print(line)
