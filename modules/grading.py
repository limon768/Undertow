"""Stage 11 — Grading / Attack Vector Scoring for UNDERTOW (core deliverable).

Reads the output files Stages 4–10 actually produced, grades each finding
Critical/High/Medium/Low/Info with a one-line rationale, and sorts the whole
list most-likely-vulnerable -> least-likely (absolute rule 7 — that ranking,
not raw counts, is the report's primary view).

vtype is one of the 8 fixed categorical slots (CLAUDE.md's report-design
mandate, capped at 8, do not add a 9th without dropping/merging one):
  secret / misconfig / takeover / outdated / tls / access / injection / network

Absolute rule 5: Loot/vuln_candidates/* (gf-pattern matches) are a manual-
verification checklist, never auto-graded, and this module never reads that
directory. Stage 10's All_Emails.txt is OSINT for the user's own manual
password-spray process, not a vulnerability — also never graded here.

Output: attack_vectors.json (full structured list, for Stage 12's report) and
attack_vectors.txt (human-readable ranked summary) at the engagement root.
"""
from __future__ import annotations

import json
import re
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass
from pathlib import Path

from . import runner

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
VTYPE_LABELS = {
    "secret": "Exposed Secret / Leak",
    "misconfig": "Misconfiguration",
    "takeover": "Subdomain Takeover",
    "outdated": "Outdated Software / CVE",
    "tls": "SSL/TLS Weakness",
    "access": "Access Control / Open Panel",
    "injection": "Injection (SQLi/XSS)",
    "network": "Network / Other Exposure",
}
RISKY_PORTS = {
    "23": ("Telnet exposed externally — unencrypted admin access", "high", "network"),
    "3389": ("RDP exposed externally", "medium", "access"),
    "5900": ("VNC exposed externally", "high", "access"),
    "1433": ("MSSQL exposed externally", "medium", "network"),
    "3306": ("MySQL exposed externally", "medium", "network"),
    "5432": ("PostgreSQL exposed externally", "medium", "network"),
}
SENSITIVE_PATH_RE = re.compile(r"\.(env|git|sql|bak|zip|tar|gz|old|swp|config)\b|backup|\.env", re.IGNORECASE)


@dataclass
class Finding:
    severity: str
    vtype: str
    title: str
    asset: str
    rationale: str
    stage: str

    def vtype_label(self) -> str:
        return VTYPE_LABELS.get(self.vtype, self.vtype)


# ------------------------------------------------------------- Stage 2 + 4

def _grade_login_endpoints(root: Path) -> list[Finding]:
    f = root / "subdomain" / "login_endpoints.txt"
    return [
        Finding("info", "access", "Possible admin/login panel discovered", line, "Title metadata suggests an authentication endpoint — confirm exposure is intentional.", "Alive Host Discovery")
        for line in runner.read_lines(f)
    ]


def _grade_shodan(root: Path) -> list[Finding]:
    findings = []
    for line in runner.read_lines(root / "nmap" / "shodan.txt"):
        m = re.match(r"^(\S+)\s*\|\s*org:\s*(.*?)\s*\|\s*vulns:\s*(.*)$", line)
        if not m or m.group(3).strip() == "none indexed":
            continue
        ip, vulns = m.group(1), m.group(3).strip()
        findings.append(Finding(
            "high", "outdated", f"Shodan-indexed CVE(s) on {ip}", ip,
            f"{vulns} (Shodan-indexed — unconfirmed, verify manually before reporting as exploitable).",
            "Port Scan",
        ))
    return findings


def _grade_risky_ports(root: Path) -> list[Finding]:
    xml_path = root / "nmap" / ".nmap_raw.xml"
    if not xml_path.exists():
        return []
    try:
        xml_root = ET.fromstring(xml_path.read_text())
    except ET.ParseError:
        return []
    findings = []
    for host_el in xml_root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ip = addr_el.get("addr", "")
        for port_el in host_el.findall(".//port"):
            portid = port_el.get("portid", "")
            if portid not in RISKY_PORTS:
                continue
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            title, severity, vtype = RISKY_PORTS[portid]
            findings.append(Finding(severity, vtype, title, f"{ip}:{portid}", f"{title} — restrict to VPN/allowlisted sources if business need exists.", "Port Scan"))
    return findings


# ------------------------------------------------------------- Stage 5

def _grade_nowaf(root: Path) -> list[Finding]:
    return [
        Finding("info", "misconfig", "No CDN/WAF detected fronting this host", h, "Direct-to-origin exposure — no edge filtering layer observed.", "Web Discovery")
        for h in runner.read_lines(root / "subdomain" / "nowaf_subs.txt")
    ]


def _grade_ffuf(root: Path) -> list[Finding]:
    findings = []
    dirbrute = root / "dirbrute"
    if not dirbrute.exists():
        return findings
    for f in sorted(dirbrute.glob("ffuf_*.txt")):
        host = f.stem.removeprefix("ffuf_")
        for line in runner.read_lines(f):
            if "[200]" in line and SENSITIVE_PATH_RE.search(line):
                path = line.split(" [", 1)[0]
                findings.append(Finding(
                    "medium", "misconfig", "Sensitive-looking path discovered via content bruteforce",
                    f"{host}{path}", "Filename pattern suggests a backup/config/VCS file — confirm and remediate exposure.",
                    "Web Discovery",
                ))
    return findings


def _grade_cariddi(root: Path) -> list[Finding]:
    findings = []
    for line in runner.read_lines(root / "Loot" / "cariddi.txt"):
        if "index of" in line.lower() or "directory listing" in line.lower():
            asset = line.split(" -> ", 1)[0] if " -> " in line else line
            findings.append(Finding("medium", "misconfig", "Directory listing enabled", asset, "Exposes file/directory structure to any unauthenticated visitor.", "Web Discovery"))
    return findings


# ------------------------------------------------------------- Stage 6

def _grade_jsleak_trufflehog(root: Path) -> list[Finding]:
    js_dir = root / "JS"
    verified_urls = set()
    for line in runner.read_lines(js_dir / "trufflehog.txt"):
        asset, _, rest = line.partition(" : ")
        if "VERIFIED LIVE" in rest:
            verified_urls.add(asset)

    findings = []
    for line in runner.read_lines(js_dir / "trufflehog.txt"):
        asset, _, rest = line.partition(" : ")
        verified = "VERIFIED LIVE" in rest
        findings.append(Finding(
            "critical" if verified else "medium", "secret",
            "Live credential found in JS" if verified else "Possible credential found in JS (unverified)",
            asset, rest.strip(), "JS Analysis",
        ))

    for line in runner.read_lines(js_dir / "jsleak.txt"):
        if not line.lower().startswith("[secret]"):
            continue
        m = re.match(r"\[secret\]\s*(\S+)\s*:\s*(.+)", line, re.IGNORECASE)
        if not m:
            continue
        asset, detail = m.group(1), m.group(2)
        if asset in verified_urls:
            continue  # already graded (and escalated) via trufflehog above
        findings.append(Finding("high", "secret", "Potential secret found in JS bundle", asset, f"{detail} — not yet verified live, confirm before escalating.", "JS Analysis"))
    return findings


SEMGREP_ASSET_RE = re.compile(r"^(https?://\S+\.js|[\w./-]+\.js)$")


def _grade_semgrep(root: Path) -> list[Finding]:
    text = (root / "JS" / "semgrep.txt")
    if not text.exists():
        return []
    findings = []
    current_asset = "beautified/recovered JS"  # fallback if semgrep's own file-path line isn't recognized
    for line in text.read_text(errors="replace").splitlines():
        stripped = line.strip()
        asset_m = SEMGREP_ASSET_RE.match(stripped)
        if asset_m:
            current_asset = asset_m.group(1)
            continue
        m = re.match(r"^❯❱\s*(\S+)", stripped)
        if not m:
            continue
        rule_id = m.group(1)
        vtype = "injection" if re.search(r"sqli|xss|ssrf|inject", rule_id, re.IGNORECASE) else "misconfig"
        findings.append(Finding("low", vtype, f"Semgrep finding: {rule_id}", current_asset, "Flagged on de-minified JS — semgrep has a weak hit rate on black-box JS, manually verify relevance.", "JS Analysis"))
    return findings


# ------------------------------------------------------------- Stage 8

def _grade_cloud_assets(root: Path) -> list[Finding]:
    findings = []
    for line in runner.read_lines(root / "MISC" / "cloud_assets.txt"):
        if "PUBLIC" not in line:
            continue
        parts = [p.strip() for p in line.split("|")]
        asset = parts[1] if len(parts) > 1 else line
        findings.append(Finding("high", "misconfig", "Publicly listable cloud storage bucket", asset, "Anyone can enumerate (and potentially read) bucket contents — audit for sensitive data.", "Cloud Assets"))
    return findings


# ------------------------------------------------------------- Stage 9

def _grade_wpscan(root: Path) -> list[Finding]:
    findings = []
    wpdir = root / "wpscan"
    if not wpdir.exists():
        return findings
    for f in sorted(wpdir.glob("*.txt")):
        host = f.stem
        for line in runner.read_lines(f):
            if "vulnerable plugin" in line.lower() or "vulnerable theme" in line.lower():
                findings.append(Finding("high", "outdated", "Vulnerable WordPress plugin/theme in use", host, line.lstrip("[+] ").strip(), "WPScan"))
            elif "wordpress version" in line.lower() and "outdated" in line.lower():
                findings.append(Finding("medium", "outdated", "Outdated WordPress core version", host, line.lstrip("[+] ").strip(), "WPScan"))
    return findings


def _grade_ssl(root: Path) -> list[Finding]:
    findings = []
    for line in runner.read_lines(root / "MISC" / "sslscan.txt"):
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 3:
            continue
        asset, tls10, tls11 = parts[0], parts[1], parts[2]
        if tls10 == "Yes":
            findings.append(Finding("low", "tls", "TLSv1.0 enabled", asset, "Deprecated protocol — vulnerable to known downgrade/cipher attacks.", "Service Checks"))
        if tls11 == "Yes":
            findings.append(Finding("low", "tls", "TLSv1.1 enabled", asset, "Deprecated protocol — should be disabled per current best practice.", "Service Checks"))
    for line in runner.read_lines(root / "MISC" / "testssl.txt"):
        if "no notable issues flagged" in line or "timeout" in line.lower():
            continue
        asset = line.split(" -> ", 1)[0] if " -> " in line else line
        findings.append(Finding("medium", "tls", "TLS configuration issue(s) flagged", asset, line.split(" -> ", 1)[-1], "Service Checks"))
    return findings


def _grade_ssh_audit(root: Path) -> list[Finding]:
    findings = []
    for line in runner.read_lines(root / "MISC" / "ssh-audit.txt"):
        if "weak algorithm" in line.lower():
            asset = line.split(" -> ", 1)[0]
            findings.append(Finding("low", "misconfig", "Weak SSH algorithm(s) offered", asset, line.split(" -> ", 1)[-1], "Service Checks"))
    return findings


def _grade_ike(root: Path) -> list[Finding]:
    findings = []
    for line in runner.read_lines(root / "MISC" / "ike-scan.txt"):
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) < 2 or parts[1] != "Yes":
            continue
        asset = parts[0]
        findings.append(Finding("high", "access", "IKE aggressive mode enabled, PSK hash retrievable", asset, "Aggressive mode leaks a crackable PSK hash to any unauthenticated peer.", "Service Checks"))
    return findings


def _grade_subzy(root: Path) -> list[Finding]:
    findings = []
    for line in runner.read_lines(root / "MISC" / "subzy.txt"):
        if line.startswith("#") or "100%" not in line:
            continue
        asset = line.split()[0]
        findings.append(Finding("critical", "takeover", "Dangling DNS record — subdomain takeover possible", asset, "subzy fingerprint match against an unclaimed provider-side resource — verify manually before claiming.", "Service Checks"))
    return findings


def _grade_socialhunter(root: Path) -> list[Finding]:
    f = root / "MISC" / "socialhunter.txt"
    if not f.exists():
        return []
    findings = []
    for line in runner.read_lines(f):
        if line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) < 2:
            continue
        findings.append(Finding("low", "misconfig", "Broken social media link (account squatting risk)", parts[0], f"Linked account {parts[1]} appears unclaimed/suspended.", "Service Checks"))
    return findings


def _grade_git_exposure(root: Path) -> list[Finding]:
    findings = []
    for line in runner.read_lines(root / "MISC" / "git_exposure.txt"):
        if "EXPOSED" in line:
            asset = line.split(" -> ", 1)[0]
            findings.append(Finding("high", "misconfig", ".git directory exposed", asset, "Source history/config may be fully downloadable — high risk of credential/source disclosure.", "Service Checks"))
    return findings


def _grade_clickjack(root: Path) -> list[Finding]:
    f = root / "MISC" / "clickjack_poc.html"
    if not f.exists():
        return []
    findings = []
    for m in re.finditer(r"<!-- (\S+): Vulnerable=Yes \((.+?)\) -->", f.read_text(errors="replace")):
        findings.append(Finding("medium", "misconfig", "Missing clickjacking protection", m.group(1), f"{m.group(2)} — page can be framed by any third-party site.", "Service Checks"))
    return findings


NUCLEI_SEVERITY_RE = re.compile(r"\[(critical|high|medium|low|info)\]", re.IGNORECASE)


def _grade_nuclei(root: Path, filename: str, stage_label: str) -> list[Finding]:
    f = root / "MISC" / filename
    if not f.exists():
        f = root / "JS" / filename
    findings = []
    for line in runner.read_lines(f):
        m = NUCLEI_SEVERITY_RE.search(line)
        severity = m.group(1).lower() if m else "info"
        findings.append(Finding(severity, "misconfig", "nuclei template match", line.strip(), line.strip(), stage_label))
    return findings


def _grade_nikto(root: Path) -> list[Finding]:
    findings = []
    misc = root / "MISC"
    if not misc.exists():
        return findings
    for f in sorted(misc.glob("nikto_*.txt")):
        host = f.stem.removeprefix("nikto_")
        for line in runner.read_lines(f):
            if line.strip() and not line.startswith("-"):
                findings.append(Finding("medium", "misconfig", "Nikto finding", host, line.strip()[:200], "Service Checks"))
    return findings


# --------------------------------------------------------------- orchestrate

GRADERS = [
    _grade_login_endpoints, _grade_shodan, _grade_risky_ports,
    _grade_nowaf, _grade_ffuf, _grade_cariddi,
    _grade_jsleak_trufflehog, _grade_semgrep,
    _grade_cloud_assets,
    _grade_wpscan, _grade_ssl, _grade_ssh_audit, _grade_ike, _grade_subzy,
    _grade_socialhunter, _grade_git_exposure, _grade_clickjack,
]


def run_stage11(engagement_root: Path, *, vuln_scan: bool = False) -> list[Finding]:
    """Reads every graded source file Stages 2-9 may have produced and returns
    the full finding list, sorted most-likely-vulnerable -> least-likely
    (severity first, then vtype slot order as a stable tie-break).

    Writes attack_vectors.json + attack_vectors.txt to the engagement root.
    """
    findings: list[Finding] = []
    for grader in GRADERS:
        findings.extend(grader(engagement_root))

    if vuln_scan:
        findings.extend(_grade_nuclei(engagement_root, "nuclei.txt", "Service Checks"))
        findings.extend(_grade_nuclei(engagement_root, "nuclei_js.txt", "JS Analysis"))
        findings.extend(_grade_nikto(engagement_root))

    vtype_rank = {k: i for i, k in enumerate(VTYPE_LABELS)}
    findings.sort(key=lambda f: (SEVERITY_ORDER.get(f.severity, 9), vtype_rank.get(f.vtype, 9)))

    json_path = engagement_root / "attack_vectors.json"
    json_path.write_text(json.dumps(
        [{"rank": i + 1, **asdict(f), "vtype_label": f.vtype_label()} for i, f in enumerate(findings)],
        indent=2,
    ))

    txt_path = engagement_root / "attack_vectors.txt"
    lines = [f"# {len(findings)} finding(s), ranked most-likely-vulnerable -> least-likely", ""]
    for i, f in enumerate(findings, 1):
        lines.append(f"{i:>3}. [{f.severity.upper():<8}] [{f.vtype_label():<28}] {f.title}")
        lines.append(f"       asset: {f.asset}")
        lines.append(f"       why:   {f.rationale}")
        lines.append(f"       stage: {f.stage}")
        lines.append("")
    runner.write_lines(txt_path, lines)

    return findings
