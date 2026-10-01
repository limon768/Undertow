"""Stage 12 — Report Generation for UNDERTOW.

Renders the tabbed design agreed in output/example_report_v2.html (Dashboard /
Attack Vectors / Leaked & Sensitive Data / Recon Detail) as a single
self-contained HTML file — no server, no external CDN, must open standalone
for client delivery. Consumes Stage 11's attack_vectors.json as the Attack
Vectors tab's primary data source (absolute rule 7: that ranking, not raw
counts, is the report's primary view).

Known, deliberate omission: the mock report also had DNS-records and WHOIS
panels. Those come from modules/dns_info.py and modules/whois_info.py, which
are the OLD generic pipeline CLAUDE.md says is being replaced and which Stage
1-11's real pipeline never calls — there's no real Stage producing that data,
so this generator doesn't fabricate empty panels for it. Flagged, not silently
dropped.
"""
from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader

from modules import runner
from modules.grading import VTYPE_LABELS

TEMPLATE_DIR = Path(__file__).parent / "templates"
VTYPE_SLOT = {k: i + 1 for i, k in enumerate(VTYPE_LABELS)}

# A finding counts as "leaked & sensitive data" if it's a credential/secret or
# a publicly-readable data store — broader than the vtype=="secret" filter
# chip alone (the workflow spec explicitly lists exposed .git and public
# cloud buckets on this tab too, even though their Attack-Vector vtype is
# "misconfig" for chip-filtering purposes).
LEAK_TITLE_MARKERS = (".git directory exposed", "Publicly listable cloud storage bucket")


def _is_leak(finding: dict) -> bool:
    return finding["vtype"] == "secret" or finding["title"] in LEAK_TITLE_MARKERS


# --------------------------------------------------------------- dashboard

def _load_findings(engagement_root: Path) -> list[dict]:
    f = engagement_root / "attack_vectors.json"
    if not f.exists():
        return []
    data = json.loads(f.read_text())
    for d in data:
        d["slot"] = VTYPE_SLOT.get(d["vtype"], 8)
    return data


def _severity_bars(findings: list[dict]) -> list[dict]:
    order = [("critical", "Critical"), ("high", "High"), ("medium", "Medium"), ("low", "Low"), ("info", "Info")]
    counts = {k: 0 for k, _ in order}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    max_count = max(counts.values(), default=0) or 1
    return [{"key": k, "label": label, "count": counts[k], "pct": round(counts[k] / max_count * 100)} for k, label in order]


def _vtype_bars(findings: list[dict]) -> list[dict]:
    counts = {k: 0 for k in VTYPE_LABELS}
    for f in findings:
        counts[f["vtype"]] = counts.get(f["vtype"], 0) + 1
    max_count = max(counts.values(), default=0) or 1
    return [
        {"slot": VTYPE_SLOT[k], "key": k, "label": label, "count": counts[k], "pct": round(counts[k] / max_count * 100)}
        for k, label in VTYPE_LABELS.items()
    ]


def _stats(engagement_root: Path, findings: list[dict]) -> dict:
    sub = engagement_root / "subdomain"
    return {
        "total_findings": len(findings),
        "subdomains": runner.count_lines(sub / "all_domain.txt"),
        "alive": runner.count_lines(sub / "alive_domain.txt"),
        "inscope": runner.count_lines(sub / "INSCOPE_domain.txt"),
        "dropped": max(runner.count_lines(sub / "OUT_OF_SCOPE_domain.txt") - 1, 0),  # minus header comment line
    }


# --------------------------------------------------------- recon detail tab

ALIVE_LINE_RE = re.compile(r"^(?P<host>\S+)\s+\[(?P<status>[^\]]*)\]\s+\[(?P<title>[^\]]*)\]\s+\[(?P<ip>[^\]]*)\]$")


def _scope_rows(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "subdomain" / "INSCOPE_subdomain_ip.txt"):
        if " -> " in line:
            host, ip = line.split(" -> ", 1)
            rows.append({"host": host, "ip": ip, "status": "In-scope", "reason": "matched scope.txt/web_scope.txt"})
    for line in runner.read_lines(root / "subdomain" / "OUT_OF_SCOPE_domain.txt"):
        m = re.match(r"^(\S+) -> (\S+)\s+\((.+)\)$", line)
        if m:
            rows.append({"host": m.group(1), "ip": m.group(2), "status": "Dropped", "reason": m.group(3)})
    return rows


def _alive_rows(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "subdomain" / "alive_domain.txt"):
        m = ALIVE_LINE_RE.match(line)
        if m:
            rows.append(m.groupdict())
    return rows


def _port_hosts(root: Path) -> list[dict]:
    xml_path = root / "nmap" / ".nmap_raw.xml"
    if not xml_path.exists():
        return []
    try:
        xml_root = ET.fromstring(xml_path.read_text())
    except ET.ParseError:
        return []
    hosts = []
    for host_el in xml_root.findall("host"):
        addr_el = host_el.find("address")
        if addr_el is None:
            continue
        ports = []
        for port_el in host_el.findall(".//port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue
            service_el = port_el.find("service")
            ports.append({
                "port": port_el.get("portid", ""), "protocol": port_el.get("protocol", ""),
                "service": service_el.get("name", "") if service_el is not None else "",
                "product": service_el.get("product", "") if service_el is not None else "",
                "version": service_el.get("version", "") if service_el is not None else "",
            })
        if ports:
            hosts.append({"ip": addr_el.get("addr", ""), "ports": ports})
    return hosts


JS_LINK_KEYWORDS = {"admin", "actuator", "internal", "debug", "config", "backup", "secret", "reset-password"}


def _js_endpoints(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "JS" / "jsleak.txt"):
        m = re.match(r"\[link\]\s*(\S+)\s*:\s*(.+)", line, re.IGNORECASE)
        if not m:
            continue
        asset, path = m.group(1), m.group(2)
        hit_keywords = [kw for kw in JS_LINK_KEYWORDS if kw in path.lower()]
        severity = "high" if hit_keywords else "low"
        reason = f"Path contains '{hit_keywords[0]}'" if hit_keywords else "Discovered via jsleak linkFinder"
        rows.append({"endpoint": f"{asset}{path}" if path.startswith("/") else path, "reason": reason, "severity": severity})
    return rows


VULN_CANDIDATE_CLASSES = [
    ("sqli", "SQLi"), ("xss", "XSS"), ("lfi", "LFI"), ("redirect", "Open Redirect"),
    ("idor", "IDOR"), ("debug_logic", "Debug/Logic exposure"), ("ssrf", "SSRF"),
    ("rce", "RCE"), ("ssti", "SSTI"),
]


def _vuln_candidates(root: Path) -> list[dict]:
    vdir = root / "Loot" / "vuln_candidates"
    if not vdir.exists():
        return []
    rows = []
    for fname, label in VULN_CANDIDATE_CLASSES:
        f = vdir / f"{fname}.txt"
        lines = runner.read_lines(f)
        example = lines[0] if lines else "— none flagged this engagement —"
        rows.append({"cls": label, "example": example, "file": f"Loot/vuln_candidates/{fname}.txt"})
    return rows


def _wpscan_rows(root: Path) -> list[dict]:
    rows = []
    wpdir = root / "wpscan"
    if not wpdir.exists():
        return rows
    for f in sorted(wpdir.glob("*.txt")):
        for line in runner.read_lines(f):
            m = re.search(r"Vulnerable (plugin|theme):\s*(\S+)\s*v?([\d.]+)?\s*-\s*(.+)", line, re.IGNORECASE)
            if m:
                rows.append({"plugin": f"{m.group(2)} ({m.group(1)})", "version": m.group(3) or "?", "vulnerable_to": m.group(4)})
                continue
            m = re.search(r"WordPress version ([\d.]+) identified \((.+)\)", line, re.IGNORECASE)
            if m:
                rows.append({"plugin": "WordPress Core", "version": m.group(1), "vulnerable_to": m.group(2)})
    return rows


def _ssl_rows(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "MISC" / "sslscan.txt"):
        if line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) >= 3:
            rows.append({"asset": parts[0], "tls10": parts[1], "tls11": parts[2]})
    return rows


def _ike_rows(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "MISC" / "ike-scan.txt"):
        if line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            rows.append({"asset": parts[0], "hash_found": parts[1], "detail": parts[2] if len(parts) > 2 else ""})
    return rows


def _subzy_rows(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "MISC" / "subzy.txt"):
        if line.startswith("#"):
            continue
        parts = line.split(None, 2)
        if len(parts) >= 2:
            rows.append({"subdomain": parts[0], "likelihood": parts[1], "detail": parts[2] if len(parts) > 2 else ""})
    return rows


def _social_rows(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "MISC" / "socialhunter.txt"):
        if line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if parts:
            rows.append({"asset": parts[0], "link": parts[1] if len(parts) > 1 else ""})
    return rows


def _clickjack_rows(root: Path) -> list[dict]:
    f = root / "MISC" / "clickjack_poc.html"
    if not f.exists():
        return []
    rows = []
    for m in re.finditer(r"<!-- (\S+): Vulnerable=(Yes|No) \((.+?)\) -->", f.read_text(errors="replace")):
        rows.append({"asset": m.group(1), "vulnerable": m.group(2), "detail": m.group(3)})
    return rows


def _sshgit_rows(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "MISC" / "ssh-audit.txt"):
        if " -> " in line:
            target, result = line.split(" -> ", 1)
            rows.append({"tool": "ssh-audit", "target": target, "result": result, "raw_file": "MISC/ssh-audit.txt"})
    for line in runner.read_lines(root / "MISC" / "git_exposure.txt"):
        if " -> " in line:
            target, result = line.split(" -> ", 1)
            rows.append({"tool": "git exposure check", "target": target, "result": result, "raw_file": "MISC/git_exposure.txt"})
    return rows


def _not_run(root: Path, vuln_scan: bool) -> list[dict]:
    if vuln_scan:
        return []
    return [
        {"tool": "nuclei", "note": "opt-in, not run this engagement (--vuln-scan not set)"},
        {"tool": "nikto", "note": "opt-in, not run this engagement (--vuln-scan not set)"},
    ]


def _cloud_rows(root: Path) -> list[dict]:
    rows = []
    for line in runner.read_lines(root / "MISC" / "cloud_assets.txt"):
        parts = [p.strip() for p in line.split("|")]
        if len(parts) == 3:
            rows.append({"provider": parts[0], "resource": parts[1], "status": parts[2]})
    return rows


def _screenshots(root: Path, max_images: int = 40) -> list[dict]:
    rows = []
    count = 0
    for subdir in ("subdomain/eyewitness/screens", "nmap/eyewitness/screens"):
        shots_dir = root / subdir
        if not shots_dir.exists():
            continue
        for png in sorted(shots_dir.glob("*.png")):
            if count >= max_images:
                break
            try:
                data_uri = "data:image/png;base64," + base64.b64encode(png.read_bytes()).decode("ascii")
            except OSError:
                data_uri = ""
            host = png.stem.split(".", 1)[-1] if "." in png.stem else png.stem
            rows.append({"host": png.stem, "data_uri": data_uri, "path": f"{subdir}/{png.name}"})
            count += 1
    return rows


def _emails(root: Path) -> list[dict]:
    email_dir = root / "email"
    if not email_dir.exists():
        return []
    source_files = {
        "metagoofil.txt": "metagoofil (document metadata)",
        "crosslinked.txt": "crosslinked (LinkedIn)",
        "bridgekeeper.txt": "bridgekeeper",
    }
    email_source: dict[str, str] = {}
    for fname, label in source_files.items():
        for e in runner.read_lines(email_dir / fname):
            email_source.setdefault(e, label)
    rows = []
    for e in runner.read_lines(email_dir / "All_Emails.txt"):
        rows.append({"email": e, "source": email_source.get(e, "merged source")})
    return rows


FILE_LIST_TEMPLATE = """
Stage 1 — <code>subdomain/subscraper.txt</code> <code>amass_passive.txt</code> <code>subfinder.txt</code> <code>urlscan_subs.txt</code> <code>github_subs.txt</code> → <code>all_passive_domain.txt</code> · <code>amass_active.txt</code> <code>reverse_dns.txt</code> <code>bruteforce_domain.txt</code> → <code>all_activeScan_domain.txt</code> → <code>all_domain.txt</code><br>
Stage 2 — <code>subdomain/alive_domain.txt</code> <code>login_endpoints.txt</code><br>
Stage 3 — <code>subdomain/INSCOPE_domain.txt</code> <code>INSCOPE_subdomain_ip.txt</code> <code>OUT_OF_SCOPE_domain.txt</code><br>
Stage 4 — <code>nmap/naabu.txt</code> <code>nmap.txt</code> <code>smap.txt</code> <code>shodan.txt</code><br>
Stage 5 — <code>Loot/katana.txt</code> <code>Loot/gau.txt</code> <code>Loot/arjun.txt</code> <code>Loot/cariddi.txt</code> <code>dirbrute/ffuf_&lt;host&gt;.txt</code> <code>subdomain/nowaf_subs.txt</code> <code>403_subs.txt</code> · triage: <code>Loot/vuln_candidates/{sqli,xss,lfi,ssrf,redirect,idor,rce,ssti,debug_logic}.txt</code><br>
Stage 6 — <code>JS/js_active.txt</code> <code>js_passive.txt</code> <code>all_js.txt</code> <code>js_live.txt</code> <code>jsleak.txt</code> <code>trufflehog.txt</code> <code>sourcemaps.txt</code> <code>recovered_src/</code> <code>beautified/</code> <code>semgrep.txt</code> (opt-in)<br>
Stage 7 — <code>subdomain/eyewitness/</code> <code>nmap/eyewitness/</code><br>
Stage 8 — <code>MISC/cloud_assets.txt</code> <code>MISC/s3_listing_&lt;bucket&gt;.txt</code><br>
Stage 9 — <code>wpscan/&lt;host&gt;.txt</code> <code>MISC/sslscan.txt</code> <code>MISC/testssl.txt</code> <code>MISC/ssh-audit.txt</code> <code>MISC/ike-scan.txt</code> <code>MISC/subzy.txt</code> <code>MISC/socialhunter.txt</code> <code>MISC/clickjack_poc.html</code> <code>MISC/git_exposure.txt</code> <code>MISC/nuclei.txt</code> <code>MISC/nikto_&lt;host&gt;.txt</code> (nuclei/nikto only when <code>--vuln-scan</code> is passed)<br>
Stage 10 — <code>email/metagoofil.txt</code> <code>crosslinked.txt</code> <code>bridgekeeper.txt</code> → <code>All_Emails.txt</code><br>
Stage 11 — <code>attack_vectors.json</code> <code>attack_vectors.txt</code>
"""


def _recon_detail(root: Path, vuln_scan: bool) -> dict:
    return {
        "scope_rows": _scope_rows(root),
        "subdomains": runner.read_lines(root / "subdomain" / "all_domain.txt"),
        "alive_rows": _alive_rows(root),
        "port_hosts": _port_hosts(root),
        "js_endpoints": _js_endpoints(root),
        "vuln_candidates": _vuln_candidates(root),
        "wpscan_rows": _wpscan_rows(root),
        "ssl_rows": _ssl_rows(root),
        "ike_rows": _ike_rows(root),
        "subzy_rows": _subzy_rows(root),
        "social_rows": _social_rows(root),
        "clickjack_rows": _clickjack_rows(root),
        "sshgit_rows": _sshgit_rows(root),
        "not_run": _not_run(root, vuln_scan),
        "cloud_rows": _cloud_rows(root),
        "screenshots": _screenshots(root),
        "emails": _emails(root),
        "file_list_html": FILE_LIST_TEMPLATE,
    }


# --------------------------------------------------------------- orchestrate

def render_report_v2(engagement_root: Path, target: str, output_path: Path, *, vuln_scan: bool = False) -> Path:
    findings = _load_findings(engagement_root)
    top5 = findings[:5]
    leaked = [f for f in findings if _is_leak(f)]
    vtype_order = [{"slot": VTYPE_SLOT[k], "key": k, "label": label} for k, label in VTYPE_LABELS.items()]

    env = Environment(loader=FileSystemLoader(str(TEMPLATE_DIR)), autoescape=True)
    template = env.get_template("report_v2.html.j2")
    html = template.render(
        target=target,
        generated_at=datetime.now().strftime("%Y-%m-%d %H:%M"),
        stats=_stats(engagement_root, findings),
        sev_bars=_severity_bars(findings),
        vt_bars=_vtype_bars(findings),
        vtype_order=vtype_order,
        top5=top5,
        all_findings=findings,
        leaked_findings=leaked,
        recon=_recon_detail(engagement_root, vuln_scan),
    )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(html, encoding="utf-8")
    return output_path
