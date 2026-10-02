#!/usr/bin/env python3
"""UNDERTOW — recon automation for authorized external pentest engagements.

CLI entrypoint. A real run against a target auto-creates the engagement
directory and populates it in the same command — scaffold-then-populate, no
separate -D pre-step. Named "{client_name}_{YYYYMMDD}" when -C/--client-name
is given (the expected real-engagement usage), falling back to the bare
target domain if it isn't.
"""
import argparse
import sys
from datetime import datetime
from pathlib import Path

from modules import cloud_assets, config, grading, http_probe, js_analysis, osint, ports, screenshots, scope_gate, service_checks, setup, subdomains, toolcheck, web_discovery
from report.generator_v2 import render_report_v2
from modules.runner import StageResult, read_lines, write_lines

VERSION = "0.1.0"

BANNER = r"""
   __  ___   ______  __________  __________ _       __
  / / / / | / / __ \/ ____/ __ \/_  __/ __ \ |     / /
 / / / /  |/ / / / / __/ / /_/ / / / / / / / | /| / /
/ /_/ / /|  / /_/ / /___/ _, _/ / / / /_/ /| |/ |/ /
\____/_/ |_/_____/_____/_/ |_| /_/  \____/ |__/|__/
"""


def print_banner() -> None:
    color, reset = ("\033[36m", "\033[0m") if sys.stdout.isatty() else ("", "")
    print(f"{color}{BANNER}{reset}")
    print(f"  recon automation for authorized external pentest engagements  ·  v{VERSION}\n")


EPILOG = """\
examples:
  # Stage 0 — check required tools, install anything missing
  undertow --check-tools --install

  # Full run, client already handed over scope files
  undertow example.com -S scope.txt -WS web_scope.txt -OS out-of-scope.txt -C "Acme Corp"

  # No scope files at all — a bare root domain is enough (writes it into web_scope.txt)
  undertow example.com -MD example.com -C "Acme Corp"

  # Opt-in extras: permutation bruteforce, active vuln templates, semgrep on JS
  undertow example.com -MD example.com -C "Acme Corp" \\
      --wordlist /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \\
      --vuln-scan --js-semgrep

notes:
  - At least one of -S / -WS / -MD is required — there is no scope to gate on otherwise.
  - Everything from Stage 4 onward reads only INSCOPE_domain.txt / INSCOPE_subdomain_ip.txt;
    OUT_OF_SCOPE_domain.txt is an audit record, never read again downstream.
  - --vuln-scan and --js-semgrep are intrusive/active — opt-in, never default.
  - The engagement folder is named "{client_name}_{YYYYMMDD}" when -C is given, otherwise
    just the target domain.

  Full pipeline spec: docs/workflow_v2.html  ·  design notes: CLAUDE.md
"""

CHECKED_TOOLS = [
    "amass", "subfinder", "httpx", "dnsx", "grepcidr", "cariddi", "subscraper",
    "naabu", "nmap", "smap", "shodan",
    "katana", "gau", "gf", "arjun", "ffuf", "github-subdomains",
    "jsleak", "trufflehog", "nuclei", "semgrep", "js-beautify",
    "eyewitness", "cloud_enum",
    "wpscan", "sslscan", "testssl.sh", "ssh-audit", "ike-scan", "subzy", "socialhunter", "nikto",
    "metagoofil", "exiftool", "crosslinked", "bridgekeeper",
]


def _append_unique(dest: Path, lines: list) -> None:
    existing = set(read_lines(dest))
    existing.update(lines)
    write_lines(dest, sorted(existing))


def _apply_scope_inputs(root: Path, args) -> None:
    """Union -S/-WS/-MD into the engagement's scope.txt/web_scope.txt, and
    -OS into out-of-scope.txt. Per rule 3, this never *expands* scope — it
    only writes in exactly what the client/user supplied on the command line.
    """
    if args.scope_file:
        _append_unique(root / "scope.txt", read_lines(Path(args.scope_file)))
    if args.web_scope_file:
        _append_unique(root / "web_scope.txt", read_lines(Path(args.web_scope_file)))
    if args.md_domain:
        # No-scope-file fallback: write the bare domain straight into
        # web_scope.txt as a suffix match. Never touches scope.txt (-MD alone
        # creates no IP/CIDR gate).
        _append_unique(root / "web_scope.txt", [args.md_domain.strip().lower()])
    if args.out_of_scope_file:
        _append_unique(root / "out-of-scope.txt", read_lines(Path(args.out_of_scope_file)))


def _print_stage(stage: StageResult) -> None:
    print(f"\n[*] {stage.stage}")
    for t in stage.tools:
        if not t.ran:
            print(f"    [SKIP] {t.tool:<18} {t.error}")
        elif t.error and not t.outfile:
            print(f"    [FAIL] {t.tool:<18} {t.error}")
        elif t.error:
            print(f"    [PARTIAL] {t.tool:<15} {t.lines} line(s) -> {t.outfile} ({t.error})")
        else:
            print(f"    [OK]   {t.tool:<18} {t.lines} line(s) -> {t.outfile}")


def run_pipeline(target: str, root: Path, args) -> None:
    stage1 = subdomains.run_stage1(
        target,
        root,
        timeout=args.timeout,
        github_token=args.github_token,
        wordlist=Path(args.wordlist) if args.wordlist else None,
    )
    _print_stage(stage1)

    stage2 = http_probe.run_stage2(stage1.outputs["all_domain"], root, timeout=args.timeout)
    _print_stage(stage2)

    if "alive_domain" not in stage2.outputs:
        print("\n[!] Stage 2 produced no alive_domain.txt — stopping before the scope gate.")
        return

    stage3 = scope_gate.run_stage3(stage2.outputs["alive_domain"], root)
    _print_stage(stage3)

    if "inscope_subdomain_ip" not in stage3.outputs:
        print(f"\n[!] {stage3.tools[-1].error if stage3.tools else 'scope gate did not run'} — stopping here.")
        return

    print(
        f"\n[+] Scope gate locked: {stage3.tools[0].lines} in-scope host(s) in "
        f"{root / 'subdomain' / 'INSCOPE_domain.txt'}"
    )

    stage4 = ports.run_stage4(
        stage3.outputs["inscope_subdomain_ip"], root,
        timeout=args.timeout, shodan_use_cli=args.shodan_use_cli,
    )
    _print_stage(stage4)

    stage5 = web_discovery.run_stage5(
        stage3.outputs["inscope_domain"], root,
        timeout=args.timeout, ffuf_wordlist=Path(args.ffuf_wordlist) if args.ffuf_wordlist else None,
    )
    _print_stage(stage5)

    stage6 = js_analysis.run_stage6(
        stage3.outputs["inscope_domain"], root,
        timeout=args.timeout, vuln_scan=args.vuln_scan, js_semgrep=args.js_semgrep,
    )
    _print_stage(stage6)

    stage7 = screenshots.run_stage7(stage3.outputs["inscope_domain"], root, timeout=args.timeout)
    _print_stage(stage7)

    stage8 = cloud_assets.run_stage8(args.cloud_keyword, root, timeout=args.timeout)
    _print_stage(stage8)

    stage9 = service_checks.run_stage9(
        stage3.outputs["inscope_domain"], stage3.outputs["inscope_subdomain_ip"], root,
        timeout=args.timeout, vuln_scan=args.vuln_scan, wpscan_api_token=args.wpscan_api_token,
    )
    _print_stage(stage9)

    stage10 = osint.run_stage10(target, args.company_name, root, timeout=args.timeout)
    _print_stage(stage10)

    findings = grading.run_stage11(root, vuln_scan=args.vuln_scan)
    print(f"\n[*] Stage 11 — Grading / Attack Vector Scoring")
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    summary = ", ".join(f"{counts.get(s, 0)} {s}" for s in ("critical", "high", "medium", "low", "info"))
    print(f"    {len(findings)} finding(s) ranked ({summary})")
    print(f"    -> {root / 'attack_vectors.txt'}")
    for f in findings[:5]:
        print(f"       [{f.severity.upper()}] {f.title} ({f.asset})")

    report_path = render_report_v2(root, target, root / "report.html", vuln_scan=args.vuln_scan)
    print(f"\n[+] Stage 12 — Report written to {report_path}")


def main():
    print_banner()

    parser = argparse.ArgumentParser(
        prog="undertow",
        description="Recon automation for authorized external pentest engagements. "
        "Orchestrates a 12-stage pipeline (subdomain enum -> alive-host probe -> hard "
        "scope gate -> ports/web/JS/vuln checks -> OSINT -> graded HTML report).",
        epilog=EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-v", "--version", action="version", version=f"undertow {VERSION}")
    parser.add_argument("target", nargs="?", help="primary target domain to enumerate, e.g. example.com")
    parser.add_argument(
        "-C", "--client-name", metavar="NAME",
        help="client/brand name. Drives the auto-created engagement folder name "
        "(\"{client_name}_{YYYYMMDD}\", e.g. Acme_Corp_20261001) and is the default "
        "for --cloud-keyword/--company-name if those aren't given separately. "
        "Falls back to the target domain for folder naming if not given.",
    )

    scope_group = parser.add_argument_group("scope input", "at least one of -S / -WS / -MD is required")
    scope_group.add_argument("-S", "--scope-file", metavar="PATH", help="scope.txt (IP/CIDR)")
    scope_group.add_argument("-WS", "--web-scope-file", metavar="PATH", help="web_scope.txt (FQDN suffix)")
    scope_group.add_argument(
        "-MD", "--md-domain", metavar="DOMAIN",
        help="bare root domain, written into web_scope.txt directly (no-scope-file fallback)",
    )
    scope_group.add_argument("-OS", "--out-of-scope-file", metavar="PATH", help="out-of-scope.txt (optional, always wins)")

    stage1_group = parser.add_argument_group("stage 1 — subdomain enumeration")
    stage1_group.add_argument(
        "--github-token", metavar="TOKEN",
        help="GitHub token for the optional github-subdomains passive source. Prefer "
        "GITHUB_TOKEN in .undertow.config (see --config) over passing it here — a CLI "
        "flag is visible in shell history and `ps`",
    )
    stage1_group.add_argument("--wordlist", metavar="PATH", help="opt-in puredns+dnsgen permutation bruteforce with this wordlist")

    stage4_group = parser.add_argument_group("stage 4 — port scan")
    stage4_group.add_argument(
        "--shodan-use-cli", action="store_true",
        help="use the authenticated `shodan host` CLI (org + CVEs, costs 1 query credit/IP) "
        "instead of the free InternetDB endpoint",
    )

    stage5_group = parser.add_argument_group("stage 5 — web/URL/param discovery")
    stage5_group.add_argument(
        "--ffuf-wordlist", metavar="PATH",
        help="content-discovery wordlist (default: seclists' Discovery/Web-Content/common.txt)",
    )

    stage6_group = parser.add_argument_group("stage 6 — JS analysis")
    stage6_group.add_argument(
        "--js-semgrep", action="store_true",
        help="opt-in: run `semgrep scan --config auto --verbose` against downloaded live JS. "
        "Weak fit for minified black-box JS — additive, not a replacement for jsleak",
    )

    stage8_group = parser.add_argument_group("stage 8 — cloud assets")
    stage8_group.add_argument(
        "--cloud-keyword", metavar="KEYWORD",
        help="company/brand keyword for cloud_enum. Defaults to --client-name if not given "
        "separately; never guessed from the domain, skipped entirely if neither is given",
    )

    stage9_group = parser.add_argument_group("stage 9 — service / vulnerability checks")
    stage9_group.add_argument(
        "--vuln-scan", action="store_true",
        help="opt-in: run nuclei/nikto-class active vuln templates (also gates stage 6's "
        "nuclei credential-disclosure pass), never default",
    )
    stage9_group.add_argument(
        "--wpscan-api-token", metavar="TOKEN",
        help="WPScan vulnerability-DB API token (avoids rate-limiting on -e vp,u). Prefer "
        "WPSCAN_API_TOKEN in .undertow.config (see --config) over passing it here",
    )

    stage10_group = parser.add_argument_group("stage 10 — OSINT / email gathering")
    stage10_group.add_argument(
        "--company-name", metavar="NAME",
        help="company name for crosslinked/bridgekeeper LinkedIn-style enumeration. "
        "Defaults to --client-name if not given separately; never guessed from the domain, "
        "skipped entirely if neither is given (metagoofil still runs on its own)",
    )

    general_group = parser.add_argument_group("general")
    general_group.add_argument("--timeout", type=int, default=180, metavar="SECONDS", help="per-tool timeout (default: 180)")
    general_group.add_argument(
        "--config", metavar="PATH",
        help="KEY=VALUE token config file (GITHUB_TOKEN, WPSCAN_API_TOKEN). Default: "
        ".undertow.config in the repo root (see .undertow.config.example). A matching "
        "--xxx-token flag always overrides the config file value",
    )

    tools_group = parser.add_argument_group("stage 0 — tool check")
    tools_group.add_argument(
        "--check-tools", action="store_true",
        help="check (and optionally install) required tools, then exit",
    )
    tools_group.add_argument("--install", action="store_true", help="with --check-tools, auto-install missing tools")

    args = parser.parse_args()

    cfg = config.load_config(Path(args.config) if args.config else None)
    if not args.github_token:
        args.github_token = cfg.get("GITHUB_TOKEN")
    if not args.wpscan_api_token:
        args.wpscan_api_token = cfg.get("WPSCAN_API_TOKEN")

    if args.check_tools:
        print("[*] Stage 0: checking required tools")
        status = toolcheck.check_tools(CHECKED_TOOLS, auto_install=args.install)
        toolcheck.print_status(status)
        return

    if not args.target:
        parser.error("target is required unless using --check-tools")

    if not (args.scope_file or args.web_scope_file or args.md_domain):
        parser.error("at least one of -S/-WS/-MD is required — there is no scope to gate on")

    if args.cloud_keyword is None:
        args.cloud_keyword = args.client_name
    if args.company_name is None:
        args.company_name = args.client_name

    folder_name = f"{args.client_name}_{datetime.now().strftime('%Y%m%d')}" if args.client_name else args.target
    root = setup.create_engagement(folder_name)
    print(f"[+] Engagement directory ready at {root.resolve()}")

    _apply_scope_inputs(root, args)

    run_pipeline(args.target, root, args)


if __name__ == "__main__":
    main()
