<div align="center">

```
   __  ___   ______  __________  __________ _       __
  / / / / | / / __ \/ ____/ __ \/_  __/ __ \ |     / /
 / / / /  |/ / / / / __/ / /_/ / / / / / / / | /| / /
/ /_/ / /|  / /_/ / /___/ _, _/ / / / /_/ /| |/ |/ /
\____/_/ |_/_____/_____/_/ |_| /_/  \____/ |__/|__/
```

**Recon automation for authorized external pentest engagements**

</div>

---

> [!WARNING]
> **For use only against targets you are explicitly authorized to test.** This tool
> orchestrates active scanning, OSINT scraping, and vulnerability probing against
> real external infrastructure. Running it against anything without a signed
> engagement/authorization in place is unauthorized access.

## What this is

UNDERTOW is a 12-stage recon pipeline that mirrors a real manual pentest
methodology. It orchestrates ~35 external CLI tools via `subprocess`, enforces a
hard client-provided scope gate before anything active happens, grades every
finding it produces, and renders a single self-contained HTML report suitable
for client delivery.

```
subdomain enum ──▶ alive-host probe ──▶ SCOPE GATE ──▶ ports / web / JS / screenshots
                                             │          / cloud / service checks / OSINT
                                             │                      │
                                     (hard boundary)                ▼
                                             │              grading (severity +
                                             └──────────▶   ranking) ──▶ report.html
```

## The 12 stages

| # | Stage | What it does | Key tools |
|---|-------|---------------|-----------|
| 0 | Tool check | Verifies (and optionally installs) every external tool the pipeline needs | `--check-tools --install` |
| 1 | Subdomain enumeration | Passive (cert transparency, archives) + active (brute-force, reverse DNS) discovery | subscraper, amass, subfinder, urlscan.io, dnsx |
| 2 | Alive host discovery | HTTP/HTTPS probe across an expanded port list | httpx |
| 3 | **Scope gate** (hard boundary) | IP/CIDR + FQDN-suffix match, minus explicit exclusions — everything downstream reads only this output | native, `ipaddress`-based |
| 4 | Port scan | Targeted port list (no `-p-` sweep) + passive Shodan/InternetDB | naabu, nmap, smap, Shodan |
| 5 | Web/URL/param discovery | Crawl + archive + param discovery + content bruteforce + `gf` vuln-candidate triage | katana, gau, arjun, ffuf, cariddi, gf |
| 6 | JS analysis | JSRecon methodology — live JS → secrets/links → verified-live check. Automatically recovers source maps and beautifies what's left minified | katana, gau, httpx, jsleak, trufflehog, (opt-in: semgrep) |
| 7 | Screenshots | EyeWitness over in-scope hosts + Stage 4's discovered HTTP(S) services | eyewitness |
| 8 | Cloud assets | Brand-keyword bucket/container enumeration, public buckets auto-listed | cloud_enum |
| 9 | Service/vuln checks | WordPress, TLS, SSH, IKE, subdomain takeover, social-link rot, git exposure, clickjack — run last, in-scope only | wpscan, sslscan, testssl.sh, ssh-audit, ike-scan, subzy, socialhunter, (opt-in: nuclei, nikto) |
| 10 | OSINT / email gathering | Document metadata + search-engine employee-name scraping | metagoofil, crosslinked, bridgekeeper |
| 11 | **Grading** (core deliverable) | Every finding gets Critical/High/Medium/Low/Info + a one-line rationale, ranked most-likely-vulnerable → least-likely | native |
| 12 | Report generation | Single self-contained `report.html` — Dashboard / Attack Vectors / Leaked & Sensitive Data / Recon Detail | native (Jinja2) |

Full spec with every tool choice's reasoning: [`docs/workflow_v2.html`](docs/workflow_v2.html).

## Installation

```bash
git clone <this-repo>
cd undertow
pip3 install -r requirements.txt
python3 undertow.py --check-tools --install
```

`--check-tools` reports every tool's status (`OK` / `MISSING` / `MANUAL`); `--install`
auto-installs what it can (apt/go/pipx, or clones+venvs the handful of lightweight
Python OSINT scripts that aren't packaged anywhere). A few tools have no installer
(e.g. `testssl.sh`, and the `shodan` CLI needs `shodan init <api-key>` run once by
hand) — those are flagged `MANUAL`/`MISSING` with a note on what to do.

## Quick start

```bash
# Client already handed over scope files
python3 undertow.py example.com -S scope.txt -WS web_scope.txt -OS out-of-scope.txt -C "Acme Corp"

# No scope files at all — a bare root domain is enough
python3 undertow.py example.com -MD example.com -C "Acme Corp"
```

That's it — one command scaffolds the engagement folder, populates it, and ends
with a finished `report.html` inside it. See `python3 undertow.py --help` for the full
flag reference (organized by stage, with worked examples in the epilog).

**At least one of `-S` / `-WS` / `-MD` is required** — the tool refuses to run
without scope to gate on. Multiple may be combined (unioned).

## Scope model — the one hard rule

A host is in-scope **only if** it matches `scope.txt` (IP/CIDR) or `web_scope.txt`
(FQDN suffix), **and** does not match `out-of-scope.txt` (explicit exclusion always
wins, even over an otherwise-valid match). Everything from Stage 4 onward reads
*only* `INSCOPE_domain.txt` / `INSCOPE_subdomain_ip.txt` — `OUT_OF_SCOPE_domain.txt`
is an audit record, never read again downstream, no exceptions.

The tool **never expands scope on its own** — no ASN/BGP discovery, no
reverse-WHOIS, no SSL-SNI cloud-IP scraping, no acquisition hunting. Scope comes
only from what the client/user provides. If you don't have scope files at all,
`-MD <domain>` writes a bare root domain into `web_scope.txt` directly — it is not
a scope-expansion mechanism, just a convenience for a client that only gave you a
domain name verbally.

## Engagement folder layout

Running against a target auto-creates the engagement directory and populates it in
the same run (no separate scaffold step). Pass `-C "Client Name"` to name it
`{Client_Name}_{YYYYMMDD}`; without it, the folder is just named after the target
domain.

```
Acme_Corp_20261001/
├── scope.txt, web_scope.txt, out-of-scope.txt, Note.txt   (your scope inputs)
├── subdomain/      INSCOPE_domain.txt, INSCOPE_subdomain_ip.txt,
│                   OUT_OF_SCOPE_domain.txt, alive_domain.txt, eyewitness/, ...
├── nmap/           naabu.txt, nmap.txt, smap.txt, shodan.txt, eyewitness/
├── Loot/           katana.txt, gau.txt, arjun.txt, cariddi.txt, vuln_candidates/
├── dirbrute/       ffuf_<host>.txt
├── JS/             jsleak.txt, trufflehog.txt, recovered_src/, beautified/, ...
├── MISC/           cloud_assets.txt, sslscan.txt, ike-scan.txt, subzy.txt, ...
├── wpscan/         <host>.txt
├── email/          All_Emails.txt + one file per OSINT source
├── attack_vectors.json / attack_vectors.txt   (Stage 11 — the ranked findings)
└── report.html     (Stage 12 — the client deliverable, open this one)
```

**Rule 1, absolute:** one named output file per tool that actually runs. If a tool
didn't run (missing, skipped, opt-in not set), there's no file for it — never an
empty placeholder pretending it ran.

## Opt-in / gated flags

Some stages run intrusive or noisy checks that are never on by default:

| Flag | Gates | Why it's opt-in |
|------|-------|------------------|
| `--vuln-scan` | nuclei (Stage 6 cred-disclosure + Stage 9 CVE/DNS templates), nikto | Active, noisy, CVE-signature scanning |
| `--js-semgrep` | `semgrep scan --config auto --verbose` on recovered/beautified JS | Weak hit-rate on black-box minified JS — additive, not load-bearing |
| `--wordlist <path>` | puredns+dnsgen permutation bruteforce (Stage 1) | Can generate a *lot* of DNS traffic |
| `--shodan-use-cli` | Authenticated `shodan host` lookups instead of free InternetDB | Costs one query credit per in-scope IP |

## Report

`report.html` is a single, fully self-contained file (inline CSS/JS, screenshots
embedded as base64) — no server, no external CDN, opens standalone in any browser
for client delivery. Four tabs:

- **Dashboard** — stat tiles, findings-by-severity and findings-by-vector-type bars, top 5 attack vectors
- **Attack Vectors** — the full Stage 11 ranking, client-side filterable by severity and vuln-type
- **Leaked & Sensitive Data** — every secret/credential/public-data-store finding, surfaced prominently rather than buried in raw tool output
- **Recon Detail** — collapsible per-stage supporting evidence (scope gate, subdomains, ports, JS endpoints, WPScan, service checks, cloud assets, screenshots, OSINT emails)


