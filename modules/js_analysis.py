"""Stage 6 — JS Analysis for UNDERTOW (JSRecon methodology).

Reads only INSCOPE_domain.txt (Stage 3's locked scope gate output).

  katana -d 5 -jc | filter .js$     -> JS/js_active.txt
  gau | filter .js$ (archived JS)   -> JS/js_passive.txt
  merge + dedupe                   -> JS/all_js.txt
  httpx -mc 200 (drop dead links)  -> JS/js_live.txt
  jsleak -s -l -k                  -> JS/jsleak.txt (secretFinder + linkFinder
                                       + status-code check, one tool — replaces
                                       standalone SecretFinder/LinkFinder/gf)
  source-map recovery (automatic)   -> JS/sourcemaps.txt + JS/recovered_src/
                                       (any `.js.map`/`sourceMappingURL` found
                                       is parsed for sourcesContent — often a
                                       full readable pre-minification source
                                       dump that was never meant to ship)
  js-beautify fallback (automatic) -> JS/beautified/ (only for live JS that
                                       had no recoverable map — improves
                                       jsleak/semgrep's hit rate on minified
                                       one-line bundles)
  trufflehog filesystem scan        -> JS/trufflehog.txt (verifies a leaked key
                                       found by jsleak is actually still *live*;
                                       also scans recovered_src/ + beautified/)
  semgrep --config auto --verbose  -> JS/semgrep.txt (opt-in --js-semgrep —
                                       reversal of an earlier "dropped" call,
                                       see CLAUDE.md: still a weak fit for
                                       minified black-box JS, so it's additive
                                       and gated, never a default/load-bearing
                                       source the way jsleak is)
  nuclei credential-disclosure      -> JS/nuclei_js.txt (opt-in --vuln-scan,
  templates                           same gate as Stage 9, never default)

Before any of the above touch the network: all_js.txt (the merged crawl+
archive list that httpx/jsleak/trufflehog/semgrep actually scan) has known
vendor/CDN library JS filtered out — jquery, bootstrap, react, lodash, GA/GTM,
etc. are never going to leak an app secret and just waste scan time/requests.
Each tool's own raw output (js_active.txt/js_passive.txt) is left unfiltered
so Rule 1 fidelity (one file = exactly what that tool found) still holds.

Dropped: standalone SecretFinder/LinkFinder/gf aws-keys/github/redirect (all
covered by jsleak), LazyEgg (GUI-only, not automatable).
"""
from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urljoin

import requests

from . import runner
from .runner import StageResult, ToolResult

JS_SUFFIX_RE = re.compile(r"\.js(\?|#|$)", re.IGNORECASE)

# Common vendor/CDN library filenames + hosts. These are never going to leak
# an app-specific secret and just cost download/scan time across every tool
# downstream of all_js.txt — filtered once, here, rather than in each tool.
VENDOR_LIB_NAME_RE = re.compile(
    r"(^|/)(jquery|bootstrap|popper|react(-dom)?|vue(\.?js)?|angular|lodash|underscore|"
    r"moment|d3|chart(\.?js)?|fontawesome|font-awesome|slick|swiper|polyfill|modernizr|"
    r"axios|select2|datatables|owl\.carousel|aos|gsap|three(\.min)?|highcharts|plotly|"
    r"dompurify|crypto-js|sweetalert2?|toastr|tether|respond|html5shiv|webfont|"
    r"analytics|gtag|googletagmanager|hotjar|clarity|recaptcha|stripe|braintree)"
    r"[-.\d]*\.(min\.)?js(\?|#|$)",
    re.IGNORECASE,
)
VENDOR_LIB_HOST_RE = re.compile(
    r"(^|\.)(cdnjs\.cloudflare\.com|cdn\.jsdelivr\.net|unpkg\.com|code\.jquery\.com|"
    r"stackpath\.bootstrapcdn\.com|ajax\.googleapis\.com|www\.googletagmanager\.com|"
    r"www\.google-analytics\.com|connect\.facebook\.net|static\.hotjar\.com)",
    re.IGNORECASE,
)


def _filter_js(urls: list[str]) -> list[str]:
    return sorted({u for u in urls if JS_SUFFIX_RE.search(u)})


def _is_vendor_lib(url: str) -> bool:
    host = _host_of(url)
    return bool(VENDOR_LIB_HOST_RE.search(host) or VENDOR_LIB_NAME_RE.search(url))


def _strip_vendor_libs(urls: list[str]) -> list[str]:
    return sorted(u for u in urls if not _is_vendor_lib(u))


# --------------------------------------------------------------- crawl + archive

def _run_katana_js(inscope_file: Path, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not runner.have("katana"):
        return ToolResult(tool="katana-js", ran=False, error="not installed")
    try:
        proc = subprocess.run(
            ["katana", "-list", str(inscope_file), "-silent", "-d", "5", "-jc"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="katana-js", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    js_urls = _filter_js(proc.stdout.splitlines())
    runner.write_lines(outfile, js_urls)
    return ToolResult(tool="katana-js", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(js_urls))


def _run_gau_js(inscope_file: Path, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not runner.have("gau"):
        return ToolResult(tool="gau-js", ran=False, error="not installed")
    hosts = runner.read_lines(inscope_file)
    try:
        proc = subprocess.run(
            ["gau", "--threads", "5"],
            input="\n".join(hosts),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="gau-js", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    js_urls = _filter_js(proc.stdout.splitlines())
    runner.write_lines(outfile, js_urls)
    return ToolResult(tool="gau-js", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(js_urls))


# ----------------------------------------------------------------------- alive

def _run_httpx_live(all_js_file: Path, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not runner.have("httpx"):
        return ToolResult(tool="httpx-js", ran=False, error="not installed")
    urls = runner.read_lines(all_js_file)
    if not urls:
        return ToolResult(tool="httpx-js", ran=False, error="all_js.txt is empty, nothing to probe")
    try:
        proc = subprocess.run(
            ["httpx", "-mc", "200", "-json", "-silent", "-timeout", "5", "-retries", "0", "-threads", "100"],
            input="\n".join(urls),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="httpx-js", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    lines = []
    for line in proc.stdout.splitlines():
        try:
            data = json.loads(line)
        except ValueError:
            continue
        url = data.get("url", "")
        status = data.get("status_code", "")
        if url:
            lines.append(f"{url} [{status}]")

    runner.write_lines(outfile, sorted(set(lines)))
    return ToolResult(tool="httpx-js", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


def _live_urls(js_live_file: Path) -> list[str]:
    urls = []
    for line in runner.read_lines(js_live_file):
        urls.append(line.split(" [", 1)[0].strip())
    return urls


# ---------------------------------------------------------- source maps / minified

SOURCEMAP_COMMENT_RE = re.compile(r"//[#@]\s*sourceMappingURL=(\S+)")
MINIFIED_HINT_RE = re.compile(r"\.min\.js(\?|#|$)", re.IGNORECASE)


def _looks_minified(content: str) -> bool:
    """Heuristic: minified JS is almost always one (or a handful of) very long
    lines rather than normally-wrapped source."""
    lines = [ln for ln in content.splitlines() if ln.strip()]
    if not lines:
        return False
    return max(len(ln) for ln in lines) > 500 or len(lines) <= 3


def _recover_sourcemaps(js_live_file: Path, outdir: Path, timeout: int) -> tuple[ToolResult, dict]:
    """For each live JS URL, look for a companion source map — either via its
    `//# sourceMappingURL=` comment or the `<file>.js.map` convention — and if
    found, recover the *original* (pre-minification) source tree from the
    map's `sourcesContent`. This is often a full, readable source dump of
    code that was never meant to be exposed.

    Returns (ToolResult for JS/sourcemaps.txt, {js_url: recovered_dir_path}).
    """
    urls = _live_urls(js_live_file)
    if not urls:
        return ToolResult(tool="sourcemap-recovery", ran=False, error="js_live.txt is empty"), {}

    recovered_root = outdir / "recovered_src"
    summary: list[str] = []
    recovered_dirs: dict[str, str] = {}

    for url in urls:
        candidates = []
        try:
            resp = requests.get(url, timeout=min(timeout, 15))
            if resp.ok:
                m = SOURCEMAP_COMMENT_RE.search(resp.text[-2000:])
                if m and not m.group(1).strip().startswith("data:"):
                    candidates.append(urljoin(url, m.group(1).strip()))
        except requests.RequestException:
            pass
        candidates.append(url + ".map")  # conventional fallback
        if url.lower().endswith(".min.js"):
            candidates.append(url[: -len(".min.js")] + ".min.map")  # e.g. jquery-3.7.1.min.map

        for map_url in candidates:
            try:
                mresp = requests.get(map_url, timeout=min(timeout, 15))
            except requests.RequestException:
                continue
            if not mresp.ok:
                continue
            try:
                data = mresp.json()
            except ValueError:
                continue

            sources = data.get("sources") or []
            contents = data.get("sourcesContent") or []
            if not sources or not contents:
                continue

            js_hash = hashlib.sha1(url.encode()).hexdigest()[:10]
            dest_base = recovered_root / js_hash
            recovered = 0
            for src_path, src_content in zip(sources, contents):
                if not src_content:
                    continue
                safe_rel = re.sub(r"[^a-zA-Z0-9_./-]", "_", src_path.lstrip("/"))
                dest = dest_base / safe_rel
                dest.parent.mkdir(parents=True, exist_ok=True)
                try:
                    dest.write_text(src_content, errors="replace")
                    recovered += 1
                except OSError:
                    continue

            if recovered:
                summary.append(f"{url} -> map at {map_url}, recovered {recovered} source file(s) -> {dest_base}")
                recovered_dirs[url] = str(dest_base)
            break  # stop trying further candidates once one map resolves

    outfile = outdir / "sourcemaps.txt"
    runner.write_lines(outfile, summary)
    result = ToolResult(
        tool="sourcemap-recovery", ran=True, returncode=0,
        outfile=outfile, lines=len(summary),
    )
    return result, recovered_dirs


def _beautify_minified(js_live_file: Path, already_recovered: dict, outdir: Path, timeout: int, engagement_root: Path) -> ToolResult:
    """js-beautify fallback for minified JS that had no recoverable source map —
    improves jsleak/semgrep's hit rate on code that's otherwise one giant line.
    """
    if not runner.have("js-beautify"):
        return ToolResult(tool="js-beautify", ran=False, error="not installed")
    urls = [u for u in _live_urls(js_live_file) if u not in already_recovered]
    if not urls:
        return ToolResult(tool="js-beautify", ran=False, error="nothing left to beautify (all mapped or empty)")

    beaut_dir = outdir / "beautified"
    produced = 0
    for url in urls:
        try:
            resp = requests.get(url, timeout=min(timeout, 15))
        except requests.RequestException:
            continue
        if not resp.ok or not _looks_minified(resp.text):
            continue

        beaut_dir.mkdir(parents=True, exist_ok=True)
        name = hashlib.sha1(url.encode()).hexdigest()[:16]
        raw_path = beaut_dir / f".raw_{name}.js"
        out_path = beaut_dir / f"{name}.js"
        raw_path.write_text(resp.text, errors="replace")
        try:
            beaut_proc = subprocess.run(
                ["js-beautify", "-o", str(out_path), str(raw_path)],
                capture_output=True, text=True, timeout=30,
            )
            runner.save_raw(engagement_root, f"js-beautify_{name}.txt", beaut_proc.stdout, beaut_proc.stderr)
        except subprocess.TimeoutExpired as exc:
            runner.save_raw(engagement_root, f"js-beautify_{name}.txt", exc.stdout or "", exc.stderr or "")
            continue
        finally:
            raw_path.unlink(missing_ok=True)
        if out_path.exists():
            produced += 1

    if not produced:
        return ToolResult(tool="js-beautify", ran=True, returncode=0, lines=0)
    return ToolResult(tool="js-beautify", ran=True, returncode=0, outfile=beaut_dir, lines=produced)


# ---------------------------------------------------------------------- jsleak

def _host_of(url: str) -> str:
    return url.split("://", 1)[-1].split("/", 1)[0]


def _run_jsleak(js_live_file: Path, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    """Runs jsleak per in-scope host rather than over the whole js_live.txt in
    one call. jsleak has no internal per-request timeout, and -l (linkFinder)
    can chase slow/unresponsive endpoints on one host (e.g. a VPN/Citrix
    gateway) indefinitely — isolating by host means one bad host times out on
    its own slice of the budget instead of silently losing every other host's
    results too.
    """
    if not runner.have("jsleak"):
        return ToolResult(tool="jsleak", ran=False, error="not installed")
    urls = _live_urls(js_live_file)
    if not urls:
        return ToolResult(tool="jsleak", ran=False, error="js_live.txt is empty, nothing to scan")

    by_host: dict[str, list[str]] = {}
    for url in urls:
        by_host.setdefault(_host_of(url), []).append(url)

    per_host_timeout = max(15, timeout // max(len(by_host), 1))
    all_lines: list[str] = []
    errors: list[str] = []
    for host, host_urls in sorted(by_host.items()):
        try:
            proc = subprocess.run(
                ["jsleak", "-s", "-l", "-k"],
                input="\n".join(host_urls),
                capture_output=True,
                text=True,
                timeout=per_host_timeout,
            )
            runner.save_raw(engagement_root, f"jsleak_{host}.txt", proc.stdout, proc.stderr)
            all_lines.extend(ln.rstrip() for ln in proc.stdout.splitlines() if ln.strip())
        except subprocess.TimeoutExpired as exc:
            runner.save_raw(engagement_root, f"jsleak_{host}.txt", exc.stdout or "", exc.stderr or "")
            errors.append(f"{host} (timeout after {per_host_timeout}s)")

    runner.write_lines(outfile, all_lines)
    error = f"{len(errors)} host(s) skipped: {', '.join(errors)}" if errors else None
    return ToolResult(tool="jsleak", ran=True, returncode=0, outfile=outfile, lines=len(all_lines), error=error)


# ------------------------------------------------------------------ trufflehog

def _download_js(urls: list[str], dest_dir: Path, timeout: int) -> dict:
    """Best-effort download of each live JS file for trufflehog's filesystem
    scan (it scans local files, not URLs). Returns {local_path: source_url}.
    """
    mapping = {}
    for url in urls:
        name = hashlib.sha1(url.encode()).hexdigest()[:16] + ".js"
        local_path = dest_dir / name
        try:
            resp = requests.get(url, timeout=min(timeout, 15))
            if resp.ok:
                local_path.write_bytes(resp.content)
                mapping[str(local_path)] = url
        except requests.RequestException:
            continue
    return mapping


def _run_trufflehog(js_live_file: Path, outfile: Path, timeout: int, engagement_root: Path, extra_scan_dirs: list[Path] | None = None) -> ToolResult:
    if not runner.have("trufflehog"):
        return ToolResult(tool="trufflehog", ran=False, error="not installed")
    urls = _live_urls(js_live_file)
    if not urls:
        return ToolResult(tool="trufflehog", ran=False, error="js_live.txt is empty, nothing to scan")

    with tempfile.TemporaryDirectory(prefix="undertow_js_") as tmp:
        tmp_dir = Path(tmp)
        url_map = _download_js(urls, tmp_dir, timeout)
        if not url_map:
            return ToolResult(tool="trufflehog", ran=True, error="could not download any live JS files to scan")

        scan_paths = [str(tmp_dir)] + [str(d) for d in (extra_scan_dirs or []) if d.exists()]
        try:
            proc = subprocess.run(
                ["trufflehog", "filesystem", "-j", *scan_paths],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
            return ToolResult(tool="trufflehog", ran=True, error=f"timeout after {timeout}s")

        runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
        lines = []
        for line in proc.stdout.splitlines():
            try:
                data = json.loads(line)
            except ValueError:
                continue
            detector = data.get("DetectorName", "unknown")
            verified = data.get("Verified", False)
            local_file = (
                data.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {}).get("file", "")
            )
            source_url = url_map.get(local_file, local_file)
            status = "VERIFIED LIVE" if verified else "unverified"
            lines.append(f"{source_url} : {detector} ({status})")

        runner.write_lines(outfile, sorted(set(lines)))
        return ToolResult(tool="trufflehog", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


# ---------------------------------------------------------- semgrep (opt-in only)

def _run_semgrep(js_live_file: Path, outfile: Path, timeout: int, engagement_root: Path, extra_scan_dirs: list[Path] | None = None) -> ToolResult:
    """Opt-in (--js-semgrep). Per CLAUDE.md this was previously dropped as "wrong
    tool for black-box minified JS" — that's still largely true for the raw
    minified bundle (semgrep's value is AST pattern matching against readable
    source), but recovered source-map output / js-beautify'd copies in
    extra_scan_dirs give it something much closer to real source to work with.
    Still additive and gated, never a default/load-bearing source like jsleak.
    """
    if not runner.have("semgrep"):
        return ToolResult(tool="semgrep", ran=False, error="not installed")
    urls = _live_urls(js_live_file)
    if not urls:
        return ToolResult(tool="semgrep", ran=False, error="js_live.txt is empty, nothing to scan")

    with tempfile.TemporaryDirectory(prefix="undertow_js_semgrep_") as tmp:
        tmp_dir = Path(tmp)
        url_map = _download_js(urls, tmp_dir, timeout)
        if not url_map:
            return ToolResult(tool="semgrep", ran=True, error="could not download any live JS files to scan")

        scan_paths = [str(tmp_dir)] + [str(d) for d in (extra_scan_dirs or []) if d.exists()]
        try:
            # `--config auto` pulls rules from Semgrep's registry, which
            # requires its metrics channel (pseudonymous usage telemetry only
            # — no scanned JS content goes with it). Forcing metrics off here
            # broke `--config auto` outright; leave it at semgrep's own
            # default ('auto': on only because --config auto needs it).
            proc = subprocess.run(
                ["semgrep", "scan", "--config", "auto", "--verbose", *scan_paths],
                capture_output=True,
                text=True,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired as exc:
            runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
            return ToolResult(tool="semgrep", ran=True, error=f"timeout after {timeout}s")

        runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
        output = proc.stdout or proc.stderr or ""
        for local_path, source_url in url_map.items():
            output = output.replace(local_path, source_url)

        # semgrep exits 0 (no findings) or 1 (findings present) on a normal
        # run — anything else is a fatal config/invocation error, not results.
        if proc.returncode not in (0, 1):
            return ToolResult(
                tool="semgrep", ran=True, returncode=proc.returncode,
                error=output.strip().splitlines()[-1][:200] if output.strip() else f"exit {proc.returncode}",
            )

        outfile.write_text(output)
        finding_lines = len([ln for ln in output.splitlines() if ln.strip()])
        return ToolResult(tool="semgrep", ran=True, returncode=proc.returncode, outfile=outfile, lines=finding_lines)


# --------------------------------------------------------- nuclei (opt-in only)

def _run_nuclei_creds(js_live_file: Path, outfile: Path, timeout: int, engagement_root: Path) -> ToolResult:
    if not runner.have("nuclei"):
        return ToolResult(tool="nuclei-js", ran=False, error="not installed")
    urls = _live_urls(js_live_file)
    if not urls:
        return ToolResult(tool="nuclei-js", ran=False, error="js_live.txt is empty, nothing to scan")
    try:
        proc = subprocess.run(
            ["nuclei", "-l", "-", "-tags", "token,creds,apikey,exposure", "-silent"],
            input="\n".join(urls),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        runner.save_raw(engagement_root, outfile.name, exc.stdout or "", exc.stderr or "")
        return ToolResult(tool="nuclei-js", ran=True, error=f"timeout after {timeout}s")

    runner.save_raw(engagement_root, outfile.name, proc.stdout, proc.stderr)
    lines = [ln.rstrip() for ln in proc.stdout.splitlines() if ln.strip()]
    runner.write_lines(outfile, lines)
    return ToolResult(tool="nuclei-js", ran=True, returncode=proc.returncode, outfile=outfile, lines=len(lines))


# --------------------------------------------------------------- orchestrate

def run_stage6(
    inscope_domain_file: Path,
    engagement_root: Path,
    *,
    timeout: int = 300,
    vuln_scan: bool = False,
    js_semgrep: bool = False,
) -> StageResult:
    outdir = engagement_root / "JS"
    outdir.mkdir(parents=True, exist_ok=True)

    stage = StageResult(stage="Stage 6 — JS Analysis")

    hosts = runner.read_lines(inscope_domain_file)
    if not hosts:
        stage.add(ToolResult(tool="js_analysis", ran=False, error="INSCOPE_domain.txt is empty — nothing to crawl"))
        return stage

    active_r = stage.add(_run_katana_js(inscope_domain_file, outdir / "js_active.txt", timeout, engagement_root))
    passive_r = stage.add(_run_gau_js(inscope_domain_file, outdir / "js_passive.txt", timeout, engagement_root))

    # Each tool's own file above stays raw/unfiltered (Rule 1 fidelity). The
    # merge that everything downstream actually scans drops known vendor/CDN
    # libraries — they're never going to leak an app secret.
    raw_urls = set()
    for r in (active_r, passive_r):
        if r.outfile:
            raw_urls.update(runner.read_lines(r.outfile))
    all_js = outdir / "all_js.txt"
    runner.write_lines(all_js, _strip_vendor_libs(list(raw_urls)))
    stage.outputs["all_js"] = all_js

    live_r = stage.add(_run_httpx_live(all_js, outdir / "js_live.txt", timeout, engagement_root))
    if not live_r.outfile:
        return stage
    stage.outputs["js_live"] = live_r.outfile

    stage.add(_run_jsleak(live_r.outfile, outdir / "jsleak.txt", timeout, engagement_root))

    # Automatic .map / minified handling: recover original source from any
    # source map we can find, then js-beautify whatever's left unmapped —
    # both feed into trufflehog/semgrep below as extra scan directories.
    sourcemap_r, recovered_dirs = _recover_sourcemaps(live_r.outfile, outdir, timeout)
    stage.add(sourcemap_r)
    beautify_r = stage.add(_beautify_minified(live_r.outfile, recovered_dirs, outdir, timeout, engagement_root))

    extra_scan_dirs = []
    if recovered_dirs:
        extra_scan_dirs.append(outdir / "recovered_src")
    if beautify_r.outfile:
        extra_scan_dirs.append(outdir / "beautified")

    stage.add(_run_trufflehog(live_r.outfile, outdir / "trufflehog.txt", timeout, engagement_root, extra_scan_dirs=extra_scan_dirs))

    if js_semgrep:
        stage.add(_run_semgrep(live_r.outfile, outdir / "semgrep.txt", timeout, engagement_root, extra_scan_dirs=extra_scan_dirs))

    if vuln_scan:
        stage.add(_run_nuclei_creds(live_r.outfile, outdir / "nuclei_js.txt", timeout, engagement_root))

    return stage
